//! netflow — eBPF-backed live network monitor.
//!
//! Architecture:
//!   * eBPF (XDP + kprobes on tcp/udp_sendmsg) writes one PacketEvent per
//!     packet/send into a 1 MiB ring buffer.
//!   * A background tokio task drains the ring buffer into a per-connection
//!     aggregator behind a Mutex.
//!   * Calling `Monitor::snapshot()` builds the live `MonitorSnapshot` and
//!     ships the just-completed epoch as XML to the archiver task.
//!   * eBPF-side filter maps (`set_filter_mode`, `add_filter_pid`,
//!     `add_filter_ipv4`) drop or hide traffic in-kernel.
//!
//! `Monitor` is `Send + Sync` and designed to live inside `tauri::State`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use aya::programs::Xdp;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod archiver;
mod filter;
mod geo;
mod loader;
mod proc_fs;
mod reader;
mod state;

pub use filter::{FilterMode, FilterState};
pub use proc_fs::available_interfaces;

// ---------- Public snapshot types -----------------------------------------

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MonitorSnapshot {
    pub available_interfaces: Vec<String>,
    pub interface_name: String,
    pub received_rate: f64,
    pub sent_rate: f64,
    pub received_today: f64,
    pub sent_today: f64,
    pub uptime_seconds: u64,
    pub processes: Vec<ProcessTraffic>,
    pub connections: Vec<ConnectionTraffic>,
    pub history: Vec<HistoryBucket>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTraffic {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub flag: String,
    pub protocol: String,
    pub received: f64,
    pub sent: f64,
    pub history: Vec<f64>,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ThreadInfo {
    pub tid: u32,
    pub name: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTraffic {
    pub remote: String,
    pub flag: String,
    pub port: u16,
    #[serde(skip)]
    pub local_port: u16,
    pub protocol: String,
    pub process_name: String,
    pub pid: u32,
    pub user: String,
    pub received: f64,
    pub sent: f64,
    pub state: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct HistoryBucket {
    pub label: String,
    pub received: f64,
    pub sent: f64,
}

// ---------- Monitor configuration -----------------------------------------

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub interface: String,
    pub archive_dir: PathBuf,
    pub history_buckets: usize,
    pub proc_history_len: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interface: "lo".to_string(),
            archive_dir: PathBuf::from("/var/lib/netflow/archive"),
            history_buckets: 60,
            proc_history_len: 30,
        }
    }
}

// ---------- Monitor -------------------------------------------------------

pub struct Monitor {
    inner: Arc<Inner>,
    /// Holds the loaded eBPF object; dropping it detaches every program.
    /// Behind a Mutex because `switch_interface` needs `&mut Ebpf`.
    ebpf: Arc<Mutex<aya::Ebpf>>,
    xdp_link: Mutex<Option<aya::programs::xdp::XdpLinkId>>,
    _tasks: Vec<JoinHandle<()>>,
}

pub(crate) struct Inner {
    pub state: Mutex<state::State>,
    pub archive_tx: mpsc::UnboundedSender<archiver::ArchiveJob>,
    pub filter: Mutex<filter::FilterMaps>,
}

impl Monitor {
    pub async fn new(config: MonitorConfig) -> Result<Self> {
        bump_memlock_rlimit();

        let loader::LoadedPrograms {
            ebpf,
            events,
            xdp_link,
            filter,
        } = loader::load(&config.interface)?;

        let (archive_tx, archive_rx) = mpsc::unbounded_channel();

        if let Err(e) = std::fs::create_dir_all(&config.archive_dir) {
            log::warn!(
                "could not create archive dir {:?}: {e}",
                config.archive_dir
            );
        }

        let iface_index = proc_fs::ifindex_of(&config.interface);

        let geo = geo::GeoCache::new();

        let inner = Arc::new(Inner {
            state: Mutex::new(state::State::new(
                config.interface.clone(),
                iface_index,
                config.history_buckets,
                config.proc_history_len,
                geo,
            )),
            archive_tx,
            filter: Mutex::new(filter),
        });

        let tasks = vec![
            tokio::spawn(reader::run(events, Arc::clone(&inner))),
            tokio::spawn(archiver::run(archive_rx, config.archive_dir.clone())),
        ];

        Ok(Self {
            inner,
            ebpf: Arc::new(Mutex::new(ebpf)),
            xdp_link: Mutex::new(Some(xdp_link)),
            _tasks: tasks,
        })
    }

    /// Build the live snapshot and ship the just-completed epoch to the
    /// archiver. Sync — safe to call from a Tauri command handler.
    pub fn snapshot(&self) -> MonitorSnapshot {
        let mut state = self.inner.state.lock().unwrap();
        let (snapshot, archive_job) = state.take_snapshot();
        drop(state);
        let _ = self.inner.archive_tx.send(archive_job);
        snapshot
    }

    pub fn interface(&self) -> String {
        self.inner.state.lock().unwrap().interface().to_string()
    }

    /// Detach XDP from the current interface and re-attach to `iface`.
    pub fn switch_interface(&self, iface: &str) -> Result<()> {
        if iface.is_empty() || iface == self.interface() {
            return Ok(());
        }
        let new_index = proc_fs::ifindex_of(iface)
            .ok_or_else(|| anyhow!("interface '{iface}' does not exist"))?;

        let mut ebpf = self.ebpf.lock().unwrap();
        let xdp: &mut Xdp = ebpf
            .program_mut("netflow")
            .ok_or_else(|| anyhow!("xdp program missing"))?
            .try_into()?;

        let mut link_slot = self.xdp_link.lock().unwrap();
        if let Some(prev) = link_slot.take() {
            let _ = xdp.detach(prev);
        }
        let new_link = loader::attach_xdp(xdp, iface)?;
        *link_slot = Some(new_link);
        drop(link_slot);
        drop(ebpf);

        self.inner
            .state
            .lock()
            .unwrap()
            .set_interface(iface.to_string(), Some(new_index));

        log::info!("switched capture interface to {iface}");
        Ok(())
    }

    // ---- Filter API ------------------------------------------------------

    pub fn set_filter_mode(&self, mode: FilterMode) -> Result<()> {
        self.inner.filter.lock().unwrap().set_mode(mode)
    }

    pub fn add_filter_pid(&self, pid: u32) -> Result<()> {
        self.inner.filter.lock().unwrap().add_pid(pid)
    }

    pub fn remove_filter_pid(&self, pid: u32) {
        self.inner.filter.lock().unwrap().remove_pid(pid);
    }

    pub fn add_filter_ipv4(&self, addr: Ipv4Addr) -> Result<()> {
        self.inner.filter.lock().unwrap().add_ipv4(addr)
    }

    pub fn remove_filter_ipv4(&self, addr: Ipv4Addr) {
        self.inner.filter.lock().unwrap().remove_ipv4(addr);
    }

    pub fn clear_filter_pids(&self) {
        self.inner.filter.lock().unwrap().clear_pids();
    }

    pub fn clear_filter_ipv4(&self) {
        self.inner.filter.lock().unwrap().clear_ipv4();
    }

    pub fn filter_state(&self) -> FilterState {
        self.inner.filter.lock().unwrap().snapshot()
    }

    /// Write a self-contained XML rollup of the most recent snapshot to
    /// `path`. Useful for the "Save history" button in the UI.
    pub fn export_history(&self, path: &Path) -> Result<()> {
        let snap = self.snapshot();
        let xml = quick_xml::se::to_string_with_root("monitorSnapshot", &snap)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, xml)?;
        Ok(())
    }
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("setrlimit(RLIMIT_MEMLOCK) failed: ret={ret}");
    }
}
