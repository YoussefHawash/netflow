//! netflow — eBPF-backed live network monitor.
//!
//! Runs an XDP program (ingress) and kprobes on `tcp_sendmsg` /
//! `udp_sendmsg` (egress) that push every observed packet/send into a ring
//! buffer. A background task drains that ring into an aggregated state
//! struct. Calling [`Monitor::snapshot`] returns the current view as a
//! [`MonitorSnapshot`] and ships the just-completed epoch's data to the XML
//! archiver, so every byte is either visible in the live snapshot or
//! persisted on disk.
//!
//! The shape of `Monitor` is deliberately Tauri-friendly:
//!
//! ```ignore
//! // In your Tauri app:
//! let monitor = Monitor::new(MonitorConfig::default()).await?;
//! tauri::Builder::default()
//!     .manage(monitor)
//!     .invoke_handler(tauri::generate_handler![get_snapshot])
//!     .run(tauri::generate_context!())?;
//!
//! #[tauri::command]
//! fn get_snapshot(monitor: tauri::State<Monitor>) -> MonitorSnapshot {
//!     monitor.snapshot()
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod archiver;
mod loader;
mod proc_fs;
mod reader;
mod state;

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

// Mirrors of the kernel-side enums; kept here so consumers don't have to
// pull in netflow-common.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Unknown,
    IPv4,
    IPv6,
    ARP,
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub net_proto: Protocol,
    pub transport_proto: Protocol,
    pub remote: [u8; 16],
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub size: u16,
    pub outbound: bool,
    pub is_ipv6: bool,
}

// ---------- Monitor configuration -----------------------------------------

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Interface to attach XDP to (e.g. "eth0", "wlan0").
    pub interface: String,
    /// Directory where per-snapshot XML archives are written.
    pub archive_dir: PathBuf,
    /// How many recent buckets to keep live in `MonitorSnapshot::history`.
    pub history_buckets: usize,
    /// Per-process history length (`ProcessTraffic::history`).
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
    // Keep the Ebpf object alive for the lifetime of the Monitor so the
    // programs stay attached to the kernel.
    _ebpf: Mutex<aya::Ebpf>,
    _tasks: Vec<JoinHandle<()>>,
}

pub(crate) struct Inner {
    pub state: Mutex<state::State>,
    pub archive_tx: mpsc::UnboundedSender<archiver::ArchiveJob>,
    pub config: MonitorConfig,
}

impl Monitor {
    /// Loads the eBPF programs, attaches them, and starts the background
    /// drain + archive tasks. Requires CAP_BPF / CAP_NET_ADMIN (i.e. root).
    pub async fn new(config: MonitorConfig) -> Result<Self> {
        bump_memlock_rlimit();

        let (mut ebpf, ring_buf) = loader::load(&config.interface)?;

        let (archive_tx, archive_rx) = mpsc::unbounded_channel();

        // Ensure the archive directory exists.
        if let Err(e) = std::fs::create_dir_all(&config.archive_dir) {
            log::warn!(
                "could not create archive dir {:?}: {e}",
                config.archive_dir
            );
        }

        let iface_index = proc_fs::ifindex_of(&config.interface);

        let inner = Arc::new(Inner {
            state: Mutex::new(state::State::new(
                config.interface.clone(),
                iface_index,
                config.history_buckets,
                config.proc_history_len,
            )),
            archive_tx,
            config: config.clone(),
        });

        // Wire up the eBPF logger if any log statements remain.
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            log::debug!("ebpf logger not initialized: {e}");
        }

        let mut tasks = Vec::new();

        tasks.push(tokio::spawn(reader::run(
            ring_buf,
            Arc::clone(&inner),
        )));

        tasks.push(tokio::spawn(archiver::run(
            archive_rx,
            config.archive_dir.clone(),
        )));

        Ok(Self {
            inner,
            _ebpf: Mutex::new(ebpf),
            _tasks: tasks,
        })
    }

    /// Build the live snapshot, queue the just-completed epoch for XML
    /// archival, and reset the per-epoch counters. Safe to call from any
    /// thread; the implementation is sync so it can be wrapped directly in
    /// a Tauri command.
    pub fn snapshot(&self) -> MonitorSnapshot {
        let mut state = self.inner.state.lock().unwrap();
        let (snapshot, archive_job) = state.take_snapshot(&self.inner.config);
        drop(state);

        // Best-effort send; if the archiver task is gone we silently drop.
        let _ = self.inner.archive_tx.send(archive_job);
        snapshot
    }

    pub fn interface(&self) -> String {
        self.inner.config.interface.clone()
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
