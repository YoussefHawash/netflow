use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, NaiveDate};
use netflow_common::{L4Proto, PacketEvent, DIR_IN, DIR_OUT};

use crate::archiver::ArchiveJob;
use crate::geo::GeoCache;
use crate::proc_fs::{self, ProcCache};
use crate::{ConnectionTraffic, HistoryBucket, MonitorSnapshot, ProcessTraffic};

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub local_port: u16,
    pub remote: [u8; 16],
    pub remote_port: u16,
    pub l4: u8,
    pub is_ipv6: bool,
}

#[derive(Clone)]
pub struct ConnAgg {
    pub received: u64,
    pub sent: u64,
    pub last_pid: u32,
    pub last_seen: Instant,
}

impl ConnAgg {
    fn new() -> Self {
        Self {
            received: 0,
            sent: 0,
            last_pid: 0,
            last_seen: Instant::now(),
        }
    }
}

const STALE_CONN_TTL: Duration = Duration::from_secs(60);

pub struct State {
    started_at: Instant,
    last_snapshot_at: Instant,

    iface: String,
    iface_index: Option<u32>,

    history_buckets: usize,
    proc_history_len: usize,

    conns: HashMap<ConnKey, ConnAgg>,

    epoch_in: u64,
    epoch_out: u64,

    today_in: u64,
    today_out: u64,
    today_date: NaiveDate,

    history: VecDeque<HistoryBucket>,
    proc_history: HashMap<u32, VecDeque<f64>>,

    proc_cache: ProcCache,
    geo: Arc<GeoCache>,
}

impl State {
    pub fn new(
        iface: String,
        iface_index: Option<u32>,
        history_buckets: usize,
        proc_history_len: usize,
        geo: Arc<GeoCache>,
    ) -> Self {
        let now = Instant::now();
        Self {
            started_at: now,
            last_snapshot_at: now,
            iface,
            iface_index,
            history_buckets,
            proc_history_len,
            conns: HashMap::new(),
            epoch_in: 0,
            epoch_out: 0,
            today_in: 0,
            today_out: 0,
            today_date: Local::now().date_naive(),
            history: VecDeque::with_capacity(history_buckets),
            proc_history: HashMap::new(),
            proc_cache: ProcCache::new(),
            geo,
        }
    }

    pub fn interface(&self) -> &str {
        &self.iface
    }

    pub fn set_interface(&mut self, iface: String, iface_index: Option<u32>) {
        self.iface = iface;
        self.iface_index = iface_index;
        self.conns.clear();
        self.proc_history.clear();
        self.history.clear();
        self.epoch_in = 0;
        self.epoch_out = 0;
        self.last_snapshot_at = Instant::now();
    }

    pub fn ingest(&mut self, ev: &PacketEvent) {
        if ev.direction == DIR_IN {
            if let Some(want) = self.iface_index {
                if ev.ifindex != want {
                    return;
                }
            }
        }

        let key = ConnKey {
            local_port: ev.local_port,
            remote: ev.remote,
            remote_port: ev.remote_port,
            l4: ev.l4_proto,
            is_ipv6: ev.is_ipv6 != 0,
        };

        let agg = self.conns.entry(key).or_insert_with(ConnAgg::new);
        let bytes = ev.size as u64;
        if ev.direction == DIR_OUT {
            agg.sent += bytes;
            self.epoch_out += bytes;
        } else {
            agg.received += bytes;
            self.epoch_in += bytes;
        }
        agg.last_seen = Instant::now();
        if ev.pid != 0 {
            agg.last_pid = ev.pid;
        }
    }

    pub fn take_snapshot(&mut self) -> (MonitorSnapshot, ArchiveJob) {
        let now = Instant::now();
        let elapsed = (now - self.last_snapshot_at).as_secs_f64().max(0.001);

        let today = Local::now().date_naive();
        if today != self.today_date {
            self.today_date = today;
            self.today_in = 0;
            self.today_out = 0;
        }
        self.today_in += self.epoch_in;
        self.today_out += self.epoch_out;

        let received_rate = self.epoch_in as f64 / elapsed;
        let sent_rate = self.epoch_out as f64 / elapsed;

        self.proc_cache.refresh();

        for (key, agg) in self.conns.iter_mut() {
            if agg.last_pid == 0 {
                if let Some(pid) = self.proc_cache.pid_for_socket(
                    key.local_port,
                    key.l4,
                    key.is_ipv6,
                    &key.remote,
                    key.remote_port,
                ) {
                    agg.last_pid = pid;
                }
            }
        }

        let mut per_proc: HashMap<u32, ProcRollup> = HashMap::new();
        let mut connections = Vec::with_capacity(self.conns.len());

        for (key, agg) in &self.conns {
            let l4 = L4Proto::from_u8(key.l4);
            let proto_str = l4_str(l4).to_string();
            let pid = agg.last_pid;

            let (name, user) = if pid != 0 {
                self.proc_cache.process_info(pid)
            } else {
                (String::new(), String::new())
            };

            let state_str = self
                .proc_cache
                .conn_state(
                    key.local_port,
                    key.l4,
                    key.is_ipv6,
                    &key.remote,
                    key.remote_port,
                )
                .unwrap_or_else(|| "UNKNOWN".to_string());

            let remote_ip = ip_from_bytes(&key.remote, key.is_ipv6);
            let flag = self.geo.lookup(remote_ip);

            connections.push(ConnectionTraffic {
                remote: remote_ip.to_string(),
                flag: flag.clone(),
                port: key.remote_port,
                local_port: key.local_port,
                protocol: proto_str.clone(),
                process_name: name,
                pid,
                user,
                received: agg.received as f64,
                sent: agg.sent as f64,
                state: state_str,
            });

            if pid != 0 {
                let entry = per_proc
                    .entry(pid)
                    .or_insert_with(|| ProcRollup::new(&proto_str));
                entry.received += agg.received;
                entry.sent += agg.sent;
                entry.add_proto(&proto_str);
                entry.note_country(&flag);
            }
        }

        let active_pids: HashSet<u32> = per_proc.keys().copied().collect();
        self.proc_history.retain(|pid, _| active_pids.contains(pid));

        let mut processes = Vec::with_capacity(per_proc.len());
        for (pid, roll) in per_proc.into_iter() {
            let (name, user) = self.proc_cache.process_info(pid);
            let threads = self.proc_cache.threads(pid);

            let hist = self
                .proc_history
                .entry(pid)
                .or_insert_with(|| VecDeque::with_capacity(self.proc_history_len));
            hist.push_back((roll.received + roll.sent) as f64);
            while hist.len() > self.proc_history_len {
                hist.pop_front();
            }
            let history: Vec<f64> = hist.iter().copied().collect();

            processes.push(ProcessTraffic {
                pid,
                name,
                user,
                flag: roll.dominant_country(),
                protocol: roll.proto_label(),
                received: roll.received as f64,
                sent: roll.sent as f64,
                history,
                threads,
            });
        }
        processes.sort_by(|a, b| {
            (b.received + b.sent)
                .partial_cmp(&(a.received + a.sent))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let label = Local::now().format("%H:%M:%S").to_string();
        let bucket = HistoryBucket {
            label,
            received: self.epoch_in as f64,
            sent: self.epoch_out as f64,
        };
        self.history.push_back(bucket.clone());
        while self.history.len() > self.history_buckets {
            self.history.pop_front();
        }

        let snapshot = MonitorSnapshot {
            available_interfaces: proc_fs::available_interfaces(),
            interface_name: self.iface.clone(),
            received_rate,
            sent_rate,
            received_today: self.today_in as f64,
            sent_today: self.today_out as f64,
            uptime_seconds: (now - self.started_at).as_secs(),
            processes: processes.clone(),
            connections: connections.clone(),
            history: self.history.iter().cloned().collect(),
        };

        let archive_job = ArchiveJob {
            timestamp: Local::now(),
            interface: self.iface.clone(),
            received_rate,
            sent_rate,
            bucket,
            connections,
            processes,
        };

        self.epoch_in = 0;
        self.epoch_out = 0;
        self.last_snapshot_at = now;
        let cutoff = now - STALE_CONN_TTL;
        self.conns.retain(|_, agg| agg.last_seen >= cutoff);

        (snapshot, archive_job)
    }
}
struct ProcRollup {
    received: u64,
    sent: u64,
    first_proto: String,
    mixed: bool,
    countries: HashMap<String, u32>,
}

impl ProcRollup {
    fn new(first_proto: &str) -> Self {
        Self {
            received: 0,
            sent: 0,
            first_proto: first_proto.to_string(),
            mixed: false,
            countries: HashMap::new(),
        }
    }

    fn add_proto(&mut self, proto: &str) {
        if !self.mixed && proto != self.first_proto {
            self.mixed = true;
        }
    }

    fn proto_label(&self) -> String {
        if self.mixed {
            "MIXED".to_string()
        } else {
            self.first_proto.clone()
        }
    }

    fn note_country(&mut self, code: &str) {
        if code.is_empty() {
            return;
        }
        *self.countries.entry(code.to_string()).or_insert(0) += 1;
    }

    fn dominant_country(&self) -> String {
        self.countries
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, _)| k.clone())
            .unwrap_or_default()
    }
}

fn l4_str(l4: L4Proto) -> &'static str {
    match l4 {
        L4Proto::Tcp => "TCP",
        L4Proto::Udp => "UDP",
        L4Proto::IcmpV4 => "ICMPv4",
        L4Proto::IcmpV6 => "ICMPv6",
        L4Proto::Unknown => "?",
    }
}

fn ip_from_bytes(bytes: &[u8; 16], is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        IpAddr::V6(Ipv6Addr::from(*bytes))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
}
