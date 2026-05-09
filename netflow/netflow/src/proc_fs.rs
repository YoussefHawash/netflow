//! /proc and /sys enrichment used at snapshot time.
//!
//! At each snapshot, [`ProcCache::refresh`] rebuilds:
//!   * the `(l4, ipv6, local_port, remote, remote_port) -> (inode, state)`
//!     map from `/proc/net/{tcp,tcp6,udp,udp6}`
//!   * the `socket_inode -> pid` map from `/proc/<pid>/fd/*` symlinks
//!
//! Process name / user / thread list are loaded lazily per snapshot.
//! The UID -> username table is preserved across refreshes since it
//! virtually never changes at runtime.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;

use netflow_common::L4Proto;

use crate::ThreadInfo;

const PROC: &str = "/proc";
const SYS_NET: &str = "/sys/class/net";

pub fn available_interfaces() -> Vec<String> {
    let Ok(rd) = fs::read_dir(SYS_NET) else {
        return Vec::new();
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    out.sort();
    out
}

pub fn ifindex_of(iface: &str) -> Option<u32> {
    let path: PathBuf = [SYS_NET, iface, "ifindex"].iter().collect();
    fs::read_to_string(path).ok()?.trim().parse::<u32>().ok()
}

#[derive(Clone, Copy)]
struct ConnInfo {
    inode: u64,
    state: &'static str,
}

/// Full 5-tuple key. Storing the remote address/port distinguishes
/// listening sockets from established connections to/from the same local
/// port, which is what makes the PID backfill work for incoming traffic.
type ConnKey = (u8, bool, u16, [u8; 16], u16);

pub struct ProcCache {
    conns: HashMap<ConnKey, ConnInfo>,
    inode_to_pid: HashMap<u64, u32>,
    proc_info: HashMap<u32, (String, String)>,
    thread_cache: HashMap<u32, Vec<ThreadInfo>>,
    user_cache: HashMap<u32, String>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
            inode_to_pid: HashMap::new(),
            proc_info: HashMap::new(),
            thread_cache: HashMap::new(),
            user_cache: HashMap::new(),
        }
    }

    pub fn refresh(&mut self) {
        self.conns.clear();
        self.proc_info.clear();
        self.thread_cache.clear();

        let tcp = L4Proto::Tcp as u8;
        let udp = L4Proto::Udp as u8;
        load_proc_net("/proc/net/tcp", tcp, false, &mut self.conns);
        load_proc_net("/proc/net/tcp6", tcp, true, &mut self.conns);
        load_proc_net("/proc/net/udp", udp, false, &mut self.conns);
        load_proc_net("/proc/net/udp6", udp, true, &mut self.conns);

        self.inode_to_pid = build_inode_map();
    }

    pub fn pid_for_socket(
        &self,
        local_port: u16,
        l4: u8,
        is_ipv6: bool,
        remote: &[u8; 16],
        remote_port: u16,
    ) -> Option<u32> {
        if let Some(info) = self.conns.get(&(l4, is_ipv6, local_port, *remote, remote_port)) {
            if let Some(pid) = self.inode_to_pid.get(&info.inode).copied() {
                return Some(pid);
            }
        }
        // Fall back to local-port-only match. Useful when:
        //   * the kernel hasn't filled in the remote yet (SYN_SENT)
        //   * we're looking at a listening socket
        //   * we have an IPv6 egress event with zero remote bytes
        for ((l4_k, ipv6_k, port_k, _, _), info) in &self.conns {
            if *l4_k == l4 && *ipv6_k == is_ipv6 && *port_k == local_port {
                if let Some(pid) = self.inode_to_pid.get(&info.inode).copied() {
                    return Some(pid);
                }
            }
        }
        None
    }

    pub fn conn_state(
        &self,
        local_port: u16,
        l4: u8,
        is_ipv6: bool,
        remote: &[u8; 16],
        remote_port: u16,
    ) -> Option<String> {
        if let Some(info) = self.conns.get(&(l4, is_ipv6, local_port, *remote, remote_port)) {
            return Some(info.state.to_string());
        }
        for ((l4_k, ipv6_k, port_k, _, _), info) in &self.conns {
            if *l4_k == l4 && *ipv6_k == is_ipv6 && *port_k == local_port {
                return Some(info.state.to_string());
            }
        }
        None
    }

    pub fn process_info(&mut self, pid: u32) -> (String, String) {
        if let Some(info) = self.proc_info.get(&pid) {
            return info.clone();
        }
        let name = fs::read_to_string(format!("{PROC}/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let user = match read_real_uid(pid) {
            Some(uid) => self
                .user_cache
                .entry(uid)
                .or_insert_with(|| uid_to_username(uid).unwrap_or_else(|| uid.to_string()))
                .clone(),
            None => String::new(),
        };

        let info = (name, user);
        self.proc_info.insert(pid, info.clone());
        info
    }

    pub fn threads(&mut self, pid: u32) -> Vec<ThreadInfo> {
        if let Some(t) = self.thread_cache.get(&pid) {
            return t.clone();
        }
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(format!("{PROC}/{pid}/task")) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Ok(tid) = name.parse::<u32>() else { continue };
                let comm = fs::read_to_string(format!("{PROC}/{pid}/task/{tid}/comm"))
                    .ok()
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                out.push(ThreadInfo { tid, name: comm });
            }
        }
        out.sort_by_key(|t| t.tid);
        self.thread_cache.insert(pid, out.clone());
        out
    }
}

// ---------- /proc/net/{tcp,tcp6,udp,udp6} parser --------------------------
//
// Format (whitespace-separated, header line skipped):
//   sl  local_address rem_address st tx:rx tr:tm retr uid timeout inode ...
// IP addresses are kernel u32s (or four u32s for v6) written as hex in the
// host's byte order; we reverse them with `to_le_bytes` so the output
// matches network-order bytes (which is what the eBPF PacketEvent carries).

fn load_proc_net(path: &str, l4: u8, is_ipv6: bool, out: &mut HashMap<ConnKey, ConnInfo>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let Some((local_addr, local_port)) = parse_addr_port(parts[1], is_ipv6) else {
            continue;
        };
        let Some((remote_addr, remote_port)) = parse_addr_port(parts[2], is_ipv6) else {
            continue;
        };

        let _ = local_addr; // unused: the eBPF side doesn't carry our local IP

        let state = if l4 == L4Proto::Tcp as u8 {
            tcp_state(parts[3])
        } else {
            udp_state(parts[3])
        };
        let inode: u64 = parts[9].parse().unwrap_or(0);

        out.insert(
            (l4, is_ipv6, local_port, remote_addr, remote_port),
            ConnInfo { inode, state },
        );
    }
}

fn parse_addr_port(field: &str, is_ipv6: bool) -> Option<([u8; 16], u16)> {
    let mut parts = field.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if is_ipv6 {
        parse_v6(addr_hex)?
    } else {
        let v4 = parse_v4(addr_hex)?;
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&v4);
        bytes
    };
    Some((addr, port))
}

fn parse_v4(hex: &str) -> Option<[u8; 4]> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(v.to_le_bytes())
}

fn parse_v6(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex[i * 8..i * 8 + 8];
        let v = u32::from_str_radix(chunk, 16).ok()?;
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    Some(out)
}

fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn udp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "07" => "UNCONN",
        _ => "STATELESS",
    }
}

// ---------- inode -> PID via /proc/<pid>/fd/* -----------------------------

fn build_inode_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(rd) = fs::read_dir(PROC) else {
        return map;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let s = target.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(num) = rest.strip_suffix(']') {
                    if let Ok(inode) = num.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }
    map
}

// ---------- /proc/<pid>/status real UID + libc lookup --------------------

fn read_real_uid(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("{PROC}/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn uid_to_username(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(pwd.pw_name) };
    Some(cstr.to_string_lossy().into_owned())
}
