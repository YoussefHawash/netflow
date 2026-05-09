//! Procfs / sysfs enrichment.
//!
//! Used at snapshot time to:
//!   * resolve the PID owning a (local_port, L4) socket (XDP can't tell us)
//!   * fetch process name / user / thread list
//!   * fetch the kernel-side connection state ("ESTABLISHED", "TIME_WAIT", …)
//!   * enumerate available network interfaces

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::path::PathBuf;

use netflow_common::L4Proto;

use crate::ThreadInfo;

const PROC: &str = "/proc";
const SYS_NET: &str = "/sys/class/net";

/// All interfaces present in /sys/class/net.
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

/// /sys/class/net/<iface>/ifindex.
pub fn ifindex_of(iface: &str) -> Option<u32> {
    let path: PathBuf = [SYS_NET, iface, "ifindex"].iter().collect();
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse::<u32>().ok()
}

#[derive(Clone, Copy)]
struct ConnInfo {
    inode: u64,
    state: &'static str,
}

/// One key per (l4, is_ipv6, local_port). Multiple sockets can share a
/// local port (e.g. SO_REUSEPORT, listening + ephemeral); we keep the most
/// recent one we saw, which is fine for the common case.
type ConnByPort = HashMap<(u8, bool, u16), ConnInfo>;

pub struct ProcCache {
    conn_by_port: ConnByPort,
    inode_to_pid: HashMap<u64, u32>,
    proc_info: HashMap<u32, (String, String)>,
    thread_cache: HashMap<u32, Vec<ThreadInfo>>,
    user_cache: HashMap<u32, String>,
}

impl ProcCache {
    pub fn new() -> Self {
        Self {
            conn_by_port: HashMap::new(),
            inode_to_pid: HashMap::new(),
            proc_info: HashMap::new(),
            thread_cache: HashMap::new(),
            user_cache: HashMap::new(),
        }
    }

    /// Rebuild the per-snapshot caches. The user_cache is preserved across
    /// refreshes since UID->name almost never changes at runtime.
    pub fn refresh(&mut self) {
        self.conn_by_port.clear();
        self.proc_info.clear();
        self.thread_cache.clear();

        let tcp = L4Proto::Tcp as u8;
        let udp = L4Proto::Udp as u8;
        load_proc_net("/proc/net/tcp", tcp, false, &mut self.conn_by_port);
        load_proc_net("/proc/net/tcp6", tcp, true, &mut self.conn_by_port);
        load_proc_net("/proc/net/udp", udp, false, &mut self.conn_by_port);
        load_proc_net("/proc/net/udp6", udp, true, &mut self.conn_by_port);

        self.inode_to_pid = build_inode_map();
    }

    pub fn pid_for_socket(&self, local_port: u16, l4: u8, is_ipv6: bool) -> Option<u32> {
        let info = self.conn_by_port.get(&(l4, is_ipv6, local_port))?;
        self.inode_to_pid.get(&info.inode).copied()
    }

    pub fn conn_state(&self, local_port: u16, l4: u8, is_ipv6: bool) -> Option<String> {
        self.conn_by_port
            .get(&(l4, is_ipv6, local_port))
            .map(|i| i.state.to_string())
    }

    pub fn process_info(&mut self, pid: u32) -> (String, String) {
        if let Some(info) = self.proc_info.get(&pid) {
            return info.clone();
        }
        let name = fs::read_to_string(format!("{PROC}/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let uid = read_real_uid(pid);
        let user = match uid {
            Some(uid) => {
                if let Some(u) = self.user_cache.get(&uid) {
                    u.clone()
                } else {
                    let u = uid_to_username(uid).unwrap_or_else(|| uid.to_string());
                    self.user_cache.insert(uid, u.clone());
                    u
                }
            }
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
                let Ok(tid) = name.parse::<u32>() else {
                    continue;
                };
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

fn load_proc_net(path: &str, l4: u8, is_ipv6: bool, out: &mut ConnByPort) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let Some(port_hex) = parts[1].split(':').nth(1) else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let state = if l4 == L4Proto::Tcp as u8 {
            tcp_state(parts[3])
        } else {
            udp_state(parts[3])
        };
        let inode: u64 = parts[9].parse().unwrap_or(0);
        out.insert((l4, is_ipv6, port), ConnInfo { inode, state });
    }
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

// ---------- inode -> PID map (/proc/*/fd/*) -------------------------------

fn build_inode_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(rd) = fs::read_dir(PROC) else {
        return map;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
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

// ---------- /proc/[pid]/status real UID + libc lookup ---------------------

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
