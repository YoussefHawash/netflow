//! Tauri entry point for netflow.
//!
//! The Rust backend owns a `Monitor` (eBPF programs + ringbuf reader +
//! archiver). The frontend invokes commands defined here via the Tauri
//! `invoke()` bridge.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use netflow::{
    available_interfaces, ExportPeriod, FilterMode, FilterState, Monitor, MonitorConfig,
    MonitorSnapshot,
};

// ---------- Tauri commands ------------------------------------------------

#[tauri::command]
fn get_network_snapshot(
    interface_name: Option<String>,
    monitor: tauri::State<'_, Monitor>,
) -> MonitorSnapshot {
    if let Some(iface) = interface_name {
        if !iface.is_empty() && iface != monitor.interface() {
            if let Err(e) = monitor.switch_interface(&iface) {
                log::warn!("interface switch to {iface} failed: {e}");
            }
        }
    }
    monitor.snapshot()
}

#[tauri::command]
fn list_interfaces() -> Vec<String> {
    available_interfaces()
}

#[tauri::command]
fn get_filter_state(monitor: tauri::State<'_, Monitor>) -> FilterState {
    monitor.filter_state()
}

#[tauri::command]
fn set_filter_mode(mode: FilterMode, monitor: tauri::State<'_, Monitor>) -> Result<(), String> {
    monitor.set_filter_mode(mode).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_filter_pid(pid: u32, monitor: tauri::State<'_, Monitor>) -> Result<(), String> {
    monitor.add_filter_pid(pid).map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_filter_pid(pid: u32, monitor: tauri::State<'_, Monitor>) {
    monitor.remove_filter_pid(pid);
}

#[tauri::command]
fn add_filter_ip(ip: String, monitor: tauri::State<'_, Monitor>) -> Result<(), String> {
    let addr = Ipv4Addr::from_str(&ip).map_err(|e| format!("invalid IPv4 '{ip}': {e}"))?;
    monitor.add_filter_ipv4(addr).map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_filter_ip(ip: String, monitor: tauri::State<'_, Monitor>) -> Result<(), String> {
    let addr = Ipv4Addr::from_str(&ip).map_err(|e| format!("invalid IPv4 '{ip}': {e}"))?;
    monitor.remove_filter_ipv4(addr);
    Ok(())
}

#[tauri::command]
fn clear_pid_filter(monitor: tauri::State<'_, Monitor>) {
    monitor.clear_filter_pids();
}

#[tauri::command]
fn clear_ip_filter(monitor: tauri::State<'_, Monitor>) {
    monitor.clear_filter_ipv4();
}

/// Save a bounded XML history file. The frontend uses the dialog plugin to
/// pick the destination before invoking this.
#[tauri::command]
fn export_history(
    path: String,
    period: Option<ExportPeriod>,
    monitor: tauri::State<'_, Monitor>,
) -> Result<(), String> {
    monitor
        .export_history(Path::new(&path), period.unwrap_or(ExportPeriod::Hour))
        .map_err(|e| e.to_string())
}

// ---------- Bootstrap -----------------------------------------------------

fn pick_default_iface() -> String {
    let interfaces = available_interfaces();
    let is_up = |iface: &String| {
        std::fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
            .map(|s| {
                let t = s.trim();
                t == "up" || t == "unknown"
            })
            .unwrap_or(false)
    };
    interfaces
        .iter()
        .find(|i| i.as_str() != "lo" && is_up(i))
        .or_else(|| interfaces.iter().find(|i| i.as_str() != "lo"))
        .or_else(|| interfaces.first())
        .cloned()
        .unwrap_or_else(|| "lo".to_string())
}

fn archive_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("NETFLOW_ARCHIVE_DIR") {
        return PathBuf::from(custom);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/netflow/archive");
    }
    PathBuf::from("/tmp/netflow-archive")
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let iface = pick_default_iface();
    let archive = archive_dir();

    let monitor = runtime.block_on(async {
        Monitor::new(MonitorConfig {
            interface: iface.clone(),
            archive_dir: archive.clone(),
            history_buckets: 60,
            proc_history_len: 30,
        })
        .await
    });

    let monitor = match monitor {
        Ok(m) => m,
        Err(e) => {
            eprintln!("\nfatal: could not start eBPF monitor: {e:#}");
            eprintln!("\nThis app needs CAP_BPF / CAP_NET_ADMIN. Run with:");
            eprintln!("    sudo -E ./netflow");
            eprintln!("or grant caps to the binary:");
            eprintln!("    sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./netflow");
            std::process::exit(1);
        }
    };

    log::info!(
        "monitor running on interface '{}', archive dir = {}",
        iface,
        archive.display()
    );

    // Keep the tokio runtime alive for the lifetime of the Tauri app so
    // the ringbuf reader / archiver / geo worker tasks keep ticking.
    let _runtime_guard = runtime;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(monitor)
        .invoke_handler(tauri::generate_handler![
            get_network_snapshot,
            list_interfaces,
            get_filter_state,
            set_filter_mode,
            add_filter_pid,
            remove_filter_pid,
            add_filter_ip,
            remove_filter_ip,
            clear_pid_filter,
            clear_ip_filter,
            export_history,
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri app");
}
