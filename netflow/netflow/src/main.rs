//! Demo binary: starts a Monitor and prints a snapshot every N seconds.
//! The same `Monitor` API is meant to be wrapped in a Tauri command later;
//! see the example in `lib.rs` doc comments.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::signal;

use netflow::{Monitor, MonitorConfig, MonitorSnapshot};

#[derive(Parser, Debug)]
struct Opt {
    /// Interface to attach XDP to.
    #[clap(short, long, default_value = "lo")]
    iface: String,

    /// Snapshot interval in seconds.
    #[clap(short = 'n', long, default_value = "5")]
    interval: u64,

    /// Where the per-snapshot XML archives go.
    #[clap(short, long, default_value = "/tmp/netflow-archive")]
    archive_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = Opt::parse();

    let monitor = Monitor::new(MonitorConfig {
        interface: opt.iface.clone(),
        archive_dir: opt.archive_dir.clone(),
        history_buckets: 60,
        proc_history_len: 30,
    })
    .await?;

    println!(
        "netflow attached on {} | snapshot every {}s | archives -> {}",
        monitor.interface(),
        opt.interval,
        opt.archive_dir.display()
    );
    println!("Ctrl-C to exit.");

    let mut tick = tokio::time::interval(Duration::from_secs(opt.interval));
    tick.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\nexiting...");
                break;
            }
            _ = tick.tick() => {
                let snap = monitor.snapshot();
                print_summary(&snap);
            }
        }
    }

    Ok(())
}

fn print_summary(s: &MonitorSnapshot) {
    println!("\n=== {} ===", chrono::Local::now().format("%H:%M:%S"));
    println!(
        "iface={}  rx={:>9.0} B/s  tx={:>9.0} B/s  today rx={:.2} MB tx={:.2} MB  up={}s",
        s.interface_name,
        s.received_rate,
        s.sent_rate,
        s.received_today / 1_000_000.0,
        s.sent_today / 1_000_000.0,
        s.uptime_seconds,
    );

    println!("processes ({}):", s.processes.len());
    for p in s.processes.iter().take(8) {
        println!(
            "  [{:>6}] {:<22} {:<10} {:<6} rx={:>10} tx={:>10}  threads={}",
            p.pid,
            truncate(&p.name, 22),
            truncate(&p.user, 10),
            p.protocol,
            p.received as u64,
            p.sent as u64,
            p.threads.len(),
        );
    }

    println!("connections ({}):", s.connections.len());
    for c in s.connections.iter().take(8) {
        println!(
            "  {:<22} :{:<5} {:<6} pid={:<6} state={:<12} rx={:>8} tx={:>8}",
            truncate(&c.remote, 22),
            c.port,
            c.protocol,
            c.pid,
            c.state,
            c.received as u64,
            c.sent as u64,
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
