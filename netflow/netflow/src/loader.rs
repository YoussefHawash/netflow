//! Loads the embedded eBPF object, attaches XDP to the requested interface
//! and the egress kprobes to `tcp_sendmsg` / `udp_sendmsg`, then returns
//! ownership of the events ring buffer to the caller.

use anyhow::{Context, Result};
use aya::{
    maps::RingBuf,
    programs::{KProbe, Xdp, XdpFlags},
    Ebpf,
};

pub fn load(interface: &str) -> Result<(Ebpf, RingBuf<aya::maps::MapData>)> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netflow"
    )))
    .context("loading embedded eBPF object")?;

    // XDP ingress.
    let xdp: &mut Xdp = ebpf
        .program_mut("netflow")
        .context("xdp program 'netflow' missing from object")?
        .try_into()?;
    xdp.load().context("loading xdp program")?;
    xdp.attach(interface, XdpFlags::default())
        .or_else(|_| xdp.attach(interface, XdpFlags::SKB_MODE))
        .with_context(|| format!("attaching XDP to {interface}"))?;

    // Egress kprobes.
    for sym in ["tcp_sendmsg", "udp_sendmsg"] {
        let kp: &mut KProbe = ebpf
            .program_mut(sym)
            .with_context(|| format!("kprobe program '{sym}' missing from object"))?
            .try_into()?;
        kp.load().with_context(|| format!("loading kprobe {sym}"))?;
        kp.attach(sym, 0)
            .with_context(|| format!("attaching kprobe to {sym}"))?;
    }

    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("EVENTS ring buffer not found")?,
    )?;

    Ok((ebpf, ring_buf))
}
