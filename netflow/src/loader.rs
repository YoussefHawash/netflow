use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, MapData, RingBuf},
    programs::{
        tc::{self, SchedClassifierLinkId},
        xdp::XdpLinkId,
        KProbe, SchedClassifier, TcAttachType, TcError, Xdp, XdpFlags,
    },
    Ebpf,
};

use crate::filter::FilterMaps;

pub struct LoadedPrograms {
    pub ebpf: Ebpf,
    pub events: RingBuf<MapData>,
    pub xdp_link: XdpLinkId,
    pub tc_egress_link: SchedClassifierLinkId,
    pub filter: FilterMaps,
}

pub fn load(interface: &str) -> Result<LoadedPrograms> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netflow"
    )))
    .context("loading embedded eBPF object")?;

    // xdp
    let xdp: &mut Xdp = ebpf
        .program_mut("netflow")
        .context("xdp program 'netflow' missing from object")?
        .try_into()?;
    xdp.load().context("loading xdp program")?;
    let xdp_link = attach_xdp(xdp, interface)?;

    // tc egress
    let tc_egress: &mut SchedClassifier = ebpf
        .program_mut("netflow_egress")
        .context("tc program 'netflow_egress' missing from object")?
        .try_into()?;
    tc_egress.load().context("loading tc egress program")?;
    let tc_egress_link = attach_tc_egress(tc_egress, interface)?;

    // kprobes
    for sym in ["tcp_sendmsg", "udp_sendmsg"] {
        let kp: &mut KProbe = ebpf
            .program_mut(sym)
            .with_context(|| format!("kprobe program '{sym}' missing from object"))?
            .try_into()?;
        kp.load().with_context(|| format!("loading kprobe {sym}"))?;
        kp.attach(sym, 0)
            .with_context(|| format!("attaching kprobe to {sym}"))?;
    }

    let events = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("EVENTS ring buffer not found")?,
    )?;

    let mode = Array::<MapData, u32>::try_from(
        ebpf.take_map("FILTER_MODE")
            .context("FILTER_MODE map not found")?,
    )?;
    let pids = HashMap::<MapData, u32, u8>::try_from(
        ebpf.take_map("FILTER_PIDS")
            .context("FILTER_PIDS map not found")?,
    )?;
    let ipv4 = HashMap::<MapData, u32, u8>::try_from(
        ebpf.take_map("FILTER_IPS_V4")
            .context("FILTER_IPS_V4 map not found")?,
    )?;

    let filter = FilterMaps::new(mode, pids, ipv4);

    Ok(LoadedPrograms {
        ebpf,
        events,
        xdp_link,
        tc_egress_link,
        filter,
    })
}

pub fn attach_xdp(xdp: &mut Xdp, interface: &str) -> Result<XdpLinkId> {
    xdp.attach(interface, XdpFlags::default())
        .or_else(|_| xdp.attach(interface, XdpFlags::SKB_MODE))
        .with_context(|| format!("attaching XDP to {interface}"))
}

pub fn attach_tc_egress(
    classifier: &mut SchedClassifier,
    interface: &str,
) -> Result<SchedClassifierLinkId> {
    ensure_clsact(interface)?;
    classifier
        .attach(interface, TcAttachType::Egress)
        .with_context(|| format!("attaching TC egress to {interface}"))
}

fn ensure_clsact(interface: &str) -> Result<()> {
    match tc::qdisc_add_clsact(interface) {
        Ok(()) | Err(TcError::AlreadyAttached) => Ok(()),
        Err(error) => Err(error).with_context(|| format!("adding clsact qdisc to {interface}")),
    }
}
