#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, map, xdp},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, TcContext, XdpContext},
};

use netflow_common::{PacketEvent, DIR_IN, DIR_OUT, MAX_REMOTE_BYTES};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static FILTER_MODE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static FILTER_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static FILTER_IPS_V4: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

const ETH_HDR_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ARP: u16 = 0x0806;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const NP_UNKNOWN: u8 = 0;
const NP_IPV4: u8 = 1;
const NP_IPV6: u8 = 2;
const NP_ARP: u8 = 3;

const L4_UNKNOWN: u8 = 0;
const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const L4_ICMPV4: u8 = 3;
const L4_ICMPV6: u8 = 4;

// sock_common offsets
const SKC_DADDR_OFF: usize = 0;
const SKC_DPORT_OFF: usize = 12;
const SKC_NUM_OFF: usize = 14;
const SKC_FAMILY_OFF: usize = 16;

#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct Ipv6Hdr {
    flow_lbl: u32,
    payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C, packed)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

#[inline(always)]
fn xdp_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

#[inline(always)]
fn tc_ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

#[inline(always)]
fn submit(event: PacketEvent) {
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

#[inline(always)]
fn empty_event() -> PacketEvent {
    PacketEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        size: 0,
        pid: 0,
        ifindex: 0,
        remote: [0u8; MAX_REMOTE_BYTES],
        remote_port: 0,
        local_port: 0,
        net_proto: NP_UNKNOWN,
        l4_proto: L4_UNKNOWN,
        direction: DIR_IN,
        is_ipv6: 0,
        _pad: [0; 4],
    }
}

#[inline(always)]
fn filter_mode() -> u32 {
    FILTER_MODE.get(0).copied().unwrap_or(0)
}

#[inline(always)]
fn ipv4_listed(addr_be: u32) -> bool {
    let host = u32::from_be(addr_be);
    unsafe { FILTER_IPS_V4.get(&host).is_some() }
}

#[inline(always)]
fn pid_listed(pid: u32) -> bool {
    unsafe { FILTER_PIDS.get(&pid).is_some() }
}

#[inline(always)]
fn should_block(matched: bool) -> bool {
    match filter_mode() {
        1 => !matched,
        _ => matched,
    }
}

#[classifier]
pub fn netflow_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    let eth = tc_ptr_at::<EthHdr>(ctx, 0).ok_or(())?;
    let proto = u16::from_be(unsafe { (*eth).h_proto });

    if proto != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let ip = tc_ptr_at::<Ipv4Hdr>(ctx, ETH_HDR_LEN).ok_or(())?;
    let daddr = unsafe { (*ip).daddr };

    if should_block(ipv4_listed(daddr)) {
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_OK)
}

#[xdp]
pub fn netflow(ctx: XdpContext) -> u32 {
    match try_ingress(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0).ok_or(())?;
    let proto = u16::from_be(unsafe { (*eth).h_proto });
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let mut event = empty_event();
    event.direction = DIR_IN;
    event.ifindex = ifindex;
    match proto {
        ETH_P_IPV4 => match parse_v4(ctx, &mut event)? {
            Verdict::Drop => return Ok(xdp_action::XDP_DROP),
            Verdict::Pass => {}
        },
        ETH_P_IPV6 => parse_v6(ctx, &mut event)?,
        ETH_P_ARP => parse_arp(ctx, &mut event)?,
        _ => return Ok(xdp_action::XDP_PASS),
    }
    submit(event);
    Ok(xdp_action::XDP_PASS)
}

enum Verdict {
    Pass,
    Drop,
}

fn parse_v4(ctx: &XdpContext, ev: &mut PacketEvent) -> Result<Verdict, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, ETH_HDR_LEN).ok_or(())?;
    let saddr = unsafe { (*ip).saddr };

    if should_block(ipv4_listed(saddr)) {
        return Ok(Verdict::Drop);
    }

    let ihl = unsafe { (*ip).ihl_version } & 0x0f;
    if ihl < 5 {
        return Err(());
    }
    let ip_hdr_len = (ihl as usize) * 4;
    let tot_len = u16::from_be(unsafe { (*ip).tot_len }) as u32;
    let proto = unsafe { (*ip).protocol };

    ev.net_proto = NP_IPV4;
    ev.is_ipv6 = 0;
    ev.size = tot_len;

    let bytes = saddr.to_ne_bytes();
    ev.remote[0] = bytes[0];
    ev.remote[1] = bytes[1];
    ev.remote[2] = bytes[2];
    ev.remote[3] = bytes[3];

    parse_l4(ctx, ETH_HDR_LEN + ip_hdr_len, proto, ev, true)?;
    Ok(Verdict::Pass)
}

fn parse_v6(ctx: &XdpContext, ev: &mut PacketEvent) -> Result<(), ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, ETH_HDR_LEN).ok_or(())?;
    let payload_len = u16::from_be(unsafe { (*ip).payload_len }) as u32;
    let next = unsafe { (*ip).next_hdr };

    ev.net_proto = NP_IPV6;
    ev.is_ipv6 = 1;
    ev.size = payload_len + 40;
    ev.remote = unsafe { (*ip).saddr };

    parse_l4(ctx, ETH_HDR_LEN + 40, next, ev, true)
}
fn parse_arp(ctx: &XdpContext, ev: &mut PacketEvent) -> Result<(), ()> {
    ev.net_proto = NP_ARP;
    ev.is_ipv6 = 0;
    Ok(())
}
fn parse_l4(
    ctx: &XdpContext,
    off: usize,
    proto: u8,
    ev: &mut PacketEvent,
    is_ingress: bool,
) -> Result<(), ()> {
    match proto {
        IPPROTO_TCP => {
            let th = ptr_at::<TcpHdr>(ctx, off).ok_or(())?;
            let src = u16::from_be(unsafe { (*th).source });
            let dst = u16::from_be(unsafe { (*th).dest });
            ev.l4_proto = L4_TCP;
            if is_ingress {
                ev.remote_port = src;
                ev.local_port = dst;
            } else {
                ev.remote_port = dst;
                ev.local_port = src;
            }
        }
        IPPROTO_UDP => {
            let uh = ptr_at::<UdpHdr>(ctx, off).ok_or(())?;
            let src = u16::from_be(unsafe { (*uh).source });
            let dst = u16::from_be(unsafe { (*uh).dest });
            ev.l4_proto = L4_UDP;
            if is_ingress {
                ev.remote_port = src;
                ev.local_port = dst;
            } else {
                ev.remote_port = dst;
                ev.local_port = src;
            }
        }
        IPPROTO_ICMP => ev.l4_proto = L4_ICMPV4,
        IPPROTO_ICMPV6 => ev.l4_proto = L4_ICMPV6,
        _ => ev.l4_proto = L4_UNKNOWN,
    }
    Ok(())
}

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_egress(ctx, L4_TCP);
    0
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_egress(ctx, L4_UDP);
    0
}

fn try_egress(ctx: ProbeContext, l4: u8) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).ok_or(0i64)?;
    if size == 0 {
        return Ok(());
    }

    let family: u16 =
        unsafe { bpf_probe_read_kernel(sk.add(SKC_FAMILY_OFF) as *const u16).map_err(|_| 0i64)? };
    let dport_be: u16 =
        unsafe { bpf_probe_read_kernel(sk.add(SKC_DPORT_OFF) as *const u16).map_err(|_| 0i64)? };
    let local_port: u16 =
        unsafe { bpf_probe_read_kernel(sk.add(SKC_NUM_OFF) as *const u16).map_err(|_| 0i64)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut event = empty_event();
    event.direction = DIR_OUT;
    event.l4_proto = l4;
    event.size = size as u32;
    event.pid = pid;
    event.local_port = local_port;
    event.remote_port = u16::from_be(dport_be);

    let mut matched = pid_listed(pid);

    if family == AF_INET {
        let daddr_be: u32 = unsafe {
            bpf_probe_read_kernel(sk.add(SKC_DADDR_OFF) as *const u32).map_err(|_| 0i64)?
        };
        let bytes = daddr_be.to_ne_bytes();
        event.net_proto = NP_IPV4;
        event.is_ipv6 = 0;
        event.remote[0] = bytes[0];
        event.remote[1] = bytes[1];
        event.remote[2] = bytes[2];
        event.remote[3] = bytes[3];

        if !matched {
            matched = ipv4_listed(daddr_be);
        }
    } else if family == AF_INET6 {
        event.net_proto = NP_IPV6;
        event.is_ipv6 = 1;
    } else {
        return Ok(());
    }

    if should_block(matched) {
        return Ok(());
    }

    submit(event);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
