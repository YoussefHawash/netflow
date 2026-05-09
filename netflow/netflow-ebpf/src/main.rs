#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, xdp},
    maps::RingBuf,
    programs::{ProbeContext, XdpContext},
};

use netflow_common::{PacketEvent, DIR_IN, DIR_OUT, MAX_REMOTE_BYTES};

// ---------- Maps ------------------------------------------------------------

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // 1 MiB

// ---------- Constants -------------------------------------------------------

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ARP: u16 = 0x0806;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// netflow_common values, re-stated here so eBPF doesn't have to walk an enum.
const NP_UNKNOWN: u8 = 0;
const NP_IPV4: u8 = 1;
const NP_IPV6: u8 = 2;
const NP_ARP: u8 = 3;

const L4_UNKNOWN: u8 = 0;
const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const L4_ICMPV4: u8 = 3;
const L4_ICMPV6: u8 = 4;

// ---------- Packet header structs ------------------------------------------

#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16, // network byte order
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
    flow_lbl: u32, // version/traffic class/flow label
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

// ---------- Helpers --------------------------------------------------------

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
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

// ---------- XDP ingress ----------------------------------------------------

#[xdp]
pub fn netflow(ctx: XdpContext) -> u32 {
    let _ = try_ingress(&ctx);
    xdp_action::XDP_PASS
}

fn try_ingress(ctx: &XdpContext) -> Result<(), ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0).ok_or(())?;
    let proto = u16::from_be(unsafe { (*eth).h_proto });
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let mut event = empty_event();
    event.direction = DIR_IN;
    event.ifindex = ifindex;

    match proto {
        ETH_P_IP => parse_v4(ctx, &mut event)?,
        ETH_P_IPV6 => parse_v6(ctx, &mut event)?,
        ETH_P_ARP => {
            // ARP: report packet but no L4 info.
            event.net_proto = NP_ARP;
            // total frame size is best estimate for ARP payload
            event.size = (ctx.data_end() - ctx.data()) as u32;
            submit(event);
            return Ok(());
        }
        _ => return Ok(()),
    }

    submit(event);
    Ok(())
}

fn parse_v4(ctx: &XdpContext, ev: &mut PacketEvent) -> Result<(), ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, ETH_HDR_LEN).ok_or(())?;
    let ihl = unsafe { (*ip).ihl_version } & 0x0f;
    if ihl < 5 {
        return Err(());
    }
    let ip_hdr_len = (ihl as usize) * 4;
    let tot_len = u16::from_be(unsafe { (*ip).tot_len }) as u32;
    let saddr = unsafe { (*ip).saddr }; // network order, host treats as bytes
    let proto = unsafe { (*ip).protocol };

    ev.net_proto = NP_IPV4;
    ev.is_ipv6 = 0;
    ev.size = tot_len;
    // Remote = source on ingress.
    let bytes = saddr.to_ne_bytes();
    ev.remote[0] = bytes[0];
    ev.remote[1] = bytes[1];
    ev.remote[2] = bytes[2];
    ev.remote[3] = bytes[3];

    let l4_off = ETH_HDR_LEN + ip_hdr_len;
    parse_l4(ctx, l4_off, proto, ev, /* is_ingress */ true)
}

fn parse_v6(ctx: &XdpContext, ev: &mut PacketEvent) -> Result<(), ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, ETH_HDR_LEN).ok_or(())?;
    let payload_len = u16::from_be(unsafe { (*ip).payload_len }) as u32;
    let next = unsafe { (*ip).next_hdr };
    let saddr = unsafe { (*ip).saddr };

    ev.net_proto = NP_IPV6;
    ev.is_ipv6 = 1;
    ev.size = payload_len + 40; // IPv6 header is fixed 40 bytes
    ev.remote = saddr;

    let l4_off = ETH_HDR_LEN + 40;
    parse_l4(ctx, l4_off, next, ev, true)
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

// ---------- Egress kprobes -------------------------------------------------
//
// Both `tcp_sendmsg` and `udp_sendmsg` have signature:
//     int proto_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
//
// We read fields out of the embedded `struct sock_common` at the head of
// `struct sock`. The relevant offsets are stable across modern kernels:
//
//     offset  field            type      meaning
//     0       skc_daddr        __be32    foreign IPv4 address
//     4       skc_rcv_saddr    __be32    bound local IPv4 address
//     12      skc_dport        __be16    foreign port (network order)
//     14      skc_num          __u16     local port (host order)
//     16      skc_family       __u16     AF_INET / AF_INET6
//
// IPv6 destinations live further into struct sock at offsets that vary with
// kernel config; we report family + bytes only and let userspace correlate
// the 5-tuple via /proc/net/{tcp6,udp6} keyed on (pid, local_port).

const SKC_DADDR_OFF: usize = 0;
const SKC_DPORT_OFF: usize = 12;
const SKC_NUM_OFF: usize = 14;
const SKC_FAMILY_OFF: usize = 16;

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_send(ctx, L4_TCP);
    0
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    let _ = try_send(ctx, L4_UDP);
    0
}

fn try_send(ctx: ProbeContext, l4: u8) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let size: usize = ctx.arg(2).ok_or(0i64)?;
    if size == 0 {
        return Ok(());
    }

    let family: u16 = unsafe {
        bpf_probe_read_kernel(sk.add(SKC_FAMILY_OFF) as *const u16).map_err(|_| 0i64)?
    };
    let dport_be: u16 = unsafe {
        bpf_probe_read_kernel(sk.add(SKC_DPORT_OFF) as *const u16).map_err(|_| 0i64)?
    };
    let local_port: u16 = unsafe {
        bpf_probe_read_kernel(sk.add(SKC_NUM_OFF) as *const u16).map_err(|_| 0i64)?
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let mut event = empty_event();
    event.direction = DIR_OUT;
    event.l4_proto = l4;
    event.size = size as u32;
    event.pid = pid;
    event.local_port = local_port;
    event.remote_port = u16::from_be(dport_be);

    if family == AF_INET {
        let daddr: u32 = unsafe {
            bpf_probe_read_kernel(sk.add(SKC_DADDR_OFF) as *const u32).map_err(|_| 0i64)?
        };
        let bytes = daddr.to_ne_bytes();
        event.net_proto = NP_IPV4;
        event.is_ipv6 = 0;
        event.remote[0] = bytes[0];
        event.remote[1] = bytes[1];
        event.remote[2] = bytes[2];
        event.remote[3] = bytes[3];
    } else if family == AF_INET6 {
        // IPv6 remote address is left zero; userspace will correlate from
        // /proc/net/tcp6 / /proc/net/udp6 using (pid, local_port).
        event.net_proto = NP_IPV6;
        event.is_ipv6 = 1;
    } else {
        // Non-IP socket; ignore.
        return Ok(());
    }

    submit(event);
    Ok(())
}

// ---------- Panic / license ------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
