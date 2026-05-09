#![no_std]

// This file defines common data structures and constants for NetFlow

pub const MAX_REMOTE_BYTES: usize = 16;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetProto {
    Unknown = 0,
    IPv4 = 1,
    IPv6 = 2,
    Arp = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Proto {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    IcmpV4 = 3,
    IcmpV6 = 4,
}

impl NetProto {
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::IPv4,
            2 => Self::IPv6,
            3 => Self::Arp,
            _ => Self::Unknown,
        }
    }
}

impl L4Proto {
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Tcp,
            2 => Self::Udp,
            3 => Self::IcmpV4,
            4 => Self::IcmpV6,
            _ => Self::Unknown,
        }
    }
}

pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    pub ts_ns: u64,
    pub size: u32,
    pub pid: u32,
    pub ifindex: u32,
    pub remote: [u8; MAX_REMOTE_BYTES],
    pub remote_port: u16,
    pub local_port: u16,
    pub net_proto: u8,
    pub l4_proto: u8,
    pub direction: u8,
    pub is_ipv6: u8,
    pub _pad: [u8; 4],
}

impl PacketEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}
