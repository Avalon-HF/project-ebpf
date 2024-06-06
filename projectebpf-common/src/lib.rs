#![no_std]

pub mod vmlinux;

// use aya_bpf::bindings::bpf_stack_build_id;
use aya_ebpf_bindings::bindings::bpf_stack_build_id;
use network_types::{
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use vmlinux::trace_entry;

pub const MAX_STACK_RAWTP: usize = 100;
#[repr(C)]
pub struct StackTraceT {
    pub pid: u64,
    pub kern_stack_size: i64,
    pub user_stack_size: i64,
    pub user_stack_buildid_size: i64,
    pub kern_stack: [u64; MAX_STACK_RAWTP],
    pub user_stack: [u64; MAX_STACK_RAWTP],
    pub user_stack_buildid: [bpf_stack_build_id; MAX_STACK_RAWTP * 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketData {
    pub pid: u32,
    pub tgid: u32,
    pub reason: u32,
    pub data_len: u32,
    pub protocol: u16,
    pub ipv4_hdr: Option<Ipv4Hdr>,
    pub ipv6_hdr: Option<Ipv6Hdr>,
    pub tcp_hdr: Option<TcpHdr>,
    pub udp_hdr: Option<UdpHdr>,
    pub data: [u8; 1500],
}
