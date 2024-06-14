#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_stack, bpf_get_stackid, bpf_map_lookup_elem,
        bpf_map_update_elem, bpf_probe_read, bpf_probe_read_buf, bpf_ringbuf_reserve,
        bpf_skb_load_bytes_relative,
    },
    macros::{btf_tracepoint, kprobe, map, tracepoint, xdp},
    maps::{stack, stack_trace, Array, HashMap, PerCpuArray, PerfEventArray, RingBuf, StackTrace},
    memcpy,
    programs::{sk_buff, tp_btf, BtfTracePointContext, ProbeContext, TracePointContext, XdpContext},
    EbpfContext, // macros::btf_tracepoint,
                 // programs::BtfTracePointContext,
};
use aya_ebpf_bindings::{
    bindings::{__u32, __u64, bpf_stack_build_id, BPF_ANY, BPF_F_USER_BUILD_ID, BPF_F_USER_STACK},
    helpers::bpf_probe_read_str,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use projectebpf_common::{vmlinux::trace_entry, PacketData, MAX_STACK_RAWTP};

#[tracepoint]
pub fn projectebpf(ctx: TracePointContext) -> u32 {
    match try_projectebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "tcp_drop_ring_map")]
static mut RINGBUF_MAP: RingBuf = RingBuf::with_byte_size(4096, 0);

#[tracepoint(category = "skb", name = "kfree_skb")]
pub fn kfree_skb(ctx: TracePointContext) -> u32 {
    match try_kfree_skb(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[btf_tracepoint(function = "kfree_skb")]
pub fn btf_kfree_skb(ctx: BtfTracePointContext) -> u32 {
    match btf_try_kfree_skb(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[xdp] //
pub fn xdp_hello(ctx: XdpContext) -> u32 {
    //
    match unsafe { try_xdp_hello(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// #[btf_tracepoint(function="kfree_skb_reason")]
// pub fn kfree_skb_reason(ctx: BtfTracePointContext) -> i32 {
//     match try_kfree_skb_reason(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// fn try_kfree_skb_reason(ctx: BtfTracePointContext) -> Result<i32, i32> {
//     info!(&ctx, "tracepoint kfree_skb_reason called");
//     Ok(0)
// }

#[kprobe(function = "kfree_skb_reason")]
pub fn tcp_drop(ctx: ProbeContext) -> u32 {
    match try_tcp_drop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kfree_skb(ctx: TracePointContext) -> Result<u32, ()> {
    // info!(&ctx, "kernal function kfree_skb called");
    let pid = ctx.pid();
    let tgid = ctx.tgid();
    // let command=ctx.command().unwrap_or_default();
    let raw = ctx
        .as_ptr()
        .cast::<projectebpf_common::vmlinux::trace_event_raw_kfree_skb>();
    // unsafe {
    let trace_kfree = unsafe { bpf_probe_read(raw).unwrap() };
    //  let trace_kfree= raw.read();
    // let reason = trace_kfree.reason;
    let sk_buff = trace_kfree
        .skbaddr
        .cast::<projectebpf_common::vmlinux::sk_buff>();
    let sk_buff = unsafe { bpf_probe_read(sk_buff).unwrap() };
    let headers = unsafe { sk_buff.__bindgen_anon_5.headers.as_ref() };
    let protocol = headers.protocol;
    // 获取 network_header 偏移量
    let network_header_offset = headers.network_header as usize;
    let data_len = sk_buff.data_len;
    // let mac_header = headers.mac_header;
    let mac_len = sk_buff.mac_len;

    // 获取 head 和 mac_header 偏移量
    let head = sk_buff.head as *const u8;
    // let data_porint_len = sk_buff.data as usize - sk_buff.tail as usize;
    let mac_header_offset = headers.mac_header as usize;
    let transport_header_offset = headers.transport_header as usize;


    // 计算 MAC 头部指针
    let mac_header_ptr = unsafe { head.add(mac_header_offset) } as *const EthHdr;

    // 读取以太网头部
    let eth_hdr = unsafe { bpf_probe_read(mac_header_ptr).unwrap() };

    // 根据协议类型处理不同的逻辑
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            info!(&ctx, "kernal This is an IPv4 packet.");
            if let Some(mut entry) = unsafe { RINGBUF_MAP.reserve::<PacketData>(0) } {
                // 处理 IPv4 协议的逻辑
                let packet_data: *mut PacketData = entry.as_mut_ptr();

                // 计算网络层头部指针
                let network_header_ptr =
                    unsafe { head.add(network_header_offset) } as *const Ipv4Hdr;

                // 读取 IPv4 头部
                let ipv4_hdr = unsafe { bpf_probe_read(network_header_ptr).unwrap() };

                // 读取数据
                let data_ptr = sk_buff.data as *mut u8;
                if transport_header_offset > 0 {
                    let transport_head_ptr = unsafe { head.add(transport_header_offset) };
                    match ipv4_hdr.proto {
                        IpProto::Tcp => {
                            let transport_head_ptr = transport_head_ptr as *const TcpHdr;
                            unsafe {
                                (*packet_data).tcp_hdr =
                                    Some(bpf_probe_read(transport_head_ptr).unwrap());
                                (*packet_data).udp_hdr = None;
                            }
                        }
                        IpProto::Udp => {
                            let transport_head_ptr = transport_head_ptr as *const UdpHdr;
                            unsafe {
                                (*packet_data).tcp_hdr = None;
                                (*packet_data).udp_hdr =
                                    Some(bpf_probe_read(transport_head_ptr).unwrap());
                            }
                        }

                        _ => {}
                    }
                }
                // 将数据写入 Ring Buffer
                unsafe {
                    (*packet_data).tgid = tgid;
                    (*packet_data).pid = pid;
                    // (*packet_data).reason = reason;
                    (*packet_data).data_len = data_len;
                    (*packet_data).protocol = protocol;
                    (*packet_data).ipv4_hdr = Some(ipv4_hdr);
                    (*packet_data).ipv6_hdr = None;
                    bpf_probe_read_buf(data_ptr, (*packet_data).data.as_mut()).unwrap();
                }
                entry.submit(0);
            }
        }
        EtherType::Ipv6 => {
            info!(&ctx, "kernal This is an IPv6 packet.");
            let network_header_offset = headers.network_header as usize;
            let network_header_ptr = unsafe { head.add(network_header_offset) };

            // 处理 IPv6 协议的逻辑
            let ipv6_hdr = unsafe { bpf_probe_read(network_header_ptr as *const Ipv6Hdr).unwrap() };
            // let src_addr = unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 };
            // let dst_addr = unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr8 };
            let data_ptr = sk_buff.data as *mut u8;
            // 将数据写入 Ring Buffer
            if let Some(mut entry) = unsafe { RINGBUF_MAP.reserve::<PacketData>(0) } {
                // *entry = mem::MaybeUninit::new(packet_data);
                unsafe {
                    let packet_data: *mut PacketData = entry.as_mut_ptr();
                    // (*packet_data).reason = reason;
                    (*packet_data).data_len = data_len;
                    (*packet_data).protocol = protocol;
                    (*packet_data).ipv4_hdr = None;
                    (*packet_data).ipv6_hdr = Some(ipv6_hdr);
                    bpf_probe_read_buf(data_ptr, (*packet_data).data.as_mut()).unwrap();
                }

                entry.submit(0);
            }
        }
        EtherType::Arp => {
            info!(&ctx, "kernal This is an ARP packet.");
            // 处理 ARP 协议的逻辑 因为不太关注这个所以暂时忽略
        }
        _ => {
            info!(&ctx, "kernal This is an unknown protocol {} ",protocol);
            // 处理其他情况
        } // };
    }
    Ok(0)
}


fn btf_try_kfree_skb(ctx: BtfTracePointContext) -> Result<u32, ()> {
    info!(&ctx, "kernal function kfree_skb called");
    let pid = ctx.pid();
    let tgid = ctx.tgid();
    // let command=ctx.command().unwrap_or_default();
    let raw = ctx
        .as_ptr()
        .cast::<projectebpf_common::vmlinux::trace_event_raw_kfree_skb>();
    // unsafe {
    let trace_kfree = unsafe { bpf_probe_read(raw).unwrap() };
    //  let trace_kfree= raw.read();
    // let reason = trace_kfree.reason;
    let sk_buff = trace_kfree
        .skbaddr
        .cast::<projectebpf_common::vmlinux::sk_buff>();
    let sk_buff = unsafe { bpf_probe_read(sk_buff).unwrap() };
    let headers = unsafe { sk_buff.__bindgen_anon_5.headers.as_ref() };
    let protocol = headers.protocol;
    // 获取 network_header 偏移量
    let network_header_offset = headers.network_header as usize;
    let data_len = sk_buff.data_len;
    // let mac_header = headers.mac_header;
    let mac_len = sk_buff.mac_len;

    // 获取 head 和 mac_header 偏移量
    let head = sk_buff.head as *const u8;
    // let data_porint_len = sk_buff.data as usize - sk_buff.tail as usize;
    let mac_header_offset = headers.mac_header as usize;
    let transport_header_offset = headers.transport_header as usize;


    // 计算 MAC 头部指针
    let mac_header_ptr = unsafe { head.add(mac_header_offset) } as *const EthHdr;

    // 读取以太网头部
    let eth_hdr = unsafe { bpf_probe_read(mac_header_ptr).unwrap() };

    // 根据协议类型处理不同的逻辑
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            info!(&ctx, "kernal This is an IPv4 packet.");
            if let Some(mut entry) = unsafe { RINGBUF_MAP.reserve::<PacketData>(0) } {
                // 处理 IPv4 协议的逻辑
                let packet_data: *mut PacketData = entry.as_mut_ptr();

                // 计算网络层头部指针
                let network_header_ptr =
                    unsafe { head.add(network_header_offset) } as *const Ipv4Hdr;

                // 读取 IPv4 头部
                let ipv4_hdr = unsafe { bpf_probe_read(network_header_ptr).unwrap() };

                // 读取数据
                let data_ptr = sk_buff.data as *mut u8;
                if transport_header_offset > 0 {
                    let transport_head_ptr = unsafe { head.add(transport_header_offset) };
                    match ipv4_hdr.proto {
                        IpProto::Tcp => {
                            let transport_head_ptr = transport_head_ptr as *const TcpHdr;
                            unsafe {
                                (*packet_data).tcp_hdr =
                                    Some(bpf_probe_read(transport_head_ptr).unwrap());
                                (*packet_data).udp_hdr = None;
                            }
                        }
                        IpProto::Udp => {
                            let transport_head_ptr = transport_head_ptr as *const UdpHdr;
                            unsafe {
                                (*packet_data).tcp_hdr = None;
                                (*packet_data).udp_hdr =
                                    Some(bpf_probe_read(transport_head_ptr).unwrap());
                            }
                        }

                        _ => {}
                    }
                }
                // 将数据写入 Ring Buffer
                unsafe {
                    (*packet_data).tgid = tgid;
                    (*packet_data).pid = pid;
                    // (*packet_data).reason = reason;
                    (*packet_data).data_len = data_len;
                    (*packet_data).protocol = protocol;
                    (*packet_data).ipv4_hdr = Some(ipv4_hdr);
                    (*packet_data).ipv6_hdr = None;
                    bpf_probe_read_buf(data_ptr, (*packet_data).data.as_mut()).unwrap();
                }
                entry.submit(0);
            }
        }
        EtherType::Ipv6 => {
            info!(&ctx, "kernal This is an IPv6 packet.");
            let network_header_offset = headers.network_header as usize;
            let network_header_ptr = unsafe { head.add(network_header_offset) };

            // 处理 IPv6 协议的逻辑
            let ipv6_hdr = unsafe { bpf_probe_read(network_header_ptr as *const Ipv6Hdr).unwrap() };
            // let src_addr = unsafe { ipv6_hdr.src_addr.in6_u.u6_addr8 };
            // let dst_addr = unsafe { ipv6_hdr.dst_addr.in6_u.u6_addr8 };
            let data_ptr = sk_buff.data as *mut u8;
            // 将数据写入 Ring Buffer
            if let Some(mut entry) = unsafe { RINGBUF_MAP.reserve::<PacketData>(0) } {
                // *entry = mem::MaybeUninit::new(packet_data);
                unsafe {
                    let packet_data: *mut PacketData = entry.as_mut_ptr();
                    // (*packet_data).reason = reason;
                    (*packet_data).data_len = data_len;
                    (*packet_data).protocol = protocol;
                    (*packet_data).ipv4_hdr = None;
                    (*packet_data).ipv6_hdr = Some(ipv6_hdr);
                    bpf_probe_read_buf(data_ptr, (*packet_data).data.as_mut()).unwrap();
                }

                entry.submit(0);
            }
        }
        EtherType::Arp => {
            info!(&ctx, "kernal This is an ARP packet.");
            // 处理 ARP 协议的逻辑 因为不太关注这个所以暂时忽略
        }
        _ => {
            info!(&ctx, "kernal This is an unknown protocol {} ",protocol);
            // 处理其他情况
        } // };
    }
    Ok(0)
}

fn try_tcp_drop(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function tcp_drop called");
    let pid = ctx.pid();
    let command = ctx.command().unwrap_or_default();
    // let sk_buff:Option<*const sk_buff>=ctx.arg(0);
    // aya_ebpf::programs::sk_buff::new(sk_buff.unwrap());
    let reason: Option<aya_ebpf::cty::c_uint> = ctx.arg(1);
    let reason = reason.unwrap_or_default();
    // ctx.
    // // bpf_probe_read_str(dst, size, unsafe_ptr)
    // // str::from_utf8(command).unwrap();
    // // let s="";
    // let command=core::str::from_utf8(&command).unwrap();
    // let reason:=ctx.arg(1);
    info!(
        &ctx,
        "pid:{},reason:{},command:{} ", pid, reason, command[0],
    );
    Ok(0)
}

unsafe fn try_xdp_hello(ctx: XdpContext) -> Result<u32, u32> {
    //
    info!(&ctx, "received a packet");
    //
    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
#[derive(Debug)]
struct SysExitMmapEvent {
    addr: u64,
    total_vm: u64,
    flags: u64,
    length: u64,
    low_limit: u64,
    high_limit: u64,
    align_mask: u64,
    align_offset: u64,
}
const MAX_STACK_DEPTH: usize = 128;

// #[map]
// static STACKS: StackTrace<u32,StackTraceT> = StackTrace::with_max_entries(16384, 16384);

#[repr(C)]
#[derive(Debug)]
struct SchedSwitchArgs {
    pad: u64,
    prev_comm: [u8; TASK_COMM_LEN],
    prev_pid: i32,
    prev_prio: i32,
    prev_state: i64,
    next_comm: [u8; TASK_COMM_LEN],
    next_pid: i32,
    next_prio: i32,
}

// #[map]
// static control_map: Array<u32> = Array::with_max_entries(1, 0);
const PERF_MAX_STACK_DEPTH: u32 = 127;
const TASK_COMM_LEN: usize = 16;
const STACKMAP_SIZE: u32 = 16384;
// #[map]
// static stackid_hmap: HashMap<u32, u32> = HashMap::with_max_entries(STACKMAP_SIZE, 0);

// #[map]
// static stackmap: StackTrace = StackTrace::with_max_entries(STACKMAP_SIZE, 0);

#[map]
static stack_events: PerfEventArray<__u32> = PerfEventArray::with_max_entries(2, 0);

#[map]
static stack_amap: PerCpuArray<projectebpf_common::StackTraceT> =
    PerCpuArray::with_max_entries(1, 0);

fn try_projectebpf(ctx: TracePointContext) -> Result<u32, u32> {
    // info!(&ctx, "tracepoint sys_exit_mmap called");
    info!(&ctx, "tracepoint sys_enter called");

    let max_len = (MAX_STACK_RAWTP * core::mem::size_of::<u64>()) as u32;
    // let max_len:u32 =  100 * core::mem::size_of::<u64>()as u32;
    // let max_len:u32 =  PERF_MAX_STACK_DEPTH*3;
    let key = 0u32;
    let mut value = 1u32;

    let data = stack_amap.get_ptr_mut(key);
    if let Some(data) = data {
        unsafe {
            let data = data.as_mut().unwrap();
            let max_buildid_len =
                (MAX_STACK_RAWTP * core::mem::size_of::<bpf_stack_build_id>()) as u32;
            data.pid = bpf_get_current_pid_tgid();
            if data.pid < 0 {
                return Ok(0);
            }

            data.kern_stack_size = bpf_get_stack(
                ctx.as_ptr(),
                data.kern_stack.as_mut_ptr() as *mut c_void,
                max_len,
                0,
            );
            data.user_stack_size = bpf_get_stack(
                ctx.as_ptr(),
                data.user_stack.as_mut_ptr() as *mut c_void,
                max_len,
                BPF_F_USER_STACK.into(),
            );
            data.user_stack_buildid_size = bpf_get_stack(
                ctx.as_ptr(),
                data.user_stack_buildid.as_mut_ptr() as *mut c_void,
                max_buildid_len,
                (BPF_F_USER_STACK | BPF_F_USER_BUILD_ID).into(),
            );
            info!(&ctx, "kern_stack_size:{}", data.kern_stack_size);
            info!(&ctx, "user_stack_size:{}", data.user_stack_size);
            info!(
                &ctx,
                "user_stack_buildid_size:{}", data.user_stack_buildid_size
            );
        }
    } else {
        info!(&ctx, "not found stack_amap key")
    }
    // unsafe {
    //     let stack_id =stackmap.get_stackid(&ctx, 0);
    //     if stack_id.is_ok() {
    //         let stack_id=stack_id.unwrap();
    //         info!(&ctx,"stack_id:{}",stack_id);
    //         if stack_id<0 {
    //             return Ok(0);
    //         }
    //         let stack_id=stack_id as u32;
    //         if let Some(stack_ref) = stack_amap.get_ptr_mut(stack_id) {
    //             let si=bpf_get_stack(ctx.as_ptr(), stack_ref as *mut c_void, max_len, 0);
    //             info!(&ctx, "si:{}", si);
    //         }
    //     }else {
    //         info!(&ctx,"get stack_id err:{}",stack_id.unwrap_err());
    //     }
    // }

    // // bpf_get_stack(ctx, buf, size, flags)
    // let size = (1 * 127) as u32;
    // type StackTraceT = [u64; MAX_STACK_DEPTH];

    // // let key=bpf_get_stackid(ctx, &STACKS, 0);
    // unsafe {
    //     let mut buf = [0u64; MAX_STACK_DEPTH];
    //     let buf_ptr = buf.as_mut_ptr();
    //     unsafe { bpf_get_stack(ctx.as_ptr(), buf_ptr as *mut core::ffi::c_void, size, 0) };
    //     let buf_immutable = &buf;
    //     info!(&ctx, "stacktrace: {}", buf_immutable.len());
    // };
    // let res: Result<SysExitMmapEvent, i64> =
    //     unsafe { ctx.read_at(mem::size_of::<SysExitMmapEvent>()) };
    // // let event = unsafe { &*(ctx.as_ptr() as *const SysExitMmapEvent) };
    // if res.is_ok() {
    //     let event = res.unwrap();
    //     let addr = event.addr;
    //     let total_vm = event.total_vm;
    //     // let common_type = event.common_type;

    //     info!(&ctx, "addr: 0x{:x} ", addr);
    //     info!(&ctx, "total_vm:{}", total_vm);
    //     // info!(&ctx, "common_type:{}", common_type);
    //     // bpf_ringbuf_reserve(ringbuf, size, flags)
    //     // bpf_get_stack(ctx,)
    // }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
