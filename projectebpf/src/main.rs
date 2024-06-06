use std::sync::{Arc, Mutex};

use aya::programs::{Program, TracePoint, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use projectebpf_common::PacketData;
use tokio::{signal, spawn};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/projectebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/projectebpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // bpf.maps().for_each(|(name,map)| {

    // let mut bpf = bpf.lock().unwrap();
    bpf.programs_mut().into_iter().for_each(|(name, program)| {
        println!(
            "found program `{}` of type `{:?}`",
            name,
            program.prog_type()
        );
        match program {
            Program::TracePoint(tp) => {
                // tp.load()?;tp.attach("syscalls","sys_exit_mmap")?;
                tp.load().unwrap();
                if name == "projectebpf" {
                    // tp.attach("syscalls", "sys_exit_mmap")?;
                } else if name == "kfree_skb" {
                    tp.attach("skb", "kfree_skb").unwrap();
                }
                // tp.attach(category, name)
            }
            Program::KProbe(kp) => {
                // kp.load()?;
                // println!("load kprobe");
                // kp.attach("kfree_skb_reason", 0)?;
                // println!("attach kprobe");
            }
            Program::UProbe(_) => todo!(),
            Program::SocketFilter(_) => todo!(),
            Program::Xdp(tp) => {
                // tp.load()?;tp.attach(&opt.iface, XdpFlags::default())?;
            }
            Program::SkMsg(_) => todo!(),
            Program::SkSkb(_) => todo!(),
            Program::CgroupSockAddr(_) => todo!(),
            Program::SockOps(_) => todo!(),
            Program::SchedClassifier(_) => todo!(),
            Program::CgroupSkb(_) => todo!(),
            Program::CgroupSysctl(_) => todo!(),
            Program::CgroupSockopt(_) => todo!(),
            Program::LircMode2(_) => todo!(),
            Program::PerfEvent(_) => todo!(),
            Program::RawTracePoint(_) => todo!(),
            Program::Lsm(_) => todo!(),
            Program::BtfTracePoint(_) => {
                // let btf = Btf::from_sys_fs()?;
                // let program: &mut BtfTracePoint = bpf.program_mut("{{tracepoint_name}}").unwrap().try_into()?;
                // program.load("{{tracepoint_name}}", &btf)?;
                // program.attach()?;
            }
            Program::FEntry(_) => todo!(),
            Program::FExit(_) => todo!(),
            Program::Extension(_) => todo!(),
            Program::SkLookup(_) => todo!(),
            Program::CgroupSock(_) => todo!(),
            Program::CgroupDevice(_) => todo!(),
        }
        // program.load()?;
    });
    // let program: &mut TracePoint = bpf.program_mut("projectebpf").unwrap().try_into()?;
    // program.load()?;
    // program.attach("syscalls", "sys_exit_mmap")?;
    // let xdp: &mut Xdp = bpf.program_mut("xdp_hello").unwrap().try_into()?;
    // xdp.load()?;
    // xdp.attach(&opt.iface, XdpFlags::default())?;
    // program.attach("syscalls", "sys_enter_gettid")?;
    // program.attach("raw_syscalls", "sys_enter")?;
    // program.attach("raw_syscalls", "sys_enter")?;
    // let mut bpf_guard = bpf_clone.lock().unwrap();
    let ring_buf = bpf.take_map("tcp_drop_ring_map").unwrap();
    // let ring_buf = {
    //     // let ring_map = bpf.map("RINGBUF_MAP").unwrap();
    //     aya::maps::RingBuf::try_from(map).unwrap()
    // };
    let ring_buf = aya::maps::RingBuf::try_from(ring_buf).unwrap();

    let mut poll = tokio::io::unix::AsyncFd::new(ring_buf).unwrap();
    // let poll=Arc::new(poll);
    // let poll=poll.clone();
    let handle = spawn(async move {
        loop {
            // let mut g=poll.readable_mut().await.unwrap();
            // g.get_inner_mut().next()
            let mut guard = poll.readable_mut().await.unwrap();

            // guard.
            let ring_buf = guard.get_inner_mut();

            while let Some(item) = ring_buf.next() {
                let hdr = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketData) };
                // println!("Received: {:?}", hdr);
                //打印 PacketData 所有字段
                let mut msg = format!(
                    "user pid {:?} tgid {:?} reason:{:?} data_len:{:?} protocol:{:?}",
                    hdr.pid, hdr.tgid, hdr.reason, hdr.data_len, hdr.protocol
                );

                if let Some(ipv4_hdr) = hdr.ipv4_hdr {
                    msg += &format!(
                        " user ipv4_hdr:  Source IP: {:?} Destination IP: {:?}",
                        ipv4_hdr.src_addr(),
                        ipv4_hdr.dst_addr()
                    );
                } else if let Some(ipv6_hdr) = hdr.ipv6_hdr {
                    msg += &format!(
                        " user ipv6_hdr:  Source IP: {:?} Destination IP: {:?}",
                        ipv6_hdr.src_addr(),
                        ipv6_hdr.dst_addr(),
                    );
                }

                if let Some(tcp_hdr) = hdr.tcp_hdr {
                    msg += &format!(
                        " user tcp_hdr:  Source Port: {:?} Destination Port: {:?}",
                        tcp_hdr.source, tcp_hdr.dest
                    );
                } else if let Some(udp_hdr) = hdr.udp_hdr {
                    msg += &format!(
                        " user udp_hdr:  Source Port: {:?} Destination Port: {:?}",
                        udp_hdr.source, udp_hdr.dest,
                    );
                }

                info!("{}", msg);

                // info!("user data: {:?}", hdr.data);
                // println!("ipv6_hdr: {:?}", hdr.ipv6_hdr);
                // println!("data: {:?}", hdr.data);
                // println!("Received: {:?}", item);
            }
            guard.clear_ready();
        }
    });
    // bpf.maps_mut().into_iter().for_each(|(name,map)| {
    //     println!("found map `{}` of type `{:?}`", name,map);
    //     match map {
    //         aya::maps::Map::Array(_) => todo!(),
    //         aya::maps::Map::BloomFilter(_) => todo!(),
    //         aya::maps::Map::CpuMap(_) => todo!(),
    //         aya::maps::Map::DevMap(_) => todo!(),
    //         aya::maps::Map::DevMapHash(_) => todo!(),
    //         aya::maps::Map::HashMap(_) => todo!(),
    //         aya::maps::Map::LpmTrie(_) => todo!(),
    //         aya::maps::Map::LruHashMap(_) => todo!(),
    //         aya::maps::Map::PerCpuArray(_) => todo!(),
    //         aya::maps::Map::PerCpuHashMap(_) => todo!(),
    //         aya::maps::Map::PerCpuLruHashMap(_) => todo!(),
    //         aya::maps::Map::PerfEventArray(_) => todo!(),
    //         aya::maps::Map::ProgramArray(_) => todo!(),
    //         aya::maps::Map::Queue(_) => todo!(),
    //         aya::maps::Map::RingBuf(mapdata) => {
    //             //
    //             // let fd = ring_buf.fd();
    //             let ring_buf = {
    //                 // let ring_map = bpf.map("RINGBUF_MAP").unwrap();
    //                 aya::maps::RingBuf::try_from(map).unwrap()
    //             };
    //             let ring_buf = aya::maps::RingBuf::try_from(ring_buf).unwrap();

    //             let mut poll = tokio::io::unix::AsyncFd::new(ring_buf).unwrap();
    //             // let poll=Arc::new(poll);
    //             // let poll=poll.clone();
    //             let handle = spawn(async move {

    //                 loop {
    //                     // let mut g=poll.readable_mut().await.unwrap();
    //                     // g.get_inner_mut().next()
    //                     let mut guard = poll.readable_mut().await.unwrap();

    //                     // guard.
    //                     let ring_buf = guard.get_inner_mut();

    //                     while let Some(item) = ring_buf.next() {
    //                         println!("Received: {:?}", item);
    //                     }
    //                     guard.clear_ready();
    //                 }
    //             });
    //         },
    //         aya::maps::Map::SockHash(_) => todo!(),
    //         aya::maps::Map::SockMap(_) => todo!(),
    //         aya::maps::Map::Stack(_) => todo!(),
    //         aya::maps::Map::StackTraceMap(_) => todo!(),
    //         aya::maps::Map::Unsupported(_) => todo!(),
    //         aya::maps::Map::XskMap(_) => todo!(),
    //     }
    // });
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
