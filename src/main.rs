mod phy;

use crate::phy::TunSocket;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::{IpVersion, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use sysconfig::setup_ip;
use tokio::runtime;

fn main() {
    let mut rt = runtime::Builder::new()
        .enable_io()
        .basic_scheduler()
        .core_threads(1)
        .max_threads(1)
        .build()
        .expect("rt");
    rt.block_on(async {
        let tun_socket = TunSocket::new("utun");
        let tun_name = tun_socket.name();
        if cfg!(target_os = "macos") {
            setup_ip(tun_name, "10.0.1.1", "10.0.1.0/24");
        } else {
            setup_ip(tun_name, "10.0.1.1/24", "10.0.1.0/24");
        }

        for i in 0..10 {
            thread::spawn(move || {
                let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
                sleep(Duration::from_secs(1));
                loop {
                    socket.send_to(b"hello", "10.0.1.1:1000".parse::<SocketAddr>().unwrap());
                }
            });
        }

        let mut buf1 = vec![0; 1024];
        let mut buf2 = vec![0; 1024];
        let mut bufs = vec![buf1.as_mut_slice(), buf2.as_mut_slice()];

        // task::spawn(async {
        //     let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        //     task::sleep(Duration::from_secs(3)).await;
        //     loop {
        //         socket
        //             .send_to(b"hello", "10.0.1.1:1000".parse::<SocketAddr>().unwrap())
        //             .await
        //             .unwrap();
        //         println!("send packet");
        //     }
        // });
        // task::spawn(async {
        //     let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        //     task::sleep(Duration::from_secs(3)).await;
        //     loop {
        //         socket
        //             .send_to(b"hello", "10.0.1.1:1000".parse::<SocketAddr>().unwrap())
        //             .await
        //             .unwrap();
        //         println!("send packet");
        //     }
        // });
        // task::spawn(async {
        //     let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        //     task::sleep(Duration::from_secs(3)).await;
        //     loop {
        //         socket
        //             .send_to(b"hello", "10.0.1.1:1000".parse::<SocketAddr>().unwrap())
        //             .await
        //             .unwrap();
        //         println!("send packet");
        //     }
        // });
        loop {
            let sizes = tun_socket
                .recvmmsg(bufs.as_mut_slice())
                .await
                .expect("recvmmsg");

            // dbg!(&sizes);

            // process ipv4 only
            for (i, size) in sizes.into_iter().enumerate() {
                let buf = &bufs[i];
                if !(size > 0
                    && IpVersion::of_packet(&buf[..size]).expect("parse") == IpVersion::Ipv4)
                {
                    continue;
                }

                let ipv4_packet = Ipv4Packet::new_unchecked(&buf[..size]);
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &ChecksumCapabilities::default())
                    .expect("parse packet");
                assert_eq!(ipv4_repr.protocol, IpProtocol::Udp);
                let udp_packet = UdpPacket::new_unchecked(&buf[ipv4_repr.buffer_len()..size]);
                let udp_repr = UdpRepr::parse(
                    &udp_packet,
                    &ipv4_repr.src_addr.into(),
                    &ipv4_repr.dst_addr.into(),
                    &ChecksumCapabilities::default(),
                )
                .unwrap();
                // dbg!(udp_repr.payload);
            }
        }
    });
}
