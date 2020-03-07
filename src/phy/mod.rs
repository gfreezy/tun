use crate::phy::sys::{Recvmmsg, Sendmmsg};
use async_std::net::driver::Watcher;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

mod sys;

pub(crate) struct TunSocket {
    mtu: usize,
    name: String,
    watcher: Watcher<sys::TunSocket>,
}

impl TunSocket {
    pub fn new(name: &str) -> TunSocket {
        let watcher = Watcher::new(sys::TunSocket::new(name).expect("TunSocket::new"));
        TunSocket {
            name: watcher.get_ref().name().expect("get name"),
            mtu: watcher.get_ref().mtu().expect("get mut"),
            watcher,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    fn poll_recvmmsg(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        bufs: &mut [&mut [u8]],
    ) -> Poll<io::Result<Vec<usize>>> {
        self.watcher
            .poll_read_with(cx, |mut inner| inner.recvmmsg(bufs))
    }

    fn poll_sendmmsg(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        bufs: &mut [&mut [u8]],
    ) -> Poll<io::Result<usize>> {
        self.watcher
            .poll_read_with(cx, |mut inner| inner.sendmmsg(bufs))
    }

    fn recvmmsg(&self, bufs: &mut [&mut [u8]]) -> RecvmmsgFuture {
        RecvmmsgFuture {
            tun_socket: self,
            bufs,
        }
    }

    fn sendmmsg(&self, bufs: &mut [&mut [u8]]) -> SendmmsgFuture {
        SendmmsgFuture {
            tun_socket: self,
            bufs,
        }
    }
}

struct RecvmmsgFuture<'a, 'b> {
    tun_socket: &'a TunSocket,
    bufs: &'b mut [&'b mut [u8]],
}

impl<'a, 'b> Future for RecvmmsgFuture<'a, 'b> {
    type Output = io::Result<Vec<usize>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.tun_socket.poll_recvmmsg(cx, self.bufs)
    }
}

struct SendmmsgFuture<'a, 'b> {
    tun_socket: &'a TunSocket,
    bufs: &'b mut [&'b mut [u8]],
}

impl<'a, 'b> Future for SendmmsgFuture<'a, 'b> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.tun_socket.poll_sendmmsg(cx, self.bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::io::timeout;
    use async_std::net::UdpSocket;
    use async_std::task;
    use async_std::task::block_on;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::*;
    use std::time::Duration;
    use sysconfig::setup_ip;

    #[test]
    fn test_recv_packets_from_tun() {
        let mut tun_socket = TunSocket::new("utun");
        let tun_name = tun_socket.name();
        if cfg!(target_os = "macos") {
            setup_ip(tun_name, "10.0.1.1", "10.0.1.0/24");
        } else {
            setup_ip(tun_name, "10.0.1.1/24", "10.0.1.0/24");
        }

        const DATA: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

        block_on(async move {
            task::spawn(async {
                task::sleep(Duration::from_secs(1)).await;
                let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                socket.send_to(&DATA, ("10.0.1.2", 9090)).await.unwrap();
            });

            let (bufs, sizes) = loop {
                let mut bufs = vec![vec![0; 1024], vec![0; 1024]];
                let sizes = tun_socket
                    .recvmmsg(&mut [&mut bufs[0], &mut bufs[1]])
                    .await
                    .unwrap();
                // process ipv4 only
                if sizes.len() > 0
                    && sizes[0] > 0
                    && IpVersion::of_packet(&bufs[0][..sizes[0]]).unwrap() == IpVersion::Ipv4
                {
                    break (bufs, sizes);
                }
            };
            let ipv4_packet = Ipv4Packet::new_unchecked(&bufs[0][..sizes[0]]);
            let ipv4_repr =
                Ipv4Repr::parse(&ipv4_packet, &ChecksumCapabilities::default()).unwrap();
            assert_eq!(ipv4_repr.protocol, IpProtocol::Udp);
            let udp_packet = UdpPacket::new_unchecked(&bufs[0][ipv4_repr.buffer_len()..sizes[0]]);
            let udp_repr = UdpRepr::parse(
                &udp_packet,
                &ipv4_repr.src_addr.into(),
                &ipv4_repr.dst_addr.into(),
                &ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!(udp_repr.dst_port, 9090);
            assert_eq!(udp_repr.payload, DATA);
        })
    }

    #[test]
    fn test_send_packets_to_tun() {
        let tun_name = "utun6";
        let mut tun_socket = TunSocket::new(tun_name);
        if cfg!(target_os = "macos") {
            setup_ip(tun_name, "10.0.3.1", "10.0.3.0/24");
        } else {
            setup_ip(tun_name, "10.0.3.1/24", "10.0.3.0/24");
        }

        let data = "hello".as_bytes();

        block_on(async move {
            let socket = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
            let handle = task::spawn(async move {
                let mut buf = vec![0; 1000];
                timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await
            });
            task::sleep(Duration::from_secs(1)).await;

            let src_addr = Ipv4Address::new(10, 0, 3, 10);
            let dst_addr = Ipv4Address::new(10, 0, 3, 1);
            let udp_repr = UdpRepr {
                src_port: 1234,
                dst_port: 1234,
                payload: &data,
            };
            let mut udp_buf = vec![0; udp_repr.buffer_len()];
            let mut udp_packet = UdpPacket::new_unchecked(&mut udp_buf);
            udp_repr.emit(
                &mut udp_packet,
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default(),
            );
            let ip_repr = Ipv4Repr {
                src_addr,
                dst_addr,
                protocol: IpProtocol::Udp,
                payload_len: udp_packet.len() as usize,
                hop_limit: 64,
            };
            let mut ip_buf = vec![0; ip_repr.buffer_len() + ip_repr.payload_len];
            let mut ip_packet = Ipv4Packet::new_unchecked(&mut ip_buf);
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            ip_buf[ip_repr.buffer_len()..].copy_from_slice(&udp_buf);
            let size = tun_socket.sendmmsg(&mut [&mut ip_buf]).await.unwrap();
            assert_eq!(size, ip_buf.len());
            let (s, _src) = handle.await.unwrap();
            assert_eq!(data.len(), s);
        })
    }
}
