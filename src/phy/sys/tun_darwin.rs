// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
use crate::phy::sys::{Recvmmsg, Sendmmsg};
use libc::*;
use std::io;
use std::io::{Error, Read, Result};
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::null_mut;

const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";
const MSG_DONTWAIT: c_int = 0x80;

#[repr(C)]
pub struct ctl_info {
    pub ctl_id: u32,
    pub ctl_name: [c_uchar; 96],
}

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

#[repr(C)]
pub struct msghdr_x {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: c_int,
    pub msg_control: *mut c_void,
    pub msg_controllen: socklen_t,
    pub msg_flags: c_int,
    pub msg_datalen: size_t,
}

extern "C" {
    pub fn recvmsg_x(fd: c_int, msg: *mut msghdr_x, cnt: c_uint, flags: c_int) -> ssize_t;
    pub fn sendmsg_x(fd: c_int, msg: *mut msghdr_x, cnt: c_uint, flags: c_int) -> ssize_t;
}

const CTLIOCGINFO: u64 = 0x0000_0000_c064_4e03;
const SIOCGIFMTU: u64 = 0x0000_0000_c020_6933;

#[derive(Default, Debug)]
pub struct TunSocket {
    pub fd: RawFd,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// On Darwin tunnel can only be named utunXXX
pub fn parse_utun_name(name: &str) -> Result<u32> {
    if !name.starts_with("utun") {
        return Err(io::ErrorKind::NotFound.into());
    }

    match name.get(4..) {
        None | Some("") => {
            // The name is simply "utun"
            Ok(0)
        }
        Some(idx) => {
            // Everything past utun should represent an integer index
            idx.parse::<u32>()
                .map_err(|_| io::ErrorKind::NotFound.into())
                .map(|x| x + 1)
        }
    }
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket> {
        let idx = parse_utun_name(name)?;

        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::last_os_error()),
            fd => fd,
        };

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        info.ctl_name[..CTRL_NAME.len()].copy_from_slice(CTRL_NAME);

        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut ctl_info) } < 0 {
            unsafe { close(fd) };
            return Err(Error::last_os_error());
        }

        let addr = sockaddr_ctl {
            sc_len: size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: idx,
            sc_reserved: Default::default(),
        };

        if unsafe {
            connect(
                fd,
                &addr as *const sockaddr_ctl as _,
                size_of_val(&addr) as _,
            )
        } < 0
        {
            unsafe { close(fd) };
            return Err(Error::last_os_error());
        }

        let socket = TunSocket { fd };
        socket.set_non_blocking()
    }

    pub fn name(&self) -> Result<String> {
        let mut tunnel_name = [0u8; 256];
        let mut tunnel_name_len: socklen_t = tunnel_name.len() as u32;
        if unsafe {
            getsockopt(
                self.fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                tunnel_name.as_mut_ptr() as _,
                &mut tunnel_name_len,
            )
        } < 0
            || tunnel_name_len == 0
        {
            return Err(Error::last_os_error());
        }

        Ok(String::from_utf8_lossy(&tunnel_name[..(tunnel_name_len - 1) as usize]).to_string())
    }

    pub fn set_non_blocking(self) -> Result<TunSocket> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::last_os_error()),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::last_os_error()),
                _ => Ok(self),
            },
        }
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::last_os_error()),
            fd => fd,
        };

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU, &ifr) } < 0 {
            return Err(Error::last_os_error());
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    fn sendmmsg_af(&self, bufs: &mut [&mut [u8]], af: u8) -> Result<usize> {
        let mut msgp = Vec::with_capacity(bufs.len());
        let mut hdr = [0u8, 0u8, 0u8, af as u8];

        for buf in bufs {
            let mut iov = [
                iovec {
                    iov_base: hdr.as_mut_ptr() as _,
                    iov_len: hdr.len(),
                },
                iovec {
                    iov_base: buf.as_mut_ptr() as _,
                    iov_len: buf.len(),
                },
            ];

            let msg_hdr = msghdr_x {
                msg_name: null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iov[0],
                msg_iovlen: iov.len() as _,
                msg_control: null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
            msgp.push(msg_hdr);
        }

        match unsafe { sendmsg_x(self.fd, msgp.as_mut_ptr(), msgp.len() as u32, MSG_DONTWAIT) } {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl Sendmmsg for TunSocket {
    fn sendmmsg(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        self.sendmmsg_af(bufs, AF_INET as u8)
    }
}

impl Recvmmsg for TunSocket {
    fn recvmmsg(&self, bufs: &mut [&mut [u8]]) -> Result<Vec<usize>> {
        let mut msgp = Vec::with_capacity(bufs.len());
        let mut hdr = [0u8; 4];

        for buf in bufs {
            let mut iov = [
                iovec {
                    iov_base: hdr.as_mut_ptr() as _,
                    iov_len: hdr.len(),
                },
                iovec {
                    iov_base: buf.as_mut_ptr() as _,
                    iov_len: buf.len(),
                },
            ];

            let msg_hdr = msghdr_x {
                msg_name: null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iov[0],
                msg_iovlen: iov.len() as _,
                msg_control: null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
            msgp.push(msg_hdr);
        }

        let cnt =
            match unsafe { recvmsg_x(self.fd, msgp.as_mut_ptr(), msgp.len() as u32, MSG_DONTWAIT) }
            {
                -1 => return Err(io::Error::last_os_error()),
                n => n as usize,
            };

        Ok(msgp
            .iter()
            .take(cnt)
            .map(|msg| {
                if msg.msg_datalen > 4 {
                    msg.msg_datalen - 4
                } else {
                    0
                }
            })
            .collect())
    }
}
