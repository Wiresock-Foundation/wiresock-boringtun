// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

const TUNSETIFF: u64 = 0x4004_54ca;
const TUNGETIFF: u64 = 0x8004_54d2;

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
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
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

impl TunSocket {
    fn write(&self, buf: &[u8]) -> usize {
        match unsafe { write(self.fd, buf.as_ptr() as _, buf.len() as _) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn new(name: &str) -> Result<TunSocket, Error> {
        // If the provided name appears to be a FD, use that.
        let provided_fd = name.parse::<i32>();
        if let Ok(fd) = provided_fd {
            return Ok(TunSocket {
                fd,
                name: name.to_string(),
            });
        }

        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };
        let iface_name = name.as_bytes();
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE) as _,
            },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let name = name.to_string();
        Ok(TunSocket { fd, name })
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(io::Error::last_os_error())),
                _ => Ok(self),
            },
        }
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// The name of the interface the TUN fd is attached to, from TUNGETIFF.
    ///
    /// Needed when the socket was built around an embedder-provided fd:
    /// `self.name` is then that fd in decimal, not an interface name that
    /// SIOCGIFMTU could resolve. Kept out of `name()`, which must keep
    /// returning the fd string -- the multi-queue path clones the socket by
    /// re-parsing it, and embedders that cannot open `/dev/net/tun` (the
    /// reason to hand over an fd at all) cannot TUNSETIFF a fresh one either.
    fn attached_interface_name(&self) -> Result<String, Error> {
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_flags: 0 },
        };

        if unsafe { ioctl(self.fd, TUNGETIFF as _, &mut ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let len = ifr
            .ifr_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(IFNAMSIZ);
        Ok(String::from_utf8_lossy(&ifr.ifr_name[..len]).to_string())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let name = if self.name.parse::<i32>().is_ok() {
            // An embedder-provided fd. This MTU sizes the read buffer and
            // clamps AmneziaWG content padding, and the monitor re-reads it
            // every second, so a fabricated value would never self-correct;
            // ask the kernel which interface the fd is attached to instead.
            // A TUNGETIFF failure means the fd is not a TUN at all, so no
            // interface can be asked: keep the pre-recovery answer of 1500
            // rather than turning such a device's construction into an error.
            match self.attached_interface_name() {
                Ok(name) => name,
                Err(_) => return Ok(1500),
            }
        } else {
            self.name.clone()
        };

        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU as _, &ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { read(self.fd, dst.as_mut_ptr() as _, dst.len()) } {
            -1 => Err(Error::IfaceRead(io::Error::last_os_error())),
            n => Ok(&mut dst[..n as usize]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream;

    /// Moves the interface MTU away from 1500, because a fresh TUN starts at
    /// exactly the value the fd path used to fabricate -- left at the default,
    /// the test below would pass with the hardcode still in place.
    fn set_mtu(name: &str, mtu: c_int) {
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(sock >= 0, "socket: {}", io::Error::last_os_error());

        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_mtu: mtu },
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());

        let ret = unsafe { ioctl(sock, SIOCSIFMTU as _, &ifr) };
        unsafe { close(sock) };
        assert!(ret >= 0, "SIOCSIFMTU: {}", io::Error::last_os_error());
    }

    /// An fd-provided TUN must report the interface's real MTU, not a
    /// fabricated 1500: the value sizes the read buffer and clamps AmneziaWG
    /// content padding, and the MTU monitor re-stores it every second, so a
    /// wrong answer here never self-corrects.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`; CI runs it via
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn an_fd_provided_tun_reports_the_real_interface_mtu() {
        let tun = TunSocket::new("utun86").unwrap();
        set_mtu("utun86", 1280);

        let fd = unsafe { dup(tun.as_raw_fd()) };
        assert!(fd >= 0, "dup: {}", io::Error::last_os_error());
        let by_fd = TunSocket::new(&fd.to_string()).unwrap();

        // The recovered name must not leak into `name()`: the multi-queue
        // clone path and the API-socket path both key off the fd string.
        assert_eq!(by_fd.name().unwrap(), fd.to_string());

        assert_eq!(by_fd.mtu().unwrap(), 1280);
    }

    /// A non-TUN fd has no attached interface to ask, and such a device
    /// constructed fine before name recovery existed, so `mtu()` keeps the
    /// historical 1500 fallback instead of erroring out of `Device::new`.
    #[test]
    fn a_non_tun_fd_falls_back_to_the_default_mtu() {
        let (a, _b) = UnixStream::pair().unwrap();
        let sock = TunSocket::new(&a.into_raw_fd().to_string()).unwrap();
        assert_eq!(sock.mtu().unwrap(), 1500);
    }
}
