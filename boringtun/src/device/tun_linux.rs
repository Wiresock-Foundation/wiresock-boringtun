// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

const TUNSETIFF: u64 = 0x4004_54ca;

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
    // The kernel's union also holds the 24-byte `ifru_map`, and get-style
    // ioctls (TUNGETIFF, SIOCGIFMTU) copy the kernel's full `struct ifreq`
    // back to userspace. Without this member the union tops out at 16 bytes
    // and every such ioctl writes past the local `ifreq`.
    ifru_kernel_size_pad: [u8; 24],
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
            unsafe { close(fd) };
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(Error::IOCtl(err));
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

    /// Whether `TunSocket::new(self.name())` can attach an additional
    /// multi-queue reader. An embedder-provided fd cannot: its name IS the
    /// fd in decimal, so re-parsing it aliases the same descriptor -- no
    /// second queue, and two `Drop`s then close one fd -- and opening
    /// `/dev/net/tun` fresh is exactly the privilege such embedders lack.
    pub fn can_add_queue(&self) -> bool {
        self.name.parse::<i32>().is_err()
    }

    /// The name of the attached interface, from TUNGETIFF, as the raw bytes
    /// the kernel reports. Bytes rather than a `String`: Linux interface
    /// names need not be UTF-8, and a lossy conversion would mangle such a
    /// name into one SIOCGIFMTU cannot resolve -- or inflate it past
    /// IFNAMSIZ, since each invalid byte becomes a three-byte replacement
    /// character.
    fn attached_interface_name(&self) -> Result<Vec<u8>, Error> {
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
        Ok(ifr.ifr_name[..len].to_vec())
    }

    /// Get the current MTU value
    ///
    /// The value sizes the TUN read buffer and clamps AmneziaWG content
    /// padding, and the device re-reads it for as long as it lives, so a
    /// fabricated answer would never self-correct. The interface is
    /// therefore asked under the name recovered live from the fd
    /// (TUNGETIFF) -- which also tracks renames -- and `self.name` is only
    /// the fallback for a named device whose fd refuses TUNGETIFF.
    ///
    /// `name()` deliberately keeps returning what the socket was built
    /// from: the UAPI socket is named after it, and for an embedder-provided
    /// fd the decimal string is the device's only stable identity.
    pub fn mtu(&self) -> Result<usize, Error> {
        let provided_fd = self.name.parse::<i32>().is_ok();

        let name = match self.attached_interface_name() {
            Ok(name) => name,
            // ENOTTY: the embedder's fd is not a TUN at all, so there is no
            // interface to ask. Such a device constructed -- and read and
            // wrote -- fine when this path fabricated its MTU, so keep the
            // historical answer rather than turning its construction into an
            // error. Every other errno on a provided fd (EBADF and friends)
            // is a descriptor that cannot carry traffic either: propagate,
            // so `Device::new` fails fast instead of building a dead device.
            Err(Error::IOCtl(ref e)) if provided_fd && e.raw_os_error() == Some(ENOTTY) => {
                return Ok(1500)
            }
            Err(e) if provided_fd => return Err(e),
            Err(_) => self.name.clone().into_bytes(),
        };

        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..name.len()].copy_from_slice(&name);

        // Errno is read before close() so the close cannot clobber it, and
        // the socket is closed on both exits: the device retries this call
        // for as long as it lives, so an error-path leak compounds.
        let ret = unsafe { ioctl(fd, SIOCGIFMTU as _, &mut ifr) };
        let err = if ret < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe { close(fd) };

        if let Some(err) = err {
            // A provided fd's interface may live in a netns this process
            // cannot resolve names in (a broker created the TUN elsewhere
            // and passed only the fd over), and that miss is exactly ENODEV.
            // The TUN itself still works through the fd, so answer what the
            // pre-recovery code always did instead of failing a working
            // device -- but only for that errno: any other failure is a
            // genuine query error, and masking it as a healthy 1500 would
            // hide it for as long as the device retries. The reverse
            // confusion -- a same-named interface in *this* netns shadowing
            // the real one -- cannot be detected from the fd alone.
            if provided_fd && err.raw_os_error() == Some(ENODEV) {
                return Ok(1500);
            }
            return Err(Error::IOCtl(err));
        }

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

    /// SIOCSIFNAME wants the old and new name side by side; the production
    /// union has no `ifru_newname`, so the test carries its own layout.
    #[repr(C)]
    struct IfreqRename {
        ifr_name: [c_uchar; IFNAMSIZ],
        ifr_newname: [c_uchar; IFNAMSIZ],
    }

    /// Moves the interface MTU away from 1500, because a fresh TUN starts at
    /// exactly the value the fd path used to fabricate -- left at the
    /// default, the tests below would pass with the hardcode still in place.
    fn set_mtu(name: &[u8], mtu: c_int) {
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(sock >= 0, "socket: {}", io::Error::last_os_error());

        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_mtu: mtu },
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name);

        let ret = unsafe { ioctl(sock, SIOCSIFMTU as _, &ifr) };
        unsafe { close(sock) };
        assert!(ret >= 0, "SIOCSIFMTU: {}", io::Error::last_os_error());
    }

    fn rename_iface(from: &[u8], to: &[u8]) {
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(sock >= 0, "socket: {}", io::Error::last_os_error());

        let mut ifr = IfreqRename {
            ifr_name: [0; IFNAMSIZ],
            ifr_newname: [0; IFNAMSIZ],
        };
        ifr.ifr_name[..from.len()].copy_from_slice(from);
        ifr.ifr_newname[..to.len()].copy_from_slice(to);

        let ret = unsafe { ioctl(sock, SIOCSIFNAME as _, &ifr) };
        unsafe { close(sock) };
        assert!(ret >= 0, "SIOCSIFNAME: {}", io::Error::last_os_error());
    }

    /// An fd-provided TUN must report the attached interface's real MTU, not
    /// a fabricated 1500. The interface is then renamed to bytes that are
    /// not UTF-8 -- which Linux allows -- to pin that recovery carries the
    /// kernel's raw name bytes and tracks renames, on both construction
    /// paths.
    ///
    /// Needs root and a TUN interface, hence `#[ignore]`; CI runs it via
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn an_fd_provided_tun_reports_the_real_interface_mtu() {
        let tun = TunSocket::new("wsbt-mtu0").unwrap();
        set_mtu(b"wsbt-mtu0", 1280);

        let fd = unsafe { dup(tun.as_raw_fd()) };
        assert!(fd >= 0, "dup: {}", io::Error::last_os_error());
        let by_fd = TunSocket::new(&fd.to_string()).unwrap();

        // The recovered name must not leak into `name()`: the API socket is
        // named from this string, and for an fd device the decimal form is
        // the only identity the embedder can correlate with.
        assert_eq!(by_fd.name().unwrap(), fd.to_string());

        assert_eq!(by_fd.mtu().unwrap(), 1280);

        rename_iface(b"wsbt-mtu0", b"wsbt-\xff\xfe0");
        assert_eq!(by_fd.mtu().unwrap(), 1280);
        assert_eq!(tun.mtu().unwrap(), 1280);
    }

    /// The broker pattern: the TUN is created, and its MTU set, inside
    /// another network namespace, and only the fd crosses over. TUNGETIFF
    /// works through the fd, but the recovered name resolves to nothing in
    /// this process's netns -- the device must still come up, on the same
    /// 1500 the fd path always answered before name recovery existed.
    ///
    /// Needs root (unshare + TUN), hence `#[ignore]`; CI runs it via
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn a_foreign_netns_tun_falls_back_instead_of_failing_construction() {
        let fd = std::thread::spawn(|| {
            // unshare moves only this thread; the TUN created after it lives
            // in the fresh netns, which the returned fd keeps alive.
            let ret = unsafe { unshare(CLONE_NEWNET) };
            assert_eq!(ret, 0, "unshare: {}", io::Error::last_os_error());

            let tun = TunSocket::new("wsbt-ns0").unwrap();
            set_mtu(b"wsbt-ns0", 1280);
            let fd = unsafe { dup(tun.as_raw_fd()) };
            assert!(fd >= 0, "dup: {}", io::Error::last_os_error());
            fd
        })
        .join()
        .unwrap();

        let by_fd = TunSocket::new(&fd.to_string()).unwrap();
        assert_eq!(by_fd.mtu().unwrap(), 1500);
    }

    /// A non-TUN fd refuses TUNGETIFF with ENOTTY, and such a device
    /// constructed fine before name recovery existed, so `mtu()` keeps the
    /// historical 1500 for it instead of erroring out of `Device::new`.
    #[test]
    fn a_non_tun_fd_falls_back_to_the_default_mtu() {
        let (a, _b) = UnixStream::pair().unwrap();
        let sock = TunSocket::new(&a.into_raw_fd().to_string()).unwrap();
        assert_eq!(sock.mtu().unwrap(), 1500);
    }

    /// A dead descriptor must not report a healthy fabricated MTU: only
    /// "this fd is not a TUN" earns the legacy 1500, every other failure
    /// means the device cannot carry traffic and construction should fail
    /// fast.
    #[test]
    fn a_dead_fd_reports_the_error_instead_of_a_fabricated_mtu() {
        let sock = TunSocket::new("-1").unwrap();
        assert!(sock.mtu().is_err(), "EBADF must propagate, not become 1500");
    }

    /// The multi-queue clone path (`TunSocket::new(&name())`) must be
    /// refused for an fd-provided socket: re-parsing the decimal name
    /// aliases the same fd -- no second queue is attached, and two `Drop`s
    /// then close one descriptor.
    #[test]
    fn an_fd_provided_socket_refuses_multi_queue_cloning() {
        let (a, _b) = UnixStream::pair().unwrap();
        let by_fd = TunSocket::new(&a.into_raw_fd().to_string()).unwrap();
        assert!(!by_fd.can_add_queue());

        let (c, _d) = UnixStream::pair().unwrap();
        let named = TunSocket {
            fd: c.into_raw_fd(),
            name: "utun100".to_string(),
        };
        assert!(named.can_add_queue());
    }
}
