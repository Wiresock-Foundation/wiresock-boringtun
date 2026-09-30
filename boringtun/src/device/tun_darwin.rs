// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::io;
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::null_mut;

const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";

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

const CTLIOCGINFO: u64 = 0x0000_0000_c064_4e03;
const SIOCGIFMTU: u64 = 0x0000_0000_c020_6933;

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
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
pub fn parse_utun_name(name: &str) -> Result<u32, Error> {
    if !name.starts_with("utun") {
        return Err(Error::InvalidTunnelName);
    }

    match name.get(4..) {
        None | Some("") => {
            // The name is simply "utun"
            Ok(0)
        }
        Some(idx) => {
            // Everything past utun should represent an integer index
            idx.parse::<u32>()
                .map_err(|_| Error::InvalidTunnelName)
                .map(|x| x + 1)
        }
    }
}

impl TunSocket {
    fn write(&self, src: &[u8], af: u8) -> usize {
        let mut hdr = [0u8, 0u8, 0u8, af as u8];
        let mut iov = [
            iovec {
                iov_base: hdr.as_mut_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: src.as_ptr() as _,
                iov_len: src.len(),
            },
        ];

        let msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { sendmsg(self.fd, &msg_hdr, 0) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn new(name: &str) -> Result<TunSocket, Error> {
        let idx = parse_utun_name(name)?;

        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        info.ctl_name[..CTRL_NAME.len()].copy_from_slice(CTRL_NAME);

        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut ctl_info) } < 0 {
            unsafe { close(fd) };
            return Err(Error::IOCtl(io::Error::last_os_error()));
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
            let mut err_string = io::Error::last_os_error().to_string();
            err_string.push_str("(did you run with sudo?)");
            return Err(Error::Connect(err_string));
        }

        Ok(TunSocket { fd })
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
            return Err(Error::GetSockOpt(io::Error::last_os_error()));
        }

        Ok(String::from_utf8_lossy(&tunnel_name[..(tunnel_name_len - 1) as usize]).to_string())
    }

    /// Get the current MTU value
    ///
    /// The interface is asked under the name the utun descriptor reports now
    /// (`name()`), through a throwaway AF_INET socket. The name comes first,
    /// so a descriptor that cannot report one fails before any socket exists;
    /// from then on the socket is owned, and closed on every return. The
    /// device asks once a second for as long as it lives, so a socket left
    /// open on an error path would leak a descriptor every second.
    pub fn mtu(&self) -> Result<usize, Error> {
        let name = self.name()?;
        let sock = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            // SAFETY: a descriptor socket(2) has just returned; nothing else
            // owns it.
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };
        query_mtu(sock, name.as_bytes())
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src, AF_INET as u8)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src, AF_INET6 as u8)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let mut hdr = [0u8; 4];

        let mut iov = [
            iovec {
                iov_base: hdr.as_mut_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: dst.as_mut_ptr() as _,
                iov_len: dst.len(),
            },
        ];

        let mut msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { recvmsg(self.fd, &mut msg_hdr, 0) } {
            -1 => Err(Error::IfaceRead(io::Error::last_os_error())),
            0..=4 => Ok(&mut dst[..0]),
            n => Ok(&mut dst[..(n - 4) as usize]),
        }
    }
}

/// The MTU of the interface called `name`, asked through `sock` with
/// SIOCGIFMTU.
///
/// Takes the socket over: it is closed exactly once, when `sock` drops,
/// whichever way this returns -- after a failed ioctl's errno has been read,
/// so the error returned is the ioctl's own. A name with no room left in
/// `ifr_name` for its terminating NUL is refused rather than cut short or
/// indexed past; the live utun name always fits, interface names being at
/// most `IFNAMSIZ - 1` bytes.
fn query_mtu(sock: OwnedFd, name: &[u8]) -> Result<usize, Error> {
    if name.len() >= IF_NAMESIZE {
        return Err(Error::InvalidTunnelName);
    }
    let mut ifr = ifreq {
        ifr_name: [0; IF_NAMESIZE],
        ifr_ifru: IfrIfru { ifru_mtu: 0 },
    };
    ifr.ifr_name[..name.len()].copy_from_slice(name);

    // `&mut`: the kernel writes its answer into `ifr`.
    if unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU, &mut ifr) } < 0 {
        return Err(Error::IOCtl(io::Error::last_os_error()));
    }

    Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    /// Every macOS host has it.
    const LOOPBACK: &[u8] = b"lo0";
    /// No interface is called this.
    const NO_SUCH_INTERFACE: &[u8] = b"wsbtnone0";

    /// Held by every test that checks a descriptor number is closed; see
    /// `high_socket`.
    static FD_NUMBERS: Mutex<()> = Mutex::new(());

    /// How far below the soft RLIMIT_NOFILE `high_socket` places its sockets.
    const HIGH_FD_HEADROOM: rlim_t = 64;

    /// The lowest number `high_socket` duplicates its socket to:
    /// `HIGH_FD_HEADROOM` below the soft RLIMIT_NOFILE, counted from at most
    /// 1024. `None` when the limit is lower than the headroom -- checked
    /// before the subtraction, so the floor is never negative, and always
    /// below the limit, where fcntl accepts it.
    fn high_fd_floor(soft_limit: rlim_t) -> Option<c_int> {
        soft_limit
            .min(1024)
            .checked_sub(HIGH_FD_HEADROOM)
            .map(|floor| floor as c_int)
    }

    /// `fd` duplicated (close-on-exec) to the lowest free number at or above
    /// `floor`, and owned -- or fcntl's own error. fcntl's -1 is checked
    /// here, so a refused duplication never becomes an `OwnedFd`.
    fn dup_at_or_above(fd: RawFd, floor: c_int) -> io::Result<OwnedFd> {
        let dup = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, floor) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor fcntl(2) has just returned; nothing else owns
        // it.
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }

    /// A fresh AF_INET socket, and the number it lives at: near the top of
    /// the descriptor table. A new descriptor takes the lowest free number,
    /// so another test thread is unlikely to be handed this one between its
    /// close and `closed`'s check -- that would need nearly every descriptor
    /// below it open at that moment. Unlikely, not impossible: other threads
    /// are not serialised. `FD_NUMBERS` does serialise the tests that use
    /// this, so they do not hand the number to each other.
    fn high_socket() -> (OwnedFd, RawFd) {
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: just returned by socket(2); nothing else owns it.
        let low = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut limit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) };
        assert_eq!(ret, 0, "getrlimit: {}", io::Error::last_os_error());
        let floor = high_fd_floor(limit.rlim_cur).unwrap_or_else(|| {
            panic!(
                "a soft RLIMIT_NOFILE of {} leaves no room for a test socket {} below it",
                limit.rlim_cur, HIGH_FD_HEADROOM
            )
        });
        // `low` stays owned until this returns, and closes its own copy then,
        // whether or not the duplicate was made.
        let high = dup_at_or_above(low.as_raw_fd(), floor)
            .unwrap_or_else(|e| panic!("F_DUPFD_CLOEXEC at or above {}: {}", floor, e));
        let number = high.as_raw_fd();
        (high, number)
    }

    /// `fd` names no open descriptor.
    fn closed(fd: RawFd) -> bool {
        let ret = unsafe { fcntl(fd, F_GETFD) };
        ret == -1 && io::Error::last_os_error().raw_os_error() == Some(EBADF)
    }

    /// The errno a bare SIOCGIFMTU for `name` fails with. What the kernel
    /// answers for a missing interface is not pinned here -- only that
    /// `query_mtu` passes it on unchanged.
    fn bare_ioctl_errno(name: &[u8]) -> Option<i32> {
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: just returned by socket(2); nothing else owns it.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name);
        let ret = unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU, &mut ifr) };
        assert!(ret < 0, "an interface called {:?} exists", name);
        io::Error::last_os_error().raw_os_error()
    }

    /// A query that succeeds closes its socket once the answer is in.
    #[test]
    fn a_successful_mtu_query_closes_its_socket() {
        let _serial = FD_NUMBERS.lock().unwrap_or_else(|e| e.into_inner());
        let (sock, fd) = high_socket();
        let mtu = query_mtu(sock, LOOPBACK).expect("lo0's MTU");
        assert!(mtu > 0, "lo0 reported an MTU of {}", mtu);
        assert!(closed(fd), "the query socket, fd {}, is still open", fd);
    }

    /// A query that fails still closes its socket, and reports the ioctl's
    /// own error: the errno a bare SIOCGIFMTU for the same name fails with,
    /// not one left behind by closing the socket.
    #[test]
    fn a_failed_mtu_query_closes_its_socket_and_keeps_the_ioctl_error() {
        let _serial = FD_NUMBERS.lock().unwrap_or_else(|e| e.into_inner());
        let expected = bare_ioctl_errno(NO_SUCH_INTERFACE);
        assert!(expected.is_some(), "the bare ioctl set no errno");
        let (sock, fd) = high_socket();
        match query_mtu(sock, NO_SUCH_INTERFACE) {
            Err(Error::IOCtl(e)) => assert_eq!(
                e.raw_os_error(),
                expected,
                "{} is not the ioctl's own error",
                e
            ),
            other => panic!("expected the ioctl's error, got {:?}", other),
        }
        assert!(closed(fd), "the query socket, fd {}, is still open", fd);
    }

    /// The monitor asks once a second for as long as the device lives, so a
    /// query that keeps failing must not keep its socket each time.
    #[test]
    fn failed_mtu_queries_in_a_row_leave_no_socket_behind() {
        let _serial = FD_NUMBERS.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..200 {
            let (sock, fd) = high_socket();
            let result = query_mtu(sock, NO_SUCH_INTERFACE);
            assert!(
                matches!(result, Err(Error::IOCtl(_))),
                "attempt {}: {:?}",
                attempt,
                result
            );
            assert!(
                closed(fd),
                "attempt {}: the query socket, fd {}, is still open",
                attempt,
                fd
            );
        }
    }

    /// A name with no room left for its terminating NUL is refused -- not cut
    /// short, not indexed past -- and the socket is closed all the same. One
    /// byte shorter, it is the kernel's to answer.
    #[test]
    fn an_mtu_query_for_an_overlong_name_is_refused_and_closes_its_socket() {
        let _serial = FD_NUMBERS.lock().unwrap_or_else(|e| e.into_inner());
        let (sock, fd) = high_socket();
        let result = query_mtu(sock, &[b'u'; IF_NAMESIZE]);
        assert!(
            matches!(result, Err(Error::InvalidTunnelName)),
            "{:?}",
            result
        );
        assert!(closed(fd), "the query socket, fd {}, is still open", fd);

        let (sock, fd) = high_socket();
        let result = query_mtu(sock, &[b'u'; IF_NAMESIZE - 1]);
        assert!(matches!(result, Err(Error::IOCtl(_))), "{:?}", result);
        assert!(closed(fd), "the query socket, fd {}, is still open", fd);
    }

    /// `mtu` fetches the interface name before it opens a socket, so a
    /// descriptor that cannot report one fails with that error -- the
    /// `getsockopt` failure, not a query error -- and no query socket exists
    /// to be left behind. A socketpair end stands in for a utun control
    /// socket gone bad: it refuses UTUN_OPT_IFNAME.
    #[test]
    fn an_mtu_query_that_cannot_name_its_interface_reports_the_name_error() {
        let (end, _other) = UnixStream::pair().unwrap();
        let tun = TunSocket {
            fd: end.into_raw_fd(),
        };
        let result = tun.mtu();
        assert!(matches!(result, Err(Error::GetSockOpt(_))), "{:?}", result);
    }

    /// The floor is checked before the headroom comes off, so it is never
    /// negative and always below the limit. A soft limit lower than the
    /// headroom gives no floor at all -- and `high_socket` fails saying so --
    /// where the unchecked subtraction gave -1 at a limit of 63, which fcntl
    /// refuses.
    #[test]
    fn the_high_descriptor_floor_is_never_negative() {
        assert_eq!(high_fd_floor(0), None);
        assert_eq!(high_fd_floor(63), None);
        assert_eq!(high_fd_floor(64), Some(0));
        assert_eq!(high_fd_floor(256), Some(192));
        assert_eq!(high_fd_floor(1024), Some(960));
        assert_eq!(high_fd_floor(10240), Some(960));
        assert_eq!(high_fd_floor(RLIM_INFINITY), Some(960));
        for limit in 0..=2048 {
            match high_fd_floor(limit) {
                None => assert!(limit < HIGH_FD_HEADROOM, "limit {}", limit),
                Some(floor) => assert!(
                    floor >= 0 && (floor as rlim_t) < limit,
                    "limit {}: floor {}",
                    limit,
                    floor
                ),
            }
        }
    }

    /// A duplication fcntl refuses is an error, never a descriptor. Asked for
    /// a negative floor -- what the unchecked subtraction produced under a
    /// low limit -- or one past any limit, F_DUPFD_CLOEXEC fails with -1
    /// (EINVAL), and that -1 must not reach `OwnedFd`.
    #[test]
    fn a_refused_descriptor_duplication_is_an_error_not_a_descriptor() {
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: just returned by socket(2); nothing else owns it.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        for floor in [-1, c_int::MAX] {
            let result = dup_at_or_above(sock.as_raw_fd(), floor);
            assert!(
                matches!(&result, Err(e) if e.raw_os_error() == Some(EINVAL)),
                "floor {}: {:?}",
                floor,
                result
            );
        }
    }
}
