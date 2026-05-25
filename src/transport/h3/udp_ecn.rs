use std::io;
use std::net::SocketAddr;

use socket2::Socket;
use tokio::net::UdpSocket;

use crate::transport::h3::quic::QuicEcnMark;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpDatagramEcn {
    pub len: usize,
    pub peer: SocketAddr,
    pub ecn_mark: Option<QuicEcnMark>,
}

pub(crate) fn enable_udp_ecn_receive(socket: &Socket, local_addr: SocketAddr) -> io::Result<()> {
    if local_addr.is_ipv4() {
        enable_udp_ecn_receive_v4(socket)
    } else {
        enable_udp_ecn_receive_v6(socket)
    }
}

#[cfg(not(any(
    target_os = "aix",
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "nto",
    target_os = "espidf",
    target_os = "vita",
    target_os = "cygwin",
)))]
fn enable_udp_ecn_receive_v4(socket: &Socket) -> io::Result<()> {
    socket.set_recv_tos_v4(true)
}

#[cfg(any(
    target_os = "aix",
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "nto",
    target_os = "espidf",
    target_os = "vita",
    target_os = "cygwin",
))]
fn enable_udp_ecn_receive_v4(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "hurd",
    target_os = "espidf",
    target_os = "vita",
)))]
fn enable_udp_ecn_receive_v6(socket: &Socket) -> io::Result<()> {
    socket.set_recv_tclass_v6(true)
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "hurd",
    target_os = "espidf",
    target_os = "vita",
))]
fn enable_udp_ecn_receive_v6(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<UdpDatagramEcn> {
    use std::os::fd::AsRawFd;

    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_with_ecn(socket.as_raw_fd(), buf)
        }) {
            Ok(result) => return Ok(result),
            Err(_would_block) => continue,
        }
    }
}

#[cfg(not(unix))]
pub(crate) async fn recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<UdpDatagramEcn> {
    let (len, peer) = socket.recv_from(buf).await?;
    Ok(UdpDatagramEcn {
        len,
        peer,
        ecn_mark: None,
    })
}

#[cfg(unix)]
fn recvmsg_with_ecn(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<UdpDatagramEcn> {
    use socket2::SockAddr;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 128];
    let mut ecn_mark = None;

    let (len, peer) = unsafe {
        SockAddr::try_init(|addr_storage, addr_len| {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_name = addr_storage.cast();
            message.msg_namelen = *addr_len;
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "control buffer too large")
            })?;

            let received = libc::recvmsg(fd, &mut message, 0);
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            *addr_len = message.msg_namelen;
            ecn_mark = parse_ecn_mark(&message);
            Ok(received as usize)
        })?
    };

    let peer = peer
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP peer address"))?;
    Ok(UdpDatagramEcn {
        len,
        peer,
        ecn_mark,
    })
}

#[cfg(unix)]
fn parse_ecn_mark(message: &libc::msghdr) -> Option<QuicEcnMark> {
    unsafe {
        let mut control = libc::CMSG_FIRSTHDR(message);
        while !control.is_null() {
            let header = std::ptr::read_unaligned(control);
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_TOS {
                let tos = *(libc::CMSG_DATA(control).cast::<u8>());
                if let Some(mark) = QuicEcnMark::from_ip_tos_bits(tos) {
                    return Some(mark);
                }
            }
            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_TCLASS {
                let traffic_class =
                    std::ptr::read_unaligned(libc::CMSG_DATA(control).cast::<libc::c_int>());
                if let Some(mark) = QuicEcnMark::from_ip_tos_bits(traffic_class as u8) {
                    return Some(mark);
                }
            }
            control =
                libc::CMSG_NXTHDR(message as *const libc::msghdr as *mut libc::msghdr, control);
        }
    }
    None
}
