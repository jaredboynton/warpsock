//! TCP/IP stack fingerprinting for browser impersonation.
//!
//! Configures TCP socket options to match browser behavior:
//! - Initial window size
//! - TTL (Time To Live)
//! - MSS (Maximum Segment Size)
//! - Window scaling
//! - SACK (Selective Acknowledgment)
//! - TCP timestamps
//!
//! These options are detectable before TLS handshake (p0f-style fingerprinting).

use std::io;

/// TCP/IP fingerprint configuration.
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    /// Initial receive window size (bytes).
    /// Chrome: 65535 (default), can be adjusted via socket buffer size
    pub window_size: u32,
    /// Initial TTL (Time To Live) for IPv4 packets.
    /// macOS: 64, Linux: 64, Windows: 128
    pub ttl: u8,
    /// Maximum Segment Size (MSS).
    /// Typically 1460 for Ethernet (1500 MTU - 40 IP/TCP headers)
    pub mss: u16,
    /// Window scaling factor (RFC 1323).
    /// Chrome: typically 6-7 (64KB * 2^6 = 4MB window)
    pub window_scale: u8,
    /// Enable SACK (Selective Acknowledgment).
    /// Modern browsers: true
    pub sack_permitted: bool,
    /// Enable TCP timestamps (RFC 1323).
    /// Modern browsers: true
    pub timestamps: bool,
    /// Optional `TCP_NOTSENT_LOWAT` watermark (bytes). Linux and macOS only.
    ///
    /// Limits unsent data in the kernel send buffer before `EPOLLOUT` is
    /// signaled, improving request-response latency on high-RTT links. Applies
    /// to all new connections; does not retroactively affect pooled connections.
    ///
    /// Recommended values (Eric Dumazet):
    /// - `16384` (16 KiB): interactive RPC / low-latency request-response
    /// - `131072` (128 KiB): general-purpose throughput/latency balance
    pub tcp_notsent_lowat: Option<u32>,
}

impl Default for TcpFingerprint {
    fn default() -> Self {
        // Chrome defaults on macOS
        Self {
            window_size: 65535,
            ttl: 64,   // macOS default
            mss: 1460, // Ethernet MTU - headers
            window_scale: 6,
            sack_permitted: true,
            timestamps: true,
            tcp_notsent_lowat: None,
        }
    }
}

impl TcpFingerprint {
    /// Create Chrome TCP fingerprint.
    pub fn chrome() -> Self {
        Self::default()
    }

    /// Create Firefox TCP fingerprint.
    /// Firefox uses similar TCP settings to Chrome.
    pub fn firefox() -> Self {
        Self::default()
    }
}

/// Configure a TCP socket with fingerprint settings.
///
/// Uses socket2 crate for cross-platform socket options.
/// Some TCP options may not be available or configurable on all platforms.
pub fn configure_tcp_socket(socket: &socket2::Socket, fp: &TcpFingerprint) -> io::Result<()> {
    // Set receive buffer size (influences window size)
    socket.set_recv_buffer_size(fp.window_size as usize)?;

    // Set send buffer size (should match receive for symmetry)
    socket.set_send_buffer_size(fp.window_size as usize)?;

    // Set TTL for IPv4 packets
    socket.set_ttl_v4(fp.ttl as u32)?;

    if let Some(bytes) = fp.tcp_notsent_lowat {
        set_tcp_notsent_lowat(socket, bytes)?;
    }

    // MSS (Maximum Segment Size) is negotiated during TCP handshake and cannot be
    // directly set via socket options. The OS handles MSS negotiation based
    // on MTU discovery.

    // Window scaling, SACK, and timestamps are negotiated during TCP handshake
    // via TCP options. These are typically handled by the OS TCP stack and
    // cannot be directly controlled via socket2 on all platforms.
    //
    // For full control, we would need raw sockets or platform-specific APIs.
    // This implementation focuses on what can be reliably configured via
    // standard socket options.

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
fn set_tcp_notsent_lowat(socket: &socket2::Socket, bytes: u32) -> io::Result<()> {
    use std::mem;
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    use libc::TCP_NOTSENT_LOWAT;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const TCP_NOTSENT_LOWAT: i32 = 0x202;

    let fd = socket.as_raw_fd();
    let value = bytes;
    // SAFETY: `fd` is a valid socket descriptor and `value` is a plain u32 for
    // TCP_NOTSENT_LOWAT on Linux/Darwin.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&raw const value).cast(),
            mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
fn set_tcp_notsent_lowat(_socket: &socket2::Socket, _bytes: u32) -> io::Result<()> {
    tracing::debug!("TCP_NOTSENT_LOWAT is not supported on this platform");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
#[cfg(test)]
fn read_tcp_notsent_lowat(socket: &socket2::Socket) -> io::Result<u32> {
    use std::mem;
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    use libc::TCP_NOTSENT_LOWAT;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const TCP_NOTSENT_LOWAT: i32 = 0x202;

    let fd = socket.as_raw_fd();
    let mut value: u32 = 0;
    let mut len = mem::size_of::<u32>() as libc::socklen_t;
    // SAFETY: `fd` is valid; `value`/`len` are initialized for getsockopt out-params.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Socket, Type};

    #[test]
    fn test_tcp_fingerprint_defaults() {
        let fp = TcpFingerprint::default();
        assert_eq!(fp.window_size, 65535);
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.mss, 1460);
        assert_eq!(fp.window_scale, 6);
        assert!(fp.sack_permitted);
        assert!(fp.timestamps);
        assert!(fp.tcp_notsent_lowat.is_none());
    }

    #[test]
    fn test_chrome_firefox_similar() {
        let chrome = TcpFingerprint::chrome();
        let firefox = TcpFingerprint::firefox();
        // Chrome and Firefox use similar TCP settings
        assert_eq!(chrome.window_size, firefox.window_size);
        assert_eq!(chrome.ttl, firefox.ttl);
    }

    #[test]
    fn default_tcp_configuration_leaves_socket_buffers_untouched() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(socket2::Protocol::TCP)).unwrap();
        let initial_recv = socket.recv_buffer_size().unwrap();
        let initial_send = socket.send_buffer_size().unwrap();

        configure_tcp_socket(&socket, &TcpFingerprint::default()).unwrap();

        assert_eq!(socket.recv_buffer_size().unwrap(), initial_recv);
        assert_eq!(socket.send_buffer_size().unwrap(), initial_send);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    #[test]
    fn tcp_notsent_lowat_round_trips_via_getsockopt() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        let fp = TcpFingerprint {
            tcp_notsent_lowat: Some(16_384),
            ..TcpFingerprint::default()
        };
        configure_tcp_socket(&socket, &fp).unwrap();
        assert_eq!(read_tcp_notsent_lowat(&socket).unwrap(), 16_384);
    }
}
