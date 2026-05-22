//! HTTP/3 Connection establishment and management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::transport::dns::DnsConfig;
use crate::transport::h3::driver::H3Driver;
use crate::transport::h3::handle::H3Handle;

use getrandom::fill as getrandom_fill;
use quiche;

pub struct H3Connection;

impl H3Connection {
    /// Connect to an HTTP/3 server and return a handle.
    /// This spawns a background driver task.
    pub async fn connect(
        url: &str,
        mut config: quiche::Config,
        max_idle_timeout: u64,
        dns_config: &DnsConfig,
    ) -> Result<H3Handle> {
        let (host, port, _path) = parse_url(url)?;

        // Resolve peer
        let peer_addr = dns_config
            .resolve(&host, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Connection("DNS/IP not found".into()))?;

        // Bind local socket
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(local_addr).await.map_err(Error::Io)?;
        let socket = Arc::new(socket);

        // Generate CID
        let mut scid = [0u8; 16];
        getrandom_fill(&mut scid).map_err(|e| Error::Quic(format!("RNG error: {}", e)))?;
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create QUIC connection
        let mut conn = quiche::connect(
            Some(&host),
            &scid,
            socket.local_addr().unwrap(),
            peer_addr,
            &mut config,
        )
        .map_err(|e| Error::Quic(format!("Connect failed: {}", e)))?;

        // Handshake Loop
        // We must drive the handshake until established BEFORE spawning driver
        // to return errors early.
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; 1350];

        let start = Instant::now();
        let timeout_dur = std::time::Duration::from_secs(10);

        loop {
            if start.elapsed() > timeout_dur {
                return Err(Error::Timeout("H3 Handshake timeout".into()));
            }

            // Flush egress
            loop {
                match conn.send(&mut out) {
                    Ok((len, _)) => {
                        socket
                            .send_to(&out[..len], peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(Error::Quic(format!("Send error: {}", e))),
                }
            }

            if conn.is_established() {
                break;
            }
            if conn.is_closed() {
                return Err(Error::Quic("Connection closed during handshake".into()));
            }

            // Recv ingress
            let recv_timeout = conn
                .timeout()
                .unwrap_or(std::time::Duration::from_millis(100));
            // Use small timeout for recv to allow sending keep-alives/re-transmits
            match tokio::time::timeout(recv_timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    if from == peer_addr {
                        let info = quiche::RecvInfo {
                            from,
                            to: socket.local_addr().unwrap(),
                        };
                        let _ = conn.recv(&mut buf[..len], info);
                    }
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_) => {
                    conn.on_timeout();
                }
            }
        }

        // Create HTTP/3 connection context
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| Error::Quic(format!("H3 Config error: {}", e)))?;
        let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
            .map_err(|e| Error::Quic(format!("H3 Init error: {}", e)))?;

        // Spawn Driver
        let (tx, rx) = mpsc::channel(32);
        let is_draining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let driver = H3Driver::new(
            tx.clone(),
            rx,
            conn,
            h3_conn,
            socket.clone(),
            peer_addr,
            is_draining.clone(),
            max_idle_timeout,
        );

        tokio::spawn(async move {
            if let Err(e) = driver.drive().await {
                tracing::error!("H3 Driver crashed: {:?}", e);
            }
        });

        Ok(H3Handle::new(tx, is_draining))
    }
}

fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let u = url::Url::parse(url).map_err(|e| Error::CookieParse(e.to_string()))?;
    if u.scheme() != "https" {
        return Err(Error::Connection("HTTP/3 requires https".into()));
    }
    let host = u
        .host_str()
        .ok_or(Error::Connection("No host".into()))?
        .to_string();
    let port = u.port().unwrap_or(443);
    let path = u.path().to_string();
    Ok((host, port, path))
}
