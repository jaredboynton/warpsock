//! HTTP/3 Connection establishment and management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::error::{Error, Result};
use crate::fingerprint::{Http3Fingerprint, QuicTransportParams, TlsFingerprint};
use crate::transport::dns::DnsConfig;
use crate::transport::h3::command::StreamResponse;
use crate::transport::h3::handle::{H3Handle, NativeH3HandshakeReport};
use crate::transport::h3::handshake::NativeQuicHandshake;
use crate::transport::h3::native;
use crate::transport::h3::quic::{ConnectionId, QuicEcnMark};
use crate::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};
use crate::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use crate::transport::h3::tls::NativeH3HandshakeStatus;
use crate::transport::h3::udp_ecn::{enable_udp_ecn_receive, recv_from_with_ecn};
use crate::transport::h3::H3TransportConfig;

use crate::transport::h3::native_driver::{spawn_native_h3_driver, NativeH3PendingResponse};
use bytes::Bytes;
use getrandom::fill as getrandom_fill;

const MAX_CONNECTION_ID_LEN: usize = 20;
const H3_UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

pub struct H3Connection;

#[derive(Debug, Clone)]
pub(crate) struct NativeH3ZeroRttRequest {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    pub payload: Bytes,
}

pub(crate) struct H3ConnectResult {
    pub handle: H3Handle,
    pub zero_rtt_response_rx: Option<oneshot::Receiver<Result<StreamResponse>>>,
}

impl NativeH3ZeroRttRequest {
    pub(crate) fn new(
        fingerprint: &Http3Fingerprint,
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Self> {
        let h3_headers = native::build_request_headers(&method, &uri, &headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, body.clone(), fingerprint);
        Ok(Self {
            method,
            uri,
            headers,
            body,
            payload,
        })
    }
}

struct NativeH3Connect {
    host: String,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    tls_fingerprint: Option<TlsFingerprint>,
    fingerprint: Http3Fingerprint,
    max_idle_timeout: u64,
    verify_peer: bool,
    root_certs: Vec<Vec<u8>>,
    use_platform_roots: bool,
    transport_config: H3TransportConfig,
    session_cache: NativeH3SessionCache,
    session_cache_key: NativeH3SessionCacheKey,
    zero_rtt_request: Option<NativeH3ZeroRttRequest>,
}

struct PendingZeroRttRequest {
    request: NativeH3ZeroRttRequest,
    stream_id: u64,
    packet_number: u64,
}

impl H3Connection {
    /// Connect to an HTTP/3 server and return a handle.
    /// This spawns a background driver task.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        url: &str,
        tls_fingerprint: Option<TlsFingerprint>,
        fingerprint: Http3Fingerprint,
        max_idle_timeout: u64,
        verify_peer: bool,
        root_certs: Vec<Vec<u8>>,
        use_platform_roots: bool,
        dns_config: &DnsConfig,
        transport_config: H3TransportConfig,
        session_cache: NativeH3SessionCache,
        session_cache_key: NativeH3SessionCacheKey,
    ) -> Result<H3Handle> {
        Ok(Self::connect_internal(
            url,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            dns_config,
            transport_config,
            session_cache,
            session_cache_key,
            None,
        )
        .await?
        .handle)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn connect_with_zero_rtt_request(
        url: &str,
        tls_fingerprint: Option<TlsFingerprint>,
        fingerprint: Http3Fingerprint,
        max_idle_timeout: u64,
        verify_peer: bool,
        root_certs: Vec<Vec<u8>>,
        use_platform_roots: bool,
        dns_config: &DnsConfig,
        transport_config: H3TransportConfig,
        session_cache: NativeH3SessionCache,
        session_cache_key: NativeH3SessionCacheKey,
        zero_rtt_request: NativeH3ZeroRttRequest,
    ) -> Result<H3ConnectResult> {
        Self::connect_internal(
            url,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            dns_config,
            transport_config,
            session_cache,
            session_cache_key,
            Some(zero_rtt_request),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_internal(
        url: &str,
        tls_fingerprint: Option<TlsFingerprint>,
        fingerprint: Http3Fingerprint,
        max_idle_timeout: u64,
        verify_peer: bool,
        root_certs: Vec<Vec<u8>>,
        use_platform_roots: bool,
        dns_config: &DnsConfig,
        transport_config: H3TransportConfig,
        session_cache: NativeH3SessionCache,
        session_cache_key: NativeH3SessionCacheKey,
        zero_rtt_request: Option<NativeH3ZeroRttRequest>,
    ) -> Result<H3ConnectResult> {
        let (host, port, _path) = parse_url(url)?;

        // Resolve peer
        let peer_addr = dns_config
            .resolve(&host, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Connection("DNS/IP not found".into()))?;

        // Bind local socket
        let local_addr: SocketAddr = if peer_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = Arc::new(bind_udp_socket(local_addr, &fingerprint.transport)?);

        Self::connect_native(NativeH3Connect {
            host,
            socket,
            peer_addr,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            transport_config,
            session_cache,
            session_cache_key,
            zero_rtt_request,
        })
        .await
    }

    async fn connect_native(request: NativeH3Connect) -> Result<H3ConnectResult> {
        let NativeH3Connect {
            host,
            socket,
            peer_addr,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            transport_config,
            session_cache,
            session_cache_key,
            zero_rtt_request,
        } = request;
        let destination_cid =
            random_connection_id(fingerprint.transport.destination_connection_id_len)?;
        let source_cid = random_connection_id(fingerprint.transport.source_connection_id_len)?;

        let cached_session = session_cache.get(&session_cache_key);
        let zero_rtt_request = zero_rtt_request.filter(|request| {
            cached_session.as_ref().is_some_and(|entry| {
                entry.supports_zero_rtt() && request.payload.len() <= entry.max_early_data as usize
            })
        });
        let zero_rtt_session = cached_session
            .as_ref()
            .zip(zero_rtt_request.as_ref())
            .map(|(entry, request)| (entry.der.as_ref(), request.payload.as_ref()));
        let handshake_result = if let Some((session_der, early_data)) = zero_rtt_session {
            NativeQuicHandshake::client_with_tls_fingerprint_and_zero_rtt_request(
                &host,
                &fingerprint,
                tls_fingerprint.as_ref(),
                destination_cid.clone(),
                source_cid.clone(),
                verify_peer,
                &root_certs,
                use_platform_roots,
                session_der,
                early_data,
            )
        } else {
            NativeQuicHandshake::client_with_tls_fingerprint_and_session(
                &host,
                &fingerprint,
                tls_fingerprint.as_ref(),
                destination_cid.clone(),
                source_cid.clone(),
                verify_peer,
                &root_certs,
                use_platform_roots,
                cached_session.as_ref().map(|entry| entry.der.as_ref()),
            )
        };
        let mut zero_rtt_request = zero_rtt_request;
        let mut handshake = match handshake_result {
            Ok(handshake) => handshake,
            Err(err) if cached_session.is_some() => {
                session_cache.evict(&session_cache_key);
                zero_rtt_request = None;
                NativeQuicHandshake::client_with_tls_fingerprint(
                    &host,
                    &fingerprint,
                    tls_fingerprint.as_ref(),
                    destination_cid,
                    source_cid,
                    verify_peer,
                    &root_certs,
                    use_platform_roots,
                )
                .map_err(|_| err)?
            }
            Err(err) => return Err(err),
        };

        socket
            .send_to(handshake.client_initial().packet.as_ref(), peer_addr)
            .await
            .map_err(Error::Io)?;
        eprintln!("temporary client sent initial");
        handshake.record_client_initial_sent_at(Instant::now());
        let mut pending_zero_rtt = if let Some(request) = zero_rtt_request {
            let packet = handshake.build_client_h3_zero_rtt_request_packet(
                &request.method,
                &request.uri,
                &request.headers,
                request.body.clone(),
            )?;
            socket
                .send_to(packet.packet.as_ref(), peer_addr)
                .await
                .map_err(Error::Io)?;
            eprintln!("temporary client sent zero-rtt pn {}", packet.packet_number);
            Some(PendingZeroRttRequest {
                request,
                stream_id: packet.stream_id,
                packet_number: packet.packet_number,
            })
        } else {
            None
        };

        let deadline = Instant::now() + Duration::from_millis(max_idle_timeout.max(1));
        let mut buf = vec![0u8; fingerprint.transport.max_recv_udp_payload_size.max(1200)];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout("native H3 handshake timeout".into()));
            }

            let loss_detection_wait = handshake
                .loss_detection_timer()
                .map(|deadline| deadline.saturating_duration_since(Instant::now()));
            let recv_wait = loss_detection_wait
                .unwrap_or_else(|| Duration::from_millis(25))
                .min(Duration::from_millis(25))
                .min(remaining);

            match tokio::time::timeout(recv_wait, recv_from_with_ecn(socket.as_ref(), &mut buf))
                .await
            {
                Ok(Ok(received)) if received.peer == peer_addr => {
                    let len = received.len;
                    let ecn_mark = received.ecn_mark;
                    eprintln!(
                        "temporary client recv len {len} long={}",
                        buf[..len].first().is_some_and(|first| first & 0x80 != 0)
                    );
                    if buf[..len].first().is_some_and(|first| first & 0x80 == 0) {
                        if handshake.is_application_ready() {
                            eprintln!("temporary client finish on short");
                            return Self::finish_native_connect(
                                handshake,
                                fingerprint,
                                socket,
                                peer_addr,
                                max_idle_timeout,
                                Some((Bytes::copy_from_slice(&buf[..len]), ecn_mark)),
                                transport_config,
                                session_cache.clone(),
                                session_cache_key.clone(),
                                pending_zero_rtt.take(),
                            )
                            .await;
                        }
                        continue;
                    }
                    let processed_packets =
                        handshake.process_server_datagram_with_ecn(&buf[..len], ecn_mark)?;
                    if let Some(packet) = handshake.take_pending_client_initial() {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                        handshake.record_client_initial_sent_at(Instant::now());
                    }
                    if let Some(packet) = handshake.build_client_initial_ack_packet()? {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    if let Some(packet) = handshake.build_client_handshake_ack_packet()? {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    for processed in processed_packets {
                        if let Some(packet) = handshake
                            .build_client_handshake_crypto_packet(processed.handshake_crypto_out)?
                        {
                            socket
                                .send_to(packet.packet.as_ref(), peer_addr)
                                .await
                                .map_err(Error::Io)?;
                        }
                    }
                    if handshake.is_application_ready() {
                        eprintln!(
                            "temporary client application ready status {:?}",
                            handshake.handshake_status()
                        );
                        return Self::finish_native_connect(
                            handshake,
                            fingerprint,
                            socket,
                            peer_addr,
                            max_idle_timeout,
                            None,
                            transport_config,
                            session_cache.clone(),
                            session_cache_key.clone(),
                            pending_zero_rtt.take(),
                        )
                        .await;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => return Err(Error::Io(err)),
                Err(_) => {
                    Self::handle_client_loss_detection_timeout(
                        &mut handshake,
                        socket.as_ref(),
                        peer_addr,
                    )
                    .await?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_native_connect(
        mut handshake: NativeQuicHandshake,
        fingerprint: Http3Fingerprint,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        max_idle_timeout: u64,
        initial_datagram: Option<(Bytes, Option<QuicEcnMark>)>,
        transport_config: H3TransportConfig,
        session_cache: NativeH3SessionCache,
        session_cache_key: NativeH3SessionCacheKey,
        pending_zero_rtt: Option<PendingZeroRttRequest>,
    ) -> Result<H3ConnectResult> {
        let mut zero_rtt_response_rx = None;
        let mut pending_zero_rtt_response = None;
        let mut native_handshake_report_override = None;
        if let Some(pending) = pending_zero_rtt {
            let status = handshake.handshake_status();
            if !status.early_data_accepted() {
                if status.early_data_rejected() {
                    session_cache.evict(&session_cache_key);
                }
                handshake.retire_client_application_packet(pending.packet_number);
                let packet = handshake.build_client_h3_replay_request_packet(
                    pending.stream_id,
                    &pending.request.method,
                    &pending.request.uri,
                    &pending.request.headers,
                    pending.request.body,
                )?;
                socket
                    .send_to(packet.packet.as_ref(), peer_addr)
                    .await
                    .map_err(Error::Io)?;
                native_handshake_report_override = Some(NativeH3HandshakeReport {
                    status: NativeH3HandshakeStatus::EarlyRejected,
                    early_data_reason: handshake.early_data_reason(),
                });
            }
            let (response_tx, response_rx) = oneshot::channel();
            pending_zero_rtt_response = Some(NativeH3PendingResponse {
                stream_id: pending.stream_id,
                response_tx,
            });
            zero_rtt_response_rx = Some(response_rx);
        }

        let handle = spawn_native_h3_driver(
            handshake,
            fingerprint,
            socket,
            peer_addr,
            max_idle_timeout,
            initial_datagram,
            transport_config,
            session_cache,
            session_cache_key,
            pending_zero_rtt_response,
            native_handshake_report_override,
        )?;

        Ok(H3ConnectResult {
            handle,
            zero_rtt_response_rx,
        })
    }

    async fn handle_client_loss_detection_timeout(
        handshake: &mut NativeQuicHandshake,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let Some(timer) = handshake.loss_detection_timer() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < timer {
            return Ok(());
        }

        let pto = handshake.application_pto();
        match handshake.on_loss_detection_timeout(now) {
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Initial,
            } => {
                for packet in handshake.retransmit_pto_client_initial_crypto_packets(now, pto)? {
                    socket
                        .send_to(packet.packet.as_ref(), peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
            }
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Handshake,
            } => {
                for packet in handshake.retransmit_pto_client_handshake_crypto_packets(now, pto)? {
                    socket
                        .send_to(packet.packet.as_ref(), peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
            }
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Application,
            }
            | LossDetectionOutcome::Loss { .. }
            | LossDetectionOutcome::Idle => {}
        }
        Ok(())
    }
}

fn random_connection_id(len: usize) -> Result<ConnectionId> {
    if len > MAX_CONNECTION_ID_LEN {
        return Err(Error::Quic(format!(
            "QUIC connection id length exceeds {MAX_CONNECTION_ID_LEN} bytes"
        )));
    }
    let mut bytes = vec![0u8; len];
    getrandom_fill(&mut bytes).map_err(|e| Error::Quic(format!("RNG error: {}", e)))?;
    ConnectionId::from_bytes(Bytes::from(bytes))
}

fn bind_udp_socket(local_addr: SocketAddr, transport: &QuicTransportParams) -> Result<UdpSocket> {
    let socket = bind_socket2_udp_socket(local_addr, transport)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(Error::Io)
}

fn bind_socket2_udp_socket(
    local_addr: SocketAddr,
    transport: &QuicTransportParams,
) -> Result<socket2::Socket> {
    let domain = if local_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(Error::Io)?;
    let _ = socket.set_recv_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES);
    let _ = socket.set_send_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES);
    enable_udp_ecn_receive(&socket, local_addr).map_err(Error::Io)?;
    apply_udp_ecn_marking(&socket, local_addr, transport)?;
    socket.set_nonblocking(true).map_err(Error::Io)?;
    socket.bind(&local_addr.into()).map_err(Error::Io)?;
    Ok(socket)
}

fn apply_udp_ecn_marking(
    socket: &socket2::Socket,
    local_addr: SocketAddr,
    transport: &QuicTransportParams,
) -> Result<()> {
    let Some(codepoint) = transport.ecn_codepoint else {
        return Ok(());
    };
    let tos_bits = codepoint.ip_tos_bits();
    if local_addr.is_ipv4() {
        socket.set_tos_v4(tos_bits).map_err(Error::Io)?;
    } else {
        #[cfg(unix)]
        {
            socket.set_tclass_v6(tos_bits).map_err(Error::Io)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::http3::{QuicEcnCodepoint, QuicTransportParams};

    #[test]
    fn native_h3_udp_socket_leaves_ipv4_ecn_unmarked_by_default() {
        let transport = QuicTransportParams::chrome();
        let socket = bind_socket2_udp_socket("127.0.0.1:0".parse().unwrap(), &transport)
            .expect("bind socket");

        assert_eq!(socket.tos_v4().expect("ipv4 tos") & 0b11, 0);
    }

    #[test]
    fn native_h3_udp_socket_applies_configured_ipv4_ecn_marking() {
        let mut transport = QuicTransportParams::chrome();
        transport.ecn_codepoint = Some(QuicEcnCodepoint::Ect0);
        let socket = bind_socket2_udp_socket("127.0.0.1:0".parse().unwrap(), &transport)
            .expect("bind socket");

        assert_eq!(
            socket.tos_v4().expect("ipv4 tos") & 0b11,
            QuicEcnCodepoint::Ect0.ip_tos_bits()
        );
    }
}
