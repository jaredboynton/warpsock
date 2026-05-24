//! Native QUIC handshake state for HTTP/3.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::fingerprint::{Http3Fingerprint, QuicTransportParams, TlsFingerprint};
use crate::transport::h3::native;
use crate::transport::h3::quic::{
    build_initial_crypto_packet, decode_frames, decode_transport_parameters,
    decode_version_negotiation_packet, derive_initial_key_material, encode_frame,
    encode_long_header, open_long_header_packet, open_short_header_packet,
    protect_long_header_packet, protect_short_header_packet, split_long_header_datagram,
    validate_retry_integrity_tag_v1, ConnectionId, LongHeaderPacket, LongHeaderType,
    QuicAckTracker, QuicCryptoAssembler, QuicFrame, QuicLossDetector, QuicPacketKeyMaterial,
    QuicPathValidator, TransportParameter,
};
use crate::transport::h3::tls::{
    build_client_initial_packet_from_capture_with_size,
    build_client_initial_packet_from_capture_with_version_and_size, ClientInitialPacket,
    NativeQuicTlsSession, QuicEncryptionLevel, QuicSecretDirection, QuicTlsSecret,
};

use getrandom::fill as getrandom_fill;

const QUIC_VERSION_1: u32 = 1;
const INITIAL_PACKET_NUMBER_LEN: usize = 4;
const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedServerInitial {
    pub packet_number: u64,
    pub crypto_data: Bytes,
    pub initial_crypto_out: Bytes,
    pub handshake_crypto_out: Bytes,
    pub secrets: Vec<QuicTlsSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakePacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub packet_number_offset: usize,
    pub crypto_data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshakePacket {
    pub packet: Bytes,
    pub packet_type: LongHeaderType,
    pub packet_number: u64,
    pub packet_number_offset: usize,
    pub crypto_data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshakeFlight {
    pub datagram: Bytes,
    pub packets: Vec<ServerHandshakePacket>,
    pub secrets: Vec<QuicTlsSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedClientHandshake {
    pub packet_number: u64,
    pub crypto_data: Bytes,
    pub secrets: Vec<QuicTlsSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAckPacket {
    pub packet: Bytes,
    pub packet_type: LongHeaderType,
    pub packet_number: u64,
    pub packet_number_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientApplicationPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub stream_id: u64,
    pub packet_number_offset: usize,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerApplicationPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub stream_id: u64,
    pub packet_number_offset: usize,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerApplicationAckPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub packet_number_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerApplicationControlPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub packet_number_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientApplicationAckPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub packet_number_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientApplicationControlPacket {
    pub packet: Bytes,
    pub packet_number: u64,
    pub packet_number_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerH3StreamEvent {
    pub stream_id: u64,
    pub stream_type: Option<native::H3StreamType>,
    pub fin: bool,
    pub frames: Vec<native::H3Frame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientH3StreamEvent {
    pub stream_id: u64,
    pub stream_type: Option<native::H3StreamType>,
    pub fin: bool,
    pub frames: Vec<native::H3Frame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientH3Event {
    Stream(ClientH3StreamEvent),
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: Bytes,
    },
    PathChallenge([u8; 8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerH3Event {
    Stream(ServerH3StreamEvent),
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: Bytes,
    },
    PathChallenge([u8; 8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SentApplicationStreamPacket {
    stream_id: u64,
    stream_offset: u64,
    fin: bool,
    data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SentCryptoPacket {
    packet_type: LongHeaderType,
    crypto_offset: u64,
    crypto_data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicApplicationFlowControl {
    local_initiator: u64,
    max_data: u64,
    sent_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    stream_sent: BTreeMap<u64, u64>,
    stream_data_overrides: BTreeMap<u64, u64>,
    last_blocked: Option<QuicFrame>,
}

impl QuicApplicationFlowControl {
    fn client(peer_transport: &QuicTransportParams) -> Self {
        Self::new(0, peer_transport)
    }

    fn server(peer_transport: &QuicTransportParams) -> Self {
        Self::new(1, peer_transport)
    }

    fn new(local_initiator: u64, peer_transport: &QuicTransportParams) -> Self {
        Self {
            local_initiator,
            max_data: peer_transport.initial_max_data,
            sent_data: 0,
            initial_max_stream_data_bidi_local: peer_transport.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: peer_transport.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: peer_transport.initial_max_stream_data_uni,
            initial_max_streams_bidi: peer_transport.initial_max_streams_bidi,
            initial_max_streams_uni: peer_transport.initial_max_streams_uni,
            stream_sent: BTreeMap::new(),
            stream_data_overrides: BTreeMap::new(),
            last_blocked: None,
        }
    }

    fn apply_max_data(&mut self, max_data: u64) {
        self.max_data = self.max_data.max(max_data);
    }

    fn apply_max_stream_data(&mut self, stream_id: u64, max_stream_data: u64) {
        self.stream_data_overrides
            .entry(stream_id)
            .and_modify(|current| *current = (*current).max(max_stream_data))
            .or_insert(max_stream_data);
    }

    fn apply_max_streams(&mut self, bidirectional: bool, max_streams: u64) {
        if bidirectional {
            self.initial_max_streams_bidi = self.initial_max_streams_bidi.max(max_streams);
        } else {
            self.initial_max_streams_uni = self.initial_max_streams_uni.max(max_streams);
        }
    }

    fn take_blocked_frame(&mut self) -> Option<QuicFrame> {
        self.last_blocked.take()
    }

    fn consume_stream_data(
        &mut self,
        stream_id: u64,
        stream_offset: u64,
        len: usize,
    ) -> Result<()> {
        let stream_limit = self.stream_data_limit(stream_id)?;
        let data_end = stream_offset
            .checked_add(len as u64)
            .ok_or_else(|| Error::HttpProtocol("QUIC flow control range overflow".into()))?;
        if data_end > stream_limit {
            self.last_blocked = Some(QuicFrame::StreamDataBlocked {
                stream_id,
                maximum_stream_data: stream_limit,
            });
            return Err(Error::Quic(format!(
                "native H3 flow control blocked stream {stream_id}: end offset {data_end} exceeds peer stream limit {stream_limit}"
            )));
        }

        let previous_stream_sent = *self.stream_sent.get(&stream_id).unwrap_or(&0);
        let new_connection_bytes = data_end.saturating_sub(previous_stream_sent);
        let next_sent_data = self
            .sent_data
            .checked_add(new_connection_bytes)
            .ok_or_else(|| Error::HttpProtocol("QUIC flow control data overflow".into()))?;
        if next_sent_data > self.max_data {
            self.last_blocked = Some(QuicFrame::DataBlocked {
                maximum_data: self.max_data,
            });
            return Err(Error::Quic(format!(
                "native H3 flow control blocked stream {stream_id}: connection data {next_sent_data} exceeds peer connection limit {}",
                self.max_data
            )));
        }

        self.sent_data = next_sent_data;
        self.stream_sent
            .insert(stream_id, previous_stream_sent.max(data_end));
        self.last_blocked = None;
        Ok(())
    }

    fn stream_data_limit(&mut self, stream_id: u64) -> Result<u64> {
        let initial_limit = if is_bidirectional_stream(stream_id) {
            if stream_initiator(stream_id) == self.local_initiator {
                self.ensure_stream_count(
                    stream_id,
                    self.initial_max_streams_bidi,
                    "bidirectional",
                )?;
                self.initial_max_stream_data_bidi_remote
            } else {
                self.initial_max_stream_data_bidi_local
            }
        } else {
            if stream_initiator(stream_id) != self.local_initiator {
                return Err(Error::Quic(format!(
                    "native H3 flow control cannot send on peer-initiated unidirectional stream {stream_id}"
                )));
            }
            self.ensure_stream_count(stream_id, self.initial_max_streams_uni, "unidirectional")?;
            self.initial_max_stream_data_uni
        };
        Ok(self
            .stream_data_overrides
            .get(&stream_id)
            .copied()
            .unwrap_or(initial_limit)
            .max(initial_limit))
    }

    fn ensure_stream_count(&mut self, stream_id: u64, max_streams: u64, label: &str) -> Result<()> {
        let required_stream_count = (stream_id >> 2) + 1;
        if required_stream_count > max_streams {
            self.last_blocked = Some(QuicFrame::StreamsBlocked {
                bidirectional: label == "bidirectional",
                maximum_streams: max_streams,
            });
            return Err(Error::Quic(format!(
                "native H3 flow control blocked stream {stream_id}: opening {required_stream_count} {label} streams exceeds peer limit {max_streams}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicReceiveFlowControl {
    local_initiator: u64,
    max_data: u64,
    max_connection_window: u64,
    received_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    max_stream_window: u64,
    stream_received: BTreeMap<u64, u64>,
    stream_data_overrides: BTreeMap<u64, u64>,
    pending_max_data: Option<u64>,
    pending_max_stream_data: BTreeMap<u64, u64>,
}

impl QuicReceiveFlowControl {
    fn client(local_transport: &QuicTransportParams) -> Self {
        Self::new(0, local_transport)
    }

    fn server(local_transport: &QuicTransportParams) -> Self {
        Self::new(1, local_transport)
    }

    fn new(local_initiator: u64, local_transport: &QuicTransportParams) -> Self {
        Self {
            local_initiator,
            max_data: local_transport.initial_max_data,
            max_connection_window: local_transport
                .max_connection_window
                .max(local_transport.initial_max_data),
            received_data: 0,
            initial_max_stream_data_bidi_local: local_transport.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: local_transport
                .initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: local_transport.initial_max_stream_data_uni,
            max_stream_window: local_transport.max_stream_window,
            stream_received: BTreeMap::new(),
            stream_data_overrides: BTreeMap::new(),
            pending_max_data: None,
            pending_max_stream_data: BTreeMap::new(),
        }
    }

    fn observe_stream_frame(
        &mut self,
        stream_id: u64,
        offset: Option<u64>,
        len: usize,
    ) -> Result<()> {
        let stream_limit = self.stream_data_limit(stream_id)?;
        let stream_offset = offset.unwrap_or(0);
        let data_end = stream_offset.checked_add(len as u64).ok_or_else(|| {
            Error::HttpProtocol("QUIC receive flow control range overflow".into())
        })?;
        if data_end > stream_limit {
            return Err(Error::Quic(format!(
                "native H3 receive flow control blocked stream {stream_id}: end offset {data_end} exceeds local stream limit {stream_limit}"
            )));
        }

        let previous_stream_received = *self.stream_received.get(&stream_id).unwrap_or(&0);
        let new_connection_bytes = data_end.saturating_sub(previous_stream_received);
        let next_received_data = self
            .received_data
            .checked_add(new_connection_bytes)
            .ok_or_else(|| Error::HttpProtocol("QUIC receive flow control data overflow".into()))?;
        if next_received_data > self.max_data {
            return Err(Error::Quic(format!(
                "native H3 receive flow control blocked stream {stream_id}: connection data {next_received_data} exceeds local connection limit {}",
                self.max_data
            )));
        }

        self.received_data = next_received_data;
        self.stream_received
            .insert(stream_id, previous_stream_received.max(data_end));
        self.maybe_queue_connection_window_update();
        self.maybe_queue_stream_window_update(stream_id)?;
        Ok(())
    }

    fn take_update_frames(&mut self) -> Vec<QuicFrame> {
        let mut frames = Vec::new();
        if let Some(max_data) = self.pending_max_data.take() {
            frames.push(QuicFrame::MaxData(max_data));
        }
        frames.extend(
            std::mem::take(&mut self.pending_max_stream_data)
                .into_iter()
                .map(|(stream_id, max_stream_data)| QuicFrame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                }),
        );
        frames
    }

    fn maybe_queue_connection_window_update(&mut self) {
        if self.max_data >= self.max_connection_window {
            return;
        }
        let remaining = self.max_data.saturating_sub(self.received_data);
        if remaining <= self.max_data / 2 {
            self.max_data = self.max_connection_window;
            self.pending_max_data = Some(self.max_data);
        }
    }

    fn maybe_queue_stream_window_update(&mut self, stream_id: u64) -> Result<()> {
        let current_limit = self.stream_data_limit(stream_id)?;
        let max_stream_window = self.max_stream_window.max(current_limit);
        if current_limit >= max_stream_window {
            return Ok(());
        }
        let received = *self.stream_received.get(&stream_id).unwrap_or(&0);
        let remaining = current_limit.saturating_sub(received);
        if remaining <= current_limit / 2 {
            self.stream_data_overrides
                .insert(stream_id, max_stream_window);
            self.pending_max_stream_data
                .insert(stream_id, max_stream_window);
        }
        Ok(())
    }

    fn stream_data_limit(&self, stream_id: u64) -> Result<u64> {
        if let Some(max_stream_data) = self.stream_data_overrides.get(&stream_id) {
            return Ok(*max_stream_data);
        }
        if is_bidirectional_stream(stream_id) {
            if stream_initiator(stream_id) == self.local_initiator {
                Ok(self.initial_max_stream_data_bidi_local)
            } else {
                Ok(self.initial_max_stream_data_bidi_remote)
            }
        } else if stream_initiator(stream_id) == self.local_initiator {
            Err(Error::Quic(format!(
                "native H3 receive flow control cannot receive on local unidirectional stream {stream_id}"
            )))
        } else {
            Ok(self.initial_max_stream_data_uni)
        }
    }
}

pub struct NativeQuicHandshake {
    client_initial: ClientInitialPacket,
    pending_client_initial: Option<ClientInitialPacket>,
    tls: NativeQuicTlsSession,
    fingerprint: Http3Fingerprint,
    server_name: String,
    tls_fingerprint: Option<TlsFingerprint>,
    verify_peer: bool,
    root_certs: Vec<Vec<u8>>,
    use_platform_roots: bool,
    supported_versions: Vec<u32>,
    client_initial_version: u32,
    retry_received: bool,
    vn_received: bool,
    server_initial_or_handshake_seen: bool,
    original_destination_cid: ConnectionId,
    retry_source_cid: Option<ConnectionId>,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
    client_initial_keys: QuicPacketKeyMaterial,
    server_initial_keys: QuicPacketKeyMaterial,
    client_handshake_keys: Option<QuicPacketKeyMaterial>,
    server_handshake_keys: Option<QuicPacketKeyMaterial>,
    client_application_keys: Option<QuicPacketKeyMaterial>,
    server_application_keys: Option<QuicPacketKeyMaterial>,
    initial_crypto: QuicCryptoAssembler,
    handshake_crypto: QuicCryptoAssembler,
    initial_ack_tracker: QuicAckTracker,
    handshake_ack_tracker: QuicAckTracker,
    application_ack_tracker: QuicAckTracker,
    client_handshake_loss_detector: QuicLossDetector,
    client_application_loss_detector: QuicLossDetector,
    client_application_flow_control: QuicApplicationFlowControl,
    client_application_receive_flow_control: QuicReceiveFlowControl,
    client_handshake_sent_crypto: BTreeMap<u64, SentCryptoPacket>,
    client_application_sent_streams: BTreeMap<u64, SentApplicationStreamPacket>,
    client_path_validator: QuicPathValidator,
    server_transport_parameters_validated: bool,
    next_client_initial_packet_number: u64,
    next_server_initial_packet_number: u64,
    next_server_handshake_packet_number: u64,
    next_client_handshake_packet_number: u64,
    next_server_application_packet_number: u64,
    next_client_application_packet_number: u64,
    next_client_bidirectional_stream_id: u64,
    next_client_unidirectional_stream_id: u64,
    client_handshake_crypto_offset: u64,
    client_stream_offsets: BTreeMap<u64, u64>,
    server_h3_stream_buffers: BTreeMap<u64, BytesMut>,
    server_h3_stream_buffer_offsets: BTreeMap<u64, u64>,
    server_h3_stream_types: BTreeMap<u64, native::H3StreamType>,
    close_draining: bool,
}

pub struct NativeQuicServerHandshake {
    tls: NativeQuicTlsSession,
    client_source_cid: ConnectionId,
    server_source_cid: ConnectionId,
    client_initial_keys: QuicPacketKeyMaterial,
    server_initial_keys: QuicPacketKeyMaterial,
    client_handshake_keys: Option<QuicPacketKeyMaterial>,
    server_handshake_keys: Option<QuicPacketKeyMaterial>,
    client_initial_crypto: QuicCryptoAssembler,
    client_handshake_crypto: QuicCryptoAssembler,
    client_initial_ack_tracker: QuicAckTracker,
    client_handshake_ack_tracker: QuicAckTracker,
    client_application_ack_tracker: QuicAckTracker,
    server_application_loss_detector: QuicLossDetector,
    server_application_flow_control: QuicApplicationFlowControl,
    server_application_receive_flow_control: QuicReceiveFlowControl,
    server_application_sent_streams: BTreeMap<u64, SentApplicationStreamPacket>,
    next_client_initial_packet_number: u64,
    next_client_handshake_packet_number: u64,
    next_client_application_packet_number: u64,
    next_server_initial_packet_number: u64,
    next_server_handshake_packet_number: u64,
    next_server_application_packet_number: u64,
    next_server_unidirectional_stream_id: u64,
    client_application_keys: Option<QuicPacketKeyMaterial>,
    server_application_keys: Option<QuicPacketKeyMaterial>,
    server_initial_crypto_offset: u64,
    server_handshake_crypto_offset: u64,
    server_stream_offsets: BTreeMap<u64, u64>,
    server_control_stream_id: Option<u64>,
    client_h3_stream_buffers: BTreeMap<u64, BytesMut>,
    client_h3_stream_buffer_offsets: BTreeMap<u64, u64>,
    client_h3_stream_types: BTreeMap<u64, native::H3StreamType>,
    close_draining: bool,
}

impl NativeQuicServerHandshake {
    pub fn new(
        fingerprint: &Http3Fingerprint,
        cert_pem: &[u8],
        key_pem: &[u8],
        client_destination_cid: ConnectionId,
        client_source_cid: ConnectionId,
        server_source_cid: ConnectionId,
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(client_destination_cid.as_bytes())?;
        Ok(Self {
            tls: NativeQuicTlsSession::server_with_connection_ids(
                fingerprint,
                cert_pem,
                key_pem,
                &client_destination_cid,
                &server_source_cid,
            )?,
            client_source_cid,
            server_source_cid,
            client_initial_keys: initial_keys.client,
            server_initial_keys: initial_keys.server,
            client_handshake_keys: None,
            server_handshake_keys: None,
            client_initial_crypto: QuicCryptoAssembler::default(),
            client_handshake_crypto: QuicCryptoAssembler::default(),
            client_initial_ack_tracker: QuicAckTracker::default(),
            client_handshake_ack_tracker: QuicAckTracker::default(),
            client_application_ack_tracker: QuicAckTracker::default(),
            server_application_loss_detector: QuicLossDetector::default(),
            server_application_flow_control: QuicApplicationFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_receive_flow_control: QuicReceiveFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_sent_streams: BTreeMap::new(),
            next_client_initial_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_client_application_packet_number: 0,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_server_unidirectional_stream_id: 3,
            client_application_keys: None,
            server_application_keys: None,
            server_initial_crypto_offset: 0,
            server_handshake_crypto_offset: 0,
            server_stream_offsets: BTreeMap::new(),
            server_control_stream_id: None,
            client_h3_stream_buffers: BTreeMap::new(),
            client_h3_stream_buffer_offsets: BTreeMap::new(),
            client_h3_stream_types: BTreeMap::new(),
            close_draining: false,
        })
    }

    pub fn new_with_transport_parameter_connection_ids(
        fingerprint: &Http3Fingerprint,
        cert_pem: &[u8],
        key_pem: &[u8],
        client_destination_cid: ConnectionId,
        client_source_cid: ConnectionId,
        server_source_cid: ConnectionId,
        transport_original_destination_cid: ConnectionId,
        transport_initial_source_cid: ConnectionId,
        transport_retry_source_cid: Option<ConnectionId>,
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(client_destination_cid.as_bytes())?;
        Ok(Self {
            tls: NativeQuicTlsSession::server_with_transport_parameter_connection_ids(
                fingerprint,
                cert_pem,
                key_pem,
                &transport_original_destination_cid,
                &transport_initial_source_cid,
                transport_retry_source_cid.as_ref(),
            )?,
            client_source_cid,
            server_source_cid,
            client_initial_keys: initial_keys.client,
            server_initial_keys: initial_keys.server,
            client_handshake_keys: None,
            server_handshake_keys: None,
            client_initial_crypto: QuicCryptoAssembler::default(),
            client_handshake_crypto: QuicCryptoAssembler::default(),
            client_initial_ack_tracker: QuicAckTracker::default(),
            client_handshake_ack_tracker: QuicAckTracker::default(),
            client_application_ack_tracker: QuicAckTracker::default(),
            server_application_loss_detector: QuicLossDetector::default(),
            server_application_flow_control: QuicApplicationFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_receive_flow_control: QuicReceiveFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_sent_streams: BTreeMap::new(),
            next_client_initial_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_client_application_packet_number: 0,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_server_unidirectional_stream_id: 3,
            client_application_keys: None,
            server_application_keys: None,
            server_initial_crypto_offset: 0,
            server_handshake_crypto_offset: 0,
            server_stream_offsets: BTreeMap::new(),
            server_control_stream_id: None,
            client_h3_stream_buffers: BTreeMap::new(),
            client_h3_stream_buffer_offsets: BTreeMap::new(),
            client_h3_stream_types: BTreeMap::new(),
            close_draining: false,
        })
    }

    pub fn is_application_ready(&self) -> bool {
        self.client_application_keys.is_some() && self.server_application_keys.is_some()
    }

    pub fn is_close_draining(&self) -> bool {
        self.close_draining
    }

    pub fn server_application_lost_packets(&self) -> Vec<u64> {
        self.server_application_loss_detector.lost_packets()
    }

    pub fn retransmit_lost_server_application_stream_packets(
        &mut self,
    ) -> Result<Vec<ServerApplicationPacket>> {
        let lost_packets = self.server_application_loss_detector.lost_packets();
        let mut retransmits = Vec::new();
        for packet_number in lost_packets {
            self.server_application_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.server_application_sent_streams.remove(&packet_number) else {
                continue;
            };
            retransmits.push(self.build_server_application_stream_packet_at_offset(
                sent.stream_id,
                sent.stream_offset,
                sent.data,
                sent.fin,
            )?);
        }
        Ok(retransmits)
    }

    pub fn process_client_initial(&mut self, datagram: &[u8]) -> Result<ServerHandshakeFlight> {
        let mut server_initial_crypto = Bytes::new();
        let mut server_handshake_crypto = Bytes::new();

        for packet in split_long_header_datagram(datagram)? {
            if packet.packet_type != LongHeaderType::Initial {
                continue;
            }

            let opened = open_long_header_packet(
                &self.client_initial_keys,
                &packet.packet,
                packet.packet_number_offset,
                self.next_client_initial_packet_number,
            )?;
            self.client_initial_ack_tracker
                .observe(opened.packet_number);
            self.next_client_initial_packet_number = opened.packet_number + 1;

            for frame in decode_frames(&opened.payload)? {
                if let QuicFrame::Crypto { offset, data } = frame {
                    self.client_initial_crypto.insert(offset, data)?;
                }
            }

            let crypto_data = self.client_initial_crypto.take_contiguous();
            if crypto_data.is_empty() {
                continue;
            }

            self.tls
                .provide_crypto(QuicEncryptionLevel::Initial, &crypto_data)?;
            self.install_tls_secrets()?;
            server_initial_crypto = self.tls.take_crypto(QuicEncryptionLevel::Initial);
            server_handshake_crypto = self.tls.take_crypto(QuicEncryptionLevel::Handshake);
        }

        let secrets = self.tls.secrets();
        let mut packets = Vec::new();
        let mut datagram_out = Vec::new();

        if !server_initial_crypto.is_empty() {
            let packet = self.build_server_initial_packet(server_initial_crypto)?;
            datagram_out.extend_from_slice(&packet.packet);
            packets.push(packet);
        }
        if !server_handshake_crypto.is_empty() {
            let packet = self.build_server_handshake_packet(server_handshake_crypto)?;
            datagram_out.extend_from_slice(&packet.packet);
            packets.push(packet);
        }

        Ok(ServerHandshakeFlight {
            datagram: Bytes::from(datagram_out),
            packets,
            secrets,
        })
    }

    pub fn build_server_initial_ack_packet(&mut self) -> Result<Option<ClientAckPacket>> {
        let packet = build_ack_packet(
            LongHeaderType::Initial,
            &self.server_initial_keys,
            &self.client_source_cid,
            &self.server_source_cid,
            &mut self.client_initial_ack_tracker,
            self.next_server_initial_packet_number,
        )?;
        if packet.is_some() {
            self.next_server_initial_packet_number += 1;
        }
        Ok(packet)
    }

    pub fn build_server_handshake_ack_packet(&mut self) -> Result<Option<ClientAckPacket>> {
        if self.client_handshake_ack_tracker.is_empty() {
            return Ok(None);
        }
        let Some(server_handshake_keys) = &self.server_handshake_keys else {
            return Err(Error::Quic(
                "native server Handshake ACK encryption is waiting for TLS Handshake keys".into(),
            ));
        };
        let packet = build_ack_packet(
            LongHeaderType::Handshake,
            server_handshake_keys,
            &self.client_source_cid,
            &self.server_source_cid,
            &mut self.client_handshake_ack_tracker,
            self.next_server_handshake_packet_number,
        )?;
        if packet.is_some() {
            self.next_server_handshake_packet_number += 1;
        }
        Ok(packet)
    }

    pub fn process_client_handshake(
        &mut self,
        datagram: &[u8],
    ) -> Result<ProcessedClientHandshake> {
        let Some(client_handshake_keys) = &self.client_handshake_keys else {
            return Err(Error::Quic(
                "native server Handshake packet decryption is waiting for TLS Handshake keys"
                    .into(),
            ));
        };

        let mut packet_number = self.next_client_handshake_packet_number;
        for packet in split_long_header_datagram(datagram)? {
            if packet.packet_type != LongHeaderType::Handshake {
                continue;
            }

            let opened = open_long_header_packet(
                client_handshake_keys,
                &packet.packet,
                packet.packet_number_offset,
                self.next_client_handshake_packet_number,
            )?;
            packet_number = opened.packet_number;
            self.client_handshake_ack_tracker
                .observe(opened.packet_number);
            self.next_client_handshake_packet_number = opened.packet_number + 1;

            for frame in decode_frames(&opened.payload)? {
                if let QuicFrame::Crypto { offset, data } = frame {
                    self.client_handshake_crypto.insert(offset, data)?;
                }
            }
        }

        let crypto_data = self.client_handshake_crypto.take_contiguous();
        if !crypto_data.is_empty() {
            self.tls
                .provide_crypto(QuicEncryptionLevel::Handshake, &crypto_data)?;
            self.install_tls_secrets()?;
        }

        Ok(ProcessedClientHandshake {
            packet_number,
            crypto_data,
            secrets: self.tls.secrets(),
        })
    }

    pub fn open_client_application_packet(&mut self, packet: &[u8]) -> Result<Vec<QuicFrame>> {
        if self.close_draining {
            return Ok(Vec::new());
        }
        let Some(client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native server application packet decryption is waiting for TLS application keys"
                    .into(),
            ));
        };
        let opened = open_short_header_packet(
            client_application_keys,
            packet,
            self.server_source_cid.as_bytes().len(),
            self.next_client_application_packet_number,
        )?;
        self.next_client_application_packet_number = opened.packet_number + 1;
        let frames = decode_frames(&opened.payload)?;
        for frame in &frames {
            if let QuicFrame::Stream {
                stream_id,
                offset,
                data,
                ..
            } = frame
            {
                self.server_application_receive_flow_control
                    .observe_stream_frame(*stream_id, *offset, data.len())?;
            }
            for packet_number in self.server_application_loss_detector.on_ack_frame(frame)? {
                self.server_application_sent_streams.remove(&packet_number);
            }
            match frame {
                QuicFrame::MaxData(max_data) => {
                    self.server_application_flow_control
                        .apply_max_data(*max_data);
                }
                QuicFrame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                } => self
                    .server_application_flow_control
                    .apply_max_stream_data(*stream_id, *max_stream_data),
                QuicFrame::MaxStreams {
                    bidirectional,
                    max_streams,
                } => self
                    .server_application_flow_control
                    .apply_max_streams(*bidirectional, *max_streams),
                _ => {}
            }
        }
        if frames.iter().any(is_ack_eliciting_quic_frame) {
            self.client_application_ack_tracker
                .observe(opened.packet_number);
        }
        Ok(frames.into_iter().filter(is_not_padding_frame).collect())
    }

    pub fn build_server_application_ack_packet(
        &mut self,
    ) -> Result<Option<ServerApplicationAckPacket>> {
        self.build_server_application_ack_packet_with_delay(Instant::now(), 0)
    }

    pub fn build_server_application_ack_packet_with_delay(
        &mut self,
        now: Instant,
        ack_delay_exponent: u64,
    ) -> Result<Option<ServerApplicationAckPacket>> {
        if self.client_application_ack_tracker.is_empty() {
            return Ok(None);
        }
        let Some(server_application_keys) = &self.server_application_keys else {
            return Err(Error::Quic(
                "native server application ACK encryption is waiting for TLS application keys"
                    .into(),
            ));
        };

        let packet_number = self.next_server_application_packet_number;
        let packet_number_len = 2;
        let frame = encode_frame(
            &self
                .client_application_ack_tracker
                .to_ack_frame_with_delay(now, ack_delay_exponent)?,
        );
        let packet = protect_short_header_packet(
            server_application_keys,
            &self.client_source_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;
        self.client_application_ack_tracker.mark_ack_sent();
        self.next_server_application_packet_number += 1;

        Ok(Some(ServerApplicationAckPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + self.client_source_cid.as_bytes().len(),
        }))
    }

    pub fn build_server_application_ack_packet_after(
        &mut self,
        threshold: usize,
    ) -> Result<Option<ServerApplicationAckPacket>> {
        if !self
            .client_application_ack_tracker
            .should_ack_after(threshold)
        {
            return Ok(None);
        }
        self.build_server_application_ack_packet()
    }

    pub fn build_server_application_ack_packet_after_or_delay(
        &mut self,
        threshold: usize,
        max_ack_delay: Duration,
        now: Instant,
        ack_delay_exponent: u64,
    ) -> Result<Option<ServerApplicationAckPacket>> {
        if !self
            .client_application_ack_tracker
            .should_ack_after_or_delay(threshold, max_ack_delay, now)
        {
            return Ok(None);
        }
        self.build_server_application_ack_packet_with_delay(now, ack_delay_exponent)
    }

    pub fn server_application_ack_deadline(&self, max_ack_delay: Duration) -> Option<Instant> {
        self.client_application_ack_tracker
            .pending_ack_deadline(max_ack_delay)
    }

    pub fn open_client_h3_stream_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<ClientH3StreamEvent>> {
        Ok(self
            .open_client_h3_event_packet(packet)?
            .into_iter()
            .filter_map(|event| match event {
                ClientH3Event::Stream(event) => Some(event),
                ClientH3Event::ResetStream { .. }
                | ClientH3Event::StopSending { .. }
                | ClientH3Event::ConnectionClose { .. }
                | ClientH3Event::PathChallenge(_) => None,
            })
            .collect())
    }

    pub fn open_client_h3_event_packet(&mut self, packet: &[u8]) -> Result<Vec<ClientH3Event>> {
        if self.close_draining {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for frame in self.open_client_application_packet(packet)? {
            match frame {
                QuicFrame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                } => {
                    if let Some(event) = apply_h3_stream_frame(
                        &mut self.client_h3_stream_buffers,
                        &mut self.client_h3_stream_buffer_offsets,
                        &mut self.client_h3_stream_types,
                        stream_id,
                        offset,
                        fin,
                        data,
                    )? {
                        events.push(ClientH3Event::Stream(ClientH3StreamEvent {
                            stream_id: event.stream_id,
                            stream_type: event.stream_type,
                            fin: event.fin,
                            frames: event.frames,
                        }));
                    }
                }
                QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } => events.push(ClientH3Event::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                }),
                QuicFrame::StopSending {
                    stream_id,
                    error_code,
                } => events.push(ClientH3Event::StopSending {
                    stream_id,
                    error_code,
                }),
                QuicFrame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    self.close_draining = true;
                    events.push(ClientH3Event::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                }
                QuicFrame::PathChallenge(data) => events.push(ClientH3Event::PathChallenge(data)),
                QuicFrame::Padding
                | QuicFrame::Ping
                | QuicFrame::Ack { .. }
                | QuicFrame::AckEcn { .. }
                | QuicFrame::Crypto { .. }
                | QuicFrame::MaxData(_)
                | QuicFrame::MaxStreamData { .. }
                | QuicFrame::MaxStreams { .. }
                | QuicFrame::DataBlocked { .. }
                | QuicFrame::StreamDataBlocked { .. }
                | QuicFrame::StreamsBlocked { .. }
                | QuicFrame::NewConnectionId { .. }
                | QuicFrame::RetireConnectionId { .. }
                | QuicFrame::PathResponse(_)
                | QuicFrame::HandshakeDone => {}
            }
        }
        Ok(events)
    }

    pub fn build_server_h3_settings_packet(
        &mut self,
        fingerprint: &Http3Fingerprint,
    ) -> Result<ServerApplicationPacket> {
        let stream_id = self.server_control_stream_id.unwrap_or_else(|| {
            let stream_id = self.next_server_unidirectional_stream_id;
            self.next_server_unidirectional_stream_id += 4;
            self.server_control_stream_id = Some(stream_id);
            stream_id
        });
        let settings = native::encode_frame(&native::H3Frame::Settings(
            native::encode_fingerprint_settings_payload(fingerprint),
        ));
        let payload = if self.server_stream_offsets.contains_key(&stream_id) {
            settings
        } else {
            native::encode_unidirectional_stream(&native::H3UnidirectionalStream {
                stream_type: native::H3StreamType::Control,
                payload: settings,
            })
        };
        self.build_server_application_stream_packet(stream_id, payload, false)
    }

    pub fn build_server_h3_goaway_packet(&mut self, id: u64) -> Result<ServerApplicationPacket> {
        let Some(stream_id) = self.server_control_stream_id else {
            return Err(Error::HttpProtocol(
                "native server H3 GOAWAY requires an open control stream".into(),
            ));
        };
        self.build_server_application_stream_packet(
            stream_id,
            native::encode_frame(&native::H3Frame::GoAway { id }),
            false,
        )
    }

    pub fn build_server_reset_stream_packet(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<ServerApplicationControlPacket> {
        let final_size = *self.server_stream_offsets.get(&stream_id).unwrap_or(&0);
        self.build_server_application_control_packet(QuicFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        })
    }

    pub fn build_server_connection_close_packet(
        &mut self,
        error_code: u64,
        reason: Bytes,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::ConnectionClose {
            error_code,
            frame_type: None,
            reason,
        })
    }

    pub fn build_server_max_data_packet(
        &mut self,
        max_data: u64,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::MaxData(max_data))
    }

    pub fn build_server_max_stream_data_packet(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::MaxStreamData {
            stream_id,
            max_stream_data,
        })
    }

    pub fn build_server_max_streams_packet(
        &mut self,
        bidirectional: bool,
        max_streams: u64,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::MaxStreams {
            bidirectional,
            max_streams,
        })
    }

    pub fn build_server_flow_control_blocked_packet(
        &mut self,
    ) -> Result<Option<ServerApplicationControlPacket>> {
        self.server_application_flow_control
            .take_blocked_frame()
            .map(|frame| self.build_server_application_control_packet(frame))
            .transpose()
    }

    pub fn build_server_receive_flow_control_update_packets(
        &mut self,
    ) -> Result<Vec<ServerApplicationControlPacket>> {
        self.server_application_receive_flow_control
            .take_update_frames()
            .into_iter()
            .map(|frame| self.build_server_application_control_packet(frame))
            .collect()
    }

    pub fn build_server_handshake_done_packet(&mut self) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::HandshakeDone)
    }

    pub fn build_server_h3_raw_stream_packet(
        &mut self,
        stream_id: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<ServerApplicationPacket> {
        self.build_server_application_stream_packet(stream_id, data, fin)
    }

    pub fn build_server_h3_response_packet(
        &mut self,
        stream_id: u64,
        headers: Vec<native::H3Header>,
        body: Option<Bytes>,
        fin: bool,
    ) -> Result<ServerApplicationPacket> {
        let mut payload = native::encode_frame(&native::H3Frame::Headers(
            native::encode_header_block(&headers),
        ))
        .to_vec();
        if let Some(body) = body {
            payload.extend_from_slice(&native::encode_frame(&native::H3Frame::Data(body)));
        }
        self.build_server_application_stream_packet(stream_id, Bytes::from(payload), fin)
    }

    pub fn build_server_h3_response_data_packet(
        &mut self,
        stream_id: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<ServerApplicationPacket> {
        self.build_server_application_stream_packet(
            stream_id,
            native::encode_frame(&native::H3Frame::Data(data)),
            fin,
        )
    }

    fn install_tls_secrets(&mut self) -> Result<()> {
        for secret in self.tls.secrets() {
            match (secret.direction, secret.level) {
                (QuicSecretDirection::Read, QuicEncryptionLevel::Handshake) => {
                    self.client_handshake_keys = Some(secret.packet_key_material()?);
                }
                (QuicSecretDirection::Write, QuicEncryptionLevel::Handshake) => {
                    self.server_handshake_keys = Some(secret.packet_key_material()?);
                }
                (QuicSecretDirection::Read, QuicEncryptionLevel::Application) => {
                    self.client_application_keys = Some(secret.packet_key_material()?);
                }
                (QuicSecretDirection::Write, QuicEncryptionLevel::Application) => {
                    self.server_application_keys = Some(secret.packet_key_material()?);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn build_server_initial_packet(&mut self, crypto_data: Bytes) -> Result<ServerHandshakePacket> {
        let packet_number = self.next_server_initial_packet_number;
        self.next_server_initial_packet_number += 1;
        let packet = build_server_crypto_packet(
            LongHeaderType::Initial,
            &self.server_initial_keys,
            &self.client_source_cid,
            &self.server_source_cid,
            packet_number,
            self.server_initial_crypto_offset,
            crypto_data,
        )?;
        self.server_initial_crypto_offset += packet.crypto_data.len() as u64;
        Ok(packet)
    }

    fn build_server_handshake_packet(
        &mut self,
        crypto_data: Bytes,
    ) -> Result<ServerHandshakePacket> {
        let Some(server_handshake_keys) = &self.server_handshake_keys else {
            return Err(Error::Quic(
                "native server Handshake packet encryption is waiting for TLS Handshake keys"
                    .into(),
            ));
        };
        let packet_number = self.next_server_handshake_packet_number;
        self.next_server_handshake_packet_number += 1;
        let packet = build_server_crypto_packet(
            LongHeaderType::Handshake,
            server_handshake_keys,
            &self.client_source_cid,
            &self.server_source_cid,
            packet_number,
            self.server_handshake_crypto_offset,
            crypto_data,
        )?;
        self.server_handshake_crypto_offset += packet.crypto_data.len() as u64;
        Ok(packet)
    }

    fn build_server_application_stream_packet(
        &mut self,
        stream_id: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<ServerApplicationPacket> {
        if data.is_empty() && !fin {
            return Err(Error::HttpProtocol(
                "native server H3 response produced no payload".into(),
            ));
        }
        let stream_offset = *self.server_stream_offsets.get(&stream_id).unwrap_or(&0);
        self.server_application_flow_control.consume_stream_data(
            stream_id,
            stream_offset,
            data.len(),
        )?;
        let packet = self.build_server_application_stream_packet_at_offset(
            stream_id,
            stream_offset,
            data,
            fin,
        )?;
        self.server_stream_offsets
            .insert(stream_id, stream_offset + packet.data.len() as u64);
        Ok(packet)
    }

    fn build_server_application_stream_packet_at_offset(
        &mut self,
        stream_id: u64,
        stream_offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<ServerApplicationPacket> {
        let Some(server_application_keys) = &self.server_application_keys else {
            return Err(Error::Quic(
                "native server application packet encryption is waiting for TLS application keys"
                    .into(),
            ));
        };

        let packet_number = self.next_server_application_packet_number;
        let packet_number_len = 2;
        let frame = encode_frame(&QuicFrame::Stream {
            stream_id,
            offset: (stream_offset > 0).then_some(stream_offset),
            fin,
            data: data.clone(),
        });
        let packet = protect_short_header_packet(
            server_application_keys,
            &self.client_source_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;

        self.server_application_loss_detector
            .on_packet_sent(packet_number);
        self.server_application_sent_streams.insert(
            packet_number,
            SentApplicationStreamPacket {
                stream_id,
                stream_offset,
                fin,
                data: data.clone(),
            },
        );
        self.next_server_application_packet_number += 1;

        Ok(ServerApplicationPacket {
            packet,
            packet_number,
            stream_id,
            packet_number_offset: 1 + self.client_source_cid.as_bytes().len(),
            data,
        })
    }

    fn build_server_application_control_packet(
        &mut self,
        frame: QuicFrame,
    ) -> Result<ServerApplicationControlPacket> {
        let Some(server_application_keys) = &self.server_application_keys else {
            return Err(Error::Quic(
                "native server application packet encryption is waiting for TLS application keys"
                    .into(),
            ));
        };

        let packet_number = self.next_server_application_packet_number;
        let packet_number_len = 2;
        let frame = padded_short_header_payload(encode_frame(&frame));
        let packet = protect_short_header_packet(
            server_application_keys,
            &self.client_source_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;
        self.server_application_loss_detector
            .on_packet_sent(packet_number);
        self.next_server_application_packet_number += 1;

        Ok(ServerApplicationControlPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + self.client_source_cid.as_bytes().len(),
        })
    }
}

impl NativeQuicHandshake {
    pub fn client(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
    ) -> Result<Self> {
        Self::client_with_verify_peer(server_name, fingerprint, destination_cid, source_cid, true)
    }

    pub fn client_with_verify_peer(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
        verify_peer: bool,
    ) -> Result<Self> {
        Self::client_with_tls_fingerprint(
            server_name,
            fingerprint,
            None,
            destination_cid,
            source_cid,
            verify_peer,
            &[],
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn client_with_tls_fingerprint(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(destination_cid.as_bytes())?;
        let mut tls =
            NativeQuicTlsSession::client_with_initial_source_connection_id_and_verify_peer(
                server_name,
                fingerprint,
                &source_cid,
                tls_fingerprint,
                verify_peer,
                root_certs,
                use_platform_roots,
            )?;
        let client_initial = build_client_initial_packet_from_capture_with_size(
            tls.take_client_initial(),
            destination_cid.clone(),
            source_cid.clone(),
            fingerprint.transport.initial_datagram_size,
        )?;

        Ok(Self {
            client_initial,
            pending_client_initial: None,
            tls,
            fingerprint: fingerprint.clone(),
            server_name: server_name.to_string(),
            tls_fingerprint: tls_fingerprint.cloned(),
            verify_peer,
            root_certs: root_certs.to_vec(),
            use_platform_roots,
            supported_versions: vec![QUIC_VERSION_1],
            client_initial_version: QUIC_VERSION_1,
            retry_received: false,
            vn_received: false,
            server_initial_or_handshake_seen: false,
            original_destination_cid: destination_cid.clone(),
            retry_source_cid: None,
            destination_cid,
            source_cid,
            client_initial_keys: initial_keys.client,
            server_initial_keys: initial_keys.server,
            client_handshake_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            initial_crypto: QuicCryptoAssembler::default(),
            handshake_crypto: QuicCryptoAssembler::default(),
            initial_ack_tracker: QuicAckTracker::default(),
            handshake_ack_tracker: QuicAckTracker::default(),
            application_ack_tracker: QuicAckTracker::default(),
            client_handshake_loss_detector: QuicLossDetector::default(),
            client_application_loss_detector: QuicLossDetector::default(),
            client_application_flow_control: QuicApplicationFlowControl::client(
                &fingerprint.transport,
            ),
            client_application_receive_flow_control: QuicReceiveFlowControl::client(
                &fingerprint.transport,
            ),
            client_handshake_sent_crypto: BTreeMap::new(),
            client_application_sent_streams: BTreeMap::new(),
            client_path_validator: QuicPathValidator::default(),
            server_transport_parameters_validated: false,
            next_client_initial_packet_number: 1,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_client_application_packet_number: 0,
            next_client_bidirectional_stream_id: 0,
            next_client_unidirectional_stream_id: 2,
            client_handshake_crypto_offset: 0,
            client_stream_offsets: BTreeMap::new(),
            server_h3_stream_buffers: BTreeMap::new(),
            server_h3_stream_buffer_offsets: BTreeMap::new(),
            server_h3_stream_types: BTreeMap::new(),
            close_draining: false,
        })
    }

    pub fn client_initial(&self) -> &ClientInitialPacket {
        &self.client_initial
    }

    pub fn take_pending_client_initial(&mut self) -> Option<ClientInitialPacket> {
        self.pending_client_initial.take()
    }

    pub fn supported_versions(&self) -> &[u32] {
        &self.supported_versions
    }

    pub fn set_supported_versions(&mut self, versions: Vec<u32>) -> Result<()> {
        if versions.is_empty() {
            return Err(Error::Quic(
                "native H3 supported QUIC versions list cannot be empty".into(),
            ));
        }
        if !versions.contains(&self.client_initial_version) {
            return Err(Error::Quic(
                "native H3 supported QUIC versions must include the issued initial version".into(),
            ));
        }
        self.supported_versions = versions;
        Ok(())
    }

    pub fn client_initial_version(&self) -> u32 {
        self.client_initial_version
    }

    pub fn retry_received(&self) -> bool {
        self.retry_received
    }

    pub fn version_negotiation_received(&self) -> bool {
        self.vn_received
    }

    pub fn install_tls_secrets(&mut self, secrets: &[QuicTlsSecret]) -> Result<()> {
        for secret in secrets {
            if secret.direction == QuicSecretDirection::Read
                && secret.level == QuicEncryptionLevel::Handshake
            {
                self.server_handshake_keys = Some(secret.packet_key_material()?);
            } else if secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Handshake
            {
                self.client_handshake_keys = Some(secret.packet_key_material()?);
            } else if secret.direction == QuicSecretDirection::Read
                && secret.level == QuicEncryptionLevel::Application
            {
                self.server_application_keys = Some(secret.packet_key_material()?);
            } else if secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Application
            {
                self.client_application_keys = Some(secret.packet_key_material()?);
            }
        }
        Ok(())
    }

    pub fn server_handshake_keys(&self) -> Option<&QuicPacketKeyMaterial> {
        self.server_handshake_keys.as_ref()
    }

    pub fn is_application_ready(&self) -> bool {
        self.client_application_keys.is_some() && self.server_application_keys.is_some()
    }

    pub fn is_close_draining(&self) -> bool {
        self.close_draining
    }

    pub fn client_path_validation_pending_count(&self) -> usize {
        self.client_path_validator.pending_count()
    }

    pub fn is_client_path_validated(&self, data: &[u8; 8]) -> bool {
        self.client_path_validator.is_validated(data)
    }

    pub fn client_application_lost_packets(&self) -> Vec<u64> {
        self.client_application_loss_detector.lost_packets()
    }

    pub fn retransmit_lost_client_application_stream_packets(
        &mut self,
    ) -> Result<Vec<ClientApplicationPacket>> {
        let lost_packets = self.client_application_loss_detector.lost_packets();
        let mut retransmits = Vec::new();
        for packet_number in lost_packets {
            self.client_application_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.client_application_sent_streams.remove(&packet_number) else {
                continue;
            };
            retransmits.push(self.build_client_application_stream_packet_at_offset(
                sent.stream_id,
                sent.stream_offset,
                sent.data,
                sent.fin,
            )?);
        }
        Ok(retransmits)
    }

    pub fn build_client_initial_ack_packet(&mut self) -> Result<Option<ClientAckPacket>> {
        let packet = build_ack_packet(
            LongHeaderType::Initial,
            &self.client_initial_keys,
            &self.destination_cid,
            &self.source_cid,
            &mut self.initial_ack_tracker,
            self.next_client_initial_packet_number,
        )?;
        if packet.is_some() {
            self.next_client_initial_packet_number += 1;
        }
        Ok(packet)
    }

    pub fn build_client_handshake_ack_packet(&mut self) -> Result<Option<ClientAckPacket>> {
        if self.handshake_ack_tracker.is_empty() {
            return Ok(None);
        }
        let Some(client_handshake_keys) = &self.client_handshake_keys else {
            return Err(Error::Quic(
                "native Handshake ACK encryption is waiting for TLS Handshake keys".into(),
            ));
        };
        let packet = build_ack_packet(
            LongHeaderType::Handshake,
            client_handshake_keys,
            &self.destination_cid,
            &self.source_cid,
            &mut self.handshake_ack_tracker,
            self.next_client_handshake_packet_number,
        )?;
        if packet.is_some() {
            self.next_client_handshake_packet_number += 1;
        }
        Ok(packet)
    }

    pub fn build_client_application_ack_packet(
        &mut self,
    ) -> Result<Option<ClientApplicationAckPacket>> {
        self.build_client_application_ack_packet_with_delay(Instant::now(), 0)
    }

    pub fn build_client_application_ack_packet_with_delay(
        &mut self,
        now: Instant,
        ack_delay_exponent: u64,
    ) -> Result<Option<ClientApplicationAckPacket>> {
        if self.application_ack_tracker.is_empty() {
            return Ok(None);
        }
        let Some(client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native application ACK encryption is waiting for TLS application keys".into(),
            ));
        };

        let packet_number = self.next_client_application_packet_number;
        let packet_number_len = 2;
        let frame = encode_frame(
            &self
                .application_ack_tracker
                .to_ack_frame_with_delay(now, ack_delay_exponent)?,
        );
        let packet = protect_short_header_packet(
            client_application_keys,
            &self.destination_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;
        self.application_ack_tracker.mark_ack_sent();
        self.next_client_application_packet_number += 1;

        Ok(Some(ClientApplicationAckPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + self.destination_cid.as_bytes().len(),
        }))
    }

    pub fn build_client_application_ack_packet_after(
        &mut self,
        threshold: usize,
    ) -> Result<Option<ClientApplicationAckPacket>> {
        if !self.application_ack_tracker.should_ack_after(threshold) {
            return Ok(None);
        }
        self.build_client_application_ack_packet()
    }

    pub fn build_client_application_ack_packet_after_or_delay(
        &mut self,
        threshold: usize,
        max_ack_delay: Duration,
        now: Instant,
        ack_delay_exponent: u64,
    ) -> Result<Option<ClientApplicationAckPacket>> {
        if !self
            .application_ack_tracker
            .should_ack_after_or_delay(threshold, max_ack_delay, now)
        {
            return Ok(None);
        }
        self.build_client_application_ack_packet_with_delay(now, ack_delay_exponent)
    }

    pub fn client_application_ack_deadline(&self, max_ack_delay: Duration) -> Option<Instant> {
        self.application_ack_tracker
            .pending_ack_deadline(max_ack_delay)
    }

    pub fn build_client_handshake_crypto_packet(
        &mut self,
        crypto_data: Bytes,
    ) -> Result<Option<ClientHandshakePacket>> {
        if crypto_data.is_empty() {
            return Ok(None);
        }

        let crypto_offset = self.client_handshake_crypto_offset;
        let packet =
            self.build_client_handshake_crypto_packet_at_offset(crypto_offset, crypto_data)?;
        self.client_handshake_crypto_offset += packet.crypto_data.len() as u64;

        Ok(Some(packet))
    }

    pub fn retransmit_pto_client_handshake_crypto_packets(
        &mut self,
        now: Instant,
        pto: Duration,
    ) -> Result<Vec<ClientHandshakePacket>> {
        let expired_packets = self
            .client_handshake_loss_detector
            .pto_expired_packets(now, pto);
        let mut retransmits = Vec::new();
        for packet_number in expired_packets {
            self.client_handshake_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.client_handshake_sent_crypto.remove(&packet_number) else {
                continue;
            };
            if sent.packet_type != LongHeaderType::Handshake {
                continue;
            }
            retransmits.push(
                self.build_client_handshake_crypto_packet_at_offset_with_sent_at(
                    sent.crypto_offset,
                    sent.crypto_data,
                    now,
                )?,
            );
        }
        Ok(retransmits)
    }

    fn build_client_handshake_crypto_packet_at_offset(
        &mut self,
        crypto_offset: u64,
        crypto_data: Bytes,
    ) -> Result<ClientHandshakePacket> {
        self.build_client_handshake_crypto_packet_at_offset_with_sent_at(
            crypto_offset,
            crypto_data,
            Instant::now(),
        )
    }

    fn build_client_handshake_crypto_packet_at_offset_with_sent_at(
        &mut self,
        crypto_offset: u64,
        crypto_data: Bytes,
        sent_at: Instant,
    ) -> Result<ClientHandshakePacket> {
        let Some(client_handshake_keys) = &self.client_handshake_keys else {
            return Err(Error::Quic(
                "native Handshake packet encryption is waiting for TLS Handshake keys".into(),
            ));
        };

        let packet_number = self.next_client_handshake_packet_number;
        let packet_number_len = 2;
        let frame = encode_frame(&QuicFrame::Crypto {
            offset: crypto_offset,
            data: crypto_data.clone(),
        });
        let header = encode_long_header(&LongHeaderPacket {
            packet_type: LongHeaderType::Handshake,
            version: 1,
            destination_cid: self.destination_cid.clone(),
            source_cid: self.source_cid.clone(),
            token: Bytes::new(),
            packet_number,
            packet_number_len,
            payload_len: frame.len() + 16,
        })?;
        let packet_number_offset = header
            .len()
            .checked_sub(packet_number_len)
            .ok_or_else(|| Error::HttpProtocol("invalid QUIC Handshake header length".into()))?;
        let packet = protect_long_header_packet(
            client_handshake_keys,
            packet_number,
            &header,
            packet_number_offset,
            packet_number_len,
            &frame,
        )?;

        self.next_client_handshake_packet_number += 1;
        self.client_handshake_loss_detector
            .on_packet_sent_at(packet_number, sent_at);
        self.client_handshake_sent_crypto.insert(
            packet_number,
            SentCryptoPacket {
                packet_type: LongHeaderType::Handshake,
                crypto_offset,
                crypto_data: crypto_data.clone(),
            },
        );

        Ok(ClientHandshakePacket {
            packet,
            packet_number,
            packet_number_offset,
            crypto_data,
        })
    }

    pub fn build_client_application_stream_packet(
        &mut self,
        stream_id: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<Option<ClientApplicationPacket>> {
        if data.is_empty() && !fin {
            return Ok(None);
        }
        let stream_offset = *self.client_stream_offsets.get(&stream_id).unwrap_or(&0);
        self.client_application_flow_control.consume_stream_data(
            stream_id,
            stream_offset,
            data.len(),
        )?;
        let packet = self.build_client_application_stream_packet_at_offset(
            stream_id,
            stream_offset,
            data,
            fin,
        )?;
        self.client_stream_offsets
            .insert(stream_id, stream_offset + packet.data.len() as u64);
        Ok(Some(packet))
    }

    fn build_client_application_stream_packet_at_offset(
        &mut self,
        stream_id: u64,
        stream_offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<ClientApplicationPacket> {
        let Some(client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        };

        let packet_number = self.next_client_application_packet_number;
        let packet_number_len = 2;
        let frame = encode_frame(&QuicFrame::Stream {
            stream_id,
            offset: (stream_offset > 0).then_some(stream_offset),
            fin,
            data: data.clone(),
        });
        let packet = protect_short_header_packet(
            client_application_keys,
            &self.destination_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;

        self.client_application_loss_detector
            .on_packet_sent(packet_number);
        self.client_application_sent_streams.insert(
            packet_number,
            SentApplicationStreamPacket {
                stream_id,
                stream_offset,
                fin,
                data: data.clone(),
            },
        );
        self.next_client_application_packet_number += 1;

        Ok(ClientApplicationPacket {
            packet,
            packet_number,
            stream_id,
            packet_number_offset: 1 + self.destination_cid.as_bytes().len(),
            data,
        })
    }

    pub fn build_client_h3_preface_packets(
        &mut self,
        fingerprint: &Http3Fingerprint,
    ) -> Result<Vec<ClientApplicationPacket>> {
        if self.client_application_keys.is_none() {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        }

        let mut packets = Vec::new();
        for stream in native::encode_client_preface_streams(fingerprint) {
            let stream_id = self.next_client_unidirectional_stream_id;
            self.next_client_unidirectional_stream_id += 4;
            let payload = native::encode_unidirectional_stream(&stream);
            if let Some(packet) =
                self.build_client_application_stream_packet(stream_id, payload, false)?
            {
                packets.push(packet);
            }
        }
        Ok(packets)
    }

    pub fn build_client_h3_request_packet(
        &mut self,
        method: &http::Method,
        uri: &http::Uri,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<ClientApplicationPacket> {
        if self.client_application_keys.is_none() {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        }

        let stream_id = self.next_client_bidirectional_stream_id;
        let h3_headers = native::build_request_headers(method, uri, headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, body, &self.fingerprint);

        let packet = self
            .build_client_application_stream_packet(stream_id, payload, true)?
            .ok_or_else(|| Error::HttpProtocol("native H3 request produced no payload".into()))?;
        self.next_client_bidirectional_stream_id += 4;
        Ok(packet)
    }

    pub fn build_client_h3_request_start_packet(
        &mut self,
        method: &http::Method,
        uri: &http::Uri,
        headers: &[(String, String)],
        body: Option<Bytes>,
        fin: bool,
    ) -> Result<ClientApplicationPacket> {
        if self.client_application_keys.is_none() {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        }

        let stream_id = self.next_client_bidirectional_stream_id;
        let h3_headers = native::build_request_headers(method, uri, headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, body, &self.fingerprint);

        let packet = self
            .build_client_application_stream_packet(stream_id, payload, fin)?
            .ok_or_else(|| {
                Error::HttpProtocol("native H3 request start produced no payload".into())
            })?;
        self.next_client_bidirectional_stream_id += 4;
        Ok(packet)
    }

    pub fn build_client_h3_websocket_connect_packet(
        &mut self,
        uri: &http::Uri,
        headers: &[(String, String)],
    ) -> Result<ClientApplicationPacket> {
        if self.client_application_keys.is_none() {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        }

        let stream_id = self.next_client_bidirectional_stream_id;
        let h3_headers = native::build_websocket_connect_headers(uri, headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, None, &self.fingerprint);

        let packet = self
            .build_client_application_stream_packet(stream_id, payload, false)?
            .ok_or_else(|| Error::HttpProtocol("native H3 CONNECT produced no payload".into()))?;
        self.next_client_bidirectional_stream_id += 4;
        Ok(packet)
    }

    pub fn build_client_h3_data_packet(
        &mut self,
        stream_id: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<Option<ClientApplicationPacket>> {
        let payload = if data.is_empty() {
            Bytes::new()
        } else {
            native::encode_frame(&native::H3Frame::Data(data))
        };
        self.build_client_application_stream_packet(stream_id, payload, fin)
    }

    pub fn build_client_reset_stream_packet(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<ClientApplicationControlPacket> {
        let final_size = *self.client_stream_offsets.get(&stream_id).unwrap_or(&0);
        self.build_client_application_control_packet(QuicFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        })
    }

    pub fn build_client_stop_sending_packet(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::StopSending {
            stream_id,
            error_code,
        })
    }

    pub fn build_client_path_response_packet(
        &mut self,
        data: [u8; 8],
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::PathResponse(data))
    }

    pub fn build_client_path_challenge_packet(
        &mut self,
        data: [u8; 8],
    ) -> Result<ClientApplicationControlPacket> {
        let frame = self.client_path_validator.path_challenge(data);
        self.build_client_application_control_packet(frame)
    }

    pub fn build_client_connection_close_packet(
        &mut self,
        error_code: u64,
        reason: Bytes,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::ConnectionClose {
            error_code,
            frame_type: None,
            reason,
        })
    }

    pub fn build_client_max_data_packet(
        &mut self,
        max_data: u64,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::MaxData(max_data))
    }

    pub fn build_client_max_stream_data_packet(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::MaxStreamData {
            stream_id,
            max_stream_data,
        })
    }

    pub fn build_client_max_streams_packet(
        &mut self,
        bidirectional: bool,
        max_streams: u64,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_control_packet(QuicFrame::MaxStreams {
            bidirectional,
            max_streams,
        })
    }

    pub fn build_client_flow_control_blocked_packet(
        &mut self,
    ) -> Result<Option<ClientApplicationControlPacket>> {
        self.client_application_flow_control
            .take_blocked_frame()
            .map(|frame| self.build_client_application_control_packet(frame))
            .transpose()
    }

    pub fn build_client_receive_flow_control_update_packets(
        &mut self,
    ) -> Result<Vec<ClientApplicationControlPacket>> {
        self.client_application_receive_flow_control
            .take_update_frames()
            .into_iter()
            .map(|frame| self.build_client_application_control_packet(frame))
            .collect()
    }

    fn build_client_application_control_packet(
        &mut self,
        frame: QuicFrame,
    ) -> Result<ClientApplicationControlPacket> {
        let Some(client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        };

        let packet_number = self.next_client_application_packet_number;
        let packet_number_len = 2;
        let frame = padded_short_header_payload(encode_frame(&frame));
        let packet = protect_short_header_packet(
            client_application_keys,
            &self.destination_cid,
            packet_number,
            packet_number_len,
            false,
            &frame,
        )?;
        self.client_application_loss_detector
            .on_packet_sent(packet_number);
        self.next_client_application_packet_number += 1;

        Ok(ClientApplicationControlPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + self.destination_cid.as_bytes().len(),
        })
    }

    pub fn open_server_application_packet(&mut self, packet: &[u8]) -> Result<Vec<QuicFrame>> {
        if self.close_draining {
            return Ok(Vec::new());
        }
        let Some(server_application_keys) = &self.server_application_keys else {
            return Err(Error::Quic(
                "native application packet decryption is waiting for TLS application keys".into(),
            ));
        };
        let opened = open_short_header_packet(
            server_application_keys,
            packet,
            self.source_cid.as_bytes().len(),
            self.next_server_application_packet_number,
        )?;
        self.next_server_application_packet_number = opened.packet_number + 1;
        let frames = decode_frames(&opened.payload)?;
        for frame in &frames {
            if let QuicFrame::Stream {
                stream_id,
                offset,
                data,
                ..
            } = frame
            {
                self.client_application_receive_flow_control
                    .observe_stream_frame(*stream_id, *offset, data.len())?;
            }
            for packet_number in self.client_application_loss_detector.on_ack_frame(frame)? {
                self.client_application_sent_streams.remove(&packet_number);
            }
            match frame {
                QuicFrame::MaxData(max_data) => {
                    self.client_application_flow_control
                        .apply_max_data(*max_data);
                }
                QuicFrame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                } => self
                    .client_application_flow_control
                    .apply_max_stream_data(*stream_id, *max_stream_data),
                QuicFrame::MaxStreams {
                    bidirectional,
                    max_streams,
                } => self
                    .client_application_flow_control
                    .apply_max_streams(*bidirectional, *max_streams),
                QuicFrame::PathResponse(data) => {
                    self.client_path_validator.on_path_response(*data);
                }
                _ => {}
            }
        }
        if frames.iter().any(is_ack_eliciting_quic_frame) {
            self.application_ack_tracker.observe(opened.packet_number);
        }
        Ok(frames.into_iter().filter(is_not_padding_frame).collect())
    }

    pub fn open_server_h3_stream_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<ServerH3StreamEvent>> {
        Ok(self
            .open_server_h3_event_packet(packet)?
            .into_iter()
            .filter_map(|event| match event {
                ServerH3Event::Stream(event) => Some(event),
                ServerH3Event::ResetStream { .. }
                | ServerH3Event::StopSending { .. }
                | ServerH3Event::ConnectionClose { .. }
                | ServerH3Event::PathChallenge(_) => None,
            })
            .collect())
    }

    pub fn open_server_h3_event_packet(&mut self, packet: &[u8]) -> Result<Vec<ServerH3Event>> {
        if self.close_draining {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for frame in self.open_server_application_packet(packet)? {
            match frame {
                QuicFrame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                    ..
                } => {
                    if let Some(event) =
                        self.apply_server_quic_stream_frame(stream_id, offset, fin, data)?
                    {
                        events.push(ServerH3Event::Stream(event));
                    }
                }
                QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } => events.push(ServerH3Event::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                }),
                QuicFrame::StopSending {
                    stream_id,
                    error_code,
                } => events.push(ServerH3Event::StopSending {
                    stream_id,
                    error_code,
                }),
                QuicFrame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    self.close_draining = true;
                    events.push(ServerH3Event::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                }
                QuicFrame::PathChallenge(data) => events.push(ServerH3Event::PathChallenge(data)),
                QuicFrame::Padding
                | QuicFrame::Ping
                | QuicFrame::Ack { .. }
                | QuicFrame::AckEcn { .. }
                | QuicFrame::Crypto { .. }
                | QuicFrame::MaxData(_)
                | QuicFrame::MaxStreamData { .. }
                | QuicFrame::MaxStreams { .. }
                | QuicFrame::DataBlocked { .. }
                | QuicFrame::StreamDataBlocked { .. }
                | QuicFrame::StreamsBlocked { .. }
                | QuicFrame::NewConnectionId { .. }
                | QuicFrame::RetireConnectionId { .. }
                | QuicFrame::PathResponse(_)
                | QuicFrame::HandshakeDone => {}
            }
        }
        Ok(events)
    }

    fn apply_server_quic_stream_frame(
        &mut self,
        stream_id: u64,
        offset: Option<u64>,
        fin: bool,
        data: Bytes,
    ) -> Result<Option<ServerH3StreamEvent>> {
        apply_h3_stream_frame(
            &mut self.server_h3_stream_buffers,
            &mut self.server_h3_stream_buffer_offsets,
            &mut self.server_h3_stream_types,
            stream_id,
            offset,
            fin,
            data,
        )
    }

    pub fn process_server_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<ProcessedServerInitial>> {
        if is_version_negotiation_datagram(datagram) {
            return self.process_version_negotiation_datagram(datagram);
        }

        let mut processed = Vec::new();
        for packet in split_long_header_datagram(datagram)? {
            match packet.packet_type {
                LongHeaderType::Initial => {
                    let opened = open_long_header_packet(
                        &self.server_initial_keys,
                        &packet.packet,
                        packet.packet_number_offset,
                        self.next_server_initial_packet_number,
                    )?;
                    self.destination_cid = packet.source_cid.clone();
                    self.initial_ack_tracker.observe(opened.packet_number);
                    self.next_server_initial_packet_number = opened.packet_number + 1;

                    for frame in decode_frames(&opened.payload)? {
                        if let QuicFrame::Crypto { offset, data } = frame {
                            self.initial_crypto.insert(offset, data)?;
                        }
                    }

                    let crypto_data = self.initial_crypto.take_contiguous();
                    if crypto_data.is_empty() {
                        continue;
                    }

                    self.tls
                        .provide_crypto(QuicEncryptionLevel::Initial, &crypto_data)?;
                    let secrets = self.tls.secrets();
                    self.install_tls_secrets(&secrets)?;
                    self.validate_server_transport_parameters_if_available()?;
                    processed.push(ProcessedServerInitial {
                        packet_number: opened.packet_number,
                        crypto_data,
                        initial_crypto_out: self.tls.take_crypto(QuicEncryptionLevel::Initial),
                        handshake_crypto_out: self.tls.take_crypto(QuicEncryptionLevel::Handshake),
                        secrets,
                    });
                }
                LongHeaderType::Handshake => {
                    let Some(server_handshake_keys) = &self.server_handshake_keys else {
                        return Err(Error::Quic(
                            "native Handshake packet decryption is waiting for TLS Handshake keys"
                                .into(),
                        ));
                    };
                    let opened = open_long_header_packet(
                        server_handshake_keys,
                        &packet.packet,
                        packet.packet_number_offset,
                        self.next_server_handshake_packet_number,
                    )?;
                    self.handshake_ack_tracker.observe(opened.packet_number);
                    self.next_server_handshake_packet_number = opened.packet_number + 1;

                    for frame in decode_frames(&opened.payload)? {
                        for packet_number in
                            self.client_handshake_loss_detector.on_ack_frame(&frame)?
                        {
                            self.client_handshake_sent_crypto.remove(&packet_number);
                        }
                        if let QuicFrame::Crypto { offset, data } = frame {
                            self.handshake_crypto.insert(offset, data)?;
                        }
                    }

                    let crypto_data = self.handshake_crypto.take_contiguous();
                    if !crypto_data.is_empty() {
                        self.tls
                            .provide_crypto(QuicEncryptionLevel::Handshake, &crypto_data)?;
                        let secrets = self.tls.secrets();
                        self.install_tls_secrets(&secrets)?;
                        self.validate_server_transport_parameters_if_available()?;
                        let handshake_crypto_out =
                            self.tls.take_crypto(QuicEncryptionLevel::Handshake);
                        if !handshake_crypto_out.is_empty() {
                            processed.push(ProcessedServerInitial {
                                packet_number: opened.packet_number,
                                crypto_data,
                                initial_crypto_out: Bytes::new(),
                                handshake_crypto_out,
                                secrets,
                            });
                        }
                    }
                }
                LongHeaderType::Retry => {
                    self.process_retry_packet(packet.packet.as_ref())?;
                }
                LongHeaderType::ZeroRtt => {}
            }
        }

        Ok(processed)
    }

    fn process_version_negotiation_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<Vec<ProcessedServerInitial>> {
        let packet = decode_version_negotiation_packet(datagram)?;
        if packet.destination_cid != self.source_cid || packet.source_cid != self.destination_cid {
            return Ok(Vec::new());
        }
        if packet.supported_versions.contains(&QUIC_VERSION_1) {
            return Ok(Vec::new());
        }
        Err(Error::Quic(
            "native H3 server did not offer QUIC version 1".into(),
        ))
    }

    fn process_retry_packet(&mut self, retry_packet: &[u8]) -> Result<()> {
        if self.retry_source_cid.is_some() {
            return Err(Error::Quic(
                "native H3 received more than one QUIC Retry packet".into(),
            ));
        }

        let retry = validate_retry_integrity_tag_v1(&self.original_destination_cid, retry_packet)?;
        if retry.destination_cid != self.source_cid {
            return Err(Error::Quic(
                "native H3 Retry destination CID does not match client source CID".into(),
            ));
        }

        let retry_keys = derive_initial_key_material(retry.source_cid.as_bytes())?;
        let packet_number = self.next_client_initial_packet_number;
        let retry_initial = build_client_initial_packet_with_token(
            &self.fingerprint,
            self.client_initial.crypto_data.clone(),
            self.client_initial.transport_parameters.clone(),
            self.client_initial.secrets.clone(),
            retry.source_cid.clone(),
            self.source_cid.clone(),
            retry.token,
            packet_number,
        )?;

        self.destination_cid = retry.source_cid.clone();
        self.retry_source_cid = Some(retry.source_cid);
        self.client_initial_keys = retry_keys.client;
        self.server_initial_keys = retry_keys.server;
        self.client_initial = retry_initial.clone();
        self.pending_client_initial = Some(retry_initial);
        self.next_client_initial_packet_number = packet_number + 1;
        Ok(())
    }

    fn validate_server_transport_parameters_if_available(&mut self) -> Result<()> {
        if self.server_transport_parameters_validated {
            return Ok(());
        }
        let peer_transport_parameters = self.tls.peer_transport_parameters();
        if peer_transport_parameters.is_empty() {
            return Ok(());
        }
        self.validate_server_transport_parameters(peer_transport_parameters.as_ref())?;
        self.server_transport_parameters_validated = true;
        Ok(())
    }

    fn validate_server_transport_parameters(&self, encoded: &[u8]) -> Result<()> {
        let mut original_destination_cid = None;
        let mut initial_source_cid = None;
        let mut retry_source_cid = None;

        for parameter in decode_transport_parameters(encoded)? {
            match parameter {
                TransportParameter::OriginalDestinationConnectionId(value) => {
                    original_destination_cid = Some(value);
                }
                TransportParameter::InitialSourceConnectionId(value) => {
                    initial_source_cid = Some(value);
                }
                TransportParameter::RetrySourceConnectionId(value) => {
                    retry_source_cid = Some(value);
                }
                _ => {}
            }
        }

        let original_destination_cid = original_destination_cid.ok_or_else(|| {
            Error::Quic("native H3 server omitted original_destination_connection_id".into())
        })?;
        if original_destination_cid.as_ref() != self.original_destination_cid.as_bytes() {
            return Err(Error::Quic(
                "native H3 server original_destination_connection_id mismatch".into(),
            ));
        }

        let initial_source_cid = initial_source_cid.ok_or_else(|| {
            Error::Quic("native H3 server omitted initial_source_connection_id".into())
        })?;
        if initial_source_cid.as_ref() != self.destination_cid.as_bytes() {
            return Err(Error::Quic(
                "native H3 server initial_source_connection_id mismatch".into(),
            ));
        }

        match (&self.retry_source_cid, retry_source_cid) {
            (Some(expected), Some(actual)) if actual.as_ref() == expected.as_bytes() => Ok(()),
            (Some(_), Some(_)) => Err(Error::Quic(
                "native H3 server retry_source_connection_id mismatch".into(),
            )),
            (Some(_), None) => Err(Error::Quic(
                "native H3 server omitted retry_source_connection_id".into(),
            )),
            (None, Some(_)) => Err(Error::Quic(
                "native H3 server sent unexpected retry_source_connection_id".into(),
            )),
            (None, None) => Ok(()),
        }
    }
}

fn is_version_negotiation_datagram(datagram: &[u8]) -> bool {
    datagram.len() >= 5
        && datagram[0] & 0x80 != 0
        && u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]) == 0
}

fn build_client_initial_packet_with_token(
    fingerprint: &Http3Fingerprint,
    crypto_data: Bytes,
    transport_parameters: Bytes,
    secrets: Vec<QuicTlsSecret>,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
    token: Bytes,
    packet_number: u64,
) -> Result<ClientInitialPacket> {
    let header_len_without_length = 1
        + 4
        + 1
        + destination_cid.as_bytes().len()
        + 1
        + source_cid.as_bytes().len()
        + varint_len(token.len() as u64)
        + token.len();
    let padded_plaintext_len = initial_plaintext_len(
        header_len_without_length,
        crypto_data.len(),
        fingerprint.transport.initial_datagram_size,
    );
    let payload_len = padded_plaintext_len + AES_GCM_TAG_LEN;
    let header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: QUIC_VERSION_1,
        destination_cid: destination_cid.clone(),
        source_cid,
        token,
        packet_number,
        packet_number_len: INITIAL_PACKET_NUMBER_LEN,
        payload_len,
    })?;
    let packet_number_offset = header
        .len()
        .checked_sub(INITIAL_PACKET_NUMBER_LEN)
        .ok_or_else(|| Error::HttpProtocol("invalid QUIC Initial header length".into()))?;
    let keys = derive_initial_key_material(destination_cid.as_bytes())?;
    let packet = build_initial_crypto_packet(
        &keys.client,
        packet_number,
        &header,
        packet_number_offset,
        INITIAL_PACKET_NUMBER_LEN,
        &crypto_data,
        padded_plaintext_len,
    )?;

    Ok(ClientInitialPacket {
        packet,
        header,
        packet_number_offset,
        crypto_data,
        transport_parameters,
        secrets,
    })
}

fn initial_plaintext_len(
    header_len_without_length: usize,
    crypto_data_len: usize,
    initial_datagram_size: usize,
) -> usize {
    let target_datagram_len = initial_datagram_size.max(1200);
    let crypto_frame_len = 1 + 1 + varint_len(crypto_data_len as u64) + crypto_data_len;
    let mut padded_len = crypto_frame_len;
    loop {
        let payload_len = padded_len + AES_GCM_TAG_LEN;
        let header_len = header_len_without_length
            + varint_len((payload_len + INITIAL_PACKET_NUMBER_LEN) as u64)
            + INITIAL_PACKET_NUMBER_LEN;
        if header_len + payload_len >= target_datagram_len {
            return padded_len;
        }
        padded_len = target_datagram_len - header_len - AES_GCM_TAG_LEN;
    }
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

fn build_server_crypto_packet(
    packet_type: LongHeaderType,
    keys: &QuicPacketKeyMaterial,
    destination_cid: &ConnectionId,
    source_cid: &ConnectionId,
    packet_number: u64,
    crypto_offset: u64,
    crypto_data: Bytes,
) -> Result<ServerHandshakePacket> {
    let packet_number_len = 2;
    let frame = encode_frame(&QuicFrame::Crypto {
        offset: crypto_offset,
        data: crypto_data.clone(),
    });
    let header = encode_long_header(&LongHeaderPacket {
        packet_type,
        version: 1,
        destination_cid: destination_cid.clone(),
        source_cid: source_cid.clone(),
        token: Bytes::new(),
        packet_number,
        packet_number_len,
        payload_len: frame.len() + 16,
    })?;
    let packet_number_offset = header
        .len()
        .checked_sub(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("invalid QUIC server long-header length".into()))?;
    let packet = protect_long_header_packet(
        keys,
        packet_number,
        &header,
        packet_number_offset,
        packet_number_len,
        &frame,
    )?;

    Ok(ServerHandshakePacket {
        packet,
        packet_type,
        packet_number,
        packet_number_offset,
        crypto_data,
    })
}

fn apply_h3_stream_frame(
    buffers: &mut BTreeMap<u64, BytesMut>,
    buffer_offsets: &mut BTreeMap<u64, u64>,
    stream_types: &mut BTreeMap<u64, native::H3StreamType>,
    stream_id: u64,
    offset: Option<u64>,
    fin: bool,
    data: Bytes,
) -> Result<Option<ServerH3StreamEvent>> {
    let (stream_type, frames) = if data.is_empty() {
        (stream_types.get(&stream_id).copied(), Vec::new())
    } else if is_unidirectional_stream(stream_id) {
        let stream_type = if let Some(stream_type) = stream_types.get(&stream_id).copied() {
            let buffer = buffers.entry(stream_id).or_default();
            buffer.extend_from_slice(&data);
            stream_type
        } else {
            let buffer = buffers.entry(stream_id).or_default();
            buffer.extend_from_slice(&data);
            let stream = match native::decode_unidirectional_stream(buffer.as_ref()) {
                Ok(stream) => stream,
                Err(error) if !fin && is_incomplete_h3_data_error(&error) => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            stream_types.insert(stream_id, stream.stream_type);
            *buffer = BytesMut::from(stream.payload.as_ref());
            stream.stream_type
        };
        let buffer = buffers.entry(stream_id).or_default();
        let frames = if buffer.is_empty() {
            Vec::new()
        } else if !matches!(stream_type, native::H3StreamType::Control) {
            buffer.clear();
            Vec::new()
        } else {
            match native::decode_frames(buffer.as_ref()) {
                Ok(frames) => {
                    buffer.clear();
                    frames
                }
                Err(error) if !fin && is_incomplete_h3_data_error(&error) => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        };
        (Some(stream_type), frames)
    } else {
        let stream_offset = offset.unwrap_or(0);
        let buffer_base = *buffer_offsets.entry(stream_id).or_insert(0);
        let buffer = buffers.entry(stream_id).or_default();
        let buffered_end = buffer_base
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| Error::HttpProtocol("native H3 stream range overflow".into()))?;
        let data_end = stream_offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::HttpProtocol("native H3 stream range overflow".into()))?;
        if data_end <= buffer_base || stream_offset > buffered_end {
            return Ok(None);
        }
        let already_buffered = usize::try_from(buffered_end - stream_offset)
            .map_err(|_| Error::HttpProtocol("native H3 stream overlap exceeds usize".into()))?;
        if already_buffered < data.len() {
            buffer.extend_from_slice(&data[already_buffered..]);
        }
        match native::decode_frames(buffer.as_ref()) {
            Ok(frames) => {
                let consumed = buffer.len() as u64;
                buffer.clear();
                buffer_offsets.insert(
                    stream_id,
                    buffer_base.checked_add(consumed).ok_or_else(|| {
                        Error::HttpProtocol("native H3 stream range overflow".into())
                    })?,
                );
                (None, frames)
            }
            Err(error) if !fin && is_incomplete_h3_data_error(&error) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    };

    Ok(Some(ServerH3StreamEvent {
        stream_id,
        stream_type,
        fin,
        frames,
    }))
}

fn is_unidirectional_stream(stream_id: u64) -> bool {
    stream_id & 0x02 != 0
}

fn is_bidirectional_stream(stream_id: u64) -> bool {
    !is_unidirectional_stream(stream_id)
}

fn stream_initiator(stream_id: u64) -> u64 {
    stream_id & 0x01
}

fn is_ack_eliciting_quic_frame(frame: &QuicFrame) -> bool {
    !matches!(
        frame,
        QuicFrame::Padding | QuicFrame::Ack { .. } | QuicFrame::AckEcn { .. }
    )
}

fn is_not_padding_frame(frame: &QuicFrame) -> bool {
    !matches!(frame, QuicFrame::Padding)
}

fn padded_short_header_payload(payload: Bytes) -> Bytes {
    const MIN_SHORT_HEADER_PAYLOAD_LEN: usize = 24;
    if payload.len() >= MIN_SHORT_HEADER_PAYLOAD_LEN {
        return payload;
    }
    let mut padded = payload.to_vec();
    padded.resize(MIN_SHORT_HEADER_PAYLOAD_LEN, 0);
    Bytes::from(padded)
}

fn is_incomplete_h3_data_error(error: &Error) -> bool {
    let message = error.to_string();
    message.contains("truncated HTTP/3 frame")
        || message.contains("missing HTTP/3 varint")
        || message.contains("truncated HTTP/3 varint")
}

fn build_ack_packet(
    packet_type: LongHeaderType,
    keys: &QuicPacketKeyMaterial,
    destination_cid: &ConnectionId,
    source_cid: &ConnectionId,
    tracker: &mut QuicAckTracker,
    packet_number: u64,
) -> Result<Option<ClientAckPacket>> {
    if tracker.is_empty() {
        return Ok(None);
    }

    let packet_number_len = 2;
    let frame = encode_frame(&tracker.to_ack_frame(0)?);
    let header = encode_long_header(&LongHeaderPacket {
        packet_type,
        version: 1,
        destination_cid: destination_cid.clone(),
        source_cid: source_cid.clone(),
        token: Bytes::new(),
        packet_number,
        packet_number_len,
        payload_len: frame.len() + 16,
    })?;
    let packet_number_offset = header
        .len()
        .checked_sub(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("invalid QUIC ACK header length".into()))?;
    let packet = protect_long_header_packet(
        keys,
        packet_number,
        &header,
        packet_number_offset,
        packet_number_len,
        &frame,
    )?;
    tracker.mark_ack_sent();

    Ok(Some(ClientAckPacket {
        packet,
        packet_type,
        packet_number,
        packet_number_offset,
    }))
}
