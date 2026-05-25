//! Native QUIC handshake state for HTTP/3.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::fingerprint::{Http3Fingerprint, QuicTransportParams, TlsFingerprint};
use crate::transport::h3::native;
use crate::transport::h3::path::{match_local_connection_id, QuicConnectionIdInventory};
use crate::transport::h3::quic::{
    build_initial_crypto_packet, decode_frames, decode_long_header, decode_transport_parameters,
    decode_version_negotiation_packet, derive_initial_key_material,
    derive_next_packet_key_material, encode_frame, encode_long_header, open_long_header_packet,
    open_short_header_packet, protect_long_header_packet, protect_short_header_packet,
    split_long_header_datagram, validate_retry_integrity_tag_v1, ConnectionId, LongHeaderPacket,
    LongHeaderType, OpenedShortHeaderPacket, QuicAckTracker, QuicCloseState, QuicCryptoAssembler,
    QuicEcnMark, QuicFrame, QuicLossDetector, QuicPacketKeyMaterial, QuicPathValidator,
    QuicPmtuProbePolicy, TransportParameter,
};
use crate::transport::h3::recovery::{
    LossDetectionOutcome, PacketNumberSpace, RecoveryState, SentPacketInfo,
};
use crate::transport::h3::tls::{
    build_client_initial_packet_from_capture_with_size,
    build_client_initial_packet_from_capture_with_version_and_size, ClientInitialPacket,
    NativeH3HandshakeStatus, NativeH3SessionTicket, NativeQuicTlsSession, QuicEncryptionLevel,
    QuicSecretDirection, QuicTlsSecret,
};

use getrandom::fill as getrandom_fill;

const QUIC_VERSION_1: u32 = 1;
const INITIAL_PACKET_NUMBER_LEN: usize = 4;
const AES_GCM_TAG_LEN: usize = 16;
const MIN_PATH_VALIDATION_DATAGRAM: usize = 1200;
const QUIC_CONNECTION_MIGRATION_ERROR: u64 = 0x0a;

fn new_server_cid_inventory(
    fingerprint: &Http3Fingerprint,
    server_source_cid: &ConnectionId,
    client_source_cid: &ConnectionId,
) -> QuicConnectionIdInventory {
    let mut inventory =
        QuicConnectionIdInventory::new(fingerprint.transport.active_connection_id_limit);
    inventory.install_initial_local(server_source_cid.clone(), [0u8; 16]);
    inventory.install_initial_peer(
        Bytes::copy_from_slice(client_source_cid.as_bytes()),
        [0u8; 16],
    );
    inventory
}

fn new_client_cid_inventory(
    fingerprint: &Http3Fingerprint,
    source_cid: &ConnectionId,
) -> QuicConnectionIdInventory {
    let mut inventory =
        QuicConnectionIdInventory::new(fingerprint.transport.active_connection_id_limit);
    inventory.install_initial_local(source_cid.clone(), [0u8; 16]);
    inventory
}

fn pad_short_header_payload_to_min_datagram(
    payload: Bytes,
    short_header_len: usize,
    min_datagram: usize,
) -> Bytes {
    let mut out = payload.to_vec();
    while short_header_len + out.len() + AES_GCM_TAG_LEN < min_datagram {
        out.push(0);
    }
    Bytes::from(out)
}

fn recovery_state_from_transport(params: &QuicTransportParams) -> RecoveryState {
    let max_ack_delay = Duration::from_millis(params.max_ack_delay_ms);
    let datagram = params.max_recv_udp_payload_size.max(1200) as u64;
    RecoveryState::new(max_ack_delay, datagram)
}

fn observe_packet_with_ecn(
    tracker: &mut QuicAckTracker,
    packet_number: u64,
    ecn_mark: Option<QuicEcnMark>,
    now: Instant,
) {
    if let Some(mark) = ecn_mark {
        tracker.observe_ecn_at(packet_number, mark, now);
    } else {
        tracker.observe_at(packet_number, now);
    }
}

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

/// Retained previous-phase packet protection keys for the RFC9001 § 6.2
/// previous-key window. Reordered packets at the old phase are decrypted via
/// these keys until `retire_at` elapses, then they are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviousKeys {
    keys: QuicPacketKeyMaterial,
    phase: bool,
    retire_at: Instant,
}

/// Bound on how long the previous-phase keys remain valid after a successful
/// key update. RFC9001 § 6.5 recommends retaining old keys for "three times
/// the PTO" worth of time, which is connection-specific; we use a conservative
/// fixed window that covers typical loss/reorder horizons.
const PREVIOUS_KEY_WINDOW: Duration = Duration::from_secs(3);

/// Tracks RFC9001 § 6.5 "key update in progress" enforcement: once the local
/// endpoint initiates a key update it MUST NOT initiate another until an ACK
/// confirms a packet sent at the new key phase has been received.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OneRttKeyUpdate {
    write_update_in_progress: bool,
    write_update_anchor: Option<u64>,
}

impl OneRttKeyUpdate {
    fn note_packet_acked(&mut self, packet_number: u64) {
        if let Some(anchor) = self.write_update_anchor {
            if packet_number >= anchor {
                self.write_update_in_progress = false;
                self.write_update_anchor = None;
            }
        }
    }
}

/// Result of opening a 1-RTT short-header packet, describing which set of
/// per-phase keys decrypted the AEAD so the caller can commit the receive
/// rotation when applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneRttOpenOutcome {
    Current,
    Previous,
    Next,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OneRttOpenedPacket {
    opened: OpenedShortHeaderPacket,
    outcome: OneRttOpenOutcome,
}

fn try_open_one_rtt_packet(
    current: &QuicPacketKeyMaterial,
    next: Option<&QuicPacketKeyMaterial>,
    previous: Option<&PreviousKeys>,
    expected_read_phase: bool,
    now: Instant,
    packet: &[u8],
    destination_cid_len: usize,
    expected_packet_number: u64,
) -> Result<OneRttOpenedPacket> {
    if let Ok(opened) =
        open_short_header_packet(current, packet, destination_cid_len, expected_packet_number)
    {
        if opened.key_phase == expected_read_phase {
            return Ok(OneRttOpenedPacket {
                opened,
                outcome: OneRttOpenOutcome::Current,
            });
        }
    }

    if let Some(previous) = previous {
        if previous.retire_at > now {
            if let Ok(opened) = open_short_header_packet(
                &previous.keys,
                packet,
                destination_cid_len,
                expected_packet_number,
            ) {
                if opened.key_phase == previous.phase {
                    return Ok(OneRttOpenedPacket {
                        opened,
                        outcome: OneRttOpenOutcome::Previous,
                    });
                }
            }
        }
    }

    if let Some(next) = next {
        let expected_next_phase = !expected_read_phase;
        if let Ok(opened) =
            open_short_header_packet(next, packet, destination_cid_len, expected_packet_number)
        {
            if opened.key_phase == expected_next_phase {
                return Ok(OneRttOpenedPacket {
                    opened,
                    outcome: OneRttOpenOutcome::Next,
                });
            }
        }
    }

    Err(Error::Quic(
        "native QUIC 1-RTT short-header packet could not be decrypted with current, previous, or next phase keys".into(),
    ))
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

// QUIC receive flow control.
//
// RFC 9000 Section 4 specifies that MAX_DATA and MAX_STREAM_DATA frames
// (encodings in Sections 19.9 and 19.10) carry the *absolute* maximum the
// receiver is willing to accept on the connection or stream, not a delta.
// Per RFC 9000 Section 4.1, "a receiver MUST close the connection with an
// error of type FLOW_CONTROL_ERROR if the sender violates the advertised
// connection or stream data limits", and Section 4.2 ties window growth to
// the receiver's application drain rate so that buffers stay bounded.
//
// We therefore derive every advertised absolute value from
// `initial_max_*data + bytes_consumed_by_application`, and only *gate* the
// emission of those frames so we are not putting one frame per byte on the
// wire. The on-wire receive path (`observe_stream_frame`) is kept purely as
// an enforcement check against the limit we have already advertised.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicReceiveFlowControl {
    local_initiator: u64,
    initial_max_data: u64,
    max_data: u64,
    max_connection_window: u64,
    received_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    max_stream_window: u64,
    stream_received: BTreeMap<u64, u64>,
    stream_data_overrides: BTreeMap<u64, u64>,
    connection_consumed: u64,
    stream_consumed: BTreeMap<u64, u64>,
    last_announced_max_data: u64,
    last_announced_max_stream_data: BTreeMap<u64, u64>,
    pending_max_data: Option<u64>,
    pending_max_stream_data: BTreeMap<u64, u64>,
    connection_update_threshold: u64,
}

impl QuicReceiveFlowControl {
    fn client(local_transport: &QuicTransportParams) -> Self {
        Self::new(0, local_transport)
    }

    fn server(local_transport: &QuicTransportParams) -> Self {
        Self::new(1, local_transport)
    }

    fn new(local_initiator: u64, local_transport: &QuicTransportParams) -> Self {
        let initial_max_data = local_transport.initial_max_data;
        let max_connection_window = local_transport.max_connection_window.max(initial_max_data);
        // Emit MAX_DATA when the absolute value we would announce has grown
        // by at least half of the originally negotiated initial window since
        // the last announcement. This keeps the same "half-window" cadence
        // that the previous receive-threshold logic used, but applied to the
        // app-consumed counter that RFC 9000 Section 4 requires.
        let connection_update_threshold = (initial_max_data / 2).max(1);
        Self {
            local_initiator,
            initial_max_data,
            max_data: initial_max_data,
            max_connection_window,
            received_data: 0,
            initial_max_stream_data_bidi_local: local_transport.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: local_transport
                .initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: local_transport.initial_max_stream_data_uni,
            max_stream_window: local_transport.max_stream_window,
            stream_received: BTreeMap::new(),
            stream_data_overrides: BTreeMap::new(),
            connection_consumed: 0,
            stream_consumed: BTreeMap::new(),
            last_announced_max_data: initial_max_data,
            last_announced_max_stream_data: BTreeMap::new(),
            pending_max_data: None,
            pending_max_stream_data: BTreeMap::new(),
            connection_update_threshold,
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
        Ok(())
    }

    // Record the bytes the application has drained off a stream's public body
    // (or RFC 9220 tunnel inbound channel). Per RFC 9000 Section 4.1/4.2 the
    // absolute MAX_DATA / MAX_STREAM_DATA values are
    //   initial_max_data + sum(bytes_consumed_by_application across streams)
    //   initial_max_stream_data[kind] + bytes_consumed_for_this_stream
    // and we only enqueue a frame when the value crosses the gating
    // threshold relative to the last announced value.
    fn record_stream_consumed(&mut self, stream_id: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let initial_stream_limit = self.initial_stream_data_limit(stream_id)?;
        let stream_window = self.max_stream_window.max(initial_stream_limit);
        let stream_threshold = (initial_stream_limit / 2).max(1);

        let stream_total = self
            .stream_consumed
            .get(&stream_id)
            .copied()
            .unwrap_or(0)
            .checked_add(len)
            .ok_or_else(|| {
                Error::HttpProtocol("QUIC receive flow control consumed overflow".into())
            })?;
        self.stream_consumed.insert(stream_id, stream_total);

        self.connection_consumed = self.connection_consumed.checked_add(len).ok_or_else(|| {
            Error::HttpProtocol("QUIC receive flow control connection consumed overflow".into())
        })?;

        let stream_announced = *self
            .last_announced_max_stream_data
            .get(&stream_id)
            .unwrap_or(&initial_stream_limit);
        let stream_absolute = initial_stream_limit
            .saturating_add(stream_total)
            .min(stream_window);
        if stream_absolute > stream_announced
            && stream_absolute - stream_announced >= stream_threshold
        {
            self.pending_max_stream_data
                .insert(stream_id, stream_absolute);
            self.stream_data_overrides
                .insert(stream_id, stream_absolute);
            self.last_announced_max_stream_data
                .insert(stream_id, stream_absolute);
        }

        let connection_absolute = self
            .initial_max_data
            .saturating_add(self.connection_consumed)
            .min(self.max_connection_window);
        if connection_absolute > self.last_announced_max_data
            && connection_absolute - self.last_announced_max_data
                >= self.connection_update_threshold
        {
            self.pending_max_data = Some(connection_absolute);
            self.max_data = connection_absolute;
            self.last_announced_max_data = connection_absolute;
        }
        Ok(())
    }

    // Drop per-stream bookkeeping when a stream is closed. RFC 9000 Section
    // 4.1 keeps the connection-level counter monotonic across stream
    // lifetimes, so we never decrement `connection_consumed`; only the
    // per-stream maps are released so completed streams cannot double-count.
    fn release_stream(&mut self, stream_id: u64) {
        self.stream_consumed.remove(&stream_id);
        self.last_announced_max_stream_data.remove(&stream_id);
        self.pending_max_stream_data.remove(&stream_id);
        self.stream_received.remove(&stream_id);
        self.stream_data_overrides.remove(&stream_id);
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

    fn stream_data_limit(&self, stream_id: u64) -> Result<u64> {
        if let Some(max_stream_data) = self.stream_data_overrides.get(&stream_id) {
            return Ok(*max_stream_data);
        }
        self.initial_stream_data_limit(stream_id)
    }

    fn initial_stream_data_limit(&self, stream_id: u64) -> Result<u64> {
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
    client_early_data_keys: Option<QuicPacketKeyMaterial>,
    server_handshake_keys: Option<QuicPacketKeyMaterial>,
    client_application_keys: Option<QuicPacketKeyMaterial>,
    server_application_keys: Option<QuicPacketKeyMaterial>,
    client_application_next_keys: Option<QuicPacketKeyMaterial>,
    server_application_next_keys: Option<QuicPacketKeyMaterial>,
    server_application_previous: Option<PreviousKeys>,
    write_key_phase: bool,
    read_key_phase: bool,
    application_key_update: OneRttKeyUpdate,
    initial_crypto: QuicCryptoAssembler,
    handshake_crypto: QuicCryptoAssembler,
    initial_ack_tracker: QuicAckTracker,
    handshake_ack_tracker: QuicAckTracker,
    application_ack_tracker: QuicAckTracker,
    client_initial_loss_detector: QuicLossDetector,
    client_handshake_loss_detector: QuicLossDetector,
    client_application_loss_detector: QuicLossDetector,
    client_application_flow_control: QuicApplicationFlowControl,
    client_application_receive_flow_control: QuicReceiveFlowControl,
    client_initial_sent_crypto: BTreeMap<u64, SentCryptoPacket>,
    client_handshake_sent_crypto: BTreeMap<u64, SentCryptoPacket>,
    client_application_sent_streams: BTreeMap<u64, SentApplicationStreamPacket>,
    client_application_recovery_lost_packets: Vec<u64>,
    client_application_ecn_congestion: bool,
    client_path_validator: QuicPathValidator,
    client_cid_inventory: QuicConnectionIdInventory,
    client_pmtu_probe: QuicPmtuProbePolicy,
    server_transport_parameters_validated: bool,
    recovery: RecoveryState,
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
    close_state: QuicCloseState,
}

pub struct NativeQuicServerHandshake {
    tls: NativeQuicTlsSession,
    client_source_cid: ConnectionId,
    server_source_cid: ConnectionId,
    client_initial_keys: QuicPacketKeyMaterial,
    server_initial_keys: QuicPacketKeyMaterial,
    client_handshake_keys: Option<QuicPacketKeyMaterial>,
    client_early_data_keys: Option<QuicPacketKeyMaterial>,
    server_handshake_keys: Option<QuicPacketKeyMaterial>,
    client_initial_crypto: QuicCryptoAssembler,
    client_handshake_crypto: QuicCryptoAssembler,
    client_initial_ack_tracker: QuicAckTracker,
    client_handshake_ack_tracker: QuicAckTracker,
    client_application_ack_tracker: QuicAckTracker,
    server_initial_loss_detector: QuicLossDetector,
    server_handshake_loss_detector: QuicLossDetector,
    server_application_loss_detector: QuicLossDetector,
    server_application_flow_control: QuicApplicationFlowControl,
    server_application_receive_flow_control: QuicReceiveFlowControl,
    server_application_sent_streams: BTreeMap<u64, SentApplicationStreamPacket>,
    server_application_recovery_lost_packets: Vec<u64>,
    server_initial_sent_crypto: BTreeMap<u64, SentCryptoPacket>,
    server_handshake_sent_crypto: BTreeMap<u64, SentCryptoPacket>,
    server_path_validator: QuicPathValidator,
    cid_inventory: QuicConnectionIdInventory,
    recovery: RecoveryState,
    ack_delay_exponent: u64,
    next_client_initial_packet_number: u64,
    next_client_handshake_packet_number: u64,
    next_client_application_packet_number: u64,
    next_server_initial_packet_number: u64,
    next_server_handshake_packet_number: u64,
    next_server_application_packet_number: u64,
    next_server_unidirectional_stream_id: u64,
    client_application_keys: Option<QuicPacketKeyMaterial>,
    server_application_keys: Option<QuicPacketKeyMaterial>,
    client_application_next_keys: Option<QuicPacketKeyMaterial>,
    server_application_next_keys: Option<QuicPacketKeyMaterial>,
    client_application_previous: Option<PreviousKeys>,
    write_key_phase: bool,
    read_key_phase: bool,
    application_key_update: OneRttKeyUpdate,
    server_initial_crypto_offset: u64,
    server_handshake_crypto_offset: u64,
    server_stream_offsets: BTreeMap<u64, u64>,
    server_control_stream_id: Option<u64>,
    client_h3_stream_buffers: BTreeMap<u64, BytesMut>,
    client_h3_stream_buffer_offsets: BTreeMap<u64, u64>,
    client_h3_stream_types: BTreeMap<u64, native::H3StreamType>,
    close_draining: bool,
    close_state: QuicCloseState,
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
        let cid_inventory = new_server_cid_inventory(
            fingerprint,
            &server_source_cid,
            &client_source_cid,
        );
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
            client_early_data_keys: None,
            server_handshake_keys: None,
            client_initial_crypto: QuicCryptoAssembler::default(),
            client_handshake_crypto: QuicCryptoAssembler::default(),
            client_initial_ack_tracker: QuicAckTracker::default(),
            client_handshake_ack_tracker: QuicAckTracker::default(),
            client_application_ack_tracker: QuicAckTracker::default(),
            server_initial_loss_detector: QuicLossDetector::default(),
            server_handshake_loss_detector: QuicLossDetector::default(),
            server_application_loss_detector: QuicLossDetector::default(),
            server_application_flow_control: QuicApplicationFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_receive_flow_control: QuicReceiveFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_sent_streams: BTreeMap::new(),
            server_application_recovery_lost_packets: Vec::new(),
            server_initial_sent_crypto: BTreeMap::new(),
            server_handshake_sent_crypto: BTreeMap::new(),
            server_path_validator: QuicPathValidator::default(),
            cid_inventory,
            next_client_initial_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_client_application_packet_number: 0,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_server_unidirectional_stream_id: 3,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            client_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            server_initial_crypto_offset: 0,
            server_handshake_crypto_offset: 0,
            server_stream_offsets: BTreeMap::new(),
            server_control_stream_id: None,
            client_h3_stream_buffers: BTreeMap::new(),
            client_h3_stream_buffer_offsets: BTreeMap::new(),
            client_h3_stream_types: BTreeMap::new(),
            close_draining: false,
            close_state: QuicCloseState::default(),
            recovery: recovery_state_from_transport(&fingerprint.transport),
            ack_delay_exponent: fingerprint.transport.ack_delay_exponent,
        })
    }

    pub fn new_with_ticket_keys(
        fingerprint: &Http3Fingerprint,
        cert_pem: &[u8],
        key_pem: &[u8],
        client_destination_cid: ConnectionId,
        client_source_cid: ConnectionId,
        server_source_cid: ConnectionId,
        ticket_keys: &[u8; crate::transport::h3::tls::NATIVE_H3_TICKET_KEY_LEN],
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(client_destination_cid.as_bytes())?;
        let cid_inventory = new_server_cid_inventory(
            fingerprint,
            &server_source_cid,
            &client_source_cid,
        );
        Ok(Self {
            tls: NativeQuicTlsSession::server_with_connection_ids_and_ticket_keys(
                fingerprint,
                cert_pem,
                key_pem,
                &client_destination_cid,
                &server_source_cid,
                ticket_keys,
            )?,
            client_source_cid,
            server_source_cid,
            client_initial_keys: initial_keys.client,
            server_initial_keys: initial_keys.server,
            client_handshake_keys: None,
            client_early_data_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            client_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            server_initial_crypto_offset: 0,
            server_handshake_crypto_offset: 0,
            server_stream_offsets: BTreeMap::new(),
            server_control_stream_id: None,
            client_h3_stream_buffers: BTreeMap::new(),
            client_h3_stream_buffer_offsets: BTreeMap::new(),
            client_h3_stream_types: BTreeMap::new(),
            close_draining: false,
            close_state: QuicCloseState::default(),
            client_initial_crypto: QuicCryptoAssembler::default(),
            client_handshake_crypto: QuicCryptoAssembler::default(),
            client_initial_ack_tracker: QuicAckTracker::default(),
            client_handshake_ack_tracker: QuicAckTracker::default(),
            client_application_ack_tracker: QuicAckTracker::default(),
            server_initial_loss_detector: QuicLossDetector::default(),
            server_handshake_loss_detector: QuicLossDetector::default(),
            server_application_loss_detector: QuicLossDetector::default(),
            server_application_flow_control: QuicApplicationFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_receive_flow_control: QuicReceiveFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_sent_streams: BTreeMap::new(),
            server_application_recovery_lost_packets: Vec::new(),
            server_initial_sent_crypto: BTreeMap::new(),
            server_handshake_sent_crypto: BTreeMap::new(),
            server_path_validator: QuicPathValidator::default(),
            cid_inventory,
            next_client_initial_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_client_application_packet_number: 0,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_server_unidirectional_stream_id: 3,
            recovery: recovery_state_from_transport(&fingerprint.transport),
            ack_delay_exponent: fingerprint.transport.ack_delay_exponent,
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
        let cid_inventory = new_server_cid_inventory(
            fingerprint,
            &server_source_cid,
            &client_source_cid,
        );
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
            client_early_data_keys: None,
            server_handshake_keys: None,
            client_initial_crypto: QuicCryptoAssembler::default(),
            client_handshake_crypto: QuicCryptoAssembler::default(),
            client_initial_ack_tracker: QuicAckTracker::default(),
            client_handshake_ack_tracker: QuicAckTracker::default(),
            client_application_ack_tracker: QuicAckTracker::default(),
            server_initial_loss_detector: QuicLossDetector::default(),
            server_handshake_loss_detector: QuicLossDetector::default(),
            server_application_loss_detector: QuicLossDetector::default(),
            server_application_flow_control: QuicApplicationFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_receive_flow_control: QuicReceiveFlowControl::server(
                &fingerprint.transport,
            ),
            server_application_sent_streams: BTreeMap::new(),
            server_application_recovery_lost_packets: Vec::new(),
            server_initial_sent_crypto: BTreeMap::new(),
            server_handshake_sent_crypto: BTreeMap::new(),
            server_path_validator: QuicPathValidator::default(),
            cid_inventory,
            next_client_initial_packet_number: 0,
            next_client_handshake_packet_number: 0,
            next_client_application_packet_number: 0,
            next_server_initial_packet_number: 0,
            next_server_handshake_packet_number: 0,
            next_server_application_packet_number: 0,
            next_server_unidirectional_stream_id: 3,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            client_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            server_initial_crypto_offset: 0,
            server_handshake_crypto_offset: 0,
            server_stream_offsets: BTreeMap::new(),
            server_control_stream_id: None,
            client_h3_stream_buffers: BTreeMap::new(),
            client_h3_stream_buffer_offsets: BTreeMap::new(),
            client_h3_stream_types: BTreeMap::new(),
            close_draining: false,
            close_state: QuicCloseState::default(),
            recovery: recovery_state_from_transport(&fingerprint.transport),
            ack_delay_exponent: fingerprint.transport.ack_delay_exponent,
        })
    }

    pub fn is_application_ready(&self) -> bool {
        self.client_application_keys.is_some() && self.server_application_keys.is_some()
    }

    /// Native HTTP/3 TLS 1.3 resumption / QUIC 0-RTT status for this server
    /// handshake. Server-side `EarlyAccepted` requires that the server
    /// configured a matching `SSL_set_quic_early_data_context` per
    /// RFC 9001 section 4.6.
    pub fn handshake_status(&self) -> NativeH3HandshakeStatus {
        self.tls.handshake_status()
    }

    /// BoringSSL `SSL_get_early_data_reason` code for diagnostic logging on
    /// the server side. See `ssl_early_data_reason_t` in `openssl/ssl.h`.
    pub fn early_data_reason(&self) -> u32 {
        self.tls.early_data_reason()
    }

    pub fn is_close_draining(&self) -> bool {
        self.close_draining
    }

    pub fn close_state(&self) -> &QuicCloseState {
        &self.close_state
    }

    pub fn close_state_mut(&mut self) -> &mut QuicCloseState {
        &mut self.close_state
    }

    /// RFC9000 § 10.2 closing: called by the server driver after emitting a
    /// CONNECTION_CLOSE frame to suppress further outbound application data
    /// and anchor the close timer.
    pub fn server_enter_closing(&mut self, now: Instant) {
        self.close_state.enter_closing(now);
        self.close_draining = true;
    }

    /// RFC9000 § 10.2 draining: called by the server driver when entering
    /// the draining phase explicitly. Receiving a peer CONNECTION_CLOSE in
    /// `open_client_h3_event_packet` also drives this transition.
    pub fn server_enter_draining(&mut self, now: Instant) {
        self.close_state.enter_draining(now);
        self.close_draining = true;
    }

    /// Returns the RFC9000 § 10.2 close window derived from the server's
    /// application-space loss detector via RFC9002 § 6.2.1
    /// `current_PTO * 3`.
    pub fn server_close_window(&self) -> Duration {
        self.server_application_loss_detector.close_window()
    }

    pub fn server_is_close_window_expired(&self, now: Instant) -> bool {
        self.close_state.is_expired(now, self.server_close_window())
    }

    pub fn server_close_time_until_expiry(&self, now: Instant) -> Option<Duration> {
        self.close_state
            .time_until_expiry(now, self.server_close_window())
    }

    pub fn server_should_replay_connection_close(&self, now: Instant) -> bool {
        self.close_state.should_replay(now)
    }

    pub fn server_mark_connection_close_replayed(&mut self, now: Instant) {
        self.close_state.mark_replayed(now);
    }

    pub fn server_observe_inbound_packet_for_close(&mut self) -> u64 {
        self.close_state.observe_inbound_packet()
    }

    pub fn server_application_pto(&self) -> Duration {
        self.server_application_loss_detector.current_pto()
    }

    /// Current write-side key phase bit per RFC9001 § 6 (the bit set on
    /// outbound 1-RTT short-header packets).
    pub fn write_key_phase(&self) -> bool {
        self.write_key_phase
    }

    /// Current read-side key phase bit per RFC9001 § 6 (what the peer's
    /// most-recent committed write phase looks like from here).
    pub fn read_key_phase(&self) -> bool {
        self.read_key_phase
    }

    /// Whether a locally-initiated key update is currently waiting for an ACK
    /// of a packet sent at the new write phase per RFC9001 § 6.5.
    pub fn key_update_in_progress(&self) -> bool {
        self.application_key_update.write_update_in_progress
    }

    /// Force a 1-RTT key update. Returns an error when the previous local key
    /// update has not yet been confirmed via ACK (RFC9001 § 6.5) so callers
    /// cannot accidentally chain updates faster than the peer can confirm.
    ///
    /// This is the deterministic test hook called for by the production
    /// implementation; in production code, a key update can also be triggered
    /// implicitly when a peer's packet at the next phase is decrypted.
    pub fn force_key_update(&mut self) -> Result<()> {
        if self.application_key_update.write_update_in_progress {
            return Err(Error::Quic(
                "RFC9001 § 6.5: cannot initiate a new key update while a previous one is unconfirmed"
                    .into(),
            ));
        }
        let next = self.server_application_next_keys.take().ok_or_else(|| {
            Error::Quic(
                "native QUIC server cannot force a key update before TLS application secrets are installed"
                    .into(),
            )
        })?;
        self.server_application_keys = Some(next);
        let new_current = self
            .server_application_keys
            .as_ref()
            .expect("server application keys just installed");
        self.server_application_next_keys = Some(derive_next_packet_key_material(new_current)?);
        self.write_key_phase = !self.write_key_phase;
        self.application_key_update.write_update_in_progress = true;
        self.application_key_update.write_update_anchor =
            Some(self.next_server_application_packet_number);
        Ok(())
    }

    fn commit_receive_key_update(&mut self, now: Instant) -> Result<()> {
        let Some(current) = self.client_application_keys.take() else {
            return Err(Error::Quic(
                "native QUIC server cannot rotate read keys without an installed current key set"
                    .into(),
            ));
        };
        let Some(next) = self.client_application_next_keys.take() else {
            return Err(Error::Quic(
                "native QUIC server cannot rotate read keys without precomputed next key set"
                    .into(),
            ));
        };
        let old_phase = self.read_key_phase;
        self.client_application_keys = Some(next);
        let new_current = self
            .client_application_keys
            .as_ref()
            .expect("client application keys just installed");
        self.client_application_next_keys = Some(derive_next_packet_key_material(new_current)?);
        self.client_application_previous = Some(PreviousKeys {
            keys: current,
            phase: old_phase,
            retire_at: now + PREVIOUS_KEY_WINDOW,
        });
        self.read_key_phase = !self.read_key_phase;

        if self.write_key_phase != self.read_key_phase
            && !self.application_key_update.write_update_in_progress
        {
            let next_write = self.server_application_next_keys.take().ok_or_else(|| {
                Error::Quic(
                    "native QUIC server cannot mirror peer key update without precomputed next write keys"
                        .into(),
                )
            })?;
            self.server_application_keys = Some(next_write);
            let new_current_write = self
                .server_application_keys
                .as_ref()
                .expect("server application keys just rotated");
            self.server_application_next_keys =
                Some(derive_next_packet_key_material(new_current_write)?);
            self.write_key_phase = !self.write_key_phase;
            self.application_key_update.write_update_in_progress = true;
            self.application_key_update.write_update_anchor =
                Some(self.next_server_application_packet_number);
        }

        Ok(())
    }

    pub fn server_application_lost_packets(&self) -> Vec<u64> {
        self.server_application_loss_detector.lost_packets()
    }

    pub fn recovery(&self) -> &RecoveryState {
        &self.recovery
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.recovery.loss_detection_timer()
    }

    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> LossDetectionOutcome {
        self.recovery.on_loss_detection_timeout(now)
    }

    pub fn application_pto(&self) -> Duration {
        self.recovery.current_pto()
    }

    pub fn application_pto_timeout(&self) -> Duration {
        let max_ack_delay = self.recovery.max_ack_delay();
        let backoff = 1u32 << self.recovery.pto_count().min(31);
        self.recovery
            .current_pto()
            .saturating_add(max_ack_delay.saturating_mul(backoff))
    }

    pub fn retransmit_lost_server_application_stream_packets(
        &mut self,
    ) -> Result<Vec<ServerApplicationPacket>> {
        let mut lost_packets = self.server_application_loss_detector.lost_packets();
        lost_packets.append(&mut self.server_application_recovery_lost_packets);
        self.retransmit_server_application_stream_packets(lost_packets)
    }

    pub fn retransmit_pto_server_application_stream_packets(
        &mut self,
        now: Instant,
        pto_timeout: Duration,
    ) -> Result<Vec<ServerApplicationPacket>> {
        let expired_packets = self
            .server_application_loss_detector
            .pto_expired_packets(now, pto_timeout);
        self.retransmit_server_application_stream_packets(expired_packets)
    }

    fn retransmit_server_application_stream_packets<I>(
        &mut self,
        packet_numbers: I,
    ) -> Result<Vec<ServerApplicationPacket>>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut packet_numbers = packet_numbers.into_iter().collect::<Vec<_>>();
        packet_numbers.sort_unstable();
        packet_numbers.dedup();
        let mut retransmits = Vec::new();
        for packet_number in packet_numbers {
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
        self.process_client_initial_with_ecn(datagram, None)
    }

    pub fn process_client_initial_with_ecn(
        &mut self,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<ServerHandshakeFlight> {
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
            observe_packet_with_ecn(
                &mut self.client_initial_ack_tracker,
                opened.packet_number,
                ecn_mark,
                Instant::now(),
            );
            self.next_client_initial_packet_number = opened.packet_number + 1;

            for frame in decode_frames(&opened.payload)? {
                for packet_number in self.server_initial_loss_detector.on_ack_frame(&frame)? {
                    self.server_initial_sent_crypto.remove(&packet_number);
                }
                let outcome = self.recovery.on_ack_received(
                    PacketNumberSpace::Initial,
                    &frame,
                    self.ack_delay_exponent,
                    Instant::now(),
                )?;
                for (packet_number, _) in outcome.newly_acked {
                    self.server_initial_sent_crypto.remove(&packet_number);
                }
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
        self.process_client_handshake_with_ecn(datagram, None)
    }

    pub fn process_client_handshake_with_ecn(
        &mut self,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
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
            observe_packet_with_ecn(
                &mut self.client_handshake_ack_tracker,
                opened.packet_number,
                ecn_mark,
                Instant::now(),
            );
            self.next_client_handshake_packet_number = opened.packet_number + 1;

            for frame in decode_frames(&opened.payload)? {
                for packet_number in self.server_handshake_loss_detector.on_ack_frame(&frame)? {
                    self.server_handshake_sent_crypto.remove(&packet_number);
                }
                let outcome = self.recovery.on_ack_received(
                    PacketNumberSpace::Handshake,
                    &frame,
                    self.ack_delay_exponent,
                    Instant::now(),
                )?;
                for (packet_number, _) in outcome.newly_acked {
                    self.server_handshake_sent_crypto.remove(&packet_number);
                }
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
        self.open_client_application_packet_with_ecn(packet, None)
    }

    pub fn open_client_application_packet_with_ecn(
        &mut self,
        packet: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<QuicFrame>> {
        // RFC9000 § 10.2: stop parsing inbound packets once we have entered
        // the draining phase. Closing-phase parsing is preserved so the
        // server can take the MAY-optimisation path (§ 10.2: closing -> draining
        // once the peer's CONNECTION_CLOSE is observed).
        if self.close_state.is_draining() {
            return Ok(Vec::new());
        }
        let Some(client_application_keys) = self.client_application_keys.as_ref() else {
            return Err(Error::Quic(
                "native server application packet decryption is waiting for TLS application keys"
                    .into(),
            ));
        };
        let now = Instant::now();
        let destination_cid_len = match_local_connection_id(
            packet,
            self.cid_inventory.unretired_locals(),
        )
        .map(|(_, len)| len)
        .unwrap_or_else(|| self.server_source_cid.as_bytes().len());
        let opened = try_open_one_rtt_packet(
            client_application_keys,
            self.client_application_next_keys.as_ref(),
            self.client_application_previous.as_ref(),
            self.read_key_phase,
            now,
            packet,
            destination_cid_len,
            self.next_client_application_packet_number,
        )?;
        if matches!(opened.outcome, OneRttOpenOutcome::Next) {
            self.commit_receive_key_update(now)?;
        }
        let opened = opened.opened;
        self.next_client_application_packet_number = opened.packet_number + 1;
        let frames = decode_frames(&opened.payload)?;
        self.apply_opened_client_application_frames(opened.packet_number, frames, now, ecn_mark)
    }

    pub fn open_client_zero_rtt_h3_event_packet(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<ClientH3Event>> {
        self.open_client_zero_rtt_h3_event_packet_with_ecn(datagram, None)
    }

    pub fn open_client_zero_rtt_h3_event_packet_with_ecn(
        &mut self,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<ClientH3Event>> {
        if self.close_state.is_draining() || !self.handshake_status().early_data_accepted() {
            return Ok(Vec::new());
        }
        let Some(client_early_data_keys) = self.client_early_data_keys.clone() else {
            return Ok(Vec::new());
        };

        let mut events = Vec::new();
        for packet in split_long_header_datagram(datagram)? {
            if packet.packet_type != LongHeaderType::ZeroRtt {
                continue;
            }
            let now = Instant::now();
            let opened = open_long_header_packet(
                &client_early_data_keys,
                &packet.packet,
                packet.packet_number_offset,
                self.next_client_application_packet_number,
            )?;
            self.next_client_application_packet_number = opened.packet_number + 1;
            let frames = decode_frames(&opened.payload)?;
            let frames = self.apply_opened_client_application_frames(
                opened.packet_number,
                frames,
                now,
                ecn_mark,
            )?;
            events.extend(self.client_h3_events_from_frames(frames, None)?);
        }
        Ok(events)
    }

    fn apply_opened_client_application_frames(
        &mut self,
        packet_number: u64,
        frames: Vec<QuicFrame>,
        now: Instant,
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<QuicFrame>> {
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
                self.application_key_update.note_packet_acked(packet_number);
            }
            if matches!(frame, QuicFrame::Ack { .. } | QuicFrame::AckEcn { .. }) {
                let outcome = self.recovery.on_ack_received(
                    PacketNumberSpace::Application,
                    frame,
                    self.ack_delay_exponent,
                    now,
                )?;
                for (packet_number, _) in outcome.newly_acked {
                    self.server_application_sent_streams.remove(&packet_number);
                    self.application_key_update.note_packet_acked(packet_number);
                }
                self.server_application_recovery_lost_packets.extend(
                    outcome
                        .lost
                        .into_iter()
                        .map(|(packet_number, _)| packet_number),
                );
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
                QuicFrame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                } => {
                    let _ = self.cid_inventory.observe_peer_new_connection_id(
                        *sequence_number,
                        *retire_prior_to,
                        connection_id.clone(),
                        *stateless_reset_token,
                    );
                }
                QuicFrame::RetireConnectionId { sequence_number } => {
                    let _ = self
                        .cid_inventory
                        .observe_peer_retire_connection_id(*sequence_number);
                }
                _ => {}
            }
        }
        if frames.iter().any(is_ack_eliciting_quic_frame) {
            observe_packet_with_ecn(
                &mut self.client_application_ack_tracker,
                packet_number,
                ecn_mark,
                now,
            );
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
            &self.server_outbound_peer_cid(),
            packet_number,
            packet_number_len,
            self.write_key_phase,
            &frame,
        )?;
        self.client_application_ack_tracker.mark_ack_sent();
        self.next_server_application_packet_number += 1;

        Ok(Some(ServerApplicationAckPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + self.server_outbound_peer_cid().as_bytes().len(),
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
        // RFC9000 § 10.2: once we are in the draining phase we MUST NOT
        // process any further inbound packets. While in the closing phase
        // we still parse incoming packets so we can take the MAY-optimisation
        // path and transition to draining when the peer also closes.
        if self.close_state.is_draining() {
            return Ok(Vec::new());
        }
        let frames = self.open_client_application_packet(packet)?;
        self.client_h3_events_from_frames(frames, None)
    }

    pub fn open_client_h3_event_packet_from(
        &mut self,
        packet: &[u8],
        remote_address: SocketAddr,
    ) -> Result<Vec<ClientH3Event>> {
        if self.close_state.is_draining() {
            return Ok(Vec::new());
        }
        let frames = self.open_client_application_packet(packet)?;
        self.client_h3_events_from_frames(frames, Some(remote_address))
    }

    fn client_h3_events_from_frames(
        &mut self,
        frames: Vec<QuicFrame>,
        remote_address: Option<SocketAddr>,
    ) -> Result<Vec<ClientH3Event>> {
        let mut events = Vec::new();
        for frame in frames {
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
                    // RFC9000 § 10.2: peer CONNECTION_CLOSE transitions us
                    // into the draining phase, which forbids any further
                    // outbound packets except an optional one-shot
                    // CONNECTION_CLOSE acknowledgement.
                    self.close_draining = true;
                    self.close_state.enter_draining(Instant::now());
                    events.push(ClientH3Event::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                }
                QuicFrame::PathChallenge(data) => events.push(ClientH3Event::PathChallenge(data)),
                QuicFrame::PathResponse(data) => {
                    if let Some(remote_address) = remote_address {
                        self.server_path_validator
                            .on_path_response_from(remote_address, data);
                    } else {
                        self.server_path_validator.on_path_response(data);
                    }
                }
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
        let packet = self.build_server_application_control_packet(QuicFrame::ConnectionClose {
            error_code,
            frame_type: None,
            reason,
        })?;
        // RFC9000 § 10.2: emitting a CONNECTION_CLOSE transitions the
        // connection into the closing phase. Mirroring the client handshake
        // helper, we anchor the timer at build time so server-side drivers
        // do not have to call `server_enter_closing` separately on every
        // path that emits a CONNECTION_CLOSE.
        self.server_enter_closing(Instant::now());
        Ok(packet)
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

    // Server-side symmetric hook for app-consumed bytes. RFC 9000 Section 4
    // treats client and server receivers identically: both advertise
    // MAX_DATA / MAX_STREAM_DATA absolute values derived from
    // `initial_max_*data + bytes_consumed_by_application` and only emit a
    // frame when the gating threshold is crossed.
    pub fn record_server_stream_consumed(&mut self, stream_id: u64, len: u64) -> Result<()> {
        self.server_application_receive_flow_control
            .record_stream_consumed(stream_id, len)
    }

    pub fn release_server_stream(&mut self, stream_id: u64) {
        self.server_application_receive_flow_control
            .release_stream(stream_id);
    }

    pub fn build_server_handshake_done_packet(&mut self) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::HandshakeDone)
    }

    pub fn build_server_new_connection_id_packet(
        &mut self,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Result<ServerApplicationControlPacket> {
        if connection_id.as_bytes().is_empty() {
            return Err(Error::Quic(
                "native QUIC NEW_CONNECTION_ID cannot carry an empty connection id".into(),
            ));
        }
        if retire_prior_to > sequence_number {
            return Err(Error::Quic(
                "native QUIC NEW_CONNECTION_ID retire_prior_to exceeds sequence_number".into(),
            ));
        }
        self.cid_inventory.register_local_issued(
            sequence_number,
            connection_id.clone(),
            stateless_reset_token,
        )?;
        self.build_server_application_control_packet(QuicFrame::NewConnectionId {
            sequence_number,
            retire_prior_to,
            connection_id: Bytes::copy_from_slice(connection_id.as_bytes()),
            stateless_reset_token,
        })
    }

    pub fn build_server_path_response_packet(
        &mut self,
        data: [u8; 8],
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet_with_min_datagram(
            QuicFrame::PathResponse(data),
            MIN_PATH_VALIDATION_DATAGRAM,
        )
    }

    pub fn build_server_path_challenge_packet_for_address(
        &mut self,
        remote_address: SocketAddr,
        data: [u8; 8],
    ) -> Result<ServerApplicationControlPacket> {
        let frame = self
            .server_path_validator
            .path_challenge_for_peer_address(remote_address, data)?;
        self.build_server_application_control_packet_with_min_datagram(
            frame,
            MIN_PATH_VALIDATION_DATAGRAM,
        )
    }

    pub fn build_server_retire_connection_id_packet(
        &mut self,
        sequence_number: u64,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet(QuicFrame::RetireConnectionId {
            sequence_number,
        })
    }

    pub fn build_server_connection_migration_close_packet(
        &mut self,
    ) -> Result<ServerApplicationControlPacket> {
        let packet = self.build_server_application_control_packet(QuicFrame::ConnectionClose {
            error_code: QUIC_CONNECTION_MIGRATION_ERROR,
            frame_type: None,
            reason: Bytes::new(),
        })?;
        self.server_enter_closing(Instant::now());
        Ok(packet)
    }

    pub fn server_pop_pending_peer_retires(&mut self) -> Vec<u64> {
        self.cid_inventory.drain_pending_peer_retires()
    }

    pub fn server_promote_peer_cid(&mut self, sequence_number: u64) -> Result<()> {
        self.cid_inventory.promote_peer_to_active(sequence_number)
    }

    pub fn server_outbound_peer_cid(&self) -> ConnectionId {
        self.cid_inventory
            .active_peer()
            .and_then(|entry| ConnectionId::from_bytes(entry.connection_id.clone()).ok())
            .unwrap_or_else(|| self.client_source_cid.clone())
    }

    pub fn server_local_cids_for_routing(&self) -> Vec<ConnectionId> {
        self.cid_inventory
            .unretired_locals()
            .map(|entry| entry.connection_id.clone())
            .collect()
    }

    pub fn is_server_path_address_validated(&self, remote_address: &SocketAddr) -> bool {
        self.server_path_validator
            .is_address_validated(remote_address)
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
                    self.recovery.set_has_handshake_keys(true);
                }
                (QuicSecretDirection::Read, QuicEncryptionLevel::EarlyData) => {
                    self.client_early_data_keys = Some(secret.packet_key_material()?);
                }
                (QuicSecretDirection::Write, QuicEncryptionLevel::Handshake) => {
                    self.server_handshake_keys = Some(secret.packet_key_material()?);
                    self.recovery.set_has_handshake_keys(true);
                }
                (QuicSecretDirection::Read, QuicEncryptionLevel::Application) => {
                    let keys = secret.packet_key_material()?;
                    self.client_application_next_keys =
                        Some(derive_next_packet_key_material(&keys)?);
                    self.client_application_keys = Some(keys);
                }
                (QuicSecretDirection::Write, QuicEncryptionLevel::Application) => {
                    let keys = secret.packet_key_material()?;
                    self.server_application_next_keys =
                        Some(derive_next_packet_key_material(&keys)?);
                    self.server_application_keys = Some(keys);
                }
                _ => {}
            }
        }
        if self.is_application_ready() && !self.recovery.handshake_complete() {
            self.recovery.discard_space(PacketNumberSpace::Initial);
            self.recovery.discard_space(PacketNumberSpace::Handshake);
            self.recovery.mark_handshake_complete();
        }
        Ok(())
    }

    fn build_server_initial_packet(&mut self, crypto_data: Bytes) -> Result<ServerHandshakePacket> {
        let crypto_offset = self.server_initial_crypto_offset;
        let packet = self.build_server_initial_packet_at_offset_with_sent_at(
            crypto_offset,
            crypto_data,
            Instant::now(),
        )?;
        self.server_initial_crypto_offset += packet.crypto_data.len() as u64;
        Ok(packet)
    }

    fn build_server_initial_packet_at_offset_with_sent_at(
        &mut self,
        crypto_offset: u64,
        crypto_data: Bytes,
        sent_at: Instant,
    ) -> Result<ServerHandshakePacket> {
        let packet_number = self.next_server_initial_packet_number;
        self.next_server_initial_packet_number += 1;
        let packet = build_server_crypto_packet(
            LongHeaderType::Initial,
            &self.server_initial_keys,
            &self.client_source_cid,
            &self.server_source_cid,
            packet_number,
            crypto_offset,
            crypto_data.clone(),
        )?;
        self.server_initial_loss_detector
            .on_packet_sent_at(packet_number, sent_at);
        self.recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            packet_number,
            SentPacketInfo::new(sent_at, packet.packet.len(), true, true),
        );
        self.server_initial_sent_crypto.insert(
            packet_number,
            SentCryptoPacket {
                packet_type: LongHeaderType::Initial,
                crypto_offset,
                crypto_data: crypto_data.clone(),
            },
        );
        Ok(packet)
    }

    fn build_server_handshake_packet(
        &mut self,
        crypto_data: Bytes,
    ) -> Result<ServerHandshakePacket> {
        let crypto_offset = self.server_handshake_crypto_offset;
        let packet = self.build_server_handshake_packet_at_offset_with_sent_at(
            crypto_offset,
            crypto_data,
            Instant::now(),
        )?;
        self.server_handshake_crypto_offset += packet.crypto_data.len() as u64;
        Ok(packet)
    }

    pub fn retransmit_pto_server_crypto_packets(
        &mut self,
        now: Instant,
        pto: Duration,
    ) -> Result<Vec<ServerHandshakePacket>> {
        let mut retransmits = Vec::new();
        for packet_number in self
            .server_initial_loss_detector
            .pto_expired_packets(now, pto)
        {
            self.server_initial_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.server_initial_sent_crypto.remove(&packet_number) else {
                continue;
            };
            if sent.packet_type != LongHeaderType::Initial {
                continue;
            }
            retransmits.push(self.build_server_initial_packet_at_offset_with_sent_at(
                sent.crypto_offset,
                sent.crypto_data,
                now,
            )?);
        }
        for packet_number in self
            .server_handshake_loss_detector
            .pto_expired_packets(now, pto)
        {
            self.server_handshake_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.server_handshake_sent_crypto.remove(&packet_number) else {
                continue;
            };
            if sent.packet_type != LongHeaderType::Handshake {
                continue;
            }
            retransmits.push(self.build_server_handshake_packet_at_offset_with_sent_at(
                sent.crypto_offset,
                sent.crypto_data,
                now,
            )?);
        }
        Ok(retransmits)
    }

    fn build_server_handshake_packet_at_offset_with_sent_at(
        &mut self,
        crypto_offset: u64,
        crypto_data: Bytes,
        sent_at: Instant,
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
            crypto_offset,
            crypto_data.clone(),
        )?;
        self.server_handshake_loss_detector
            .on_packet_sent_at(packet_number, sent_at);
        self.recovery.on_packet_sent(
            PacketNumberSpace::Handshake,
            packet_number,
            SentPacketInfo::new(sent_at, packet.packet.len(), true, true),
        );
        self.server_handshake_sent_crypto.insert(
            packet_number,
            SentCryptoPacket {
                packet_type: LongHeaderType::Handshake,
                crypto_offset,
                crypto_data: crypto_data.clone(),
            },
        );
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
        let peer_cid = self.server_outbound_peer_cid();
        let frame = encode_frame(&QuicFrame::Stream {
            stream_id,
            offset: (stream_offset > 0).then_some(stream_offset),
            fin,
            data: data.clone(),
        });
        let packet = protect_short_header_packet(
            server_application_keys,
            &peer_cid,
            packet_number,
            packet_number_len,
            self.write_key_phase,
            &frame,
        )?;

        let now = Instant::now();
        let packet_size = packet.len();
        self.server_application_loss_detector
            .on_packet_sent_at(packet_number, now);
        self.server_application_sent_streams.insert(
            packet_number,
            SentApplicationStreamPacket {
                stream_id,
                stream_offset,
                fin,
                data: data.clone(),
            },
        );
        self.recovery.on_packet_sent(
            PacketNumberSpace::Application,
            packet_number,
            SentPacketInfo::new(now, packet_size, true, true),
        );
        self.next_server_application_packet_number += 1;

        Ok(ServerApplicationPacket {
            packet,
            packet_number,
            stream_id,
            packet_number_offset: 1 + peer_cid.as_bytes().len(),
            data,
        })
    }

    fn build_server_application_control_packet(
        &mut self,
        frame: QuicFrame,
    ) -> Result<ServerApplicationControlPacket> {
        self.build_server_application_control_packet_with_min_datagram(frame, 0)
    }

    fn build_server_application_control_packet_with_min_datagram(
        &mut self,
        frame: QuicFrame,
        min_datagram: usize,
    ) -> Result<ServerApplicationControlPacket> {
        let Some(server_application_keys) = &self.server_application_keys else {
            return Err(Error::Quic(
                "native server application packet encryption is waiting for TLS application keys"
                    .into(),
            ));
        };

        let packet_number = self.next_server_application_packet_number;
        let packet_number_len = 2;
        let peer_cid = self.server_outbound_peer_cid();
        let short_header_len = 1 + peer_cid.as_bytes().len() + packet_number_len;
        let payload = if min_datagram > 0 {
            pad_short_header_payload_to_min_datagram(
                padded_short_header_payload(encode_frame(&frame)),
                short_header_len,
                min_datagram,
            )
        } else {
            padded_short_header_payload(encode_frame(&frame))
        };
        let packet = protect_short_header_packet(
            server_application_keys,
            &peer_cid,
            packet_number,
            packet_number_len,
            self.write_key_phase,
            &payload,
        )?;
        let now = Instant::now();
        let packet_size = packet.len();
        self.server_application_loss_detector
            .on_packet_sent_at(packet_number, now);
        self.recovery.on_packet_sent(
            PacketNumberSpace::Application,
            packet_number,
            SentPacketInfo::new(now, packet_size, true, true),
        );
        self.next_server_application_packet_number += 1;

        Ok(ServerApplicationControlPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + peer_cid.as_bytes().len(),
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

    /// Build a client handshake that optionally replays a cached TLS 1.3
    /// session ticket. When `session_der` is `Some`, the ClientHello is emitted
    /// via the resumption path (`client_with_replayed_session_ticket`);
    /// otherwise it falls through to the ordinary first-handshake constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn client_with_tls_fingerprint_and_session(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
        session_der: Option<&[u8]>,
    ) -> Result<Self> {
        match session_der {
            Some(session_der) => Self::client_with_replayed_session_ticket(
                server_name,
                fingerprint,
                tls_fingerprint,
                destination_cid,
                source_cid,
                verify_peer,
                root_certs,
                use_platform_roots,
                session_der,
            ),
            None => Self::client_with_tls_fingerprint(
                server_name,
                fingerprint,
                tls_fingerprint,
                destination_cid,
                source_cid,
                verify_peer,
                root_certs,
                use_platform_roots,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn client_with_tls_fingerprint_and_zero_rtt_request(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
        session_der: &[u8],
        early_data: &[u8],
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(destination_cid.as_bytes())?;
        let mut tls =
            NativeQuicTlsSession::client_with_initial_source_connection_id_and_zero_rtt_offer(
                server_name,
                fingerprint,
                &source_cid,
                tls_fingerprint,
                verify_peer,
                root_certs,
                use_platform_roots,
                session_der,
                early_data,
            )?;
        let client_initial = build_client_initial_packet_from_capture_with_size(
            tls.take_client_initial(),
            destination_cid.clone(),
            source_cid.clone(),
            fingerprint.transport.initial_datagram_size,
        )?;
        let client_early_data_keys = client_initial
            .secrets
            .iter()
            .find(|secret| {
                secret.direction == QuicSecretDirection::Write
                    && secret.level == QuicEncryptionLevel::EarlyData
            })
            .map(QuicTlsSecret::packet_key_material)
            .transpose()?;
        let client_cid_inventory = new_client_cid_inventory(fingerprint, &source_cid);

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
            client_early_data_keys,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            server_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            initial_crypto: QuicCryptoAssembler::default(),
            handshake_crypto: QuicCryptoAssembler::default(),
            initial_ack_tracker: QuicAckTracker::default(),
            handshake_ack_tracker: QuicAckTracker::default(),
            application_ack_tracker: QuicAckTracker::default(),
            client_initial_loss_detector: QuicLossDetector::default(),
            client_handshake_loss_detector: QuicLossDetector::default(),
            client_application_loss_detector: QuicLossDetector::default(),
            client_application_flow_control: QuicApplicationFlowControl::client(
                &fingerprint.transport,
            ),
            client_application_receive_flow_control: QuicReceiveFlowControl::client(
                &fingerprint.transport,
            ),
            client_initial_sent_crypto: BTreeMap::new(),
            client_handshake_sent_crypto: BTreeMap::new(),
            client_application_sent_streams: BTreeMap::new(),
            client_application_recovery_lost_packets: Vec::new(),
            client_application_ecn_congestion: false,
            client_path_validator: QuicPathValidator::default(),
            client_cid_inventory,
            client_pmtu_probe: QuicPmtuProbePolicy::from_transport(&fingerprint.transport),
            server_transport_parameters_validated: false,
            recovery: recovery_state_from_transport(&fingerprint.transport),
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
            close_state: QuicCloseState::default(),
        })
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
        let client_cid_inventory = new_client_cid_inventory(fingerprint, &source_cid);

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
            client_early_data_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            server_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            initial_crypto: QuicCryptoAssembler::default(),
            handshake_crypto: QuicCryptoAssembler::default(),
            initial_ack_tracker: QuicAckTracker::default(),
            handshake_ack_tracker: QuicAckTracker::default(),
            application_ack_tracker: QuicAckTracker::default(),
            client_initial_loss_detector: QuicLossDetector::default(),
            client_handshake_loss_detector: QuicLossDetector::default(),
            client_application_loss_detector: QuicLossDetector::default(),
            client_application_flow_control: QuicApplicationFlowControl::client(
                &fingerprint.transport,
            ),
            client_application_receive_flow_control: QuicReceiveFlowControl::client(
                &fingerprint.transport,
            ),
            client_initial_sent_crypto: BTreeMap::new(),
            client_handshake_sent_crypto: BTreeMap::new(),
            client_application_sent_streams: BTreeMap::new(),
            client_application_recovery_lost_packets: Vec::new(),
            client_application_ecn_congestion: false,
            client_path_validator: QuicPathValidator::default(),
            client_cid_inventory,
            client_pmtu_probe: QuicPmtuProbePolicy::from_transport(&fingerprint.transport),
            server_transport_parameters_validated: false,
            recovery: recovery_state_from_transport(&fingerprint.transport),
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
            close_state: QuicCloseState::default(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn client_with_replayed_session_ticket(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
        destination_cid: ConnectionId,
        source_cid: ConnectionId,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
        session_ticket_der: &[u8],
    ) -> Result<Self> {
        let initial_keys = derive_initial_key_material(destination_cid.as_bytes())?;
        let mut tls =
            NativeQuicTlsSession::client_with_initial_source_connection_id_and_replayed_session(
                server_name,
                fingerprint,
                &source_cid,
                tls_fingerprint,
                verify_peer,
                root_certs,
                use_platform_roots,
                session_ticket_der,
            )?;
        let client_initial = build_client_initial_packet_from_capture_with_size(
            tls.take_client_initial(),
            destination_cid.clone(),
            source_cid.clone(),
            fingerprint.transport.initial_datagram_size,
        )?;
        let client_cid_inventory = new_client_cid_inventory(fingerprint, &source_cid);

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
            client_early_data_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            client_application_next_keys: None,
            server_application_next_keys: None,
            server_application_previous: None,
            write_key_phase: false,
            read_key_phase: false,
            application_key_update: OneRttKeyUpdate::default(),
            initial_crypto: QuicCryptoAssembler::default(),
            handshake_crypto: QuicCryptoAssembler::default(),
            initial_ack_tracker: QuicAckTracker::default(),
            handshake_ack_tracker: QuicAckTracker::default(),
            application_ack_tracker: QuicAckTracker::default(),
            client_initial_loss_detector: QuicLossDetector::default(),
            client_handshake_loss_detector: QuicLossDetector::default(),
            client_application_loss_detector: QuicLossDetector::default(),
            client_application_flow_control: QuicApplicationFlowControl::client(
                &fingerprint.transport,
            ),
            client_application_receive_flow_control: QuicReceiveFlowControl::client(
                &fingerprint.transport,
            ),
            client_initial_sent_crypto: BTreeMap::new(),
            client_handshake_sent_crypto: BTreeMap::new(),
            client_application_sent_streams: BTreeMap::new(),
            client_application_recovery_lost_packets: Vec::new(),
            client_application_ecn_congestion: false,
            client_path_validator: QuicPathValidator::default(),
            client_cid_inventory,
            client_pmtu_probe: QuicPmtuProbePolicy::from_transport(&fingerprint.transport),
            server_transport_parameters_validated: false,
            recovery: recovery_state_from_transport(&fingerprint.transport),
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
            close_state: QuicCloseState::default(),
        })
    }

    pub fn take_session_tickets(&mut self) -> Vec<NativeH3SessionTicket> {
        self.tls.take_session_tickets()
    }

    /// Native HTTP/3 TLS 1.3 resumption / QUIC 0-RTT status for this handshake.
    ///
    /// Combines `SSL_session_reused`, `SSL_early_data_accepted`, and the
    /// per-session 0-RTT offer flag into [`NativeH3HandshakeStatus`]. Stable
    /// once the handshake has produced application secrets per RFC 9001
    /// section 4.6.
    pub fn handshake_status(&self) -> NativeH3HandshakeStatus {
        self.tls.handshake_status()
    }

    /// BoringSSL `SSL_get_early_data_reason` code (e.g. `ssl_early_data_accepted = 2`,
    /// `ssl_early_data_quic_parameter_mismatch = 13`) for diagnostic logging.
    pub fn early_data_reason(&self) -> u32 {
        self.tls.early_data_reason()
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
                && secret.level == QuicEncryptionLevel::EarlyData
            {
                self.client_early_data_keys = Some(secret.packet_key_material()?);
            } else if secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Handshake
            {
                self.client_handshake_keys = Some(secret.packet_key_material()?);
            } else if secret.direction == QuicSecretDirection::Read
                && secret.level == QuicEncryptionLevel::Application
            {
                let keys = secret.packet_key_material()?;
                self.server_application_next_keys = Some(derive_next_packet_key_material(&keys)?);
                self.server_application_keys = Some(keys);
            } else if secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Application
            {
                let keys = secret.packet_key_material()?;
                self.client_application_next_keys = Some(derive_next_packet_key_material(&keys)?);
                self.client_application_keys = Some(keys);
            }
        }
        if self.is_application_ready() && !self.recovery.handshake_complete() {
            self.recovery.discard_space(PacketNumberSpace::Initial);
            self.recovery.discard_space(PacketNumberSpace::Handshake);
            self.recovery.mark_handshake_complete();
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

    pub fn close_state(&self) -> &QuicCloseState {
        &self.close_state
    }

    pub fn close_state_mut(&mut self) -> &mut QuicCloseState {
        &mut self.close_state
    }

    /// RFC9000 § 10.2 closing: called by the client driver after emitting a
    /// CONNECTION_CLOSE frame to suppress further outbound application data
    /// and anchor the close timer at `now`.
    pub fn client_enter_closing(&mut self, now: Instant) {
        self.close_state.enter_closing(now);
        self.close_draining = true;
    }

    /// RFC9000 § 10.2 draining: called when the client driver wants to
    /// enter draining explicitly. Peer CONNECTION_CLOSE handling in
    /// `open_client_h3_event_packet` also drives this transition.
    pub fn client_enter_draining(&mut self, now: Instant) {
        self.close_state.enter_draining(now);
        self.close_draining = true;
    }

    /// Returns the RFC9000 § 10.2 close window derived from the client
    /// application-space loss detector via RFC9002 § 6.2.1 `current_PTO * 3`.
    pub fn client_close_window(&self) -> Duration {
        self.client_application_loss_detector.close_window()
    }

    pub fn client_is_close_window_expired(&self, now: Instant) -> bool {
        self.close_state.is_expired(now, self.client_close_window())
    }

    pub fn client_close_time_until_expiry(&self, now: Instant) -> Option<Duration> {
        self.close_state
            .time_until_expiry(now, self.client_close_window())
    }

    pub fn client_should_replay_connection_close(&self, now: Instant) -> bool {
        self.close_state.should_replay(now)
    }

    pub fn client_mark_connection_close_replayed(&mut self, now: Instant) {
        self.close_state.mark_replayed(now);
    }

    pub fn client_observe_inbound_packet_for_close(&mut self) -> u64 {
        self.close_state.observe_inbound_packet()
    }

    pub fn client_application_pto(&self) -> Duration {
        self.client_application_loss_detector.current_pto()
    }

    /// Current write-side key phase bit per RFC9001 § 6.
    pub fn write_key_phase(&self) -> bool {
        self.write_key_phase
    }

    /// Current read-side key phase bit per RFC9001 § 6.
    pub fn read_key_phase(&self) -> bool {
        self.read_key_phase
    }

    /// Whether a locally-initiated key update is currently waiting for an ACK
    /// of a packet sent at the new write phase per RFC9001 § 6.5.
    pub fn key_update_in_progress(&self) -> bool {
        self.application_key_update.write_update_in_progress
    }

    /// Force a 1-RTT key update. Returns an error when the previous local key
    /// update has not yet been confirmed via ACK (RFC9001 § 6.5).
    pub fn force_key_update(&mut self) -> Result<()> {
        if self.application_key_update.write_update_in_progress {
            return Err(Error::Quic(
                "RFC9001 § 6.5: cannot initiate a new key update while a previous one is unconfirmed"
                    .into(),
            ));
        }
        let next = self.client_application_next_keys.take().ok_or_else(|| {
            Error::Quic(
                "native QUIC client cannot force a key update before TLS application secrets are installed"
                    .into(),
            )
        })?;
        self.client_application_keys = Some(next);
        let new_current = self
            .client_application_keys
            .as_ref()
            .expect("client application keys just installed");
        self.client_application_next_keys = Some(derive_next_packet_key_material(new_current)?);
        self.write_key_phase = !self.write_key_phase;
        self.application_key_update.write_update_in_progress = true;
        self.application_key_update.write_update_anchor =
            Some(self.next_client_application_packet_number);
        Ok(())
    }

    fn commit_receive_key_update(&mut self, now: Instant) -> Result<()> {
        let Some(current) = self.server_application_keys.take() else {
            return Err(Error::Quic(
                "native QUIC client cannot rotate read keys without an installed current key set"
                    .into(),
            ));
        };
        let Some(next) = self.server_application_next_keys.take() else {
            return Err(Error::Quic(
                "native QUIC client cannot rotate read keys without precomputed next key set"
                    .into(),
            ));
        };
        let old_phase = self.read_key_phase;
        self.server_application_keys = Some(next);
        let new_current = self
            .server_application_keys
            .as_ref()
            .expect("server application keys just installed");
        self.server_application_next_keys = Some(derive_next_packet_key_material(new_current)?);
        self.server_application_previous = Some(PreviousKeys {
            keys: current,
            phase: old_phase,
            retire_at: now + PREVIOUS_KEY_WINDOW,
        });
        self.read_key_phase = !self.read_key_phase;

        if self.write_key_phase != self.read_key_phase
            && !self.application_key_update.write_update_in_progress
        {
            let next_write = self.client_application_next_keys.take().ok_or_else(|| {
                Error::Quic(
                    "native QUIC client cannot mirror peer key update without precomputed next write keys"
                        .into(),
                )
            })?;
            self.client_application_keys = Some(next_write);
            let new_current_write = self
                .client_application_keys
                .as_ref()
                .expect("client application keys just rotated");
            self.client_application_next_keys =
                Some(derive_next_packet_key_material(new_current_write)?);
            self.write_key_phase = !self.write_key_phase;
            self.application_key_update.write_update_in_progress = true;
            self.application_key_update.write_update_anchor =
                Some(self.next_client_application_packet_number);
        }

        Ok(())
    }

    pub fn client_path_validation_pending_count(&self) -> usize {
        self.client_path_validator.pending_count()
    }

    pub fn is_client_path_validated(&self, data: &[u8; 8]) -> bool {
        self.client_path_validator.is_validated(data)
    }

    pub fn is_client_path_address_validated(&self, remote_address: &SocketAddr) -> bool {
        self.client_path_validator
            .is_address_validated(remote_address)
    }

    pub fn client_path_migration_connection_id(
        &self,
        remote_address: &SocketAddr,
    ) -> Option<&ConnectionId> {
        self.client_path_validator
            .migration_connection_id(remote_address)
    }

    pub fn client_pmtu_current_size(&self) -> usize {
        self.client_pmtu_probe.current_size()
    }

    pub fn client_pmtu_pending_probe_size(&self) -> Option<usize> {
        self.client_pmtu_probe.pending_probe_size()
    }

    pub fn client_application_lost_packets(&self) -> Vec<u64> {
        self.client_application_loss_detector.lost_packets()
    }

    pub fn take_client_application_ecn_congestion(&mut self) -> bool {
        std::mem::take(&mut self.client_application_ecn_congestion)
    }

    /// Smoothed RTT observed on the application packet number space, as
    /// updated by RFC9002 § 5.3 from inbound ACK frames. Read-only consumer
    /// of the loss detector's RTT estimator.
    pub fn client_application_smoothed_rtt(&self) -> Option<Duration> {
        self.client_application_loss_detector.smoothed_rtt()
    }

    /// Minimum RTT observed on the application packet number space.
    /// Read-only consumer of the loss detector's RTT estimator.
    pub fn client_application_min_rtt(&self) -> Option<Duration> {
        self.client_application_loss_detector.min_rtt()
    }

    pub fn retransmit_lost_client_application_stream_packets(
        &mut self,
    ) -> Result<Vec<ClientApplicationPacket>> {
        let mut lost_packets = self.client_application_loss_detector.lost_packets();
        lost_packets.append(&mut self.client_application_recovery_lost_packets);
        self.retransmit_client_application_stream_packets(lost_packets)
    }

    pub fn retransmit_pto_client_application_stream_packets(
        &mut self,
        now: Instant,
        pto_timeout: Duration,
    ) -> Result<Vec<ClientApplicationPacket>> {
        let expired_packets = self
            .client_application_loss_detector
            .pto_expired_packets(now, pto_timeout);
        self.retransmit_client_application_stream_packets(expired_packets)
    }

    fn retransmit_client_application_stream_packets<I>(
        &mut self,
        packet_numbers: I,
    ) -> Result<Vec<ClientApplicationPacket>>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut packet_numbers = packet_numbers.into_iter().collect::<Vec<_>>();
        packet_numbers.sort_unstable();
        packet_numbers.dedup();
        let mut retransmits = Vec::new();
        for packet_number in packet_numbers {
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
            self.write_key_phase,
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

    /// Record that the initial client Initial datagram (or its Retry/VN
    /// rebuild) has been handed to the socket. RFC9002 § 6.1 OnPacketSent for
    /// the Initial packet number space: tracks the packet for loss/PTO
    /// detection and seeds `recovery` so the loss detection timer can arm.
    pub fn record_client_initial_sent_at(&mut self, sent_at: Instant) {
        let packet_number = self.next_client_initial_packet_number.saturating_sub(1);
        if self.client_initial_sent_crypto.contains_key(&packet_number) {
            return;
        }
        let packet_size = self.client_initial.packet.len();
        let crypto_data = self.client_initial.crypto_data.clone();
        self.client_initial_loss_detector
            .on_packet_sent_at(packet_number, sent_at);
        self.client_initial_sent_crypto.insert(
            packet_number,
            SentCryptoPacket {
                packet_type: LongHeaderType::Initial,
                crypto_offset: 0,
                crypto_data,
            },
        );
        self.recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            packet_number,
            SentPacketInfo::new(sent_at, packet_size, true, true),
        );
    }

    /// Retransmit Initial CRYPTO whose PTO has expired. RFC9002 § 6.2.4
    /// triggers a probe by resending the unacknowledged CRYPTO bytes with a
    /// fresh Initial packet number, preserving CRYPTO offsets so the peer
    /// reassembler accepts the duplicate.
    pub fn retransmit_pto_client_initial_crypto_packets(
        &mut self,
        now: Instant,
        pto: Duration,
    ) -> Result<Vec<ClientInitialPacket>> {
        let expired_packets = self
            .client_initial_loss_detector
            .pto_expired_packets(now, pto);
        let mut retransmits = Vec::new();
        for packet_number in expired_packets {
            self.client_initial_loss_detector
                .retire_packet(packet_number);
            let Some(sent) = self.client_initial_sent_crypto.remove(&packet_number) else {
                continue;
            };
            if sent.packet_type != LongHeaderType::Initial {
                continue;
            }
            retransmits.push(self.build_client_initial_crypto_pto_packet(sent.crypto_data, now)?);
        }
        Ok(retransmits)
    }

    fn build_client_initial_crypto_pto_packet(
        &mut self,
        crypto_data: Bytes,
        sent_at: Instant,
    ) -> Result<ClientInitialPacket> {
        let packet_number = self.next_client_initial_packet_number;
        let token = decode_long_header(&self.client_initial.header)?.token;
        let packet = build_client_initial_packet_with_token_and_version(
            &self.fingerprint,
            crypto_data.clone(),
            self.client_initial.transport_parameters.clone(),
            self.client_initial.secrets.clone(),
            self.destination_cid.clone(),
            self.source_cid.clone(),
            token,
            packet_number,
            self.client_initial_version,
        )?;
        let packet_size = packet.packet.len();
        self.next_client_initial_packet_number = packet_number + 1;
        self.client_initial_loss_detector
            .on_packet_sent_at(packet_number, sent_at);
        self.client_initial_sent_crypto.insert(
            packet_number,
            SentCryptoPacket {
                packet_type: LongHeaderType::Initial,
                crypto_offset: 0,
                crypto_data,
            },
        );
        self.recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            packet_number,
            SentPacketInfo::new(sent_at, packet_size, true, true),
        );
        Ok(packet)
    }

    /// Read-only access to the RFC9002 packet-space recovery state for tests
    /// and the H3 driver loss-detection timer wakeup.
    pub fn recovery(&self) -> &RecoveryState {
        &self.recovery
    }

    /// Driver hook: when the loss detection timer fires, call this to either
    /// declare time-threshold losses (RFC9002 § 6.1.2) or schedule a PTO probe
    /// in the earliest in-flight space.
    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> LossDetectionOutcome {
        self.recovery.on_loss_detection_timeout(now)
    }

    /// Convenience for the driver: where to schedule the next loss detection
    /// timer wakeup, if any.
    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.recovery.loss_detection_timer()
    }

    /// Current PTO duration (`smoothed_rtt + max(4*rttvar, kGranularity)`)
    /// applied to the Application space after handshake confirmation.
    pub fn application_pto(&self) -> Duration {
        self.recovery.current_pto()
    }

    /// Application packet-number-space PTO including peer max_ack_delay and
    /// current RFC9002 PTO backoff.
    pub fn application_pto_timeout(&self) -> Duration {
        let max_ack_delay = self.recovery.max_ack_delay();
        let backoff = 1u32 << self.recovery.pto_count().min(31);
        self.recovery
            .current_pto()
            .saturating_add(max_ack_delay.saturating_mul(backoff))
    }

    /// Marks Handshake confirmation so Application PTO includes `max_ack_delay`
    /// and the loss detection timer is rearmed. Idempotent.
    pub fn mark_handshake_confirmed(&mut self) {
        self.recovery.mark_handshake_complete();
    }

    /// Discards an entire packet-number space per RFC9002 § 6.4 (e.g. when
    /// Handshake keys install or HANDSHAKE_DONE is received). Resets
    /// `pto_count` and returns bytes_in_flight credit to the congestion
    /// controller.
    pub fn discard_packet_space(&mut self, space: PacketNumberSpace) {
        self.recovery.discard_space(space);
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

        let packet_size = packet.len();
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
        self.recovery.on_packet_sent(
            PacketNumberSpace::Handshake,
            packet_number,
            SentPacketInfo::new(sent_at, packet_size, true, true),
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

    pub fn build_client_h3_zero_rtt_request_packet(
        &mut self,
        method: &http::Method,
        uri: &http::Uri,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<ClientApplicationPacket> {
        let stream_id = self.next_client_bidirectional_stream_id;
        let h3_headers = native::build_request_headers(method, uri, headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, body, &self.fingerprint);

        let packet = self
            .build_client_zero_rtt_stream_packet(stream_id, payload, true)?
            .ok_or_else(|| {
                Error::HttpProtocol("native H3 0-RTT request produced no payload".into())
            })?;
        self.next_client_bidirectional_stream_id += 4;
        Ok(packet)
    }

    pub fn build_client_h3_replay_request_packet(
        &mut self,
        stream_id: u64,
        method: &http::Method,
        uri: &http::Uri,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<ClientApplicationPacket> {
        let h3_headers = native::build_request_headers(method, uri, headers)?;
        let payload =
            native::encode_request_stream_with_fingerprint(&h3_headers, body, &self.fingerprint);
        let payload_len = payload.len() as u64;
        let packet =
            self.build_client_application_stream_packet_at_offset(stream_id, 0, payload, true)?;
        self.client_stream_offsets.insert(stream_id, payload_len);
        Ok(packet)
    }

    fn build_client_zero_rtt_stream_packet(
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
        let Some(client_early_data_keys) = &self.client_early_data_keys else {
            return Err(Error::Quic(
                "native 0-RTT packet encryption is waiting for TLS early-data keys".into(),
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
        let header = encode_long_header(&LongHeaderPacket {
            packet_type: LongHeaderType::ZeroRtt,
            version: QUIC_VERSION_1,
            destination_cid: self.destination_cid.clone(),
            source_cid: self.source_cid.clone(),
            token: Bytes::new(),
            packet_number,
            packet_number_len,
            payload_len: frame.len() + AES_GCM_TAG_LEN,
        })?;
        let packet_number_offset = header
            .len()
            .checked_sub(packet_number_len)
            .ok_or_else(|| Error::HttpProtocol("invalid QUIC 0-RTT header length".into()))?;
        let packet = protect_long_header_packet(
            client_early_data_keys,
            packet_number,
            &header,
            packet_number_offset,
            packet_number_len,
            &frame,
        )?;

        let now = Instant::now();
        let packet_size = packet.len();
        self.client_application_loss_detector
            .on_packet_sent_at(packet_number, now);
        self.client_application_sent_streams.insert(
            packet_number,
            SentApplicationStreamPacket {
                stream_id,
                stream_offset,
                fin,
                data: data.clone(),
            },
        );
        self.recovery.on_packet_sent(
            PacketNumberSpace::Application,
            packet_number,
            SentPacketInfo::new(now, packet_size, true, true),
        );
        self.next_client_application_packet_number += 1;
        self.client_stream_offsets
            .insert(stream_id, stream_offset + data.len() as u64);

        Ok(Some(ClientApplicationPacket {
            packet,
            packet_number,
            stream_id,
            packet_number_offset,
            data,
        }))
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
            self.write_key_phase,
            &frame,
        )?;

        let now = Instant::now();
        let packet_size = packet.len();
        self.client_application_loss_detector
            .on_packet_sent_at(packet_number, now);
        self.client_application_sent_streams.insert(
            packet_number,
            SentApplicationStreamPacket {
                stream_id,
                stream_offset,
                fin,
                data: data.clone(),
            },
        );
        self.recovery.on_packet_sent(
            PacketNumberSpace::Application,
            packet_number,
            SentPacketInfo::new(now, packet_size, true, true),
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
        let payload = self.encode_client_h3_request_payload(method, uri, headers, body)?;

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
        let payload = self.encode_client_h3_request_payload(method, uri, headers, body)?;

        let packet = self
            .build_client_application_stream_packet(stream_id, payload, fin)?
            .ok_or_else(|| {
                Error::HttpProtocol("native H3 request start produced no payload".into())
            })?;
        self.next_client_bidirectional_stream_id += 4;
        Ok(packet)
    }

    pub fn retire_client_application_packet(&mut self, packet_number: u64) {
        self.client_application_loss_detector
            .retire_packet(packet_number);
        self.client_application_sent_streams.remove(&packet_number);
    }

    fn encode_client_h3_request_payload(
        &self,
        method: &http::Method,
        uri: &http::Uri,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<Bytes> {
        let h3_headers = native::build_request_headers(method, uri, headers)?;
        Ok(native::encode_request_stream_with_fingerprint(
            &h3_headers,
            body,
            &self.fingerprint,
        ))
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

    pub fn build_client_new_connection_id_packet(
        &mut self,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Result<ClientApplicationControlPacket> {
        if connection_id.as_bytes().is_empty() {
            return Err(Error::Quic(
                "native QUIC NEW_CONNECTION_ID cannot carry an empty connection id".into(),
            ));
        }
        if retire_prior_to > sequence_number {
            return Err(Error::Quic(
                "native QUIC NEW_CONNECTION_ID retire_prior_to exceeds sequence_number".into(),
            ));
        }
        self.client_cid_inventory.register_local_issued(
            sequence_number,
            connection_id.clone(),
            stateless_reset_token,
        )?;
        self.build_client_application_control_packet(QuicFrame::NewConnectionId {
            sequence_number,
            retire_prior_to,
            connection_id: Bytes::copy_from_slice(connection_id.as_bytes()),
            stateless_reset_token,
        })
    }

    pub fn build_client_path_challenge_packet(
        &mut self,
        data: [u8; 8],
    ) -> Result<ClientApplicationControlPacket> {
        let frame = self.client_path_validator.path_challenge(data);
        self.build_client_application_control_packet(frame)
    }

    pub fn build_client_path_challenge_packet_for_address(
        &mut self,
        remote_address: SocketAddr,
        connection_id_sequence: u64,
        data: [u8; 8],
    ) -> Result<ClientApplicationControlPacket> {
        let destination_cid = self
            .client_path_validator
            .connection_id(connection_id_sequence)
            .cloned()
            .ok_or_else(|| {
                Error::Quic("native QUIC path migration requires an available connection id".into())
            })?;
        let frame = self.client_path_validator.path_challenge_for_address(
            remote_address,
            connection_id_sequence,
            data,
        )?;
        self.build_client_application_control_packet_to(frame, &destination_cid)
    }

    pub fn build_client_pmtu_probe_packet(
        &mut self,
        now: Instant,
    ) -> Result<Option<ClientApplicationControlPacket>> {
        let Some(target_size) = self.client_pmtu_probe.next_probe_size() else {
            return Ok(None);
        };
        let packet = self.build_client_application_probe_packet(target_size, now)?;
        self.client_pmtu_probe
            .on_probe_sent(packet.packet_number, packet.packet.len(), now);
        Ok(Some(packet))
    }

    pub fn build_client_connection_close_packet(
        &mut self,
        error_code: u64,
        reason: Bytes,
    ) -> Result<ClientApplicationControlPacket> {
        let packet = self.build_client_application_control_packet(QuicFrame::ConnectionClose {
            error_code,
            frame_type: None,
            reason,
        })?;
        // RFC9000 § 10.2: emitting a CONNECTION_CLOSE transitions the
        // connection into the closing phase. We anchor the timer here so the
        // driver does not have to remember to call `client_enter_closing`
        // separately on every send path.
        self.client_enter_closing(Instant::now());
        Ok(packet)
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

    // Hook for the H3 driver to surface bytes the application has actually
    // drained from a streaming response body or RFC 9220 tunnel inbound
    // channel. Per RFC 9000 Section 4 these counters drive the absolute
    // MAX_DATA / MAX_STREAM_DATA values we are willing to advertise.
    pub fn record_client_stream_consumed(&mut self, stream_id: u64, len: u64) -> Result<()> {
        self.client_application_receive_flow_control
            .record_stream_consumed(stream_id, len)
    }

    pub fn release_client_stream(&mut self, stream_id: u64) {
        self.client_application_receive_flow_control
            .release_stream(stream_id);
    }

    fn build_client_application_control_packet(
        &mut self,
        frame: QuicFrame,
    ) -> Result<ClientApplicationControlPacket> {
        let destination_cid = self.destination_cid.clone();
        self.build_client_application_control_packet_to(frame, &destination_cid)
    }

    fn build_client_application_control_packet_to(
        &mut self,
        frame: QuicFrame,
        destination_cid: &ConnectionId,
    ) -> Result<ClientApplicationControlPacket> {
        self.build_client_application_payload_packet_at_to(
            padded_short_header_payload(encode_frame(&frame)),
            Instant::now(),
            destination_cid,
        )
    }

    fn build_client_application_probe_packet(
        &mut self,
        target_size: usize,
        now: Instant,
    ) -> Result<ClientApplicationControlPacket> {
        let Some(_client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        };
        let packet_number_len = 2;
        let header_len = 1 + self.destination_cid.as_bytes().len() + packet_number_len;
        let tag_len = AES_GCM_TAG_LEN;
        let target_payload_len = target_size.saturating_sub(header_len + tag_len);
        let mut payload = encode_frame(&QuicFrame::Ping).to_vec();
        payload.resize(target_payload_len.max(payload.len()), 0);
        self.build_client_application_payload_packet_at(Bytes::from(payload), now)
    }

    fn build_client_application_payload_packet_at(
        &mut self,
        payload: Bytes,
        now: Instant,
    ) -> Result<ClientApplicationControlPacket> {
        let destination_cid = self.destination_cid.clone();
        self.build_client_application_payload_packet_at_to(payload, now, &destination_cid)
    }

    fn build_client_application_payload_packet_at_to(
        &mut self,
        payload: Bytes,
        now: Instant,
        destination_cid: &ConnectionId,
    ) -> Result<ClientApplicationControlPacket> {
        let Some(client_application_keys) = &self.client_application_keys else {
            return Err(Error::Quic(
                "native application packet encryption is waiting for TLS application keys".into(),
            ));
        };

        let packet_number = self.next_client_application_packet_number;
        let packet_number_len = 2;
        let packet = protect_short_header_packet(
            client_application_keys,
            destination_cid,
            packet_number,
            packet_number_len,
            self.write_key_phase,
            &payload,
        )?;
        let packet_size = packet.len();
        self.client_application_loss_detector
            .on_packet_sent_at(packet_number, now);
        self.recovery.on_packet_sent(
            PacketNumberSpace::Application,
            packet_number,
            SentPacketInfo::new(now, packet_size, true, true),
        );
        self.next_client_application_packet_number += 1;

        Ok(ClientApplicationControlPacket {
            packet,
            packet_number,
            packet_number_offset: 1 + destination_cid.as_bytes().len(),
        })
    }

    pub fn open_server_application_packet(&mut self, packet: &[u8]) -> Result<Vec<QuicFrame>> {
        self.open_server_application_packet_with_ecn(packet, None)
    }

    pub fn open_server_application_packet_with_ecn(
        &mut self,
        packet: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<QuicFrame>> {
        self.open_server_application_packet_with_path(packet, None, ecn_mark)
    }

    fn open_server_application_packet_with_path(
        &mut self,
        packet: &[u8],
        remote_address: Option<SocketAddr>,
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<QuicFrame>> {
        // RFC9000 § 10.2: stop decrypting peer packets once we are draining;
        // closing-phase decryption is preserved so we can still apply the
        // § 10.2 MAY-optimisation (closing -> draining on peer CONNECTION_CLOSE).
        if self.close_state.is_draining() {
            return Ok(Vec::new());
        }
        let Some(server_application_keys) = self.server_application_keys.as_ref() else {
            return Err(Error::Quic(
                "native application packet decryption is waiting for TLS application keys".into(),
            ));
        };
        let now = Instant::now();
        let opened = try_open_one_rtt_packet(
            server_application_keys,
            self.server_application_next_keys.as_ref(),
            self.server_application_previous.as_ref(),
            self.read_key_phase,
            now,
            packet,
            self.source_cid.as_bytes().len(),
            self.next_server_application_packet_number,
        )?;
        if matches!(opened.outcome, OneRttOpenOutcome::Next) {
            self.commit_receive_key_update(now)?;
        }
        let opened = opened.opened;
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
                self.application_key_update.note_packet_acked(packet_number);
                self.client_pmtu_probe.on_probe_acked(packet_number);
            }
            if matches!(frame, QuicFrame::Ack { .. } | QuicFrame::AckEcn { .. }) {
                let outcome = self.recovery.on_ack_received(
                    PacketNumberSpace::Application,
                    frame,
                    self.fingerprint.transport.ack_delay_exponent,
                    now,
                )?;
                for (packet_number, _) in outcome.newly_acked {
                    self.client_application_sent_streams.remove(&packet_number);
                    self.application_key_update.note_packet_acked(packet_number);
                    self.client_pmtu_probe.on_probe_acked(packet_number);
                }
                for (packet_number, _) in &outcome.lost {
                    self.client_pmtu_probe.on_probe_lost(*packet_number);
                }
                self.client_application_recovery_lost_packets.extend(
                    outcome
                        .lost
                        .into_iter()
                        .map(|(packet_number, _)| packet_number),
                );
                if outcome.ecn_congestion {
                    self.client_application_ecn_congestion = true;
                }
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
                QuicFrame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                } => self.client_path_validator.register_connection_id(
                    *sequence_number,
                    *retire_prior_to,
                    ConnectionId::from_bytes(connection_id.clone())?,
                    *stateless_reset_token,
                )?,
                QuicFrame::PathResponse(data) => {
                    if let Some(remote_address) = remote_address {
                        if self
                            .client_path_validator
                            .on_path_response_from(remote_address, *data)
                        {
                            if let Some(connection_id) = self
                                .client_path_validator
                                .migration_connection_id(&remote_address)
                                .cloned()
                            {
                                self.destination_cid = connection_id;
                            }
                        }
                    } else {
                        self.client_path_validator.on_path_response(*data);
                    }
                }
                _ => {}
            }
        }
        if frames.iter().any(is_ack_eliciting_quic_frame) {
            observe_packet_with_ecn(
                &mut self.application_ack_tracker,
                opened.packet_number,
                ecn_mark,
                now,
            );
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
        self.open_server_h3_event_packet_with_ecn(packet, None)
    }

    pub fn open_server_h3_event_packet_from(
        &mut self,
        packet: &[u8],
        remote_address: SocketAddr,
    ) -> Result<Vec<ServerH3Event>> {
        self.open_server_h3_event_packet_with_path_ecn(packet, Some(remote_address), None)
    }

    pub fn open_server_h3_event_packet_from_with_ecn(
        &mut self,
        packet: &[u8],
        remote_address: SocketAddr,
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<ServerH3Event>> {
        self.open_server_h3_event_packet_with_path_ecn(packet, Some(remote_address), ecn_mark)
    }

    pub fn open_server_h3_event_packet_with_ecn(
        &mut self,
        packet: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<ServerH3Event>> {
        self.open_server_h3_event_packet_with_path_ecn(packet, None, ecn_mark)
    }

    fn open_server_h3_event_packet_with_path_ecn(
        &mut self,
        packet: &[u8],
        remote_address: Option<SocketAddr>,
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<Vec<ServerH3Event>> {
        // RFC9000 § 10.2: once we are draining we MUST drop inbound packets.
        // Closing-phase parsing remains active so the MAY optimisation in
        // § 10.2 ("transition from closing to draining if you can confirm
        // the peer is also closing") fires when the peer sends us a
        // CONNECTION_CLOSE in response to ours.
        if self.close_state.is_draining() {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for frame in
            self.open_server_application_packet_with_path(packet, remote_address, ecn_mark)?
        {
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
                    // RFC9000 § 10.2: peer CONNECTION_CLOSE transitions us
                    // into the draining phase. Drivers must stop sending
                    // packets and may emit at most one CONNECTION_CLOSE in
                    // response.
                    self.close_draining = true;
                    self.close_state.enter_draining(Instant::now());
                    events.push(ServerH3Event::ConnectionClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                }
                QuicFrame::PathChallenge(data) => events.push(ServerH3Event::PathChallenge(data)),
                QuicFrame::PathResponse(_) => {}
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
        self.process_server_datagram_with_ecn(datagram, None)
    }

    pub fn process_server_datagram_with_ecn(
        &mut self,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
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
                    self.server_initial_or_handshake_seen = true;
                    observe_packet_with_ecn(
                        &mut self.initial_ack_tracker,
                        opened.packet_number,
                        ecn_mark,
                        Instant::now(),
                    );
                    self.next_server_initial_packet_number = opened.packet_number + 1;

                    for frame in decode_frames(&opened.payload)? {
                        for packet_number in
                            self.client_initial_loss_detector.on_ack_frame(&frame)?
                        {
                            self.client_initial_sent_crypto.remove(&packet_number);
                        }
                        let outcome = self.recovery.on_ack_received(
                            PacketNumberSpace::Initial,
                            &frame,
                            self.fingerprint.transport.ack_delay_exponent,
                            Instant::now(),
                        )?;
                        for (packet_number, _) in outcome.newly_acked {
                            self.client_initial_sent_crypto.remove(&packet_number);
                        }
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
                    self.server_initial_or_handshake_seen = true;
                    observe_packet_with_ecn(
                        &mut self.handshake_ack_tracker,
                        opened.packet_number,
                        ecn_mark,
                        Instant::now(),
                    );
                    self.next_server_handshake_packet_number = opened.packet_number + 1;

                    for frame in decode_frames(&opened.payload)? {
                        for packet_number in
                            self.client_handshake_loss_detector.on_ack_frame(&frame)?
                        {
                            self.client_handshake_sent_crypto.remove(&packet_number);
                        }
                        let outcome = self.recovery.on_ack_received(
                            PacketNumberSpace::Handshake,
                            &frame,
                            self.fingerprint.transport.ack_delay_exponent,
                            Instant::now(),
                        )?;
                        for (packet_number, _) in outcome.newly_acked {
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
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<ProcessedServerInitial>> {
        let packet = decode_version_negotiation_packet(datagram)?;
        if packet.destination_cid != self.source_cid || packet.source_cid != self.destination_cid {
            return Ok(Vec::new());
        }
        if self.vn_received {
            return Ok(Vec::new());
        }
        if packet
            .supported_versions
            .contains(&self.client_initial_version)
        {
            return Ok(Vec::new());
        }

        let chosen_version = self
            .supported_versions
            .iter()
            .copied()
            .find(|version| packet.supported_versions.contains(version));
        let Some(chosen_version) = chosen_version else {
            return Err(Error::Quic(format!(
                "version_negotiation_failed: native H3 server did not offer QUIC version 1 or any other version we support (offered {:?})",
                packet.supported_versions,
            )));
        };

        self.restart_for_version_negotiation(chosen_version)?;
        Ok(Vec::new())
    }

    fn process_retry_packet(&mut self, retry_packet: &[u8]) -> Result<()> {
        if self.retry_received {
            return Ok(());
        }
        if self.server_initial_or_handshake_seen {
            return Ok(());
        }

        let retry =
            match validate_retry_integrity_tag_v1(&self.original_destination_cid, retry_packet) {
                Ok(retry) => retry,
                Err(_) => return Ok(()),
            };
        if retry.destination_cid != self.source_cid {
            return Ok(());
        }
        if retry.source_cid.as_bytes() == self.original_destination_cid.as_bytes() {
            return Ok(());
        }
        if retry.token.is_empty() {
            return Ok(());
        }

        let retry_keys = derive_initial_key_material(retry.source_cid.as_bytes())?;
        let packet_number = self.next_client_initial_packet_number;
        let retry_initial = build_client_initial_packet_with_token_and_version(
            &self.fingerprint,
            self.client_initial.crypto_data.clone(),
            self.client_initial.transport_parameters.clone(),
            self.client_initial.secrets.clone(),
            retry.source_cid.clone(),
            self.source_cid.clone(),
            retry.token,
            packet_number,
            self.client_initial_version,
        )?;

        self.destination_cid = retry.source_cid.clone();
        self.retry_source_cid = Some(retry.source_cid);
        self.retry_received = true;
        self.client_initial_keys = retry_keys.client;
        self.server_initial_keys = retry_keys.server;
        self.client_initial = retry_initial.clone();
        self.pending_client_initial = Some(retry_initial);
        self.next_client_initial_packet_number = packet_number + 1;
        self.client_initial_loss_detector = QuicLossDetector::default();
        self.client_initial_sent_crypto.clear();
        self.recovery = recovery_state_from_transport(&self.fingerprint.transport);
        Ok(())
    }

    fn restart_for_version_negotiation(&mut self, chosen_version: u32) -> Result<()> {
        let new_source_cid = random_connection_id(self.source_cid.as_bytes().len())?;
        let mut new_tls =
            NativeQuicTlsSession::client_with_initial_source_connection_id_and_verify_peer(
                &self.server_name,
                &self.fingerprint,
                &new_source_cid,
                self.tls_fingerprint.as_ref(),
                self.verify_peer,
                &self.root_certs,
                self.use_platform_roots,
            )?;
        let captured = new_tls.take_client_initial();
        let new_initial = build_client_initial_packet_from_capture_with_version_and_size(
            captured,
            self.destination_cid.clone(),
            new_source_cid.clone(),
            chosen_version,
            self.fingerprint.transport.initial_datagram_size,
        )?;
        let initial_keys = derive_initial_key_material(self.destination_cid.as_bytes())?;

        self.tls = new_tls;
        self.source_cid = new_source_cid;
        self.client_initial_version = chosen_version;
        self.vn_received = true;
        self.retry_received = false;
        self.retry_source_cid = None;
        self.server_initial_or_handshake_seen = false;
        self.server_transport_parameters_validated = false;
        self.close_draining = false;
        self.client_initial = new_initial.clone();
        self.pending_client_initial = Some(new_initial);
        self.client_initial_keys = initial_keys.client;
        self.server_initial_keys = initial_keys.server;
        self.client_handshake_keys = None;
        self.server_handshake_keys = None;
        self.client_application_keys = None;
        self.server_application_keys = None;
        self.initial_crypto = QuicCryptoAssembler::default();
        self.handshake_crypto = QuicCryptoAssembler::default();
        self.initial_ack_tracker = QuicAckTracker::default();
        self.handshake_ack_tracker = QuicAckTracker::default();
        self.application_ack_tracker = QuicAckTracker::default();
        self.client_initial_loss_detector = QuicLossDetector::default();
        self.client_handshake_loss_detector = QuicLossDetector::default();
        self.client_application_loss_detector = QuicLossDetector::default();
        self.client_application_flow_control =
            QuicApplicationFlowControl::client(&self.fingerprint.transport);
        self.client_application_receive_flow_control =
            QuicReceiveFlowControl::client(&self.fingerprint.transport);
        self.client_initial_sent_crypto.clear();
        self.client_handshake_sent_crypto.clear();
        self.client_application_sent_streams.clear();
        self.client_application_recovery_lost_packets.clear();
        self.client_path_validator = QuicPathValidator::default();
        self.client_cid_inventory =
            new_client_cid_inventory(&self.fingerprint, &self.source_cid);
        self.client_pmtu_probe = QuicPmtuProbePolicy::from_transport(&self.fingerprint.transport);
        self.recovery = recovery_state_from_transport(&self.fingerprint.transport);
        self.next_client_initial_packet_number = 1;
        self.next_server_initial_packet_number = 0;
        self.next_server_handshake_packet_number = 0;
        self.next_client_handshake_packet_number = 0;
        self.next_server_application_packet_number = 0;
        self.next_client_application_packet_number = 0;
        self.next_client_bidirectional_stream_id = 0;
        self.next_client_unidirectional_stream_id = 2;
        self.client_handshake_crypto_offset = 0;
        self.client_stream_offsets.clear();
        self.server_h3_stream_buffers.clear();
        self.server_h3_stream_buffer_offsets.clear();
        self.server_h3_stream_types.clear();
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

fn build_client_initial_packet_with_token_and_version(
    fingerprint: &Http3Fingerprint,
    crypto_data: Bytes,
    transport_parameters: Bytes,
    secrets: Vec<QuicTlsSecret>,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
    token: Bytes,
    packet_number: u64,
    version: u32,
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
        version,
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

fn random_connection_id(len: usize) -> Result<ConnectionId> {
    let mut bytes = vec![0u8; len];
    getrandom_fill(&mut bytes)
        .map_err(|err| Error::Quic(format!("native H3 connection id RNG failed: {err}")))?;
    ConnectionId::from_bytes(Bytes::from(bytes))
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

#[cfg(test)]
mod receive_flow_control_tests {
    use super::*;
    use crate::fingerprint::QuicTransportParams;

    // Build a `QuicTransportParams` that exposes small, easy-to-reason-about
    // initial limits so threshold/gating math is obvious. RFC 9000 Section 4
    // numbers the absolute MAX_DATA / MAX_STREAM_DATA value space; the
    // initial limits below are what the peer is presumed to know via the
    // transport parameter exchange (RFC 9000 Section 18.2).
    fn flow_control_params() -> QuicTransportParams {
        let mut params = QuicTransportParams::chrome();
        params.initial_max_data = 100;
        params.initial_max_stream_data_bidi_local = 40;
        params.initial_max_stream_data_bidi_remote = 40;
        params.initial_max_stream_data_uni = 40;
        params.max_connection_window = 100_000;
        params.max_stream_window = 100_000;
        params
    }

    fn client_flow_control() -> QuicReceiveFlowControl {
        QuicReceiveFlowControl::client(&flow_control_params())
    }

    // Stream 0 (client-bidi-local) consumes exactly N bytes; the absolute
    // MAX_STREAM_DATA we are willing to advertise is initial + N, never the
    // bytes seen on the wire, per RFC 9000 Section 4.1 ("a receiver
    // advertises a credit limit based on its progress on the application
    // protocol").
    #[test]
    fn record_stream_consumed_advertises_initial_plus_drained_per_stream() {
        let mut fc = client_flow_control();
        let stream_id = 0;

        fc.record_stream_consumed(stream_id, 5)
            .expect("first drain");
        // 5 bytes < threshold (40 / 2 = 20), so no frame yet.
        assert!(fc.take_update_frames().is_empty());

        fc.record_stream_consumed(stream_id, 20)
            .expect("threshold-crossing drain");
        // Total drained is 25 >= threshold; emit MAX_STREAM_DATA with the
        // absolute initial(40) + drained(25) = 65 value, not an arbitrary
        // receive-threshold ceiling.
        let frames = fc.take_update_frames();
        assert_eq!(
            frames,
            vec![QuicFrame::MaxStreamData {
                stream_id,
                max_stream_data: 65,
            }]
        );

        // A further small drain below the next threshold delta keeps the
        // queue empty so we do not flood the wire with one frame per byte.
        fc.record_stream_consumed(stream_id, 5)
            .expect("small drain");
        assert!(fc.take_update_frames().is_empty());

        // Cumulative drain (5 + 20 + 5 + 16 = 46) crosses the next
        // half-window delta relative to the previously announced 65, so the
        // emitted frame is the exact absolute initial(40) + drained(46) = 86,
        // not rounded up to a static receive-threshold ceiling.
        fc.record_stream_consumed(stream_id, 16)
            .expect("next threshold");
        let frames = fc.take_update_frames();
        assert_eq!(
            frames,
            vec![QuicFrame::MaxStreamData {
                stream_id,
                max_stream_data: 86,
            }]
        );
    }

    // RFC 9000 Section 4.2: the connection-level MAX_DATA value is the
    // initial connection window plus the sum of bytes consumed across all
    // streams, with no double-counting between per-stream and connection
    // counters.
    #[test]
    fn record_stream_consumed_aggregates_connection_level_across_streams() {
        let mut fc = client_flow_control();
        // Two distinct client-bidi-local streams.
        let stream_a = 0;
        let stream_b = 4;

        // 30 bytes on each stream: total 60 consumed. Connection threshold
        // is 100 / 2 = 50, so MAX_DATA fires; each stream is above its 20
        // stream-level threshold, so per-stream MAX_STREAM_DATA fires too.
        fc.record_stream_consumed(stream_a, 30).expect("a drains");
        fc.record_stream_consumed(stream_b, 30).expect("b drains");
        let mut frames = fc.take_update_frames();
        frames.sort_by_key(|frame| match frame {
            QuicFrame::MaxData(_) => 0u8,
            QuicFrame::MaxStreamData { stream_id, .. } => 1 + (*stream_id as u8 % 8),
            _ => 255,
        });

        // initial_max_data(100) + connection_consumed(60) = 160 absolute.
        assert!(frames.contains(&QuicFrame::MaxData(160)));
        // Per-stream absolute = initial(40) + per-stream drained(30) = 70.
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: stream_a,
            max_stream_data: 70,
        }));
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: stream_b,
            max_stream_data: 70,
        }));
    }

    // RFC 9000 Section 19.9/19.10 forbid emitting frames for every byte
    // drained; we gate emission on a half-initial-window delta but the
    // absolute value still comes from the consumed counter.
    #[test]
    fn threshold_gates_emit_but_does_not_round_absolute_value() {
        let mut fc = client_flow_control();
        let stream_id = 0;

        // Many tiny drains adding up to just below the half-window
        // threshold do not produce a frame.
        for _ in 0..19 {
            fc.record_stream_consumed(stream_id, 1).expect("tiny drain");
            assert!(fc.take_update_frames().is_empty());
        }

        // The very next byte crosses the 20-byte half-initial-window
        // threshold and emits exactly initial(40) + drained(20) = 60.
        fc.record_stream_consumed(stream_id, 1)
            .expect("crossing drain");
        let frames = fc.take_update_frames();
        assert_eq!(
            frames,
            vec![QuicFrame::MaxStreamData {
                stream_id,
                max_stream_data: 60,
            }]
        );
    }

    // Stream completion must release per-stream bookkeeping cleanly. The
    // connection-level counter is monotonic across stream lifetimes
    // (RFC 9000 Section 4.1) so completed streams must not be double-counted
    // into the next stream's absolute value.
    #[test]
    fn release_stream_drops_per_stream_state_without_double_counting_connection() {
        let mut fc = client_flow_control();
        let stream_a = 0;
        let stream_b = 4;

        fc.record_stream_consumed(stream_a, 40)
            .expect("a fully drains");
        let _ = fc.take_update_frames();
        // Stream A retires.
        fc.release_stream(stream_a);
        assert!(
            !fc.stream_consumed.contains_key(&stream_a),
            "release_stream must clear per-stream consumed bookkeeping"
        );
        assert!(
            !fc.last_announced_max_stream_data.contains_key(&stream_a),
            "release_stream must clear per-stream announced bookkeeping"
        );

        // Stream B drains fresh; the connection counter still reflects
        // 40 (from A) + 30 (from B) = 70, not 30 alone, and not 110.
        fc.record_stream_consumed(stream_b, 30)
            .expect("b drains after a retired");
        let frames = fc.take_update_frames();
        // 70 >= connection threshold (50): emit MAX_DATA with absolute
        // initial(100) + connection_consumed(70) = 170.
        assert!(frames.contains(&QuicFrame::MaxData(170)));
        // Per-stream B is still ahead of its threshold and emits
        // initial(40) + per-stream(30) = 70.
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: stream_b,
            max_stream_data: 70,
        }));
    }

    // RFC 9000 Section 4.1: violations of an advertised limit MUST cause a
    // FLOW_CONTROL_ERROR. The receive-side enforcement still uses the
    // advertised window, which now grows from the consumed counter; once we
    // advertise more, the peer is allowed to send up to that new limit.
    #[test]
    fn observe_stream_frame_uses_advertised_limit_after_consume_grows_window() {
        let mut fc = client_flow_control();
        let stream_id = 0;

        // Without any consumption, the initial 40-byte stream window is
        // enforced.
        let too_much = fc.observe_stream_frame(stream_id, Some(0), 41);
        assert!(too_much.is_err(), "must reject data above initial limit");

        // Drain 40 bytes to push absolute to 80; emit and clear frames.
        fc.observe_stream_frame(stream_id, Some(0), 40)
            .expect("fill initial window");
        fc.record_stream_consumed(stream_id, 40)
            .expect("drain initial window");
        let _ = fc.take_update_frames();

        // 41 more bytes (offsets 40..81) now fit under the new 80 absolute.
        fc.observe_stream_frame(stream_id, Some(40), 40)
            .expect("data within newly advertised window");
    }
}
