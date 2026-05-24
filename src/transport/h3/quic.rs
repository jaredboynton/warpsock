//! Native QUIC packet primitives for Specter's HTTP/3 transport.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use boring::hash::hmac_sha256;
use boring::symm::{decrypt_aead, encrypt_aead, Cipher, Crypter, Mode};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::fingerprint::QuicTransportParams;

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const INITIAL_SECRET_LEN: usize = 32;
const AES_128_GCM_KEY_LEN: usize = 16;
const AES_128_GCM_IV_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;
const RETRY_INTEGRITY_TAG_LEN: usize = 16;
const RETRY_INTEGRITY_KEY_V1: [u8; AES_128_GCM_KEY_LEN] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; AES_128_GCM_IV_LEN] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const HEADER_PROTECTION_SAMPLE_LEN: usize = 16;
const HEADER_PROTECTION_MASK_LEN: usize = 5;
const MAX_PACKET_NUMBER: u64 = (1u64 << 62) - 1;
const HEADER_FORM_LONG: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const PACKET_NUMBER_LEN_MASK: u8 = 0x03;
const SHORT_KEY_PHASE_BIT: u8 = 0x04;
const MAX_CID_LEN: usize = 20;

const TP_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x0;
const TP_MAX_IDLE_TIMEOUT: u64 = 0x1;
const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x3;
const TP_INITIAL_MAX_DATA: u64 = 0x4;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x5;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x6;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x7;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x8;
const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x9;
const TP_ACK_DELAY_EXPONENT: u64 = 0xa;
const TP_MAX_ACK_DELAY: u64 = 0xb;
const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0xc;
const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0xe;
const TP_INITIAL_SOURCE_CONNECTION_ID: u64 = 0xf;
const TP_RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
const TP_GREASE_RESERVED: u64 = 27;
const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_RESET_STREAM: u64 = 0x04;
const FRAME_STOP_SENDING: u64 = 0x05;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_STREAM_BASE: u8 = 0x08;
const FRAME_STREAM_MAX: u64 = 0x0f;
const FRAME_STREAM_OFF: u8 = 0x04;
const FRAME_STREAM_LEN: u8 = 0x02;
const FRAME_STREAM_FIN: u8 = 0x01;
const FRAME_MAX_DATA: u64 = 0x10;
const FRAME_MAX_STREAM_DATA: u64 = 0x11;
const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
const FRAME_DATA_BLOCKED: u64 = 0x14;
const FRAME_STREAM_DATA_BLOCKED: u64 = 0x15;
const FRAME_STREAMS_BLOCKED_BIDI: u64 = 0x16;
const FRAME_STREAMS_BLOCKED_UNI: u64 = 0x17;
const FRAME_NEW_CONNECTION_ID: u64 = 0x18;
const FRAME_RETIRE_CONNECTION_ID: u64 = 0x19;
const FRAME_PATH_CHALLENGE: u64 = 0x1a;
const FRAME_PATH_RESPONSE: u64 = 0x1b;
const FRAME_CONNECTION_CLOSE_TRANSPORT: u64 = 0x1c;
const FRAME_CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
const FRAME_HANDSHAKE_DONE: u64 = 0x1e;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(Bytes);

impl ConnectionId {
    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self(Bytes::from_static(bytes))
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        if bytes.len() > MAX_CID_LEN {
            return Err(Error::HttpProtocol(
                "QUIC connection id length exceeds 20 bytes".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LongHeaderType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeaderPacket {
    pub packet_type: LongHeaderType,
    pub version: u32,
    pub destination_cid: ConnectionId,
    pub source_cid: ConnectionId,
    pub token: Bytes,
    pub packet_number: u64,
    pub packet_number_len: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeaderDatagramPacket {
    pub packet_type: LongHeaderType,
    pub version: u32,
    pub destination_cid: ConnectionId,
    pub source_cid: ConnectionId,
    pub token: Bytes,
    pub declared_remaining_len: usize,
    pub packet_number_offset: usize,
    pub packet: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNegotiationPacket {
    pub destination_cid: ConnectionId,
    pub source_cid: ConnectionId,
    pub supported_versions: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPacket {
    pub version: u32,
    pub destination_cid: ConnectionId,
    pub source_cid: ConnectionId,
    pub token: Bytes,
    pub integrity_tag: [u8; RETRY_INTEGRITY_TAG_LEN],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicPathValidator {
    pending: BTreeSet<[u8; 8]>,
    validated: BTreeSet<[u8; 8]>,
}

impl QuicPathValidator {
    pub fn path_challenge(&mut self, data: [u8; 8]) -> QuicFrame {
        self.pending.insert(data);
        QuicFrame::PathChallenge(data)
    }

    pub fn on_path_response(&mut self, data: [u8; 8]) -> bool {
        if !self.pending.remove(&data) {
            return false;
        }
        self.validated.insert(data);
        true
    }

    pub fn is_validated(&self, data: &[u8; 8]) -> bool {
        self.validated.contains(data)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeaderPacket {
    pub destination_cid: ConnectionId,
    pub packet_number: u64,
    pub packet_number_len: usize,
    pub key_phase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedShortHeaderPacket {
    pub packet_number: u64,
    pub destination_cid: ConnectionId,
    pub header: Bytes,
    pub payload: Bytes,
    pub key_phase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportParameter {
    OriginalDestinationConnectionId(Bytes),
    MaxIdleTimeout(u64),
    MaxUdpPayloadSize(u64),
    InitialMaxData(u64),
    InitialMaxStreamDataBidiLocal(u64),
    InitialMaxStreamDataBidiRemote(u64),
    InitialMaxStreamDataUni(u64),
    InitialMaxStreamsBidi(u64),
    InitialMaxStreamsUni(u64),
    AckDelayExponent(u64),
    MaxAckDelay(u64),
    DisableActiveMigration,
    ActiveConnectionIdLimit(u64),
    InitialSourceConnectionId(Bytes),
    RetrySourceConnectionId(Bytes),
    MaxDatagramFrameSize(u64),
    Additional(u64, Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicAckRange {
    pub gap: u64,
    pub ack_range_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrame {
    Padding,
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ranges: Vec<QuicAckRange>,
    },
    AckEcn {
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ranges: Vec<QuicAckRange>,
        ect0_count: u64,
        ect1_count: u64,
        ce_count: u64,
    },
    Crypto {
        offset: u64,
        data: Bytes,
    },
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
    Stream {
        stream_id: u64,
        offset: Option<u64>,
        fin: bool,
        data: Bytes,
    },
    MaxData(u64),
    MaxStreamData {
        stream_id: u64,
        max_stream_data: u64,
    },
    MaxStreams {
        bidirectional: bool,
        max_streams: u64,
    },
    DataBlocked {
        maximum_data: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    StreamsBlocked {
        bidirectional: bool,
        maximum_streams: u64,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Bytes,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    HandshakeDone,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicCryptoAssembler {
    next_offset: u64,
    segments: BTreeMap<u64, Bytes>,
}

impl QuicCryptoAssembler {
    pub fn insert(&mut self, offset: u64, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let data_end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::HttpProtocol("QUIC CRYPTO range overflow".into()))?;
        if data_end <= self.next_offset {
            return Ok(());
        }

        let (mut merged_start, mut merged_data) = if offset < self.next_offset {
            let trim = usize::try_from(self.next_offset - offset)
                .map_err(|_| Error::HttpProtocol("QUIC CRYPTO trim offset exceeds usize".into()))?;
            (self.next_offset, data.slice(trim..))
        } else {
            (offset, data)
        };
        let mut merged_end = merged_start
            .checked_add(merged_data.len() as u64)
            .ok_or_else(|| Error::HttpProtocol("QUIC CRYPTO range overflow".into()))?;

        let overlapping_starts = self
            .segments
            .iter()
            .filter_map(|(segment_start, segment_data)| {
                let segment_end = segment_start.checked_add(segment_data.len() as u64)?;
                if segment_end >= merged_start && *segment_start <= merged_end {
                    Some(*segment_start)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for segment_start in overlapping_starts {
            let Some(segment_data) = self.segments.remove(&segment_start) else {
                continue;
            };
            merge_crypto_segment(
                &mut merged_start,
                &mut merged_end,
                &mut merged_data,
                segment_start,
                segment_data,
            )?;
        }

        self.segments.insert(merged_start, merged_data);
        Ok(())
    }

    pub fn take_contiguous(&mut self) -> Bytes {
        let mut out = BytesMut::new();
        while let Some(segment) = self.segments.remove(&self.next_offset) {
            self.next_offset += segment.len() as u64;
            out.extend_from_slice(&segment);
        }
        out.freeze()
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicAckTracker {
    received: BTreeSet<u64>,
    received_at: BTreeMap<u64, Instant>,
    pending_ack: bool,
    pending_ack_count: usize,
    first_pending_ack_at: Option<Instant>,
}

impl QuicAckTracker {
    pub fn observe(&mut self, packet_number: u64) {
        self.observe_at(packet_number, Instant::now());
    }

    pub fn observe_at(&mut self, packet_number: u64, now: Instant) {
        if packet_number <= MAX_PACKET_NUMBER && self.received.insert(packet_number) {
            self.received_at.insert(packet_number, now);
            if !self.pending_ack {
                self.first_pending_ack_at = Some(now);
            }
            self.pending_ack = true;
            self.pending_ack_count = self.pending_ack_count.saturating_add(1);
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.pending_ack
    }

    pub fn should_ack_after(&self, threshold: usize) -> bool {
        self.pending_ack && self.pending_ack_count >= threshold.max(1)
    }

    pub fn should_ack_after_or_delay(
        &self,
        threshold: usize,
        max_ack_delay: Duration,
        now: Instant,
    ) -> bool {
        self.should_ack_after(threshold)
            || self
                .pending_ack_elapsed(now)
                .is_some_and(|elapsed| elapsed >= max_ack_delay)
    }

    pub fn pending_ack_deadline(&self, max_ack_delay: Duration) -> Option<Instant> {
        self.pending_ack
            .then(|| self.first_pending_ack_at.map(|first| first + max_ack_delay))
            .flatten()
    }

    pub fn mark_ack_sent(&mut self) {
        self.pending_ack = false;
        self.pending_ack_count = 0;
        self.first_pending_ack_at = None;
    }

    pub fn to_ack_frame(&self, ack_delay: u64) -> Result<QuicFrame> {
        let Some(&largest_acknowledged) = self.received.iter().next_back() else {
            return Err(Error::HttpProtocol(
                "cannot build QUIC ACK frame without received packets".into(),
            ));
        };

        let ranges = self.ack_ranges_descending();
        let first = ranges
            .first()
            .ok_or_else(|| Error::HttpProtocol("missing QUIC ACK range".into()))?;
        let first_ack_range = first.start - first.end;
        let mut additional_ranges = Vec::new();
        let mut previous_end = first.end;
        for range in ranges.iter().skip(1) {
            additional_ranges.push(QuicAckRange {
                gap: previous_end - range.start - 2,
                ack_range_length: range.start - range.end,
            });
            previous_end = range.end;
        }

        Ok(QuicFrame::Ack {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ranges: additional_ranges,
        })
    }

    pub fn to_ack_frame_with_delay(
        &self,
        now: Instant,
        ack_delay_exponent: u64,
    ) -> Result<QuicFrame> {
        let Some(&largest_acknowledged) = self.received.iter().next_back() else {
            return Err(Error::HttpProtocol(
                "cannot build QUIC ACK frame without received packets".into(),
            ));
        };
        let delay = self
            .received_at
            .get(&largest_acknowledged)
            .map(|received_at| {
                encode_ack_delay(
                    now.saturating_duration_since(*received_at),
                    ack_delay_exponent,
                )
            })
            .unwrap_or(0);
        self.to_ack_frame(delay)
    }

    fn ack_ranges_descending(&self) -> Vec<AckRange> {
        let mut ranges = Vec::new();
        let mut current: Option<AckRange> = None;

        for &packet_number in self.received.iter().rev() {
            match &mut current {
                Some(range) if range.end == packet_number + 1 => {
                    range.end = packet_number;
                }
                Some(range) => {
                    ranges.push(*range);
                    current = Some(AckRange {
                        start: packet_number,
                        end: packet_number,
                    });
                }
                None => {
                    current = Some(AckRange {
                        start: packet_number,
                        end: packet_number,
                    });
                }
            }
        }

        if let Some(range) = current {
            ranges.push(range);
        }

        ranges
    }

    fn pending_ack_elapsed(&self, now: Instant) -> Option<Duration> {
        self.pending_ack
            .then(|| {
                self.first_pending_ack_at
                    .map(|first| now.saturating_duration_since(first))
            })
            .flatten()
    }
}

fn encode_ack_delay(delay: Duration, ack_delay_exponent: u64) -> u64 {
    let micros = delay.as_micros();
    let scaled = if ack_delay_exponent >= u128::BITS as u64 {
        0
    } else {
        micros >> ack_delay_exponent
    };
    scaled.min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AckRange {
    start: u64,
    end: u64,
}

/// RFC9002 § 5.3 initial smoothed RTT used when no samples have been taken yet.
pub const INITIAL_RTT: Duration = Duration::from_millis(333);
/// RFC9002 § 6.1.2 loss detection timer granularity floor.
pub const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicLossDetector {
    sent: BTreeSet<u64>,
    sent_at: BTreeMap<u64, Instant>,
    acked: BTreeSet<u64>,
    packet_threshold: u64,
    ecn_counts: Option<EcnCounters>,
    ecn_validation_failed: bool,
    ecn_ce_marked_packets: u64,
    largest_sent: Option<u64>,
    largest_acked: Option<u64>,
    /// RFC9002 § 5.1 latest_rtt observed for the most recent acknowledgement
    /// that newly acknowledged the largest packet number.
    latest_rtt: Option<Duration>,
    /// RFC9002 § 5.2 smoothed_rtt, updated using the standard 7/8 + 1/8 EWMA.
    smoothed_rtt: Option<Duration>,
    /// RFC9002 § 5.3 rttvar, the variation in the RTT samples.
    rttvar: Duration,
    /// RFC9002 § 5.2 min_rtt, the smallest RTT sample observed.
    min_rtt: Option<Duration>,
    /// RFC9002 § 6.2.1: peer's ack_delay_exponent for decoding ACK ack_delay
    /// fields prior to subtraction from latest_rtt.
    peer_ack_delay_exponent: u64,
    /// RFC9002 § 6.2.1 max_ack_delay used when computing the PTO duration.
    max_ack_delay: Duration,
}

impl Default for QuicLossDetector {
    fn default() -> Self {
        Self {
            sent: BTreeSet::new(),
            sent_at: BTreeMap::new(),
            acked: BTreeSet::new(),
            packet_threshold: 3,
            ecn_counts: None,
            ecn_validation_failed: false,
            ecn_ce_marked_packets: 0,
            largest_sent: None,
            largest_acked: None,
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: Duration::ZERO,
            min_rtt: None,
            peer_ack_delay_exponent: 0,
            max_ack_delay: Duration::from_millis(25),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct EcnCounters {
    ect0: u64,
    ect1: u64,
    ce: u64,
}

impl EcnCounters {
    fn total(self) -> Result<u64> {
        self.ect0
            .checked_add(self.ect1)
            .and_then(|total| total.checked_add(self.ce))
            .ok_or_else(|| Error::HttpProtocol("QUIC ACK_ECN counter overflow".into()))
    }
}

impl QuicLossDetector {
    pub fn with_packet_threshold(mut self, threshold: u64) -> Self {
        self.packet_threshold = threshold.max(1);
        self
    }

    pub fn on_packet_sent(&mut self, packet_number: u64) {
        self.on_packet_sent_at(packet_number, Instant::now());
    }

    pub fn on_packet_sent_at(&mut self, packet_number: u64, sent_at: Instant) {
        if packet_number <= MAX_PACKET_NUMBER {
            self.sent.insert(packet_number);
            self.sent_at.insert(packet_number, sent_at);
        }
    }

    pub fn on_ack_received(&mut self, packet_number: u64) {
        if self.sent.contains(&packet_number) {
            self.acked.insert(packet_number);
            self.sent_at.remove(&packet_number);
        }
    }

    pub fn on_ack_frame(&mut self, frame: &QuicFrame) -> Result<Vec<u64>> {
        let (largest_acknowledged, first_ack_range, ranges, ecn_counts) = match frame {
            QuicFrame::Ack {
                largest_acknowledged,
                first_ack_range,
                ranges,
                ..
            } => (*largest_acknowledged, *first_ack_range, ranges, None),
            QuicFrame::AckEcn {
                largest_acknowledged,
                first_ack_range,
                ranges,
                ect0_count,
                ect1_count,
                ce_count,
                ..
            } => (
                *largest_acknowledged,
                *first_ack_range,
                ranges,
                Some(EcnCounters {
                    ect0: *ect0_count,
                    ect1: *ect1_count,
                    ce: *ce_count,
                }),
            ),
            _ => return Ok(Vec::new()),
        };

        let mut decoded_ranges = Vec::new();
        let mut acked_packets = Vec::new();
        let mut smallest_acked = self.collect_ack_range(
            largest_acknowledged,
            first_ack_range,
            &mut acked_packets,
            &mut decoded_ranges,
        )?;
        for range in ranges {
            let gap = range
                .gap
                .checked_add(2)
                .ok_or_else(|| Error::HttpProtocol("QUIC ACK gap overflow".into()))?;
            let largest_in_range = smallest_acked.checked_sub(gap).ok_or_else(|| {
                Error::HttpProtocol("QUIC ACK range underflowed packet number space".into())
            })?;
            smallest_acked = self.collect_ack_range(
                largest_in_range,
                range.ack_range_length,
                &mut acked_packets,
                &mut decoded_ranges,
            )?;
        }

        if let Some(ecn_counts) = ecn_counts {
            let newly_acked = acked_packets
                .iter()
                .filter(|packet_number| !self.acked.contains(packet_number))
                .count() as u64;
            self.validate_ack_ecn_counts(ecn_counts, newly_acked)?;
        }

        for (largest_acknowledged, ack_range_length) in decoded_ranges {
            self.on_ack_range(largest_acknowledged, ack_range_length)?;
        }

        Ok(acked_packets)
    }

    pub fn retire_packet(&mut self, packet_number: u64) {
        self.sent.remove(&packet_number);
        self.sent_at.remove(&packet_number);
    }

    pub fn lost_packets(&self) -> Vec<u64> {
        let Some(&largest_acked) = self.acked.iter().next_back() else {
            return Vec::new();
        };
        let Some(loss_cutoff) = largest_acked.checked_sub(self.packet_threshold) else {
            return Vec::new();
        };

        self.sent
            .iter()
            .copied()
            .filter(|packet_number| {
                *packet_number <= loss_cutoff && !self.acked.contains(packet_number)
            })
            .collect()
    }

    pub fn pto_expired_packets(&self, now: Instant, pto: Duration) -> Vec<u64> {
        self.sent
            .iter()
            .copied()
            .filter(|packet_number| !self.acked.contains(packet_number))
            .filter(|packet_number| {
                self.sent_at
                    .get(packet_number)
                    .is_some_and(|sent_at| now.saturating_duration_since(*sent_at) >= pto)
            })
            .collect()
    }

    pub fn ecn_validation_failed(&self) -> bool {
        self.ecn_validation_failed
    }

    pub fn ecn_ce_marked_packets(&self) -> u64 {
        self.ecn_ce_marked_packets
    }

    fn collect_ack_range(
        &self,
        largest_acknowledged: u64,
        ack_range_length: u64,
        acked_packets: &mut Vec<u64>,
        decoded_ranges: &mut Vec<(u64, u64)>,
    ) -> Result<u64> {
        let smallest_acknowledged = largest_acknowledged
            .checked_sub(ack_range_length)
            .ok_or_else(|| {
                Error::HttpProtocol("QUIC ACK range exceeded largest packet number".into())
            })?;
        for packet_number in smallest_acknowledged..=largest_acknowledged {
            if self.sent.contains(&packet_number) {
                acked_packets.push(packet_number);
            }
        }
        decoded_ranges.push((largest_acknowledged, ack_range_length));
        Ok(smallest_acknowledged)
    }

    fn on_ack_range(&mut self, largest_acknowledged: u64, ack_range_length: u64) -> Result<()> {
        let smallest_acknowledged = largest_acknowledged
            .checked_sub(ack_range_length)
            .ok_or_else(|| {
                Error::HttpProtocol("QUIC ACK range exceeded largest packet number".into())
            })?;
        for packet_number in smallest_acknowledged..=largest_acknowledged {
            self.on_ack_received(packet_number);
        }
        Ok(())
    }

    fn validate_ack_ecn_counts(
        &mut self,
        counters: EcnCounters,
        newly_acked_packets: u64,
    ) -> Result<()> {
        let previous = self.ecn_counts.unwrap_or_default();
        if counters.ect0 < previous.ect0
            || counters.ect1 < previous.ect1
            || counters.ce < previous.ce
        {
            self.ecn_validation_failed = true;
            return Err(Error::Quic("QUIC ACK_ECN counters decreased".into()));
        }

        let count_increase = counters
            .total()?
            .checked_sub(previous.total()?)
            .ok_or_else(|| Error::HttpProtocol("QUIC ACK_ECN counter total underflow".into()))?;
        if count_increase > newly_acked_packets {
            self.ecn_validation_failed = true;
            return Err(Error::Quic(format!(
                "QUIC ACK_ECN count increase {count_increase} exceeds newly acknowledged packet count {newly_acked_packets}"
            )));
        }

        self.ecn_counts = Some(counters);
        self.ecn_ce_marked_packets = counters.ce;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialKeyMaterial {
    pub initial_secret: Bytes,
    pub client: QuicPacketKeyMaterial,
    pub server: QuicPacketKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicPacketKeyMaterial {
    pub secret: Bytes,
    pub packet_key: Bytes,
    pub iv: Bytes,
    pub header_protection_key: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedInitialPacket {
    pub packet_number: u64,
    pub header: Bytes,
    pub payload: Bytes,
}

pub fn derive_initial_key_material(
    client_destination_cid: &[u8],
) -> Result<QuicInitialKeyMaterial> {
    if client_destination_cid.len() > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }

    let initial_secret = hkdf_extract_sha256(&INITIAL_SALT_V1, client_destination_cid)?;
    let client_secret =
        hkdf_expand_label_sha256(&initial_secret, b"client in", INITIAL_SECRET_LEN)?;
    let server_secret =
        hkdf_expand_label_sha256(&initial_secret, b"server in", INITIAL_SECRET_LEN)?;

    Ok(QuicInitialKeyMaterial {
        initial_secret,
        client: derive_packet_key_material_from_secret(client_secret)?,
        server: derive_packet_key_material_from_secret(server_secret)?,
    })
}

pub fn derive_packet_key_material_from_secret(secret: Bytes) -> Result<QuicPacketKeyMaterial> {
    Ok(QuicPacketKeyMaterial {
        packet_key: hkdf_expand_label_sha256(&secret, b"quic key", AES_128_GCM_KEY_LEN)?,
        iv: hkdf_expand_label_sha256(&secret, b"quic iv", AES_128_GCM_IV_LEN)?,
        header_protection_key: hkdf_expand_label_sha256(&secret, b"quic hp", AES_128_GCM_KEY_LEN)?,
        secret,
    })
}

pub fn seal_packet_payload(
    keys: &QuicPacketKeyMaterial,
    packet_number: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Bytes> {
    let nonce = packet_nonce(&keys.iv, packet_number)?;
    let mut tag = [0u8; AES_GCM_TAG_LEN];
    let mut ciphertext = encrypt_aead(
        Cipher::aes_128_gcm(),
        &keys.packet_key,
        Some(&nonce),
        aad,
        plaintext,
        &mut tag,
    )
    .map_err(|err| Error::Quic(format!("QUIC packet seal failed: {err}")))?;
    ciphertext.extend_from_slice(&tag);
    Ok(Bytes::from(ciphertext))
}

pub fn open_packet_payload(
    keys: &QuicPacketKeyMaterial,
    packet_number: u64,
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Bytes> {
    if ciphertext_and_tag.len() < AES_GCM_TAG_LEN {
        return Err(Error::HttpProtocol("truncated QUIC packet tag".into()));
    }

    let nonce = packet_nonce(&keys.iv, packet_number)?;
    let tag_offset = ciphertext_and_tag.len() - AES_GCM_TAG_LEN;
    let plaintext = decrypt_aead(
        Cipher::aes_128_gcm(),
        &keys.packet_key,
        Some(&nonce),
        aad,
        &ciphertext_and_tag[..tag_offset],
        &ciphertext_and_tag[tag_offset..],
    )
    .map_err(|err| Error::Quic(format!("QUIC packet open failed: {err}")))?;
    Ok(Bytes::from(plaintext))
}

pub fn header_protection_mask(
    keys: &QuicPacketKeyMaterial,
    sample: &[u8],
) -> Result<[u8; HEADER_PROTECTION_MASK_LEN]> {
    if sample.len() < HEADER_PROTECTION_SAMPLE_LEN {
        return Err(Error::HttpProtocol(
            "QUIC header protection sample is too short".into(),
        ));
    }

    let mut crypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Encrypt,
        &keys.header_protection_key,
        None,
    )
    .map_err(|err| Error::Quic(format!("QUIC header protection init failed: {err}")))?;
    crypter.pad(false);

    let mut output = [0u8; HEADER_PROTECTION_SAMPLE_LEN + 16];
    let count = crypter
        .update(&sample[..HEADER_PROTECTION_SAMPLE_LEN], &mut output)
        .map_err(|err| Error::Quic(format!("QUIC header protection update failed: {err}")))?;
    let rest = crypter
        .finalize(&mut output[count..])
        .map_err(|err| Error::Quic(format!("QUIC header protection finalize failed: {err}")))?;

    let protected = &output[..count + rest];
    if protected.len() < HEADER_PROTECTION_MASK_LEN {
        return Err(Error::Quic("QUIC header protection mask too short".into()));
    }

    let mut mask = [0u8; HEADER_PROTECTION_MASK_LEN];
    mask.copy_from_slice(&protected[..HEADER_PROTECTION_MASK_LEN]);
    Ok(mask)
}

pub fn protect_long_header(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    mask: [u8; HEADER_PROTECTION_MASK_LEN],
) -> Result<()> {
    validate_packet_number_len(packet_number_len)?;
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if header.len() < packet_number_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC header for protection".into(),
        ));
    }

    header[0] ^= mask[0] & 0x0f;
    for index in 0..packet_number_len {
        header[packet_number_offset + index] ^= mask[index + 1];
    }

    Ok(())
}

pub fn protect_short_header(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    mask: [u8; HEADER_PROTECTION_MASK_LEN],
) -> Result<()> {
    validate_packet_number_len(packet_number_len)?;
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if header.len() < packet_number_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC short header for protection".into(),
        ));
    }

    header[0] ^= mask[0] & 0x1f;
    for index in 0..packet_number_len {
        header[packet_number_offset + index] ^= mask[index + 1];
    }

    Ok(())
}

pub fn protect_initial_packet(
    keys: &QuicPacketKeyMaterial,
    packet_number: u64,
    header: &[u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    plaintext: &[u8],
) -> Result<Bytes> {
    protect_long_header_packet(
        keys,
        packet_number,
        header,
        packet_number_offset,
        packet_number_len,
        plaintext,
    )
}

pub fn protect_long_header_packet(
    keys: &QuicPacketKeyMaterial,
    packet_number: u64,
    header: &[u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    plaintext: &[u8],
) -> Result<Bytes> {
    validate_packet_number_len(packet_number_len)?;
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if header.len() != packet_number_end {
        return Err(Error::HttpProtocol(
            "QUIC Initial header length must end after packet number".into(),
        ));
    }

    let sealed = seal_packet_payload(keys, packet_number, header, plaintext)?;
    let mut packet = Vec::with_capacity(header.len() + sealed.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(&sealed);

    let sample = header_protection_sample(&packet, packet_number_offset)?;
    let mask = header_protection_mask(keys, sample)?;
    protect_long_header(
        &mut packet[..header.len()],
        packet_number_offset,
        packet_number_len,
        mask,
    )?;

    Ok(Bytes::from(packet))
}

pub fn protect_short_header_packet(
    keys: &QuicPacketKeyMaterial,
    destination_cid: &ConnectionId,
    packet_number: u64,
    packet_number_len: usize,
    key_phase: bool,
    plaintext: &[u8],
) -> Result<Bytes> {
    let header = encode_short_header(&ShortHeaderPacket {
        destination_cid: destination_cid.clone(),
        packet_number,
        packet_number_len,
        key_phase,
    })?;
    let packet_number_offset = 1 + destination_cid.len();
    let sealed = seal_packet_payload(keys, packet_number, &header, plaintext)?;
    let mut packet = Vec::with_capacity(header.len() + sealed.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&sealed);

    let sample = header_protection_sample(&packet, packet_number_offset)?;
    let mask = header_protection_mask(keys, sample)?;
    protect_short_header(
        &mut packet[..header.len()],
        packet_number_offset,
        packet_number_len,
        mask,
    )?;

    Ok(Bytes::from(packet))
}

pub fn initial_crypto_plaintext(crypto_data: &[u8], padded_len: usize) -> Result<Bytes> {
    let mut plaintext = encode_frame(&QuicFrame::Crypto {
        offset: 0,
        data: Bytes::copy_from_slice(crypto_data),
    })
    .to_vec();
    if plaintext.len() > padded_len {
        return Err(Error::HttpProtocol(
            "QUIC Initial CRYPTO frame exceeds padded length".into(),
        ));
    }
    plaintext.resize(padded_len, FRAME_PADDING as u8);
    Ok(Bytes::from(plaintext))
}

pub fn build_initial_crypto_packet(
    keys: &QuicPacketKeyMaterial,
    packet_number: u64,
    header: &[u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    crypto_data: &[u8],
    padded_plaintext_len: usize,
) -> Result<Bytes> {
    let plaintext = initial_crypto_plaintext(crypto_data, padded_plaintext_len)?;
    protect_initial_packet(
        keys,
        packet_number,
        header,
        packet_number_offset,
        packet_number_len,
        &plaintext,
    )
}

pub fn open_initial_packet(
    keys: &QuicPacketKeyMaterial,
    packet: &[u8],
    packet_number_offset: usize,
) -> Result<OpenedInitialPacket> {
    let sample = header_protection_sample(packet, packet_number_offset)?;
    let mask = header_protection_mask(keys, sample)?;
    let mut opened = packet.to_vec();

    opened[0] ^= mask[0] & 0x0f;
    let packet_number_len = ((opened[0] & PACKET_NUMBER_LEN_MASK) + 1) as usize;
    validate_packet_number_len(packet_number_len)?;

    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if opened.len() < packet_number_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC Initial packet number".into(),
        ));
    }

    for index in 0..packet_number_len {
        opened[packet_number_offset + index] ^= mask[index + 1];
    }

    let packet_number = read_packet_number(&opened[packet_number_offset..packet_number_end]);
    let header = Bytes::copy_from_slice(&opened[..packet_number_end]);
    let payload = open_packet_payload(keys, packet_number, &header, &opened[packet_number_end..])?;

    Ok(OpenedInitialPacket {
        packet_number,
        header,
        payload,
    })
}

pub fn open_protected_initial_packet(
    keys: &QuicPacketKeyMaterial,
    packet: &[u8],
    expected_packet_number: u64,
) -> Result<OpenedInitialPacket> {
    let packet_number_offset = initial_packet_number_offset(packet)?;
    open_long_header_packet(keys, packet, packet_number_offset, expected_packet_number)
}

pub fn open_long_header_packet(
    keys: &QuicPacketKeyMaterial,
    packet: &[u8],
    packet_number_offset: usize,
    expected_packet_number: u64,
) -> Result<OpenedInitialPacket> {
    let sample = header_protection_sample(packet, packet_number_offset)?;
    let mask = header_protection_mask(keys, sample)?;
    let mut opened = packet.to_vec();

    opened[0] ^= mask[0] & 0x0f;
    let packet_number_len = ((opened[0] & PACKET_NUMBER_LEN_MASK) + 1) as usize;
    validate_packet_number_len(packet_number_len)?;
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if opened.len() < packet_number_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC Initial packet number".into(),
        ));
    }

    for index in 0..packet_number_len {
        opened[packet_number_offset + index] ^= mask[index + 1];
    }

    let truncated = read_packet_number(&opened[packet_number_offset..packet_number_end]);
    let packet_number =
        recover_packet_number(truncated, packet_number_len, expected_packet_number)?;
    let header = Bytes::copy_from_slice(&opened[..packet_number_end]);
    let payload = open_packet_payload(keys, packet_number, &header, &opened[packet_number_end..])?;

    Ok(OpenedInitialPacket {
        packet_number,
        header,
        payload,
    })
}

pub fn open_short_header_packet(
    keys: &QuicPacketKeyMaterial,
    packet: &[u8],
    destination_cid_len: usize,
    expected_packet_number: u64,
) -> Result<OpenedShortHeaderPacket> {
    if destination_cid_len > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }
    if packet.len() < 1 + destination_cid_len {
        return Err(Error::HttpProtocol("truncated QUIC short header".into()));
    }
    if packet[0] & HEADER_FORM_LONG != 0 {
        return Err(Error::HttpProtocol("expected QUIC short header".into()));
    }

    let packet_number_offset = 1 + destination_cid_len;
    let sample = header_protection_sample(packet, packet_number_offset)?;
    let mask = header_protection_mask(keys, sample)?;
    let mut opened = packet.to_vec();

    opened[0] ^= mask[0] & 0x1f;
    if opened[0] & FIXED_BIT == 0 {
        return Err(Error::HttpProtocol("missing QUIC fixed bit".into()));
    }
    let key_phase = opened[0] & SHORT_KEY_PHASE_BIT != 0;
    let packet_number_len = ((opened[0] & PACKET_NUMBER_LEN_MASK) + 1) as usize;
    validate_packet_number_len(packet_number_len)?;
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC packet number offset overflow".into()))?;
    if opened.len() < packet_number_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC short-header packet number".into(),
        ));
    }

    for index in 0..packet_number_len {
        opened[packet_number_offset + index] ^= mask[index + 1];
    }

    let truncated = read_packet_number(&opened[packet_number_offset..packet_number_end]);
    let packet_number =
        recover_packet_number(truncated, packet_number_len, expected_packet_number)?;
    let header = Bytes::copy_from_slice(&opened[..packet_number_end]);
    let destination_cid =
        ConnectionId::from_bytes(Bytes::copy_from_slice(&opened[1..1 + destination_cid_len]))?;
    let payload = open_packet_payload(keys, packet_number, &header, &opened[packet_number_end..])?;

    Ok(OpenedShortHeaderPacket {
        packet_number,
        destination_cid,
        header,
        payload,
        key_phase,
    })
}

pub fn recover_packet_number(
    truncated_packet_number: u64,
    packet_number_len: usize,
    expected_packet_number: u64,
) -> Result<u64> {
    validate_packet_number_len(packet_number_len)?;
    if expected_packet_number > MAX_PACKET_NUMBER {
        return Err(Error::HttpProtocol(
            "expected QUIC packet number exceeds 2^62-1".into(),
        ));
    }

    let packet_number_bits = packet_number_len * 8;
    let packet_number_window = 1u64 << packet_number_bits;
    let packet_number_half_window = packet_number_window / 2;
    let packet_number_mask = packet_number_window - 1;
    if truncated_packet_number > packet_number_mask {
        return Err(Error::HttpProtocol(
            "truncated QUIC packet number is too large".into(),
        ));
    }

    let expected = expected_packet_number;
    let mut candidate = (expected & !packet_number_mask) | truncated_packet_number;
    if candidate + packet_number_half_window <= expected
        && candidate < MAX_PACKET_NUMBER - packet_number_window
    {
        candidate += packet_number_window;
    } else if candidate > expected + packet_number_half_window && candidate >= packet_number_window
    {
        candidate -= packet_number_window;
    }

    Ok(candidate)
}

pub fn encode_transport_parameters(params: &QuicTransportParams) -> Bytes {
    let mut out = BytesMut::new();
    if let Some(raw_ordered_parameters) = &params.raw_ordered_transport_parameters {
        for parameter in raw_ordered_parameters {
            put_transport_parameter_bytes(&mut out, parameter.id, &parameter.value);
        }
        return out.freeze();
    }
    put_transport_parameter(
        &mut out,
        TP_MAX_IDLE_TIMEOUT,
        Some(params.max_idle_timeout_ms),
    );
    put_transport_parameter(
        &mut out,
        TP_MAX_UDP_PAYLOAD_SIZE,
        Some(params.max_recv_udp_payload_size as u64),
    );
    put_transport_parameter(&mut out, TP_INITIAL_MAX_DATA, Some(params.initial_max_data));
    put_transport_parameter(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        Some(params.initial_max_stream_data_bidi_local),
    );
    put_transport_parameter(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        Some(params.initial_max_stream_data_bidi_remote),
    );
    put_transport_parameter(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_UNI,
        Some(params.initial_max_stream_data_uni),
    );
    put_transport_parameter(
        &mut out,
        TP_INITIAL_MAX_STREAMS_BIDI,
        Some(params.initial_max_streams_bidi),
    );
    put_transport_parameter(
        &mut out,
        TP_INITIAL_MAX_STREAMS_UNI,
        Some(params.initial_max_streams_uni),
    );
    put_transport_parameter(
        &mut out,
        TP_ACK_DELAY_EXPONENT,
        Some(params.ack_delay_exponent),
    );
    put_transport_parameter(&mut out, TP_MAX_ACK_DELAY, Some(params.max_ack_delay_ms));
    if params.disable_active_migration {
        put_transport_parameter(&mut out, TP_DISABLE_ACTIVE_MIGRATION, None);
    }
    put_transport_parameter(
        &mut out,
        TP_ACTIVE_CONNECTION_ID_LIMIT,
        Some(params.active_connection_id_limit),
    );
    if let Some(value) = params.max_datagram_frame_size {
        put_transport_parameter(&mut out, TP_MAX_DATAGRAM_FRAME_SIZE, Some(value));
    }
    if params.grease
        && !params
            .additional_transport_parameters
            .iter()
            .any(|(id, _)| *id == TP_GREASE_RESERVED)
    {
        put_transport_parameter_bytes(&mut out, TP_GREASE_RESERVED, &[]);
    }
    for (id, value) in &params.additional_transport_parameters {
        put_transport_parameter_bytes(&mut out, *id, value);
    }
    out.freeze()
}

pub fn encode_transport_parameters_with_initial_source_connection_id(
    params: &QuicTransportParams,
    initial_source_connection_id: &ConnectionId,
) -> Bytes {
    let mut out = BytesMut::from(encode_transport_parameters(params).as_ref());
    put_transport_parameter_bytes(
        &mut out,
        TP_INITIAL_SOURCE_CONNECTION_ID,
        initial_source_connection_id.as_bytes(),
    );
    out.freeze()
}

pub fn encode_server_transport_parameters(
    params: &QuicTransportParams,
    original_destination_connection_id: &ConnectionId,
    initial_source_connection_id: &ConnectionId,
    retry_source_connection_id: Option<&ConnectionId>,
) -> Bytes {
    let mut out = BytesMut::new();
    put_transport_parameter_bytes(
        &mut out,
        TP_ORIGINAL_DESTINATION_CONNECTION_ID,
        original_destination_connection_id.as_bytes(),
    );
    out.extend_from_slice(encode_transport_parameters(params).as_ref());
    put_transport_parameter_bytes(
        &mut out,
        TP_INITIAL_SOURCE_CONNECTION_ID,
        initial_source_connection_id.as_bytes(),
    );
    if let Some(retry_source_connection_id) = retry_source_connection_id {
        put_transport_parameter_bytes(
            &mut out,
            TP_RETRY_SOURCE_CONNECTION_ID,
            retry_source_connection_id.as_bytes(),
        );
    }
    out.freeze()
}

pub fn decode_transport_parameters(bytes: &[u8]) -> Result<Vec<TransportParameter>> {
    let mut input = Bytes::copy_from_slice(bytes);
    let mut params = Vec::new();
    while input.has_remaining() {
        let id = get_varint(&mut input)?;
        let len = get_varint(&mut input)? as usize;
        if input.remaining() < len {
            return Err(Error::HttpProtocol(
                "truncated QUIC transport parameter".into(),
            ));
        }
        let mut value = input.copy_to_bytes(len);
        params.push(match id {
            TP_ORIGINAL_DESTINATION_CONNECTION_ID => {
                TransportParameter::OriginalDestinationConnectionId(value)
            }
            TP_MAX_IDLE_TIMEOUT => TransportParameter::MaxIdleTimeout(read_tp_varint(&mut value)?),
            TP_MAX_UDP_PAYLOAD_SIZE => {
                TransportParameter::MaxUdpPayloadSize(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_MAX_DATA => TransportParameter::InitialMaxData(read_tp_varint(&mut value)?),
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                TransportParameter::InitialMaxStreamDataBidiLocal(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                TransportParameter::InitialMaxStreamDataBidiRemote(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_MAX_STREAM_DATA_UNI => {
                TransportParameter::InitialMaxStreamDataUni(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_MAX_STREAMS_BIDI => {
                TransportParameter::InitialMaxStreamsBidi(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_MAX_STREAMS_UNI => {
                TransportParameter::InitialMaxStreamsUni(read_tp_varint(&mut value)?)
            }
            TP_ACK_DELAY_EXPONENT => {
                TransportParameter::AckDelayExponent(read_tp_varint(&mut value)?)
            }
            TP_MAX_ACK_DELAY => TransportParameter::MaxAckDelay(read_tp_varint(&mut value)?),
            TP_DISABLE_ACTIVE_MIGRATION => {
                if value.has_remaining() {
                    return Err(Error::HttpProtocol(
                        "disable_active_migration must have empty value".into(),
                    ));
                }
                TransportParameter::DisableActiveMigration
            }
            TP_ACTIVE_CONNECTION_ID_LIMIT => {
                TransportParameter::ActiveConnectionIdLimit(read_tp_varint(&mut value)?)
            }
            TP_INITIAL_SOURCE_CONNECTION_ID => TransportParameter::InitialSourceConnectionId(value),
            TP_RETRY_SOURCE_CONNECTION_ID => TransportParameter::RetrySourceConnectionId(value),
            TP_MAX_DATAGRAM_FRAME_SIZE => {
                TransportParameter::MaxDatagramFrameSize(read_tp_varint(&mut value)?)
            }
            id => TransportParameter::Additional(id, value),
        });
    }
    Ok(params)
}

pub fn encode_frame(frame: &QuicFrame) -> Bytes {
    let mut out = BytesMut::new();
    match frame {
        QuicFrame::Padding => out.put_u8(FRAME_PADDING as u8),
        QuicFrame::Ping => out.put_u8(FRAME_PING as u8),
        QuicFrame::Ack {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ranges,
        } => {
            put_varint(&mut out, FRAME_ACK);
            encode_ack_fields(
                &mut out,
                *largest_acknowledged,
                *ack_delay,
                *first_ack_range,
                ranges,
            );
        }
        QuicFrame::AckEcn {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ranges,
            ect0_count,
            ect1_count,
            ce_count,
        } => {
            put_varint(&mut out, FRAME_ACK_ECN);
            encode_ack_fields(
                &mut out,
                *largest_acknowledged,
                *ack_delay,
                *first_ack_range,
                ranges,
            );
            put_varint(&mut out, *ect0_count);
            put_varint(&mut out, *ect1_count);
            put_varint(&mut out, *ce_count);
        }
        QuicFrame::Crypto { offset, data } => {
            put_varint(&mut out, FRAME_CRYPTO);
            put_varint(&mut out, *offset);
            put_varint(&mut out, data.len() as u64);
            out.extend_from_slice(data);
        }
        QuicFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            put_varint(&mut out, FRAME_RESET_STREAM);
            put_varint(&mut out, *stream_id);
            put_varint(&mut out, *error_code);
            put_varint(&mut out, *final_size);
        }
        QuicFrame::StopSending {
            stream_id,
            error_code,
        } => {
            put_varint(&mut out, FRAME_STOP_SENDING);
            put_varint(&mut out, *stream_id);
            put_varint(&mut out, *error_code);
        }
        QuicFrame::ConnectionClose {
            error_code,
            frame_type,
            reason,
        } => {
            if let Some(frame_type) = frame_type {
                put_varint(&mut out, FRAME_CONNECTION_CLOSE_TRANSPORT);
                put_varint(&mut out, *error_code);
                put_varint(&mut out, *frame_type);
            } else {
                put_varint(&mut out, FRAME_CONNECTION_CLOSE_APPLICATION);
                put_varint(&mut out, *error_code);
            }
            put_varint(&mut out, reason.len() as u64);
            out.extend_from_slice(reason);
        }
        QuicFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => {
            let mut frame_type = FRAME_STREAM_BASE | FRAME_STREAM_LEN;
            if offset.is_some() {
                frame_type |= FRAME_STREAM_OFF;
            }
            if *fin {
                frame_type |= FRAME_STREAM_FIN;
            }
            out.put_u8(frame_type);
            put_varint(&mut out, *stream_id);
            if let Some(offset) = offset {
                put_varint(&mut out, *offset);
            }
            put_varint(&mut out, data.len() as u64);
            out.extend_from_slice(data);
        }
        QuicFrame::MaxData(max_data) => {
            put_varint(&mut out, FRAME_MAX_DATA);
            put_varint(&mut out, *max_data);
        }
        QuicFrame::MaxStreamData {
            stream_id,
            max_stream_data,
        } => {
            put_varint(&mut out, FRAME_MAX_STREAM_DATA);
            put_varint(&mut out, *stream_id);
            put_varint(&mut out, *max_stream_data);
        }
        QuicFrame::MaxStreams {
            bidirectional,
            max_streams,
        } => {
            put_varint(
                &mut out,
                if *bidirectional {
                    FRAME_MAX_STREAMS_BIDI
                } else {
                    FRAME_MAX_STREAMS_UNI
                },
            );
            put_varint(&mut out, *max_streams);
        }
        QuicFrame::DataBlocked { maximum_data } => {
            put_varint(&mut out, FRAME_DATA_BLOCKED);
            put_varint(&mut out, *maximum_data);
        }
        QuicFrame::StreamDataBlocked {
            stream_id,
            maximum_stream_data,
        } => {
            put_varint(&mut out, FRAME_STREAM_DATA_BLOCKED);
            put_varint(&mut out, *stream_id);
            put_varint(&mut out, *maximum_stream_data);
        }
        QuicFrame::StreamsBlocked {
            bidirectional,
            maximum_streams,
        } => {
            put_varint(
                &mut out,
                if *bidirectional {
                    FRAME_STREAMS_BLOCKED_BIDI
                } else {
                    FRAME_STREAMS_BLOCKED_UNI
                },
            );
            put_varint(&mut out, *maximum_streams);
        }
        QuicFrame::NewConnectionId {
            sequence_number,
            retire_prior_to,
            connection_id,
            stateless_reset_token,
        } => {
            put_varint(&mut out, FRAME_NEW_CONNECTION_ID);
            put_varint(&mut out, *sequence_number);
            put_varint(&mut out, *retire_prior_to);
            out.put_u8(connection_id.len() as u8);
            out.extend_from_slice(connection_id);
            out.extend_from_slice(stateless_reset_token);
        }
        QuicFrame::RetireConnectionId { sequence_number } => {
            put_varint(&mut out, FRAME_RETIRE_CONNECTION_ID);
            put_varint(&mut out, *sequence_number);
        }
        QuicFrame::PathChallenge(data) => {
            put_varint(&mut out, FRAME_PATH_CHALLENGE);
            out.extend_from_slice(data);
        }
        QuicFrame::PathResponse(data) => {
            put_varint(&mut out, FRAME_PATH_RESPONSE);
            out.extend_from_slice(data);
        }
        QuicFrame::HandshakeDone => {
            put_varint(&mut out, FRAME_HANDSHAKE_DONE);
        }
    }
    out.freeze()
}

fn encode_ack_fields(
    out: &mut BytesMut,
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ranges: &[QuicAckRange],
) {
    put_varint(out, largest_acknowledged);
    put_varint(out, ack_delay);
    put_varint(out, ranges.len() as u64);
    put_varint(out, first_ack_range);
    for range in ranges {
        put_varint(out, range.gap);
        put_varint(out, range.ack_range_length);
    }
}

pub fn decode_frame(bytes: &[u8]) -> Result<QuicFrame> {
    let mut input = Bytes::copy_from_slice(bytes);
    let frame = decode_frame_from(&mut input)?;
    if input.has_remaining() {
        return Err(Error::HttpProtocol("QUIC frame has trailing bytes".into()));
    }
    Ok(frame)
}

pub fn decode_frames(bytes: &[u8]) -> Result<Vec<QuicFrame>> {
    let mut input = Bytes::copy_from_slice(bytes);
    let mut frames = Vec::new();
    while input.has_remaining() {
        frames.push(decode_frame_from(&mut input)?);
    }
    Ok(frames)
}

pub fn encode_initial_header(packet: &LongHeaderPacket) -> Result<Bytes> {
    if packet.packet_type != LongHeaderType::Initial {
        return Err(Error::HttpProtocol(
            "encode_initial_header requires an Initial packet".into(),
        ));
    }
    encode_long_header(packet)
}

pub fn encode_long_header(packet: &LongHeaderPacket) -> Result<Bytes> {
    if packet.packet_type == LongHeaderType::Retry {
        return Err(Error::HttpProtocol(
            "encode_long_header does not support Retry packets".into(),
        ));
    }
    validate_packet_number_len(packet.packet_number_len)?;
    validate_cid(&packet.destination_cid)?;
    validate_cid(&packet.source_cid)?;

    let length = packet
        .payload_len
        .checked_add(packet.packet_number_len)
        .ok_or_else(|| Error::HttpProtocol("QUIC Initial length overflow".into()))?;
    let mut out = BytesMut::with_capacity(
        1 + 4
            + 1
            + packet.destination_cid.len()
            + 1
            + packet.source_cid.len()
            + if packet.packet_type == LongHeaderType::Initial {
                varint_len(packet.token.len() as u64) + packet.token.len()
            } else {
                0
            }
            + varint_len(length as u64)
            + packet.packet_number_len,
    );

    let packet_type = match packet.packet_type {
        LongHeaderType::Initial => 0,
        LongHeaderType::ZeroRtt => 1,
        LongHeaderType::Handshake => 2,
        LongHeaderType::Retry => unreachable!("Retry rejected above"),
    };
    let first = HEADER_FORM_LONG
        | FIXED_BIT
        | ((packet_type as u8) << 4)
        | ((packet.packet_number_len as u8 - 1) & 0x03);
    out.put_u8(first);
    out.put_u32(packet.version);
    put_cid(&mut out, &packet.destination_cid)?;
    put_cid(&mut out, &packet.source_cid)?;
    if packet.packet_type == LongHeaderType::Initial {
        put_varint(&mut out, packet.token.len() as u64);
        out.extend_from_slice(&packet.token);
    }
    put_varint(&mut out, length as u64);
    put_packet_number(&mut out, packet.packet_number, packet.packet_number_len)?;

    Ok(out.freeze())
}

pub fn encode_short_header(packet: &ShortHeaderPacket) -> Result<Bytes> {
    validate_packet_number_len(packet.packet_number_len)?;
    validate_cid(&packet.destination_cid)?;

    let mut out =
        BytesMut::with_capacity(1 + packet.destination_cid.len() + packet.packet_number_len);
    let mut first = FIXED_BIT | ((packet.packet_number_len as u8 - 1) & PACKET_NUMBER_LEN_MASK);
    if packet.key_phase {
        first |= SHORT_KEY_PHASE_BIT;
    }
    out.put_u8(first);
    out.extend_from_slice(packet.destination_cid.as_bytes());
    put_packet_number(&mut out, packet.packet_number, packet.packet_number_len)?;
    Ok(out.freeze())
}

pub fn split_long_header_datagram(datagram: &[u8]) -> Result<Vec<LongHeaderDatagramPacket>> {
    let mut packets = Vec::new();
    let mut offset = 0;

    while offset < datagram.len() {
        let packet_start = offset;
        let first = read_u8_at(datagram, &mut offset, "truncated QUIC long header")?;
        if first & HEADER_FORM_LONG == 0 {
            if packets.is_empty() {
                return Err(Error::HttpProtocol("expected QUIC long header".into()));
            }
            break;
        }
        if first & FIXED_BIT == 0 {
            return Err(Error::HttpProtocol("missing QUIC fixed bit".into()));
        }

        let packet_type = match (first & LONG_PACKET_TYPE_MASK) >> 4 {
            0 => LongHeaderType::Initial,
            1 => LongHeaderType::ZeroRtt,
            2 => LongHeaderType::Handshake,
            _ => LongHeaderType::Retry,
        };
        let version = read_u32_at(datagram, &mut offset)?;
        let destination_cid = read_cid_at(datagram, &mut offset)?;
        let source_cid = read_cid_at(datagram, &mut offset)?;
        if packet_type == LongHeaderType::Retry {
            let declared_remaining_len = datagram
                .len()
                .checked_sub(offset)
                .ok_or_else(|| Error::HttpProtocol("QUIC Retry packet length underflow".into()))?;
            if declared_remaining_len < RETRY_INTEGRITY_TAG_LEN {
                return Err(Error::HttpProtocol(
                    "truncated QUIC Retry integrity tag".into(),
                ));
            }
            let token_len = declared_remaining_len - RETRY_INTEGRITY_TAG_LEN;
            let packet_number_offset = offset - packet_start;
            let token = read_bytes_at(
                datagram,
                &mut offset,
                token_len,
                "truncated QUIC Retry token",
            )?;
            let _integrity_tag = read_bytes_at(
                datagram,
                &mut offset,
                RETRY_INTEGRITY_TAG_LEN,
                "truncated QUIC Retry integrity tag",
            )?;

            packets.push(LongHeaderDatagramPacket {
                packet_type,
                version,
                destination_cid,
                source_cid,
                token,
                declared_remaining_len,
                packet_number_offset,
                packet: Bytes::copy_from_slice(&datagram[packet_start..offset]),
            });
            continue;
        }
        let token = if packet_type == LongHeaderType::Initial {
            let token_len =
                usize::try_from(read_varint_at(datagram, &mut offset)?).map_err(|_| {
                    Error::HttpProtocol("QUIC Initial token length exceeds usize".into())
                })?;
            read_bytes_at(
                datagram,
                &mut offset,
                token_len,
                "truncated QUIC Initial token",
            )?
        } else {
            Bytes::new()
        };
        let declared_remaining_len = usize::try_from(read_varint_at(datagram, &mut offset)?)
            .map_err(|_| {
                Error::HttpProtocol("QUIC long-header packet length exceeds usize".into())
            })?;
        let packet_number_offset = offset - packet_start;
        let packet_end = offset
            .checked_add(declared_remaining_len)
            .ok_or_else(|| Error::HttpProtocol("QUIC long-header packet length overflow".into()))?;
        if packet_end > datagram.len() {
            return Err(Error::HttpProtocol(
                "truncated QUIC long-header packet".into(),
            ));
        }

        packets.push(LongHeaderDatagramPacket {
            packet_type,
            version,
            destination_cid,
            source_cid,
            token,
            declared_remaining_len,
            packet_number_offset,
            packet: Bytes::copy_from_slice(&datagram[packet_start..packet_end]),
        });
        offset = packet_end;
    }

    Ok(packets)
}

pub fn decode_long_header(bytes: &[u8]) -> Result<LongHeaderPacket> {
    let mut input = Bytes::copy_from_slice(bytes);
    if input.remaining() < 6 {
        return Err(Error::HttpProtocol("truncated QUIC long header".into()));
    }

    let first = input.get_u8();
    if first & HEADER_FORM_LONG == 0 {
        return Err(Error::HttpProtocol("expected QUIC long header".into()));
    }
    if first & FIXED_BIT == 0 {
        return Err(Error::HttpProtocol("missing QUIC fixed bit".into()));
    }

    let packet_type = match (first & LONG_PACKET_TYPE_MASK) >> 4 {
        0 => LongHeaderType::Initial,
        1 => LongHeaderType::ZeroRtt,
        2 => LongHeaderType::Handshake,
        _ => LongHeaderType::Retry,
    };
    let packet_number_len = ((first & PACKET_NUMBER_LEN_MASK) + 1) as usize;
    let version = input.get_u32();
    let destination_cid = get_cid(&mut input)?;
    let source_cid = get_cid(&mut input)?;

    let token = if packet_type == LongHeaderType::Initial {
        let token_len = get_varint(&mut input)? as usize;
        if input.remaining() < token_len {
            return Err(Error::HttpProtocol("truncated QUIC Initial token".into()));
        }
        input.copy_to_bytes(token_len)
    } else {
        Bytes::new()
    };

    let length = get_varint(&mut input)? as usize;
    if length < packet_number_len || input.remaining() < packet_number_len {
        return Err(Error::HttpProtocol("truncated QUIC packet number".into()));
    }
    let packet_number = get_packet_number(&mut input, packet_number_len)?;

    Ok(LongHeaderPacket {
        packet_type,
        version,
        destination_cid,
        source_cid,
        token,
        packet_number,
        packet_number_len,
        payload_len: length - packet_number_len,
    })
}

pub fn decode_version_negotiation_packet(bytes: &[u8]) -> Result<VersionNegotiationPacket> {
    let mut input = Bytes::copy_from_slice(bytes);
    if input.remaining() < 6 {
        return Err(Error::HttpProtocol(
            "truncated QUIC Version Negotiation packet".into(),
        ));
    }

    let first = input.get_u8();
    if first & HEADER_FORM_LONG == 0 {
        return Err(Error::HttpProtocol("expected QUIC long header".into()));
    }
    let version = input.get_u32();
    if version != 0 {
        return Err(Error::HttpProtocol(
            "expected QUIC Version Negotiation packet".into(),
        ));
    }
    let destination_cid = get_cid(&mut input)?;
    let source_cid = get_cid(&mut input)?;
    if input.remaining() == 0 {
        return Err(Error::HttpProtocol(
            "QUIC Version Negotiation packet has no versions".into(),
        ));
    }
    if input.remaining() % 4 != 0 {
        return Err(Error::HttpProtocol(
            "truncated QUIC Version Negotiation supported version list".into(),
        ));
    }

    let mut supported_versions = Vec::with_capacity(input.remaining() / 4);
    while input.has_remaining() {
        supported_versions.push(input.get_u32());
    }

    Ok(VersionNegotiationPacket {
        destination_cid,
        source_cid,
        supported_versions,
    })
}

pub fn decode_retry_packet(bytes: &[u8]) -> Result<RetryPacket> {
    let mut input = Bytes::copy_from_slice(bytes);
    if input.remaining() < 1 + 4 + 1 + 1 + RETRY_INTEGRITY_TAG_LEN {
        return Err(Error::HttpProtocol("truncated QUIC Retry packet".into()));
    }

    let first = input.get_u8();
    if first & HEADER_FORM_LONG == 0 {
        return Err(Error::HttpProtocol("expected QUIC long header".into()));
    }
    if first & FIXED_BIT == 0 {
        return Err(Error::HttpProtocol("missing QUIC fixed bit".into()));
    }
    if (first & LONG_PACKET_TYPE_MASK) >> 4 != 3 {
        return Err(Error::HttpProtocol("expected QUIC Retry packet".into()));
    }
    let version = input.get_u32();
    if version == 0 {
        return Err(Error::HttpProtocol(
            "QUIC Retry packet cannot use version 0".into(),
        ));
    }
    let destination_cid = get_cid(&mut input)?;
    let source_cid = get_cid(&mut input)?;
    if input.remaining() < RETRY_INTEGRITY_TAG_LEN {
        return Err(Error::HttpProtocol(
            "truncated QUIC Retry integrity tag".into(),
        ));
    }
    let token_len = input.remaining() - RETRY_INTEGRITY_TAG_LEN;
    let token = input.copy_to_bytes(token_len);
    let integrity_tag = input.copy_to_bytes(RETRY_INTEGRITY_TAG_LEN);
    let mut tag = [0u8; RETRY_INTEGRITY_TAG_LEN];
    tag.copy_from_slice(&integrity_tag);

    Ok(RetryPacket {
        version,
        destination_cid,
        source_cid,
        token,
        integrity_tag: tag,
    })
}

pub fn retry_integrity_tag_v1(
    original_destination_cid: &ConnectionId,
    retry_without_integrity_tag: &[u8],
) -> Result<[u8; RETRY_INTEGRITY_TAG_LEN]> {
    let mut pseudo_packet =
        Vec::with_capacity(1 + original_destination_cid.len() + retry_without_integrity_tag.len());
    pseudo_packet.push(original_destination_cid.len() as u8);
    pseudo_packet.extend_from_slice(original_destination_cid.as_bytes());
    pseudo_packet.extend_from_slice(retry_without_integrity_tag);

    let mut tag = [0u8; RETRY_INTEGRITY_TAG_LEN];
    let ciphertext = encrypt_aead(
        Cipher::aes_128_gcm(),
        &RETRY_INTEGRITY_KEY_V1,
        Some(&RETRY_INTEGRITY_NONCE_V1),
        &pseudo_packet,
        &[],
        &mut tag,
    )
    .map_err(|err| Error::Quic(format!("QUIC Retry integrity tag failed: {err}")))?;
    if !ciphertext.is_empty() {
        return Err(Error::Quic(
            "QUIC Retry integrity tag produced ciphertext".into(),
        ));
    }
    Ok(tag)
}

pub fn validate_retry_integrity_tag_v1(
    original_destination_cid: &ConnectionId,
    retry_packet: &[u8],
) -> Result<RetryPacket> {
    let decoded = decode_retry_packet(retry_packet)?;
    if decoded.version != 1 {
        return Err(Error::HttpProtocol(
            "QUIC Retry integrity validation only supports version 1".into(),
        ));
    }
    let tag_offset = retry_packet
        .len()
        .checked_sub(RETRY_INTEGRITY_TAG_LEN)
        .ok_or_else(|| Error::HttpProtocol("truncated QUIC Retry packet".into()))?;
    let expected = retry_integrity_tag_v1(original_destination_cid, &retry_packet[..tag_offset])?;
    if expected != decoded.integrity_tag {
        return Err(Error::HttpProtocol(
            "invalid QUIC Retry integrity tag".into(),
        ));
    }
    Ok(decoded)
}

fn merge_crypto_segment(
    merged_start: &mut u64,
    merged_end: &mut u64,
    merged_data: &mut Bytes,
    segment_start: u64,
    segment_data: Bytes,
) -> Result<()> {
    let segment_end = segment_start
        .checked_add(segment_data.len() as u64)
        .ok_or_else(|| Error::HttpProtocol("QUIC CRYPTO range overflow".into()))?;
    let new_start = (*merged_start).min(segment_start);
    let new_end = (*merged_end).max(segment_end);
    let new_len = usize::try_from(new_end - new_start)
        .map_err(|_| Error::HttpProtocol("QUIC CRYPTO merged range exceeds usize".into()))?;
    let mut merged = vec![0; new_len];

    let current_offset = usize::try_from(*merged_start - new_start)
        .map_err(|_| Error::HttpProtocol("QUIC CRYPTO current offset exceeds usize".into()))?;
    merged[current_offset..current_offset + merged_data.len()].copy_from_slice(merged_data);

    let segment_offset = usize::try_from(segment_start - new_start)
        .map_err(|_| Error::HttpProtocol("QUIC CRYPTO segment offset exceeds usize".into()))?;
    merged[segment_offset..segment_offset + segment_data.len()].copy_from_slice(&segment_data);

    *merged_start = new_start;
    *merged_end = new_end;
    *merged_data = Bytes::from(merged);
    Ok(())
}

fn hkdf_extract_sha256(salt: &[u8], input_key_material: &[u8]) -> Result<Bytes> {
    let prk = hmac_sha256(salt, input_key_material)
        .map_err(|err| Error::Quic(format!("HKDF extract failed: {err}")))?;
    Ok(Bytes::copy_from_slice(&prk))
}

fn hkdf_expand_label_sha256(secret: &[u8], label: &[u8], len: usize) -> Result<Bytes> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let full_label_len = LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or_else(|| Error::HttpProtocol("HKDF label length overflow".into()))?;
    if full_label_len > u8::MAX as usize || len > u16::MAX as usize {
        return Err(Error::HttpProtocol("HKDF label is too large".into()));
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(0);

    hkdf_expand_sha256(secret, &info, len)
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Bytes> {
    const HASH_LEN: usize = 32;
    if len > 255 * HASH_LEN {
        return Err(Error::HttpProtocol(
            "HKDF output length is too large".into(),
        ));
    }

    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;

    while okm.len() < len {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);

        previous = hmac_sha256(prk, &input)
            .map_err(|err| Error::Quic(format!("HKDF expand failed: {err}")))?
            .to_vec();
        okm.extend_from_slice(&previous);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::HttpProtocol("HKDF counter overflow".into()))?;
    }

    okm.truncate(len);
    Ok(Bytes::from(okm))
}

fn packet_nonce(iv: &[u8], packet_number: u64) -> Result<[u8; AES_128_GCM_IV_LEN]> {
    if iv.len() != AES_128_GCM_IV_LEN {
        return Err(Error::HttpProtocol("invalid QUIC packet IV length".into()));
    }

    let mut nonce = [0u8; AES_128_GCM_IV_LEN];
    nonce.copy_from_slice(iv);
    let packet_number = packet_number.to_be_bytes();
    for index in 0..packet_number.len() {
        nonce[AES_128_GCM_IV_LEN - packet_number.len() + index] ^= packet_number[index];
    }
    Ok(nonce)
}

fn header_protection_sample(packet: &[u8], packet_number_offset: usize) -> Result<&[u8]> {
    let sample_offset = packet_number_offset
        .checked_add(4)
        .ok_or_else(|| Error::HttpProtocol("QUIC header protection sample overflow".into()))?;
    let sample_end = sample_offset
        .checked_add(HEADER_PROTECTION_SAMPLE_LEN)
        .ok_or_else(|| Error::HttpProtocol("QUIC header protection sample overflow".into()))?;
    if packet.len() < sample_end {
        return Err(Error::HttpProtocol(
            "truncated QUIC header protection sample".into(),
        ));
    }
    Ok(&packet[sample_offset..sample_end])
}

fn initial_packet_number_offset(packet: &[u8]) -> Result<usize> {
    let mut input = Bytes::copy_from_slice(packet);
    if input.remaining() < 6 {
        return Err(Error::HttpProtocol("truncated QUIC Initial packet".into()));
    }
    let first = input.get_u8();
    if first & HEADER_FORM_LONG == 0 {
        return Err(Error::HttpProtocol("expected QUIC long header".into()));
    }
    if first & FIXED_BIT == 0 {
        return Err(Error::HttpProtocol("missing QUIC fixed bit".into()));
    }
    if (first & LONG_PACKET_TYPE_MASK) >> 4 != 0 {
        return Err(Error::HttpProtocol("expected QUIC Initial packet".into()));
    }
    input.advance(4);
    let destination_cid_len = get_cid_len(&mut input)?;
    input.advance(destination_cid_len);
    let source_cid_len = get_cid_len(&mut input)?;
    input.advance(source_cid_len);
    let token_len = get_varint(&mut input)? as usize;
    if input.remaining() < token_len {
        return Err(Error::HttpProtocol("truncated QUIC Initial token".into()));
    }
    input.advance(token_len);
    let _payload_len = get_varint(&mut input)?;
    Ok(packet.len() - input.remaining())
}

fn read_u8_at(bytes: &[u8], offset: &mut usize, context: &str) -> Result<u8> {
    let Some(value) = bytes.get(*offset).copied() else {
        return Err(Error::HttpProtocol(context.into()));
    };
    *offset += 1;
    Ok(value)
}

fn read_u32_at(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::HttpProtocol("QUIC long-header offset overflow".into()))?;
    let Some(value) = bytes.get(*offset..end) else {
        return Err(Error::HttpProtocol("truncated QUIC long header".into()));
    };
    *offset = end;
    Ok(u32::from_be_bytes(
        value.try_into().expect("slice length checked above"),
    ))
}

fn read_bytes_at(bytes: &[u8], offset: &mut usize, len: usize, context: &str) -> Result<Bytes> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| Error::HttpProtocol("QUIC long-header offset overflow".into()))?;
    let Some(value) = bytes.get(*offset..end) else {
        return Err(Error::HttpProtocol(context.into()));
    };
    *offset = end;
    Ok(Bytes::copy_from_slice(value))
}

fn read_cid_at(bytes: &[u8], offset: &mut usize) -> Result<ConnectionId> {
    let len = read_u8_at(bytes, offset, "missing QUIC connection id length")? as usize;
    if len > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }
    let cid = read_bytes_at(bytes, offset, len, "truncated QUIC connection id")?;
    ConnectionId::from_bytes(cid)
}

fn read_varint_at(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let first = read_u8_at(bytes, offset, "truncated QUIC varint")?;
    let tag = first >> 6;
    let len = 1usize << tag;
    let mut value = (first & 0x3f) as u64;

    let remaining = len - 1;
    let end = offset
        .checked_add(remaining)
        .ok_or_else(|| Error::HttpProtocol("QUIC varint offset overflow".into()))?;
    let Some(rest) = bytes.get(*offset..end) else {
        return Err(Error::HttpProtocol("truncated QUIC varint".into()));
    };
    for byte in rest {
        value = (value << 8) | *byte as u64;
    }
    *offset = end;
    Ok(value)
}

fn get_cid_len(input: &mut Bytes) -> Result<usize> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol(
            "missing QUIC connection id length".into(),
        ));
    }
    let len = input.get_u8() as usize;
    if len > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QUIC connection id".into()));
    }
    Ok(len)
}

fn read_packet_number(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |packet_number, byte| {
        (packet_number << 8) | *byte as u64
    })
}

fn decode_frame_from(input: &mut Bytes) -> Result<QuicFrame> {
    let frame_type = get_varint(input)?;
    match frame_type {
        FRAME_PADDING => Ok(QuicFrame::Padding),
        FRAME_PING => Ok(QuicFrame::Ping),
        FRAME_ACK => decode_ack_frame(input, false),
        FRAME_ACK_ECN => decode_ack_frame(input, true),
        FRAME_CRYPTO => Ok(QuicFrame::Crypto {
            offset: get_varint(input)?,
            data: {
                let len = get_varint(input)? as usize;
                take_bytes(input, len, "truncated QUIC CRYPTO frame")?
            },
        }),
        FRAME_RESET_STREAM => Ok(QuicFrame::ResetStream {
            stream_id: get_varint(input)?,
            error_code: get_varint(input)?,
            final_size: get_varint(input)?,
        }),
        FRAME_STOP_SENDING => Ok(QuicFrame::StopSending {
            stream_id: get_varint(input)?,
            error_code: get_varint(input)?,
        }),
        FRAME_MAX_STREAM_DATA => Ok(QuicFrame::MaxStreamData {
            stream_id: get_varint(input)?,
            max_stream_data: get_varint(input)?,
        }),
        FRAME_MAX_STREAMS_BIDI => Ok(QuicFrame::MaxStreams {
            bidirectional: true,
            max_streams: get_varint(input)?,
        }),
        FRAME_MAX_STREAMS_UNI => Ok(QuicFrame::MaxStreams {
            bidirectional: false,
            max_streams: get_varint(input)?,
        }),
        FRAME_DATA_BLOCKED => Ok(QuicFrame::DataBlocked {
            maximum_data: get_varint(input)?,
        }),
        FRAME_STREAM_DATA_BLOCKED => Ok(QuicFrame::StreamDataBlocked {
            stream_id: get_varint(input)?,
            maximum_stream_data: get_varint(input)?,
        }),
        FRAME_STREAMS_BLOCKED_BIDI => Ok(QuicFrame::StreamsBlocked {
            bidirectional: true,
            maximum_streams: get_varint(input)?,
        }),
        FRAME_STREAMS_BLOCKED_UNI => Ok(QuicFrame::StreamsBlocked {
            bidirectional: false,
            maximum_streams: get_varint(input)?,
        }),
        FRAME_NEW_CONNECTION_ID => {
            let sequence_number = get_varint(input)?;
            let retire_prior_to = get_varint(input)?;
            if !input.has_remaining() {
                return Err(Error::HttpProtocol(
                    "missing QUIC NEW_CONNECTION_ID connection id length".into(),
                ));
            }
            let cid_len = input.get_u8() as usize;
            if cid_len > MAX_CID_LEN {
                return Err(Error::HttpProtocol(
                    "QUIC NEW_CONNECTION_ID connection id length exceeds 20 bytes".into(),
                ));
            }
            let connection_id = take_bytes(
                input,
                cid_len,
                "truncated QUIC NEW_CONNECTION_ID connection id",
            )?;
            let token = take_bytes(
                input,
                16,
                "truncated QUIC NEW_CONNECTION_ID stateless reset token",
            )?;
            let mut stateless_reset_token = [0u8; 16];
            stateless_reset_token.copy_from_slice(&token);
            Ok(QuicFrame::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            })
        }
        FRAME_RETIRE_CONNECTION_ID => Ok(QuicFrame::RetireConnectionId {
            sequence_number: get_varint(input)?,
        }),
        FRAME_PATH_CHALLENGE => Ok(QuicFrame::PathChallenge(take_fixed_8(
            input,
            "truncated QUIC PATH_CHALLENGE frame",
        )?)),
        FRAME_PATH_RESPONSE => Ok(QuicFrame::PathResponse(take_fixed_8(
            input,
            "truncated QUIC PATH_RESPONSE frame",
        )?)),
        FRAME_CONNECTION_CLOSE_TRANSPORT => {
            let error_code = get_varint(input)?;
            let frame_type = get_varint(input)?;
            let reason_len = get_varint(input)? as usize;
            Ok(QuicFrame::ConnectionClose {
                error_code,
                frame_type: Some(frame_type),
                reason: take_bytes(input, reason_len, "truncated QUIC CONNECTION_CLOSE reason")?,
            })
        }
        FRAME_CONNECTION_CLOSE_APPLICATION => {
            let error_code = get_varint(input)?;
            let reason_len = get_varint(input)? as usize;
            Ok(QuicFrame::ConnectionClose {
                error_code,
                frame_type: None,
                reason: take_bytes(input, reason_len, "truncated QUIC CONNECTION_CLOSE reason")?,
            })
        }
        FRAME_MAX_DATA => Ok(QuicFrame::MaxData(get_varint(input)?)),
        FRAME_HANDSHAKE_DONE => Ok(QuicFrame::HandshakeDone),
        frame_type if (FRAME_STREAM_BASE as u64..=FRAME_STREAM_MAX).contains(&frame_type) => {
            decode_stream_frame(frame_type as u8, input)
        }
        ty => Err(Error::HttpProtocol(format!(
            "unsupported QUIC frame type {ty:#x}"
        ))),
    }
}

fn decode_ack_frame(input: &mut Bytes, ecn_counts: bool) -> Result<QuicFrame> {
    let largest_acknowledged = get_varint(input)?;
    let ack_delay = get_varint(input)?;
    let range_count = get_varint(input)?;
    let first_ack_range = get_varint(input)?;
    let mut ranges = Vec::with_capacity(range_count as usize);
    for _ in 0..range_count {
        ranges.push(QuicAckRange {
            gap: get_varint(input)?,
            ack_range_length: get_varint(input)?,
        });
    }
    if ecn_counts {
        Ok(QuicFrame::AckEcn {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ranges,
            ect0_count: get_varint(input)?,
            ect1_count: get_varint(input)?,
            ce_count: get_varint(input)?,
        })
    } else {
        Ok(QuicFrame::Ack {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ranges,
        })
    }
}

fn decode_stream_frame(frame_type: u8, input: &mut Bytes) -> Result<QuicFrame> {
    let stream_id = get_varint(input)?;
    let offset = if frame_type & FRAME_STREAM_OFF != 0 {
        Some(get_varint(input)?)
    } else {
        None
    };
    let len = if frame_type & FRAME_STREAM_LEN != 0 {
        get_varint(input)? as usize
    } else {
        input.remaining()
    };
    Ok(QuicFrame::Stream {
        stream_id,
        offset,
        fin: frame_type & FRAME_STREAM_FIN != 0,
        data: take_bytes(input, len, "truncated QUIC STREAM frame")?,
    })
}

fn put_cid(out: &mut BytesMut, cid: &ConnectionId) -> Result<()> {
    validate_cid(cid)?;
    out.put_u8(cid.len() as u8);
    out.extend_from_slice(cid.as_bytes());
    Ok(())
}

fn put_transport_parameter(out: &mut BytesMut, id: u64, value: Option<u64>) {
    put_varint(out, id);
    if let Some(value) = value {
        put_varint(out, varint_len(value) as u64);
        put_varint(out, value);
    } else {
        put_varint(out, 0);
    }
}

fn put_transport_parameter_bytes(out: &mut BytesMut, id: u64, value: &[u8]) {
    put_varint(out, id);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn read_tp_varint(value: &mut Bytes) -> Result<u64> {
    let decoded = get_varint(value)?;
    if value.has_remaining() {
        return Err(Error::HttpProtocol(
            "transport parameter has trailing bytes".into(),
        ));
    }
    Ok(decoded)
}

fn get_cid(input: &mut Bytes) -> Result<ConnectionId> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol(
            "missing QUIC connection id length".into(),
        ));
    }
    let len = input.get_u8() as usize;
    if len > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QUIC connection id".into()));
    }
    ConnectionId::from_bytes(input.copy_to_bytes(len))
}

fn validate_cid(cid: &ConnectionId) -> Result<()> {
    if cid.len() > MAX_CID_LEN {
        return Err(Error::HttpProtocol(
            "QUIC connection id length exceeds 20 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_packet_number_len(len: usize) -> Result<()> {
    if !(1..=4).contains(&len) {
        return Err(Error::HttpProtocol(
            "QUIC packet number length must be 1..=4 bytes".into(),
        ));
    }
    Ok(())
}

fn put_packet_number(out: &mut BytesMut, packet_number: u64, len: usize) -> Result<()> {
    validate_packet_number_len(len)?;
    for shift in (0..len).rev().map(|index| index * 8) {
        out.put_u8((packet_number >> shift) as u8);
    }
    Ok(())
}

fn get_packet_number(input: &mut Bytes, len: usize) -> Result<u64> {
    validate_packet_number_len(len)?;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QUIC packet number".into()));
    }
    let mut packet_number = 0u64;
    for _ in 0..len {
        packet_number = (packet_number << 8) | input.get_u8() as u64;
    }
    Ok(packet_number)
}

fn take_bytes(input: &mut Bytes, len: usize, message: &'static str) -> Result<Bytes> {
    if input.remaining() < len {
        return Err(Error::HttpProtocol(message.into()));
    }
    Ok(input.copy_to_bytes(len))
}

fn take_fixed_8(input: &mut Bytes, message: &'static str) -> Result<[u8; 8]> {
    let bytes = take_bytes(input, 8, message)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn put_varint(out: &mut BytesMut, value: u64) {
    match value {
        0..=0x3f => out.put_u8(value as u8),
        0x40..=0x3fff => out.put_u16((value as u16) | 0x4000),
        0x4000..=0x3fff_ffff => out.put_u32((value as u32) | 0x8000_0000),
        _ => out.put_u64(value | 0xc000_0000_0000_0000),
    }
}

fn get_varint(input: &mut Bytes) -> Result<u64> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol("missing QUIC varint".into()));
    }
    let first = input[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QUIC varint".into()));
    }

    Ok(match len {
        1 => input.get_u8() as u64 & 0x3f,
        2 => input.get_u16() as u64 & 0x3fff,
        4 => input.get_u32() as u64 & 0x3fff_ffff,
        8 => input.get_u64() & 0x3fff_ffff_ffff_ffff,
        _ => unreachable!(),
    })
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}
