//! RFC 9002 packet-space recovery, RTT estimation, congestion control, and PTO
//! state for the native QUIC transport.
//!
//! The state machine here is pure logic with no IO. It is driven by the QUIC
//! send and receive paths in `handshake.rs` and `native_driver.rs`: every QUIC
//! packet send calls `on_packet_sent` for the appropriate
//! [`PacketNumberSpace`], every received ACK frame calls `on_ack_received`, and
//! a single `loss_detection_timer` deadline is exposed for the driver to wake
//! on. When that deadline fires, the driver calls `on_loss_detection_timeout`,
//! which either declares time-threshold losses or schedules a PTO probe in the
//! earliest space.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::transport::h3::quic::QuicFrame;

/// RFC 9002 packet number spaces. Ordering matches RFC discard order
/// (Initial < Handshake < Application).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketNumberSpace {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

impl PacketNumberSpace {
    pub const ALL: [PacketNumberSpace; 3] = [
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::Application,
    ];

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentPacketInfo {
    pub sent_at: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    pub in_flight: bool,
}

impl SentPacketInfo {
    pub fn new(sent_at: Instant, size: usize, ack_eliciting: bool, in_flight: bool) -> Self {
        Self {
            sent_at,
            size,
            ack_eliciting,
            in_flight,
        }
    }
}

const K_PACKET_THRESHOLD: u64 = 3;
const K_TIME_THRESHOLD_NUMERATOR: u32 = 9;
const K_TIME_THRESHOLD_DENOMINATOR: u32 = 8;
const K_GRANULARITY: Duration = Duration::from_millis(1);
const K_INITIAL_RTT: Duration = Duration::from_millis(333);
const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;
const K_INITIAL_WINDOW_PACKETS: u64 = 10;
const K_MIN_CWND_PACKETS: u64 = 2;
const K_DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;
const K_DEFAULT_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// RFC 9002 A.7 RTT estimator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RttEstimator {
    latest_rtt: Option<Duration>,
    smoothed_rtt: Option<Duration>,
    rttvar: Option<Duration>,
    min_rtt: Option<Duration>,
    first_rtt_sample: Option<Instant>,
    max_ack_delay: Duration,
}

impl RttEstimator {
    pub fn new(max_ack_delay: Duration) -> Self {
        Self {
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: None,
            min_rtt: None,
            first_rtt_sample: None,
            max_ack_delay,
        }
    }

    pub fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(K_INITIAL_RTT)
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar.unwrap_or(K_INITIAL_RTT / 2)
    }

    pub fn first_rtt_sample(&self) -> Option<Instant> {
        self.first_rtt_sample
    }

    pub fn has_sample(&self) -> bool {
        self.smoothed_rtt.is_some()
    }

    pub fn max_ack_delay(&self) -> Duration {
        self.max_ack_delay
    }

    pub fn set_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
    }

    /// RFC 9002 5.3 RTT sample update.
    pub fn update(
        &mut self,
        latest_rtt: Duration,
        ack_delay: Duration,
        handshake_complete: bool,
        sample_time: Instant,
    ) {
        self.latest_rtt = Some(latest_rtt);
        let min_rtt = match self.min_rtt {
            Some(prev) => prev.min(latest_rtt),
            None => latest_rtt,
        };
        self.min_rtt = Some(min_rtt);

        let bounded_ack_delay = if handshake_complete {
            ack_delay.min(self.max_ack_delay)
        } else {
            ack_delay
        };
        let mut adjusted_rtt = latest_rtt;
        if latest_rtt >= min_rtt.saturating_add(bounded_ack_delay) {
            adjusted_rtt = latest_rtt - bounded_ack_delay;
        }

        match (self.smoothed_rtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                let diff = if srtt > adjusted_rtt {
                    srtt - adjusted_rtt
                } else {
                    adjusted_rtt - srtt
                };
                let new_rttvar = (rttvar * 3 + diff) / 4;
                let new_srtt = (srtt * 7 + adjusted_rtt) / 8;
                self.rttvar = Some(new_rttvar);
                self.smoothed_rtt = Some(new_srtt);
            }
            _ => {
                self.smoothed_rtt = Some(adjusted_rtt);
                self.rttvar = Some(adjusted_rtt / 2);
                self.first_rtt_sample = Some(sample_time);
            }
        }
    }
}

/// RFC 9002 6.2.1 base PTO contribution (excluding `max_ack_delay`).
fn pto_base(rtt: &RttEstimator) -> Duration {
    rtt.smoothed_rtt()
        .saturating_add(K_GRANULARITY.max(rtt.rttvar() * 4))
}

/// Per packet-number-space recovery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSpaceRecovery {
    sent_packets: BTreeMap<u64, SentPacketInfo>,
    largest_acked: Option<u64>,
    loss_time: Option<Instant>,
    time_of_last_ack_eliciting_packet: Option<Instant>,
    ecn_ce_count: u64,
}

impl PacketSpaceRecovery {
    fn new() -> Self {
        Self {
            sent_packets: BTreeMap::new(),
            largest_acked: None,
            loss_time: None,
            time_of_last_ack_eliciting_packet: None,
            ecn_ce_count: 0,
        }
    }

    pub fn sent_packets(&self) -> &BTreeMap<u64, SentPacketInfo> {
        &self.sent_packets
    }

    pub fn largest_acked(&self) -> Option<u64> {
        self.largest_acked
    }

    pub fn loss_time(&self) -> Option<Instant> {
        self.loss_time
    }

    pub fn time_of_last_ack_eliciting_packet(&self) -> Option<Instant> {
        self.time_of_last_ack_eliciting_packet
    }

    pub fn has_ack_eliciting_in_flight(&self) -> bool {
        self.sent_packets
            .values()
            .any(|p| p.in_flight && p.ack_eliciting)
    }

    pub fn in_flight_bytes(&self) -> u64 {
        self.sent_packets
            .values()
            .filter(|p| p.in_flight)
            .map(|p| p.size as u64)
            .sum()
    }
}

/// RFC 9002 NewReno congestion control (minimum implementation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionController {
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    max_datagram_size: u64,
    congestion_recovery_start_time: Option<Instant>,
}

impl CongestionController {
    pub fn new(max_datagram_size: u64) -> Self {
        let max_datagram_size = max_datagram_size.max(1);
        Self {
            cwnd: K_INITIAL_WINDOW_PACKETS.saturating_mul(max_datagram_size),
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            max_datagram_size,
            congestion_recovery_start_time: None,
        }
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }

    pub fn max_datagram_size(&self) -> u64 {
        self.max_datagram_size
    }

    pub fn set_max_datagram_size(&mut self, max_datagram_size: u64) {
        let max_datagram_size = max_datagram_size.max(1);
        self.max_datagram_size = max_datagram_size;
    }

    fn on_packet_sent(&mut self, size: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(size);
    }

    fn on_packet_acked(&mut self, info: &SentPacketInfo) {
        if !info.in_flight {
            return;
        }
        let size = info.size as u64;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);

        if self.in_congestion_recovery(info.sent_at) {
            return;
        }

        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(size);
        } else {
            let increment = self
                .max_datagram_size
                .saturating_mul(size)
                .checked_div(self.cwnd.max(1))
                .unwrap_or(0);
            self.cwnd = self.cwnd.saturating_add(increment);
        }
    }

    fn on_packet_discarded(&mut self, info: &SentPacketInfo) {
        if !info.in_flight {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(info.size as u64);
    }

    fn on_congestion_event(&mut self, sent_at: Instant, now: Instant) {
        if self.in_congestion_recovery(sent_at) {
            return;
        }
        self.congestion_recovery_start_time = Some(now);
        self.cwnd = (self.cwnd / 2).max(self.max_datagram_size.saturating_mul(K_MIN_CWND_PACKETS));
        self.ssthresh = self.cwnd;
    }

    fn in_congestion_recovery(&self, sent_at: Instant) -> bool {
        match self.congestion_recovery_start_time {
            Some(start) => sent_at <= start,
            None => false,
        }
    }

    fn on_persistent_congestion(&mut self) {
        self.cwnd = self
            .max_datagram_size
            .saturating_mul(K_MIN_CWND_PACKETS);
        self.congestion_recovery_start_time = None;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckOutcome {
    pub newly_acked: Vec<(u64, SentPacketInfo)>,
    pub lost: Vec<(u64, SentPacketInfo)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossDetectionOutcome {
    Loss {
        space: PacketNumberSpace,
        lost: Vec<(u64, SentPacketInfo)>,
    },
    Pto {
        space: PacketNumberSpace,
    },
    Idle,
}

/// Aggregate RFC 9002 recovery state for one QUIC connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    rtt: RttEstimator,
    spaces: [PacketSpaceRecovery; 3],
    congestion: CongestionController,
    pto_count: u32,
    peer_completed_address_validation: bool,
    handshake_complete: bool,
    has_handshake_keys: bool,
    max_ack_delay: Duration,
    packet_threshold: u64,
    time_threshold_numerator: u32,
    time_threshold_denominator: u32,
    granularity: Duration,
    persistent_congestion_threshold: u32,
    loss_detection_timer: Option<Instant>,
    discarded_spaces: [bool; 3],
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new(K_DEFAULT_MAX_ACK_DELAY, K_DEFAULT_MAX_DATAGRAM_SIZE)
    }
}

impl RecoveryState {
    pub fn new(max_ack_delay: Duration, max_datagram_size: u64) -> Self {
        Self {
            rtt: RttEstimator::new(max_ack_delay),
            spaces: [
                PacketSpaceRecovery::new(),
                PacketSpaceRecovery::new(),
                PacketSpaceRecovery::new(),
            ],
            congestion: CongestionController::new(max_datagram_size),
            pto_count: 0,
            peer_completed_address_validation: false,
            handshake_complete: false,
            has_handshake_keys: false,
            max_ack_delay,
            packet_threshold: K_PACKET_THRESHOLD,
            time_threshold_numerator: K_TIME_THRESHOLD_NUMERATOR,
            time_threshold_denominator: K_TIME_THRESHOLD_DENOMINATOR,
            granularity: K_GRANULARITY,
            persistent_congestion_threshold: K_PERSISTENT_CONGESTION_THRESHOLD,
            loss_detection_timer: None,
            discarded_spaces: [false; 3],
        }
    }

    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    pub fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    pub fn space(&self, space: PacketNumberSpace) -> &PacketSpaceRecovery {
        &self.spaces[space.index()]
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn max_ack_delay(&self) -> Duration {
        self.max_ack_delay
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    pub fn peer_completed_address_validation(&self) -> bool {
        self.peer_completed_address_validation
    }

    pub fn set_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
        self.rtt.set_max_ack_delay(max_ack_delay);
        self.update_loss_detection_timer();
    }

    pub fn set_max_datagram_size(&mut self, max_datagram_size: u64) {
        self.congestion.set_max_datagram_size(max_datagram_size);
    }

    pub fn set_packet_threshold(&mut self, threshold: u64) {
        self.packet_threshold = threshold.max(1);
    }

    pub fn set_has_handshake_keys(&mut self, value: bool) {
        self.has_handshake_keys = value;
        self.update_loss_detection_timer();
    }

    pub fn set_peer_completed_address_validation(&mut self, value: bool) {
        self.peer_completed_address_validation = value;
        self.update_loss_detection_timer();
    }

    /// RFC 9002 6.3 "after the handshake is confirmed". Sets Application PTO
    /// to include `max_ack_delay` and unblocks anti-deadlock fallbacks.
    pub fn mark_handshake_complete(&mut self) {
        self.handshake_complete = true;
        self.peer_completed_address_validation = true;
        self.update_loss_detection_timer();
    }

    /// RFC 9002 6.4 packet-number-space discard. Drops in-flight bookkeeping
    /// for that space and resets `pto_count` because the peer has confirmed
    /// progress past that space.
    pub fn discard_space(&mut self, space: PacketNumberSpace) {
        let index = space.index();
        if self.discarded_spaces[index] {
            return;
        }
        let sent = std::mem::take(&mut self.spaces[index].sent_packets);
        for (_, info) in sent {
            self.congestion.on_packet_discarded(&info);
        }
        self.spaces[index] = PacketSpaceRecovery::new();
        self.discarded_spaces[index] = true;
        self.pto_count = 0;
        self.update_loss_detection_timer();
    }

    /// RFC 9002 6.1 OnPacketSent.
    pub fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        info: SentPacketInfo,
    ) {
        if self.discarded_spaces[space.index()] {
            return;
        }
        if info.in_flight {
            self.congestion.on_packet_sent(info.size as u64);
            if info.ack_eliciting {
                self.spaces[space.index()].time_of_last_ack_eliciting_packet = Some(info.sent_at);
            }
        }
        self.spaces[space.index()]
            .sent_packets
            .insert(packet_number, info);
        self.update_loss_detection_timer();
    }

    /// RFC 9002 6.1 OnAckReceived. Returns newly acked + newly lost packets.
    pub fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        frame: &QuicFrame,
        ack_delay_exponent: u64,
        now: Instant,
    ) -> Result<AckOutcome> {
        if self.discarded_spaces[space.index()] {
            return Ok(AckOutcome::default());
        }

        let (largest_acknowledged, ack_delay, first_ack_range, ranges, ce_count) = match frame {
            QuicFrame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ranges,
            } => (
                *largest_acknowledged,
                *ack_delay,
                *first_ack_range,
                ranges.as_slice(),
                None,
            ),
            QuicFrame::AckEcn {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ranges,
                ce_count,
                ..
            } => (
                *largest_acknowledged,
                *ack_delay,
                *first_ack_range,
                ranges.as_slice(),
                Some(*ce_count),
            ),
            _ => return Ok(AckOutcome::default()),
        };

        let mut acked: Vec<(u64, SentPacketInfo)> = Vec::new();
        let mut smallest = self.consume_range(space, largest_acknowledged, first_ack_range, &mut acked);
        for range in ranges {
            let gap = range.gap.saturating_add(2);
            let Some(anchor) = smallest else { break };
            let Some(largest_in_range) = anchor.checked_sub(gap) else { break };
            smallest = self.consume_range(
                space,
                largest_in_range,
                range.ack_range_length,
                &mut acked,
            );
        }

        if acked.is_empty() {
            // ACK_ECN CE growth still informs congestion control even without newly
            // acked packets, but bookkeeping is unaffected so we skip RTT updates.
            self.update_loss_detection_timer();
            return Ok(AckOutcome::default());
        }

        let pkt_space = &mut self.spaces[space.index()];
        pkt_space.largest_acked = Some(match pkt_space.largest_acked {
            Some(prev) => prev.max(largest_acknowledged),
            None => largest_acknowledged,
        });

        if let Some((_, info)) = acked.iter().find(|(pn, _)| *pn == largest_acknowledged) {
            if info.ack_eliciting {
                let latest_rtt = now.saturating_duration_since(info.sent_at);
                let shift = ack_delay_exponent.min(62) as u32;
                let scaled_delay_us = ack_delay.saturating_mul(1u64.checked_shl(shift).unwrap_or(0));
                let ack_delay_duration = Duration::from_micros(scaled_delay_us);
                self.rtt
                    .update(latest_rtt, ack_delay_duration, self.handshake_complete, now);
            }
        }

        for (_, info) in &acked {
            self.congestion.on_packet_acked(info);
        }

        if let Some(ce_count) = ce_count {
            let pkt_space = &mut self.spaces[space.index()];
            if ce_count > pkt_space.ecn_ce_count {
                pkt_space.ecn_ce_count = ce_count;
                if let Some((_, oldest)) = acked.iter().min_by_key(|(_, info)| info.sent_at) {
                    self.congestion.on_congestion_event(oldest.sent_at, now);
                }
            }
        }

        let lost = self.detect_and_remove_lost_packets(space, now);

        let any_ack_eliciting = acked.iter().any(|(_, info)| info.ack_eliciting);
        if any_ack_eliciting {
            self.pto_count = 0;
            if space == PacketNumberSpace::Handshake {
                self.peer_completed_address_validation = true;
            }
        }

        self.update_loss_detection_timer();

        Ok(AckOutcome {
            newly_acked: acked,
            lost,
        })
    }

    fn consume_range(
        &mut self,
        space: PacketNumberSpace,
        largest: u64,
        length: u64,
        acked: &mut Vec<(u64, SentPacketInfo)>,
    ) -> Option<u64> {
        let smallest = largest.checked_sub(length)?;
        let candidates: Vec<u64> = self.spaces[space.index()]
            .sent_packets
            .range(smallest..=largest)
            .map(|(pn, _)| *pn)
            .collect();
        for pn in candidates {
            if let Some(info) = self.spaces[space.index()].sent_packets.remove(&pn) {
                acked.push((pn, info));
            }
        }
        Some(smallest)
    }

    fn detect_and_remove_lost_packets(
        &mut self,
        space: PacketNumberSpace,
        now: Instant,
    ) -> Vec<(u64, SentPacketInfo)> {
        let index = space.index();
        self.spaces[index].loss_time = None;
        let Some(largest_acked) = self.spaces[index].largest_acked else {
            return Vec::new();
        };

        let loss_delay_base = match (self.rtt.latest_rtt, self.rtt.smoothed_rtt) {
            (Some(latest), Some(srtt)) => latest.max(srtt),
            _ => K_INITIAL_RTT,
        };
        let loss_delay = (loss_delay_base * self.time_threshold_numerator
            / self.time_threshold_denominator)
            .max(self.granularity);
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);

        let mut lost: Vec<(u64, SentPacketInfo)> = Vec::new();
        let mut new_loss_time: Option<Instant> = None;

        let candidates: Vec<(u64, SentPacketInfo)> = self.spaces[index]
            .sent_packets
            .range(..=largest_acked)
            .map(|(pn, info)| (*pn, *info))
            .collect();
        for (pn, info) in candidates {
            if pn > largest_acked {
                continue;
            }
            let pn_threshold_met = largest_acked
                .checked_sub(pn)
                .is_some_and(|gap| gap >= self.packet_threshold);
            if info.sent_at <= lost_send_time || pn_threshold_met {
                self.spaces[index].sent_packets.remove(&pn);
                lost.push((pn, info));
            } else {
                let candidate = info.sent_at + loss_delay;
                new_loss_time = Some(match new_loss_time {
                    Some(prev) => prev.min(candidate),
                    None => candidate,
                });
            }
        }
        self.spaces[index].loss_time = new_loss_time;

        if !lost.is_empty() {
            let in_flight_lost: Vec<&SentPacketInfo> = lost
                .iter()
                .filter_map(|(_, info)| if info.in_flight { Some(info) } else { None })
                .collect();
            if let Some(earliest) = in_flight_lost.iter().map(|i| i.sent_at).min() {
                self.congestion.on_congestion_event(earliest, now);
            }
            for (_, info) in &lost {
                self.congestion.on_packet_discarded(info);
            }
            self.check_persistent_congestion(&lost);
        }

        lost
    }

    fn check_persistent_congestion(&mut self, lost: &[(u64, SentPacketInfo)]) {
        if !self.rtt.has_sample() {
            return;
        }
        if self.rtt.first_rtt_sample.is_none() {
            return;
        }
        let mut ack_eliciting_in_flight: Vec<&SentPacketInfo> = lost
            .iter()
            .filter_map(|(_, info)| {
                if info.in_flight && info.ack_eliciting {
                    Some(info)
                } else {
                    None
                }
            })
            .collect();
        ack_eliciting_in_flight.sort_by_key(|i| i.sent_at);
        if ack_eliciting_in_flight.len() < 2 {
            return;
        }
        let pc_duration = (self.rtt.smoothed_rtt()
            + self.rtt.rttvar() * 4
            + self.max_ack_delay)
            * self.persistent_congestion_threshold;
        let first = ack_eliciting_in_flight.first().unwrap();
        let last = ack_eliciting_in_flight.last().unwrap();
        let span = last.sent_at.saturating_duration_since(first.sent_at);
        if span >= pc_duration {
            self.congestion.on_persistent_congestion();
        }
    }

    fn earliest_loss_time(&self) -> Option<(PacketNumberSpace, Instant)> {
        let mut earliest: Option<(PacketNumberSpace, Instant)> = None;
        for space in PacketNumberSpace::ALL {
            let Some(t) = self.spaces[space.index()].loss_time else {
                continue;
            };
            earliest = Some(match earliest {
                Some((_, prev)) if prev <= t => earliest.unwrap(),
                _ => (space, t),
            });
        }
        earliest
    }

    /// RFC 9002 6.2.2 GetPtoTimeAndSpace.
    pub fn pto_time_and_space(&self) -> Option<(PacketNumberSpace, Instant)> {
        let base = pto_base(&self.rtt);
        let backoff = 1u32 << self.pto_count.min(31);
        let duration = base.saturating_mul(backoff);

        let any_in_flight = PacketNumberSpace::ALL
            .iter()
            .any(|&s| self.spaces[s.index()].has_ack_eliciting_in_flight());
        if !any_in_flight {
            if self.peer_completed_address_validation {
                return None;
            }
            let space = if self.has_handshake_keys {
                PacketNumberSpace::Handshake
            } else {
                PacketNumberSpace::Initial
            };
            return Some((space, Instant::now() + duration));
        }

        let mut earliest: Option<(PacketNumberSpace, Instant)> = None;
        for space in PacketNumberSpace::ALL {
            let pkt_space = &self.spaces[space.index()];
            if !pkt_space.has_ack_eliciting_in_flight() {
                continue;
            }
            let mut space_duration = duration;
            if space == PacketNumberSpace::Application {
                if !self.handshake_complete {
                    continue;
                }
                space_duration = space_duration
                    .saturating_add(self.max_ack_delay.saturating_mul(backoff));
            }
            let Some(last) = pkt_space.time_of_last_ack_eliciting_packet else {
                continue;
            };
            let timeout = last + space_duration;
            earliest = Some(match earliest {
                Some((_, prev)) if prev <= timeout => earliest.unwrap(),
                _ => (space, timeout),
            });
        }
        earliest
    }

    /// RFC 9002 6.2.1 SetLossDetectionTimer (refresh `loss_detection_timer`).
    pub fn update_loss_detection_timer(&mut self) {
        if let Some((_, t)) = self.earliest_loss_time() {
            self.loss_detection_timer = Some(t);
            return;
        }
        let any_in_flight = PacketNumberSpace::ALL
            .iter()
            .any(|&s| self.spaces[s.index()].has_ack_eliciting_in_flight());
        if !any_in_flight && self.peer_completed_address_validation {
            self.loss_detection_timer = None;
            return;
        }
        self.loss_detection_timer = self.pto_time_and_space().map(|(_, t)| t);
    }

    /// RFC 9002 6.2.1 OnLossDetectionTimeout.
    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> LossDetectionOutcome {
        if let Some((space, _)) = self.earliest_loss_time() {
            let lost = self.detect_and_remove_lost_packets(space, now);
            self.update_loss_detection_timer();
            return LossDetectionOutcome::Loss { space, lost };
        }
        let Some((space, _)) = self.pto_time_and_space() else {
            self.update_loss_detection_timer();
            return LossDetectionOutcome::Idle;
        };
        self.pto_count = self.pto_count.saturating_add(1);
        self.update_loss_detection_timer();
        LossDetectionOutcome::Pto { space }
    }

    pub fn current_pto(&self) -> Duration {
        let base = pto_base(&self.rtt);
        let backoff = 1u32 << self.pto_count.min(31);
        base.saturating_mul(backoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(sent_at: Instant, size: usize) -> SentPacketInfo {
        SentPacketInfo::new(sent_at, size, true, true)
    }

    fn ack_frame(largest: u64, ack_delay: u64) -> QuicFrame {
        QuicFrame::Ack {
            largest_acknowledged: largest,
            ack_delay,
            first_ack_range: 0,
            ranges: Vec::new(),
        }
    }

    fn ack_frame_range(largest: u64, first_ack_range: u64) -> QuicFrame {
        QuicFrame::Ack {
            largest_acknowledged: largest,
            ack_delay: 0,
            first_ack_range,
            ranges: Vec::new(),
        }
    }

    #[test]
    fn rtt_estimator_first_sample_initialises_smoothed_and_var() {
        let mut rtt = RttEstimator::new(Duration::from_millis(25));
        let now = Instant::now();
        rtt.update(
            Duration::from_millis(80),
            Duration::ZERO,
            false,
            now,
        );
        assert_eq!(rtt.smoothed_rtt(), Duration::from_millis(80));
        assert_eq!(rtt.rttvar(), Duration::from_millis(40));
        assert_eq!(rtt.latest_rtt(), Some(Duration::from_millis(80)));
        assert_eq!(rtt.min_rtt(), Some(Duration::from_millis(80)));
        assert!(rtt.first_rtt_sample().is_some());
    }

    #[test]
    fn rtt_estimator_subsequent_sample_weights_existing_smoothed() {
        let mut rtt = RttEstimator::new(Duration::from_millis(25));
        let now = Instant::now();
        rtt.update(Duration::from_millis(80), Duration::ZERO, false, now);
        rtt.update(Duration::from_millis(40), Duration::ZERO, false, now);
        let srtt = rtt.smoothed_rtt();
        let rttvar = rtt.rttvar();
        assert_eq!(srtt, Duration::from_millis(75));
        assert_eq!(rttvar, Duration::from_millis(40));
        assert_eq!(rtt.min_rtt(), Some(Duration::from_millis(40)));
    }

    #[test]
    fn rtt_estimator_subtracts_ack_delay_when_within_min_rtt() {
        let mut rtt = RttEstimator::new(Duration::from_millis(20));
        let now = Instant::now();
        rtt.update(
            Duration::from_millis(50),
            Duration::ZERO,
            false,
            now,
        );
        rtt.update(
            Duration::from_millis(70),
            Duration::from_millis(15),
            true,
            now,
        );
        assert_eq!(rtt.min_rtt(), Some(Duration::from_millis(50)));
        assert_eq!(rtt.smoothed_rtt(), Duration::from_millis(51));
    }

    #[test]
    fn recovery_on_ack_updates_rtt_and_clears_acked_packets() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        let sent_at = now - Duration::from_millis(75);
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(sent_at, 1200),
        );
        let frame = ack_frame(1, 0);
        let outcome = recovery
            .on_ack_received(PacketNumberSpace::Application, &frame, 3, now)
            .expect("ack");
        assert_eq!(outcome.newly_acked.len(), 1);
        assert_eq!(outcome.lost.len(), 0);
        assert_eq!(
            recovery
                .space(PacketNumberSpace::Application)
                .sent_packets()
                .len(),
            0
        );
        assert!(recovery.rtt().has_sample());
        assert_eq!(recovery.rtt().latest_rtt(), Some(Duration::from_millis(75)));
        assert_eq!(recovery.pto_count(), 0);
        assert_eq!(recovery.congestion().bytes_in_flight(), 0);
    }

    #[test]
    fn recovery_on_packet_sent_tracks_bytes_in_flight() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.on_packet_sent(PacketNumberSpace::Initial, 1, meta(now, 1200));
        recovery.on_packet_sent(PacketNumberSpace::Initial, 2, meta(now, 800));
        assert_eq!(recovery.congestion().bytes_in_flight(), 2000);

        let frame = ack_frame_range(2, 1);
        let outcome = recovery
            .on_ack_received(PacketNumberSpace::Initial, &frame, 3, now)
            .expect("ack");
        assert_eq!(outcome.newly_acked.len(), 2);
        assert_eq!(recovery.congestion().bytes_in_flight(), 0);
    }

    #[test]
    fn recovery_packet_threshold_marks_old_unacked_packet_lost() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        for pn in 1..=4u64 {
            recovery.on_packet_sent(
                PacketNumberSpace::Application,
                pn,
                meta(now, 1200),
            );
        }
        let frame = ack_frame(4, 0);
        let outcome = recovery
            .on_ack_received(PacketNumberSpace::Application, &frame, 3, now)
            .expect("ack");
        let lost_pns: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
        assert_eq!(lost_pns, vec![1]);
        let still_in_flight = recovery
            .space(PacketNumberSpace::Application)
            .sent_packets()
            .len();
        assert_eq!(still_in_flight, 2);
    }

    #[test]
    fn recovery_time_threshold_marks_old_packet_lost_after_loss_delay() {
        let mut recovery = RecoveryState::default();
        let base = Instant::now();
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(base, 1200),
        );
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            2,
            meta(base + Duration::from_millis(1000), 1200),
        );
        let ack_time = base + Duration::from_millis(1075);
        let frame = ack_frame(2, 0);
        let outcome = recovery
            .on_ack_received(PacketNumberSpace::Application, &frame, 3, ack_time)
            .expect("ack");
        let lost_pns: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
        assert_eq!(lost_pns, vec![1]);
    }

    #[test]
    fn recovery_pto_timer_arms_to_last_ack_eliciting_plus_pto() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.set_peer_completed_address_validation(true);
        recovery.mark_handshake_complete();
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(now, 1200),
        );
        let timer = recovery.loss_detection_timer().expect("timer armed");
        let pto = recovery.current_pto() + recovery.max_ack_delay();
        let expected = now + pto;
        let drift = if expected > timer {
            expected - timer
        } else {
            timer - expected
        };
        assert!(drift <= Duration::from_micros(1));
    }

    #[test]
    fn recovery_pto_timeout_doubles_pto_count() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.set_peer_completed_address_validation(true);
        recovery.mark_handshake_complete();
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(now, 1200),
        );
        assert_eq!(recovery.pto_count(), 0);
        let outcome = recovery.on_loss_detection_timeout(now);
        match outcome {
            LossDetectionOutcome::Pto { space } => {
                assert_eq!(space, PacketNumberSpace::Application);
            }
            other => panic!("expected PTO outcome, got {other:?}"),
        }
        assert_eq!(recovery.pto_count(), 1);
    }

    #[test]
    fn recovery_pto_count_resets_on_ack_eliciting_ack() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.set_peer_completed_address_validation(true);
        recovery.mark_handshake_complete();
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(now, 1200),
        );
        let _ = recovery.on_loss_detection_timeout(now);
        assert_eq!(recovery.pto_count(), 1);
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            2,
            meta(now, 1200),
        );
        let frame = ack_frame(2, 0);
        let _ = recovery
            .on_ack_received(PacketNumberSpace::Application, &frame, 3, now + Duration::from_millis(50))
            .expect("ack");
        assert_eq!(recovery.pto_count(), 0);
    }

    #[test]
    fn recovery_pto_target_initial_when_no_handshake_keys_and_no_in_flight() {
        let mut recovery = RecoveryState::default();
        recovery.set_peer_completed_address_validation(false);
        recovery.set_has_handshake_keys(false);
        let space = recovery
            .pto_time_and_space()
            .expect("anti-deadlock pto")
            .0;
        assert_eq!(space, PacketNumberSpace::Initial);
    }

    #[test]
    fn recovery_pto_target_handshake_when_handshake_keys_present_and_no_in_flight() {
        let mut recovery = RecoveryState::default();
        recovery.set_peer_completed_address_validation(false);
        recovery.set_has_handshake_keys(true);
        let space = recovery
            .pto_time_and_space()
            .expect("anti-deadlock pto")
            .0;
        assert_eq!(space, PacketNumberSpace::Handshake);
    }

    #[test]
    fn recovery_per_space_pto_picks_earliest_in_flight_space() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.set_has_handshake_keys(true);
        recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            1,
            meta(now, 1200),
        );
        recovery.on_packet_sent(
            PacketNumberSpace::Handshake,
            1,
            meta(now + Duration::from_millis(20), 1200),
        );
        let (space, _) = recovery.pto_time_and_space().expect("pto");
        assert_eq!(space, PacketNumberSpace::Initial);
    }

    #[test]
    fn recovery_discard_space_resets_bytes_in_flight_and_pto_count() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            1,
            meta(now, 1200),
        );
        recovery.on_packet_sent(
            PacketNumberSpace::Initial,
            2,
            meta(now, 800),
        );
        let _ = recovery.on_loss_detection_timeout(now);
        recovery.discard_space(PacketNumberSpace::Initial);
        assert_eq!(recovery.pto_count(), 0);
        assert_eq!(recovery.congestion().bytes_in_flight(), 0);
        assert!(recovery
            .space(PacketNumberSpace::Initial)
            .sent_packets()
            .is_empty());
    }

    #[test]
    fn recovery_persistent_congestion_collapses_cwnd_to_minimum_window() {
        let mut recovery = RecoveryState::default();
        let now = Instant::now();
        recovery.set_peer_completed_address_validation(true);
        recovery.mark_handshake_complete();
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            0,
            meta(now - Duration::from_millis(50), 1200),
        );
        let ack_frame = ack_frame(0, 0);
        let _ = recovery
            .on_ack_received(
                PacketNumberSpace::Application,
                &ack_frame,
                3,
                now - Duration::from_millis(40),
            )
            .expect("ack");
        let pc_unit = recovery.rtt().smoothed_rtt()
            + recovery.rtt().rttvar() * 4
            + recovery.max_ack_delay();
        let span = pc_unit * K_PERSISTENT_CONGESTION_THRESHOLD as u32 + Duration::from_millis(10);
        let first_sent = now;
        let last_sent = first_sent + span;
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            1,
            meta(first_sent, 1200),
        );
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            2,
            meta(last_sent, 1200),
        );
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            5,
            meta(last_sent + Duration::from_millis(1), 1200),
        );
        let frame = ack_frame(5, 0);
        let outcome = recovery
            .on_ack_received(
                PacketNumberSpace::Application,
                &frame,
                3,
                last_sent + Duration::from_millis(2),
            )
            .expect("ack");
        let lost_pns: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
        assert!(lost_pns.contains(&1) && lost_pns.contains(&2));
        let min_cwnd = recovery.congestion().max_datagram_size() * K_MIN_CWND_PACKETS;
        assert_eq!(recovery.congestion().cwnd(), min_cwnd);
    }
}
