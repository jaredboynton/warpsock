//! Native QUIC path validation, connection-ID inventory, and anti-amplification
//! primitives.
//!
//! Implements the RFC 9000 § 5.1 / § 8.1 / § 9 state needed to support path
//! migration beyond the existing `QuicPathValidator` token tracker:
//!
//! - `QuicAntiAmplificationLimit` enforces the RFC 9000 § 8.1 3x send budget
//!   that protects unvalidated peer addresses from being used to amplify
//!   traffic toward third parties.
//! - `QuicConnectionIdInventory` tracks locally issued connection IDs (RFC 9000
//!   § 5.1.1) and peer-issued connection IDs (RFC 9000 § 5.1.2), processes
//!   NEW_CONNECTION_ID (RFC 9000 § 19.15) and RETIRE_CONNECTION_ID (RFC 9000
//!   § 19.16) frames, enforces `active_connection_id_limit` (RFC 9000 § 18.2),
//!   and surfaces retire-prior-to obligations as outbound frame work.
//! - `QuicPathState` / `QuicPath` / `QuicPathSet` track the RFC 9000 § 9
//!   primary path and any probing paths during a migration attempt, including
//!   per-path anti-amplification accounting and pending PATH_CHALLENGE tokens.
//!
//! Driver / handshake integration (issuing NEW_CONNECTION_ID after handshake
//! completion, switching the active path on validation success, gating
//! outbound packet builders on the anti-amplification budget) is layered on
//! top of these primitives.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::transport::h3::quic::ConnectionId;

/// RFC 9000 § 18.2 minimum value for `active_connection_id_limit`. A peer must
/// be willing to track at least two connection IDs in addition to the one used
/// during the handshake; we enforce the same floor for our own inventory.
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// RFC 9000 § 8.1 anti-amplification factor. Until a peer address is
/// validated, an endpoint must not send more than three times the amount of
/// data it has received from that address.
pub const ANTI_AMPLIFICATION_FACTOR: u64 = 3;

/// RFC 9000 § 8.1 per-path send budget tracker. Until the path is validated,
/// the endpoint may not send more than `ANTI_AMPLIFICATION_FACTOR * bytes_received`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicAntiAmplificationLimit {
    bytes_received: u64,
    bytes_sent: u64,
    validated: bool,
}

impl QuicAntiAmplificationLimit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn validated(&self) -> bool {
        self.validated
    }

    /// Mark the path as validated, removing the 3x cap (RFC 9000 § 8.1).
    pub fn mark_validated(&mut self) {
        self.validated = true;
    }

    pub fn on_received(&mut self, len: usize) {
        self.bytes_received = self.bytes_received.saturating_add(len as u64);
    }

    pub fn on_sent(&mut self, len: usize) {
        self.bytes_sent = self.bytes_sent.saturating_add(len as u64);
    }

    /// Remaining send budget before the 3x cap is hit. Returns `u64::MAX` once
    /// the path is validated.
    pub fn remaining_send_budget(&self) -> u64 {
        if self.validated {
            return u64::MAX;
        }
        let allowance = self
            .bytes_received
            .saturating_mul(ANTI_AMPLIFICATION_FACTOR);
        allowance.saturating_sub(self.bytes_sent)
    }

    /// Whether sending `additional_bytes` is permitted under the current
    /// anti-amplification accounting.
    pub fn may_send(&self, additional_bytes: usize) -> bool {
        if self.validated {
            return true;
        }
        self.remaining_send_budget() >= additional_bytes as u64
    }
}

/// RFC 9000 § 5.1.1: a connection ID issued by this endpoint. We accept
/// packets destined to any non-retired local CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConnectionIdEntry {
    pub sequence_number: u64,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
    pub retired: bool,
}

/// RFC 9000 § 5.1.2: a connection ID issued by the peer. We use one of these
/// as the destination CID on outbound packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnectionIdEntry {
    pub sequence_number: u64,
    pub connection_id: Bytes,
    pub stateless_reset_token: [u8; 16],
    pub retired: bool,
}

/// Per-connection CID inventory tracking both locally issued and peer-issued
/// connection IDs (RFC 9000 § 5.1). Enforces the `active_connection_id_limit`
/// transport parameter (RFC 9000 § 18.2) and surfaces retire-prior-to
/// obligations from incoming NEW_CONNECTION_ID frames (RFC 9000 § 19.15).
#[derive(Debug, Clone)]
pub struct QuicConnectionIdInventory {
    active_connection_id_limit: u64,
    next_local_sequence: u64,
    locals: BTreeMap<u64, LocalConnectionIdEntry>,
    peer_retire_prior_to: u64,
    next_peer_sequence: u64,
    peers: BTreeMap<u64, PeerConnectionIdEntry>,
    pending_peer_retires: VecDeque<u64>,
    active_peer_sequence: Option<u64>,
    active_local_sequence: Option<u64>,
}

impl QuicConnectionIdInventory {
    /// Create an inventory with the negotiated `active_connection_id_limit`.
    /// RFC 9000 § 18.2 requires the value be at least 2; we clamp to
    /// `MIN_ACTIVE_CONNECTION_ID_LIMIT`.
    pub fn new(active_connection_id_limit: u64) -> Self {
        Self {
            active_connection_id_limit: active_connection_id_limit
                .max(MIN_ACTIVE_CONNECTION_ID_LIMIT),
            next_local_sequence: 0,
            locals: BTreeMap::new(),
            peer_retire_prior_to: 0,
            next_peer_sequence: 0,
            peers: BTreeMap::new(),
            pending_peer_retires: VecDeque::new(),
            active_peer_sequence: None,
            active_local_sequence: None,
        }
    }

    pub fn active_connection_id_limit(&self) -> u64 {
        self.active_connection_id_limit
    }

    /// Install the connection ID negotiated during the handshake as local
    /// sequence number 0 (RFC 9000 § 5.1.1).
    pub fn install_initial_local(
        &mut self,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> u64 {
        let sequence_number = self.next_local_sequence;
        self.locals.insert(
            sequence_number,
            LocalConnectionIdEntry {
                sequence_number,
                connection_id,
                stateless_reset_token,
                retired: false,
            },
        );
        self.next_local_sequence = self.next_local_sequence.saturating_add(1);
        if self.active_local_sequence.is_none() {
            self.active_local_sequence = Some(sequence_number);
        }
        sequence_number
    }

    /// Install the peer-issued connection ID from the handshake as peer
    /// sequence number 0 (RFC 9000 § 5.1.2).
    pub fn install_initial_peer(
        &mut self,
        connection_id: Bytes,
        stateless_reset_token: [u8; 16],
    ) -> u64 {
        let sequence_number = self.next_peer_sequence;
        self.peers.insert(
            sequence_number,
            PeerConnectionIdEntry {
                sequence_number,
                connection_id,
                stateless_reset_token,
                retired: false,
            },
        );
        self.next_peer_sequence = self.next_peer_sequence.saturating_add(1);
        if self.active_peer_sequence.is_none() {
            self.active_peer_sequence = Some(sequence_number);
        }
        sequence_number
    }

    /// Allocate the next outbound NEW_CONNECTION_ID frame, respecting the
    /// peer's `active_connection_id_limit` (RFC 9000 § 18.2). Returns `None`
    /// when issuing another local CID would exceed the negotiated limit.
    pub fn allocate_next_local_to_issue(
        &mut self,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    ) -> Option<LocalConnectionIdEntry> {
        if self.unretired_local_count() >= self.active_connection_id_limit as usize {
            return None;
        }
        let sequence_number = self.next_local_sequence;
        let entry = LocalConnectionIdEntry {
            sequence_number,
            connection_id,
            stateless_reset_token,
            retired: false,
        };
        self.locals.insert(sequence_number, entry.clone());
        self.next_local_sequence = self.next_local_sequence.saturating_add(1);
        Some(entry)
    }

    /// Process an inbound NEW_CONNECTION_ID frame (RFC 9000 § 19.15). Validates
    /// that the sequence number is novel, that `retire_prior_to` does not
    /// exceed `sequence_number`, and enforces the `active_connection_id_limit`.
    pub fn observe_peer_new_connection_id(
        &mut self,
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Bytes,
        stateless_reset_token: [u8; 16],
    ) -> Result<()> {
        if retire_prior_to > sequence_number {
            return Err(Error::quic(
                "RFC9000 19.15: NEW_CONNECTION_ID retire_prior_to exceeds sequence_number",
            ));
        }
        if let Some(existing) = self.peers.get(&sequence_number) {
            if existing.connection_id != connection_id
                || existing.stateless_reset_token != stateless_reset_token
            {
                return Err(Error::quic(
                    "RFC9000 19.15: NEW_CONNECTION_ID reuses sequence number with different CID",
                ));
            }
            return Ok(());
        }
        if retire_prior_to > self.peer_retire_prior_to {
            self.peer_retire_prior_to = retire_prior_to;
            self.retire_peer_below(retire_prior_to);
        }
        let entry = PeerConnectionIdEntry {
            sequence_number,
            connection_id,
            stateless_reset_token,
            retired: sequence_number < self.peer_retire_prior_to,
        };
        if entry.retired {
            self.pending_peer_retires.push_back(sequence_number);
        }
        self.peers.insert(sequence_number, entry);
        if self.next_peer_sequence <= sequence_number {
            self.next_peer_sequence = sequence_number.saturating_add(1);
        }
        if self.unretired_peer_count() > self.active_connection_id_limit as usize {
            return Err(Error::quic(
                "RFC9000 18.2: peer exceeded active_connection_id_limit",
            ));
        }
        if self.active_peer_sequence.is_none() {
            self.active_peer_sequence = Some(sequence_number);
        } else if self
            .active_peer_sequence
            .is_some_and(|active| active < self.peer_retire_prior_to)
        {
            self.active_peer_sequence =
                self.peers.iter().find_map(
                    |(seq, entry)| {
                        if entry.retired {
                            None
                        } else {
                            Some(*seq)
                        }
                    },
                );
        }
        Ok(())
    }

    /// Process an inbound RETIRE_CONNECTION_ID frame (RFC 9000 § 19.16): the
    /// peer is retiring one of the connection IDs we previously issued.
    pub fn observe_peer_retire_connection_id(&mut self, sequence_number: u64) -> Result<()> {
        {
            let entry = self.locals.get_mut(&sequence_number).ok_or_else(|| {
                Error::quic("RFC9000 19.16: RETIRE_CONNECTION_ID for unknown local sequence")
            })?;
            entry.retired = true;
        }
        if Some(sequence_number) == self.active_local_sequence {
            self.active_local_sequence = self.locals.iter().find_map(|(seq, value)| {
                if !value.retired && *seq != sequence_number {
                    Some(*seq)
                } else {
                    None
                }
            });
        }
        Ok(())
    }

    /// Drain the queue of peer sequence numbers we need to retire via outbound
    /// RETIRE_CONNECTION_ID frames (driven by retire_prior_to obligations from
    /// previously observed NEW_CONNECTION_ID frames).
    pub fn drain_pending_peer_retires(&mut self) -> Vec<u64> {
        self.pending_peer_retires.drain(..).collect()
    }

    pub fn active_local(&self) -> Option<&LocalConnectionIdEntry> {
        self.active_local_sequence
            .and_then(|seq| self.locals.get(&seq))
    }

    pub fn active_peer(&self) -> Option<&PeerConnectionIdEntry> {
        self.active_peer_sequence
            .and_then(|seq| self.peers.get(&seq))
    }

    /// Promote a non-retired peer CID to active, for example when migrating
    /// to a probed path (RFC 9000 § 9.5).
    pub fn promote_peer_to_active(&mut self, sequence_number: u64) -> Result<()> {
        let entry = self
            .peers
            .get(&sequence_number)
            .ok_or_else(|| Error::quic("RFC9000 9.5: cannot promote unknown peer connection ID"))?;
        if entry.retired {
            return Err(Error::quic(
                "RFC9000 9.5: cannot promote a retired peer connection ID",
            ));
        }
        self.active_peer_sequence = Some(sequence_number);
        Ok(())
    }

    pub fn unretired_local_count(&self) -> usize {
        self.locals.values().filter(|entry| !entry.retired).count()
    }

    pub fn unretired_peer_count(&self) -> usize {
        self.peers.values().filter(|entry| !entry.retired).count()
    }

    fn retire_peer_below(&mut self, threshold: u64) {
        for (sequence, entry) in self.peers.iter_mut() {
            if *sequence < threshold && !entry.retired {
                entry.retired = true;
                self.pending_peer_retires.push_back(*sequence);
            }
        }
    }
}

/// RFC 9000 § 9 lifecycle of a single path for a QUIC connection. A
/// connection always has one `Primary` path; `Probing` paths are validated
/// before promotion to `Primary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPathState {
    /// Newly observed peer address, no challenge in flight yet.
    Probing,
    /// PATH_CHALLENGE issued, awaiting matching PATH_RESPONSE (RFC 9000 § 8.2).
    Validating,
    /// PATH_RESPONSE matched; eligible for promotion (RFC 9000 § 9.4).
    Validated,
    /// Primary path for the connection.
    Primary,
    /// Abandoned after migration or validation failure.
    Abandoned,
}

/// Per-path state used by the migration state machine.
#[derive(Debug, Clone)]
pub struct QuicPath {
    pub peer_addr: SocketAddr,
    pub state: QuicPathState,
    pub anti_amplification: QuicAntiAmplificationLimit,
    pub pending_challenges: Vec<[u8; 8]>,
    pub last_activity: Option<Instant>,
}

impl QuicPath {
    fn new(peer_addr: SocketAddr, state: QuicPathState) -> Self {
        let mut anti_amplification = QuicAntiAmplificationLimit::default();
        if matches!(state, QuicPathState::Primary | QuicPathState::Validated) {
            anti_amplification.mark_validated();
        }
        Self {
            peer_addr,
            state,
            anti_amplification,
            pending_challenges: Vec::new(),
            last_activity: None,
        }
    }
}

/// RFC 9000 § 9 container for the primary path plus any concurrent probing
/// paths during a migration attempt. Sends and receives are tracked per path
/// so anti-amplification accounting follows the actual peer address.
#[derive(Debug, Default)]
pub struct QuicPathSet {
    paths: Vec<QuicPath>,
    primary_index: Option<usize>,
}

impl QuicPathSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the handshake peer address as the primary path. Already
    /// validated per RFC 9000 § 8.1 (the handshake itself validates the path).
    pub fn install_primary(&mut self, peer_addr: SocketAddr) -> &QuicPath {
        if let Some(existing) = self
            .paths
            .iter()
            .position(|path| path.peer_addr == peer_addr)
        {
            self.primary_index = Some(existing);
            let path = &mut self.paths[existing];
            path.state = QuicPathState::Primary;
            path.anti_amplification.mark_validated();
            return &self.paths[existing];
        }
        self.paths
            .push(QuicPath::new(peer_addr, QuicPathState::Primary));
        let index = self.paths.len() - 1;
        self.primary_index = Some(index);
        &self.paths[index]
    }

    /// Observe an inbound packet from `peer_addr`. If the address is new it is
    /// added as a `Probing` path; in either case the per-path
    /// received-byte counter is incremented for anti-amplification accounting.
    pub fn observe_packet_from(&mut self, peer_addr: SocketAddr, len: usize, now: Instant) {
        if let Some(index) = self
            .paths
            .iter()
            .position(|path| path.peer_addr == peer_addr)
        {
            let path = &mut self.paths[index];
            path.anti_amplification.on_received(len);
            path.last_activity = Some(now);
            return;
        }
        let mut path = QuicPath::new(peer_addr, QuicPathState::Probing);
        path.anti_amplification.on_received(len);
        path.last_activity = Some(now);
        self.paths.push(path);
    }

    /// Record bytes sent to `peer_addr` so anti-amplification accounting
    /// stays accurate. Returns the per-path remaining send budget after the
    /// accounting update.
    pub fn record_sent_to(&mut self, peer_addr: SocketAddr, len: usize) -> Option<u64> {
        let path = self
            .paths
            .iter_mut()
            .find(|path| path.peer_addr == peer_addr)?;
        path.anti_amplification.on_sent(len);
        Some(path.anti_amplification.remaining_send_budget())
    }

    /// Whether the endpoint may send `additional_bytes` to `peer_addr` under
    /// the current anti-amplification budget.
    pub fn may_send_to(&self, peer_addr: SocketAddr, additional_bytes: usize) -> bool {
        self.paths
            .iter()
            .find(|path| path.peer_addr == peer_addr)
            .map(|path| path.anti_amplification.may_send(additional_bytes))
            .unwrap_or(false)
    }

    /// Issue a PATH_CHALLENGE token for `peer_addr`. Returns true if a probing
    /// or primary path exists for that address.
    pub fn issue_challenge(&mut self, peer_addr: SocketAddr, token: [u8; 8]) -> bool {
        if let Some(path) = self
            .paths
            .iter_mut()
            .find(|path| path.peer_addr == peer_addr)
        {
            path.pending_challenges.push(token);
            if path.state == QuicPathState::Probing {
                path.state = QuicPathState::Validating;
            }
            true
        } else {
            false
        }
    }

    /// Observe a PATH_RESPONSE from `peer_addr`. Returns true if the token
    /// matched an outstanding challenge on that path; the path transitions to
    /// `Validated` and its anti-amplification budget is removed.
    pub fn observe_path_response(&mut self, peer_addr: SocketAddr, token: [u8; 8]) -> bool {
        let Some(path) = self
            .paths
            .iter_mut()
            .find(|path| path.peer_addr == peer_addr)
        else {
            return false;
        };
        let initial = path.pending_challenges.len();
        path.pending_challenges.retain(|pending| pending != &token);
        if path.pending_challenges.len() == initial {
            return false;
        }
        path.state = QuicPathState::Validated;
        path.anti_amplification.mark_validated();
        true
    }

    /// Promote `peer_addr` from `Validated` to `Primary` and demote any
    /// existing primary to `Abandoned` (RFC 9000 § 9.5).
    pub fn promote_to_primary(&mut self, peer_addr: SocketAddr) -> bool {
        let Some(target_index) = self
            .paths
            .iter()
            .position(|path| path.peer_addr == peer_addr)
        else {
            return false;
        };
        if !matches!(
            self.paths[target_index].state,
            QuicPathState::Validated | QuicPathState::Primary
        ) {
            return false;
        }
        if let Some(previous) = self.primary_index {
            if previous != target_index {
                self.paths[previous].state = QuicPathState::Abandoned;
            }
        }
        self.paths[target_index].state = QuicPathState::Primary;
        self.paths[target_index].anti_amplification.mark_validated();
        self.primary_index = Some(target_index);
        true
    }

    pub fn primary(&self) -> Option<&QuicPath> {
        self.primary_index.and_then(|index| self.paths.get(index))
    }

    pub fn path(&self, peer_addr: SocketAddr) -> Option<&QuicPath> {
        self.paths.iter().find(|path| path.peer_addr == peer_addr)
    }

    pub fn paths(&self) -> &[QuicPath] {
        &self.paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_entry(seq: u64) -> LocalConnectionIdEntry {
        LocalConnectionIdEntry {
            sequence_number: seq,
            connection_id: ConnectionId::from_slice(&[seq as u8; 8]),
            stateless_reset_token: [seq as u8; 16],
            retired: false,
        }
    }

    #[test]
    fn anti_amplification_blocks_send_beyond_three_times_received() {
        let mut limit = QuicAntiAmplificationLimit::new();
        limit.on_received(1200);
        assert_eq!(limit.remaining_send_budget(), 3600);
        assert!(limit.may_send(3600));
        assert!(!limit.may_send(3601));

        limit.on_sent(1200);
        assert_eq!(limit.remaining_send_budget(), 2400);
        assert!(limit.may_send(2400));
        assert!(!limit.may_send(2401));
    }

    #[test]
    fn anti_amplification_validation_removes_cap() {
        let mut limit = QuicAntiAmplificationLimit::new();
        limit.on_received(100);
        assert!(!limit.may_send(1_000_000));
        limit.mark_validated();
        assert!(limit.may_send(1_000_000));
        assert_eq!(limit.remaining_send_budget(), u64::MAX);
    }

    #[test]
    fn inventory_installs_initial_local_and_peer_at_sequence_zero() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        let local_seq =
            inventory.install_initial_local(ConnectionId::from_slice(&[1; 8]), [0xAA; 16]);
        let peer_seq = inventory.install_initial_peer(Bytes::from_static(&[2; 8]), [0xBB; 16]);
        assert_eq!(local_seq, 0);
        assert_eq!(peer_seq, 0);
        assert_eq!(inventory.active_local().map(|e| e.sequence_number), Some(0));
        assert_eq!(inventory.active_peer().map(|e| e.sequence_number), Some(0));
        assert_eq!(inventory.unretired_local_count(), 1);
        assert_eq!(inventory.unretired_peer_count(), 1);
    }

    #[test]
    fn inventory_observes_peer_new_connection_id_within_active_limit() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_peer(Bytes::from_static(&[0; 8]), [0xBB; 16]);

        inventory
            .observe_peer_new_connection_id(1, 0, Bytes::from_static(&[1; 8]), [0xCC; 16])
            .expect("novel sequence accepted");
        inventory
            .observe_peer_new_connection_id(2, 0, Bytes::from_static(&[2; 8]), [0xDD; 16])
            .expect("novel sequence accepted");
        assert_eq!(inventory.unretired_peer_count(), 3);
    }

    #[test]
    fn inventory_rejects_peer_new_connection_id_above_active_limit() {
        let mut inventory = QuicConnectionIdInventory::new(2);
        inventory.install_initial_peer(Bytes::from_static(&[0; 8]), [0xBB; 16]);
        inventory
            .observe_peer_new_connection_id(1, 0, Bytes::from_static(&[1; 8]), [0xCC; 16])
            .expect("first novel sequence accepted");

        let err = inventory
            .observe_peer_new_connection_id(2, 0, Bytes::from_static(&[2; 8]), [0xDD; 16])
            .expect_err("third unretired CID must violate active_connection_id_limit=2");
        match err {
            Error::Quic(msg) => {
                assert!(msg.contains("active_connection_id_limit"), "{msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn inventory_rejects_retire_prior_to_above_sequence_number() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_peer(Bytes::from_static(&[0; 8]), [0xBB; 16]);

        let err = inventory
            .observe_peer_new_connection_id(1, 2, Bytes::from_static(&[1; 8]), [0xCC; 16])
            .expect_err("retire_prior_to > sequence_number is a protocol violation");
        match err {
            Error::Quic(msg) => {
                assert!(msg.contains("retire_prior_to"), "{msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn inventory_queues_peer_retires_when_retire_prior_to_advances() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_peer(Bytes::from_static(&[0; 8]), [0xBB; 16]);
        inventory
            .observe_peer_new_connection_id(1, 0, Bytes::from_static(&[1; 8]), [0xCC; 16])
            .expect("first novel sequence accepted");
        inventory
            .observe_peer_new_connection_id(2, 2, Bytes::from_static(&[2; 8]), [0xDD; 16])
            .expect("retire_prior_to=2 retires sequences 0 and 1");

        let retired = inventory.drain_pending_peer_retires();
        assert_eq!(retired, vec![0, 1]);
        assert_eq!(inventory.unretired_peer_count(), 1);
        assert_eq!(inventory.active_peer().map(|e| e.sequence_number), Some(2));
    }

    #[test]
    fn inventory_retires_local_on_peer_retire_connection_id() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_local(ConnectionId::from_slice(&[1; 8]), [0xAA; 16]);
        let issued = inventory
            .allocate_next_local_to_issue(ConnectionId::from_slice(&[2; 8]), [0xBB; 16])
            .expect("allocation within active_connection_id_limit");
        assert_eq!(issued.sequence_number, 1);
        assert_eq!(inventory.unretired_local_count(), 2);

        inventory
            .observe_peer_retire_connection_id(0)
            .expect("peer retire of issued local sequence");
        assert_eq!(inventory.unretired_local_count(), 1);
        assert_eq!(
            inventory.active_local().map(|e| e.sequence_number),
            Some(1),
            "active local shifts to the surviving sequence"
        );
    }

    #[test]
    fn inventory_rejects_retire_of_unknown_local_sequence() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_local(ConnectionId::from_slice(&[1; 8]), [0xAA; 16]);
        let err = inventory
            .observe_peer_retire_connection_id(99)
            .expect_err("unknown sequence retire must error");
        match err {
            Error::Quic(msg) => {
                assert!(msg.contains("RETIRE_CONNECTION_ID"), "{msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn inventory_allocation_caps_at_active_connection_id_limit() {
        let mut inventory = QuicConnectionIdInventory::new(2);
        inventory.install_initial_local(ConnectionId::from_slice(&[1; 8]), [0xAA; 16]);
        assert!(inventory
            .allocate_next_local_to_issue(ConnectionId::from_slice(&[2; 8]), [0xBB; 16])
            .is_some());
        assert!(
            inventory
                .allocate_next_local_to_issue(ConnectionId::from_slice(&[3; 8]), [0xCC; 16])
                .is_none(),
            "third allocation must be rejected at limit=2"
        );
    }

    #[test]
    fn inventory_active_connection_id_limit_clamps_to_two() {
        let inventory = QuicConnectionIdInventory::new(0);
        assert_eq!(inventory.active_connection_id_limit(), 2);
        let inventory = QuicConnectionIdInventory::new(1);
        assert_eq!(inventory.active_connection_id_limit(), 2);
    }

    #[test]
    fn inventory_promote_peer_to_active_requires_unretired_sequence() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        inventory.install_initial_peer(Bytes::from_static(&[0; 8]), [0xBB; 16]);
        inventory
            .observe_peer_new_connection_id(1, 0, Bytes::from_static(&[1; 8]), [0xCC; 16])
            .unwrap();
        inventory.promote_peer_to_active(1).expect("known sequence");
        assert_eq!(inventory.active_peer().map(|e| e.sequence_number), Some(1));

        inventory
            .observe_peer_new_connection_id(2, 2, Bytes::from_static(&[2; 8]), [0xDD; 16])
            .expect("retire_prior_to=2 retires sequences 0 and 1");
        let err = inventory
            .promote_peer_to_active(1)
            .expect_err("promoting a retired sequence must fail");
        match err {
            Error::Quic(msg) => assert!(msg.contains("retired"), "{msg}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn local_entries_default_to_active_local() {
        let mut inventory = QuicConnectionIdInventory::new(4);
        let seq = inventory.install_initial_local(local_entry(0).connection_id, [0xAA; 16]);
        assert_eq!(
            inventory.active_local().map(|e| e.sequence_number),
            Some(seq)
        );
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn pathset_install_primary_is_already_validated() {
        let mut set = QuicPathSet::new();
        let primary = set.install_primary(addr(7000));
        assert_eq!(primary.state, QuicPathState::Primary);
        assert!(primary.anti_amplification.validated());
        assert!(set.may_send_to(addr(7000), 1_000_000));
    }

    #[test]
    fn pathset_observes_probing_path_from_new_address() {
        let mut set = QuicPathSet::new();
        set.install_primary(addr(7000));
        set.observe_packet_from(addr(7001), 1200, Instant::now());
        let probing = set.path(addr(7001)).expect("path tracked");
        assert_eq!(probing.state, QuicPathState::Probing);
        assert!(!probing.anti_amplification.validated());
        assert_eq!(probing.anti_amplification.bytes_received(), 1200);
        assert!(set.may_send_to(addr(7001), 3600));
        assert!(!set.may_send_to(addr(7001), 3601));
    }

    #[test]
    fn pathset_challenge_validation_promotes_path_and_unblocks_send_budget() {
        let mut set = QuicPathSet::new();
        set.install_primary(addr(7000));
        set.observe_packet_from(addr(7001), 1200, Instant::now());
        let token = [0xAB; 8];
        assert!(set.issue_challenge(addr(7001), token));
        assert!(matches!(
            set.path(addr(7001)).map(|p| p.state),
            Some(QuicPathState::Validating)
        ));
        assert!(set.observe_path_response(addr(7001), token));
        let validated = set.path(addr(7001)).expect("path still tracked");
        assert_eq!(validated.state, QuicPathState::Validated);
        assert!(validated.anti_amplification.validated());
        assert!(set.may_send_to(addr(7001), 1_000_000));
    }

    #[test]
    fn pathset_promote_to_primary_demotes_previous_primary() {
        let mut set = QuicPathSet::new();
        set.install_primary(addr(7000));
        set.observe_packet_from(addr(7001), 1200, Instant::now());
        let token = [0xCD; 8];
        set.issue_challenge(addr(7001), token);
        set.observe_path_response(addr(7001), token);
        assert!(set.promote_to_primary(addr(7001)));
        assert_eq!(
            set.primary().map(|p| p.peer_addr),
            Some(addr(7001)),
            "new primary path is the validated address"
        );
        assert_eq!(
            set.path(addr(7000)).map(|p| p.state),
            Some(QuicPathState::Abandoned)
        );
    }

    #[test]
    fn pathset_observe_path_response_ignores_unknown_token() {
        let mut set = QuicPathSet::new();
        set.install_primary(addr(7000));
        set.observe_packet_from(addr(7001), 1200, Instant::now());
        set.issue_challenge(addr(7001), [0xAA; 8]);
        assert!(
            !set.observe_path_response(addr(7001), [0xBB; 8]),
            "non-matching token must be ignored"
        );
        assert!(
            !set.path(addr(7001)).unwrap().anti_amplification.validated(),
            "validation must not be claimed on a bad token"
        );
    }
}
