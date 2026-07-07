//! RFC 9218 Extensible Priorities conformance.
//!
//! Covers:
//! - `priority` request-header structured-field serialization (u range 0-7, i flag).
//! - Fingerprint accuracy: certified Chrome/Firefox profiles emit NO RFC 9218
//!   priority signal by default (matches `docs/fingerprints/chrome-142-148.md`,
//!   which shows no `priority` header and no PRIORITY_UPDATE frames — Chrome
//!   expresses priority via the legacy RFC 7540 dependency tree). Fingerprint
//!   accuracy wins ties, so RFC 9218 emission is opt-in and off by default.
//! - PRIORITY_UPDATE frame layout bytes for H2 (type 0x10, stream 0) and H3
//!   (type 0xf0700), plus encode/decode round-trips.
//! - Grease tolerance (RFC 9218 §7): server-sent and malformed PRIORITY_UPDATE
//!   frames MUST NOT error the client.

use bytes::Bytes;

use warpsock::fingerprint::http2::Http2Settings;
use warpsock::transport::h2::{FrameType, PriorityUpdateFrame};
use warpsock::transport::h3::native::{decode_frame, encode_frame, H3Frame};
use warpsock::PrioritySignals;

// ---------------------------------------------------------------------------
// Structured-field serialization (RFC 9218 §4 + RFC 8941)
// ---------------------------------------------------------------------------

#[test]
fn default_priority_signals_match_rfc_defaults() {
    // RFC 9218 §4.1/§4.2 defaults: urgency 3, incremental false.
    let p = PrioritySignals::default();
    assert_eq!(p.urgency, 3);
    assert!(!p.incremental);
    // Both members at default => empty structured field => "do not emit header".
    assert_eq!(p.to_header_value(), "");
}

#[test]
fn urgency_only_serializes_when_non_default() {
    assert_eq!(PrioritySignals::new(0, false).to_header_value(), "u=0");
    assert_eq!(PrioritySignals::new(5, false).to_header_value(), "u=5");
    assert_eq!(PrioritySignals::new(7, false).to_header_value(), "u=7");
    // u=3 is the default and is omitted.
    assert_eq!(PrioritySignals::new(3, false).to_header_value(), "");
}

#[test]
fn incremental_flag_serializes_as_bare_member() {
    assert_eq!(PrioritySignals::new(3, true).to_header_value(), "i");
    assert_eq!(PrioritySignals::new(5, true).to_header_value(), "u=5, i");
    assert_eq!(PrioritySignals::new(0, true).to_header_value(), "u=0, i");
}

#[test]
fn urgency_is_clamped_to_valid_range() {
    // RFC 9218 §4.1: urgency is 0..=7. Out-of-range input is clamped, never
    // emitted as an invalid structured field.
    let p = PrioritySignals::new(9, false);
    assert_eq!(p.urgency, 7);
    assert_eq!(p.to_header_value(), "u=7");
}

#[test]
fn field_value_matches_header_value() {
    // RFC 9218 §7.1: the PRIORITY_UPDATE field value uses the same encoding as
    // the `priority` header.
    let p = PrioritySignals::new(5, true);
    assert_eq!(p.to_field_value(), p.to_header_value());
    assert_eq!(p.to_field_value(), "u=5, i");
}

// ---------------------------------------------------------------------------
// Fingerprint accuracy: no RFC 9218 signal on certified browser profiles
// ---------------------------------------------------------------------------

#[test]
fn chrome_profile_emits_no_priority_signal_by_default() {
    // docs/fingerprints/chrome-142-148.md shows no `priority` header and no
    // PRIORITY_UPDATE frames; Chrome uses the legacy PRIORITY dependency tree.
    // Fingerprint accuracy wins ties, so the default must be None.
    assert!(Http2Settings::default().priority_signals.is_none());
    // The legacy RFC 7540 priority tree remains the Chrome signal.
    assert!(Http2Settings::default().priority_tree.is_some());
}

#[test]
fn firefox_profile_emits_no_priority_signal_by_default() {
    assert!(Http2Settings::firefox().priority_signals.is_none());
}

#[test]
fn opt_in_profile_can_carry_priority_signal() {
    // A non-browser profile may deliberately follow the RFC 9218 SHOULD defaults.
    let settings = Http2Settings {
        priority_signals: Some(PrioritySignals::new(1, true)),
        ..Http2Settings::default()
    };
    let signal = settings.priority_signals.expect("opt-in signal present");
    assert_eq!(signal.to_header_value(), "u=1, i");
}

// ---------------------------------------------------------------------------
// H2 PRIORITY_UPDATE frame layout (RFC 9218 §7.2, type 0x10 on stream 0)
// ---------------------------------------------------------------------------

#[test]
fn h2_priority_update_frame_type_is_0x10() {
    assert_eq!(PriorityUpdateFrame::TYPE, 0x10);
    assert_eq!(u8::from(FrameType::PriorityUpdate), 0x10);
    assert_eq!(FrameType::from(0x10u8), FrameType::PriorityUpdate);
}

#[test]
fn h2_priority_update_frame_layout_bytes() {
    let field = PrioritySignals::new(5, false).to_field_value(); // "u=5"
    let frame = PriorityUpdateFrame::new(7, Bytes::from(field.into_bytes()));
    let bytes = frame.serialize();

    // 9-byte frame header + 4-byte prioritized stream id + 3-byte "u=5".
    let field_len = 3usize;
    let payload_len = 4 + field_len;
    assert_eq!(bytes.len(), 9 + payload_len);

    // Length (24-bit big-endian).
    assert_eq!(
        u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
        payload_len as u32
    );
    // Type 0x10.
    assert_eq!(bytes[3], 0x10);
    // Flags: none.
    assert_eq!(bytes[4], 0x00);
    // Stream ID: MUST be 0 (connection control stream).
    assert_eq!(
        u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]),
        0
    );
    // Prioritized Stream ID = 7 (reserved high bit clear).
    assert_eq!(
        u32::from_be_bytes([bytes[9] & 0x7f, bytes[10], bytes[11], bytes[12]]),
        7
    );
    // Field value = ASCII "u=5".
    assert_eq!(&bytes[13..], b"u=5");
}

#[test]
fn h2_priority_update_round_trip() {
    let field = Bytes::from_static(b"u=2, i");
    let frame = PriorityUpdateFrame::new(11, field.clone());
    let bytes = frame.serialize();
    // Skip the 9-byte header; parse the payload as delivered on stream 0.
    let payload = Bytes::copy_from_slice(&bytes[9..]);
    let parsed = PriorityUpdateFrame::parse(0, payload).expect("parse");
    assert_eq!(parsed.prioritized_stream_id, 11);
    assert_eq!(parsed.field_value, field);
}

#[test]
fn h2_priority_update_masks_reserved_bit() {
    // The reserved high bit MUST be 0 on the wire regardless of input.
    let frame = PriorityUpdateFrame::new(0xffff_ffff, Bytes::new());
    assert_eq!(frame.prioritized_stream_id, 0x7fff_ffff);
    let bytes = frame.serialize();
    assert_eq!(bytes[9] & 0x80, 0);
}

// ---------------------------------------------------------------------------
// H2 grease tolerance (RFC 9218 §7): malformed / non-stream-0 must not error
// ---------------------------------------------------------------------------

#[test]
fn h2_priority_update_on_nonzero_stream_is_rejected_at_frame_layer() {
    // Frame-layer parse enforces §7.2 (stream 0). The connection receive loop
    // deliberately swallows this error to stay lenient per §7 (see
    // src/transport/h2/connection.rs FrameType::PriorityUpdate arm).
    let payload = Bytes::from_static(&[0, 0, 0, 3, b'u', b'=', b'0']);
    assert!(PriorityUpdateFrame::parse(3, payload).is_err());
}

#[test]
fn h2_priority_update_short_payload_is_rejected_at_frame_layer() {
    // Fewer than 4 bytes cannot carry a prioritized stream id.
    let payload = Bytes::from_static(&[0, 0, 1]);
    assert!(PriorityUpdateFrame::parse(0, payload).is_err());
}

#[test]
fn h2_priority_update_empty_field_value_is_valid() {
    // An empty field value means "reset to defaults" and MUST be accepted.
    let payload = Bytes::from_static(&[0, 0, 0, 5]);
    let parsed = PriorityUpdateFrame::parse(0, payload).expect("parse");
    assert_eq!(parsed.prioritized_stream_id, 5);
    assert!(parsed.field_value.is_empty());
}

// ---------------------------------------------------------------------------
// H3 PRIORITY_UPDATE frame layout (RFC 9218 §7.2, type 0xf0700)
// ---------------------------------------------------------------------------

#[test]
fn h3_priority_update_frame_type_and_layout() {
    let field = Bytes::from_static(b"u=3, i");
    let frame = H3Frame::PriorityUpdateRequest {
        prioritized_element_id: 0,
        field_value: field.clone(),
    };
    let bytes = encode_frame(&frame);

    // First varint is the frame type 0xf0700. 0xf0700 needs a 4-byte varint
    // (0x4000..=0x3fff_ffff range), high two bits = 0b10.
    assert_eq!(bytes[0] & 0xc0, 0x80, "frame type encoded as 4-byte varint");
    let type_word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x3fff_ffff;
    assert_eq!(type_word, 0xf0700);
}

#[test]
fn h3_priority_update_round_trip() {
    let field = Bytes::from_static(b"u=6");
    let frame = H3Frame::PriorityUpdateRequest {
        prioritized_element_id: 42,
        field_value: field.clone(),
    };
    let bytes = encode_frame(&frame);
    let decoded = decode_frame(&bytes).expect("decode");
    match decoded {
        H3Frame::PriorityUpdateRequest {
            prioritized_element_id,
            field_value,
        } => {
            assert_eq!(prioritized_element_id, 42);
            assert_eq!(field_value, field);
        }
        other => panic!("expected PriorityUpdateRequest, got {other:?}"),
    }
}

#[test]
fn h3_priority_update_empty_field_value_round_trips() {
    let frame = H3Frame::PriorityUpdateRequest {
        prioritized_element_id: 9,
        field_value: Bytes::new(),
    };
    let decoded = decode_frame(&encode_frame(&frame)).expect("decode");
    match decoded {
        H3Frame::PriorityUpdateRequest {
            prioritized_element_id,
            field_value,
        } => {
            assert_eq!(prioritized_element_id, 9);
            assert!(field_value.is_empty());
        }
        other => panic!("expected PriorityUpdateRequest, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// H3 grease tolerance (RFC 9218 §7): server-sent + malformed must not error
// ---------------------------------------------------------------------------

#[test]
fn h3_server_priority_update_is_tolerated() {
    // Simulate a server-emitted PRIORITY_UPDATE and confirm the client decodes
    // it without erroring (RFC 9218 §7).
    let frame = H3Frame::PriorityUpdateRequest {
        prioritized_element_id: 3,
        field_value: Bytes::from_static(b"u=0"),
    };
    let bytes = encode_frame(&frame);
    assert!(decode_frame(&bytes).is_ok());
}

#[test]
fn h3_malformed_priority_update_falls_back_to_unknown() {
    // A PRIORITY_UPDATE frame whose payload cannot even yield a prioritized
    // element id varint MUST NOT error; it decodes as an Unknown frame so the
    // connection stays up (RFC 9218 §7 grease tolerance).
    // Hand-build: type 0xf0700 (4-byte varint), length 0, empty payload.
    let type_varint = (0xf0700u32 | 0x8000_0000).to_be_bytes();
    let mut wire = Vec::new();
    wire.extend_from_slice(&type_varint);
    wire.push(0x00); // length varint = 0
    let decoded = decode_frame(&wire).expect("malformed priority update must not error");
    match decoded {
        // Empty payload => no element id varint => Unknown fallback.
        H3Frame::Unknown { frame_type, .. } => assert_eq!(frame_type, 0xf0700),
        // (An implementation that treats empty as element-id 0 would also be
        //  acceptable, but the current decoder uses the Unknown fallback.)
        other => panic!("expected Unknown fallback, got {other:?}"),
    }
}

#[test]
fn h3_unknown_priority_grease_type_is_tolerated() {
    // An unrelated unknown/grease frame type must also be tolerated (§7).
    let frame = H3Frame::Unknown {
        frame_type: 0x21,
        payload: Bytes::from_static(b"grease"),
    };
    let bytes = encode_frame(&frame);
    assert!(decode_frame(&bytes).is_ok());
}
