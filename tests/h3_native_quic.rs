use bytes::Bytes;
use specter::fingerprint::QuicTransportParams;
use specter::transport::h3::quic::{
    build_initial_crypto_packet, decode_frame, decode_frames, decode_long_header,
    decode_retry_packet, decode_transport_parameters, decode_version_negotiation_packet,
    derive_initial_key_material, derive_packet_key_material_from_secret, encode_frame,
    encode_initial_header, encode_long_header, encode_server_transport_parameters,
    encode_short_header, encode_transport_parameters,
    encode_transport_parameters_with_initial_source_connection_id, header_protection_mask,
    initial_crypto_plaintext, open_initial_packet, open_long_header_packet, open_packet_payload,
    open_protected_initial_packet, open_short_header_packet, protect_initial_packet,
    protect_long_header, protect_long_header_packet, protect_short_header_packet,
    recover_packet_number, retry_integrity_tag_v1, seal_packet_payload, split_long_header_datagram,
    validate_retry_integrity_tag_v1, ConnectionId, LongHeaderPacket, LongHeaderType, QuicAckRange,
    QuicAckTracker, QuicCryptoAssembler, QuicFrame, QuicLossDetector, QuicPathValidator,
    ShortHeaderPacket, TransportParameter,
};
use std::time::{Duration, Instant};

#[test]
fn native_quic_initial_header_round_trips_connection_ids_token_and_packet_number() {
    let packet = LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: 1,
        destination_cid: ConnectionId::from_static(b"destination-id"),
        source_cid: ConnectionId::from_static(b"source-id"),
        token: Bytes::from_static(b"retry-token"),
        packet_number: 0x1234,
        packet_number_len: 2,
        payload_len: 8,
    };

    let encoded = encode_initial_header(&packet).unwrap();
    let decoded = decode_long_header(&encoded).unwrap();

    assert_eq!(decoded, packet);
}

#[test]
fn native_quic_splits_coalesced_long_header_datagrams() {
    let initial_header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: 1,
        destination_cid: ConnectionId::from_static(b"server-dcid"),
        source_cid: ConnectionId::from_static(b"server-scid"),
        token: Bytes::new(),
        packet_number: 1,
        packet_number_len: 1,
        payload_len: 4,
    })
    .unwrap();
    let handshake_header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"server-dcid"),
        source_cid: ConnectionId::from_static(b"server-scid"),
        token: Bytes::new(),
        packet_number: 2,
        packet_number_len: 2,
        payload_len: 3,
    })
    .unwrap();
    let mut initial_packet = initial_header.to_vec();
    initial_packet.extend_from_slice(b"init");
    let mut handshake_packet = handshake_header.to_vec();
    handshake_packet.extend_from_slice(b"hsk");
    let mut datagram = initial_packet.clone();
    datagram.extend_from_slice(&handshake_packet);

    let packets = split_long_header_datagram(&datagram).unwrap();

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].packet_type, LongHeaderType::Initial);
    assert_eq!(packets[0].declared_remaining_len, 5);
    assert_eq!(packets[0].packet_number_offset, initial_header.len() - 1);
    assert_eq!(packets[0].packet.as_ref(), initial_packet.as_slice());
    assert_eq!(packets[1].packet_type, LongHeaderType::Handshake);
    assert_eq!(packets[1].declared_remaining_len, 5);
    assert_eq!(packets[1].packet_number_offset, handshake_header.len() - 2);
    assert_eq!(packets[1].packet.as_ref(), handshake_packet.as_slice());
}

#[test]
fn native_quic_decodes_version_negotiation_packet_without_fixed_bit() {
    let mut packet = vec![0x80, 0, 0, 0, 0, 8];
    packet.extend_from_slice(b"clientid");
    packet.push(7);
    packet.extend_from_slice(b"server1");
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&0xff00_001du32.to_be_bytes());

    let decoded = decode_version_negotiation_packet(&packet).unwrap();

    assert_eq!(
        decoded.destination_cid,
        ConnectionId::from_static(b"clientid")
    );
    assert_eq!(decoded.source_cid, ConnectionId::from_static(b"server1"));
    assert_eq!(decoded.supported_versions, vec![1, 0xff00_001d]);
}

#[test]
fn native_quic_version_negotiation_rejects_truncated_version_list() {
    let mut packet = vec![0xc0, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(&[0, 0, 1]);

    let err = decode_version_negotiation_packet(&packet).expect_err("truncated version fails");

    assert!(err.to_string().contains("supported version"));
}

#[test]
fn native_quic_decodes_retry_packet_and_validates_rfc9001_integrity_tag() {
    let original_dcid =
        ConnectionId::from_bytes(Bytes::from(hex::decode("8394c8f03e515708").unwrap())).unwrap();
    let retry = hex::decode(
        "\
        ff000000010008f067a5502a4262b574\
        6f6b656e04a265ba2eff4d829058fb3f\
        0f2496ba\
    ",
    )
    .unwrap();

    let decoded = decode_retry_packet(&retry).unwrap();
    let validated = validate_retry_integrity_tag_v1(&original_dcid, &retry).unwrap();

    assert_eq!(decoded, validated);
    assert_eq!(validated.version, 1);
    assert_eq!(validated.destination_cid.as_bytes(), b"");
    assert_eq!(
        validated.source_cid.as_bytes(),
        hex::decode("f067a5502a4262b5").unwrap().as_slice()
    );
    assert_eq!(validated.token, Bytes::from_static(b"token"));
    assert_eq!(
        hex::encode(validated.integrity_tag),
        "04a265ba2eff4d829058fb3f0f2496ba"
    );
}

#[test]
fn native_quic_retry_integrity_rejects_corrupted_tag() {
    let original_dcid =
        ConnectionId::from_bytes(Bytes::from(hex::decode("8394c8f03e515708").unwrap())).unwrap();
    let mut retry = hex::decode(
        "\
        ff000000010008f067a5502a4262b574\
        6f6b656e04a265ba2eff4d829058fb3f\
        0f2496ba\
    ",
    )
    .unwrap();
    *retry.last_mut().unwrap() ^= 0x01;

    let err =
        validate_retry_integrity_tag_v1(&original_dcid, &retry).expect_err("bad tag must fail");

    assert!(err.to_string().contains("Retry integrity tag"));
}

#[test]
fn native_quic_retry_integrity_tag_matches_rfc9001_vector() {
    let original_dcid =
        ConnectionId::from_bytes(Bytes::from(hex::decode("8394c8f03e515708").unwrap())).unwrap();
    let retry_without_tag = hex::decode(
        "\
        ff000000010008f067a5502a4262b574\
        6f6b656e\
    ",
    )
    .unwrap();

    let tag = retry_integrity_tag_v1(&original_dcid, &retry_without_tag).unwrap();

    assert_eq!(hex::encode(tag), "04a265ba2eff4d829058fb3f0f2496ba");
}

#[test]
fn native_quic_short_header_round_trips_stream_payload() {
    let keys = derive_packet_key_material_from_secret(Bytes::from_static(&[0x99; 32])).unwrap();
    let destination_cid = ConnectionId::from_static(b"client-cid");
    let plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: None,
        fin: false,
        data: Bytes::from_static(b"h3-preface"),
    });

    let packet =
        protect_short_header_packet(&keys, &destination_cid, 0x1234, 2, false, &plaintext).unwrap();
    let opened =
        open_short_header_packet(&keys, &packet, destination_cid.as_bytes().len(), 0x1200).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(opened.packet_number, 0x1234);
    assert_eq!(opened.destination_cid, destination_cid);
    assert!(!opened.key_phase);
    assert!(matches!(
        &frames[0],
        QuicFrame::Stream { stream_id: 0, data, .. } if data == b"h3-preface".as_slice()
    ));
}

#[test]
fn native_quic_path_validator_only_accepts_matching_path_response() {
    let challenge = *b"12345678";
    let mut validator = QuicPathValidator::default();

    assert_eq!(
        validator.path_challenge(challenge),
        QuicFrame::PathChallenge(challenge)
    );
    assert_eq!(validator.pending_count(), 1);
    assert!(!validator.on_path_response(*b"87654321"));
    assert!(!validator.is_validated(&challenge));

    assert!(validator.on_path_response(challenge));
    assert!(validator.is_validated(&challenge));
    assert_eq!(validator.pending_count(), 0);
    assert!(!validator.on_path_response(challenge));
}

#[test]
fn native_quic_short_header_encoder_preserves_key_phase_and_packet_number_len() {
    let header = encode_short_header(&ShortHeaderPacket {
        destination_cid: ConnectionId::from_static(b"dcid"),
        packet_number: 7,
        packet_number_len: 1,
        key_phase: true,
    })
    .unwrap();

    assert_eq!(header[0] & 0x80, 0);
    assert_eq!(header[0] & 0x40, 0x40);
    assert_eq!(header[0] & 0x04, 0x04);
    assert_eq!(header[0] & 0x03, 0);
    assert_eq!(&header[1..5], b"dcid");
    assert_eq!(header[5], 7);
}

#[test]
fn native_quic_splitter_keeps_long_header_prefix_before_short_header_suffix() {
    let long_header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"dcid"),
        source_cid: ConnectionId::from_static(b"scid"),
        token: Bytes::new(),
        packet_number: 7,
        packet_number_len: 1,
        payload_len: 4,
    })
    .unwrap();
    let short_header = encode_short_header(&ShortHeaderPacket {
        destination_cid: ConnectionId::from_static(b"dcid"),
        packet_number: 0,
        packet_number_len: 1,
        key_phase: false,
    })
    .unwrap();
    let mut datagram = long_header.clone().to_vec();
    datagram.extend_from_slice(b"hsk!");
    datagram.extend_from_slice(&short_header);
    datagram.extend_from_slice(b"ciphertext");

    let packets = split_long_header_datagram(&datagram).unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].packet_type, LongHeaderType::Handshake);
    assert_eq!(
        packets[0].packet.as_ref(),
        &datagram[..long_header.len() + 4]
    );
}

#[test]
fn native_quic_splitter_rejects_truncated_coalesced_packet() {
    let header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"dcid"),
        source_cid: ConnectionId::from_static(b"scid"),
        token: Bytes::new(),
        packet_number: 7,
        packet_number_len: 1,
        payload_len: 5,
    })
    .unwrap();
    let mut datagram = header.to_vec();
    datagram.extend_from_slice(b"no");

    let err = split_long_header_datagram(&datagram).expect_err("truncated packet must fail");

    assert!(err
        .to_string()
        .contains("truncated QUIC long-header packet"));
}

#[test]
fn native_quic_crypto_assembler_buffers_out_of_order_ranges() {
    let mut assembler = QuicCryptoAssembler::default();

    assembler.insert(5, Bytes::from_static(b"world")).unwrap();
    assert!(assembler.take_contiguous().is_empty());
    assembler.insert(0, Bytes::from_static(b"hello")).unwrap();

    assert_eq!(
        assembler.take_contiguous(),
        Bytes::from_static(b"helloworld")
    );
    assert!(assembler.take_contiguous().is_empty());
}

#[test]
fn native_quic_crypto_assembler_merges_overlapping_retransmits() {
    let mut assembler = QuicCryptoAssembler::default();

    assembler.insert(0, Bytes::from_static(b"hello")).unwrap();
    assembler.insert(3, Bytes::from_static(b"lo!")).unwrap();

    assert_eq!(assembler.take_contiguous(), Bytes::from_static(b"hello!"));
    assembler.insert(1, Bytes::from_static(b"old")).unwrap();
    assert!(assembler.take_contiguous().is_empty());
}

#[test]
fn native_quic_packet_key_material_derives_from_tls_traffic_secret() {
    let initial = derive_initial_key_material(&hex::decode("8394c8f03e515708").unwrap()).unwrap();

    let from_secret =
        derive_packet_key_material_from_secret(initial.client.secret.clone()).unwrap();

    assert_eq!(from_secret, initial.client);
}

#[test]
fn native_quic_opens_protected_handshake_long_header_packet() {
    let keys = derive_packet_key_material_from_secret(Bytes::from_static(&[0x11; 32])).unwrap();
    let plaintext = initial_crypto_plaintext(b"server-handshake-flight", 64).unwrap();
    let header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"client-dcid"),
        source_cid: ConnectionId::from_static(b"server-scid"),
        token: Bytes::new(),
        packet_number: 0x1234,
        packet_number_len: 2,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 2;
    let packet =
        protect_long_header_packet(&keys, 0x1234, &header, packet_number_offset, 2, &plaintext)
            .unwrap();

    let opened = open_long_header_packet(&keys, &packet, packet_number_offset, 0x1200).unwrap();

    assert_eq!(opened.packet_number, 0x1234);
    assert_eq!(opened.header, header);
    assert_eq!(opened.payload, plaintext);
    assert_eq!(
        decode_long_header(&opened.header).unwrap().packet_type,
        LongHeaderType::Handshake
    );
}

#[test]
fn native_quic_long_header_rejects_invalid_connection_id_lengths() {
    let mut bytes = vec![0xc0, 0, 0, 0, 1, 21];
    bytes.extend_from_slice(b"012345678901234567890");

    let err = decode_long_header(&bytes).expect_err("CID length over 20 must fail");
    assert!(err.to_string().contains("connection id"));
}

#[test]
fn native_quic_long_header_rejects_short_header_packets() {
    let err = decode_long_header(&[0x40, 0, 0, 0]).expect_err("short header is not long header");
    assert!(err.to_string().contains("long header"));
}

#[test]
fn native_quic_transport_parameters_preserve_fingerprint_order_and_values() {
    let params = QuicTransportParams {
        max_idle_timeout_ms: 10_000,
        max_recv_udp_payload_size: 1452,
        initial_max_data: 15_663_105,
        initial_max_stream_data_bidi_local: 1_000_000,
        initial_max_stream_data_bidi_remote: 2_000_000,
        initial_max_stream_data_uni: 3_000_000,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 10,
        ack_delay_exponent: 3,
        max_ack_delay_ms: 25,
        active_connection_id_limit: 4,
        disable_active_migration: true,
        grease: false,
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(&encode_transport_parameters(&params)).unwrap();

    assert_eq!(
        decoded,
        vec![
            TransportParameter::MaxIdleTimeout(10_000),
            TransportParameter::MaxUdpPayloadSize(1452),
            TransportParameter::InitialMaxData(15_663_105),
            TransportParameter::InitialMaxStreamDataBidiLocal(1_000_000),
            TransportParameter::InitialMaxStreamDataBidiRemote(2_000_000),
            TransportParameter::InitialMaxStreamDataUni(3_000_000),
            TransportParameter::InitialMaxStreamsBidi(100),
            TransportParameter::InitialMaxStreamsUni(10),
            TransportParameter::AckDelayExponent(3),
            TransportParameter::MaxAckDelay(25),
            TransportParameter::DisableActiveMigration,
            TransportParameter::ActiveConnectionIdLimit(4),
        ]
    );
}

#[test]
fn native_quic_transport_parameters_emit_grease_and_custom_unknowns() {
    let params = QuicTransportParams {
        grease: true,
        additional_transport_parameters: vec![(0x4a6f, b"raw-fingerprint".to_vec())],
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(&encode_transport_parameters(&params)).unwrap();

    assert!(decoded.contains(&TransportParameter::Additional(27, Bytes::new())));
    assert_eq!(
        decoded.last(),
        Some(&TransportParameter::Additional(
            0x4a6f,
            Bytes::from_static(b"raw-fingerprint")
        ))
    );
}

#[test]
fn native_quic_transport_parameters_emit_max_datagram_frame_size() {
    let params = QuicTransportParams {
        grease: false,
        max_datagram_frame_size: Some(1200),
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(&encode_transport_parameters(&params)).unwrap();

    assert_eq!(
        decoded.last(),
        Some(&TransportParameter::MaxDatagramFrameSize(1200))
    );
}

#[test]
fn native_quic_transport_parameters_can_include_initial_source_connection_id() {
    let params = encode_transport_parameters_with_initial_source_connection_id(
        &QuicTransportParams::chrome(),
        &ConnectionId::from_static(b"client-scid"),
    );

    let decoded = decode_transport_parameters(&params).unwrap();

    assert!(
        decoded.contains(&TransportParameter::InitialSourceConnectionId(
            Bytes::from_static(b"client-scid")
        ))
    );
}

#[test]
fn native_quic_server_transport_parameters_include_required_connection_ids() {
    let params = encode_server_transport_parameters(
        &QuicTransportParams::chrome(),
        &ConnectionId::from_static(b"client-dcid"),
        &ConnectionId::from_static(b"server-scid"),
        None,
    );

    let decoded = decode_transport_parameters(&params).unwrap();

    assert!(
        decoded.contains(&TransportParameter::OriginalDestinationConnectionId(
            Bytes::from_static(b"client-dcid")
        ))
    );
    assert!(
        decoded.contains(&TransportParameter::InitialSourceConnectionId(
            Bytes::from_static(b"server-scid")
        ))
    );
    assert!(!decoded
        .iter()
        .any(|parameter| matches!(parameter, TransportParameter::RetrySourceConnectionId(_))));
}

#[test]
fn native_quic_frame_decoder_accepts_reset_stream_and_stop_sending() {
    assert_eq!(
        specter::transport::h3::quic::decode_frame(&[0x04, 0x00, 0x01, 0x05]).unwrap(),
        QuicFrame::ResetStream {
            stream_id: 0,
            error_code: 1,
            final_size: 5,
        }
    );
    assert_eq!(
        specter::transport::h3::quic::decode_frame(&[0x05, 0x00, 0x01]).unwrap(),
        QuicFrame::StopSending {
            stream_id: 0,
            error_code: 1,
        }
    );
}

#[test]
fn native_quic_connection_close_frames_round_trip() {
    let transport_close = QuicFrame::ConnectionClose {
        error_code: 0x0100,
        frame_type: Some(0x08),
        reason: Bytes::from_static(b"transport close"),
    };
    let application_close = QuicFrame::ConnectionClose {
        error_code: 0x0101,
        frame_type: None,
        reason: Bytes::from_static(b"application close"),
    };

    assert_eq!(
        decode_frame(&encode_frame(&transport_close)).unwrap(),
        transport_close
    );
    assert_eq!(
        decode_frame(&encode_frame(&application_close)).unwrap(),
        application_close
    );
}

#[test]
fn native_quic_control_frames_round_trip() {
    let frames = vec![
        QuicFrame::MaxStreamData {
            stream_id: 4,
            max_stream_data: 65_535,
        },
        QuicFrame::MaxStreams {
            bidirectional: true,
            max_streams: 128,
        },
        QuicFrame::MaxStreams {
            bidirectional: false,
            max_streams: 32,
        },
        QuicFrame::DataBlocked {
            maximum_data: 1_048_576,
        },
        QuicFrame::StreamDataBlocked {
            stream_id: 8,
            maximum_stream_data: 16_384,
        },
        QuicFrame::StreamsBlocked {
            bidirectional: true,
            maximum_streams: 64,
        },
        QuicFrame::StreamsBlocked {
            bidirectional: false,
            maximum_streams: 16,
        },
        QuicFrame::NewConnectionId {
            sequence_number: 2,
            retire_prior_to: 1,
            connection_id: Bytes::from_static(b"replacement-cid"),
            stateless_reset_token: [0xab; 16],
        },
        QuicFrame::RetireConnectionId { sequence_number: 1 },
        QuicFrame::PathChallenge(*b"12345678"),
        QuicFrame::PathResponse(*b"abcdefgh"),
    ];

    let mut encoded = Vec::new();
    for frame in &frames {
        encoded.extend_from_slice(&encode_frame(frame));
    }

    assert_eq!(decode_frames(&encoded).unwrap(), frames);
}

#[test]
fn native_quic_crypto_frame_round_trips_offset_and_payload() {
    let frame = QuicFrame::Crypto {
        offset: 1024,
        data: Bytes::from_static(b"tls-client-hello"),
    };

    let encoded = encode_frame(&frame);
    let decoded = decode_frame(&encoded).unwrap();

    assert_eq!(encoded[0], 0x06);
    assert_eq!(decoded, frame);
}

#[test]
fn native_quic_stream_frame_round_trips_offset_length_fin_and_payload() {
    let frame = QuicFrame::Stream {
        stream_id: 0,
        offset: Some(4096),
        fin: true,
        data: Bytes::from_static(b"native-h3-request"),
    };

    let encoded = encode_frame(&frame);
    let decoded = decode_frame(&encoded).unwrap();

    assert_eq!(encoded[0], 0x0f);
    assert_eq!(decoded, frame);
}

#[test]
fn native_quic_ack_frame_round_trips_minimal_ack_range() {
    let frame = QuicFrame::Ack {
        largest_acknowledged: 42,
        ack_delay: 7,
        first_ack_range: 10,
        ranges: vec![QuicAckRange {
            gap: 1,
            ack_range_length: 3,
        }],
    };

    let encoded = encode_frame(&frame);
    let decoded = decode_frame(&encoded).unwrap();

    assert_eq!(encoded[0], 0x02);
    assert_eq!(decoded, frame);
}

#[test]
fn native_quic_ack_ecn_frame_round_trips_ranges_and_ecn_counts() {
    let frame = QuicFrame::AckEcn {
        largest_acknowledged: 42,
        ack_delay: 7,
        first_ack_range: 10,
        ranges: vec![QuicAckRange {
            gap: 1,
            ack_range_length: 3,
        }],
        ect0_count: 123,
        ect1_count: 4,
        ce_count: 2,
    };

    let encoded = encode_frame(&frame);
    let decoded = decode_frame(&encoded).unwrap();

    assert_eq!(encoded[0], 0x03);
    assert_eq!(decoded, frame);
}

#[test]
fn native_quic_ack_tracker_builds_rfc9000_ack_ranges() {
    let mut tracker = QuicAckTracker::default();
    tracker.observe(10);
    tracker.observe(9);
    tracker.observe(7);

    let frame = tracker.to_ack_frame(5).unwrap();

    assert_eq!(
        frame,
        QuicFrame::Ack {
            largest_acknowledged: 10,
            ack_delay: 5,
            first_ack_range: 1,
            ranges: vec![QuicAckRange {
                gap: 0,
                ack_range_length: 0,
            }],
        }
    );
}

#[test]
fn native_quic_ack_tracker_ignores_duplicate_packets() {
    let mut tracker = QuicAckTracker::default();
    tracker.observe(3);
    tracker.observe(3);
    tracker.observe(2);

    let frame = tracker.to_ack_frame(0).unwrap();

    assert_eq!(
        frame,
        QuicFrame::Ack {
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 1,
            ranges: vec![],
        }
    );
}

#[test]
fn native_quic_ack_tracker_clears_pending_ack_without_forgetting_ranges() {
    let mut tracker = QuicAckTracker::default();
    tracker.observe(3);
    tracker.observe(2);
    assert!(!tracker.is_empty());

    let frame = tracker.to_ack_frame(0).unwrap();
    tracker.mark_ack_sent();

    assert!(tracker.is_empty());
    assert_eq!(tracker.to_ack_frame(0).unwrap(), frame);

    tracker.observe(3);
    assert!(tracker.is_empty());
    tracker.observe(4);
    assert!(!tracker.is_empty());
}

#[test]
fn native_quic_ack_tracker_defers_until_configured_packet_threshold() {
    let mut tracker = QuicAckTracker::default();

    assert!(!tracker.should_ack_after(4));
    tracker.observe(1);
    tracker.observe(2);
    tracker.observe(3);
    assert!(!tracker.should_ack_after(4));

    tracker.observe(4);
    assert!(tracker.should_ack_after(4));

    tracker.mark_ack_sent();
    assert!(!tracker.should_ack_after(4));

    tracker.observe(4);
    assert!(!tracker.should_ack_after(1));
    tracker.observe(5);
    assert!(tracker.should_ack_after(1));
}

#[test]
fn native_quic_ack_tracker_uses_max_ack_delay_timer_below_packet_threshold() {
    let mut tracker = QuicAckTracker::default();
    let first_observed = Instant::now();

    tracker.observe_at(1, first_observed);

    assert!(!tracker.should_ack_after_or_delay(
        16,
        Duration::from_millis(25),
        first_observed + Duration::from_millis(24)
    ));
    assert!(tracker.should_ack_after_or_delay(
        16,
        Duration::from_millis(25),
        first_observed + Duration::from_millis(25)
    ));
}

#[test]
fn native_quic_ack_tracker_encodes_delayed_ack_delay_units() {
    let mut tracker = QuicAckTracker::default();
    let first_observed = Instant::now();
    tracker.observe_at(7, first_observed);

    let frame = tracker
        .to_ack_frame_with_delay(first_observed + Duration::from_millis(25), 3)
        .expect("ACK frame");

    assert!(matches!(
        frame,
        QuicFrame::Ack {
            largest_acknowledged: 7,
            ack_delay: 3125,
            ..
        }
    ));
}

#[test]
fn native_quic_loss_detector_marks_packets_lost_by_reordering_threshold() {
    let mut detector = QuicLossDetector::default();
    detector.on_packet_sent(1);
    detector.on_packet_sent(2);
    detector.on_packet_sent(3);
    detector.on_packet_sent(4);
    detector.on_ack_received(4);

    assert_eq!(detector.lost_packets(), vec![1]);
}

#[test]
fn native_quic_loss_detector_keeps_acked_packets_out_of_loss_set() {
    let mut detector = QuicLossDetector::default();
    detector.on_packet_sent(1);
    detector.on_packet_sent(2);
    detector.on_packet_sent(3);
    detector.on_packet_sent(4);
    detector.on_ack_received(1);
    detector.on_ack_received(4);

    assert_eq!(detector.lost_packets(), Vec::<u64>::new());
}

#[test]
fn native_quic_loss_detector_applies_ack_frame_ranges() {
    let mut detector = QuicLossDetector::default();
    for packet_number in 1..=10 {
        detector.on_packet_sent(packet_number);
    }

    detector
        .on_ack_frame(&QuicFrame::Ack {
            largest_acknowledged: 10,
            ack_delay: 0,
            first_ack_range: 1,
            ranges: vec![QuicAckRange {
                gap: 1,
                ack_range_length: 2,
            }],
        })
        .unwrap();

    assert_eq!(detector.lost_packets(), vec![1, 2, 3, 7]);
}

#[test]
fn native_quic_loss_detector_samples_rtt_from_newly_acked_largest_packet() {
    let mut detector = QuicLossDetector::default()
        .with_peer_ack_delay_exponent(3)
        .with_max_ack_delay(Duration::from_millis(25));
    let sent_at = Instant::now() - Duration::from_millis(40);
    detector.on_packet_sent_at(7, sent_at);

    detector
        .on_ack_frame(&QuicFrame::Ack {
            largest_acknowledged: 7,
            ack_delay: 3125,
            first_ack_range: 0,
            ranges: Vec::new(),
        })
        .unwrap();

    assert_eq!(detector.lost_packets(), Vec::<u64>::new());
    assert!(detector.latest_rtt().is_some());
    assert!(detector.min_rtt().is_some());
    assert!(detector.smoothed_rtt().is_some());
    assert!(detector.rttvar() > Duration::ZERO);
    assert!(detector.current_pto() < Duration::from_millis(333 * 3));
}

#[test]
fn native_quic_loss_detector_applies_ack_ecn_frame_ranges() {
    let mut detector = QuicLossDetector::default();
    for packet_number in 1..=10 {
        detector.on_packet_sent(packet_number);
    }

    detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 10,
            ack_delay: 0,
            first_ack_range: 1,
            ranges: vec![QuicAckRange {
                gap: 1,
                ack_range_length: 2,
            }],
            ect0_count: 4,
            ect1_count: 0,
            ce_count: 1,
        })
        .unwrap();

    assert_eq!(detector.lost_packets(), vec![1, 2, 3, 7]);
}

#[test]
fn native_quic_loss_detector_rejects_ack_ecn_counter_regression() {
    let mut detector = QuicLossDetector::default();
    for packet_number in 1..=3 {
        detector.on_packet_sent(packet_number);
    }

    detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            ranges: Vec::new(),
            ect0_count: 1,
            ect1_count: 0,
            ce_count: 0,
        })
        .unwrap();
    let err = detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 2,
            ack_delay: 0,
            first_ack_range: 0,
            ranges: Vec::new(),
            ect0_count: 0,
            ect1_count: 0,
            ce_count: 0,
        })
        .unwrap_err();

    assert!(format!("{err}").contains("QUIC ACK_ECN counters decreased"));
    assert!(detector.ecn_validation_failed());
}

#[test]
fn native_quic_loss_detector_rejects_ack_ecn_counts_above_new_acknowledgements() {
    let mut detector = QuicLossDetector::default();
    detector.on_packet_sent(1);

    let err = detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            ranges: Vec::new(),
            ect0_count: 2,
            ect1_count: 0,
            ce_count: 0,
        })
        .unwrap_err();

    assert!(format!("{err}").contains("QUIC ACK_ECN count increase"));
    assert!(detector.ecn_validation_failed());
}

#[test]
fn native_quic_loss_detector_records_ce_marks_without_marking_acked_packets_lost() {
    let mut detector = QuicLossDetector::default();
    for packet_number in 1..=4 {
        detector.on_packet_sent(packet_number);
    }

    detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 2,
            ack_delay: 0,
            first_ack_range: 1,
            ranges: Vec::new(),
            ect0_count: 1,
            ect1_count: 0,
            ce_count: 1,
        })
        .unwrap();

    assert_eq!(detector.ecn_ce_marked_packets(), 1);
    assert_eq!(detector.lost_packets(), Vec::<u64>::new());

    detector
        .on_ack_frame(&QuicFrame::AckEcn {
            largest_acknowledged: 4,
            ack_delay: 0,
            first_ack_range: 1,
            ranges: Vec::new(),
            ect0_count: 2,
            ect1_count: 0,
            ce_count: 2,
        })
        .unwrap();

    assert_eq!(detector.ecn_ce_marked_packets(), 2);
}

#[test]
fn native_quic_loss_detector_reports_pto_expired_unacked_packets_by_send_time() {
    let mut detector = QuicLossDetector::default();
    let sent_at = Instant::now();

    detector.on_packet_sent_at(1, sent_at);
    detector.on_packet_sent_at(2, sent_at + Duration::from_millis(10));

    assert_eq!(
        detector.pto_expired_packets(
            sent_at + Duration::from_millis(49),
            Duration::from_millis(50)
        ),
        Vec::<u64>::new()
    );
    assert_eq!(
        detector.pto_expired_packets(
            sent_at + Duration::from_millis(50),
            Duration::from_millis(50)
        ),
        vec![1]
    );

    detector.on_ack_received(1);

    assert_eq!(
        detector.pto_expired_packets(
            sent_at + Duration::from_millis(60),
            Duration::from_millis(50)
        ),
        vec![2]
    );
}

#[test]
fn native_quic_frame_decoder_preserves_padding_ping_and_max_data_order() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&encode_frame(&QuicFrame::Padding));
    encoded.extend_from_slice(&encode_frame(&QuicFrame::Ping));
    encoded.extend_from_slice(&encode_frame(&QuicFrame::MaxData(15_663_105)));

    let decoded = decode_frames(&encoded).unwrap();

    assert_eq!(
        decoded,
        vec![
            QuicFrame::Padding,
            QuicFrame::Ping,
            QuicFrame::MaxData(15_663_105),
        ]
    );
}

#[test]
fn native_quic_initial_key_material_matches_rfc9001_vectors() {
    let cid = hex::decode("8394c8f03e515708").unwrap();

    let keys = derive_initial_key_material(&cid).unwrap();

    assert_eq!(
        hex::encode(keys.initial_secret.as_ref()),
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
    );
    assert_eq!(
        hex::encode(keys.client.secret.as_ref()),
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
    );
    assert_eq!(
        hex::encode(keys.client.packet_key.as_ref()),
        "1f369613dd76d5467730efcbe3b1a22d"
    );
    assert_eq!(
        hex::encode(keys.client.iv.as_ref()),
        "fa044b2f42a3fd3b46fb255c"
    );
    assert_eq!(
        hex::encode(keys.client.header_protection_key.as_ref()),
        "9f50449e04a0e810283a1e9933adedd2"
    );
    assert_eq!(
        hex::encode(keys.server.secret.as_ref()),
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
    );
    assert_eq!(
        hex::encode(keys.server.packet_key.as_ref()),
        "cf3a5331653c364c88f0f379b6067e37"
    );
    assert_eq!(
        hex::encode(keys.server.iv.as_ref()),
        "0ac1493ca1905853b0bba03e"
    );
    assert_eq!(
        hex::encode(keys.server.header_protection_key.as_ref()),
        "c206b8d9b9f0f37644430b490eeaa314"
    );
}

#[test]
fn native_quic_initial_payload_protection_matches_rfc9001_sample() {
    let cid = hex::decode("8394c8f03e515708").unwrap();
    let keys = derive_initial_key_material(&cid).unwrap();
    let header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
    let plaintext = rfc9001_client_initial_plaintext();

    let sealed = seal_packet_payload(&keys.client, 2, &header, &plaintext).unwrap();
    let opened = open_packet_payload(&keys.client, 2, &header, &sealed).unwrap();

    assert_eq!(sealed.len(), 1178);
    assert_eq!(
        hex::encode(&sealed[..16]),
        "d1b1c98dd7689fb8ec11d242b123dc9b"
    );
    assert_eq!(opened, plaintext);
}

#[test]
fn native_quic_long_header_protection_matches_rfc9001_sample() {
    let cid = hex::decode("8394c8f03e515708").unwrap();
    let keys = derive_initial_key_material(&cid).unwrap();
    let sample = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b").unwrap();
    let mut header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();

    let mask = header_protection_mask(&keys.client, &sample).unwrap();
    protect_long_header(&mut header, 18, 4, mask).unwrap();

    assert_eq!(hex::encode(mask), "437b9aec36");
    assert_eq!(
        hex::encode(header),
        "c000000001088394c8f03e5157080000449e7b9aec34"
    );
}

#[test]
fn native_quic_initial_packet_protection_matches_rfc9001_packet_prefix() {
    let cid = hex::decode("8394c8f03e515708").unwrap();
    let keys = derive_initial_key_material(&cid).unwrap();
    let header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
    let plaintext = rfc9001_client_initial_plaintext();

    let packet = protect_initial_packet(&keys.client, 2, &header, 18, 4, &plaintext).unwrap();

    assert_eq!(packet.len(), 1200);
    assert_eq!(
        hex::encode(&packet[..64]),
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    );
}

#[test]
fn native_quic_initial_packet_open_removes_header_and_payload_protection() {
    let cid = hex::decode("8394c8f03e515708").unwrap();
    let keys = derive_initial_key_material(&cid).unwrap();
    let header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
    let plaintext = rfc9001_client_initial_plaintext();
    let packet = protect_initial_packet(&keys.client, 2, &header, 18, 4, &plaintext).unwrap();

    let opened = open_initial_packet(&keys.client, &packet, 18).unwrap();

    assert_eq!(opened.packet_number, 2);
    assert_eq!(opened.header.as_ref(), header.as_slice());
    assert_eq!(opened.payload.as_ref(), plaintext.as_slice());
}

#[test]
fn native_quic_protected_initial_open_recovers_truncated_packet_number() {
    let cid = ConnectionId::from_static(b"destination-id");
    let keys = derive_initial_key_material(cid.as_bytes()).unwrap();
    let plaintext = initial_crypto_plaintext(b"server-handshake", 64).unwrap();
    let header = encode_initial_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: 1,
        destination_cid: cid,
        source_cid: ConnectionId::from_static(b"source-id"),
        token: Bytes::new(),
        packet_number: 0xa82f9b32,
        packet_number_len: 2,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 2;
    let packet = protect_initial_packet(
        &keys.client,
        0xa82f9b32,
        &header,
        packet_number_offset,
        2,
        &plaintext,
    )
    .unwrap();

    let opened = open_protected_initial_packet(&keys.client, &packet, 0xa82f30eb).unwrap();

    assert_eq!(opened.packet_number, 0xa82f9b32);
    assert_eq!(opened.header, header);
    assert_eq!(opened.payload, plaintext);
}

#[test]
fn native_quic_packet_number_recovery_matches_rfc9000_example() {
    let recovered = recover_packet_number(0x9b32, 2, 0xa82f30eb).unwrap();

    assert_eq!(recovered, 0xa82f9b32);
}

#[test]
fn native_quic_initial_crypto_plaintext_wraps_client_hello_and_padding() {
    let expected = rfc9001_client_initial_plaintext();
    let client_hello = &expected[4..245];

    let plaintext = initial_crypto_plaintext(client_hello, expected.len()).unwrap();

    assert_eq!(plaintext.as_ref(), expected.as_slice());
}

#[test]
fn native_quic_initial_crypto_packet_matches_rfc9001_packet_prefix() {
    let cid = hex::decode("8394c8f03e515708").unwrap();
    let keys = derive_initial_key_material(&cid).unwrap();
    let header = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
    let expected_plaintext = rfc9001_client_initial_plaintext();
    let client_hello = &expected_plaintext[4..245];

    let packet =
        build_initial_crypto_packet(&keys.client, 2, &header, 18, 4, client_hello, 1162).unwrap();

    assert_eq!(packet.len(), 1200);
    assert_eq!(
        hex::encode(&packet[..64]),
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    );
}

fn rfc9001_client_initial_plaintext() -> Vec<u8> {
    let mut plaintext = hex::decode(
        "\
        060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
        04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
        616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
        04616c706e000500050100000000003300260024001d00209370b2c9caa47fba\
        baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400\
        0d0010000e0403050306030203080408050806002d00020101001c0002400100\
        3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000\
        75300901100f088394c8f03e51570806048000ffff\
    ",
    )
    .unwrap();
    plaintext.resize(1162, 0);
    plaintext
}
