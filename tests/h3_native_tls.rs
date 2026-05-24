use bytes::Bytes;
use specter::fingerprint::tls::{NativeH3TlsFeatureStatus, TlsExtensionOrderBehavior};
use specter::fingerprint::{
    CertCompression, Http3Fingerprint, RawQuicTransportParameter, TlsFingerprint,
};
use specter::transport::h3::quic::{
    decode_frames, decode_long_header, decode_transport_parameters, derive_initial_key_material,
    derive_packet_key_material_from_secret, encode_transport_parameters, open_initial_packet,
    ConnectionId, LongHeaderType, QuicFrame, TransportParameter,
};
use specter::transport::h3::tls::{
    build_client_initial_packet, capture_client_initial_crypto, native_h3_tls_capabilities,
    NativeQuicTlsSession, QuicEncryptionLevel, QuicSecretDirection, QuicTlsSecret,
};

mod helpers;

fn clienthello_extension_ids(crypto_data: &[u8]) -> Vec<u16> {
    assert_eq!(crypto_data[0], 0x01);
    let mut offset = 4 + 2 + 32;
    let session_id_len = crypto_data[offset] as usize;
    offset += 1 + session_id_len;
    let cipher_suites_len =
        u16::from_be_bytes([crypto_data[offset], crypto_data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    let compression_methods_len = crypto_data[offset] as usize;
    offset += 1 + compression_methods_len;
    let extensions_len =
        u16::from_be_bytes([crypto_data[offset], crypto_data[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    let mut extensions = Vec::new();
    while offset < extensions_end {
        let extension_id = u16::from_be_bytes([crypto_data[offset], crypto_data[offset + 1]]);
        let extension_len =
            u16::from_be_bytes([crypto_data[offset + 2], crypto_data[offset + 3]]) as usize;
        extensions.push(extension_id);
        offset += 4 + extension_len;
    }
    extensions
}

#[test]
fn native_tls_clienthello_capture_emits_initial_crypto_with_h3_alpn() {
    let captured =
        capture_client_initial_crypto("example.com", &Http3Fingerprint::chrome()).unwrap();

    assert_eq!(captured.crypto_data[0], 0x01);
    assert!(captured
        .crypto_data
        .windows(3)
        .any(|window| window == b"\x02h3"));
}

#[test]
fn native_tls_clienthello_capture_embeds_fingerprint_transport_parameters() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.max_idle_timeout_ms = 12_345;
    fingerprint.transport.initial_max_streams_bidi = 321;
    let expected = encode_transport_parameters(&fingerprint.transport);

    let captured = capture_client_initial_crypto("example.com", &fingerprint).unwrap();

    assert_eq!(captured.transport_parameters, expected);
    assert!(captured
        .crypto_data
        .windows(expected.len())
        .any(|window| window == expected.as_ref()));
}

#[test]
fn native_tls_clienthello_capture_uses_raw_ordered_transport_parameter_fingerprint() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.grease = false;
    fingerprint.transport.raw_ordered_transport_parameters = Some(vec![
        RawQuicTransportParameter {
            id: 0x0b,
            value: vec![0x19],
        },
        RawQuicTransportParameter {
            id: 0x0c,
            value: vec![],
        },
        RawQuicTransportParameter {
            id: 0x01,
            value: vec![0x1e],
        },
        RawQuicTransportParameter {
            id: 0x04,
            value: vec![0x3f],
        },
        RawQuicTransportParameter {
            id: 0x4a6f,
            value: b"raw".to_vec(),
        },
    ]);
    let expected = encode_transport_parameters(&fingerprint.transport);

    let captured = capture_client_initial_crypto("example.com", &fingerprint).unwrap();
    let decoded = decode_transport_parameters(&captured.transport_parameters).unwrap();

    assert_eq!(
        decoded,
        vec![
            TransportParameter::MaxAckDelay(25),
            TransportParameter::DisableActiveMigration,
            TransportParameter::MaxIdleTimeout(30),
            TransportParameter::InitialMaxData(63),
            TransportParameter::Additional(0x4a6f, Bytes::from_static(b"raw")),
        ]
    );
    assert_eq!(captured.transport_parameters, expected);
    assert!(captured
        .crypto_data
        .windows(expected.len())
        .any(|window| window == expected.as_ref()));
}

#[test]
fn native_tls_clienthello_advertises_tls_fingerprint_cert_compression() {
    let mut tls_fingerprint = TlsFingerprint::chrome();
    tls_fingerprint.cert_compression = CertCompression::Brotli;
    let mut session = NativeQuicTlsSession::client_with_tls_fingerprint(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&tls_fingerprint),
        false,
    )
    .unwrap();

    let initial = session.take_crypto(QuicEncryptionLevel::Initial);
    let extensions = clienthello_extension_ids(&initial);

    assert!(
        extensions.contains(&16),
        "test parser should find the ALPN extension in {extensions:?}"
    );
    assert!(
        extensions.contains(&27),
        "Brotli cert compression should advertise compress_certificate extension 27 in {extensions:?}"
    );
}

#[test]
fn native_tls_can_reject_invalid_replayed_session_ticket_before_clienthello() {
    let err = match NativeQuicTlsSession::client_with_replayed_session(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&TlsFingerprint::chrome()),
        false,
        b"not-a-der-session-ticket",
    ) {
        Ok(_) => {
            panic!("invalid replayed TLS session tickets must fail before ClientHello capture")
        }
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("session ticket"),
        "unexpected replay error: {err}"
    );
}

#[test]
fn native_tls_zero_rtt_offer_requires_replayable_session_ticket() {
    let err = match NativeQuicTlsSession::client_with_zero_rtt_offer(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&TlsFingerprint::chrome()),
        false,
        None,
        b"GET / HTTP/3\r\n\r\n",
    ) {
        Ok(_) => panic!("0-RTT must be gated on a replayable TLS session ticket"),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("0-RTT") && err.to_string().contains("session ticket"),
        "unexpected 0-RTT gating error: {err}"
    );
}

#[test]
fn native_tls_deterministic_extension_order_policy_disables_permutation() {
    let mut tls_fingerprint = TlsFingerprint::chrome();
    tls_fingerprint.grease = false;
    tls_fingerprint.cert_compression = CertCompression::None;
    tls_fingerprint.extension_order_behavior = TlsExtensionOrderBehavior::Deterministic;

    assert_eq!(
        tls_fingerprint.native_h3_extension_order_behavior(),
        TlsExtensionOrderBehavior::Deterministic
    );

    let mut first = NativeQuicTlsSession::client_with_tls_fingerprint(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&tls_fingerprint),
        false,
    )
    .unwrap();
    let mut second = NativeQuicTlsSession::client_with_tls_fingerprint(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&tls_fingerprint),
        false,
    )
    .unwrap();

    let first_extensions =
        clienthello_extension_ids(&first.take_crypto(QuicEncryptionLevel::Initial));
    let second_extensions =
        clienthello_extension_ids(&second.take_crypto(QuicEncryptionLevel::Initial));

    assert_eq!(first_extensions, second_extensions);
}

#[test]
fn native_h3_tls_capabilities_report_supported_resumption_and_zero_rtt() {
    let capabilities = native_h3_tls_capabilities(&TlsFingerprint::chrome());

    assert_eq!(
        capabilities.session_resumption,
        NativeH3TlsFeatureStatus::Supported,
        "native H3 now wires BoringSSL session tickets into the QUIC handshake per RFC 8446 section 4.6.1"
    );
    assert_eq!(
        capabilities.zero_rtt,
        NativeH3TlsFeatureStatus::Supported,
        "native H3 now configures SSL_set_quic_early_data_context per RFC 9001 section 4.6"
    );
}

#[test]
fn native_tls_client_initial_packet_wraps_captured_clienthello() {
    let fingerprint = Http3Fingerprint::chrome();
    let destination_cid = ConnectionId::from_static(b"destination-id");
    let source_cid = ConnectionId::from_static(b"source-id");

    let initial =
        build_client_initial_packet("example.com", &fingerprint, destination_cid, source_cid)
            .unwrap();
    let decoded_header = decode_long_header(&initial.header).unwrap();
    let keys = derive_initial_key_material(decoded_header.destination_cid.as_bytes()).unwrap();
    let opened =
        open_initial_packet(&keys.client, &initial.packet, initial.packet_number_offset).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(decoded_header.packet_type, LongHeaderType::Initial);
    assert!(initial.packet.len() >= 1200);
    assert_eq!(opened.header, initial.header);
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == &initial.crypto_data
    ));
}

#[test]
fn native_tls_clienthello_capture_has_no_tls_traffic_secrets_before_server_flight() {
    let captured =
        capture_client_initial_crypto("example.com", &Http3Fingerprint::chrome()).unwrap();

    assert!(captured.secrets.is_empty());
}

#[test]
fn native_tls_session_exposes_client_initial_without_dropping_state() {
    let mut session =
        NativeQuicTlsSession::client("example.com", &Http3Fingerprint::chrome()).unwrap();
    let initial = session.take_crypto(QuicEncryptionLevel::Initial);

    assert_eq!(initial[0], 0x01);
    assert!(initial.windows(3).any(|window| window == b"\x02h3"));
    assert_eq!(session.secrets().len(), 0);
}

#[test]
fn native_tls_session_rejects_invalid_server_initial_crypto() {
    let mut session =
        NativeQuicTlsSession::client("example.com", &Http3Fingerprint::chrome()).unwrap();

    let err = session
        .provide_crypto(QuicEncryptionLevel::Initial, b"\xff\0\0\0")
        .expect_err("invalid server crypto must fail");

    assert!(err.to_string().contains("server CRYPTO"));
}

#[test]
fn native_tls_server_accepts_client_initial_crypto_and_emits_server_flight() {
    let fingerprint = Http3Fingerprint::chrome();
    let mut client = NativeQuicTlsSession::client("localhost", &fingerprint).unwrap();
    let client_initial = client.take_crypto(QuicEncryptionLevel::Initial);
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicTlsSession::server(&fingerprint, &cert_pem, &key_pem).unwrap();

    server
        .provide_crypto(QuicEncryptionLevel::Initial, &client_initial)
        .unwrap();

    let server_initial = server.take_crypto(QuicEncryptionLevel::Initial);
    let server_handshake = server.take_crypto(QuicEncryptionLevel::Handshake);
    assert!(
        !server_initial.is_empty(),
        "server should emit ServerHello CRYPTO at Initial level"
    );
    assert!(
        !server_handshake.is_empty(),
        "server should emit EncryptedExtensions/certificate CRYPTO at Handshake level"
    );
    assert!(server_handshake
        .windows(3)
        .any(|window| window == b"\x02h3"));
}

#[test]
fn native_tls_session_applies_tls_fingerprint_curve_policy() {
    let mut tls_fingerprint = TlsFingerprint::default();
    tls_fingerprint.curves = vec!["not-a-real-group"];

    let err = match NativeQuicTlsSession::client_with_tls_fingerprint(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&tls_fingerprint),
        true,
    ) {
        Ok(_) => panic!("invalid native TLS curve group must be rejected"),
        Err(err) => err,
    };
    let err = err.to_string();

    assert!(
        err.contains("curves") || err.contains("group") || err.contains("TLS"),
        "unexpected native TLS fingerprint error: {err}"
    );
}

#[test]
fn native_tls_recorded_secret_derives_quic_packet_keys() {
    let secret = Bytes::from_static(&[0x22; 32]);
    let recorded = QuicTlsSecret {
        direction: QuicSecretDirection::Write,
        level: QuicEncryptionLevel::Handshake,
        secret: secret.clone(),
    };

    assert_eq!(
        recorded.packet_key_material().unwrap(),
        derive_packet_key_material_from_secret(secret).unwrap()
    );
}
