use bytes::Bytes;
use specter::fingerprint::{Http3Fingerprint, QpackHeaderBlockStrategy};
use specter::transport::h3::handshake::{
    ClientH3Event, NativeQuicHandshake, NativeQuicServerHandshake, ServerH3Event,
};
use specter::transport::h3::native::{
    decode_frame as decode_h3_frame, decode_header_block, decode_unidirectional_stream,
    encode_fingerprint_settings_payload, encode_frame as encode_h3_frame, encode_header_block,
    encode_unidirectional_stream, H3Frame, H3Header, H3Setting, H3StreamType,
    H3UnidirectionalStream,
};
use specter::transport::h3::native_driver::{
    NativeH3DriverState, NativeH3Event, NativeH3Response, NativeH3StreamingResponseEvent,
    NativeH3TunnelEvent,
};
use specter::transport::h3::quic::{
    decode_frames, decode_long_header, derive_initial_key_material,
    derive_next_packet_key_material, derive_packet_key_material_from_secret, encode_frame,
    encode_initial_header, encode_long_header, initial_crypto_plaintext, open_long_header_packet,
    open_short_header_packet, protect_long_header_packet, protect_short_header_packet,
    retry_integrity_tag_v1, split_long_header_datagram, ConnectionId, LongHeaderPacket,
    LongHeaderType, QuicFrame,
};
use specter::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};
use specter::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use specter::transport::h3::tls::{
    NativeH3HandshakeStatus, NativeQuicTlsSession, QuicEncryptionLevel, QuicSecretDirection,
    QuicTlsSecret,
};
use specter::{DnsConfig, H3Backend, H3Client};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server, TEST_RESUMPTION_TICKET_KEYS};

fn capture_mock_server_session_ticket(fingerprint: &Http3Fingerprint) -> Bytes {
    let mut client =
        NativeQuicTlsSession::client_with_tls_fingerprint("127.0.0.1", fingerprint, None, false)
            .expect("native H3 client TLS session");
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicTlsSession::server_with_ticket_keys(
        fingerprint,
        &cert_pem,
        &key_pem,
        &TEST_RESUMPTION_TICKET_KEYS,
    )
    .expect("native H3 server TLS session");

    let client_initial = client.take_crypto(QuicEncryptionLevel::Initial);
    server
        .provide_crypto(QuicEncryptionLevel::Initial, &client_initial)
        .expect("server processes ClientHello");
    let server_initial = server.take_crypto(QuicEncryptionLevel::Initial);
    if !server_initial.is_empty() {
        client
            .provide_crypto(QuicEncryptionLevel::Initial, &server_initial)
            .expect("client processes ServerHello");
    }
    let server_handshake = server.take_crypto(QuicEncryptionLevel::Handshake);
    if !server_handshake.is_empty() {
        client
            .provide_crypto(QuicEncryptionLevel::Handshake, &server_handshake)
            .expect("client processes server handshake");
    }
    let client_handshake = client.take_crypto(QuicEncryptionLevel::Handshake);
    if !client_handshake.is_empty() {
        server
            .provide_crypto(QuicEncryptionLevel::Handshake, &client_handshake)
            .expect("server processes client Finished");
    }
    let server_app = server.take_crypto(QuicEncryptionLevel::Application);
    if !server_app.is_empty() {
        client
            .provide_crypto(QuicEncryptionLevel::Application, &server_app)
            .expect("client processes NewSessionTicket");
    }

    client
        .take_session_tickets()
        .into_iter()
        .next()
        .expect("mock server must issue a session ticket")
        .der
}

fn native_h3_cache_key_for_mock_host(
    host: &str,
    fingerprint: &Http3Fingerprint,
) -> NativeH3SessionCacheKey {
    let mut hasher = DefaultHasher::new();
    false.hash(&mut hasher);
    0usize.hash(&mut hasher);
    let root_store = format!("platform=false;roots={:016x}", hasher.finish());

    NativeH3SessionCacheKey::new(
        host,
        fingerprint.alpn_protocols.clone(),
        false,
        Some(format!(
            "tls=default;h3={};{}",
            fingerprint.pool_key_string(),
            root_store
        )),
    )
}

fn version_negotiation_packet(
    destination_cid: &ConnectionId,
    source_cid: &ConnectionId,
    supported_versions: &[u32],
) -> Bytes {
    let mut packet = Vec::new();
    packet.push(0x80);
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.push(destination_cid.as_bytes().len() as u8);
    packet.extend_from_slice(destination_cid.as_bytes());
    packet.push(source_cid.as_bytes().len() as u8);
    packet.extend_from_slice(source_cid.as_bytes());
    for version in supported_versions {
        packet.extend_from_slice(&version.to_be_bytes());
    }
    Bytes::from(packet)
}

fn retry_packet(
    original_destination_cid: &ConnectionId,
    destination_cid: &ConnectionId,
    source_cid: &ConnectionId,
    token: &[u8],
) -> Bytes {
    let mut packet = Vec::new();
    packet.push(0xf0);
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(destination_cid.as_bytes().len() as u8);
    packet.extend_from_slice(destination_cid.as_bytes());
    packet.push(source_cid.as_bytes().len() as u8);
    packet.extend_from_slice(source_cid.as_bytes());
    packet.extend_from_slice(token);
    let tag = retry_integrity_tag_v1(original_destination_cid, &packet).unwrap();
    packet.extend_from_slice(&tag);
    Bytes::from(packet)
}

fn completed_native_server_handshake() -> (
    Http3Fingerprint,
    NativeQuicHandshake,
    NativeQuicServerHandshake,
) {
    let fingerprint = Http3Fingerprint::chrome();
    completed_native_server_handshake_with_fingerprint(fingerprint)
}

fn completed_native_server_handshake_with_fingerprint(
    fingerprint: Http3Fingerprint,
) -> (
    Http3Fingerprint,
    NativeQuicHandshake,
    NativeQuicServerHandshake,
) {
    completed_native_server_handshake_with_fingerprints(fingerprint.clone(), fingerprint)
}

fn completed_native_server_handshake_with_fingerprints(
    client_fingerprint: Http3Fingerprint,
    server_fingerprint: Http3Fingerprint,
) -> (
    Http3Fingerprint,
    NativeQuicHandshake,
    NativeQuicServerHandshake,
) {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &client_fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &server_fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();

    (client_fingerprint, client, server)
}

#[test]
fn native_h3_server_opens_client_short_header_with_server_source_connection_id() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"original-dcid-1234");
    let client_source_cid = ConnectionId::from_static(b"client-scid-12345");
    let server_source_cid = ConnectionId::from_static(b"srv-cid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        server_source_cid.clone(),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    let processed = server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    let client_application_keys = processed
        .secrets
        .iter()
        .find(|secret| {
            secret.direction == QuicSecretDirection::Read
                && secret.level == QuicEncryptionLevel::Application
        })
        .expect("server should install client application read secret")
        .packet_key_material()
        .unwrap();
    let mut plaintext = encode_frame(&QuicFrame::Ping).to_vec();
    plaintext.resize(24, 0);
    let packet = protect_short_header_packet(
        &client_application_keys,
        &server_source_cid,
        0,
        2,
        false,
        &Bytes::from(plaintext),
    )
    .unwrap();

    let frames = server.open_client_application_packet(&packet).unwrap();

    assert!(frames.iter().any(|frame| matches!(frame, QuicFrame::Ping)));
}

#[test]
fn native_h3_server_handshake_packetizes_initial_and_handshake_flight() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let server_source_cid = ConnectionId::from_static(b"native-server-cid");
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        server_source_cid.clone(),
    )
    .unwrap();

    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();

    assert_eq!(server_flight.packets.len(), 2);
    assert_eq!(
        server_flight.packets[0].packet_type,
        LongHeaderType::Initial
    );
    assert_eq!(
        server_flight.packets[1].packet_type,
        LongHeaderType::Handshake
    );
    assert_eq!(
        server_flight.datagram.len(),
        server_flight
            .packets
            .iter()
            .map(|packet| packet.packet.len())
            .sum::<usize>()
    );

    let initial_keys = derive_initial_key_material(client_destination_cid.as_bytes()).unwrap();
    let opened_initial = open_long_header_packet(
        &initial_keys.server,
        &server_flight.packets[0].packet,
        server_flight.packets[0].packet_number_offset,
        0,
    )
    .unwrap();
    let initial_frames = decode_frames(&opened_initial.payload).unwrap();
    assert!(matches!(
        &initial_frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == &server_flight.packets[0].crypto_data
    ));

    let server_handshake_keys = server_flight
        .secrets
        .iter()
        .find(|secret| {
            secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Handshake
        })
        .expect("server handshake write secret should be recorded")
        .packet_key_material()
        .unwrap();
    let opened_handshake = open_long_header_packet(
        &server_handshake_keys,
        &server_flight.packets[1].packet,
        server_flight.packets[1].packet_number_offset,
        0,
    )
    .unwrap();
    let handshake_frames = decode_frames(&opened_handshake.payload).unwrap();
    assert!(matches!(
        &handshake_frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == &server_flight.packets[1].crypto_data
    ));

    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .expect("client should accept native server flight");
    assert_eq!(processed.len(), 2);
}

#[test]
fn native_h3_server_handshake_builds_initial_ack_for_client_initial() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid,
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        ConnectionId::from_static(b"client-scid"),
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();

    let ack = server
        .build_server_initial_ack_packet()
        .unwrap()
        .expect("observed client Initial should produce a server ACK");
    let keys = derive_initial_key_material(client_destination_cid.as_bytes()).unwrap();
    let opened =
        open_long_header_packet(&keys.server, &ack.packet, ack.packet_number_offset, 1).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(ack.packet_number, 1);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 0,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_server_handshake_builds_handshake_ack_for_client_finished() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();

    let ack = server
        .build_server_handshake_ack_packet()
        .unwrap()
        .expect("observed client Finished should produce a server Handshake ACK");
    let server_handshake_keys = server_flight
        .secrets
        .iter()
        .find(|secret| {
            secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Handshake
        })
        .unwrap()
        .packet_key_material()
        .unwrap();
    let opened = open_long_header_packet(
        &server_handshake_keys,
        &ack.packet,
        ack.packet_number_offset,
        1,
    )
    .unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(ack.packet_number, 1);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 0,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_server_handshake_ingests_client_finished_and_installs_application_keys() {
    let (_, client, server) = completed_native_server_handshake();

    assert!(client.is_application_ready());
    assert!(server.is_application_ready());
}

#[test]
fn native_h3_server_handshake_packetizes_handshake_done() {
    let (_, mut client, mut server) = completed_native_server_handshake();

    let packet = server.build_server_handshake_done_packet().unwrap();
    let frames = client
        .open_server_application_packet(packet.packet.as_ref())
        .unwrap();

    assert!(frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::HandshakeDone)));
}

#[test]
fn native_h3_client_opens_server_packet_after_one_rtt_key_update() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid.clone(),
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    let processed = server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    let server_application_keys = processed
        .secrets
        .iter()
        .find(|secret| {
            secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Application
        })
        .unwrap()
        .packet_key_material()
        .unwrap();
    let next_keys = derive_next_packet_key_material(&server_application_keys).unwrap();
    let mut payload = encode_frame(&QuicFrame::Ping).to_vec();
    payload.resize(24, 0);
    let packet =
        protect_short_header_packet(&next_keys, &client_source_cid, 0, 2, true, &payload).unwrap();

    let frames = client.open_server_application_packet(&packet).unwrap();

    assert!(frames.iter().any(|frame| matches!(frame, QuicFrame::Ping)));
}

#[test]
fn native_h3_server_opens_client_packet_after_one_rtt_key_update() {
    let (_, mut client, mut server) = completed_native_server_handshake();

    client.force_key_update().unwrap();
    let packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"phase1"), false)
        .unwrap()
        .unwrap();
    let frames = server
        .open_client_application_packet(packet.packet.as_ref())
        .unwrap();

    assert!(server.read_key_phase());
    assert!(frames.iter().any(|frame| {
        matches!(
            frame,
            QuicFrame::Stream { stream_id: 0, data, .. } if data == b"phase1".as_slice()
        )
    }));
}

#[test]
fn native_h3_server_decrypts_previous_phase_packet_after_key_update_within_window() {
    let (_, mut client, mut server) = completed_native_server_handshake();

    let old_phase_packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"old-phase"), false)
        .unwrap()
        .unwrap();

    client.force_key_update().unwrap();
    let new_phase_packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"new-phase"), false)
        .unwrap()
        .unwrap();
    server
        .open_client_application_packet(new_phase_packet.packet.as_ref())
        .unwrap();
    assert!(server.read_key_phase());

    let frames = server
        .open_client_application_packet(old_phase_packet.packet.as_ref())
        .unwrap();
    assert!(frames.iter().any(|frame| matches!(
        frame,
        QuicFrame::Stream { stream_id: 0, data, .. } if data == b"old-phase".as_slice()
    )));
}

#[test]
fn native_h3_force_key_update_twice_without_ack_returns_error() {
    let (_, mut client, _server) = completed_native_server_handshake();

    client
        .force_key_update()
        .expect("first key update must succeed");
    assert!(client.key_update_in_progress());
    let err = client
        .force_key_update()
        .expect_err("second update must wait for ACK confirmation per RFC9001 § 6.5");
    assert!(
        err.to_string().contains("RFC9001"),
        "expected RFC9001 § 6.5 error, got: {err}"
    );
}

#[test]
fn native_h3_key_update_confirms_after_ack_of_new_phase_packet() {
    let (_, mut client, mut server) = completed_native_server_handshake();

    client.force_key_update().unwrap();
    assert!(client.key_update_in_progress());
    let stream_packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"new-phase-1"), false)
        .unwrap()
        .unwrap();
    server
        .open_client_application_packet(stream_packet.packet.as_ref())
        .unwrap();
    let ack = server
        .build_server_application_ack_packet()
        .unwrap()
        .expect("server must ACK the ack-eliciting new-phase client packet");
    client
        .open_server_application_packet(ack.packet.as_ref())
        .unwrap();

    assert!(client.read_key_phase());
    assert!(!client.key_update_in_progress());
    client
        .force_key_update()
        .expect("subsequent update should succeed after the first is confirmed by ACK");
}

#[test]
fn native_h3_server_handshake_opens_client_request_stream_packet() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    assert!(client.is_application_ready());
    assert!(server.is_application_ready());

    let uri: http::Uri = "https://localhost/native?fixture=1".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(
            &http::Method::POST,
            &uri,
            &[("user-agent".into(), "specter-native".into())],
            Some(Bytes::from_static(b"hello")),
        )
        .unwrap();

    let events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].stream_id, request.stream_id);
    assert!(events[0].fin);
    let H3Frame::Headers(block) = &events[0].frames[0] else {
        panic!("request stream should start with HEADERS");
    };
    let headers = decode_header_block(block.as_ref()).unwrap();
    assert!(headers
        .iter()
        .any(|header| header.name() == ":method" && header.value() == "POST"));
    assert!(headers
        .iter()
        .any(|header| header.name() == ":path" && header.value() == "/native?fixture=1"));
    assert!(headers
        .iter()
        .any(|header| header.name() == "user-agent" && header.value() == "specter-native"));
    assert_eq!(
        events[0].frames[1],
        H3Frame::Data(Bytes::from_static(b"hello"))
    );
}

#[test]
fn native_h3_server_handshake_packetizes_response_for_client_request_stream() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();

    let response = server
        .build_server_h3_response_packet(
            request_events[0].stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"native-ok")),
            true,
        )
        .unwrap();
    let response_events = client
        .open_server_h3_stream_packet(response.packet.as_ref())
        .unwrap();

    assert_eq!(response.stream_id, request_events[0].stream_id);
    assert_eq!(response_events.len(), 1);
    assert!(response_events[0].fin);
    let H3Frame::Headers(block) = &response_events[0].frames[0] else {
        panic!("response should start with HEADERS");
    };
    assert_eq!(
        decode_header_block(block.as_ref()).unwrap(),
        vec![H3Header::new(":status", "200")]
    );
    assert_eq!(
        response_events[0].frames[1],
        H3Frame::Data(Bytes::from_static(b"native-ok"))
    );
}

#[test]
fn native_h3_server_handshake_packetizes_streaming_response_data_after_headers() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;

    let response_headers = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            None,
            false,
        )
        .unwrap();
    let response_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"chunk"), true)
        .unwrap();

    let header_events = client
        .open_server_h3_stream_packet(response_headers.packet.as_ref())
        .unwrap();
    let data_events = client
        .open_server_h3_stream_packet(response_data.packet.as_ref())
        .unwrap();

    assert_eq!(header_events.len(), 1);
    assert!(!header_events[0].fin);
    assert!(matches!(header_events[0].frames[0], H3Frame::Headers(_)));
    assert_eq!(data_events.len(), 1);
    assert!(data_events[0].fin);
    assert_eq!(
        data_events[0].frames,
        vec![H3Frame::Data(Bytes::from_static(b"chunk"))]
    );
}

#[test]
fn native_h3_server_handshake_builds_application_ack_for_client_request() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();

    let ack = server
        .build_server_application_ack_packet()
        .unwrap()
        .expect("observed client request should produce a server application ACK");
    let frames = client
        .open_server_application_packet(ack.packet.as_ref())
        .unwrap();

    assert_eq!(ack.packet_number, 0);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 0,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_server_handshake_packetizes_settings_control_stream() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();

    let settings = server
        .build_server_h3_settings_packet(&fingerprint)
        .unwrap();
    let events = client
        .open_server_h3_stream_packet(settings.packet.as_ref())
        .unwrap();

    assert_eq!(settings.stream_id, 3);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].stream_type, Some(H3StreamType::Control));
    assert_eq!(
        events[0].frames,
        vec![H3Frame::Settings(encode_fingerprint_settings_payload(
            &fingerprint
        ))]
    );
}

#[test]
fn native_h3_server_handshake_packetizes_goaway_on_settings_control_stream() {
    let (fingerprint, mut client, mut server) = completed_native_server_handshake();
    let settings = server
        .build_server_h3_settings_packet(&fingerprint)
        .unwrap();
    client
        .open_server_h3_stream_packet(settings.packet.as_ref())
        .unwrap();

    let goaway = server.build_server_h3_goaway_packet(0).unwrap();
    let events = client
        .open_server_h3_stream_packet(goaway.packet.as_ref())
        .unwrap();

    assert_eq!(goaway.stream_id, settings.stream_id);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].stream_type, Some(H3StreamType::Control));
    assert_eq!(events[0].frames, vec![H3Frame::GoAway { id: 0 }]);
}

#[test]
fn native_h3_server_handshake_packetizes_reset_stream_after_response_bytes() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;
    let response = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"before-reset")),
            false,
        )
        .unwrap();
    client
        .open_server_h3_stream_packet(response.packet.as_ref())
        .unwrap();

    let reset = server
        .build_server_reset_stream_packet(stream_id, 0x010c)
        .unwrap();
    let events = client
        .open_server_h3_event_packet(reset.packet.as_ref())
        .unwrap();

    assert_eq!(reset.packet_number, response.packet_number + 1);
    assert_eq!(
        events,
        vec![ServerH3Event::ResetStream {
            stream_id,
            error_code: 0x010c,
            final_size: response.data.len() as u64,
        }]
    );
}

#[test]
fn native_h3_server_handshake_packetizes_connection_close() {
    let (_, mut client, mut server) = completed_native_server_handshake();

    let close = server
        .build_server_connection_close_packet(0x0100, Bytes::from_static(b"fixture done"))
        .unwrap();
    let events = client
        .open_server_h3_event_packet(close.packet.as_ref())
        .unwrap();

    assert_eq!(close.packet_number, 0);
    assert_eq!(
        events,
        vec![ServerH3Event::ConnectionClose {
            error_code: 0x0100,
            frame_type: None,
            reason: Bytes::from_static(b"fixture done"),
        }]
    );
}

#[test]
fn native_h3_client_applies_server_application_ack_to_sent_loss_state() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_start_packet(&http::Method::POST, &uri, &[], None, false)
        .unwrap();
    let _first_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"one"), false)
        .unwrap()
        .unwrap();
    let _second_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"two"), false)
        .unwrap()
        .unwrap();
    let third_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"three"), false)
        .unwrap()
        .unwrap();

    server
        .open_client_application_packet(third_data.packet.as_ref())
        .unwrap();
    let ack = server
        .build_server_application_ack_packet()
        .unwrap()
        .expect("server should ACK observed client application packet");
    client
        .open_server_application_packet(ack.packet.as_ref())
        .unwrap();

    assert_eq!(client.client_application_lost_packets(), vec![0]);
}

#[test]
fn native_h3_server_applies_client_application_ack_to_sent_loss_state() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;
    let _headers = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"headers")),
            false,
        )
        .unwrap();
    let _first_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"one"), false)
        .unwrap();
    let _second_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"two"), false)
        .unwrap();
    let third_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"three"), false)
        .unwrap();

    client
        .open_server_application_packet(third_data.packet.as_ref())
        .unwrap();
    let ack = client
        .build_client_application_ack_packet()
        .unwrap()
        .expect("client should ACK observed server application packet");
    server
        .open_client_application_packet(ack.packet.as_ref())
        .unwrap();

    assert_eq!(server.server_application_lost_packets(), vec![0]);
}

#[test]
fn native_h3_client_retransmits_lost_application_stream_packet() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_start_packet(&http::Method::POST, &uri, &[], None, false)
        .unwrap();
    let _first_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"one"), false)
        .unwrap()
        .unwrap();
    let _second_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"two"), false)
        .unwrap()
        .unwrap();
    let third_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"three"), false)
        .unwrap()
        .unwrap();

    server
        .open_client_application_packet(third_data.packet.as_ref())
        .unwrap();
    let ack = server
        .build_server_application_ack_packet()
        .unwrap()
        .expect("server should ACK observed client application packet");
    client
        .open_server_application_packet(ack.packet.as_ref())
        .unwrap();

    let retransmits = client
        .retransmit_lost_client_application_stream_packets()
        .unwrap();

    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].packet_number, third_data.packet_number + 1);
    assert_eq!(retransmits[0].stream_id, request.stream_id);
    let events = server
        .open_client_h3_stream_packet(retransmits[0].packet.as_ref())
        .unwrap();
    assert_eq!(events[0].stream_id, request.stream_id);
    assert!(matches!(&events[0].frames[0], H3Frame::Headers(_)));
}

#[test]
fn native_h3_client_application_ack_updates_packet_space_recovery() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();

    assert!(client.recovery().handshake_complete());
    assert!(client
        .recovery()
        .space(PacketNumberSpace::Application)
        .sent_packets()
        .contains_key(&request.packet_number));

    server
        .open_client_application_packet(request.packet.as_ref())
        .unwrap();
    let ack = server
        .build_server_application_ack_packet()
        .unwrap()
        .expect("server should ACK observed client application packet");
    client
        .open_server_application_packet(ack.packet.as_ref())
        .unwrap();

    assert!(client
        .recovery()
        .space(PacketNumberSpace::Application)
        .sent_packets()
        .is_empty());
}

#[test]
fn native_h3_server_application_ack_updates_packet_space_recovery() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;
    let response = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"hello")),
            false,
        )
        .unwrap();

    assert!(server.recovery().handshake_complete());
    assert!(server
        .recovery()
        .space(PacketNumberSpace::Application)
        .sent_packets()
        .contains_key(&response.packet_number));

    client
        .open_server_application_packet(response.packet.as_ref())
        .unwrap();
    let ack = client
        .build_client_application_ack_packet()
        .unwrap()
        .expect("client should ACK observed server application packet");
    server
        .open_client_application_packet(ack.packet.as_ref())
        .unwrap();

    assert!(server
        .recovery()
        .space(PacketNumberSpace::Application)
        .sent_packets()
        .is_empty());
}

#[test]
fn native_h3_client_retransmits_application_stream_packet_on_pto() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let timer = client
        .loss_detection_timer()
        .expect("application packet should arm loss detection timer");
    let now = timer + Duration::from_millis(1);
    let pto = client.application_pto();

    let outcome = client.on_loss_detection_timeout(now);
    assert_eq!(
        outcome,
        LossDetectionOutcome::Pto {
            space: PacketNumberSpace::Application,
        }
    );

    let retransmits = client
        .retransmit_pto_client_application_stream_packets(now, pto)
        .unwrap();

    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].packet_number, request.packet_number + 1);
    assert_eq!(retransmits[0].stream_id, request.stream_id);
    let events = server
        .open_client_h3_stream_packet(retransmits[0].packet.as_ref())
        .unwrap();
    assert_eq!(events[0].stream_id, request.stream_id);
    assert!(matches!(&events[0].frames[0], H3Frame::Headers(_)));
}

#[test]
fn native_h3_server_retransmits_application_stream_packet_on_pto() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;
    let response = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"hello")),
            false,
        )
        .unwrap();
    let timer = server
        .loss_detection_timer()
        .expect("server application packet should arm loss detection timer");
    let now = timer + Duration::from_millis(1);
    let pto = server.application_pto();

    let outcome = server.on_loss_detection_timeout(now);
    assert_eq!(
        outcome,
        LossDetectionOutcome::Pto {
            space: PacketNumberSpace::Application,
        }
    );

    let retransmits = server
        .retransmit_pto_server_application_stream_packets(now, pto)
        .unwrap();

    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].packet_number, response.packet_number + 1);
    assert_eq!(retransmits[0].stream_id, stream_id);
    let events = client
        .open_server_h3_stream_packet(retransmits[0].packet.as_ref())
        .unwrap();
    assert_eq!(events[0].stream_id, stream_id);
    assert!(matches!(&events[0].frames[0], H3Frame::Headers(_)));
}

#[test]
fn native_h3_server_retransmits_lost_application_stream_packet() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;
    let headers = server
        .build_server_h3_response_packet(
            stream_id,
            vec![H3Header::new(":status", "200")],
            Some(Bytes::from_static(b"headers")),
            false,
        )
        .unwrap();
    let _first_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"one"), false)
        .unwrap();
    let _second_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"two"), false)
        .unwrap();
    let third_data = server
        .build_server_h3_response_data_packet(stream_id, Bytes::from_static(b"three"), false)
        .unwrap();

    client
        .open_server_application_packet(third_data.packet.as_ref())
        .unwrap();
    let ack = client
        .build_client_application_ack_packet()
        .unwrap()
        .expect("client should ACK observed server application packet");
    server
        .open_client_application_packet(ack.packet.as_ref())
        .unwrap();

    let retransmits = server
        .retransmit_lost_server_application_stream_packets()
        .unwrap();

    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].packet_number, third_data.packet_number + 1);
    assert_eq!(retransmits[0].stream_id, stream_id);
    let events = client
        .open_server_h3_stream_packet(retransmits[0].packet.as_ref())
        .unwrap();
    assert_eq!(events[0].stream_id, stream_id);
    assert_eq!(retransmits[0].data, headers.data);
    assert!(matches!(&events[0].frames[0], H3Frame::Headers(_)));
}

#[test]
fn native_h3_client_enforces_peer_initial_flow_control_on_application_stream() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 3;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 3;
    let (_, mut client, _) = completed_native_server_handshake_with_fingerprint(fingerprint);

    let error = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("client must not send over peer flow-control credit");

    assert!(error.to_string().contains("flow control"));
}

#[test]
fn native_h3_client_rejects_server_stream_over_receive_connection_window() {
    let mut client_fingerprint = Http3Fingerprint::chrome();
    client_fingerprint.transport.initial_max_data = 3;
    client_fingerprint
        .transport
        .initial_max_stream_data_bidi_local = 64;
    let mut server_fingerprint = Http3Fingerprint::chrome();
    server_fingerprint.transport.initial_max_data = 64;
    server_fingerprint
        .transport
        .initial_max_stream_data_bidi_local = 64;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprints(client_fingerprint, server_fingerprint);

    let packet = server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect("server send credit should not block this receive-side test");
    let error = client
        .open_server_application_packet(packet.packet.as_ref())
        .expect_err("client must reject server data over its receive connection window");

    assert!(error.to_string().contains("flow control"));
}

#[test]
fn native_h3_server_rejects_client_stream_over_receive_stream_window() {
    let mut client_fingerprint = Http3Fingerprint::chrome();
    client_fingerprint.transport.initial_max_data = 64;
    client_fingerprint
        .transport
        .initial_max_stream_data_bidi_remote = 64;
    let mut server_fingerprint = Http3Fingerprint::chrome();
    server_fingerprint.transport.initial_max_data = 64;
    server_fingerprint
        .transport
        .initial_max_stream_data_bidi_remote = 3;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprints(client_fingerprint, server_fingerprint);

    let packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect("client send credit should not block this receive-side test")
        .expect("client should emit a packet");
    let error = server
        .open_client_application_packet(packet.packet.as_ref())
        .expect_err("server must reject client data over its receive stream window");

    assert!(error.to_string().contains("flow control"));
}

#[test]
fn native_h3_client_emits_max_data_after_receive_connection_window_threshold() {
    let mut client_fingerprint = Http3Fingerprint::chrome();
    client_fingerprint.transport.initial_max_data = 8;
    client_fingerprint.transport.max_connection_window = 16;
    client_fingerprint
        .transport
        .initial_max_stream_data_bidi_local = 64;
    let mut server_fingerprint = Http3Fingerprint::chrome();
    server_fingerprint.transport.initial_max_data = 64;
    server_fingerprint
        .transport
        .initial_max_stream_data_bidi_local = 64;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprints(client_fingerprint, server_fingerprint);

    let packet = server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"eight!!!"), false)
        .expect("server send credit should not block receive-window update test");
    client
        .open_server_application_packet(packet.packet.as_ref())
        .expect("client should accept data below the advertised receive limit");

    assert!(
        client
            .build_client_receive_flow_control_update_packets()
            .expect("client should packetize receive-window updates")
            .is_empty(),
        "receive credit must not be advertised before public body consumption"
    );
    client
        .record_client_stream_consumed(0, 8)
        .expect("public body consumption should release receive credit");

    let updates = client
        .build_client_receive_flow_control_update_packets()
        .expect("client should packetize receive-window updates");
    let frames = updates
        .iter()
        .flat_map(|packet| {
            server
                .open_client_application_packet(packet.packet.as_ref())
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(frames.contains(&QuicFrame::MaxData(16)));
}

#[test]
fn native_h3_server_emits_max_stream_data_after_receive_stream_window_threshold() {
    let mut client_fingerprint = Http3Fingerprint::chrome();
    client_fingerprint.transport.initial_max_data = 64;
    client_fingerprint
        .transport
        .initial_max_stream_data_bidi_remote = 64;
    let mut server_fingerprint = Http3Fingerprint::chrome();
    server_fingerprint.transport.initial_max_data = 64;
    server_fingerprint
        .transport
        .initial_max_stream_data_bidi_remote = 8;
    server_fingerprint.transport.max_stream_window = 16;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprints(client_fingerprint, server_fingerprint);

    let packet = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"eight!!!"), false)
        .expect("client send credit should not block receive-window update test")
        .expect("client should emit a packet");
    server
        .open_client_application_packet(packet.packet.as_ref())
        .expect("server should accept data below the advertised receive limit");

    assert!(
        server
            .build_server_receive_flow_control_update_packets()
            .expect("server should packetize receive-window updates")
            .is_empty(),
        "receive credit must not be advertised before public body consumption"
    );
    server
        .record_server_stream_consumed(0, 8)
        .expect("public body consumption should release receive credit");

    let updates = server
        .build_server_receive_flow_control_update_packets()
        .expect("server should packetize receive-window updates");
    let frames = updates
        .iter()
        .flat_map(|packet| {
            client
                .open_server_application_packet(packet.packet.as_ref())
                .unwrap()
        })
        .collect::<Vec<_>>();

    assert!(frames.contains(&QuicFrame::MaxStreamData {
        stream_id: 0,
        max_stream_data: 16,
    }));
}

#[test]
fn native_h3_server_enforces_peer_initial_flow_control_on_application_stream() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 3;
    fingerprint.transport.initial_max_stream_data_bidi_local = 3;
    let (_, _, mut server) = completed_native_server_handshake_with_fingerprint(fingerprint);

    let error = server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("server must not send over peer flow-control credit");

    assert!(error.to_string().contains("flow control"));
}

#[test]
fn native_h3_client_applies_server_max_data_to_unblock_flow_control() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 3;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 64;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    let blocked = client
        .build_client_application_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("client must start blocked by peer connection limit");
    assert!(blocked.to_string().contains("flow control"));

    let max_data = server.build_server_max_data_packet(64).unwrap();
    client
        .open_server_application_packet(max_data.packet.as_ref())
        .unwrap();

    assert!(client
        .build_client_application_stream_packet(0, Bytes::from_static(b"four"), false)
        .unwrap()
        .is_some());
}

#[test]
fn native_h3_server_applies_client_max_stream_data_to_unblock_flow_control() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 64;
    fingerprint.transport.initial_max_stream_data_bidi_local = 3;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    let blocked = server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("server must start blocked by peer stream limit");
    assert!(blocked.to_string().contains("flow control"));

    let max_stream_data = client.build_client_max_stream_data_packet(0, 64).unwrap();
    server
        .open_client_application_packet(max_stream_data.packet.as_ref())
        .unwrap();

    server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"four"), false)
        .unwrap();
}

#[test]
fn native_h3_client_applies_server_max_streams_to_unblock_bidirectional_streams() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 64;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 64;
    fingerprint.transport.initial_max_streams_bidi = 1;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    client
        .build_client_application_stream_packet(0, Bytes::from_static(b"one"), false)
        .unwrap()
        .unwrap();
    let blocked = client
        .build_client_application_stream_packet(4, Bytes::from_static(b"two"), false)
        .expect_err("client must start blocked by peer bidirectional stream limit");
    assert!(blocked.to_string().contains("flow control"));

    let max_streams = server.build_server_max_streams_packet(true, 2).unwrap();
    client
        .open_server_application_packet(max_streams.packet.as_ref())
        .unwrap();

    assert!(client
        .build_client_application_stream_packet(4, Bytes::from_static(b"two"), false)
        .unwrap()
        .is_some());
}

#[test]
fn native_h3_request_retry_after_streams_blocked_reuses_blocked_stream_id() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 4096;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 4096;
    fingerprint.transport.initial_max_streams_bidi = 1;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);
    let uri: http::Uri = "https://localhost/native".parse().unwrap();

    let first = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    assert_eq!(first.stream_id, 0);

    client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .expect_err("second request must block behind peer stream limit");

    let max_streams = server.build_server_max_streams_packet(true, 2).unwrap();
    client
        .open_server_application_packet(max_streams.packet.as_ref())
        .unwrap();

    let retry = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    assert_eq!(retry.stream_id, 4);
}

#[test]
fn native_h3_data_retry_after_stream_data_blocked_reuses_blocked_offset() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 4096;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 96;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);
    let uri: http::Uri = "https://localhost/native".parse().unwrap();

    let request = client
        .build_client_h3_request_start_packet(&http::Method::POST, &uri, &[], None, false)
        .unwrap();
    let first_data = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"ok"), false)
        .unwrap()
        .unwrap();
    server
        .open_client_h3_event_packet(request.packet.as_ref())
        .unwrap();
    server
        .open_client_h3_event_packet(first_data.packet.as_ref())
        .unwrap();

    client
        .build_client_h3_data_packet(request.stream_id, Bytes::from(vec![b'x'; 128]), false)
        .expect_err("oversized DATA must block behind peer stream data limit");

    let max_stream_data = server
        .build_server_max_stream_data_packet(request.stream_id, 512)
        .unwrap();
    client
        .open_server_application_packet(max_stream_data.packet.as_ref())
        .unwrap();

    let retry = client
        .build_client_h3_data_packet(request.stream_id, Bytes::from_static(b"retry"), false)
        .unwrap()
        .unwrap();
    let opened = server
        .open_client_h3_event_packet(retry.packet.as_ref())
        .unwrap();

    assert!(matches!(
        opened.as_slice(),
        [ClientH3Event::Stream(event)]
            if event.stream_id == request.stream_id
                && event.frames.iter().any(|frame| matches!(frame, H3Frame::Data(data) if data.as_ref() == b"retry"))
    ));
}

#[test]
fn native_h3_server_applies_client_max_streams_to_unblock_unidirectional_streams() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 256;
    fingerprint.transport.initial_max_stream_data_uni = 256;
    fingerprint.transport.initial_max_streams_uni = 1;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    server
        .build_server_h3_settings_packet(&Http3Fingerprint::chrome())
        .unwrap();
    let blocked = server
        .build_server_h3_raw_stream_packet(7, Bytes::from_static(b"two"), false)
        .expect_err("server must start blocked by peer unidirectional stream limit");
    assert!(blocked.to_string().contains("flow control"));

    let max_streams = client.build_client_max_streams_packet(false, 2).unwrap();
    server
        .open_client_application_packet(max_streams.packet.as_ref())
        .unwrap();

    server
        .build_server_h3_raw_stream_packet(7, Bytes::from_static(b"two"), false)
        .unwrap();
}

#[test]
fn native_h3_client_emits_data_blocked_after_connection_flow_control_block() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 3;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 64;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    client
        .build_client_application_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("client must start blocked by peer connection limit");
    let blocked = client
        .build_client_flow_control_blocked_packet()
        .unwrap()
        .expect("blocked send should schedule DATA_BLOCKED");

    let frames = server
        .open_client_application_packet(blocked.packet.as_ref())
        .unwrap();
    assert_eq!(frames, vec![QuicFrame::DataBlocked { maximum_data: 3 }]);
}

#[test]
fn native_h3_server_emits_stream_data_blocked_after_stream_flow_control_block() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 64;
    fingerprint.transport.initial_max_stream_data_bidi_local = 3;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    server
        .build_server_h3_raw_stream_packet(0, Bytes::from_static(b"four"), false)
        .expect_err("server must start blocked by peer stream limit");
    let blocked = server
        .build_server_flow_control_blocked_packet()
        .unwrap()
        .expect("blocked send should schedule STREAM_DATA_BLOCKED");

    let frames = client
        .open_server_application_packet(blocked.packet.as_ref())
        .unwrap();
    assert_eq!(
        frames,
        vec![QuicFrame::StreamDataBlocked {
            stream_id: 0,
            maximum_stream_data: 3,
        }]
    );
}

#[test]
fn native_h3_client_emits_streams_blocked_after_stream_count_block() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_data = 64;
    fingerprint.transport.initial_max_stream_data_bidi_remote = 64;
    fingerprint.transport.initial_max_streams_bidi = 1;
    let (_, mut client, mut server) =
        completed_native_server_handshake_with_fingerprint(fingerprint);

    client
        .build_client_application_stream_packet(0, Bytes::from_static(b"one"), false)
        .unwrap()
        .unwrap();
    client
        .build_client_application_stream_packet(4, Bytes::from_static(b"two"), false)
        .expect_err("client must start blocked by peer bidirectional stream limit");
    let blocked = client
        .build_client_flow_control_blocked_packet()
        .unwrap()
        .expect("blocked send should schedule STREAMS_BLOCKED");

    let frames = server
        .open_client_application_packet(blocked.packet.as_ref())
        .unwrap();
    assert_eq!(
        frames,
        vec![QuicFrame::StreamsBlocked {
            bidirectional: true,
            maximum_streams: 1,
        }]
    );
}

#[test]
fn native_h3_server_handshake_surfaces_client_reset_and_stop_events_once() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(
            &http::Method::POST,
            &uri,
            &[],
            Some(Bytes::from_static(b"uploaded")),
        )
        .unwrap();
    server
        .open_client_h3_event_packet(request.packet.as_ref())
        .unwrap();

    let reset = client
        .build_client_reset_stream_packet(request.stream_id, 0x010c)
        .unwrap();
    let stop = client
        .build_client_stop_sending_packet(request.stream_id, 0x010d)
        .unwrap();

    assert_eq!(
        server
            .open_client_h3_event_packet(reset.packet.as_ref())
            .unwrap(),
        vec![ClientH3Event::ResetStream {
            stream_id: request.stream_id,
            error_code: 0x010c,
            final_size: request.data.len() as u64,
        }]
    );
    assert_eq!(
        server
            .open_client_h3_event_packet(stop.packet.as_ref())
            .unwrap(),
        vec![ClientH3Event::StopSending {
            stream_id: request.stream_id,
            error_code: 0x010d,
        }]
    );
}

#[test]
fn native_h3_server_handshake_packetizes_raw_stream_bytes_and_fin_only() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let uri: http::Uri = "https://localhost/native".parse().unwrap();
    let request = client
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let request_events = server
        .open_client_h3_stream_packet(request.packet.as_ref())
        .unwrap();
    let stream_id = request_events[0].stream_id;

    let raw_data = server
        .build_server_h3_raw_stream_packet(
            stream_id,
            encode_h3_frame(&H3Frame::Data(Bytes::from_static(b"raw"))),
            false,
        )
        .unwrap();
    let fin_only = server
        .build_server_h3_raw_stream_packet(stream_id, Bytes::new(), true)
        .unwrap();

    let data_events = client
        .open_server_h3_stream_packet(raw_data.packet.as_ref())
        .unwrap();
    let fin_events = client
        .open_server_h3_stream_packet(fin_only.packet.as_ref())
        .unwrap();

    assert_eq!(
        data_events[0].frames,
        vec![H3Frame::Data(Bytes::from_static(b"raw"))]
    );
    assert!(!data_events[0].fin);
    assert!(fin_events[0].frames.is_empty());
    assert!(fin_events[0].fin);
}

#[test]
fn native_h3_handshake_opens_server_initial_and_feeds_tls_crypto() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let keys = derive_initial_key_material(client_destination_cid.as_bytes()).unwrap();
    let plaintext = initial_crypto_plaintext(b"\xff\0\0\0", 64).unwrap();
    let header = encode_initial_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: 1,
        destination_cid: client_source_cid,
        source_cid: client_destination_cid,
        token: Bytes::new(),
        packet_number: 0,
        packet_number_len: 1,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 1;
    let packet = protect_long_header_packet(
        &keys.server,
        0,
        &header,
        packet_number_offset,
        1,
        &plaintext,
    )
    .unwrap();

    let err = handshake
        .process_server_datagram(&packet)
        .expect_err("invalid server Initial CRYPTO must fail through TLS");

    assert!(err.to_string().contains("server CRYPTO"));
}

#[test]
fn native_h3_handshake_rejects_version_negotiation_without_quic_v1() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let packet = version_negotiation_packet(
        &client_source_cid,
        &client_destination_cid,
        &[0xff00_001d, 0x709a_50c4],
    );

    let err = handshake
        .process_server_datagram(&packet)
        .expect_err("VN without QUIC v1 must stop native H3 handshake");

    assert!(err.to_string().contains("QUIC version 1"));
}

#[test]
fn native_h3_handshake_ignores_version_negotiation_that_lists_quic_v1() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let packet = version_negotiation_packet(&client_source_cid, &client_destination_cid, &[1]);

    let processed = handshake
        .process_server_datagram(&packet)
        .expect("VN that lists the selected version must be ignored");

    assert!(processed.is_empty());
}

#[test]
fn native_h3_handshake_validates_retry_and_queues_new_initial() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let original_initial = handshake.client_initial().packet.clone();
    let retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &retry_source_cid,
        b"retry-token",
    );

    let processed = handshake
        .process_server_datagram(&retry)
        .expect("valid Retry should be accepted by client handshake");
    let pending = handshake
        .take_pending_client_initial()
        .expect("Retry should queue a token-bearing Initial");

    assert!(processed.is_empty());
    assert_ne!(pending.packet, original_initial);
    let header = decode_long_header(&pending.packet).unwrap();
    assert_eq!(header.destination_cid, retry_source_cid);
    assert_eq!(header.source_cid, client_source_cid);
    assert_eq!(header.token, Bytes::from_static(b"retry-token"));

    let packets = split_long_header_datagram(pending.packet.as_ref()).unwrap();
    let retry_keys = derive_initial_key_material(retry_source_cid.as_bytes()).unwrap();
    let opened = open_long_header_packet(
        &retry_keys.client,
        pending.packet.as_ref(),
        packets[0].packet_number_offset,
        1,
    )
    .unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(opened.packet_number, 1);
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == &pending.crypto_data
    ));
}

#[test]
fn native_h3_handshake_retry_restarts_initial_crypto_offset_at_zero_with_new_dcid() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &retry_source_cid,
        b"retry-token",
    );

    handshake
        .process_server_datagram(&retry)
        .expect("valid Retry is accepted");
    let pending = handshake
        .take_pending_client_initial()
        .expect("Retry queues a token-bearing Initial");

    let packets = split_long_header_datagram(pending.packet.as_ref()).unwrap();
    let retry_keys = derive_initial_key_material(retry_source_cid.as_bytes()).unwrap();
    let opened = open_long_header_packet(
        &retry_keys.client,
        pending.packet.as_ref(),
        packets[0].packet_number_offset,
        1,
    )
    .unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    assert!(
        matches!(&frames[0], QuicFrame::Crypto { offset, .. } if *offset == 0),
        "Retry Initial must restart CRYPTO offset at zero per RFC9000 section 7.2"
    );
    assert!(handshake.retry_received());
}

#[test]
fn native_h3_handshake_ignores_second_retry_per_rfc9000_section_17_2_5_2() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let first_retry_source_cid = ConnectionId::from_static(b"retry-scid-1");
    let second_retry_source_cid = ConnectionId::from_static(b"retry-scid-2");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();

    let first = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &first_retry_source_cid,
        b"first-token",
    );
    handshake
        .process_server_datagram(&first)
        .expect("first Retry is accepted");
    let first_pending = handshake
        .take_pending_client_initial()
        .expect("first Retry queues an Initial");
    let first_header = decode_long_header(&first_pending.packet).unwrap();
    assert_eq!(first_header.token, Bytes::from_static(b"first-token"));

    let second = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &second_retry_source_cid,
        b"second-token",
    );
    handshake
        .process_server_datagram(&second)
        .expect("second Retry must be silently discarded per RFC9000 section 17.2.5.2");

    assert!(handshake.take_pending_client_initial().is_none());
}

#[test]
fn native_h3_handshake_discards_retry_after_server_initial_packet_observed() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let server_source_cid = ConnectionId::from_static(b"native-server-cid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        server_source_cid,
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    client
        .process_server_datagram(&server_flight.datagram)
        .expect("server Initial+Handshake flight is accepted");

    let late_retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &ConnectionId::from_static(b"late-retry-scid"),
        b"late-retry-token",
    );

    client
        .process_server_datagram(&late_retry)
        .expect("late Retry must be silently discarded per RFC9000 section 17.2.5.1");
    assert!(client.take_pending_client_initial().is_none());
}

#[test]
fn native_h3_handshake_discards_retry_with_corrupted_integrity_tag() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let mut retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &retry_source_cid,
        b"retry-token",
    )
    .to_vec();
    let last = retry.len() - 1;
    retry[last] ^= 0x01;

    handshake
        .process_server_datagram(&retry)
        .expect("Retry with invalid integrity tag must be silently discarded");
    assert!(handshake.take_pending_client_initial().is_none());
    assert!(!handshake.retry_received());
}

#[test]
fn native_h3_handshake_discards_retry_with_empty_token_per_rfc9000_section_17_2_5() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &retry_source_cid,
        b"",
    );

    handshake
        .process_server_datagram(&retry)
        .expect("Retry with empty token must be silently discarded");
    assert!(handshake.take_pending_client_initial().is_none());
    assert!(!handshake.retry_received());
}

#[test]
fn native_h3_handshake_discards_retry_whose_source_cid_matches_original_destination() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let retry = retry_packet(
        &client_destination_cid,
        &client_source_cid,
        &client_destination_cid,
        b"retry-token",
    );

    handshake
        .process_server_datagram(&retry)
        .expect("Retry whose source CID equals original DCID must be discarded");
    assert!(handshake.take_pending_client_initial().is_none());
}

#[test]
fn native_h3_handshake_version_negotiation_restarts_with_supported_draft_version() {
    const DRAFT_VERSION: u32 = 0x0000_0029;
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    handshake
        .set_supported_versions(vec![1, DRAFT_VERSION])
        .unwrap();
    let original_initial = handshake.client_initial().packet.clone();

    let vn = version_negotiation_packet(
        &client_source_cid,
        &client_destination_cid,
        &[DRAFT_VERSION, 0x709a_50c4],
    );
    let processed = handshake
        .process_server_datagram(&vn)
        .expect("VN that lists a supported draft must trigger restart");
    let pending = handshake
        .take_pending_client_initial()
        .expect("VN restart queues a fresh Initial");

    assert!(processed.is_empty());
    assert!(handshake.version_negotiation_received());
    assert_eq!(handshake.client_initial_version(), DRAFT_VERSION);
    assert_ne!(pending.packet, original_initial);

    let header = decode_long_header(&pending.packet).unwrap();
    assert_eq!(
        header.version, DRAFT_VERSION,
        "VN restart must encode the chosen version in the Initial header"
    );
    assert_eq!(header.destination_cid, client_destination_cid);
    assert_ne!(
        header.source_cid, client_source_cid,
        "VN restart must regenerate a fresh source connection ID"
    );
    assert_eq!(
        header.source_cid.as_bytes().len(),
        client_source_cid.as_bytes().len(),
    );
}

#[test]
fn native_h3_handshake_version_negotiation_errors_when_no_supported_version_in_list() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let vn = version_negotiation_packet(
        &client_source_cid,
        &client_destination_cid,
        &[0xff00_001d, 0x709a_50c4],
    );

    let err = handshake
        .process_server_datagram(&vn)
        .expect_err("VN without overlap must surface a clear error");

    assert!(err.to_string().contains("version_negotiation_failed"));
    assert!(handshake.take_pending_client_initial().is_none());
    assert!(!handshake.version_negotiation_received());
}

#[test]
fn native_h3_handshake_ignores_second_version_negotiation_after_restart() {
    const DRAFT_VERSION: u32 = 0x0000_0029;
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    handshake
        .set_supported_versions(vec![1, DRAFT_VERSION])
        .unwrap();

    let first_vn = version_negotiation_packet(
        &client_source_cid,
        &client_destination_cid,
        &[DRAFT_VERSION],
    );
    handshake
        .process_server_datagram(&first_vn)
        .expect("first VN triggers restart");
    let first_pending = handshake
        .take_pending_client_initial()
        .expect("first VN restart queues an Initial");
    let new_source_cid = decode_long_header(&first_pending.packet)
        .unwrap()
        .source_cid;

    let second_vn =
        version_negotiation_packet(&new_source_cid, &client_destination_cid, &[DRAFT_VERSION]);
    let processed = handshake
        .process_server_datagram(&second_vn)
        .expect("subsequent VN must be silently ignored");

    assert!(processed.is_empty());
    assert!(handshake.take_pending_client_initial().is_none());
}

#[test]
fn native_h3_handshake_retry_after_version_negotiation_restart_uses_new_source_cid() {
    const DRAFT_VERSION: u32 = 0x0000_0029;
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid-vn");
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    handshake
        .set_supported_versions(vec![1, DRAFT_VERSION])
        .unwrap();

    let vn = version_negotiation_packet(
        &client_source_cid,
        &client_destination_cid,
        &[DRAFT_VERSION],
    );
    handshake
        .process_server_datagram(&vn)
        .expect("VN restart succeeds");
    let restarted = handshake
        .take_pending_client_initial()
        .expect("VN restart queues fresh Initial");
    let new_source_cid = decode_long_header(&restarted.packet).unwrap().source_cid;

    let retry = retry_packet(
        &client_destination_cid,
        &new_source_cid,
        &retry_source_cid,
        b"vn-retry-token",
    );
    handshake
        .process_server_datagram(&retry)
        .expect("Retry against post-VN attempt is accepted");
    let retry_initial = handshake
        .take_pending_client_initial()
        .expect("Retry restart queues a token-bearing Initial");
    let retry_header = decode_long_header(&retry_initial.packet).unwrap();

    assert_eq!(retry_header.destination_cid, retry_source_cid);
    assert_eq!(retry_header.source_cid, new_source_cid);
    assert_eq!(retry_header.token, Bytes::from_static(b"vn-retry-token"));
    assert!(handshake.retry_received());
}

#[test]
fn native_h3_handshake_rejects_server_original_dcid_transport_parameter_mismatch() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let server_source_cid = ConnectionId::from_static(b"server-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new_with_transport_parameter_connection_ids(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        client_source_cid,
        server_source_cid.clone(),
        ConnectionId::from_static(b"wrong-dcid"),
        server_source_cid,
        None,
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();

    let err = client
        .process_server_datagram(&server_flight.datagram)
        .expect_err("client must reject mismatched server original_destination_connection_id");

    assert!(err
        .to_string()
        .contains("original_destination_connection_id"));
}

#[test]
fn native_h3_handshake_requires_retry_source_transport_parameter_after_retry() {
    let fingerprint = Http3Fingerprint::chrome();
    let original_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let retry_source_cid = ConnectionId::from_static(b"retry-scid");
    let server_source_cid = ConnectionId::from_static(b"server-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        original_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let retry = retry_packet(
        &original_destination_cid,
        &client_source_cid,
        &retry_source_cid,
        b"retry-token",
    );
    client.process_server_datagram(&retry).unwrap();
    let retry_initial = client.take_pending_client_initial().unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new_with_transport_parameter_connection_ids(
        &fingerprint,
        &cert_pem,
        &key_pem,
        retry_source_cid,
        client_source_cid,
        server_source_cid.clone(),
        original_destination_cid,
        server_source_cid,
        None,
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(retry_initial.packet.as_ref())
        .unwrap();

    let err = client
        .process_server_datagram(&server_flight.datagram)
        .expect_err("server transport parameters must prove the Retry source CID");

    assert!(err.to_string().contains("retry_source_connection_id"));
}

#[test]
fn native_h3_handshake_exposes_single_client_initial_packet() {
    let handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();

    assert!(handshake.client_initial().packet.len() >= 1200);
    assert!(handshake
        .client_initial()
        .crypto_data
        .windows(3)
        .any(|window| window == b"\x02h3"));
}

#[test]
fn native_h3_handshake_installs_read_handshake_secret_for_server_packets() {
    let read_secret = Bytes::from_static(&[0x33; 32]);
    let write_secret = Bytes::from_static(&[0x44; 32]);
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();

    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Handshake,
                secret: read_secret.clone(),
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Handshake,
                secret: write_secret,
            },
        ])
        .unwrap();

    assert_eq!(
        handshake.server_handshake_keys().unwrap(),
        &derive_packet_key_material_from_secret(read_secret).unwrap()
    );
}

#[test]
fn native_h3_handshake_reports_application_readiness_after_1rtt_keys() {
    let read_secret = Bytes::from_static(&[0x41; 32]);
    let write_secret = Bytes::from_static(&[0x42; 32]);
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();

    assert!(!handshake.is_application_ready());

    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    assert!(!handshake.is_application_ready());

    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Application,
            secret: read_secret,
        }])
        .unwrap();

    assert!(handshake.is_application_ready());
}

#[test]
fn native_h3_handshake_opens_server_handshake_crypto_packet() {
    let read_secret = Bytes::from_static(&[0x55; 32]);
    let keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Handshake,
            secret: read_secret,
        }])
        .unwrap();
    let plaintext = encode_frame(&QuicFrame::Crypto {
        offset: 0,
        data: Bytes::from_static(b"\xff\0\0\0"),
    });
    let header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"client-scid"),
        source_cid: ConnectionId::from_static(b"server-dcid"),
        token: Bytes::new(),
        packet_number: 0,
        packet_number_len: 1,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 1;
    let packet =
        protect_long_header_packet(&keys, 0, &header, packet_number_offset, 1, &plaintext).unwrap();

    let err = handshake
        .process_server_datagram(&packet)
        .expect_err("invalid server Handshake CRYPTO must fail through TLS");

    assert!(err.to_string().contains("server CRYPTO"));
}

#[test]
fn native_h3_handshake_packetizes_client_handshake_crypto_with_write_secret() {
    let write_secret = Bytes::from_static(&[0x66; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Handshake,
            secret: write_secret,
        }])
        .unwrap();

    let packet = handshake
        .build_client_handshake_crypto_packet(Bytes::from_static(b"client-finished"))
        .unwrap()
        .expect("non-empty handshake crypto should produce a packet");
    let opened =
        open_long_header_packet(&keys, &packet.packet, packet.packet_number_offset, 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(packet.packet_number, 0);
    assert_eq!(opened.packet_number, 0);
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == b"client-finished".as_slice()
    ));
}

#[test]
fn native_h3_client_retransmits_unacked_handshake_crypto_after_pto() {
    let write_secret = Bytes::from_static(&[0x76; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Handshake,
            secret: write_secret,
        }])
        .unwrap();

    let original = handshake
        .build_client_handshake_crypto_packet(Bytes::from_static(b"client-finished"))
        .unwrap()
        .expect("non-empty handshake crypto should produce a packet");

    let retransmits = handshake
        .retransmit_pto_client_handshake_crypto_packets(Instant::now(), Duration::ZERO)
        .unwrap();

    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].packet_number, original.packet_number + 1);
    assert_eq!(retransmits[0].crypto_data, original.crypto_data);
    let opened = open_long_header_packet(
        &keys,
        &retransmits[0].packet,
        retransmits[0].packet_number_offset,
        retransmits[0].packet_number,
    )
    .unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == b"client-finished".as_slice()
    ));
}

#[test]
fn native_h3_server_retransmits_unacked_initial_and_handshake_crypto_after_pto() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let server_source_cid = ConnectionId::from_static(b"native-server-cid");
    let client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        client_source_cid,
        server_source_cid,
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let server_handshake_keys = server_flight
        .secrets
        .iter()
        .find(|secret| {
            secret.direction == QuicSecretDirection::Write
                && secret.level == QuicEncryptionLevel::Handshake
        })
        .unwrap()
        .packet_key_material()
        .unwrap();

    let retransmits = server
        .retransmit_pto_server_crypto_packets(Instant::now(), Duration::ZERO)
        .unwrap();

    assert_eq!(retransmits.len(), 2);
    assert_eq!(retransmits[0].packet_type, LongHeaderType::Initial);
    assert_eq!(
        retransmits[0].packet_number,
        server_flight.packets[0].packet_number + 1
    );
    assert_eq!(
        retransmits[0].crypto_data,
        server_flight.packets[0].crypto_data
    );
    assert_eq!(retransmits[1].packet_type, LongHeaderType::Handshake);
    assert_eq!(
        retransmits[1].packet_number,
        server_flight.packets[1].packet_number + 1
    );
    assert_eq!(
        retransmits[1].crypto_data,
        server_flight.packets[1].crypto_data
    );

    let initial_keys = derive_initial_key_material(client_destination_cid.as_bytes()).unwrap();
    let opened_initial = open_long_header_packet(
        &initial_keys.server,
        &retransmits[0].packet,
        retransmits[0].packet_number_offset,
        retransmits[0].packet_number,
    )
    .unwrap();
    assert!(matches!(
        &decode_frames(&opened_initial.payload).unwrap()[0],
        QuicFrame::Crypto { offset: 0, data } if data == &retransmits[0].crypto_data
    ));
    let opened_handshake = open_long_header_packet(
        &server_handshake_keys,
        &retransmits[1].packet,
        retransmits[1].packet_number_offset,
        retransmits[1].packet_number,
    )
    .unwrap();
    assert!(matches!(
        &decode_frames(&opened_handshake.payload).unwrap()[0],
        QuicFrame::Crypto { offset: 0, data } if data == &retransmits[1].crypto_data
    ));
}

#[test]
fn native_h3_client_initial_ack_retires_pto_retransmission() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    client.record_client_initial_sent_at(Instant::now() - Duration::from_secs(1));
    server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let ack = server
        .build_server_initial_ack_packet()
        .unwrap()
        .expect("server must ACK the client Initial");

    client.process_server_datagram(ack.packet.as_ref()).unwrap();

    assert_eq!(
        client
            .retransmit_pto_client_initial_crypto_packets(Instant::now(), Duration::ZERO)
            .unwrap(),
        Vec::new(),
        "ACKed client Initial CRYPTO must not be retransmitted on PTO"
    );
    assert_eq!(
        client.recovery().congestion().bytes_in_flight(),
        0,
        "Initial ACK must release recovery bytes-in-flight"
    );
}

#[tokio::test]
async fn native_h3_backend_sends_client_initial_datagram_before_timeout() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("native backend should send a UDP datagram")
        .unwrap();
        buf.truncate(len);
        buf
    });
    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_max_idle_timeout(50)
        .with_dns_config(DnsConfig::new().with_override("native-h3.test", vec![server_addr]));

    let result = client
        .send_request("https://native-h3.test/", "GET", vec![], None)
        .await;
    let datagram = received.await.unwrap();
    let packets = split_long_header_datagram(&datagram).unwrap();
    let keys = derive_initial_key_material(packets[0].destination_cid.as_bytes()).unwrap();
    let opened = open_long_header_packet(
        &keys.client,
        &packets[0].packet,
        packets[0].packet_number_offset,
        0,
    )
    .unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert!(matches!(result, Err(specter::Error::Timeout(_))));
    assert!(datagram.len() >= 1200);
    assert_eq!(packets[0].packet_type, LongHeaderType::Initial);
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { data, .. } if data.windows(3).any(|window| window == b"\x02h3")
    ));
}

#[tokio::test]
async fn native_h3_backend_uses_fingerprint_connection_id_lengths() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("native backend should send a UDP datagram")
        .unwrap();
        buf.truncate(len);
        buf
    });
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.destination_connection_id_len = 12;
    fingerprint.transport.source_connection_id_len = 8;
    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_http3_fingerprint(fingerprint)
        .with_max_idle_timeout(50)
        .with_dns_config(DnsConfig::new().with_override("native-h3.test", vec![server_addr]));

    let result = client
        .send_request("https://native-h3.test/", "GET", vec![], None)
        .await;
    let datagram = received.await.unwrap();
    let packets = split_long_header_datagram(&datagram).unwrap();

    assert!(matches!(result, Err(specter::Error::Timeout(_))));
    assert_eq!(packets[0].destination_cid.as_bytes().len(), 12);
    assert_eq!(packets[0].source_cid.as_bytes().len(), 8);
}

#[tokio::test]
async fn native_h3_backend_uses_fingerprint_initial_datagram_size() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .expect("native backend should send a UDP datagram")
        .unwrap();
        buf.truncate(len);
        buf
    });
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_datagram_size = 1280;
    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_http3_fingerprint(fingerprint)
        .with_max_idle_timeout(50)
        .with_dns_config(DnsConfig::new().with_override("native-h3.test", vec![server_addr]));

    let result = client
        .send_request("https://native-h3.test/", "GET", vec![], None)
        .await;
    let datagram = received.await.unwrap();

    assert!(matches!(result, Err(specter::Error::Timeout(_))));
    assert_eq!(datagram.len(), 1280);
}

#[tokio::test]
async fn native_h3_backend_completes_get_against_mock_h3_server() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"native-h3-ok", true)
            .await;
    });

    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_max_idle_timeout(250)
        .danger_accept_invalid_certs(true);
    let mut response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.send_request(&url, "GET", vec![], None),
    )
    .await
    .expect("native H3 GET should not hang")
    .expect("native H3 GET should complete");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.body_mut().collect_to_bytes().await.unwrap(),
        b"native-h3-ok".as_slice()
    );
}

#[tokio::test]
async fn native_h3_backend_replays_rejected_zero_rtt_get_and_reports_status() {
    let fingerprint = Http3Fingerprint::default();
    let ticket = capture_mock_server_session_ticket(&fingerprint);
    let cache = NativeH3SessionCache::new();
    cache.insert(
        native_h3_cache_key_for_mock_host("127.0.0.1", &fingerprint),
        ticket,
        u32::MAX,
        None,
    );

    let server = MockH3Server::new_with_session_resumption().await.unwrap();
    let url = server.url();
    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"zero-rtt-replayed", true)
            .await;
    });

    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_native_session_cache(cache)
        .with_max_idle_timeout(500)
        .danger_accept_invalid_certs(true);

    let mut response = tokio::time::timeout(
        Duration::from_secs(2),
        client.send_request(&url, "GET", vec![], None),
    )
    .await
    .expect("native H3 0-RTT GET should not hang")
    .expect("native H3 0-RTT GET should replay over 1-RTT when rejected");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.body_mut().collect_to_bytes().await.unwrap(),
        b"zero-rtt-replayed".as_slice()
    );
    assert_eq!(
        client.last_native_handshake_status(),
        NativeH3HandshakeStatus::EarlyRejected,
        "client-level status must propagate the TLS 0-RTT rejection that triggered replay"
    );
}

#[tokio::test]
async fn native_h3_backend_rejects_self_signed_without_danger() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"should-not-pass", true)
            .await;
    });

    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_max_idle_timeout(250);

    let err = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.send_request(&url, "GET", vec![], None),
    )
    .await
    .expect("native H3 verification failure should not hang")
    .expect_err("native H3 must reject the mock self-signed certificate by default");
    let err = err.to_string();

    assert!(
        err.contains("TLS") || err.contains("certificate") || err.contains("server CRYPTO"),
        "unexpected native H3 verification error: {err}"
    );
}

#[tokio::test]
async fn native_h3_backend_accepts_self_signed_with_custom_root() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let (ca_cert, _) = helpers::tls::cached_cert_and_key_pem();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"trusted-native-h3", true)
            .await;
    });

    let client = H3Client::new()
        .with_h3_backend(H3Backend::Native)
        .with_max_idle_timeout(250)
        .add_root_certificate(ca_cert);

    let mut response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.send_request(&url, "GET", vec![], None),
    )
    .await
    .expect("native H3 trusted custom root request should not hang")
    .expect("native H3 should trust the configured custom root");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.body_mut().collect_to_bytes().await.unwrap(),
        b"trusted-native-h3".as_slice()
    );
}

#[test]
fn native_h3_handshake_builds_initial_ack_for_observed_server_initial_packet() {
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let keys = derive_initial_key_material(client_destination_cid.as_bytes()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        client_destination_cid.clone(),
        client_source_cid.clone(),
    )
    .unwrap();
    let mut plaintext = encode_frame(&QuicFrame::Ping).to_vec();
    plaintext.resize(24, 0);
    let plaintext = Bytes::from(plaintext);
    let header = encode_initial_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: 1,
        destination_cid: client_source_cid,
        source_cid: client_destination_cid,
        token: Bytes::new(),
        packet_number: 3,
        packet_number_len: 1,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 1;
    let packet = protect_long_header_packet(
        &keys.server,
        3,
        &header,
        packet_number_offset,
        1,
        &plaintext,
    )
    .unwrap();

    handshake.process_server_datagram(&packet).unwrap();
    let ack = handshake
        .build_client_initial_ack_packet()
        .unwrap()
        .expect("observed server Initial should produce an ACK");
    let opened =
        open_long_header_packet(&keys.client, &ack.packet, ack.packet_number_offset, 1).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(ack.packet_number, 1);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 3,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_handshake_builds_handshake_ack_with_write_keys() {
    let read_secret = Bytes::from_static(&[0x77; 32]);
    let write_secret = Bytes::from_static(&[0x88; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let client_keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Handshake,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Handshake,
                secret: write_secret,
            },
        ])
        .unwrap();
    let mut plaintext = encode_frame(&QuicFrame::Ping).to_vec();
    plaintext.resize(24, 0);
    let plaintext = Bytes::from(plaintext);
    let header = encode_long_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Handshake,
        version: 1,
        destination_cid: ConnectionId::from_static(b"client-scid"),
        source_cid: ConnectionId::from_static(b"server-dcid"),
        token: Bytes::new(),
        packet_number: 2,
        packet_number_len: 1,
        payload_len: plaintext.len() + 16,
    })
    .unwrap();
    let packet_number_offset = header.len() - 1;
    let packet = protect_long_header_packet(
        &server_keys,
        2,
        &header,
        packet_number_offset,
        1,
        &plaintext,
    )
    .unwrap();

    handshake.process_server_datagram(&packet).unwrap();
    let ack = handshake
        .build_client_handshake_ack_packet()
        .unwrap()
        .expect("observed server Handshake should produce an ACK");
    let opened =
        open_long_header_packet(&client_keys, &ack.packet, ack.packet_number_offset, 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(ack.packet_number, 0);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 2,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_handshake_builds_application_ack_with_write_keys() {
    let read_secret = Bytes::from_static(&[0x90; 32]);
    let write_secret = Bytes::from_static(&[0x91; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let client_keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();
    let mut plaintext = encode_frame(&QuicFrame::Ping).to_vec();
    plaintext.resize(24, 0);
    let plaintext = Bytes::from(plaintext);
    let packet = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        7,
        2,
        false,
        &plaintext,
    )
    .unwrap();

    handshake.open_server_application_packet(&packet).unwrap();
    let ack = handshake
        .build_client_application_ack_packet()
        .unwrap()
        .expect("observed server 1-RTT packet should produce an ACK");
    let opened = open_short_header_packet(&client_keys, &ack.packet, b"server-dcid".len(), 0)
        .expect("application ACK should be a protected short-header packet");
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(ack.packet_number, 0);
    assert!(matches!(
        &frames[0],
        QuicFrame::Ack {
            largest_acknowledged: 7,
            first_ack_range: 0,
            ..
        }
    ));
}

#[test]
fn native_h3_handshake_does_not_ack_application_ack_only_packet() {
    let read_secret = Bytes::from_static(&[0x92; 32]);
    let write_secret = Bytes::from_static(&[0x93; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();
    let mut plaintext = encode_frame(&QuicFrame::Ack {
        largest_acknowledged: 1,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    })
    .to_vec();
    plaintext.resize(24, 0);
    let plaintext = Bytes::from(plaintext);
    let packet = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        3,
        2,
        false,
        &plaintext,
    )
    .unwrap();

    handshake.open_server_application_packet(&packet).unwrap();

    assert!(handshake
        .build_client_application_ack_packet()
        .unwrap()
        .is_none());
}

#[test]
fn native_h3_handshake_answers_path_challenge_with_path_response() {
    let read_secret = Bytes::from_static(&[0x94; 32]);
    let write_secret = Bytes::from_static(&[0x95; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let client_keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();
    let challenge = *b"12345678";
    let packet = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        9,
        2,
        false,
        &encode_frame(&QuicFrame::PathChallenge(challenge)),
    )
    .unwrap();

    let events = handshake.open_server_h3_event_packet(&packet).unwrap();
    assert_eq!(events, vec![ServerH3Event::PathChallenge(challenge)]);

    let response = handshake
        .build_client_path_response_packet(challenge)
        .unwrap();
    let opened =
        open_short_header_packet(&client_keys, &response.packet, b"server-dcid".len(), 0).unwrap();

    assert_eq!(response.packet_number, 0);
    assert_eq!(
        decode_frames(&opened.payload)
            .unwrap()
            .into_iter()
            .filter(|frame| !matches!(frame, QuicFrame::Padding))
            .collect::<Vec<_>>(),
        vec![QuicFrame::PathResponse(challenge)]
    );
}

#[test]
fn native_h3_client_path_challenge_validates_only_matching_path_response() {
    let read_secret = Bytes::from_static(&[0x9a; 32]);
    let write_secret = Bytes::from_static(&[0x9b; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let client_keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();
    let challenge = *b"PATHPING";

    let challenge_packet = handshake
        .build_client_path_challenge_packet(challenge)
        .unwrap();
    let opened = open_short_header_packet(
        &client_keys,
        &challenge_packet.packet,
        b"server-dcid".len(),
        0,
    )
    .unwrap();

    assert_eq!(handshake.client_path_validation_pending_count(), 1);
    assert_eq!(
        decode_frames(&opened.payload)
            .unwrap()
            .into_iter()
            .filter(|frame| !matches!(frame, QuicFrame::Padding))
            .collect::<Vec<_>>(),
        vec![QuicFrame::PathChallenge(challenge)]
    );

    let wrong_response = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &encode_frame(&QuicFrame::PathResponse(*b"WRONGDAT")),
    )
    .unwrap();
    assert_eq!(
        handshake
            .open_server_h3_event_packet(&wrong_response)
            .unwrap(),
        Vec::<ServerH3Event>::new()
    );
    assert_eq!(handshake.client_path_validation_pending_count(), 1);
    assert!(!handshake.is_client_path_validated(&challenge));

    let response = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        1,
        2,
        false,
        &encode_frame(&QuicFrame::PathResponse(challenge)),
    )
    .unwrap();

    assert!(handshake
        .open_server_h3_event_packet(&response)
        .unwrap()
        .is_empty());
    assert!(handshake.is_client_path_validated(&challenge));
    assert_eq!(handshake.client_path_validation_pending_count(), 0);
}

#[test]
fn native_h3_client_path_migration_binds_validation_to_address_and_connection_id() {
    let read_secret = Bytes::from_static(&[0x6a; 32]);
    let write_secret = Bytes::from_static(&[0x6b; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();

    let migrated_address = SocketAddr::from(([198, 51, 100, 10], 4433));
    let wrong_address = SocketAddr::from(([203, 0, 113, 7], 4433));
    let migrated_cid = ConnectionId::from_static(b"migrated-cid");
    let challenge = *b"MIGRATE!";

    let new_cid_packet = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &encode_frame(&QuicFrame::NewConnectionId {
            sequence_number: 3,
            retire_prior_to: 0,
            connection_id: Bytes::copy_from_slice(migrated_cid.as_bytes()),
            stateless_reset_token: [0x42; 16],
        }),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet(&new_cid_packet)
        .unwrap()
        .is_empty());

    handshake
        .build_client_path_challenge_packet_for_address(migrated_address, 3, challenge)
        .unwrap();
    assert_eq!(handshake.client_path_validation_pending_count(), 1);
    assert!(!handshake.is_client_path_address_validated(&migrated_address));

    let wrong_response = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        1,
        2,
        false,
        &encode_frame(&QuicFrame::PathResponse(challenge)),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet_from(&wrong_response, wrong_address)
        .unwrap()
        .is_empty());
    assert_eq!(handshake.client_path_validation_pending_count(), 1);
    assert!(!handshake.is_client_path_address_validated(&migrated_address));

    let matching_response = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        2,
        2,
        false,
        &encode_frame(&QuicFrame::PathResponse(challenge)),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet_from(&matching_response, migrated_address)
        .unwrap()
        .is_empty());
    assert!(handshake.is_client_path_address_validated(&migrated_address));
    assert_eq!(handshake.client_path_validation_pending_count(), 0);
    assert_eq!(
        handshake.client_path_migration_connection_id(&migrated_address),
        Some(&migrated_cid)
    );
}

#[test]
fn native_h3_client_path_migration_promotes_validated_connection_id_for_future_packets() {
    let read_secret = Bytes::from_static(&[0x7a; 32]);
    let write_secret = Bytes::from_static(&[0x7b; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();

    let migrated_address = SocketAddr::from(([198, 51, 100, 10], 4433));
    let migrated_cid = ConnectionId::from_static(b"migrated-cid");
    let challenge = *b"MIGRATE!";
    let new_cid_packet = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &encode_frame(&QuicFrame::NewConnectionId {
            sequence_number: 3,
            retire_prior_to: 0,
            connection_id: Bytes::copy_from_slice(migrated_cid.as_bytes()),
            stateless_reset_token: [0x42; 16],
        }),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet(&new_cid_packet)
        .unwrap()
        .is_empty());

    let challenge_packet = handshake
        .build_client_path_challenge_packet_for_address(migrated_address, 3, challenge)
        .unwrap();
    assert_eq!(
        &challenge_packet.packet[1..1 + migrated_cid.as_bytes().len()],
        migrated_cid.as_bytes(),
        "path validation probes for a migrated address must use that path's peer-issued CID"
    );

    let matching_response = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        1,
        2,
        false,
        &encode_frame(&QuicFrame::PathResponse(challenge)),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet_from(&matching_response, migrated_address)
        .unwrap()
        .is_empty());

    let future_control = handshake
        .build_client_path_response_packet(*b"SERVER??")
        .unwrap();
    assert_eq!(
        &future_control.packet[1..1 + migrated_cid.as_bytes().len()],
        migrated_cid.as_bytes(),
        "future 1-RTT packets after path validation must use the migrated peer-issued CID"
    );
}

#[test]
fn native_h3_client_pmtu_probe_packet_promotes_size_only_after_ack() {
    let read_secret = Bytes::from_static(&[0x8c; 32]);
    let write_secret = Bytes::from_static(&[0x8d; 32]);
    let server_keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let client_keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.initial_datagram_size = 1200;
    fingerprint.transport.max_send_udp_payload_size = 1280;
    fingerprint.transport.max_recv_udp_payload_size = 1280;
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &fingerprint,
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: read_secret,
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: write_secret,
            },
        ])
        .unwrap();

    assert_eq!(handshake.client_pmtu_current_size(), 1200);
    let probe = handshake
        .build_client_pmtu_probe_packet(Instant::now())
        .unwrap()
        .expect("first PMTU probe should be scheduled");
    assert!(probe.packet.len() > 1200);
    assert!(probe.packet.len() <= 1280);
    assert_eq!(handshake.client_pmtu_current_size(), 1200);
    assert_eq!(
        handshake.client_pmtu_pending_probe_size(),
        Some(probe.packet.len())
    );
    let opened_probe =
        open_short_header_packet(&client_keys, &probe.packet, b"server-dcid".len(), 0).unwrap();
    let probe_frames = decode_frames(&opened_probe.payload).unwrap();
    assert!(probe_frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::Ping)));
    assert!(probe_frames
        .iter()
        .any(|frame| matches!(frame, QuicFrame::Padding)));

    let ack = protect_short_header_packet(
        &server_keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &encode_frame(&QuicFrame::Ack {
            largest_acknowledged: probe.packet_number,
            ack_delay: 0,
            first_ack_range: 0,
            ranges: Vec::new(),
        }),
    )
    .unwrap();
    assert!(handshake
        .open_server_h3_event_packet(&ack)
        .unwrap()
        .is_empty());
    assert_eq!(handshake.client_pmtu_current_size(), probe.packet.len());
    assert_eq!(handshake.client_pmtu_pending_probe_size(), None);
}

#[test]
fn native_h3_handshake_packetizes_client_connection_close() {
    let write_secret = Bytes::from_static(&[0x96; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();

    let close = handshake
        .build_client_connection_close_packet(0x00, Bytes::from_static(b"Client shutdown"))
        .unwrap();
    let opened = open_short_header_packet(&keys, &close.packet, b"server-dcid".len(), 0).unwrap();

    assert_eq!(close.packet_number, 0);
    assert_eq!(
        decode_frames(&opened.payload)
            .unwrap()
            .into_iter()
            .filter(|frame| !matches!(frame, QuicFrame::Padding))
            .collect::<Vec<_>>(),
        vec![QuicFrame::ConnectionClose {
            error_code: 0,
            frame_type: None,
            reason: Bytes::from_static(b"Client shutdown"),
        }]
    );
}

#[test]
fn native_h3_client_enters_close_draining_after_peer_connection_close() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let close = server
        .build_server_connection_close_packet(0x0100, Bytes::from_static(b"done"))
        .unwrap();

    let events = client
        .open_server_h3_event_packet(close.packet.as_ref())
        .unwrap();

    assert!(matches!(
        events.as_slice(),
        [ServerH3Event::ConnectionClose {
            error_code: 0x0100,
            reason,
            ..
        }] if reason == b"done".as_slice()
    ));
    assert!(client.is_close_draining());

    let later = server.build_server_max_data_packet(4096).unwrap();

    assert!(client
        .open_server_h3_event_packet(later.packet.as_ref())
        .unwrap()
        .is_empty());
}

// RFC9000 § 10.2: emitting a CONNECTION_CLOSE must transition the local
// endpoint into the closing phase and arm the 3 * PTO close timer derived
// from the application loss detector's PTO.
#[test]
fn native_h3_client_enters_closing_phase_on_local_connection_close() {
    let (_, mut client, _) = completed_native_server_handshake();
    let _close = client
        .build_client_connection_close_packet(0x00, Bytes::from_static(b"local close"))
        .unwrap();

    assert!(client.close_state().is_closing());
    assert!(!client.close_state().is_draining());
    assert!(client.is_close_draining());

    let close_window = client.client_close_window();
    let pto = client.client_application_pto();
    assert!(close_window >= pto * 3, "RFC9000 close window is 3 * PTO");

    let now = std::time::Instant::now();
    assert!(!client.client_is_close_window_expired(now));
    let remaining = client
        .client_close_time_until_expiry(now)
        .expect("draining window pending");
    assert!(remaining <= close_window);
    let far_future = now + close_window + Duration::from_millis(50);
    assert!(client.client_is_close_window_expired(far_future));
}

// RFC9000 § 10.2.1: a closing endpoint may replay CONNECTION_CLOSE in
// response to peer packets but MUST rate-limit those replays. This test
// drives the close-state machine directly to prove the gating logic.
#[test]
fn native_h3_client_replays_connection_close_rate_limited() {
    let (_, mut client, _) = completed_native_server_handshake();
    let _close = client
        .build_client_connection_close_packet(0x00, Bytes::from_static(b"local"))
        .unwrap();
    // Lock in a known, deterministic replay interval and threshold so the
    // assertions do not depend on wall-clock PTO drift.
    let close_state = client.close_state_mut();
    close_state.set_replay_min_interval(Duration::from_millis(50));
    close_state.set_replay_packet_threshold(1);

    let t0 = std::time::Instant::now();
    assert!(
        !client.client_should_replay_connection_close(t0),
        "no peer packets yet"
    );
    client.client_observe_inbound_packet_for_close();
    assert!(
        !client.client_should_replay_connection_close(t0),
        "interval not elapsed"
    );
    assert!(
        client.client_should_replay_connection_close(t0 + Duration::from_millis(60)),
        "after one packet plus min-interval the replay fires"
    );
    client.client_mark_connection_close_replayed(t0 + Duration::from_millis(60));
    assert!(
        !client.client_should_replay_connection_close(t0 + Duration::from_millis(60)),
        "replays must wait for fresh inbound packets after mark_replayed"
    );
    client.client_observe_inbound_packet_for_close();
    assert!(
        client.client_should_replay_connection_close(t0 + Duration::from_millis(150)),
        "subsequent packet plus interval re-enables replay"
    );
}

// RFC9000 § 10.2: receiving a peer CONNECTION_CLOSE while we have a pending
// local close (we were in the closing phase) MUST supersede our closing
// phase with the draining phase, because draining endpoints "MUST NOT send
// any packets except a single CONNECTION_CLOSE".
#[test]
fn native_h3_client_peer_connection_close_supersedes_local_closing_phase() {
    let (_, mut client, mut server) = completed_native_server_handshake();
    let _local_close = client
        .build_client_connection_close_packet(0x00, Bytes::from_static(b"local"))
        .unwrap();
    assert!(client.close_state().is_closing());

    let peer_close = server
        .build_server_connection_close_packet(0x0100, Bytes::from_static(b"peer"))
        .unwrap();
    let events = client
        .open_server_h3_event_packet(peer_close.packet.as_ref())
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, ServerH3Event::ConnectionClose { .. })),
        "expected at least one ConnectionClose event, got {events:?}"
    );
    assert!(client.close_state().is_draining());
    assert!(!client.close_state().is_closing());
    assert!(client.is_close_draining());
}

// RFC9000 § 10.2 mirrored on the server: emitting CONNECTION_CLOSE on the
// server side puts the server handshake into the closing phase with a
// 3 * PTO close window.
#[test]
fn native_h3_server_enters_closing_phase_on_local_connection_close() {
    let (_, _, mut server) = completed_native_server_handshake();
    let _close = server
        .build_server_connection_close_packet(0x0100, Bytes::from_static(b"server close"))
        .unwrap();

    assert!(server.close_state().is_closing());
    assert!(server.is_close_draining());

    let close_window = server.server_close_window();
    let pto = server.server_application_pto();
    assert!(close_window >= pto * 3, "RFC9000 close window is 3 * PTO");

    let now = std::time::Instant::now();
    assert!(!server.server_is_close_window_expired(now));
    let far_future = now + close_window + Duration::from_millis(50);
    assert!(server.server_is_close_window_expired(far_future));
}

#[test]
fn native_h3_handshake_packetizes_client_application_stream_with_write_secret() {
    let write_secret = Bytes::from_static(&[0xaa; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();

    let packet = handshake
        .build_client_application_stream_packet(0, Bytes::from_static(b"h3-control"), false)
        .unwrap()
        .expect("non-empty application stream data should produce a packet");
    let opened = open_short_header_packet(&keys, &packet.packet, b"server-dcid".len(), 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(packet.packet_number, 0);
    assert_eq!(
        opened.destination_cid,
        ConnectionId::from_static(b"server-dcid")
    );
    assert!(matches!(
        &frames[0],
        QuicFrame::Stream { stream_id: 0, data, fin: false, .. } if data == b"h3-control".as_slice()
    ));
}

#[test]
fn native_h3_handshake_packetizes_client_preface_streams_in_fingerprint_order() {
    let write_secret = Bytes::from_static(&[0xac; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let fingerprint = Http3Fingerprint::chrome();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &fingerprint,
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();

    let packets = handshake
        .build_client_h3_preface_packets(&fingerprint)
        .unwrap();

    assert_eq!(
        packets
            .iter()
            .map(|packet| packet.stream_id)
            .collect::<Vec<_>>(),
        vec![2, 6, 10, 14]
    );

    let stream_payloads = packets
        .iter()
        .map(|packet| {
            let opened =
                open_short_header_packet(&keys, &packet.packet, b"server-dcid".len(), 0).unwrap();
            let frames = decode_frames(&opened.payload).unwrap();
            let QuicFrame::Stream {
                stream_id,
                data,
                fin: false,
                ..
            } = &frames[0]
            else {
                panic!("preface packet must carry an open STREAM frame");
            };
            assert_eq!(*stream_id, packet.stream_id);
            decode_unidirectional_stream(data).unwrap()
        })
        .collect::<Vec<_>>();

    assert_eq!(stream_payloads[0].stream_type, H3StreamType::Control);
    assert_eq!(
        decode_h3_frame(&stream_payloads[0].payload).unwrap(),
        H3Frame::Settings(encode_fingerprint_settings_payload(&fingerprint))
    );
    assert_eq!(stream_payloads[1].stream_type, H3StreamType::QpackEncoder);
    assert_eq!(stream_payloads[2].stream_type, H3StreamType::QpackDecoder);
    assert_eq!(stream_payloads[3].stream_type, H3StreamType::Grease(0x21));
}

#[test]
fn native_h3_handshake_packetizes_client_request_streams_with_bidi_ids() {
    let write_secret = Bytes::from_static(&[0xad; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    let uri: http::Uri = "https://example.com/search?q=h3".parse().unwrap();

    let first = handshake
        .build_client_h3_request_packet(
            &http::Method::GET,
            &uri,
            &[("user-agent".into(), "specter-native".into())],
            None,
        )
        .unwrap();
    let second = handshake
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();

    assert_eq!(first.stream_id, 0);
    assert_eq!(second.stream_id, 4);

    let opened = open_short_header_packet(&keys, &first.packet, b"server-dcid".len(), 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    let QuicFrame::Stream {
        stream_id,
        data,
        fin: true,
        ..
    } = &frames[0]
    else {
        panic!("request packet must carry a FIN STREAM frame");
    };
    assert_eq!(*stream_id, 0);

    let h3_frames = specter::transport::h3::native::decode_frames(data).unwrap();
    let H3Frame::Headers(block) = &h3_frames[0] else {
        panic!("request stream must begin with HEADERS");
    };
    let headers = decode_header_block(block).unwrap();
    assert!(headers
        .iter()
        .any(|header| header.name() == ":path" && header.value() == "/search?q=h3"));
    assert!(headers
        .iter()
        .any(|header| header.name() == "user-agent" && header.value() == "specter-native"));
}

#[test]
fn native_h3_handshake_uses_fingerprint_qpack_request_strategy() {
    let write_secret = Bytes::from_static(&[0xac; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.request_header_block_strategy = QpackHeaderBlockStrategy::LiteralOnly;
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &fingerprint,
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    let uri: http::Uri = "https://example.com/".parse().unwrap();

    let packet = handshake
        .build_client_h3_request_packet(&http::Method::GET, &uri, &[], None)
        .unwrap();
    let opened = open_short_header_packet(&keys, &packet.packet, b"server-dcid".len(), 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    let QuicFrame::Stream { data, .. } = &frames[0] else {
        panic!("request packet must carry STREAM data");
    };
    let h3_frames = specter::transport::h3::native::decode_frames(data).unwrap();
    let H3Frame::Headers(block) = &h3_frames[0] else {
        panic!("request stream must begin with HEADERS");
    };

    assert_ne!(&block[..5], &[0x00, 0x00, 0xd1, 0xd7, 0xc1]);
    assert_eq!(
        decode_header_block(block).unwrap()[..3],
        [
            H3Header::new(":method", "GET"),
            H3Header::new(":scheme", "https"),
            H3Header::new(":authority", "example.com"),
        ]
    );
}

#[test]
fn native_h3_handshake_opens_server_application_stream_with_read_secret() {
    let read_secret = Bytes::from_static(&[0xbb; 32]);
    let keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Application,
            secret: read_secret,
        }])
        .unwrap();
    let plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: None,
        fin: false,
        data: Bytes::from_static(b"server-control"),
    });
    let packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &plaintext,
    )
    .unwrap();

    let frames = handshake.open_server_application_packet(&packet).unwrap();

    assert!(matches!(
        &frames[0],
        QuicFrame::Stream { stream_id: 0, data, .. } if data == b"server-control".as_slice()
    ));
}

#[test]
fn native_h3_handshake_reassembles_response_frames_across_stream_packets() {
    let read_secret = Bytes::from_static(&[0xbe; 32]);
    let keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Application,
            secret: read_secret,
        }])
        .unwrap();
    let headers = vec![H3Header::new(":status", "200")];
    let mut response_stream = Vec::new();
    response_stream.extend_from_slice(&encode_h3_frame(&H3Frame::Headers(encode_header_block(
        &headers,
    ))));
    response_stream.extend_from_slice(&encode_h3_frame(&H3Frame::Data(Bytes::from_static(
        b"split",
    ))));
    let split_at = 2;
    let first_plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: None,
        fin: false,
        data: Bytes::copy_from_slice(&response_stream[..split_at]),
    });
    let second_plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: Some(split_at as u64),
        fin: true,
        data: Bytes::copy_from_slice(&response_stream[split_at..]),
    });
    let first_packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &first_plaintext,
    )
    .unwrap();
    let second_packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        1,
        2,
        false,
        &second_plaintext,
    )
    .unwrap();

    let first = handshake
        .open_server_h3_stream_packet(&first_packet)
        .unwrap();
    let second = handshake
        .open_server_h3_stream_packet(&second_packet)
        .unwrap();

    assert!(first.is_empty());
    assert_eq!(second.len(), 1);
    assert!(second[0].fin);
    assert_eq!(second[0].frames.len(), 2);
    assert_eq!(
        second[0].frames[1],
        H3Frame::Data(Bytes::from_static(b"split"))
    );
}

#[test]
fn native_h3_handshake_decodes_sequential_response_frames_with_offsets() {
    let read_secret = Bytes::from_static(&[0xb1; 32]);
    let keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Application,
            secret: read_secret,
        }])
        .unwrap();
    let headers = vec![H3Header::new(":status", "200")];
    let header_frame = encode_h3_frame(&H3Frame::Headers(encode_header_block(&headers)));
    let data_frame = encode_h3_frame(&H3Frame::Data(Bytes::from_static(b"ok")));
    let header_plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: None,
        fin: false,
        data: header_frame.clone(),
    });
    let data_plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 0,
        offset: Some(header_frame.len() as u64),
        fin: false,
        data: data_frame,
    });
    let header_packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &header_plaintext,
    )
    .unwrap();
    let data_packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        1,
        2,
        false,
        &data_plaintext,
    )
    .unwrap();

    let first = handshake
        .open_server_h3_stream_packet(&header_packet)
        .unwrap();
    let second = handshake
        .open_server_h3_stream_packet(&data_packet)
        .unwrap();

    assert_eq!(first.len(), 1);
    assert!(matches!(first[0].frames[0], H3Frame::Headers(_)));
    assert_eq!(second.len(), 1);
    assert_eq!(
        second[0].frames,
        vec![H3Frame::Data(Bytes::from_static(b"ok"))]
    );
}

#[test]
fn native_h3_handshake_decodes_server_control_stream_settings() {
    let read_secret = Bytes::from_static(&[0xbd; 32]);
    let keys = derive_packet_key_material_from_secret(read_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Read,
            level: QuicEncryptionLevel::Application,
            secret: read_secret,
        }])
        .unwrap();
    let control_payload = encode_unidirectional_stream(&H3UnidirectionalStream {
        stream_type: H3StreamType::Control,
        payload: encode_h3_frame(&H3Frame::Settings(vec![
            H3Setting::QpackMaxTableCapacity(0),
            H3Setting::EnableConnectProtocol(1),
        ])),
    });
    let plaintext = encode_frame(&QuicFrame::Stream {
        stream_id: 3,
        offset: None,
        fin: false,
        data: control_payload,
    });
    let packet = protect_short_header_packet(
        &keys,
        &ConnectionId::from_static(b"client-scid"),
        0,
        2,
        false,
        &plaintext,
    )
    .unwrap();

    let events = handshake.open_server_h3_stream_packet(&packet).unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].stream_id, 3);
    assert_eq!(events[0].stream_type, Some(H3StreamType::Control));
    assert_eq!(
        events[0].frames,
        vec![H3Frame::Settings(vec![
            H3Setting::QpackMaxTableCapacity(0),
            H3Setting::EnableConnectProtocol(1),
        ])]
    );
}

#[test]
fn native_h3_driver_state_maps_settings_headers_data_and_finished_events() {
    let mut state = NativeH3DriverState::default();

    let settings_events = state
        .apply_stream_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 3,
            stream_type: Some(H3StreamType::Control),
            fin: false,
            frames: vec![H3Frame::Settings(vec![
                H3Setting::QpackMaxTableCapacity(0),
                H3Setting::EnableConnectProtocol(1),
            ])],
        })
        .unwrap();

    assert_eq!(settings_events, vec![NativeH3Event::PeerSettings]);
    assert!(state.extended_connect_enabled_by_peer());

    let headers = vec![
        H3Header::new(":status", "200"),
        H3Header::new("content-type", "text/plain"),
    ];
    let response_events = state
        .apply_stream_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: true,
            frames: vec![
                H3Frame::Headers(encode_header_block(&headers)),
                H3Frame::Data(Bytes::from_static(b"hello")),
            ],
        })
        .unwrap();

    assert_eq!(
        response_events,
        vec![
            NativeH3Event::Headers {
                stream_id: 0,
                headers,
            },
            NativeH3Event::Data {
                stream_id: 0,
                bytes: Bytes::from_static(b"hello"),
            },
            NativeH3Event::Finished { stream_id: 0 },
        ]
    );
}

#[test]
fn native_h3_driver_state_assembles_tracked_response_across_events() {
    let mut state = NativeH3DriverState::default();
    state.track_response_stream(0);
    let headers = vec![
        H3Header::new(":status", "200"),
        H3Header::new("content-type", "text/plain"),
    ];

    let first = state
        .apply_tracked_response_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: false,
            frames: vec![H3Frame::Headers(encode_header_block(&headers))],
        })
        .unwrap();
    let completed = state
        .apply_tracked_response_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: true,
            frames: vec![H3Frame::Data(Bytes::from_static(b"hello"))],
        })
        .unwrap();

    assert_eq!(first, None);
    assert_eq!(
        completed,
        Some(NativeH3Response {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: Bytes::from_static(b"hello"),
        })
    );
}

#[test]
fn native_h3_driver_state_maps_streaming_response_incrementally() {
    let mut state = NativeH3DriverState::default();
    state.track_streaming_response_stream(0);
    let headers = vec![
        H3Header::new(":status", "200"),
        H3Header::new("content-type", "text/plain"),
    ];

    let opened = state
        .apply_tracked_streaming_response_event(
            specter::transport::h3::handshake::ServerH3StreamEvent {
                stream_id: 0,
                stream_type: None,
                fin: false,
                frames: vec![H3Frame::Headers(encode_header_block(&headers))],
            },
        )
        .unwrap();
    let data = state
        .apply_tracked_streaming_response_event(
            specter::transport::h3::handshake::ServerH3StreamEvent {
                stream_id: 0,
                stream_type: None,
                fin: false,
                frames: vec![H3Frame::Data(Bytes::from_static(b"chunk"))],
            },
        )
        .unwrap();
    let finished = state
        .apply_tracked_streaming_response_event(
            specter::transport::h3::handshake::ServerH3StreamEvent {
                stream_id: 0,
                stream_type: None,
                fin: true,
                frames: Vec::new(),
            },
        )
        .unwrap();

    assert_eq!(
        opened,
        vec![NativeH3StreamingResponseEvent::Headers {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
        }]
    );
    assert_eq!(
        data,
        vec![NativeH3StreamingResponseEvent::Data(Bytes::from_static(
            b"chunk"
        ))]
    );
    assert_eq!(finished, vec![NativeH3StreamingResponseEvent::Finished]);
}

#[test]
fn native_h3_driver_state_maps_successful_tunnel_lifecycle() {
    let mut state = NativeH3DriverState::default();
    state.track_tunnel_stream(0);
    let headers = vec![
        H3Header::new(":status", "200"),
        H3Header::new("sec-websocket-protocol", "chat"),
    ];

    let opened = state
        .apply_tracked_tunnel_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: false,
            frames: vec![H3Frame::Headers(encode_header_block(&headers))],
        })
        .unwrap();
    let data = state
        .apply_tracked_tunnel_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: false,
            frames: vec![H3Frame::Data(Bytes::from_static(b"frame"))],
        })
        .unwrap();
    let finished = state
        .apply_tracked_tunnel_event(specter::transport::h3::handshake::ServerH3StreamEvent {
            stream_id: 0,
            stream_type: None,
            fin: true,
            frames: Vec::new(),
        })
        .unwrap();

    assert_eq!(
        opened,
        vec![NativeH3TunnelEvent::Open {
            status: 200,
            headers: vec![("sec-websocket-protocol".into(), "chat".into())],
        }]
    );
    assert_eq!(
        data,
        vec![NativeH3TunnelEvent::Data(Bytes::from_static(b"frame"))]
    );
    assert_eq!(finished, vec![NativeH3TunnelEvent::Finished]);
}

#[test]
fn native_h3_handshake_packetizes_open_request_start_for_streaming_body() {
    let write_secret = Bytes::from_static(&[0xaf; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    let uri: http::Uri = "https://example.com/upload".parse().unwrap();

    let start = handshake
        .build_client_h3_request_start_packet(
            &http::Method::POST,
            &uri,
            &[("content-type".into(), "application/octet-stream".into())],
            None,
            false,
        )
        .unwrap();
    let body = handshake
        .build_client_application_stream_packet(start.stream_id, Bytes::from_static(b"chunk"), true)
        .unwrap()
        .expect("streaming body chunk should produce a packet");

    assert_eq!(start.stream_id, 0);
    assert_eq!(body.stream_id, 0);

    let opened_start =
        open_short_header_packet(&keys, &start.packet, b"server-dcid".len(), 0).unwrap();
    let start_frames = decode_frames(&opened_start.payload).unwrap();
    let QuicFrame::Stream {
        data: start_data,
        fin: false,
        ..
    } = &start_frames[0]
    else {
        panic!("request start must keep the stream open");
    };
    let h3_frames = specter::transport::h3::native::decode_frames(start_data).unwrap();
    assert!(matches!(h3_frames[0], H3Frame::Headers(_)));

    let opened_body =
        open_short_header_packet(&keys, &body.packet, b"server-dcid".len(), 1).unwrap();
    let body_frames = decode_frames(&opened_body.payload).unwrap();
    assert!(matches!(
        &body_frames[0],
        QuicFrame::Stream { stream_id: 0, offset: Some(_), data, fin: true } if data == b"chunk".as_slice()
    ));
}

#[test]
fn native_h3_handshake_packetizes_websocket_connect_without_fin() {
    let write_secret = Bytes::from_static(&[0xae; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    let uri: http::Uri = "https://example.com/chat".parse().unwrap();

    let packet = handshake
        .build_client_h3_websocket_connect_packet(
            &uri,
            &[("sec-websocket-protocol".into(), "chat".into())],
        )
        .unwrap();

    assert_eq!(packet.stream_id, 0);
    let opened = open_short_header_packet(&keys, &packet.packet, b"server-dcid".len(), 0).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    let QuicFrame::Stream {
        stream_id,
        data,
        fin: false,
        ..
    } = &frames[0]
    else {
        panic!("RFC 9220 CONNECT packet must keep the stream open");
    };
    assert_eq!(*stream_id, 0);

    let h3_frames = specter::transport::h3::native::decode_frames(data).unwrap();
    let H3Frame::Headers(block) = &h3_frames[0] else {
        panic!("CONNECT stream must begin with HEADERS");
    };
    let headers = decode_header_block(block).unwrap();
    assert!(headers
        .iter()
        .any(|header| header.name() == ":method" && header.value() == "CONNECT"));
    assert!(headers
        .iter()
        .any(|header| header.name() == ":protocol" && header.value() == "websocket"));
    assert!(headers
        .iter()
        .any(|header| header.name() == "sec-websocket-protocol" && header.value() == "chat"));
}

#[test]
fn native_h3_handshake_packetizes_websocket_bytes_as_h3_data_frame() {
    let write_secret = Bytes::from_static(&[0xb0; 32]);
    let keys = derive_packet_key_material_from_secret(write_secret.clone()).unwrap();
    let mut handshake = NativeQuicHandshake::client(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
    )
    .unwrap();
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Application,
            secret: write_secret,
        }])
        .unwrap();
    let uri: http::Uri = "https://example.com/chat".parse().unwrap();
    let connect = handshake
        .build_client_h3_websocket_connect_packet(&uri, &[])
        .unwrap();

    let data = handshake
        .build_client_h3_data_packet(connect.stream_id, Bytes::from_static(b"\x81\x02hi"), false)
        .unwrap()
        .expect("websocket tunnel bytes should produce an H3 DATA packet");

    let opened = open_short_header_packet(&keys, &data.packet, b"server-dcid".len(), 1).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();
    let QuicFrame::Stream {
        stream_id,
        offset: Some(_),
        data,
        fin: false,
    } = &frames[0]
    else {
        panic!("websocket bytes must stay on the CONNECT stream");
    };
    assert_eq!(*stream_id, connect.stream_id);
    assert_eq!(
        specter::transport::h3::native::decode_frames(data).unwrap(),
        vec![H3Frame::Data(Bytes::from_static(b"\x81\x02hi"))]
    );
}
