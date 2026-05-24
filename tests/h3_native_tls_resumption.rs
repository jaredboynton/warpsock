//! Native HTTP/3 TLS session resumption and 0-RTT (early-data) tests.
//!
//! These tests drive a complete in-process client/server TLS 1.3 handshake
//! over the BoringSSL QUIC method, capture the server-issued NewSessionTicket
//! via `SSL_CTX_sess_set_new_cb`, replay it on a second client via
//! `SSL_set_session`, and confirm the runtime status reported by
//! `NativeQuicTlsSession::handshake_status` matches the expected outcome
//! (`Resumed` / `EarlyAccepted` / `EarlyRejected`) per RFC 9001 section 4.6
//! and RFC 8446 section 4.6.1.

use bytes::Bytes;
use specter::fingerprint::tls::TlsExtensionOrderBehavior;
use specter::fingerprint::{Http3Fingerprint, TlsFingerprint};
use specter::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use specter::transport::h3::tls::{
    NativeH3HandshakeStatus, NativeQuicTlsSession, QuicEncryptionLevel,
};

mod helpers;

/// Drive the BoringSSL handshake state machines for a client/server pair until
/// both sides have produced application keys. Returns the captured DER
/// session ticket emitted by the server (the first one), if any.
///
/// This loop deliberately calls only the BoringSSL TLS surface
/// (`SSL_provide_quic_data` + `SSL_do_handshake` via the public
/// `take_crypto` / `provide_crypto` helpers) so it exercises exactly the
/// path that the production native H3 driver uses for the handshake.
fn run_handshake_to_completion(
    client: &mut NativeQuicTlsSession,
    server: &mut NativeQuicTlsSession,
) -> Option<Bytes> {
    // Initial flight (ClientHello is already buffered after construction).
    let client_initial = client.take_crypto(QuicEncryptionLevel::Initial);
    server
        .provide_crypto(QuicEncryptionLevel::Initial, &client_initial)
        .expect("server processes ClientHello");

    // Server emits ServerHello (Initial) plus EE / Certificate / Finished
    // (Handshake). Hand them back to the client.
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
            .expect("client processes server Handshake flight");
    }

    // Client emits Finished at Handshake level.
    let client_handshake = client.take_crypto(QuicEncryptionLevel::Handshake);
    if !client_handshake.is_empty() {
        server
            .provide_crypto(QuicEncryptionLevel::Handshake, &client_handshake)
            .expect("server processes client Finished");
    }

    // Post-handshake: the server issues a NewSessionTicket at Application level.
    let server_app = server.take_crypto(QuicEncryptionLevel::Application);
    if !server_app.is_empty() {
        client
            .provide_crypto(QuicEncryptionLevel::Application, &server_app)
            .expect("client processes server NewSessionTicket");
    }

    let tickets = client.take_session_tickets();
    tickets.into_iter().next().map(|ticket| ticket.der)
}

/// Capture a session ticket from a fresh in-process handshake using the
/// given fingerprint. Returns the captured DER ticket.
///
/// Panics if the server does not issue a NewSessionTicket. With
/// `SSL_CTX_set_early_data_enabled` configured on the server side, BoringSSL
/// always issues at least one ticket on a TLS 1.3 + QUIC handshake.
fn capture_initial_session_ticket(
    fingerprint: &Http3Fingerprint,
    tls_fingerprint: &TlsFingerprint,
) -> Bytes {
    let mut client = NativeQuicTlsSession::client_with_tls_fingerprint(
        "localhost",
        fingerprint,
        Some(tls_fingerprint),
        false,
    )
    .expect("native H3 client TLS session");
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicTlsSession::server(fingerprint, &cert_pem, &key_pem)
        .expect("native H3 server TLS session");

    let ticket = run_handshake_to_completion(&mut client, &mut server)
        .expect("server must issue a NewSessionTicket on a fresh TLS 1.3 + QUIC handshake");

    assert_eq!(
        client.handshake_status(),
        NativeH3HandshakeStatus::None,
        "first handshake must report no resumption"
    );
    ticket
}

#[test]
fn native_h3_tls_round_trip_handshake_emits_session_ticket() {
    let fingerprint = Http3Fingerprint::chrome();
    let tls_fingerprint = TlsFingerprint::chrome();
    let ticket = capture_initial_session_ticket(&fingerprint, &tls_fingerprint);
    assert!(
        !ticket.is_empty(),
        "captured session ticket should carry DER-encoded SSL_SESSION bytes"
    );
}

#[test]
fn native_h3_tls_replayed_session_ticket_produces_resumed_status() {
    let fingerprint = Http3Fingerprint::chrome();
    let tls_fingerprint = TlsFingerprint::chrome();

    let ticket = capture_initial_session_ticket(&fingerprint, &tls_fingerprint);

    let mut resumed_client = NativeQuicTlsSession::client_with_replayed_session(
        "localhost",
        &fingerprint,
        Some(&tls_fingerprint),
        false,
        ticket.as_ref(),
    )
    .expect("native H3 client with replayed session");
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut resumed_server =
        NativeQuicTlsSession::server(&fingerprint, &cert_pem, &key_pem).expect("server session");

    let _second_ticket = run_handshake_to_completion(&mut resumed_client, &mut resumed_server);

    assert_eq!(
        resumed_client.handshake_status(),
        NativeH3HandshakeStatus::Resumed,
        "second connect must report Resumed via SSL_session_reused (RFC 8446 section 2.2)"
    );
    assert!(resumed_client.session_reused());
}

#[test]
fn native_h3_tls_zero_rtt_offer_reports_early_accept_or_clean_reject() {
    let fingerprint = Http3Fingerprint::chrome();
    let tls_fingerprint = TlsFingerprint::chrome();

    let ticket = capture_initial_session_ticket(&fingerprint, &tls_fingerprint);

    let mut zero_rtt_client = NativeQuicTlsSession::client_with_zero_rtt_offer(
        "localhost",
        &fingerprint,
        Some(&tls_fingerprint),
        false,
        Some(ticket.as_ref()),
        b"GET / HTTP/3\r\n\r\n",
    )
    .expect("native H3 client with 0-RTT offer");

    // The TLS layer must register the zero-RTT offer before any server
    // crypto is processed. This is what guarantees 0-RTT CRYPTO at the
    // ssl_encryption_early_data level is available to the QUIC driver
    // before the Finished is received (RFC 9001 section 4.6).
    assert!(
        zero_rtt_client.zero_rtt_offer().is_some(),
        "client must register the 0-RTT offer before the server's Finished is received"
    );

    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut zero_rtt_server =
        NativeQuicTlsSession::server(&fingerprint, &cert_pem, &key_pem).expect("server session");

    let _post_ticket = run_handshake_to_completion(&mut zero_rtt_client, &mut zero_rtt_server);

    let status = zero_rtt_client.handshake_status();
    // EarlyAccepted is the happy path; EarlyRejected is the cleanly-handled
    // fallback (caller would retry over 1-RTT). Anything else means we
    // either silently downgraded to non-resumption or never offered 0-RTT
    // in the first place, both of which would break the gap closure.
    assert!(
        matches!(
            status,
            NativeH3HandshakeStatus::EarlyAccepted | NativeH3HandshakeStatus::EarlyRejected
        ),
        "0-RTT offer must resolve to EarlyAccepted or EarlyRejected, got {status:?} \
         (early_data_reason = {})",
        zero_rtt_client.early_data_reason()
    );
    assert!(
        zero_rtt_client.session_reused(),
        "0-RTT requires the underlying session to be resumed (RFC 9001 section 4.6)"
    );
}

#[test]
fn native_h3_session_cache_does_not_reuse_session_across_fingerprints() {
    let fingerprint = Http3Fingerprint::chrome();
    let chrome_tls = TlsFingerprint::chrome();
    let firefox_tls = TlsFingerprint::firefox();

    let ticket = capture_initial_session_ticket(&fingerprint, &chrome_tls);

    let cache = NativeH3SessionCache::new();
    let chrome_key = NativeH3SessionCacheKey::new(
        "localhost",
        fingerprint.alpn_protocols.clone(),
        false,
        Some(chrome_tls.pool_key_string()),
    );
    cache.insert(chrome_key.clone(), ticket.clone(), 0, None);

    let firefox_key = NativeH3SessionCacheKey::new(
        "localhost",
        fingerprint.alpn_protocols.clone(),
        false,
        Some(firefox_tls.pool_key_string()),
    );
    assert!(
        cache.get(&firefox_key).is_none(),
        "Firefox fingerprint lookup must not pick up a Chrome-issued session ticket: \
         differing ClientHello shapes would break the PSK identity binder \
         (RFC 8446 section 4.2.11)"
    );
    assert!(
        cache.get(&chrome_key).is_some(),
        "Chrome fingerprint lookup must still find its own ticket"
    );

    // Even if the cache returned the wrong ticket, BoringSSL itself rejects
    // an inconsistent ClientHello: replaying the Chrome-captured ticket with
    // Firefox curves / sigalgs / cipher list still completes a 1-RTT
    // handshake, but `session_reused()` must remain false (or we would have
    // emitted a PSK binder under a shape the server cannot verify).
    let mut firefox_client = NativeQuicTlsSession::client_with_replayed_session(
        "localhost",
        &fingerprint,
        Some(&firefox_tls),
        false,
        ticket.as_ref(),
    )
    .expect("native H3 client with mismatched-fingerprint session");
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut firefox_server =
        NativeQuicTlsSession::server(&fingerprint, &cert_pem, &key_pem).expect("server session");
    let _ = run_handshake_to_completion(&mut firefox_client, &mut firefox_server);

    let status = firefox_client.handshake_status();
    // Either the resumption was abandoned entirely (None) or it completed
    // through to 1-RTT without 0-RTT. The critical invariant is that we did
    // not accept 0-RTT under a fingerprint shape the cache had no row for.
    assert!(
        !matches!(status, NativeH3HandshakeStatus::EarlyAccepted),
        "0-RTT must never be accepted when the cache row for the active fingerprint is missing, \
         got {status:?}"
    );
}

#[test]
fn native_h3_session_cache_does_not_reuse_session_across_extension_order_policies() {
    let fingerprint = Http3Fingerprint::chrome();
    let mut deterministic_tls = TlsFingerprint::chrome();
    deterministic_tls.extension_order_behavior = TlsExtensionOrderBehavior::Deterministic;
    let permuted_tls = TlsFingerprint::chrome();

    let ticket = capture_initial_session_ticket(&fingerprint, &permuted_tls);

    let cache = NativeH3SessionCache::new();
    let permuted_key = NativeH3SessionCacheKey::new(
        "localhost",
        fingerprint.alpn_protocols.clone(),
        false,
        Some(permuted_tls.pool_key_string()),
    );
    cache.insert(permuted_key, ticket, 0, None);

    let deterministic_key = NativeH3SessionCacheKey::new(
        "localhost",
        fingerprint.alpn_protocols.clone(),
        false,
        Some(deterministic_tls.pool_key_string()),
    );
    assert!(
        cache.get(&deterministic_key).is_none(),
        "extension-order policy change must move the session cache row so the \
         PSK identity binder is never emitted under a different ClientHello shape"
    );
}
