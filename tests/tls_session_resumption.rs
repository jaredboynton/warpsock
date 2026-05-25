//! C1 integration test: TLS 1.3 session ticket resumption across back-to-back dials.
//!
//! Spins a local BoringSSL accept loop on `127.0.0.1:0`, performs two `connect()`
//! calls through a shared `BoringConnector`, and asserts the second handshake
//! resumed via the cached session ticket.

mod helpers;

use boring::ssl::{SslOptions, SslSessionCacheMode, SslVersion};
use boring_sys::SSL_CTX;
use helpers::tls::generate_cert_bundle;
use specter::transport::connector::{BoringConnector, EarlyDataOutcome};
use specter::transport::dns::{DnsConfig, Resolve, ResolveFuture};
use specter::transport::session::SessionCache;
use std::ffi::c_int;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

extern "C" {
    fn SSL_CTX_set_early_data_enabled(ctx: *mut SSL_CTX, enabled: c_int);
}

struct StaticResolver {
    addrs: Vec<SocketAddr>,
}

impl Resolve for StaticResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let addrs = self.addrs.clone();
        Box::pin(async move { Ok(addrs) })
    }
}

/// Spawn a minimal TLS 1.3 accept loop that issues a fresh session ticket and
/// writes a single `PING` byte string after the handshake completes so that the
/// client surfaces the NewSessionTicket via its `set_new_session_callback`.
async fn spawn_tls13_ticket_server() -> (SocketAddr, Vec<u8>, oneshot::Sender<()>) {
    spawn_tls13_server(false).await
}

async fn spawn_tls13_ticket_server_with_early_data() -> (SocketAddr, Vec<u8>, oneshot::Sender<()>) {
    spawn_tls13_server(true).await
}

async fn spawn_tls13_server(enable_early_data: bool) -> (SocketAddr, Vec<u8>, oneshot::Sender<()>) {
    let (mut builder, ca_pem) = generate_cert_bundle();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .expect("min version");
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .expect("max version");
    builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
    builder.clear_options(SslOptions::NO_TICKET);
    if enable_early_data {
        unsafe {
            SSL_CTX_set_early_data_enabled(builder.as_ptr() as *mut SSL_CTX, 1);
        }
    }
    let acceptor = Arc::new(builder.build());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let Ok((tcp, _)) = accept else { break };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = tokio_boring::accept(&acceptor, tcp).await else { return };
                        // Send a small payload so the client's read drives ticket processing.
                        let _ = tls.write_all(b"PING\n").await;
                        let _ = tls.flush().await;
                        let mut buf = [0u8; 16];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.shutdown().await;
                    });
                }
            }
        }
    });

    (addr, ca_pem, shutdown_tx)
}

#[tokio::test]
async fn second_connect_resumes_tls13_session_ticket() {
    let (addr, ca_pem, shutdown) = spawn_tls13_ticket_server().await;
    let shared_cache = Arc::new(SessionCache::new());
    let resolver = Arc::new(StaticResolver { addrs: vec![addr] });
    let connector = BoringConnector::new()
        .with_root_certificates(vec![ca_pem])
        .with_shared_session_cache(shared_cache.clone())
        .with_dns_config(
            DnsConfig::new()
                .with_resolver(resolver)
                .with_cache_enabled(false),
        );

    // Use a stable SNI hostname (must match the loopback cert SANs).
    let uri: http::Uri = format!("https://127.0.0.1:{}/", addr.port())
        .parse()
        .unwrap();

    let mut first = connector.connect(&uri).await.expect("first TLS handshake");
    assert!(
        !first.session_reused(),
        "first handshake should be a fresh session, not resumption"
    );
    // Drive a read so the client processes the NewSessionTicket frame.
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        use tokio::io::AsyncReadExt;
        first.read(&mut buf).await
    })
    .await;
    drop(first);

    // Wait for the new-session callback after BoringSSL parses the NewSessionTicket.
    let key = specter::transport::session::SessionCacheKey::new("127.0.0.1", addr.port());
    assert!(
        shared_cache
            .wait_for_session(&key, Duration::from_secs(2))
            .await
    );
    assert!(
        shared_cache.get_session(&key).is_some(),
        "expected a TLS 1.3 session ticket to be cached after the first dial"
    );

    let second = connector.connect(&uri).await.expect("second TLS handshake");
    assert!(
        second.session_reused(),
        "second handshake must resume the cached TLS 1.3 ticket"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn early_data_session_marked_zero_rtt_capable_when_server_enables_it() {
    let (addr, ca_pem, shutdown) = spawn_tls13_ticket_server_with_early_data().await;
    let shared_cache = Arc::new(SessionCache::new());
    let resolver = Arc::new(StaticResolver { addrs: vec![addr] });
    let connector = BoringConnector::new()
        .with_root_certificates(vec![ca_pem])
        .with_shared_session_cache(shared_cache.clone())
        .with_early_data(true)
        .with_dns_config(
            DnsConfig::new()
                .with_resolver(resolver)
                .with_cache_enabled(false),
        );
    let uri: http::Uri = format!("https://127.0.0.1:{}/", addr.port())
        .parse()
        .unwrap();

    let mut first = connector.connect(&uri).await.expect("first handshake");
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), first.read(&mut buf)).await;
    drop(first);

    let key = specter::transport::session::SessionCacheKey::new("127.0.0.1", addr.port());
    assert!(
        shared_cache
            .wait_for_session(&key, Duration::from_secs(2))
            .await
    );
    assert!(
        shared_cache.supports_zero_rtt(&key),
        "TLS session ticket must advertise early-data capability when the server enables 0-RTT"
    );

    // A second dial with idempotent early-data bytes should not fail; the
    // BoringSSL stack reports `Accepted` or `Rejected` based on server policy
    // (either is a valid integration result — what we must not see is `NotAttempted`
    // when the cached ticket is zero-rtt-capable and the flag is on).
    let (_stream, outcome) = connector
        .connect_with_alpn_and_early_data(
            &uri,
            specter::transport::connector::AlpnMode::Default,
            Some(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        )
        .await
        .expect("second dial with early data");
    assert!(
        matches!(
            outcome,
            EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected { .. }
        ),
        "expected an early-data Accepted/Rejected outcome, got {:?}",
        outcome
    );

    let _ = shutdown.send(());
}
