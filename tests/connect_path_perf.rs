//! Connect-path performance fixes: session cache, happy eyeballs, H2 keepalive bridge.

use specter::fingerprint::FingerprintProfile;
use specter::transport::connector::BoringConnector;
use specter::transport::dns::{DnsConfig, Resolve, ResolveFuture};
use specter::transport::session::SessionCache;
use specter::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

struct StaticAddrsResolver {
    addrs: Vec<SocketAddr>,
}

impl Resolve for StaticAddrsResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let addrs = self.addrs.clone();
        Box::pin(async move { Ok(addrs) })
    }
}

#[tokio::test]
async fn h2_keepalive_bridge_uses_fingerprint_ping_interval() {
    let chrome = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .build()
        .unwrap();
    assert_eq!(
        chrome.http2_keep_alive_interval(),
        Some(Duration::from_secs(45))
    );
    assert!(chrome.http2_keep_alive_while_idle());

    let firefox = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .build()
        .unwrap();
    assert_eq!(
        firefox.http2_keep_alive_interval(),
        Some(Duration::from_secs(30))
    );
    assert!(firefox.http2_keep_alive_while_idle());
}

#[tokio::test]
async fn happy_eyeballs_prefers_reachable_ipv4_over_blackholed_ipv6() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((_, _)) = listener.accept().await {
            // Connection probe only; no TLS required for this timing test.
        }
    });

    let resolver = Arc::new(StaticAddrsResolver {
        addrs: vec![
            SocketAddr::new("2001:db8::1".parse().unwrap(), 443),
            reachable,
        ],
    });
    let connector = BoringConnector::new()
        .with_dns_config(
            DnsConfig::new()
                .with_resolver(resolver)
                .with_cache_enabled(false),
        )
        .happy_eyeballs_delay(Duration::from_millis(50));

    let uri: http::Uri = format!("http://127.0.0.1:{}/", reachable.port())
        .parse()
        .unwrap();
    let started = Instant::now();
    connector
        .connect(&uri)
        .await
        .expect("connect should succeed");
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "expected staggered v4 win, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn session_cache_is_shared_across_connector_clones() {
    let cache = Arc::new(SessionCache::new());
    cache.store_ticket("example.com", vec![9, 8, 7], None);
    let a = BoringConnector::new().with_shared_session_cache(cache.clone());
    let b = a.clone();
    assert_eq!(a.session_cache().len(), 1);
    assert_eq!(b.session_cache().len(), 1);
}

#[tokio::test]
async fn explicit_http2_keepalive_interval_preserves_while_idle_default() {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .http2_keep_alive_interval(Some(Duration::from_secs(10)))
        .build()
        .unwrap();
    assert_eq!(
        client.http2_keep_alive_interval(),
        Some(Duration::from_secs(10))
    );
    assert!(
        !client.http2_keep_alive_while_idle(),
        "explicit interval should not force keep_alive_while_idle"
    );
}
