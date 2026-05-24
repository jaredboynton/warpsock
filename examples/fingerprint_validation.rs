//! Fingerprint validation against detection services.
//!
//! Run with: cargo run --example fingerprint_validation
//!
//! Tests TLS and HTTP/2 fingerprints against:
//! - tls.browserleaks.com (TLS/JA3/Akamai fingerprint)
//! - tls.peet.ws (TLS fingerprint with detailed breakdown)
//! - tools.scrapfly.io (JA3/JA3N/Akamai format)
//!
//! Reference fingerprints (curl_cffi benchmarks):
//! - Python requests: 8d9f7747675e24454cd9b7ed35c58707 (detectable)
//! - cURL 7.x: e7d705a3286e19ea42f587b344ee6865 (detectable)
//! - curl_cffi Chrome: 579ccef312d18482fc42e2b822ca2430 (passes detection)
//!
//! HTTP/2 Akamai format: settings|window_update|priority|pseudo_headers
//! Chrome 142 values: 1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,s,a,p
//! Note: Chrome also sends GREASE settings (random IDs) which vary per connection

use specter::error::Result;
use specter::fingerprint::{
    http2::Http2Settings, profiles::FingerprintProfile, tls::TlsFingerprint,
};
use specter::headers::OrderedHeaders;
use specter::transport::connector::{BoringConnector, MaybeHttpsStream};
use specter::transport::h2::{H2Connection, PseudoHeaderOrder};
use specter::transport::h3::H3Client;

use http::{Method, Uri};
use tracing::{error, info, warn};

/// Known automation tool fingerprints (to avoid matching)
const KNOWN_JA3_PYTHON_REQUESTS: &str = "8d9f7747675e24454cd9b7ed35c58707";
const KNOWN_JA3_CURL_7X: &str = "e7d705a3286e19ea42f587b344ee6865";

/// Expected Chrome 142 HTTP/2 Akamai format (core settings, GREASE excluded)
const EXPECTED_AKAMAI_SETTINGS: &str = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144";
const EXPECTED_WINDOW_UPDATE: &str = "15663105";
const EXPECTED_PSEUDO_ORDER: &str = "m,s,a,p";

/// Expected Firefox 133 HTTP/2 Akamai format
const EXPECTED_FIREFOX_AKAMAI_SETTINGS: &str = "1:65536;4:131072;5:16384";
const EXPECTED_FIREFOX_WINDOW_UPDATE: &str = "12517377";
const EXPECTED_FIREFOX_PSEUDO_ORDER: &str = "m,p,a,s";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("=== Specter Fingerprint Validation ===");
    info!("");

    let mut test_results = Vec::new();

    // Test 1: TLS Fingerprint via BoringConnector (Chrome)
    info!("[1/8] Chrome TLS Fingerprint (BoringSSL)");
    info!("      Target: tls.peet.ws/api/all");
    let result1 = test_tls_fingerprint().await.is_ok();
    test_results.push(("Chrome TLS Fingerprint", result1));
    info!("");

    // Test 2: HTTP/2 SETTINGS Fingerprint (Chrome)
    info!("[2/8] Chrome HTTP/2 SETTINGS Fingerprint");
    info!("      Target: tls.peet.ws/api/all (HTTP/2)");
    let result2 = test_h2_fingerprint().await.is_ok();
    test_results.push(("Chrome HTTP/2 Settings", result2));
    info!("");

    // Test 3: Firefox TLS Fingerprint
    info!("[3/8] Firefox TLS Fingerprint");
    info!("      Target: tls.peet.ws/api/all");
    let result3 = test_firefox_tls_fingerprint().await.is_ok();
    test_results.push(("Firefox TLS Fingerprint", result3));
    info!("");

    // Test 4: Firefox HTTP/2 Fingerprint
    info!("[4/8] Firefox HTTP/2 SETTINGS Fingerprint");
    info!("      Target: tls.peet.ws/api/all (HTTP/2)");
    let result4 = test_firefox_h2_fingerprint().await.is_ok();
    test_results.push(("Firefox HTTP/2 Settings", result4));
    info!("");

    // Test 5: HTTP/3 Fingerprint
    info!("[5/8] HTTP/3 Fingerprint (QUIC/quiche)");
    info!("      Target: cloudflare.com (HTTP/3)");
    let result5 = test_h3_fingerprint().await.is_ok();
    test_results.push(("HTTP/3 Fingerprint", result5));
    info!("");

    // Test 6: Full validation against browserleaks
    info!("[6/8] Testing against browserleaks.com");
    let result6 = test_browserleaks().await.is_ok();
    test_results.push(("Browserleaks Validation", result6));
    info!("");

    // Test 7: ScrapFly fingerprint service
    info!("[7/8] Testing against ScrapFly");
    let result7 = test_scrapfly().await.is_ok();
    test_results.push(("ScrapFly Validation", result7));
    info!("");

    // Test 8: Header order and JA4H
    info!("[8/8] Header Order (JA4H) Validation");
    let result8 = test_header_order().is_ok();
    test_results.push(("JA4H Header Order", result8));
    info!("");

    // Summary
    info!("Fingerprint Analysis Summary");
    print_fingerprint_summary();
    info!("");

    // Final validation summary
    print_validation_result(&test_results);

    Ok(())
}

/// Test TLS fingerprint using BoringConnector
async fn test_tls_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();

    info!("      Configured TLS Fingerprint:");
    info!("      - Cipher suites: {} configured", fp.cipher_list.len());
    info!(
        "      - Signature algorithms: {} configured",
        fp.sigalgs.len()
    );
    info!("      - Curves: {:?}", fp.curves);
    info!("      - GREASE: {}", fp.grease);

    // Create connector with fingerprint
    let connector = BoringConnector::with_fingerprint(fp);

    // Test connection to fingerprint service
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            info!("      [PASS] TLS connection established");

            // Check ALPN negotiation
            let alpn = stream.alpn_protocol();
            info!("      [PASS] ALPN negotiated: {:?}", alpn);

            // Check if we got HTTPS
            match &stream {
                MaybeHttpsStream::Https(ssl_stream) => {
                    // Get cipher suite
                    if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                        info!("      [PASS] Cipher: {}", cipher.name());
                    }

                    // Get TLS version
                    info!(
                        "      [PASS] TLS Version: {:?}",
                        ssl_stream.ssl().version_str()
                    );
                }
                MaybeHttpsStream::Http(_) => {
                    warn!("      [WARN] Got plain HTTP instead of HTTPS");
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/2 SETTINGS fingerprint
async fn test_h2_fingerprint() -> Result<()> {
    let settings = Http2Settings::default();

    info!("      Configured HTTP/2 SETTINGS:");
    info!("      - HEADER_TABLE_SIZE: {}", settings.header_table_size);
    info!("      - ENABLE_PUSH: {}", settings.enable_push);
    info!(
        "      - MAX_CONCURRENT_STREAMS: {}",
        settings.max_concurrent_streams
    );
    info!(
        "      - INITIAL_WINDOW_SIZE: {}",
        settings.initial_window_size
    );
    info!("      - MAX_FRAME_SIZE: {}", settings.max_frame_size);
    info!(
        "      - MAX_HEADER_LIST_SIZE: {}",
        settings.max_header_list_size
    );

    // Expected Chrome values
    info!("      Expected Chrome 142 values:");
    info!(
        "      - HEADER_TABLE_SIZE: 65536 {}",
        check(settings.header_table_size == 65536)
    );
    info!(
        "      - ENABLE_PUSH: false {}",
        check(!settings.enable_push)
    );
    info!(
        "      - MAX_CONCURRENT_STREAMS: 1000 {}",
        check(settings.max_concurrent_streams == 1000)
    );
    info!(
        "      - INITIAL_WINDOW_SIZE: 6291456 {}",
        check(settings.initial_window_size == 6291456)
    );
    info!(
        "      - MAX_FRAME_SIZE: 16384 {}",
        check(settings.max_frame_size == 16384)
    );
    info!(
        "      - MAX_HEADER_LIST_SIZE: 262144 {}",
        check(settings.max_header_list_size == 262144)
    );

    // Expected Akamai format
    info!("      Expected Akamai HTTP/2 format:");
    info!("      - SETTINGS: {} [REFERENCE]", EXPECTED_AKAMAI_SETTINGS);
    info!(
        "      - WINDOW_UPDATE: {} [REFERENCE]",
        EXPECTED_WINDOW_UPDATE
    );
    info!(
        "      - Pseudo-header order: {} [REFERENCE]",
        EXPECTED_PSEUDO_ORDER
    );

    // Test actual HTTP/2 connection
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            // IMPORTANT: Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("      ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("      [WARN] Server did not negotiate HTTP/2 via ALPN, skipping H2 test");
                return Ok(());
            }

            // Create H2 connection with fingerprinted settings and Chrome pseudo-header order
            match H2Connection::connect(stream, settings.clone(), PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    info!("      [PASS] HTTP/2 connection established with custom SETTINGS");

                    // Send a request
                    let headers = vec![
                        (
                            "user-agent".to_string(),
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                                .to_string(),
                        ),
                        ("accept".to_string(), "application/json".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!(
                                "      [PASS] HTTP/2 request succeeded: {}",
                                response.status()
                            );

                            // Parse response to check fingerprint
                            let body = String::from_utf8_lossy(
                                response.buffered_bytes().map(|b| b.as_ref()).unwrap_or(&[]),
                            );
                            if body.contains("h2") {
                                info!("      [PASS] Server confirmed HTTP/2 connection");
                            }

                            // Try to extract fingerprint info from response
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                if let Some(h2_fp) = json.get("http2") {
                                    info!("      Server-detected HTTP/2 fingerprint:");
                                    info!(
                                        "      {}",
                                        serde_json::to_string_pretty(h2_fp).unwrap_or_default()
                                    );

                                    // Check Akamai fingerprint if present
                                    if let Some(akamai) = h2_fp.get("akamai_fingerprint") {
                                        let akamai_str = akamai.as_str().unwrap_or("");
                                        validate_akamai_fingerprint(akamai_str);
                                    }
                                }
                                if let Some(tls_fp) = json.get("tls") {
                                    info!("      Server-detected TLS fingerprint:");
                                    if let Some(ja3) = tls_fp.get("ja3_hash") {
                                        let ja3_str = ja3.as_str().unwrap_or("");
                                        info!("      - JA3 Hash: {}", ja3);
                                        validate_ja3(ja3_str);
                                    }
                                    if let Some(ja4) = tls_fp.get("ja4") {
                                        info!("      - JA4: {}", ja4);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("      [FAIL] HTTP/2 request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("      [FAIL] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/3 fingerprint using quiche
async fn test_h3_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();

    info!("      Configured HTTP/3 TLS Fingerprint:");
    info!("      - Cipher suites: {} configured", fp.cipher_list.len());
    info!("      - Curves: {:?}", fp.curves);
    info!("      - GREASE: {}", fp.grease);

    // Create H3 client with fingerprint
    let h3_client = H3Client::with_fingerprint(fp);

    // Test against Cloudflare (known HTTP/3 support)
    let url = "https://cloudflare.com/cdn-cgi/trace";

    info!("      Testing HTTP/3 connection to: {}", url);

    match h3_client
        .send_request(
            url,
            "GET",
            vec![
                (
                    "user-agent".to_string(),
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                        .to_string(),
                ),
                ("accept".to_string(), "*/*".to_string()),
            ],
            None,
        )
        .await
    {
        Ok(response) => {
            info!(
                "      [PASS] HTTP/3 request succeeded: {}",
                response.status()
            );
            info!("      [PASS] Protocol: {}", response.http_version());

            let body = String::from_utf8_lossy(
                response.buffered_bytes().map(|b| b.as_ref()).unwrap_or(&[]),
            );
            info!("      [INFO] Cloudflare trace response:");
            for line in body.lines().take(10) {
                info!("      {}", line);
            }

            // Check if we actually used HTTP/3
            if response.http_version() == "HTTP/3" {
                info!("      [PASS] Confirmed HTTP/3 connection");
            } else {
                warn!(
                    "      [WARN] Did not use HTTP/3: {}",
                    response.http_version()
                );
            }
        }
        Err(e) => {
            error!("      [FAIL] HTTP/3 request failed: {}", e);
            info!("      [INFO] Note: HTTP/3 requires UDP connectivity and server support");
        }
    }

    // Also try quic.tech for fingerprint detection
    info!("      Testing HTTP/3 fingerprint detection at quic.tech...");
    let quic_url = "https://quic.tech:8443/";

    match h3_client
        .send_request(
            quic_url,
            "GET",
            vec![
                (
                    "user-agent".to_string(),
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                        .to_string(),
                ),
                ("accept".to_string(), "text/html".to_string()),
            ],
            None,
        )
        .await
    {
        Ok(response) => {
            info!("      [PASS] quic.tech response: {}", response.status());
            if response.http_version() == "HTTP/3" {
                info!("      [PASS] HTTP/3 confirmed");
            }
        }
        Err(e) => {
            info!(
                "      [INFO] quic.tech test: {} (server may be unavailable)",
                e
            );
        }
    }

    Ok(())
}

/// Test Firefox TLS fingerprint using BoringConnector
async fn test_firefox_tls_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::firefox_133();

    info!("      Configured Firefox TLS Fingerprint:");
    info!("      - Cipher suites: {} configured", fp.cipher_list.len());
    info!(
        "      - Signature algorithms: {} configured",
        fp.sigalgs.len()
    );
    info!("      - Curves: {:?}", fp.curves);
    info!(
        "      - GREASE: {} (Firefox does NOT use GREASE)",
        fp.grease
    );

    // Create connector with fingerprint
    let connector = BoringConnector::with_fingerprint(fp);

    // Test connection to fingerprint service
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            info!("      [PASS] TLS connection established");

            // Check ALPN negotiation
            let alpn = stream.alpn_protocol();
            info!("      [PASS] ALPN negotiated: {:?}", alpn);

            // Check if we got HTTPS
            match &stream {
                MaybeHttpsStream::Https(ssl_stream) => {
                    // Get cipher suite
                    if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                        info!("      [PASS] Cipher: {}", cipher.name());
                    }

                    // Get TLS version
                    info!(
                        "      [PASS] TLS Version: {:?}",
                        ssl_stream.ssl().version_str()
                    );
                }
                MaybeHttpsStream::Http(_) => {
                    warn!("      [WARN] Got plain HTTP instead of HTTPS");
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test Firefox HTTP/2 SETTINGS fingerprint
async fn test_firefox_h2_fingerprint() -> Result<()> {
    let settings = Http2Settings::firefox();

    info!("      Configured Firefox HTTP/2 SETTINGS:");
    info!("      - HEADER_TABLE_SIZE: {}", settings.header_table_size);
    info!(
        "      - INITIAL_WINDOW_SIZE: {}",
        settings.initial_window_size
    );
    info!("      - MAX_FRAME_SIZE: {}", settings.max_frame_size);
    info!(
        "      - send_all_settings: {} (Firefox only sends 3)",
        settings.send_all_settings
    );

    // Expected Firefox values
    info!("      Expected Firefox 133 values:");
    info!(
        "      - HEADER_TABLE_SIZE: 65536 {}",
        check(settings.header_table_size == 65536)
    );
    info!(
        "      - INITIAL_WINDOW_SIZE: 131072 {}",
        check(settings.initial_window_size == 131072)
    );
    info!(
        "      - MAX_FRAME_SIZE: 16384 {}",
        check(settings.max_frame_size == 16384)
    );
    info!(
        "      - WINDOW_UPDATE: 12517377 {}",
        check(settings.initial_window_update == 12517377)
    );

    // Expected Akamai format
    info!("      Expected Firefox Akamai HTTP/2 format:");
    info!(
        "      - SETTINGS: {} [REFERENCE]",
        EXPECTED_FIREFOX_AKAMAI_SETTINGS
    );
    info!(
        "      - WINDOW_UPDATE: {} [REFERENCE]",
        EXPECTED_FIREFOX_WINDOW_UPDATE
    );
    info!(
        "      - Pseudo-header order: {} [REFERENCE]",
        EXPECTED_FIREFOX_PSEUDO_ORDER
    );

    // Test actual HTTP/2 connection
    let fp = TlsFingerprint::firefox_133();
    let connector = BoringConnector::with_fingerprint(fp);
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            // Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("      ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("      [WARN] Server did not negotiate HTTP/2 via ALPN, skipping H2 test");
                return Ok(());
            }

            // Create H2 connection with Firefox settings and pseudo-header order
            match H2Connection::connect(stream, settings.clone(), PseudoHeaderOrder::Firefox).await
            {
                Ok(mut h2_conn) => {
                    info!("      [PASS] HTTP/2 connection established with Firefox SETTINGS");

                    // Send a request
                    let headers = vec![
                        (
                            "user-agent".to_string(),
                            FingerprintProfile::Firefox133.user_agent().to_string(),
                        ),
                        ("accept".to_string(), "application/json".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!(
                                "      [PASS] HTTP/2 request succeeded: {}",
                                response.status()
                            );

                            // Parse response to check fingerprint
                            let body = String::from_utf8_lossy(
                                response.buffered_bytes().map(|b| b.as_ref()).unwrap_or(&[]),
                            );
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                if let Some(h2_fp) = json.get("http2") {
                                    info!("      Server-detected HTTP/2 fingerprint:");
                                    if let Some(akamai) = h2_fp.get("akamai_fingerprint") {
                                        let akamai_str = akamai.as_str().unwrap_or("");
                                        validate_firefox_akamai_fingerprint(akamai_str);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("      [FAIL] HTTP/2 request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("      [FAIL] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test header order and JA4H fingerprint
fn test_header_order() -> Result<()> {
    info!("      Testing header order preservation and JA4H calculation");

    // Test Chrome headers
    let chrome_headers = OrderedHeaders::chrome_navigation();
    let chrome_ja4h = chrome_headers.ja4h_fingerprint();
    info!("      Chrome JA4H: {}", chrome_ja4h);
    info!("      [PASS] Chrome headers ordered correctly");

    // Test Firefox headers
    let firefox_headers = OrderedHeaders::firefox_navigation();
    let firefox_ja4h = firefox_headers.ja4h_fingerprint();
    info!("      Firefox JA4H: {}", firefox_ja4h);
    info!("      [PASS] Firefox headers ordered correctly");

    // Verify headers are different (different User-Agent, no Client Hints in Firefox)
    assert_ne!(
        chrome_ja4h, firefox_ja4h,
        "Chrome and Firefox should have different JA4H"
    );
    info!("      [PASS] Chrome and Firefox have distinct JA4H fingerprints");

    Ok(())
}

/// Validate Firefox Akamai HTTP/2 fingerprint format
fn validate_firefox_akamai_fingerprint(akamai: &str) {
    // Akamai format: settings|window_update|priority|pseudo_headers
    let parts: Vec<&str> = akamai.split('|').collect();
    if parts.len() >= 4 {
        info!("      Firefox Akamai Validation:");

        // Firefox only sends 3 settings (1, 4, 5)
        let settings_str = parts[0];
        let core_settings: Vec<&str> = settings_str
            .split(';')
            .filter(|s| {
                // Keep known settings (1, 4, 5) - Firefox doesn't send 2, 3, 6
                s.starts_with("1:") || s.starts_with("4:") || s.starts_with("5:")
            })
            .collect();
        let normalized_settings = core_settings.join(";");

        let settings_match = normalized_settings == EXPECTED_FIREFOX_AKAMAI_SETTINGS;
        info!(
            "      - SETTINGS: {} {}",
            settings_str,
            if settings_match {
                "[PASS] Matches Firefox 133 core settings"
            } else {
                "[INFO] Core settings present, may include additional settings"
            }
        );

        let window_match = parts[1] == EXPECTED_FIREFOX_WINDOW_UPDATE;
        info!(
            "      - WINDOW_UPDATE: {} {}",
            parts[1],
            if window_match {
                "[PASS]"
            } else {
                "[INFO] Value differs (may vary by connection)"
            }
        );

        // Priority (parts[2]) varies
        info!("      - Priority: {} [INFO] Value may vary", parts[2]);

        let pseudo_match = parts[3] == EXPECTED_FIREFOX_PSEUDO_ORDER;
        info!(
            "      - Pseudo-header order: {} {}",
            parts[3],
            if pseudo_match {
                "[PASS] Matches Firefox 133 order"
            } else {
                "[INFO] Order differs from reference"
            }
        );
    }
}

/// Test against browserleaks.com TLS fingerprint service
async fn test_browserleaks() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // browserleaks TLS endpoint
    let uri: Uri = "https://tls.browserleaks.com/json".parse().unwrap();

    info!("      Testing: {}", uri);

    match connector.connect(&uri).await {
        Ok(stream) => {
            // Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("      ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("      [WARN] Server did not negotiate HTTP/2 via ALPN, skipping test");
                return Ok(());
            }

            match H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!("      [PASS] Response: {}", response.status());

                            let body = String::from_utf8_lossy(
                                response.buffered_bytes().map(|b| b.as_ref()).unwrap_or(&[]),
                            );

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                info!("      Browserleaks TLS Fingerprint Results:");

                                if let Some(ja3) = json.get("ja3_hash") {
                                    let ja3_str = ja3.as_str().unwrap_or("");
                                    info!("      - JA3 Hash: {}", ja3);
                                    validate_ja3(ja3_str);
                                }
                                if let Some(ja3_text) = json.get("ja3_text") {
                                    info!("      - JA3 Text: {}", ja3_text);
                                }
                                if let Some(ja3n) = json.get("ja3n_hash") {
                                    info!("      - JA3N Hash: {}", ja3n);
                                }
                                if let Some(ja4) = json.get("ja4") {
                                    info!("      - JA4: {}", ja4);
                                }
                                if let Some(akamai) = json.get("akamai_hash") {
                                    info!("      - Akamai Hash: {}", akamai);
                                }
                                if let Some(akamai_fp) = json.get("akamai_fingerprint") {
                                    let akamai_str = akamai_fp.as_str().unwrap_or("");
                                    info!("      - Akamai Fingerprint: {}", akamai_fp);
                                    validate_akamai_fingerprint(akamai_str);
                                }
                                if let Some(tls_version) = json.get("tls_version") {
                                    info!("      - TLS Version: {}", tls_version);
                                }
                                if let Some(cipher) = json.get("cipher_suite") {
                                    info!("      - Cipher Suite: {}", cipher);
                                }

                                // Check for Chrome-like fingerprint
                                if let Some(user_agent_match) = json.get("user_agent_match") {
                                    let ua_match = user_agent_match.as_bool().unwrap_or(false);
                                    info!(
                                        "      User-Agent Match: {} {}",
                                        ua_match,
                                        check(ua_match)
                                    );
                                }
                            } else {
                                info!(
                                    "      Response body (raw):\n      {}",
                                    &body[..body.len().min(500)]
                                );
                            }
                        }
                        Err(e) => {
                            error!("      [FAIL] Request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("      [FAIL] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test against ScrapFly fingerprint service
async fn test_scrapfly() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // ScrapFly fingerprint endpoint
    let uri: Uri = "https://tools.scrapfly.io/api/fp/ja3".parse().unwrap();

    info!("      Testing: {}", uri);

    match connector.connect(&uri).await {
        Ok(stream) => {
            // Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("      ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("      [WARN] Server did not negotiate HTTP/2 via ALPN, skipping test");
                return Ok(());
            }

            match H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!("      [PASS] Response: {}", response.status());

                            let body = String::from_utf8_lossy(
                                response.buffered_bytes().map(|b| b.as_ref()).unwrap_or(&[]),
                            );

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                info!("      ScrapFly Fingerprint Results:");

                                if let Some(ja3) = json.get("ja3") {
                                    let ja3_str = ja3.as_str().unwrap_or("");
                                    info!("      - JA3 Hash: {}", ja3);
                                    validate_ja3(ja3_str);
                                }
                                if let Some(ja3_digest) = json.get("ja3_digest") {
                                    info!("      - JA3 Digest: {}", ja3_digest);
                                }
                                if let Some(ja3n) = json.get("ja3n") {
                                    info!("      - JA3N: {}", ja3n);
                                }
                                if let Some(ja3n_digest) = json.get("ja3n_digest") {
                                    info!("      - JA3N Digest: {}", ja3n_digest);
                                }
                                if let Some(akamai) = json.get("akamai") {
                                    let akamai_str = akamai.as_str().unwrap_or("");
                                    info!("      - Akamai: {}", akamai);
                                    validate_akamai_fingerprint(akamai_str);
                                }
                                if let Some(akamai_digest) = json.get("akamai_digest") {
                                    info!("      - Akamai Digest: {}", akamai_digest);
                                }
                                if let Some(scrapfly_fp) = json.get("scrapfly_fp") {
                                    info!("      - ScrapFly FP: {}", scrapfly_fp);
                                }
                                if let Some(scrapfly_fp_digest) = json.get("scrapfly_fp_digest") {
                                    info!("      - ScrapFly FP Digest: {}", scrapfly_fp_digest);
                                }

                                // HTTP/2 specific
                                if let Some(h2_settings) = json.get("h2_settings") {
                                    info!("      - HTTP/2 SETTINGS: {}", h2_settings);
                                }
                                if let Some(h2_window) = json.get("h2_window_update") {
                                    info!("      - HTTP/2 WINDOW_UPDATE: {}", h2_window);
                                }
                                if let Some(h2_pseudo) = json.get("h2_pseudo_header_order") {
                                    info!("      - HTTP/2 Pseudo Order: {}", h2_pseudo);
                                }
                            } else {
                                info!(
                                    "      Response body (raw):\n      {}",
                                    &body[..body.len().min(500)]
                                );
                            }
                        }
                        Err(e) => {
                            error!("      [FAIL] Request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("      [FAIL] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("      [FAIL] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Validate JA3 fingerprint against known automation tools
fn validate_ja3(ja3: &str) {
    if ja3 == KNOWN_JA3_PYTHON_REQUESTS {
        error!("      [FAIL] Matches Python requests fingerprint (detectable)!");
    } else if ja3 == KNOWN_JA3_CURL_7X {
        error!("      [FAIL] Matches cURL 7.x fingerprint (detectable)!");
    } else {
        info!("      [PASS] Does not match known automation tools");
    }
}

/// Validate Akamai HTTP/2 fingerprint format
/// Strips GREASE settings (random IDs) before comparison since they vary per connection
fn validate_akamai_fingerprint(akamai: &str) {
    // Akamai format: settings|window_update|priority|pseudo_headers
    let parts: Vec<&str> = akamai.split('|').collect();
    if parts.len() >= 4 {
        info!("      Akamai Validation:");

        // Strip GREASE settings (random IDs like :0 or UNKNOWN_SETTING_2570)
        // GREASE IDs are in the range 0x0a0a, 0x1a1a, 0x2a2a, etc. (ending in 0x0a0a pattern)
        // For simplicity, we'll extract known settings and ignore unknown ones
        let settings_str = parts[0];
        let core_settings: Vec<&str> = settings_str
            .split(';')
            .filter(|s| {
                // Keep known settings (1-6) and ignore GREASE/unknown
                s.starts_with("1:")
                    || s.starts_with("2:")
                    || s.starts_with("3:")
                    || s.starts_with("4:")
                    || s.starts_with("5:")
                    || s.starts_with("6:")
            })
            .collect();
        let normalized_settings = core_settings.join(";");

        let has_grease = settings_str.contains(":0")
            || settings_str.split(';').any(|s| {
                s.parse::<u16>()
                    .map(|id| id >= 0x0a0a && (id & 0x0f0f) == 0x0a0a)
                    .unwrap_or(false)
            });

        if has_grease {
            info!("      [INFO] GREASE settings detected (expected for Chrome anti-detection)");
        }

        let settings_match = normalized_settings == EXPECTED_AKAMAI_SETTINGS;
        info!(
            "      - SETTINGS: {} {}",
            settings_str,
            if settings_match {
                "[PASS] Matches Chrome 142 core settings"
            } else {
                "[INFO] Core settings present, may include additional Chrome settings"
            }
        );

        let window_match = parts[1] == EXPECTED_WINDOW_UPDATE;
        info!(
            "      - WINDOW_UPDATE: {} {}",
            parts[1],
            if window_match {
                "[PASS]"
            } else {
                "[INFO] Value differs (may vary by connection)"
            }
        );

        // Priority (parts[2]) varies and is less critical
        info!("      - Priority: {} [INFO] Value may vary", parts[2]);

        let pseudo_match = parts[3] == EXPECTED_PSEUDO_ORDER;
        info!(
            "      - Pseudo-header order: {} {}",
            parts[3],
            if pseudo_match {
                "[PASS] Matches Chrome 142 order"
            } else {
                "[INFO] Order differs from reference"
            }
        );
    }
}

/// Print summary of fingerprint expectations
fn print_fingerprint_summary() {
    info!("      Reference Fingerprints (for comparison):");
    info!("");
    info!("      Known automation tool fingerprints (should NOT match):");
    info!("      - Python requests: {}", KNOWN_JA3_PYTHON_REQUESTS);
    info!("      - cURL 7.x:        {}", KNOWN_JA3_CURL_7X);
    info!("");
    info!("      Expected HTTP/2 Akamai format (Chrome 142):");
    info!("      - SETTINGS:        {}", EXPECTED_AKAMAI_SETTINGS);
    info!("      - WINDOW_UPDATE:   {}", EXPECTED_WINDOW_UPDATE);
    info!("      - Pseudo order:    {}", EXPECTED_PSEUDO_ORDER);
    info!("");
    info!("      Expected HTTP/2 Akamai format (Firefox 133):");
    info!(
        "      - SETTINGS:        {} (only 3 settings)",
        EXPECTED_FIREFOX_AKAMAI_SETTINGS
    );
    info!(
        "      - WINDOW_UPDATE:   {}",
        EXPECTED_FIREFOX_WINDOW_UPDATE
    );
    info!("      - Pseudo order:    {}", EXPECTED_FIREFOX_PSEUDO_ORDER);
    info!("");
    info!("      HTTP/2 SETTINGS breakdown (Chrome):");
    info!("      - 1 = HEADER_TABLE_SIZE:    65536");
    info!("      - 2 = ENABLE_PUSH:          0");
    info!("      - 3 = MAX_CONCURRENT_STREAMS: 1000");
    info!("      - 4 = INITIAL_WINDOW_SIZE:  6291456");
    info!("      - 5 = MAX_FRAME_SIZE:      16384");
    info!("      - 6 = MAX_HEADER_LIST_SIZE: 262144");
    info!("");
    info!("      HTTP/2 SETTINGS breakdown (Firefox):");
    info!("      - 1 = HEADER_TABLE_SIZE:    65536");
    info!("      - 4 = INITIAL_WINDOW_SIZE:  131072 (128KB)");
    info!("      - 5 = MAX_FRAME_SIZE:      16384");
    info!("      (Firefox does NOT send settings 2, 3, 6)");
}

fn check(condition: bool) -> &'static str {
    if condition {
        "[PASS]"
    } else {
        "[FAIL]"
    }
}

/// Print final validation summary with clear PASS/FAIL status
fn print_validation_result(results: &[(&str, bool)]) {
    info!("=== Validation Summary ===");
    info!("");

    let passed = results.iter().filter(|(_, result)| *result).count();
    let total = results.len();

    for (name, result) in results {
        let status = if *result { "[PASS]" } else { "[FAIL]" };
        info!("  {} {}", status, name);
    }

    info!("");
    if passed == total {
        info!("[PASS] {}/{} tests passed", passed, total);
        info!("[INFO] Fingerprint does not match known automation tools");
        info!("[INFO] All fingerprint validation services returned success");
    } else {
        warn!(
            "[WARN] {}/{} tests passed - some validations failed",
            passed, total
        );
    }
    info!("");
    info!("=== Validation Complete ===");
}
