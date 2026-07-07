//! RFC 9114 HTTP/3 Error Handling Tests
//!
//! https://www.rfc-editor.org/rfc/rfc9114

use warpsock::transport::h3::H3Client;

#[tokio::test]
async fn test_h3_unsupported_scheme_rfc9114() {
    let client = H3Client::new();
    // HTTP/3 only supports HTTPS URI scheme (RFC 9114 Section 3.1)
    // "h3" token in Alt-Svc implies UDP/443 typically, but URI must be https generally for semantics.
    // Our client explicitly checks parsing.

    let result = client
        .send_request(
            "http://example.com", // Error: scheme must be https
            "GET",
            vec![],
            None,
        )
        .await;

    assert!(result.is_err(), "Expected error for http scheme, got Ok");
    let err = result.err().unwrap().to_string();
    println!("Got error: {}", err);
    assert!(
        err.contains("Unsupported scheme")
            || err.contains("only https")
            || err.contains("requires https")
    );
}

#[tokio::test]
async fn test_h3_dns_resolution_failure() {
    let client = H3Client::new();
    // Use the reserved .invalid TLD (RFC 2606) which guarantees DNS failure
    let result = client
        .send_request("https://domain.invalid", "GET", vec![], None)
        .await;

    assert!(result.is_err(), "Expected error for invalid domain, got Ok");
    let err = result.err().unwrap().to_string();
    println!("Got error: {}", err);
    assert!(
        err.to_lowercase().contains("failed to resolve")
            || err.to_lowercase().contains("no address found")
            || err.to_lowercase().contains("dns")
            || err.to_lowercase().contains("service not known"),
        "Unexpected error message: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Workstream B2 (H3): high-level malformed-input tolerance (RFC 9114 §9)
// ---------------------------------------------------------------------------
//
// Codec-level frame-tolerance assertions (unknown frame types, grease frames,
// MAX_PUSH_ID, QPACK dynamic-table edge cases, truncated frames) live in
// tests/h3_native_codec.rs where the H3Frame codec is exported. These tests
// keep the client-facing error-path assertions for RFC 9114 §9.

#[tokio::test]
async fn test_h3_request_target_without_authority_is_rejected() {
    // RFC 9114 §4.3.1 requires :authority; a URL with no host must fail rather
    // than emit a malformed request.
    let client = H3Client::new();
    let result = client
        .send_request("https:///path-only", "GET", vec![], None)
        .await;
    assert!(result.is_err(), "URL without authority must be rejected");
}
