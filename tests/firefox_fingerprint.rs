//! Firefox-specific fingerprint validation tests.
//!
//! Validates shared Firefox TLS, HTTP/2, and header fingerprints match expected values.

use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::profiles::FingerprintProfile;
use specter::fingerprint::tls::TlsFingerprint;
use specter::headers::{firefox_133_ajax_headers, firefox_133_form_headers, firefox_133_headers};

const FIREFOX_PROFILES: &[FingerprintProfile] = &[
    FingerprintProfile::Firefox133,
    FingerprintProfile::Firefox134,
    FingerprintProfile::Firefox135,
    FingerprintProfile::Firefox136,
    FingerprintProfile::Firefox137,
    FingerprintProfile::Firefox138,
    FingerprintProfile::Firefox139,
    FingerprintProfile::Firefox140,
    FingerprintProfile::Firefox141,
    FingerprintProfile::Firefox142,
    FingerprintProfile::Firefox143,
    FingerprintProfile::Firefox144,
    FingerprintProfile::Firefox145,
    FingerprintProfile::Firefox146,
    FingerprintProfile::Firefox147,
    FingerprintProfile::Firefox148,
    FingerprintProfile::Firefox149,
    FingerprintProfile::Firefox150,
    FingerprintProfile::Firefox151,
    FingerprintProfile::FirefoxEsr115,
    FingerprintProfile::FirefoxEsr128,
    FingerprintProfile::FirefoxEsr140,
];

#[test]
fn test_firefox_tls_fingerprint_constants() {
    let fp = TlsFingerprint::firefox();

    assert_eq!(
        fp,
        TlsFingerprint::firefox_133(),
        "Firefox 133 constructor remains a compatibility alias"
    );

    // Firefox does NOT use GREASE
    assert!(!fp.grease, "Firefox should NOT use GREASE");

    // Verify cipher suite order (AES-GCM preferred, ChaCha20 third)
    assert_eq!(fp.cipher_list[0], "TLS_AES_128_GCM_SHA256");
    assert_eq!(fp.cipher_list[1], "TLS_AES_256_GCM_SHA384");
    assert_eq!(fp.cipher_list[2], "TLS_CHACHA20_POLY1305_SHA256");

    // Verify Firefox supports more curves (includes P-521)
    // Note: BoringSSL uses P-256/P-384/P-521 format
    assert!(fp.curves.contains(&"x25519"));
    assert!(fp.curves.contains(&"P-256"));
    assert!(fp.curves.contains(&"P-384"));
    assert!(fp.curves.contains(&"P-521")); // Firefox-specific

    // Verify signature algorithms
    assert!(!fp.sigalgs.is_empty());
    assert_eq!(fp.sigalgs[0], "ecdsa_secp256r1_sha256");
}

#[test]
fn test_all_firefox_profiles_use_shared_firefox_transport_invariants() {
    for profile in FIREFOX_PROFILES {
        let tls = profile.tls_fingerprint();
        assert_eq!(tls, TlsFingerprint::firefox(), "{profile:?} TLS");
        assert!(!tls.grease, "{profile:?} should not use GREASE");
        assert_eq!(tls.cert_compression, specter::fingerprint::tls::CertCompression::None);
        assert!(!tls.enable_kyber, "{profile:?} should not enable Kyber");

        let h2 = profile.http2_settings();
        assert_eq!(h2, Http2Settings::firefox(), "{profile:?} H2");
        assert_eq!(profile.http2_pseudo_order().akamai_string(), "m,p,a,s");
    }
}

#[test]
fn test_firefox_http2_settings() {
    let settings = Http2Settings::firefox();

    // Firefox only sends 3 settings (1, 4, 5)
    assert_eq!(settings.header_table_size, 65536);
    assert_eq!(settings.initial_window_size, 131072); // 128KB vs Chrome's 6MB
    assert_eq!(settings.max_frame_size, 16384);

    // Firefox does NOT send these in SETTINGS frame
    // (but they may have internal defaults)
    assert_eq!(settings.max_header_list_size, 0); // Not sent

    // Firefox WINDOW_UPDATE value
    assert_eq!(settings.initial_window_update, 12517377); // vs Chrome's 15663105

    // Firefox only sends selective settings
    assert!(
        !settings.send_all_settings,
        "Firefox should NOT send all 6 settings"
    );

    // Firefox sends PRIORITY frames
    assert!(settings.priority_tree.is_some());
    let priority_tree = settings.priority_tree.as_ref().unwrap();
    assert_eq!(priority_tree.priorities.len(), 3); // Firefox sends 3 PRIORITY frames
}

#[test]
fn test_firefox_profile_enum() {
    let profile = FingerprintProfile::Firefox133;

    // Verify User-Agent
    let ua = profile.user_agent();
    assert!(ua.contains("Firefox/133.0"));
    assert!(ua.contains("Gecko"));
    assert!(!ua.contains("Chrome")); // Should NOT contain Chrome

    // Verify TLS fingerprint
    let tls_fp = profile.tls_fingerprint();
    assert!(!tls_fp.grease, "Firefox profile should NOT use GREASE");

    // Verify HTTP/2 settings
    let h2_settings = profile.http2_settings();
    assert_eq!(h2_settings.initial_window_update, 12517377);
    assert!(!h2_settings.send_all_settings);
}

#[test]
fn test_firefox_headers_no_client_hints() {
    // Navigation headers
    let nav_headers = firefox_133_headers();
    let nav_header_names: Vec<&str> = nav_headers.iter().map(|(k, _)| *k).collect();

    // Firefox does NOT send Client Hints
    assert!(
        !nav_header_names.iter().any(|k| k.starts_with("Sec-Ch-Ua")),
        "Firefox navigation headers should NOT contain Sec-Ch-Ua headers"
    );

    // Should contain standard headers
    assert!(nav_header_names.contains(&"User-Agent"));
    assert!(nav_header_names.contains(&"Accept"));
    assert!(nav_header_names.contains(&"Sec-Fetch-Dest"));

    // AJAX headers
    let ajax_headers = firefox_133_ajax_headers();
    let ajax_header_names: Vec<&str> = ajax_headers.iter().map(|(k, _)| *k).collect();

    assert!(
        !ajax_header_names.iter().any(|k| k.starts_with("Sec-Ch-Ua")),
        "Firefox AJAX headers should NOT contain Sec-Ch-Ua headers"
    );

    // Form headers
    let form_headers = firefox_133_form_headers();
    let form_header_names: Vec<&str> = form_headers.iter().map(|(k, _)| *k).collect();

    assert!(
        !form_header_names.iter().any(|k| k.starts_with("Sec-Ch-Ua")),
        "Firefox form headers should NOT contain Sec-Ch-Ua headers"
    );
}

#[test]
fn test_firefox_http2_pseudo_header_order() {
    use specter::transport::h2::PseudoHeaderOrder;

    // Firefox uses m,p,a,s order
    assert_eq!(format!("{:?}", PseudoHeaderOrder::Firefox), "Firefox");

    // Verify this differs from Chrome
    assert_ne!(PseudoHeaderOrder::Chrome, PseudoHeaderOrder::Firefox);
}

#[test]
fn test_firefox_vs_chrome_differences() {
    let chrome_fp = TlsFingerprint::chrome_142();
    let firefox_fp = TlsFingerprint::firefox();

    // GREASE difference
    assert!(chrome_fp.grease, "Chrome should use GREASE");
    assert!(!firefox_fp.grease, "Firefox should NOT use GREASE");

    // TLS 1.3 cipher order is now the same for both browsers
    // (AES-128-GCM, AES-256-GCM, ChaCha20)
    assert_eq!(chrome_fp.cipher_list[0], firefox_fp.cipher_list[0]);
    assert_eq!(chrome_fp.cipher_list[1], firefox_fp.cipher_list[1]);
    assert_eq!(chrome_fp.cipher_list[2], firefox_fp.cipher_list[2]);

    // Curve count difference
    assert_eq!(chrome_fp.curves.len(), 3);
    assert_eq!(firefox_fp.curves.len(), 4); // Firefox has P-521

    // HTTP/2 settings differences
    let chrome_settings = Http2Settings::default();
    let firefox_settings = Http2Settings::firefox();

    assert_eq!(chrome_settings.initial_window_size, 6291456); // 6MB
    assert_eq!(firefox_settings.initial_window_size, 131072); // 128KB

    assert_eq!(chrome_settings.initial_window_update, 15663105);
    assert_eq!(firefox_settings.initial_window_update, 12517377);

    assert!(chrome_settings.send_all_settings);
    assert!(!firefox_settings.send_all_settings);
}
