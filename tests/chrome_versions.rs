//! Chrome multi-version fingerprint validation tests.
//!
//! Validates Chrome 142-146 fingerprint profiles produce correct
//! User-Agent strings, Sec-Ch-Ua headers, and shared TLS/HTTP2 config.

use specter::fingerprint::profiles::FingerprintProfile;
use specter::fingerprint::tls::{CertCompression, TlsFingerprint};
use specter::headers::{
    chrome_142_ajax_headers, chrome_142_form_headers, chrome_142_headers, chrome_143_ajax_headers,
    chrome_143_form_headers, chrome_143_headers, chrome_144_ajax_headers, chrome_144_form_headers,
    chrome_144_headers, chrome_145_ajax_headers, chrome_145_form_headers, chrome_145_headers,
    chrome_146_ajax_headers, chrome_146_form_headers, chrome_146_headers,
};

#[test]
fn test_default_profile_is_chrome142() {
    // Default must remain Chrome142 for SemVer backwards compatibility
    assert_eq!(FingerprintProfile::default(), FingerprintProfile::Chrome142);
}

#[test]
fn test_chrome_user_agents_contain_correct_version() {
    let cases = [
        (FingerprintProfile::Chrome142, "Chrome/142.0.0.0"),
        (FingerprintProfile::Chrome143, "Chrome/143.0.0.0"),
        (FingerprintProfile::Chrome144, "Chrome/144.0.0.0"),
        (FingerprintProfile::Chrome145, "Chrome/145.0.0.0"),
        (FingerprintProfile::Chrome146, "Chrome/146.0.0.0"),
    ];

    for (profile, expected_version) in &cases {
        let ua = profile.user_agent();
        assert!(
            ua.contains(expected_version),
            "Profile {:?} UA should contain '{}', got: {}",
            profile,
            expected_version,
            ua
        );
        // All should be macOS
        assert!(
            ua.contains("Macintosh; Intel Mac OS X 10_15_7"),
            "UA should contain macOS platform"
        );
        // All should have Safari token
        assert!(
            ua.contains("Safari/537.36"),
            "UA should contain Safari token"
        );
    }
}

#[test]
fn test_chrome_tls_fingerprints_identical_across_versions() {
    let profiles = [
        FingerprintProfile::Chrome142,
        FingerprintProfile::Chrome143,
        FingerprintProfile::Chrome144,
        FingerprintProfile::Chrome145,
        FingerprintProfile::Chrome146,
    ];

    let base = profiles[0].tls_fingerprint();

    for profile in &profiles[1..] {
        let fp = profile.tls_fingerprint();
        assert_eq!(
            fp.cipher_list, base.cipher_list,
            "Cipher suites should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.sigalgs, base.sigalgs,
            "Signature algorithms should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.curves, base.curves,
            "Curves should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.extensions, base.extensions,
            "Extensions should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.grease, base.grease,
            "GREASE should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.cert_compression, base.cert_compression,
            "Cert compression should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.enable_kyber, base.enable_kyber,
            "Kyber should be identical for {:?}",
            profile
        );
    }

    // Verify shared Chrome TLS properties
    assert!(base.grease, "Chrome should use GREASE");
    assert_eq!(
        base.cert_compression,
        CertCompression::Brotli,
        "Chrome should use Brotli cert compression"
    );
    assert!(base.enable_kyber, "Chrome should enable Kyber");
}

#[test]
fn test_chrome_http2_settings_identical_across_versions() {
    let profiles = [
        FingerprintProfile::Chrome142,
        FingerprintProfile::Chrome143,
        FingerprintProfile::Chrome144,
        FingerprintProfile::Chrome145,
        FingerprintProfile::Chrome146,
    ];

    let base = profiles[0].http2_settings();

    for profile in &profiles[1..] {
        let settings = profile.http2_settings();
        assert_eq!(settings.initial_window_size, base.initial_window_size);
        assert_eq!(settings.initial_window_update, base.initial_window_update);
        assert_eq!(settings.header_table_size, base.header_table_size);
        assert_eq!(settings.max_frame_size, base.max_frame_size);
    }
}

#[test]
fn test_chrome_sec_ch_ua_brand_strings() {
    // Verify each version has the correct GREASE brand string from Chromium algorithm
    let nav_142 = chrome_142_headers();
    let nav_143 = chrome_143_headers();
    let nav_144 = chrome_144_headers();
    let nav_145 = chrome_145_headers();
    let nav_146 = chrome_146_headers();

    fn get_sec_ch_ua<'a>(headers: &'a [(&str, &str)]) -> &'a str {
        headers.iter().find(|(k, _)| *k == "Sec-Ch-Ua").unwrap().1
    }

    let ua_142 = get_sec_ch_ua(&nav_142);
    let ua_143 = get_sec_ch_ua(&nav_143);
    let ua_144 = get_sec_ch_ua(&nav_144);
    let ua_145 = get_sec_ch_ua(&nav_145);
    let ua_146 = get_sec_ch_ua(&nav_146);

    // Chrome 142: "Not_A Brand" v="24", order: Chromium, GC, GREASE
    assert!(
        ua_142.contains(r#""Not_A Brand";v="24""#),
        "Chrome 142 brand: {}",
        ua_142
    );
    assert!(
        ua_142.starts_with(r#""Chromium""#),
        "Chrome 142 order: {}",
        ua_142
    );

    // Chrome 143: "Not A(Brand" v="99", order: GC, Chromium, GREASE
    assert!(
        ua_143.contains(r#""Not A(Brand";v="99""#),
        "Chrome 143 brand: {}",
        ua_143
    );
    assert!(
        ua_143.starts_with(r#""Google Chrome""#),
        "Chrome 143 order: {}",
        ua_143
    );

    // Chrome 144: "Not(A:Brand" v="8", order: GREASE, Chromium, GC
    assert!(
        ua_144.contains(r#""Not(A:Brand";v="8""#),
        "Chrome 144 brand: {}",
        ua_144
    );
    assert!(
        ua_144.starts_with(r#""Not(A:Brand""#),
        "Chrome 144 order: {}",
        ua_144
    );

    // Chrome 145: "Not:A-Brand" v="24", order: GREASE, GC, Chromium
    assert!(
        ua_145.contains(r#""Not:A-Brand";v="24""#),
        "Chrome 145 brand: {}",
        ua_145
    );
    assert!(
        ua_145.starts_with(r#""Not:A-Brand""#),
        "Chrome 145 order: {}",
        ua_145
    );

    // Chrome 146: "Not-A.Brand" v="99", order: Chromium, GREASE, GC
    assert!(
        ua_146.contains(r#""Not-A.Brand";v="99""#),
        "Chrome 146 brand: {}",
        ua_146
    );
    assert!(
        ua_146.starts_with(r#""Chromium""#),
        "Chrome 146 order: {}",
        ua_146
    );

    // All should be distinct
    let all = [ua_142, ua_143, ua_144, ua_145, ua_146];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "Sec-Ch-Ua should differ between versions");
        }
    }
}

#[test]
fn test_chrome_all_versions_have_three_header_types() {
    // Verify each version exports navigation, AJAX, and form headers
    let versions: Vec<(Vec<_>, Vec<_>, Vec<_>)> = vec![
        (
            chrome_142_headers(),
            chrome_142_ajax_headers(),
            chrome_142_form_headers(),
        ),
        (
            chrome_143_headers(),
            chrome_143_ajax_headers(),
            chrome_143_form_headers(),
        ),
        (
            chrome_144_headers(),
            chrome_144_ajax_headers(),
            chrome_144_form_headers(),
        ),
        (
            chrome_145_headers(),
            chrome_145_ajax_headers(),
            chrome_145_form_headers(),
        ),
        (
            chrome_146_headers(),
            chrome_146_ajax_headers(),
            chrome_146_form_headers(),
        ),
    ];

    for (i, (nav, ajax, form)) in versions.iter().enumerate() {
        let version = 142 + i;

        // Navigation headers should have Sec-Fetch-User
        let nav_names: Vec<&str> = nav.iter().map(|(k, _)| *k).collect();
        assert!(
            nav_names.contains(&"Sec-Fetch-User"),
            "Chrome {} nav missing Sec-Fetch-User",
            version
        );
        assert!(
            nav_names.contains(&"Upgrade-Insecure-Requests"),
            "Chrome {} nav missing UIR",
            version
        );

        // AJAX headers should have Content-Type: application/json
        let ajax_ct = ajax.iter().find(|(k, _)| *k == "Content-Type");
        assert_eq!(
            ajax_ct.unwrap().1,
            "application/json",
            "Chrome {} AJAX Content-Type",
            version
        );

        // Form headers should have Content-Type: application/x-www-form-urlencoded
        let form_ct = form.iter().find(|(k, _)| *k == "Content-Type");
        assert_eq!(
            form_ct.unwrap().1,
            "application/x-www-form-urlencoded",
            "Chrome {} form Content-Type",
            version
        );

        // All should have the same User-Agent containing the version number
        let expected_ua_fragment = format!("Chrome/{}.0.0.0", version);
        for (header_type, headers) in [("nav", nav), ("ajax", ajax), ("form", form)] {
            let ua = headers.iter().find(|(k, _)| *k == "User-Agent").unwrap().1;
            assert!(
                ua.contains(&expected_ua_fragment),
                "Chrome {} {} UA should contain '{}': {}",
                version,
                header_type,
                expected_ua_fragment,
                ua
            );
        }
    }
}

#[test]
fn test_chrome_tls_constructors_match_shared() {
    // All version-specific constructors should produce the same result as chrome()
    let shared = TlsFingerprint::chrome();
    let constructors = [
        TlsFingerprint::chrome_142(),
        TlsFingerprint::chrome_143(),
        TlsFingerprint::chrome_144(),
        TlsFingerprint::chrome_145(),
        TlsFingerprint::chrome_146(),
    ];

    for (i, fp) in constructors.iter().enumerate() {
        assert_eq!(
            fp.cipher_list,
            shared.cipher_list,
            "chrome_{} ciphers",
            142 + i
        );
        assert_eq!(fp.sigalgs, shared.sigalgs, "chrome_{} sigalgs", 142 + i);
        assert_eq!(fp.curves, shared.curves, "chrome_{} curves", 142 + i);
    }
}
