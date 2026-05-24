//! Firefox multi-version fingerprint validation tests.
//!
//! Validates Firefox release and ESR profiles produce version-correct
//! User-Agent strings, shared Firefox transport fingerprints, and exact
//! header presets.

use std::collections::HashSet;

use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::http3::Http3Fingerprint;
use specter::fingerprint::profiles::FingerprintProfile;
use specter::fingerprint::tls::{CertCompression, TlsFingerprint};
use specter::headers::{
    firefox_133_ajax_headers, firefox_133_form_headers, firefox_133_headers,
    firefox_134_ajax_headers, firefox_134_form_headers, firefox_134_headers,
    firefox_135_ajax_headers, firefox_135_form_headers, firefox_135_headers,
    firefox_136_ajax_headers, firefox_136_form_headers, firefox_136_headers,
    firefox_137_ajax_headers, firefox_137_form_headers, firefox_137_headers,
    firefox_138_ajax_headers, firefox_138_form_headers, firefox_138_headers,
    firefox_139_ajax_headers, firefox_139_form_headers, firefox_139_headers,
    firefox_140_ajax_headers, firefox_140_form_headers, firefox_140_headers,
    firefox_141_ajax_headers, firefox_141_form_headers, firefox_141_headers,
    firefox_142_ajax_headers, firefox_142_form_headers, firefox_142_headers,
    firefox_143_ajax_headers, firefox_143_form_headers, firefox_143_headers,
    firefox_144_ajax_headers, firefox_144_form_headers, firefox_144_headers,
    firefox_145_ajax_headers, firefox_145_form_headers, firefox_145_headers,
    firefox_146_ajax_headers, firefox_146_form_headers, firefox_146_headers,
    firefox_147_ajax_headers, firefox_147_form_headers, firefox_147_headers,
    firefox_148_ajax_headers, firefox_148_form_headers, firefox_148_headers,
    firefox_149_ajax_headers, firefox_149_form_headers, firefox_149_headers,
    firefox_150_ajax_headers, firefox_150_form_headers, firefox_150_headers,
    firefox_151_ajax_headers, firefox_151_form_headers, firefox_151_headers,
    firefox_esr_115_ajax_headers, firefox_esr_115_form_headers, firefox_esr_115_headers,
    firefox_esr_128_ajax_headers, firefox_esr_128_form_headers, firefox_esr_128_headers,
    firefox_esr_140_ajax_headers, firefox_esr_140_form_headers, firefox_esr_140_headers,
    OrderedHeaders,
};
use specter::transport::h2::PseudoHeaderOrder;
use specter::PoolKey;

type HeaderFactory = fn() -> Vec<(&'static str, &'static str)>;

#[derive(Clone, Copy)]
struct FirefoxCase {
    profile: FingerprintProfile,
    major: u16,
    ua: &'static str,
    nav: HeaderFactory,
    ajax: HeaderFactory,
    form: HeaderFactory,
}

const FIREFOX_RELEASE_PROFILES: &[(FingerprintProfile, u16)] = &[
    (FingerprintProfile::Firefox134, 134),
    (FingerprintProfile::Firefox135, 135),
    (FingerprintProfile::Firefox136, 136),
    (FingerprintProfile::Firefox137, 137),
    (FingerprintProfile::Firefox138, 138),
    (FingerprintProfile::Firefox139, 139),
    (FingerprintProfile::Firefox140, 140),
    (FingerprintProfile::Firefox141, 141),
    (FingerprintProfile::Firefox142, 142),
    (FingerprintProfile::Firefox143, 143),
    (FingerprintProfile::Firefox144, 144),
    (FingerprintProfile::Firefox145, 145),
    (FingerprintProfile::Firefox146, 146),
    (FingerprintProfile::Firefox147, 147),
    (FingerprintProfile::Firefox148, 148),
    (FingerprintProfile::Firefox149, 149),
    (FingerprintProfile::Firefox150, 150),
    (FingerprintProfile::Firefox151, 151),
];

const FIREFOX_ESR_PROFILES: &[(FingerprintProfile, u16)] = &[
    (FingerprintProfile::FirefoxEsr115, 115),
    (FingerprintProfile::FirefoxEsr128, 128),
    (FingerprintProfile::FirefoxEsr140, 140),
];

const FIREFOX_CASES: &[FirefoxCase] = &[
    FirefoxCase {
        profile: FingerprintProfile::Firefox133,
        major: 133,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        nav: firefox_133_headers,
        ajax: firefox_133_ajax_headers,
        form: firefox_133_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox134,
        major: 134,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
        nav: firefox_134_headers,
        ajax: firefox_134_ajax_headers,
        form: firefox_134_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox135,
        major: 135,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
        nav: firefox_135_headers,
        ajax: firefox_135_ajax_headers,
        form: firefox_135_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox136,
        major: 136,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
        nav: firefox_136_headers,
        ajax: firefox_136_ajax_headers,
        form: firefox_136_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox137,
        major: 137,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
        nav: firefox_137_headers,
        ajax: firefox_137_ajax_headers,
        form: firefox_137_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox138,
        major: 138,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
        nav: firefox_138_headers,
        ajax: firefox_138_ajax_headers,
        form: firefox_138_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox139,
        major: 139,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
        nav: firefox_139_headers,
        ajax: firefox_139_ajax_headers,
        form: firefox_139_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox140,
        major: 140,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
        nav: firefox_140_headers,
        ajax: firefox_140_ajax_headers,
        form: firefox_140_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox141,
        major: 141,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
        nav: firefox_141_headers,
        ajax: firefox_141_ajax_headers,
        form: firefox_141_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox142,
        major: 142,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
        nav: firefox_142_headers,
        ajax: firefox_142_ajax_headers,
        form: firefox_142_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox143,
        major: 143,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
        nav: firefox_143_headers,
        ajax: firefox_143_ajax_headers,
        form: firefox_143_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox144,
        major: 144,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
        nav: firefox_144_headers,
        ajax: firefox_144_ajax_headers,
        form: firefox_144_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox145,
        major: 145,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
        nav: firefox_145_headers,
        ajax: firefox_145_ajax_headers,
        form: firefox_145_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox146,
        major: 146,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
        nav: firefox_146_headers,
        ajax: firefox_146_ajax_headers,
        form: firefox_146_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox147,
        major: 147,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
        nav: firefox_147_headers,
        ajax: firefox_147_ajax_headers,
        form: firefox_147_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox148,
        major: 148,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
        nav: firefox_148_headers,
        ajax: firefox_148_ajax_headers,
        form: firefox_148_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox149,
        major: 149,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
        nav: firefox_149_headers,
        ajax: firefox_149_ajax_headers,
        form: firefox_149_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox150,
        major: 150,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
        nav: firefox_150_headers,
        ajax: firefox_150_ajax_headers,
        form: firefox_150_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::Firefox151,
        major: 151,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
        nav: firefox_151_headers,
        ajax: firefox_151_ajax_headers,
        form: firefox_151_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::FirefoxEsr115,
        major: 115,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:115.0) Gecko/20100101 Firefox/115.0",
        nav: firefox_esr_115_headers,
        ajax: firefox_esr_115_ajax_headers,
        form: firefox_esr_115_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::FirefoxEsr128,
        major: 128,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
        nav: firefox_esr_128_headers,
        ajax: firefox_esr_128_ajax_headers,
        form: firefox_esr_128_form_headers,
    },
    FirefoxCase {
        profile: FingerprintProfile::FirefoxEsr140,
        major: 140,
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
        nav: firefox_esr_140_headers,
        ajax: firefox_esr_140_ajax_headers,
        form: firefox_esr_140_form_headers,
    },
];

#[test]
fn test_firefox_release_profile_coverage_is_exact_134_through_151() {
    let majors: Vec<u16> = FIREFOX_RELEASE_PROFILES
        .iter()
        .map(|(_, major)| *major)
        .collect();
    assert_eq!(majors, (134..=151).collect::<Vec<_>>());
    assert_eq!(FIREFOX_RELEASE_PROFILES.len(), 18);

    let unique: HashSet<_> = FIREFOX_RELEASE_PROFILES
        .iter()
        .map(|(profile, _)| *profile)
        .collect();
    assert_eq!(unique.len(), FIREFOX_RELEASE_PROFILES.len());
}

#[test]
fn test_firefox_esr_profile_coverage() {
    let majors: Vec<u16> = FIREFOX_ESR_PROFILES
        .iter()
        .map(|(_, major)| *major)
        .collect();
    assert_eq!(majors, vec![115, 128, 140]);

    let unique: HashSet<_> = FIREFOX_ESR_PROFILES
        .iter()
        .map(|(profile, _)| *profile)
        .collect();
    assert_eq!(unique.len(), FIREFOX_ESR_PROFILES.len());
    assert_ne!(
        FingerprintProfile::Firefox140,
        FingerprintProfile::FirefoxEsr140
    );
}

#[test]
fn test_firefox_user_agents_match_major_versions() {
    for case in FIREFOX_CASES {
        assert_eq!(case.profile.user_agent(), case.ua, "{:?}", case.profile);
        assert!(case.ua.contains(&format!("rv:{}.0", case.major)));
        assert!(case.ua.contains(&format!("Firefox/{}.0", case.major)));
    }
}

#[test]
fn test_firefox_transport_fingerprints_equal_canonical_firefox() {
    for case in FIREFOX_CASES {
        assert_eq!(
            case.profile.tls_fingerprint(),
            TlsFingerprint::firefox(),
            "{:?} TLS",
            case.profile
        );
        assert_eq!(
            case.profile.http2_settings(),
            Http2Settings::firefox(),
            "{:?} H2",
            case.profile
        );
        assert_eq!(
            case.profile.http3_fingerprint(),
            Http3Fingerprint::firefox(),
            "{:?} H3",
            case.profile
        );
        assert_eq!(
            case.profile.http2_pseudo_order(),
            PseudoHeaderOrder::Firefox
        );
    }
}

#[test]
fn test_firefox_transport_invariants_explain_failures() {
    let tls = TlsFingerprint::firefox();
    assert!(!tls.grease);
    assert_eq!(tls.cert_compression, CertCompression::None);
    assert!(!tls.enable_kyber);
    assert!(tls.curves.contains(&"P-521"));

    let h2 = Http2Settings::firefox();
    assert_eq!(h2.header_table_size, 65_536);
    assert_eq!(h2.initial_window_size, 131_072);
    assert_eq!(h2.max_frame_size, 16_384);
    assert_eq!(h2.initial_window_update, 12_517_377);
    assert!(!h2.send_all_settings);
    assert_eq!(PseudoHeaderOrder::Firefox.akamai_string(), "m,p,a,s");

    let h3 = Http3Fingerprint::firefox();
    assert_eq!(h3.alpn_protocols, vec![b"h3".to_vec()]);
    assert!(!h3.transport.grease);
    assert_eq!(
        h3.transport.initial_max_stream_data_bidi_local,
        4 * 1024 * 1024
    );
    assert_eq!(
        h3.transport.initial_max_stream_data_bidi_remote,
        4 * 1024 * 1024
    );
    assert_eq!(h3.transport.initial_max_stream_data_uni, 4 * 1024 * 1024);
    assert!(!h3.stream.send_grease_stream);
    assert!(!h3.stream.send_grease_frames);
}

#[test]
fn test_firefox_header_helpers_match_exact_ordered_sequences() {
    for case in FIREFOX_CASES {
        assert_eq!(
            (case.nav)(),
            expected_nav(case.ua),
            "{:?} nav",
            case.profile
        );
        assert_eq!(
            (case.ajax)(),
            expected_ajax(case.ua),
            "{:?} ajax",
            case.profile
        );
        assert_eq!(
            (case.form)(),
            expected_form(case.ua),
            "{:?} form",
            case.profile
        );
    }
}

#[test]
fn test_firefox_header_helpers_have_no_client_hints() {
    for case in FIREFOX_CASES {
        for headers in [(case.nav)(), (case.ajax)(), (case.form)()] {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.starts_with("Sec-Ch-Ua")),
                "{:?}",
                case.profile
            );
        }
    }
}

#[test]
fn test_ordered_headers_firefox_navigation_uses_latest_stable() {
    let latest = OrderedHeaders::firefox_navigation();
    let actual: Vec<(&str, &str)> = latest
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(actual, expected_nav(FIREFOX_CASES[18].ua));
}

#[test]
fn test_firefox_profile_pool_key_behavior() {
    let firefox150 = PoolKey::new(
        "example.com".to_string(),
        443,
        true,
        FingerprintProfile::Firefox150,
        PseudoHeaderOrder::Firefox,
    );
    let firefox151 = PoolKey::new(
        "example.com".to_string(),
        443,
        true,
        FingerprintProfile::Firefox151,
        PseudoHeaderOrder::Firefox,
    );

    assert_ne!(firefox150, firefox151);
    assert_eq!(
        FingerprintProfile::Firefox150
            .http3_fingerprint()
            .pool_key_string(),
        FingerprintProfile::Firefox151
            .http3_fingerprint()
            .pool_key_string()
    );
}

fn expected_nav(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

fn expected_ajax(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Connection", "keep-alive"),
    ]
}

fn expected_form(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}
