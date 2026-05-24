use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::FingerprintProfile;
use specter::transport::h2::PseudoHeaderOrder;
use specter::Client;

#[test]
fn fingerprint_profile_drives_h2_defaults_without_live_network() {
    for profile in [
        FingerprintProfile::Firefox133,
        FingerprintProfile::Firefox151,
        FingerprintProfile::FirefoxEsr140,
    ] {
        let firefox = Client::builder().fingerprint(profile).build().unwrap();

        assert_eq!(firefox.fingerprint_profile(), profile);
        assert_eq!(firefox.pseudo_order(), PseudoHeaderOrder::Firefox);
        assert_eq!(firefox.http2_settings().initial_window_size, 131_072);
        assert_eq!(firefox.http2_settings().initial_window_update, 12_517_377);
        assert!(!firefox.http2_settings().send_all_settings);
        assert_eq!(
            firefox.h3_client().http3_fingerprint(),
            &profile.http3_fingerprint()
        );
    }

    let chrome = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .build()
        .unwrap();

    assert_eq!(chrome.pseudo_order(), PseudoHeaderOrder::Chrome);
    assert_eq!(chrome.http2_settings().initial_window_size, 6_291_456);
    assert!(chrome.http2_settings().send_all_settings);
    assert_eq!(
        chrome.h3_client().http3_fingerprint(),
        &FingerprintProfile::Chrome148.http3_fingerprint()
    );
}

#[test]
fn stable_and_esr_140_profiles_remain_distinct() {
    let stable = Client::builder()
        .fingerprint(FingerprintProfile::Firefox140)
        .build()
        .unwrap();
    let esr = Client::builder()
        .fingerprint(FingerprintProfile::FirefoxEsr140)
        .build()
        .unwrap();

    assert_eq!(stable.fingerprint_profile(), FingerprintProfile::Firefox140);
    assert_eq!(esr.fingerprint_profile(), FingerprintProfile::FirefoxEsr140);
    assert_ne!(stable.fingerprint_profile(), esr.fingerprint_profile());
    assert_eq!(
        FingerprintProfile::Firefox140.user_agent(),
        FingerprintProfile::FirefoxEsr140.user_agent()
    );
}

#[test]
fn explicit_h2_overrides_take_precedence_over_profile_defaults() {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .http2_settings(Http2Settings::default())
        .pseudo_order(PseudoHeaderOrder::Standard)
        .build()
        .unwrap();

    assert_eq!(client.pseudo_order(), PseudoHeaderOrder::Standard);
    assert_eq!(client.http2_settings().initial_window_size, 6_291_456);
    assert!(client.http2_settings().send_all_settings);
}

#[test]
fn h2_window_helpers_start_from_selected_profile() {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .http2_initial_stream_window_size(Some(512_000))
        .build()
        .unwrap();

    assert_eq!(client.pseudo_order(), PseudoHeaderOrder::Firefox);
    assert_eq!(client.http2_settings().initial_window_size, 512_000);
    assert_eq!(client.http2_settings().initial_window_update, 12_517_377);
    assert!(!client.http2_settings().send_all_settings);
}
