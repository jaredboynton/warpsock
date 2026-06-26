//! A request with no Accept-Encoding is a bot signal that Cloudflare challenges
//! from datacenter egress (403 interstitial) while passing it from residential
//! IPs. `RequestBuilder::build()` must default Accept-Encoding when the caller
//! omits it, and must leave an explicit caller value untouched.

use warpsock::Client;

#[test]
fn build_defaults_accept_encoding_when_absent() {
    let client = Client::builder().build().unwrap();
    let request = client
        .get("https://example.com/")
        .build()
        .expect("build request");

    let ae = request
        .headers()
        .get("accept-encoding")
        .expect("Accept-Encoding must be defaulted when the caller omits it");
    assert_eq!(ae, "gzip, deflate, br, zstd");
}

#[test]
fn build_preserves_explicit_accept_encoding() {
    let client = Client::builder().build().unwrap();
    let request = client
        .get("https://example.com/")
        .header("Accept-Encoding", "identity")
        .build()
        .expect("build request");

    let values: Vec<&str> = request
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        values,
        vec!["identity"],
        "an explicit Accept-Encoding must be preserved verbatim with no duplicate default appended"
    );
}
