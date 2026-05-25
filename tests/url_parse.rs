//! Parity corpus for the internal RFC 3986 URL helper.

use specter::Url;

#[test]
fn parse_basic_https_url() {
    let url = Url::parse("https://example.com/path?q=1").unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.path(), "/path");
    assert_eq!(url.query(), Some("q=1"));
    assert_eq!(url.port_or_known_default(), Some(443));
}

#[test]
fn relative_resolution_dot_segments() {
    // RFC 3986 section 5.2.4 preserves trailing slashes for `.` and `..`.
    let base = Url::parse("https://example.com/a/b/c").unwrap();
    assert_eq!(base.join("..").unwrap().as_str(), "https://example.com/a/");
    assert_eq!(base.join(".").unwrap().as_str(), "https://example.com/a/b/");
    assert_eq!(
        base.join("../../a").unwrap().as_str(),
        "https://example.com/a"
    );
}

#[test]
fn relative_resolution_query_only() {
    let base = Url::parse("https://example.com/a/b?x=1").unwrap();
    assert_eq!(
        base.join("?q=1").unwrap().as_str(),
        "https://example.com/a/b?q=1"
    );
}

#[test]
fn relative_resolution_strips_fragment() {
    let base = Url::parse("https://example.com/a").unwrap();
    assert_eq!(
        base.join("#frag").unwrap().as_str(),
        "https://example.com/a"
    );
}

#[test]
fn relative_resolution_empty_reference() {
    let base = Url::parse("https://example.com/a?x=1").unwrap();
    assert_eq!(base.join("").unwrap().as_str(), "https://example.com/a?x=1");
}

#[test]
fn relative_resolution_absolute_path() {
    let base = Url::parse("https://example.com/a/b").unwrap();
    assert_eq!(base.join("/x").unwrap().as_str(), "https://example.com/x");
}

#[test]
fn relative_resolution_scheme_relative() {
    let base = Url::parse("https://example.com/a").unwrap();
    assert_eq!(
        base.join("//other.example/x").unwrap().as_str(),
        "https://other.example/x"
    );
}

#[test]
fn relative_resolution_scheme_absolute() {
    let base = Url::parse("https://example.com/a").unwrap();
    assert_eq!(
        base.join("https://other.example/x").unwrap().as_str(),
        "https://other.example/x"
    );
}

#[test]
fn authority_ipv6_with_port() {
    let url = Url::parse("http://[::1]:8080/").unwrap();
    assert_eq!(url.host_str(), Some("::1"));
    assert_eq!(url.port(), Some(8080));
    assert_eq!(url.port_or_known_default(), Some(8080));
}

#[test]
fn rejects_userinfo_authority() {
    let err = Url::parse("http://user:pass@host/").unwrap_err();
    assert!(err.to_string().contains("userinfo"));
}

#[test]
fn percent_encoding_round_trip() {
    let input = "https://example.com/%E2%9C%93?q=%26%3D";
    let url = Url::parse(input).unwrap();
    assert_eq!(url.as_str(), input);
    assert_eq!(url.path(), "/%E2%9C%93");
    assert_eq!(url.query(), Some("q=%26%3D"));
}

#[test]
fn explicit_default_port_is_retained() {
    let url = Url::parse("http://example.com:80/").unwrap();
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.port_or_known_default(), Some(80));
    assert_eq!(url.as_str(), "http://example.com:80/");
}

#[test]
fn implicit_default_port_is_known() {
    let url = Url::parse("https://example.com/").unwrap();
    assert_eq!(url.port(), None);
    assert_eq!(url.port_or_known_default(), Some(443));
}

#[test]
fn cross_origin_scheme_and_port_defaults() {
    let http = Url::parse("http://example.com").unwrap();
    let https = Url::parse("https://example.com").unwrap();
    let http_explicit = Url::parse("http://example.com:80").unwrap();

    assert_ne!(http.scheme(), https.scheme());
    assert_eq!(http.host_str(), https.host_str());
    assert_eq!(
        http.port_or_known_default(),
        http_explicit.port_or_known_default()
    );
}

#[test]
fn set_scheme_port_and_query() {
    let mut url = Url::parse("wss://Example.COM/socket").unwrap();
    url.set_scheme("https").unwrap();
    url.set_port(Some(8443)).unwrap();
    url.set_query(Some("room=blue")).unwrap();

    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.port(), Some(8443));
    assert_eq!(url.query(), Some("room=blue"));
}

#[test]
fn rejects_non_ascii_authority() {
    let err = Url::parse("https://exämple.com/").unwrap_err();
    assert!(err.to_string().contains("non-ASCII"));
}
