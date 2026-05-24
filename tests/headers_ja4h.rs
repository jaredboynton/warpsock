//! Header order and JA4H fingerprint tests.
//!
//! Validates OrderedHeaders preserves order and JA4H fingerprint calculation.

use specter::headers::{chrome_142_headers, firefox_133_headers, firefox_151_headers, OrderedHeaders};

#[test]
fn test_ordered_headers_preserves_order() {
    let headers = vec![
        ("header1".to_string(), "value1".to_string()),
        ("header2".to_string(), "value2".to_string()),
        ("header3".to_string(), "value3".to_string()),
    ];

    let ordered = OrderedHeaders::new(headers.clone());
    let retrieved = ordered.headers();

    assert_eq!(retrieved.len(), 3);
    assert_eq!(retrieved[0].0, "header1");
    assert_eq!(retrieved[1].0, "header2");
    assert_eq!(retrieved[2].0, "header3");
}

#[test]
fn test_ja4h_fingerprint_deterministic() {
    let headers = vec![
        ("user-agent".to_string(), "test".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];

    let ordered1 = OrderedHeaders::new(headers.clone());
    let ordered2 = OrderedHeaders::new(headers);

    // Same headers should produce same JA4H
    assert_eq!(ordered1.ja4h_fingerprint(), ordered2.ja4h_fingerprint());
}

#[test]
fn test_firefox_user_agent_value_changes_do_not_change_current_ja4h() {
    let firefox_133 = OrderedHeaders::new(firefox_133_headers());
    let firefox_151 = OrderedHeaders::new(firefox_151_headers());

    assert_ne!(
        firefox_133
            .headers()
            .iter()
            .find(|(name, _)| name == "User-Agent")
            .map(|(_, value)| value),
        firefox_151
            .headers()
            .iter()
            .find(|(name, _)| name == "User-Agent")
            .map(|(_, value)| value)
    );
    assert_eq!(
        firefox_133.ja4h_fingerprint(),
        firefox_151.ja4h_fingerprint(),
        "Current JA4H implementation is header-name/order based, not User-Agent-value sensitive"
    );
}

#[test]
fn test_ja4h_fingerprint_format() {
    let headers = vec![
        ("user-agent".to_string(), "test".to_string()),
        ("accept".to_string(), "json".to_string()),
    ];

    let ordered = OrderedHeaders::new(headers);
    let ja4h = ordered.ja4h_fingerprint();

    // JA4H format: header_names|hash
    assert!(ja4h.contains('|'), "JA4H should contain separator");

    let parts: Vec<&str> = ja4h.split('|').collect();
    assert_eq!(parts.len(), 2, "JA4H should have 2 parts");

    // First part: comma-separated lowercase header names
    let names = parts[0];
    assert!(names.contains("user-agent"));
    assert!(names.contains("accept"));
    assert_eq!(
        names,
        names.to_lowercase(),
        "Header names should be lowercase"
    );

    // Second part: hash (6 hex characters)
    let hash = parts[1];
    assert_eq!(hash.len(), 6, "Hash should be 6 hex characters");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash should be hex"
    );
}

#[test]
fn test_chrome_firefox_ja4h_distinct() {
    let chrome_ordered = OrderedHeaders::chrome_navigation();
    let firefox_ordered = OrderedHeaders::firefox_navigation();

    let chrome_ja4h = chrome_ordered.ja4h_fingerprint();
    let firefox_ja4h = firefox_ordered.ja4h_fingerprint();

    // Chrome and Firefox should have different JA4H fingerprints
    assert_ne!(
        chrome_ja4h, firefox_ja4h,
        "Chrome and Firefox JA4H fingerprints should differ"
    );

    // Verify they contain different header sets
    let chrome_names: Vec<&str> = chrome_ja4h.split('|').next().unwrap().split(',').collect();
    let firefox_names: Vec<&str> = firefox_ja4h.split('|').next().unwrap().split(',').collect();

    // Chrome has Sec-Ch-Ua headers, Firefox doesn't
    assert!(
        chrome_names.iter().any(|n| n.contains("sec-ch-ua")),
        "Chrome should have Sec-Ch-Ua headers"
    );
    assert!(
        !firefox_names.iter().any(|n| n.contains("sec-ch-ua")),
        "Firefox should NOT have Sec-Ch-Ua headers"
    );
}

#[test]
fn test_chrome_headers_contain_client_hints() {
    let chrome_headers = chrome_142_headers();
    let header_names: Vec<&str> = chrome_headers.iter().map(|(k, _)| *k).collect();

    // Chrome sends Client Hints
    assert!(
        header_names.contains(&"Sec-Ch-Ua"),
        "Chrome should send Sec-Ch-Ua header"
    );
    assert!(
        header_names.contains(&"Sec-Ch-Ua-Mobile"),
        "Chrome should send Sec-Ch-Ua-Mobile header"
    );
    assert!(
        header_names.contains(&"Sec-Ch-Ua-Platform"),
        "Chrome should send Sec-Ch-Ua-Platform header"
    );
}

#[test]
fn test_firefox_headers_no_client_hints() {
    let firefox_headers = firefox_133_headers();
    let header_names: Vec<&str> = firefox_headers.iter().map(|(k, _)| *k).collect();

    // Firefox does NOT send Client Hints
    assert!(
        !header_names.iter().any(|k| k.starts_with("Sec-Ch-Ua")),
        "Firefox should NOT send any Sec-Ch-Ua headers"
    );

    // But should send other Sec- headers
    assert!(
        header_names.contains(&"Sec-Fetch-Dest"),
        "Firefox should send Sec-Fetch-Dest"
    );
    assert!(
        header_names.contains(&"Sec-Fetch-Mode"),
        "Firefox should send Sec-Fetch-Mode"
    );
}

#[test]
fn test_ordered_headers_add_preserves_order() {
    let mut ordered = OrderedHeaders::chrome_navigation();
    ordered = ordered.add("custom-header".to_string(), "value".to_string());

    let headers = ordered.headers();
    let last_header = headers.last().unwrap();

    assert_eq!(last_header.0, "custom-header");
    assert_eq!(last_header.1, "value");
}

#[test]
fn test_ordered_headers_conversion() {
    let chrome_ordered = OrderedHeaders::chrome_navigation();

    // Convert to Vec
    let vec: Vec<(String, String)> = chrome_ordered.clone().into();
    assert!(!vec.is_empty());

    // Convert back from Vec
    let restored = OrderedHeaders::from(vec.clone());
    assert_eq!(restored.headers().len(), vec.len());
}

#[test]
fn test_ja4h_order_sensitive() {
    // Different order should produce different JA4H
    let headers1 = vec![
        ("header1".to_string(), "value1".to_string()),
        ("header2".to_string(), "value2".to_string()),
    ];

    let headers2 = vec![
        ("header2".to_string(), "value2".to_string()),
        ("header1".to_string(), "value1".to_string()),
    ];

    let ordered1 = OrderedHeaders::new(headers1);
    let ordered2 = OrderedHeaders::new(headers2);

    // Different order should produce different hash
    let ja4h1 = ordered1.ja4h_fingerprint();
    let ja4h2 = ordered2.ja4h_fingerprint();

    // Header names part will differ
    let names1 = ja4h1.split('|').next().unwrap();
    let names2 = ja4h2.split('|').next().unwrap();

    assert_ne!(
        names1, names2,
        "Different order should produce different header names string"
    );
}
