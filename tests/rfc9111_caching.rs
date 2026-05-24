//! RFC 9111 HTTP Caching Tests
//!
//! https://www.rfc-editor.org/rfc/rfc9111

use bytes::Bytes;
use http::Method;
use specter::cache::{CacheStatus, HttpCache};
use specter::response::Response;
use specter::Headers;

#[test]
fn test_cache_no_store_rfc9111_section_5_2_2_3() {
    let mut cache = HttpCache::new();
    let url = "https://example.com/sensitive";

    let response = Response::new(
        200,
        Headers::from(vec![("Cache-Control".to_string(), "no-store".to_string())]),
        Bytes::from("secret"),
        "HTTP/1.1".to_string(),
    );

    cache.store(url, &response);

    // Should NOT be stored
    let cached = cache.get(&Method::GET, url);
    assert!(
        matches!(cached, CacheStatus::Miss),
        "Response with no-store MUST NOT be cached"
    );
}

#[test]
fn test_cache_hit_rfc9111() {
    let mut cache = HttpCache::new();
    let url = "https://example.com/public";

    let response = Response::new(
        200,
        Headers::from(vec![(
            "Cache-Control".to_string(),
            "max-age=3600".to_string(),
        )]),
        Bytes::from("data"),
        "HTTP/1.1".to_string(),
    );

    cache.store(url, &response);

    let cached = cache.get(&Method::GET, url);
    match cached {
        CacheStatus::Fresh(resp) => assert_eq!(
            resp.buffered_bytes()
                .expect("buffered cached body")
                .as_ref(),
            &b"data"[..]
        ),
        _ => panic!("Response with max-age SHOULD be cached and fresh"),
    }
}

#[test]
fn test_cache_revalidation_etag() {
    let mut cache = HttpCache::new();
    let url = "https://example.com/etag";

    // Stored response with ETag
    let response = Response::new(
        200,
        Headers::from(vec![
            ("Cache-Control".to_string(), "max-age=1".to_string()), // Expire quickly
            ("ETag".to_string(), "\"12345\"".to_string()),
        ]),
        Bytes::from("data"),
        "HTTP/1.1".to_string(),
    );

    cache.store(url, &response);

    // Simulate passage of time (mocking not easy with SystemTime, relying on short processing
    // or manual modification if possible, but fields private.
    // We'll rely on explicit sleep for 1.1s for test simplicity)
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let cached = cache.get(&Method::GET, url);
    match cached {
        CacheStatus::Revalidate(_, etag, _) => {
            assert_eq!(etag, Some("\"12345\"".to_string()));
        }
        _ => panic!("Expired response with ETag should be Revalidate"),
    }
}
