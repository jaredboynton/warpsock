//! Browser header presets for HTTP requests.
//!
//! Supported Chrome versions: 142, 143, 144, 145, 146, 147, 148
//! Supported Firefox versions: 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, ESR 115, ESR 128, ESR 140

use crate::cookie::CookieJar;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use std::sync::{Arc, OnceLock};

/// Chrome 142 browser headers for page navigation.
pub fn chrome_142_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="142.0.7444.176", "Google Chrome";v="142.0.7444.176", "Not_A Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for AJAX/API requests.
/// Extended Client Hints are typically only sent on navigation requests,
/// not on AJAX/API requests unless explicitly requested by the server.
pub fn chrome_142_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for form submissions.
pub fn chrome_142_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="142.0.7444.176", "Google Chrome";v="142.0.7444.176", "Not_A Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 browser headers for page navigation.
pub fn chrome_143_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 headers for AJAX/API requests.
pub fn chrome_143_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 headers for form submissions.
pub fn chrome_143_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 browser headers for page navigation.
pub fn chrome_144_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.133", "Google Chrome";v="144.0.7559.133""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 headers for AJAX/API requests.
pub fn chrome_144_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 headers for form submissions.
pub fn chrome_144_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.133", "Google Chrome";v="144.0.7559.133""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 browser headers for page navigation.
pub fn chrome_145_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.117", "Chromium";v="145.0.7632.117""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 headers for AJAX/API requests.
pub fn chrome_145_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 headers for form submissions.
pub fn chrome_145_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.117", "Chromium";v="145.0.7632.117""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 browser headers for page navigation.
pub fn chrome_146_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="146.0.7680.165", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.165""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 headers for AJAX/API requests.
pub fn chrome_146_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 headers for form submissions.
pub fn chrome_146_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="146.0.7680.165", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.165""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 browser headers for page navigation.
pub fn chrome_147_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="147.0.7727.138", "Not.A/Brand";v="8.0.0.0", "Chromium";v="147.0.7727.138""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 headers for AJAX/API requests.
pub fn chrome_147_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 headers for form submissions.
pub fn chrome_147_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="147.0.7727.138", "Not.A/Brand";v="8.0.0.0", "Chromium";v="147.0.7727.138""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 browser headers for page navigation.
pub fn chrome_148_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="148.0.7778.179", "Google Chrome";v="148.0.7778.179", "Not/A)Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 headers for AJAX/API requests.
pub fn chrome_148_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 headers for form submissions.
pub fn chrome_148_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="148.0.7778.179", "Google Chrome";v="148.0.7778.179", "Not/A)Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Add Cookie header from jar.
pub fn with_cookies(base: impl Into<Headers>, url: &str, jar: &CookieJar) -> Headers {
    let base = base.into();
    let mut builder = HeadersBuilder::from_headers(&base);
    builder.remove("cookie");
    if let Some(cookie_header) = jar.build_cookie_header(url) {
        builder.insert("Cookie", cookie_header);
    }
    builder.build()
}

/// Add Origin header.
pub fn with_origin(headers: Headers, origin: &str) -> Headers {
    let mut builder = HeadersBuilder::from_headers(&headers);
    builder.remove("origin");
    builder.insert("Origin", origin);
    builder.build()
}

/// Add Referer header.
pub fn with_referer(headers: Headers, referer: &str) -> Headers {
    let mut builder = HeadersBuilder::from_headers(&headers);
    builder.remove("referer");
    builder.insert("Referer", referer);
    builder.build()
}

/// Convert owned headers to references.
pub fn headers_as_refs(headers: &Headers) -> Vec<(&str, &str)> {
    headers.as_refs()
}

/// Convert static headers to owned.
pub fn headers_to_owned(headers: Vec<(&'static str, &'static str)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Byte span into a contiguous header buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSpan {
    name_start: u32,
    name_len: u32,
    value_start: u32,
    value_len: u32,
}

impl HeaderSpan {
    fn name<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = self.name_start as usize;
        &buf[start..start + self.name_len as usize]
    }

    fn value<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = self.value_start as usize;
        &buf[start..start + self.value_len as usize]
    }
}

fn name_eq_ignore_ascii_case(buf: &[u8], span: &HeaderSpan, name: &[u8]) -> bool {
    let header_name = span.name(buf);
    header_name.len() == name.len()
        && header_name
            .iter()
            .zip(name)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn push_header_bytes(buf: &mut BytesMut, spans: &mut Vec<HeaderSpan>, name: &[u8], value: &[u8]) {
    let name_start = buf.len() as u32;
    buf.extend_from_slice(name);
    let name_len = name.len() as u32;
    let value_start = buf.len() as u32;
    buf.extend_from_slice(value);
    let value_len = value.len() as u32;
    spans.push(HeaderSpan {
        name_start,
        name_len,
        value_start,
        value_len,
    });
}

/// Mutable builder for byte-spanned headers.
#[derive(Debug, Default)]
pub struct HeadersBuilder {
    buf: BytesMut,
    spans: Vec<HeaderSpan>,
}

impl HeadersBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(header_count: usize, byte_capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(byte_capacity),
            spans: Vec::with_capacity(header_count),
        }
    }

    pub fn from_headers(headers: &Headers) -> Self {
        let mut builder = Self::with_capacity(headers.len(), headers.buf.len());
        for (name, value) in headers.iter_bytes() {
            builder.push(name, value);
        }
        builder
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn push(&mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        push_header_bytes(
            &mut self.buf,
            &mut self.spans,
            name.as_ref(),
            value.as_ref(),
        );
    }

    pub fn append(&mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.push(name, value);
    }

    pub fn insert(&mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        let name = name.as_ref();
        self.spans
            .retain(|span| !name_eq_ignore_ascii_case(&self.buf, span, name));
        self.push(name, value);
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<Vec<u8>>> {
        let name = name.as_bytes();
        let mut removed = Vec::new();
        self.spans.retain(|span| {
            if name_eq_ignore_ascii_case(&self.buf, span, name) {
                removed.push(span.value(&self.buf).to_vec());
                false
            } else {
                true
            }
        });
        if removed.is_empty() {
            None
        } else {
            Some(removed)
        }
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let name = name.as_bytes();
        self.spans
            .iter()
            .find(|span| name_eq_ignore_ascii_case(&self.buf, span, name))
            .map(|span| span.value(&self.buf))
    }

    pub fn get_all(&self, name: &str) -> Vec<&[u8]> {
        let name = name.as_bytes();
        self.spans
            .iter()
            .filter_map(|span| {
                if name_eq_ignore_ascii_case(&self.buf, span, name) {
                    Some(span.value(&self.buf))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.spans
            .iter()
            .map(|span| (span.name(&self.buf), span.value(&self.buf)))
    }

    pub fn build(self) -> Headers {
        Headers {
            buf: self.buf.freeze(),
            spans: Arc::from(self.spans.into_boxed_slice()),
        }
    }
}

/// Ordered headers for requests and responses.
///
/// This preserves insertion order for fingerprinting while providing
/// convenient lookup and mutation helpers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    buf: Bytes,
    spans: Arc<[HeaderSpan]>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_vec(headers: Vec<(String, String)>) -> Self {
        let mut builder = HeadersBuilder::with_capacity(headers.len(), headers.len() * 32);
        for (name, value) in headers {
            builder.push(name.as_bytes(), value.as_bytes());
        }
        builder.build()
    }

    pub fn from_static(headers: Vec<(&'static str, &'static str)>) -> Self {
        let mut builder = HeadersBuilder::with_capacity(headers.len(), headers.len() * 32);
        for (name, value) in headers {
            builder.push(name.as_bytes(), value.as_bytes());
        }
        builder.build()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let mut builder = HeadersBuilder::from_headers(self);
        builder.insert(name.into(), value.into());
        *self = builder.build();
    }

    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let mut builder = HeadersBuilder::from_headers(self);
        builder.append(name.into(), value.into());
        *self = builder.build();
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        let mut builder = HeadersBuilder::from_headers(self);
        let removed = builder.remove(name).map(|values| {
            values
                .into_iter()
                .map(|value| String::from_utf8_lossy(&value).into_owned())
                .collect()
        });
        *self = builder.build();
        removed
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = name.as_bytes();
        self.spans
            .iter()
            .find(|span| name_eq_ignore_ascii_case(&self.buf, span, name))
            .and_then(|span| std::str::from_utf8(span.value(&self.buf)).ok())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let name = name.as_bytes();
        self.spans
            .iter()
            .filter_map(|span| {
                if name_eq_ignore_ascii_case(&self.buf, span, name) {
                    std::str::from_utf8(span.value(&self.buf)).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter_bytes(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.spans
            .iter()
            .map(|span| (span.name(&self.buf), span.value(&self.buf)))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.iter_bytes().filter_map(|(name, value)| {
            Some((
                std::str::from_utf8(name).ok()?,
                std::str::from_utf8(value).ok()?,
            ))
        })
    }

    pub fn iter_ordered(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.iter()
    }

    pub fn extend(&mut self, other: Headers) {
        let mut builder = HeadersBuilder::from_headers(self);
        for (name, value) in other.iter_bytes() {
            builder.append(name, value);
        }
        *self = builder.build();
    }

    pub fn as_refs(&self) -> Vec<(&str, &str)> {
        self.iter().collect()
    }

    pub fn to_vec(&self) -> Vec<(String, String)> {
        self.iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    pub fn into_inner(self) -> Vec<(String, String)> {
        self.to_vec()
    }
}

impl From<Vec<(String, String)>> for Headers {
    fn from(value: Vec<(String, String)>) -> Self {
        Headers::from_vec(value)
    }
}

impl From<&Headers> for Headers {
    fn from(value: &Headers) -> Self {
        value.clone()
    }
}

impl From<&[(String, String)]> for Headers {
    fn from(value: &[(String, String)]) -> Self {
        let mut builder = HeadersBuilder::with_capacity(value.len(), value.len() * 32);
        for (name, value) in value {
            builder.push(name.as_bytes(), value.as_bytes());
        }
        builder.build()
    }
}

impl From<&Vec<(String, String)>> for Headers {
    fn from(value: &Vec<(String, String)>) -> Self {
        Headers::from(value.as_slice())
    }
}

impl<const N: usize> From<&[(String, String); N]> for Headers {
    fn from(value: &[(String, String); N]) -> Self {
        Headers::from(value.as_slice())
    }
}

impl PartialEq<Vec<(String, String)>> for Headers {
    fn eq(&self, other: &Vec<(String, String)>) -> bool {
        self.to_vec() == *other
    }
}

impl PartialEq<Headers> for Vec<(String, String)> {
    fn eq(&self, other: &Headers) -> bool {
        *self == other.to_vec()
    }
}

impl From<HeaderMap> for Headers {
    fn from(map: HeaderMap) -> Self {
        let mut builder = HeadersBuilder::with_capacity(map.len(), map.len() * 32);
        for (name, value) in map.iter() {
            builder.append(name.as_str(), value.as_bytes());
        }
        builder.build()
    }
}

impl From<HeadersBuilder> for Headers {
    fn from(builder: HeadersBuilder) -> Self {
        builder.build()
    }
}

/// Ordered headers with JA4H fingerprint calculation.
///
/// JA4H (JA4 for HTTP) fingerprints HTTP clients based on:
/// - Header order
/// - Header names (normalized to lowercase)
///
/// This implementation is intentionally header-name/order based and does not
/// include header values in the hash. Firefox version differences that only
/// change the User-Agent value are not JA4H-distinguishable here.
///
/// This type preserves exact header order for fingerprint accuracy.
#[derive(Debug)]
pub struct OrderedHeaders {
    headers: Headers,
    cached_pairs: OnceLock<Arc<[(String, String)]>>,
}

impl Clone for OrderedHeaders {
    fn clone(&self) -> Self {
        Self {
            headers: self.headers.clone(),
            cached_pairs: OnceLock::new(),
        }
    }
}

static CHROME_NAVIGATION_HEADERS: OnceLock<OrderedHeaders> = OnceLock::new();
static FIREFOX_NAVIGATION_HEADERS: OnceLock<OrderedHeaders> = OnceLock::new();

impl OrderedHeaders {
    /// Create new ordered headers.
    pub fn new(headers: Vec<(String, String)>) -> Self {
        Self {
            headers: Headers::from_vec(headers),
            cached_pairs: OnceLock::new(),
        }
    }

    /// Create Chrome navigation headers with exact order.
    /// Uses Chrome 148 (latest implemented) by default.
    pub fn chrome_navigation() -> Self {
        CHROME_NAVIGATION_HEADERS
            .get_or_init(|| Self::new(headers_to_owned(chrome_148_headers())))
            .clone()
    }

    /// Create Firefox navigation headers with exact order.
    /// Uses Firefox 151 (latest implemented release) by default.
    pub fn firefox_navigation() -> Self {
        FIREFOX_NAVIGATION_HEADERS
            .get_or_init(|| Self::new(headers_to_owned(firefox_151_headers())))
            .clone()
    }

    /// Get headers as vector pairs (cached for stable references).
    pub fn headers(&self) -> &[(String, String)] {
        self.cached_pairs
            .get_or_init(|| {
                let pairs = self.headers.to_vec();
                Arc::from(pairs.into_boxed_slice())
            })
            .as_ref()
    }

    /// Borrow the underlying byte-spanned headers.
    pub fn headers_ref(&self) -> &Headers {
        &self.headers
    }

    /// Calculate JA4H fingerprint string.
    ///
    /// JA4H format: header_names|header_order_hash
    /// - header_names: comma-separated lowercase header names
    /// - header_order_hash: hash of header order
    pub fn ja4h_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        let header_names: Vec<String> = self
            .headers
            .iter()
            .map(|(name, _)| name.to_lowercase())
            .collect();

        let names_str = header_names.join(",");

        let mut hasher = Sha256::new();
        hasher.update(names_str.as_bytes());
        let hash = hasher.finalize();

        let hash_str: String = hash[..3].iter().map(|b| format!("{:02x}", b)).collect();

        format!("{}|{}", names_str, hash_str)
    }

    /// Add a header (preserves order).
    pub fn add(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Convert to vector of owned headers.
    pub fn into_vec(self) -> Vec<(String, String)> {
        self.headers.into_inner()
    }
}

impl From<Vec<(String, String)>> for OrderedHeaders {
    fn from(headers: Vec<(String, String)>) -> Self {
        Self::new(headers)
    }
}

impl From<OrderedHeaders> for Vec<(String, String)> {
    fn from(oh: OrderedHeaders) -> Self {
        oh.into_vec()
    }
}

fn firefox_navigation_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
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

fn firefox_ajax_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
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

fn firefox_form_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
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

macro_rules! firefox_header_set {
    ($headers_fn:ident, $ajax_fn:ident, $form_fn:ident, $ua:literal, $label:literal) => {
        #[doc = concat!("Firefox ", $label, " browser headers for page navigation.")]
        #[doc = "Firefox does NOT send Sec-Ch-Ua headers (Client Hints)."]
        pub fn $headers_fn() -> Vec<(&'static str, &'static str)> {
            firefox_navigation_headers($ua)
        }

        #[doc = concat!("Firefox ", $label, " headers for AJAX/API requests.")]
        pub fn $ajax_fn() -> Vec<(&'static str, &'static str)> {
            firefox_ajax_headers($ua)
        }

        #[doc = concat!("Firefox ", $label, " headers for form submissions.")]
        pub fn $form_fn() -> Vec<(&'static str, &'static str)> {
            firefox_form_headers($ua)
        }
    };
}

firefox_header_set!(
    firefox_133_headers,
    firefox_133_ajax_headers,
    firefox_133_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "133"
);
firefox_header_set!(
    firefox_134_headers,
    firefox_134_ajax_headers,
    firefox_134_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
    "134"
);
firefox_header_set!(
    firefox_135_headers,
    firefox_135_ajax_headers,
    firefox_135_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
    "135"
);
firefox_header_set!(
    firefox_136_headers,
    firefox_136_ajax_headers,
    firefox_136_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
    "136"
);
firefox_header_set!(
    firefox_137_headers,
    firefox_137_ajax_headers,
    firefox_137_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
    "137"
);
firefox_header_set!(
    firefox_138_headers,
    firefox_138_ajax_headers,
    firefox_138_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "138"
);
firefox_header_set!(
    firefox_139_headers,
    firefox_139_ajax_headers,
    firefox_139_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
    "139"
);
firefox_header_set!(
    firefox_140_headers,
    firefox_140_ajax_headers,
    firefox_140_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "140"
);
firefox_header_set!(
    firefox_141_headers,
    firefox_141_ajax_headers,
    firefox_141_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
    "141"
);
firefox_header_set!(
    firefox_142_headers,
    firefox_142_ajax_headers,
    firefox_142_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
    "142"
);
firefox_header_set!(
    firefox_143_headers,
    firefox_143_ajax_headers,
    firefox_143_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
    "143"
);
firefox_header_set!(
    firefox_144_headers,
    firefox_144_ajax_headers,
    firefox_144_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
    "144"
);
firefox_header_set!(
    firefox_145_headers,
    firefox_145_ajax_headers,
    firefox_145_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
    "145"
);
firefox_header_set!(
    firefox_146_headers,
    firefox_146_ajax_headers,
    firefox_146_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
    "146"
);
firefox_header_set!(
    firefox_147_headers,
    firefox_147_ajax_headers,
    firefox_147_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
    "147"
);
firefox_header_set!(
    firefox_148_headers,
    firefox_148_ajax_headers,
    firefox_148_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
    "148"
);
firefox_header_set!(
    firefox_149_headers,
    firefox_149_ajax_headers,
    firefox_149_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
    "149"
);
firefox_header_set!(
    firefox_150_headers,
    firefox_150_ajax_headers,
    firefox_150_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
    "150"
);
firefox_header_set!(
    firefox_151_headers,
    firefox_151_ajax_headers,
    firefox_151_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
    "151"
);
firefox_header_set!(
    firefox_esr_115_headers,
    firefox_esr_115_ajax_headers,
    firefox_esr_115_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:115.0) Gecko/20100101 Firefox/115.0",
    "115 ESR"
);
firefox_header_set!(
    firefox_esr_128_headers,
    firefox_esr_128_ajax_headers,
    firefox_esr_128_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "128 ESR"
);
firefox_header_set!(
    firefox_esr_140_headers,
    firefox_esr_140_ajax_headers,
    firefox_esr_140_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "140 ESR"
);
