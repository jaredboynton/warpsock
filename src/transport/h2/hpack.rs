//! HPACK header compression with custom pseudo-header ordering.
//!
//! This module provides a custom HPACK implementation with:
//! - Custom pseudo-header ordering (Chrome uses `:method, :scheme, :authority, :path`)
//! - Full control over header encoding for fingerprint accuracy
//! - Complete Huffman encoding support

use crate::transport::h2::hpack_impl::{Decoder, Encoder};
use bytes::Bytes;

/// Pseudo-header ordering for HTTP/2 fingerprinting.
///
/// Different browsers/clients send pseudo-headers in different orders.
/// This order is visible in the Akamai HTTP/2 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PseudoHeaderOrder {
    /// Chrome order: :method, :scheme, :authority, :path (m,s,a,p)
    #[default]
    Chrome,
    /// Firefox order: :method, :path, :authority, :scheme (m,p,a,s)
    Firefox,
    /// Safari order: :method, :scheme, :path, :authority (m,s,p,a)
    Safari,
    /// Legacy order: :method, :authority, :scheme, :path (m,a,s,p)
    Standard,
    /// Custom order specified by indices (0=method, 1=authority, 2=scheme, 3=path)
    Custom([u8; 4]),
}

impl PseudoHeaderOrder {
    /// Get the order as array indices.
    /// Input array is [method(0), authority(1), scheme(2), path(3)].
    /// Returns indices to select in output order.
    fn order(&self) -> [usize; 4] {
        match self {
            // Chrome: m,s,a,p -> method, scheme, authority, path
            Self::Chrome => [0, 2, 1, 3], // m=0, s=2, a=1, p=3
            // Firefox: m,p,a,s
            Self::Firefox => [0, 3, 1, 2], // m=0, p=3, a=1, s=2
            // Safari: m,s,p,a
            Self::Safari => [0, 2, 3, 1], // m=0, s=2, p=3, a=1
            // Legacy: m,a,s,p (old incorrect Chrome assumption)
            Self::Standard => [0, 1, 2, 3], // m=0, a=1, s=2, p=3
            Self::Custom(order) => [
                order[0] as usize,
                order[1] as usize,
                order[2] as usize,
                order[3] as usize,
            ],
        }
    }

    /// Get the Akamai fingerprint string for this order.
    pub fn akamai_string(&self) -> &'static str {
        match self {
            Self::Chrome => "m,s,a,p",
            Self::Firefox => "m,p,a,s",
            Self::Safari => "m,s,p,a",
            Self::Standard => "m,a,s,p",
            Self::Custom(_) => "custom",
        }
    }
}

/// HPACK encoder with custom pseudo-header ordering.
pub struct HpackEncoder {
    encoder: Encoder,
    pseudo_order: PseudoHeaderOrder,
}

impl HpackEncoder {
    /// Create a new encoder with the specified pseudo-header order.
    pub fn new(pseudo_order: PseudoHeaderOrder) -> Self {
        Self {
            encoder: Encoder::new(),
            pseudo_order,
        }
    }

    /// Create encoder with Chrome pseudo-header order (default).
    pub fn chrome() -> Self {
        Self::new(PseudoHeaderOrder::Chrome)
    }

    /// Set the dynamic table size.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.encoder.set_max_table_size(size);
    }

    /// Encode headers for an HTTP/2 request.
    ///
    /// Pseudo-headers are ordered according to the configured order.
    /// Regular headers follow in the order provided.
    pub fn encode_request(
        &mut self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Bytes {
        // Build pseudo-headers in configured order
        let pseudo_headers: [(&[u8], &[u8]); 4] = [
            (b":method", method.as_bytes()),
            (b":authority", authority.as_bytes()),
            (b":scheme", scheme.as_bytes()),
            (b":path", path.as_bytes()),
        ];

        // Collect all headers in the correct order
        let mut all_headers: Vec<(&[u8], &[u8])> = Vec::new();

        // Storage for processed valid headers (lowercased name, value ref)
        // We need this intermediate storage to ensure the Strings live long enough
        // and to avoid borrow checker issues (references into a growing Vec).
        let mut valid_headers: Vec<(String, &str)> = Vec::with_capacity(headers.len());

        // Filter and process headers first
        for (name, value) in headers {
            // Skip any pseudo-headers that were incorrectly passed in
            if name.starts_with(':') {
                continue;
            }

            // RFC 9113 Section 8.1.2: Validate header name
            if name.is_empty() {
                continue;
            }
            if name
                .as_bytes()
                .iter()
                .any(|&b| b < 0x21 || (b > 0x7E && b != 0x7F))
            {
                continue;
            }

            // HTTP/2 requires header names to be lowercase
            let name_lower = name.to_lowercase();

            // Skip connection-specific headers forbidden in HTTP/2
            if name_lower == "connection"
                || name_lower == "keep-alive"
                || name_lower == "proxy-connection"
                || name_lower == "transfer-encoding"
                || name_lower == "upgrade"
            {
                continue;
            }

            // RFC 9113 Section 8.1.2.2: TE header allowed ONLY if value is "trailers"
            if name_lower == "te" && value.to_lowercase() != "trailers" {
                continue;
            }

            valid_headers.push((name_lower, value));
        }

        // Add pseudo-headers in the specified order
        let order = self.pseudo_order.order();
        for &idx in &order {
            all_headers.push(pseudo_headers[idx]);
        }

        // Add regular headers from the validated list
        for (n, v) in &valid_headers {
            all_headers.push((n.as_bytes(), v.as_bytes()));
        }

        // Encode all headers
        let encoded = self.encoder.encode(&all_headers);
        Bytes::from(encoded)
    }

    /// Encode RFC 8441 Extended CONNECT headers for WebSocket over HTTP/2.
    ///
    /// The pseudo-header order is deterministic and spec-compliant for RFC 8441;
    /// it is not claimed to be Chrome-exact.
    pub fn encode_extended_connect_websocket(
        &mut self,
        authority: &str,
        scheme: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Bytes, String> {
        if authority.is_empty() {
            return Err(":authority must not be empty".to_string());
        }
        if scheme.is_empty() {
            return Err(":scheme must not be empty".to_string());
        }
        if path.is_empty() {
            return Err(":path must not be empty".to_string());
        }

        let pseudo_headers: [(&[u8], &[u8]); 5] = [
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", scheme.as_bytes()),
            (b":path", path.as_bytes()),
            (b":authority", authority.as_bytes()),
        ];

        let mut valid_headers: Vec<(String, &str)> = Vec::with_capacity(headers.len());

        for (name, value) in headers {
            if name.starts_with(':') {
                return Err(format!("RFC 8441 user pseudo-header rejected: {name}"));
            }

            if name.is_empty() {
                return Err("RFC 8441 header name must not be empty".to_string());
            }
            if name
                .as_bytes()
                .iter()
                .any(|&b| b < 0x21 || (b > 0x7E && b != 0x7F))
            {
                return Err(format!("RFC 8441 invalid header name rejected: {name}"));
            }

            let name_lower = name.to_lowercase();
            if matches!(
                name_lower.as_str(),
                "connection"
                    | "upgrade"
                    | "host"
                    | "sec-websocket-key"
                    | "sec-websocket-accept"
                    | "sec-websocket-extensions"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
            ) {
                return Err(format!("RFC 8441 forbidden header rejected: {name_lower}"));
            }

            if name_lower == "te" && value.to_lowercase() != "trailers" {
                return Err("RFC 8441 forbids TE values other than trailers".to_string());
            }

            valid_headers.push((name_lower, value));
        }

        let mut all_headers: Vec<(&[u8], &[u8])> =
            Vec::with_capacity(pseudo_headers.len() + valid_headers.len());
        all_headers.extend_from_slice(&pseudo_headers);
        for (name, value) in &valid_headers {
            all_headers.push((name.as_bytes(), value.as_bytes()));
        }

        let encoded = self.encoder.encode(&all_headers);
        Ok(Bytes::from(encoded))
    }

    /// Split an encoded header block into chunks if it exceeds max_frame_size.
    /// Returns (first_chunk, remaining_chunks).
    ///
    /// This is used when header blocks exceed MAX_FRAME_SIZE and must be
    /// split across HEADERS + CONTINUATION frames per RFC 9113 Section 6.10.
    ///
    /// Use this after calling encode_request() to chunk the result if needed.
    pub fn chunk_encoded(encoded: Bytes, max_frame_size: usize) -> (Bytes, Vec<Bytes>) {
        if encoded.len() <= max_frame_size {
            // Fits in single frame
            return (encoded, Vec::new());
        }

        // Split into chunks
        let mut chunks: Vec<Bytes> = encoded
            .chunks(max_frame_size)
            .map(Bytes::copy_from_slice)
            .collect();

        let first = chunks.remove(0);
        (first, chunks)
    }
}

/// HPACK decoder.
pub struct HpackDecoder {
    decoder: Decoder,
}

impl HpackDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            decoder: Decoder::new(),
        }
    }

    /// Set the maximum dynamic table size.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.decoder.set_max_table_size(size);
    }

    /// Decode a header block into a list of headers.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();

        self.decoder
            .decode_with_cb(data, |name, value| {
                let name_str = String::from_utf8_lossy(name).into_owned();
                let value_str = String::from_utf8_lossy(value).into_owned();
                headers.push((name_str, value_str));
            })
            .map_err(|e| format!("HPACK decode error: {:?}", e))?;

        Ok(headers)
    }
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pseudo_order_chrome() {
        let order = PseudoHeaderOrder::Chrome;
        assert_eq!(order.akamai_string(), "m,s,a,p");
    }

    #[test]
    fn test_pseudo_order_standard() {
        let order = PseudoHeaderOrder::Standard;
        assert_eq!(order.akamai_string(), "m,a,s,p");
    }

    #[test]
    fn test_encoder_creates_valid_block() {
        let mut encoder = HpackEncoder::chrome();
        let block = encoder.encode_request(
            "GET",
            "https",
            "example.com",
            "/",
            &[("user-agent".to_string(), "test".to_string())],
        );

        // Block should be non-empty
        assert!(!block.is_empty());

        // Decode and verify
        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&block).unwrap();

        // Should have 5 headers (4 pseudo + 1 regular)
        assert_eq!(headers.len(), 5);

        // Verify Chrome order: m,s,a,p
        assert_eq!(headers[0].0, ":method");
        assert_eq!(headers[0].1, "GET");
        assert_eq!(headers[1].0, ":scheme");
        assert_eq!(headers[1].1, "https");
        assert_eq!(headers[2].0, ":authority");
        assert_eq!(headers[2].1, "example.com");
        assert_eq!(headers[3].0, ":path");
        assert_eq!(headers[3].1, "/");
        assert_eq!(headers[4].0, "user-agent");
        assert_eq!(headers[4].1, "test");
    }

    #[test]
    fn test_encoder_standard_order() {
        let mut encoder = HpackEncoder::new(PseudoHeaderOrder::Standard);
        let block = encoder.encode_request("GET", "https", "example.com", "/", &[]);

        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&block).unwrap();

        // Verify Standard/legacy order: m,a,s,p
        assert_eq!(headers[0].0, ":method");
        assert_eq!(headers[1].0, ":authority");
        assert_eq!(headers[2].0, ":scheme");
        assert_eq!(headers[3].0, ":path");
    }

    #[test]
    fn test_encoder_filters_connection_headers() {
        let mut encoder = HpackEncoder::chrome();
        let block = encoder.encode_request(
            "GET",
            "https",
            "example.com",
            "/",
            &[
                ("connection".to_string(), "keep-alive".to_string()),
                ("keep-alive".to_string(), "timeout=5".to_string()),
                ("user-agent".to_string(), "test".to_string()),
            ],
        );

        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&block).unwrap();

        // Should only have pseudo-headers + user-agent (connection headers filtered)
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[4].0, "user-agent");
    }
}
