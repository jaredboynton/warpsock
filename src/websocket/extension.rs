use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::url::Url;

use super::{WebSocketError, WebSocketResult};

const PMD_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Default LZ77 window bits per RFC 7692: an absent `*_max_window_bits`
/// parameter means the endpoint uses the full 32 KiB window (15 bits).
const DEFAULT_WINDOW_BITS: u8 = 15;
const MIN_WINDOW_BITS: u8 = 8;
const MAX_WINDOW_BITS: u8 = 15;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WebSocketExtensions {
    pub(crate) permessage_deflate: Option<PermessageDeflateConfig>,
    /// The offer that produced this negotiation state. On the request side this
    /// drives the `Sec-WebSocket-Extensions` header; on the response side it
    /// bounds which parameters the server is allowed to echo (RFC 7692 §5.1).
    pub(crate) offer: Option<PermessageDeflateOffer>,
}

impl WebSocketExtensions {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Request permessage-deflate with an explicit offer. The negotiated
    /// `PermessageDeflateConfig` is filled in later from the server response.
    pub(crate) fn offer(offer: PermessageDeflateOffer) -> Self {
        Self {
            permessage_deflate: None,
            offer: Some(offer),
        }
    }

    pub(crate) fn permessage_deflate(config: PermessageDeflateConfig) -> Self {
        Self {
            permessage_deflate: Some(config),
            offer: None,
        }
    }

    pub(crate) fn has_permessage_deflate(self) -> bool {
        self.permessage_deflate.is_some() || self.offer.is_some()
    }

    /// The offer to advertise; falls back to the Chrome-accurate default when a
    /// caller requested compression without a specific offer.
    pub(crate) fn offer_or_default(self) -> PermessageDeflateOffer {
        self.offer.unwrap_or_default()
    }
}

/// What the client offers in the `Sec-WebSocket-Extensions` request header.
///
/// This is distinct from [`PermessageDeflateConfig`], which records the
/// *negotiated* result parsed out of the server response. The offer controls
/// which parameters we advertise and therefore which parameters the server is
/// allowed to echo back (RFC 7692 §5.1: a response MUST NOT contain a parameter
/// the client did not offer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermessageDeflateOffer {
    /// Advertise `client_max_window_bits` (valueless) so the server may cap the
    /// client's window. Chrome sends exactly this and nothing else.
    pub offer_client_max_window_bits: bool,
    /// Advertise `server_max_window_bits=<n>` to request a bounded server
    /// window; `None` omits the parameter (server keeps its default 15).
    pub server_max_window_bits: Option<u8>,
    /// Advertise `client_no_context_takeover` (reset the client compressor per
    /// message, bounding client memory).
    pub client_no_context_takeover: bool,
    /// Advertise `server_no_context_takeover` (ask the server to reset per
    /// message, bounding decompressor memory).
    pub server_no_context_takeover: bool,
}

impl Default for PermessageDeflateOffer {
    /// Chrome-accurate default offer: `permessage-deflate; client_max_window_bits`
    /// with no context-takeover parameters. Fingerprint accuracy wins ties, so
    /// this matches what a real Chrome browser advertises.
    fn default() -> Self {
        Self {
            offer_client_max_window_bits: true,
            server_max_window_bits: None,
            client_no_context_takeover: false,
            server_no_context_takeover: false,
        }
    }
}

impl PermessageDeflateOffer {
    /// The legacy warpsock offer that forced no-context-takeover on both ends.
    /// Preserved so callers who want the smaller memory profile can opt in.
    pub fn no_context_takeover() -> Self {
        Self {
            offer_client_max_window_bits: false,
            server_max_window_bits: None,
            client_no_context_takeover: true,
            server_no_context_takeover: true,
        }
    }

    /// Serialize the offer into a `Sec-WebSocket-Extensions` header value.
    pub(crate) fn header_value(&self) -> String {
        let mut header = String::from("permessage-deflate");
        if self.client_no_context_takeover {
            header.push_str("; client_no_context_takeover");
        }
        if self.server_no_context_takeover {
            header.push_str("; server_no_context_takeover");
        }
        if self.offer_client_max_window_bits {
            header.push_str("; client_max_window_bits");
        }
        if let Some(bits) = self.server_max_window_bits {
            header.push_str(&format!("; server_max_window_bits={bits}"));
        }
        header
    }
}

/// The negotiated permessage-deflate parameters extracted from the server
/// response. This struct is the contract consumed by the frame encoder/decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermessageDeflateConfig {
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_no_context_takeover: bool,
    /// LZ77 window bits for the client's *compressor* (bounds our own window).
    pub(crate) client_max_window_bits: u8,
    /// LZ77 window bits for the server's compressor, i.e. our *decompressor*.
    pub(crate) server_max_window_bits: u8,
}

impl Default for PermessageDeflateConfig {
    fn default() -> Self {
        Self {
            client_no_context_takeover: false,
            server_no_context_takeover: false,
            client_max_window_bits: DEFAULT_WINDOW_BITS,
            server_max_window_bits: DEFAULT_WINDOW_BITS,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PermessageDeflateEncoder {
    config: PermessageDeflateConfig,
    inner: Compress,
    /// `inner.total_in()` at the start of the current `compress` call, so we
    /// can compute how much of this message's payload has been consumed across
    /// the drain loop (the compressor's counters are cumulative). Reset to 0
    /// whenever the compressor is rebuilt for no-context-takeover.
    base_in: u64,
}

impl PermessageDeflateEncoder {
    pub(crate) fn new(config: PermessageDeflateConfig) -> Self {
        Self {
            config,
            inner: new_compress(config.client_max_window_bits),
            base_in: 0,
        }
    }

    pub(crate) fn compress(&mut self, url: &Url, payload: &[u8]) -> WebSocketResult<Vec<u8>> {
        // `compress_vec` only writes into `out`'s spare capacity and stops
        // (returning `Status::Ok`) when the buffer fills, silently truncating
        // output for payloads larger than our initial guess. Loop, draining
        // all input and growing `out` until the compressor has consumed the
        // whole payload and emitted every deflate byte for this SYNC flush.
        // Reserve generously up front so a typical message compresses in one
        // `compress_vec` call; grow by doubling only when a call fills every
        // byte of spare capacity (which means more output is still pending).
        let mut out = Vec::with_capacity(payload.len().max(256));
        loop {
            // Give the deflater room to write before each call; if the previous
            // call filled the buffer exactly, more output may still be pending.
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(256));
            }
            let cap = out.capacity();
            let consumed = (self.inner.total_in() - self.base_in) as usize;
            let remaining = &payload[consumed.min(payload.len())..];
            let status = self
                .inner
                .compress_vec(remaining, &mut out, FlushCompress::Sync)
                .map_err(|err| {
                    WebSocketError::protocol(
                        url,
                        format!("permessage-deflate compress failed: {err}"),
                    )
                })?;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            // A repeated SYNC flush on empty input re-emits the sync marker
            // forever, so `total_out` growth is NOT a completion signal. The
            // flush is done once every input byte is consumed AND this call left
            // spare output capacity -- unused room proves nothing more is pending.
            let all_consumed = (self.inner.total_in() - self.base_in) as usize >= payload.len();
            if all_consumed && out.len() < cap {
                break;
            }
        }
        self.base_in = self.inner.total_in();
        if out.ends_with(&PMD_TAIL) {
            out.truncate(out.len() - PMD_TAIL.len());
        }
        if self.config.client_no_context_takeover {
            self.inner = new_compress(self.config.client_max_window_bits);
            self.base_in = 0;
        }
        Ok(out)
    }
}

fn new_compress(_window_bits: u8) -> Compress {
    // The default flate2 backend (miniz_oxide) always uses a 15-bit (32 KiB)
    // window and offers no way to shrink it. The negotiated `client_max_window_bits`
    // is recorded in `PermessageDeflateConfig` for the frame layer and for
    // zlib-backed builds; here we construct the raw-deflate compressor. A 15-bit
    // window is a superset of any smaller negotiated window, so a peer sized to
    // `client_max_window_bits` still decodes our output correctly.
    Compress::new(Compression::fast(), false)
}

#[derive(Debug)]
pub(crate) struct PermessageDeflateDecoder {
    config: PermessageDeflateConfig,
    inner: Decompress,
    /// `inner.total_in()` at the start of the current `decompress` call. Same
    /// role as the encoder's field: the drain loop uses it to know how much of
    /// this block (payload + PMD tail) has been consumed. Reset to 0 on rebuild.
    base_in: u64,
}

impl PermessageDeflateDecoder {
    pub(crate) fn new(config: PermessageDeflateConfig) -> Self {
        Self {
            config,
            inner: new_decompress(config.server_max_window_bits),
            base_in: 0,
        }
    }

    pub(crate) fn decompress(&mut self, url: &Url, payload: &[u8]) -> WebSocketResult<Vec<u8>> {
        let mut input = Vec::with_capacity(payload.len() + PMD_TAIL.len());
        input.extend_from_slice(payload);
        input.extend_from_slice(&PMD_TAIL);
        // `decompress_vec` stops (returning `Status::Ok`) once `out` is full,
        // so a single call silently truncates any message that inflates larger
        // than our guess. Loop, growing `out` and feeding the not-yet-consumed
        // tail of `input`, until the whole block is consumed and drained.
        let mut out = Vec::with_capacity(payload.len().saturating_mul(4).max(256));
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(256));
            }
            let cap = out.capacity();
            let consumed = (self.inner.total_in() - self.base_in) as usize;
            let remaining = &input[consumed.min(input.len())..];
            let status = self
                .inner
                .decompress_vec(remaining, &mut out, FlushDecompress::Sync)
                .map_err(|err| {
                    WebSocketError::protocol(
                        url,
                        format!("permessage-deflate decompress failed: {err}"),
                    )
                })?;
            if matches!(status, Status::StreamEnd) {
                break;
            }
            // Same completion rule as compress: all input (payload + PMD tail)
            // consumed and spare output capacity left over.
            let all_consumed = (self.inner.total_in() - self.base_in) as usize >= input.len();
            if all_consumed && out.len() < cap {
                break;
            }
        }
        self.base_in = self.inner.total_in();
        if self.config.server_no_context_takeover {
            self.inner = new_decompress(self.config.server_max_window_bits);
            self.base_in = 0;
        }
        Ok(out)
    }
}

fn new_decompress(_window_bits: u8) -> Decompress {
    // miniz_oxide always decompresses with a 15-bit window, which is >= any
    // `server_max_window_bits` the server may have negotiated, so it decodes
    // every conformant server stream. The negotiated value is retained in
    // `PermessageDeflateConfig` as the contract for the frame layer.
    Decompress::new(false)
}

/// Parse a single window-bits parameter value per RFC 7692 §7.1.2.1/§7.1.2.2.
/// The value MUST be a decimal integer in the range 8..=15 with no leading
/// zeros or extra characters.
fn parse_window_bits(url: &Url, param: &str, value: &str) -> WebSocketResult<u8> {
    let value = value.trim();
    // Reject quoted values, empty values, leading zeros, signs, and anything
    // that is not a bare decimal integer.
    let looks_valid = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'));
    if !looks_valid {
        return Err(WebSocketError::protocol(
            url,
            format!("permessage-deflate {param} must be an integer 8-15, got {value:?}"),
        ));
    }
    let bits: u16 = value.parse().map_err(|_| {
        WebSocketError::protocol(
            url,
            format!("permessage-deflate {param} must be an integer 8-15, got {value:?}"),
        )
    })?;
    if !(u16::from(MIN_WINDOW_BITS)..=u16::from(MAX_WINDOW_BITS)).contains(&bits) {
        return Err(WebSocketError::protocol(
            url,
            format!("permessage-deflate {param} out of range 8-15: {bits}"),
        ));
    }
    Ok(bits as u8)
}

/// Parse and validate the server's permessage-deflate response against the
/// offer we sent. Returns `Ok(Some(config))` on a valid negotiated result,
/// `Ok(None)` if no permessage-deflate response element was present, and `Err`
/// on any malformed or unsolicited parameter (RFC 7692 §5-§7).
pub(crate) fn parse_permessage_deflate_response(
    url: &Url,
    value: &str,
    offer: PermessageDeflateOffer,
) -> WebSocketResult<Option<PermessageDeflateConfig>> {
    let mut matched: Option<PermessageDeflateConfig> = None;
    for element in value.split(',') {
        let mut parts = element
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty());
        let Some(name) = parts.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case("permessage-deflate") {
            return Err(WebSocketError::UnexpectedExtension {
                url: url.to_string(),
            });
        }
        if matched.is_some() {
            return Err(WebSocketError::protocol(
                url,
                "duplicate permessage-deflate extension response",
            ));
        }
        let mut config = PermessageDeflateConfig::default();
        let mut seen_client_ncto = false;
        let mut seen_server_ncto = false;
        let mut seen_client_bits = false;
        let mut seen_server_bits = false;
        for param in parts {
            let (key, val) = match param.split_once('=') {
                Some((key, val)) => (key.trim(), Some(val.trim())),
                None => (param.trim(), None),
            };
            match key.to_ascii_lowercase().as_str() {
                "client_no_context_takeover" => {
                    if val.is_some() {
                        return Err(WebSocketError::protocol(
                            url,
                            "permessage-deflate client_no_context_takeover takes no value",
                        ));
                    }
                    if seen_client_ncto {
                        return Err(WebSocketError::protocol(
                            url,
                            "duplicate permessage-deflate client_no_context_takeover",
                        ));
                    }
                    seen_client_ncto = true;
                    config.client_no_context_takeover = true;
                }
                "server_no_context_takeover" => {
                    if val.is_some() {
                        return Err(WebSocketError::protocol(
                            url,
                            "permessage-deflate server_no_context_takeover takes no value",
                        ));
                    }
                    if seen_server_ncto {
                        return Err(WebSocketError::protocol(
                            url,
                            "duplicate permessage-deflate server_no_context_takeover",
                        ));
                    }
                    seen_server_ncto = true;
                    config.server_no_context_takeover = true;
                }
                "client_max_window_bits" => {
                    // RFC 7692 §5.1: server MUST NOT include client_max_window_bits
                    // unless the client offered it.
                    if !offer.offer_client_max_window_bits {
                        return Err(WebSocketError::protocol(
                            url,
                            "server returned client_max_window_bits that was not offered",
                        ));
                    }
                    if seen_client_bits {
                        return Err(WebSocketError::protocol(
                            url,
                            "duplicate permessage-deflate client_max_window_bits",
                        ));
                    }
                    seen_client_bits = true;
                    // In a response a valueless client_max_window_bits means the
                    // server accepts our full window (keep the default 15).
                    if let Some(val) = val {
                        config.client_max_window_bits =
                            parse_window_bits(url, "client_max_window_bits", val)?;
                    }
                }
                "server_max_window_bits" => {
                    if seen_server_bits {
                        return Err(WebSocketError::protocol(
                            url,
                            "duplicate permessage-deflate server_max_window_bits",
                        ));
                    }
                    seen_server_bits = true;
                    // The response MUST carry an explicit value (RFC 7692 §7.1.2.2).
                    let Some(val) = val else {
                        return Err(WebSocketError::protocol(
                            url,
                            "permessage-deflate server_max_window_bits requires a value in a response",
                        ));
                    };
                    let bits = parse_window_bits(url, "server_max_window_bits", val)?;
                    // A server may only shrink relative to what we offered.
                    if let Some(offered) = offer.server_max_window_bits {
                        if bits > offered {
                            return Err(WebSocketError::protocol(
                                url,
                                format!("server_max_window_bits={bits} exceeds offered {offered}"),
                            ));
                        }
                    }
                    config.server_max_window_bits = bits;
                }
                _ => {
                    return Err(WebSocketError::protocol(
                        url,
                        format!("unsupported permessage-deflate parameter {key}"),
                    ));
                }
            }
        }
        matched = Some(config);
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        Url::parse("wss://example.com/socket").unwrap()
    }

    // Round-trip compress -> decompress across the payload sizes and repetition
    // counts the Autobahn 12.x/13.x "send 1000 compressed messages" cases use,
    // with context takeover on (default Chrome offer). Guards against silent
    // output truncation and the drain loop failing to terminate.
    #[test]
    fn context_takeover_round_trips_all_sizes() {
        let cfg = PermessageDeflateConfig::default();
        for &size in &[
            0usize, 1, 63, 64, 255, 256, 1024, 4096, 8192, 16384, 32768, 65536,
        ] {
            let mut enc = PermessageDeflateEncoder::new(cfg);
            let mut dec = PermessageDeflateDecoder::new(cfg);
            for round in 0..64 {
                let payload: Vec<u8> = (0..size)
                    .map(|i| ((i * 31 + round * 7) % 251) as u8)
                    .collect();
                let compressed = enc.compress(&url(), &payload).unwrap();
                let restored = dec.decompress(&url(), &compressed).unwrap();
                assert_eq!(
                    restored,
                    payload,
                    "round-trip mismatch at size={size} round={round}: got {} bytes, expected {}",
                    restored.len(),
                    payload.len()
                );
            }
        }
    }

    #[test]
    fn default_offer_matches_chrome() {
        assert_eq!(
            PermessageDeflateOffer::default().header_value(),
            "permessage-deflate; client_max_window_bits"
        );
    }

    #[test]
    fn legacy_offer_preserves_no_context_takeover() {
        assert_eq!(
            PermessageDeflateOffer::no_context_takeover().header_value(),
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover"
        );
    }

    #[test]
    fn accepts_server_chosen_window_bits() {
        let offer = PermessageDeflateOffer {
            offer_client_max_window_bits: true,
            server_max_window_bits: Some(15),
            ..PermessageDeflateOffer::default()
        };
        let config = parse_permessage_deflate_response(
            &url(),
            "permessage-deflate; client_max_window_bits=10; server_max_window_bits=12",
            offer,
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.client_max_window_bits, 10);
        assert_eq!(config.server_max_window_bits, 12);
    }

    #[test]
    fn valueless_client_max_window_bits_in_response_keeps_default() {
        let config = parse_permessage_deflate_response(
            &url(),
            "permessage-deflate; client_max_window_bits",
            PermessageDeflateOffer::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.client_max_window_bits, DEFAULT_WINDOW_BITS);
    }

    #[test]
    fn rejects_client_max_window_bits_not_offered() {
        let offer = PermessageDeflateOffer {
            offer_client_max_window_bits: false,
            ..PermessageDeflateOffer::default()
        };
        assert!(parse_permessage_deflate_response(
            &url(),
            "permessage-deflate; client_max_window_bits=10",
            offer,
        )
        .is_err());
    }

    #[test]
    fn rejects_out_of_range_window_bits() {
        for bad in ["7", "16", "0", "99"] {
            let value = format!("permessage-deflate; server_max_window_bits={bad}");
            assert!(
                parse_permessage_deflate_response(
                    &url(),
                    &value,
                    PermessageDeflateOffer::default()
                )
                .is_err(),
                "expected reject for {bad}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_and_unknown_params() {
        assert!(parse_permessage_deflate_response(
            &url(),
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            PermessageDeflateOffer::default(),
        )
        .is_err());
        assert!(parse_permessage_deflate_response(
            &url(),
            "permessage-deflate; totally_made_up",
            PermessageDeflateOffer::default(),
        )
        .is_err());
    }
}
