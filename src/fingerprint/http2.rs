//! HTTP/2 fingerprint configuration (SETTINGS frame).

use std::time::Duration;

/// PRIORITY frame pattern for browser fingerprinting.
///
/// Different browsers send PRIORITY frames with different dependency trees.
/// Format: (stream_id, depends_on_stream_id, weight, exclusive)
/// - exclusive: true means this stream replaces all dependencies of the parent
/// - weight: 1-256, higher means more bandwidth allocation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityTree {
    /// Priority frames to send: (stream_id, depends_on, weight, exclusive)
    pub priorities: Vec<(u32, u32, u8, bool)>,
}

impl PriorityTree {
    /// Chrome PRIORITY frame pattern.
    ///
    /// Chrome sends PRIORITY frames for streams 3,5,7,9,11:
    /// - Stream 3: depends on 0 (root), weight 201
    /// - Stream 5: depends on 0 (root), weight 101
    /// - Stream 7: depends on 0 (root), weight 1
    /// - Stream 9: depends on 7, weight 1
    /// - Stream 11: depends on 3, weight 1
    ///
    /// Akamai format: `3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1`
    pub fn chrome() -> Self {
        Self {
            priorities: vec![
                (3, 0, 201, false), // High priority resource
                (5, 0, 101, false), // Medium priority resource
                (7, 0, 1, false),   // Low priority resource
                (9, 7, 1, false),   // Depends on stream 7
                (11, 3, 1, false),  // Depends on stream 3
            ],
        }
    }

    /// Firefox PRIORITY frame pattern.
    ///
    /// Firefox sends PRIORITY frames for streams that haven't been opened yet,
    /// establishing a dependency tree for future streams. Firefox uses a different
    /// pattern than Chrome.
    ///
    /// The exact Firefox HTTP/2 fingerprint pattern requires verification against
    /// real browser traffic captures.
    /// This is a placeholder based on Firefox's known behavior of sending
    /// PRIORITY frames for unopened streams.
    pub fn firefox() -> Self {
        // Firefox typically sends fewer PRIORITY frames than Chrome
        // and uses different dependency patterns
        Self {
            priorities: vec![(3, 0, 201, false), (5, 0, 101, false), (7, 0, 1, false)],
        }
    }

    /// No PRIORITY frames (some clients don't send them).
    pub fn none() -> Self {
        Self {
            priorities: Vec::new(),
        }
    }
}

/// RFC 9218 Extensible Priorities signal for a request.
///
/// Serializes to an HTTP structured-field dictionary for the `priority`
/// request header (`u=<0-7>`, optional boolean `i`) and supplies the
/// priority field value carried by `PRIORITY_UPDATE` frames (H2 type 0x10 on
/// stream 0, H3 type 0xf0700 on the control stream).
///
/// Fingerprint decision (evidence: `docs/fingerprints/chrome-142-148.md`):
/// The certified Chrome 142-148 desktop macOS captures do NOT carry a
/// `priority` request header or `PRIORITY_UPDATE` frames. Chrome's HTTP/2
/// prioritization on these profiles is expressed through the legacy RFC 7540
/// PRIORITY-frame dependency tree (see [`PriorityTree::chrome`]). Because
/// fingerprint accuracy wins ties, the Chrome and Firefox profiles leave
/// priority emission set to `None` by default: emitting the RFC 9218 header
/// would itself be a fingerprint tell against a real browser. This type
/// exists so a caller can opt in explicitly (e.g. a non-browser profile that
/// follows the RFC 9218 SHOULD defaults) and so the encoder/decoder are
/// exercised by the RFC 9218 conformance suite. Server-sent priority signals
/// are always tolerated (parsed and ignored) per RFC 9218 §7 regardless of
/// this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrioritySignals {
    /// Urgency, 0 (highest) through 7 (lowest). RFC 9218 default is 3.
    pub urgency: u8,
    /// Incremental flag (`i`). RFC 9218 default is false.
    pub incremental: bool,
}

impl Default for PrioritySignals {
    fn default() -> Self {
        // RFC 9218 §4.1 / §4.2 defaults: urgency 3, incremental false.
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

impl PrioritySignals {
    /// Construct from an urgency (clamped to the valid 0-7 range per
    /// RFC 9218 §4.1) and an incremental flag.
    pub fn new(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency: urgency.min(7),
            incremental,
        }
    }

    /// Serialize to the `priority` request-header value as an HTTP
    /// structured-field dictionary (RFC 8941), e.g. `u=3` or `u=5, i`.
    ///
    /// The urgency member is only emitted when it differs from the RFC 9218
    /// default (3); the incremental member is only emitted when true, since
    /// its default is false. When both are default the value is the empty
    /// string, which callers should treat as "do not emit the header".
    pub fn to_header_value(&self) -> String {
        let urgency = self.urgency.min(7);
        let mut parts: Vec<String> = Vec::new();
        if urgency != 3 {
            parts.push(format!("u={urgency}"));
        }
        if self.incremental {
            parts.push("i".to_string());
        }
        parts.join(", ")
    }

    /// The priority field value carried in a `PRIORITY_UPDATE` frame payload.
    /// Same structured-field encoding as the `priority` header (RFC 9218
    /// §7.1). Unlike [`Self::to_header_value`], the empty string is a valid
    /// frame value ("reset to defaults"), so callers may emit it as-is.
    pub fn to_field_value(&self) -> String {
        self.to_header_value()
    }
}

/// HTTP/2 SETTINGS for fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    /// Initial connection-level WINDOW_UPDATE value sent after SETTINGS.
    /// Chrome: 15663105 (15MB), Firefox: 12517377 (12MB)
    pub initial_window_update: u32,
    /// Whether to send all 6 SETTINGS parameters (Chrome) or only selective ones (Firefox).
    /// Firefox only sends: HEADER_TABLE_SIZE (1), INITIAL_WINDOW_SIZE (4), MAX_FRAME_SIZE (5)
    pub send_all_settings: bool,
    /// PRIORITY frame pattern to send during connection setup.
    /// Chrome sends PRIORITY frames for streams 3,5,7,9,11.
    /// Firefox sends different PRIORITY patterns.
    pub priority_tree: Option<PriorityTree>,
    /// PING frame interval for connection keep-alive.
    /// Chrome sends PING frames approximately every 45 seconds.
    /// Set to None to disable automatic PING frames.
    pub ping_interval: Option<Duration>,
    /// Handshake timeout for waiting for server SETTINGS frame.
    /// Default: 10 seconds (matches h2 crate behavior).
    /// Set to None for no timeout (not recommended for production).
    pub handshake_timeout: Option<Duration>,
    /// RFC 9218 Extensible Priorities signal to emit on requests via the
    /// `priority` header and `PRIORITY_UPDATE` frames.
    ///
    /// `None` (the Chrome/Firefox default) means "emit no RFC 9218 priority
    /// signal", which matches the certified browser captures
    /// (`docs/fingerprints/chrome-142-148.md` shows no `priority` header and
    /// no PRIORITY_UPDATE frames — Chrome expresses priority via the legacy
    /// RFC 7540 `priority_tree` above). Set to `Some(..)` only for a
    /// non-browser profile that deliberately follows RFC 9218 SHOULD defaults.
    /// Independent of this setting, server-sent priority signals are always
    /// parsed and ignored (never errored) per RFC 9218 §7.
    pub priority_signals: Option<PrioritySignals>,
}

impl Default for Http2Settings {
    fn default() -> Self {
        // Chrome defaults
        Self {
            header_table_size: 65536,
            enable_push: false,
            max_concurrent_streams: 1000,
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            initial_window_update: 15663105, // Chrome's 15MB window update
            send_all_settings: true,         // Chrome sends all 6 settings
            priority_tree: Some(PriorityTree::chrome()), // Chrome sends PRIORITY frames
            ping_interval: Some(Duration::from_secs(45)), // Chrome sends PING ~every 45s
            handshake_timeout: Some(Duration::from_secs(10)),
            // Chrome capture shows no RFC 9218 priority header/PRIORITY_UPDATE.
            priority_signals: None,
        }
    }
}

impl Http2Settings {
    /// Create shared Firefox desktop HTTP/2 settings.
    ///
    /// Firefox differs from Chrome:
    /// - HEADER_TABLE_SIZE: 65536 (same)
    /// - ENABLE_PUSH: not sent (omitted from SETTINGS frame)
    /// - MAX_CONCURRENT_STREAMS: not sent (omitted, defaults to unlimited)
    /// - INITIAL_WINDOW_SIZE: 131072 (128KB, vs Chrome's 6MB)
    /// - MAX_FRAME_SIZE: 16384 (same)
    /// - MAX_HEADER_LIST_SIZE: not sent (omitted)
    ///
    /// Expected Firefox Akamai SETTINGS: `1:65536;4:131072;5:16384`
    /// Expected Firefox WINDOW_UPDATE: `12517377` (vs Chrome's 15663105)
    pub fn firefox() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: true, // Firefox enables push, but doesn't send in SETTINGS
            max_concurrent_streams: 100, // Firefox default, but not sent in SETTINGS
            initial_window_size: 131072, // 128KB (desktop), vs Chrome's 6MB
            max_frame_size: 16384,
            max_header_list_size: 0, // Not sent in Firefox SETTINGS frame
            initial_window_update: 12517377, // Firefox's 12MB window update
            send_all_settings: false, // Firefox only sends 3 settings (1, 4, 5)
            priority_tree: Some(PriorityTree::firefox()), // Firefox sends PRIORITY frames
            ping_interval: Some(Duration::from_secs(30)), // Firefox sends PING ~every 30s
            handshake_timeout: Some(Duration::from_secs(10)),
            // Firefox capture likewise shows no RFC 9218 priority signal.
            priority_signals: None,
        }
    }
}
