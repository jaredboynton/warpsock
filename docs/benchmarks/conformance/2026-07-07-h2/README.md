# h2spec client-conformance map — 2026-07-07 (RFC 9113)

**Tool:** `summerwind/h2spec` (case IDs from the `http2/` and `hpack/` case tree
at <https://github.com/summerwind/h2spec>).

**Why this is a map, not a raw run:** h2spec is a *server*-conformance tool. It
plays the client role and asserts the *server-under-test* rejects protocol
violations. Warpsock is an HTTP/2 **client**, so h2spec cannot be pointed at it
directly. The client-relevant half of each case is its mirror: when a
malicious/broken **server** emits the same violation, the warpsock client must
fail-closed (GOAWAY / RST_STREAM / surfaced error) and never crash. Cases whose
obligation is purely server-side (e.g. "server must accept a valid request")
have no client mirror and are marked **N/A (server-only)**.

Deviations that are intentional and Chrome-fingerprint-justified are called out;
none were required for this sweep.

## RFC 9113 section → warpsock coverage

| h2spec section | Client-relevant obligation (mirror) | Covered by | Status |
|---|---|---|---|
| 3.5 Connection Preface | Client emits the client preface + initial SETTINGS | `tests/h2_frames_debug.rs::test_connection_preface` | Covered |
| 4.1 Frame Format (unknown type) | Client MUST ignore/discard frames of unknown type | `tests/h2spec_client_conformance.rs::client_ignores_unknown_frame_type_rfc9113_5_5` | Covered (added) |
| 4.2 Frame Size | Client rejects frames exceeding SETTINGS_MAX_FRAME_SIZE (FRAME_SIZE_ERROR) | `tests/h2_malformed.rs::test_oversized_frame` | Covered |
| 4.3 Header Compression | Client surfaces error on malformed/empty header block | `tests/h2_malformed.rs::test_zero_length_headers_frame` | Covered |
| 5.1 Stream States | Client rejects DATA on a closed stream (RST_STREAM/GOAWAY) | `tests/h2_state_machine.rs::test_data_on_closed_stream` | Covered |
| 5.1.1 Stream Identifiers | Client rejects server-initiated even stream ID | `tests/h2_state_machine.rs::test_server_initiated_stream_even_id` | Covered |
| 5.1.2 Stream Concurrency | Client opens streams with strictly ascending IDs, respects concurrency | `tests/h2_multiplexing.rs::test_h2_stream_ids_ascending`, `test_h2_parallel_requests_multiplex` | Covered |
| 5.3 Stream Priority | Priority signaling (RFC 7540 tree / RFC 9218) — fingerprint-gated | `tests/rfc9218_priorities.rs` | Covered |
| 5.4 Error Handling | Client surfaces connection/stream errors instead of crashing | `tests/h2_malformed.rs`, `tests/h2_state_machine.rs` | Covered |
| 5.5 Extending HTTP/2 (unknown frames/settings) | Client ignores unknown frame types and unknown settings | `tests/h2spec_client_conformance.rs::client_ignores_unknown_frame_type_rfc9113_5_5` | Covered (added) |
| 6.1 DATA | Client applies flow control / END_STREAM to DATA | `tests/h2_flow_control.rs`, `tests/h2_multiplexing.rs::test_h2_response_body_per_stream` | Covered |
| 6.2 HEADERS | Client decodes response HEADERS; rejects empty block | `tests/h2_malformed.rs::test_zero_length_headers_frame`, `tests/h2_header_casing.rs` | Covered |
| 6.3 PRIORITY | Client tolerates server PRIORITY frames | `tests/rfc9218_priorities.rs` (PRIORITY_UPDATE layout) | Covered |
| 6.4 RST_STREAM | Client honors server RST_STREAM (stream terminates) | `tests/h2_state_machine.rs` (RST accepted as valid violation response), `tests/rfc9113_http2_frames.rs::test_rst_stream_frame_rfc9113_section_6_4` | Covered |
| 6.5 SETTINGS | Client ACKs server SETTINGS; serializes its own | `tests/rfc9113_http2_frames.rs::test_settings_frame_rfc9113_section_6_5`; handshake ACK in `tests/h2_state_machine.rs` | Covered |
| 6.5.2 Defined Settings | Client honors SETTINGS_MAX_FRAME_SIZE etc. | `tests/h2_malformed.rs::test_oversized_frame`, `tests/h2_flow_control.rs` | Covered |
| 6.5.3 Settings Synchronization | Client sends SETTINGS ACK on receipt | handshake in every h2 suite (`send_settings` + client ACK asserted) | Covered |
| 6.6 PUSH_PROMISE | Client rejects/ignores push when disabled | `tests/h2_push_promise.rs::test_push_promise_when_disabled` | Covered |
| 6.7 PING | Client serializes/parses PING correctly | `tests/rfc9113_http2_frames.rs::test_ping_frame_rfc9113_section_6_7` | Covered |
| 6.8 GOAWAY | Client handles server GOAWAY (streams > last-id unprocessed); fails-closed | `tests/h2spec_client_conformance.rs::client_handles_server_goaway_rfc9113_6_8`; serialization in `tests/rfc9113_http2_frames.rs::test_goaway_frame_rfc9113_section_6_8` | Covered (added) |
| 6.9 WINDOW_UPDATE | Client emits WINDOW_UPDATE, respects flow-control window | `tests/h2_flow_control.rs::connection_window_update_refresh_uses_advertised_increment`, `test_large_upload_flow_control`; `tests/rfc9113_http2_frames.rs::test_window_update_rfc9113_section_6_9` | Covered |
| 6.9.1 Flow-Control Window | Client waits for WINDOW_UPDATE on large uploads | `tests/h2_flow_control.rs::test_large_upload_flow_control` | Covered |
| 6.9.2 Initial Window Size | Client tolerates zero/edge initial window | `tests/h2_flow_control.rs::zero_initial_connection_window_size_does_not_send_invalid_window_update` | Covered |
| 6.10 CONTINUATION | Client reassembles/handles CONTINUATION | HPACK block handling in `tests/rfc7541_hpack.rs`, `tests/h2_malformed.rs` | Covered |
| 8.1 HTTP Request/Response Exchange | Client produces valid request pseudo-headers | `tests/h2_header_casing.rs`, `tests/rfc9110_semantics.rs` | Covered |
| 8.1.2 Header Fields / casing | Client does not lowercase reserved-case values incorrectly; rejects connection-specific headers | `tests/h2_header_casing.rs::test_uppercase_headers_are_not_lowercased` | Covered |
| 8.2 Server Push | Client handling of server push (disabled path) | `tests/h2_push_promise.rs` | Covered |
| HPACK 2.x / 4.x / 5.x / 6.x | Client HPACK encode/decode, dynamic table, huffman, string literals | `tests/rfc7541_hpack.rs` | Covered |
| `client/*` (h2spec client-suite) | These test a real HTTP/2 client's outbound behavior; warpsock is the client-under-test | `tests/rfc9113_http2_frames.rs` + all h2 suites | Covered (warpsock is the SUT) |
| Server-acceptance-only cases (e.g. "server accepts valid frame") | No client mirror | — | N/A (server-only) |

## Sweep result

- No FAILED client-relevant obligations.
- Two previously-uncovered client mirrors were added as deterministic loopback
  tests (`tests/h2spec_client_conformance.rs`), not merely documented.
- No RFC deviations required; Chrome fingerprint does not force any SHOULD
  deviation in the sections above (priority signaling is fingerprint-gated and
  documented separately in `tests/rfc9218_priorities.rs`).
