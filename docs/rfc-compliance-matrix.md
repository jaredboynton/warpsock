# RFC Compliance Matrix

One row per RFC MUST-cluster mapped to its owning integration-test binary/file
under `tests/`. Every row is grounded in a real test file (verified via `rg`);
none are aspirational. This matrix is the compliance regression gate: any
fingerprint-profile change touching wire behavior MUST update the affected row
or add a justified-deviation entry below (mirrors the README benchmark policy).

## WebSocket — RFC 6455

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Client frame masking, opcode/FIN framing, control-frame handling, split reader/writer | `tests/rfc6455_websocket.rs` (18 tests) | `send_text_writes_masked_client_frame`, `incoming_ping_writes_matching_pong_if_auto_pong_is_supported`, `split_reader_and_writer_operate_independently` |
| Handshake key/accept, header validation, upgrade negotiation | `tests/websocket_handshake.rs` | `Sec-WebSocket-Key`/`Accept` and upgrade-header assertions |
| Close-code / protocol-error surfacing | `tests/websocket_errors.rs` | close-code and protocol-error cases |
| End-to-end wire conformance (all §4-§7 MUSTs) | Autobahn `crossbario/autobahn-testsuite` fuzzingserver, agent `warpsock` | see Autobahn artifact below (cases 1.x-11.x graded OK/NON-STRICT) |

## permessage-deflate — RFC 7692

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Extension offer/response header, context-takeover + `max_window_bits` params, DEFLATE round-trip, RSV1 semantics | `tests/rfc7692_permessage_deflate.rs` (15 tests) | `ext_header`, `deflate_message`, `server_compressed_text_frame` |
| Compressed-frame wire conformance (§7 cases) | Autobahn fuzzingserver, agent `warpsock-deflate` (`AUTOBAHN_DEFLATE=1`) | cases 12.x/13.x — see Autobahn artifact below |

## HPACK — RFC 7541

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Dynamic-table size updates (§6.3), eviction on capacity change | `tests/rfc7541_hpack.rs` (2 tests) | `test_dynamic_table_size_update_rfc7541_section_6_3`, `test_hpack_eviction_rfc7541` |
| Header casing / field ordering under HPACK | `tests/h2_header_casing.rs` | H2 field-encoding assertions |

## WebSocket over HTTP/2 — RFC 8441

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Extended CONNECT handshake, status-200 open, pseudo-header order | `tests/rfc8441_handshake.rs` (5), `tests/rfc8441_headers.rs` (5) | `rfc8441_extended_connect_encodes_required_pseudo_headers_first`, `rfc8441_extended_connect_rejects_h1_websocket_headers` |
| `SETTINGS_ENABLE_CONNECT_PROTOCOL` gating & raw id preservation | `tests/rfc8441_settings.rs` (3) | `rfc8441_settings_id_supports_enable_connect_protocol`, `rfc8441_client_initial_settings_do_not_advertise_enable_connect_protocol` |
| Tunnel byte transport, multiplexing with normal requests, flow control | `tests/rfc8441_tunnel.rs` (9), `tests/rfc8441_multiplexing.rs` (3), `tests/rfc8441_flow_control.rs` (3) | `rfc8441_tunnel_and_normal_h2_request_share_one_connection` |
| Client builder surface | `tests/rfc8441_client_api.rs` (4) | `accept_one_rfc8441_tunnel` |

## WebSocket over HTTP/3 — RFC 9220

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Extended CONNECT over H3, status-200 open (reject 101), pseudo-header order | `tests/rfc9220_handshake.rs` (3), `tests/rfc9220_headers.rs` (2) | `rfc9220_successful_open_requires_status_200`, `rfc9220_rejects_status_101`, `rfc9220_extended_connect_sends_required_pseudo_headers_in_order` |
| SETTINGS gating, ws-scheme rejection before QUIC | `tests/rfc9220_settings.rs` (2) | `rfc9220_does_not_send_extended_connect_before_server_enables_it`, `rfc9220_ws_scheme_is_rejected_before_quic` |
| WebSocket frames carried in H3 DATA (incl. native H3) | `tests/rfc9220_tunnel.rs` (4) | `rfc9220_tunnel_carries_websocket_frame_bytes_in_h3_data`, `native_h3_rfc9220_tunnel_carries_websocket_frame_bytes_in_h3_data` |
| Client builder surface | `tests/rfc9220_client_api.rs` (2) | `rfc9220_client_builder_exposes_websocket_h3` |

## HTTP Semantics — RFC 9110

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Redirect handling, content negotiation, method/status semantics | `tests/rfc9110_semantics.rs` (3) | `test_redirect_response_301`, `test_content_negotiation_accept_header` |

## HTTP Caching — RFC 9111

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| `no-store` (§5.2.2.3), cache hit, ETag revalidation | `tests/rfc9111_caching.rs` (3) | `test_cache_no_store_rfc9111_section_5_2_2_3`, `test_cache_hit_rfc9111`, `test_cache_revalidation_etag` |

## HTTP/1.1 — RFC 9112

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Content-Length vs chunked framing, connection reuse, 204/no-body, general §MUSTs | `tests/rfc9112_http1.rs` (3), `tests/h1_rfc_compliance.rs` (13) | `test_request_framing_content_length`, `test_request_framing_chunked`, `test_http11_connection_reuse`, `test_204_no_content_has_no_body` |

## HTTP/2 — RFC 9113

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Frame header serialization, SETTINGS (§6.5), WINDOW_UPDATE (§6.9) | `tests/rfc9113_http2_frames.rs` (6) | `test_settings_frame_rfc9113_section_6_5`, `test_window_update_rfc9113_section_6_9` |
| Flow control, multiplexing, state machine, malformed-frame rejection | `tests/h2_flow_control.rs`, `tests/h2_multiplexing.rs`, `tests/h2_state_machine.rs`, `tests/h2_malformed.rs` | H2 connection-behavior suites |

## HTTP/3 — RFC 9114

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Clean shutdown, malformed-frame handling, protocol behavior | `tests/rfc9114_http3_protocol.rs` (2) | `test_h3_clean_shutdown`, `test_h3_malformed_frame` |
| Error mapping (unsupported scheme, DNS failure) | `tests/rfc9114_http3_errors.rs` (2) | `test_h3_unsupported_scheme_rfc9114`, `test_h3_dns_resolution_failure` |
| Native H3 frame codec (DATA/HEADERS/GOAWAY round-trip, settings order) | `tests/h3_native_codec.rs` (23) | `native_h3_codec_round_trips_data_headers_and_goaway_frames` |

## QPACK — RFC 9204

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Encoder/decoder stream payloads, `qpack_max_table_capacity` / `qpack_blocked_streams` settings, fingerprint-ordered stream bytes | `tests/h3_native_codec.rs` (23) | `native_h3_client_preface_uses_fingerprint_qpack_stream_payloads` (`h3_native_codec.rs:200`), settings at `:54-55` |
| Header-block encode/decode over H3 | `tests/h3_native_handshake.rs`, `tests/h3_fingerprint_config.rs` | QPACK header-block assertions |

## Extensible Priorities — RFC 9218

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Default urgency/incremental signals, sf-dictionary serialization (bare members, non-default only), PRIORITY_UPDATE emission | `tests/rfc9218_priorities.rs` (21) | `default_priority_signals_match_rfc_defaults`, `urgency_only_serializes_when_non_default`, `incremental_flag_serializes_as_bare_member` |

## Cookies — RFC 6265

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Domain normalization, Secure-flag enforcement (§5.4), public-suffix blocking (§5.3) | `tests/rfc6265_cookies.rs` (10) | `test_cookie_domain_normalization`, `test_secure_flag_enforcement_rfc6265_section_5_4`, `test_public_suffix_blocking_rfc6265_section_5_3` |

## HTTP Authentication — RFC 7616 / 7617

| MUST-cluster | Owning test | Evidence |
|---|---|---|
| Digest auth SHA-256 (§ example), challenge parsing | `tests/rfc7616_digest_auth.rs` (2) | `test_digest_auth_sha256_rfc7616_example`, `test_parse_digest_challenge` |
| Basic auth encoding (§2), colon-in-password, round-trip | `tests/rfc7617_auth.rs` (3) | `test_basic_auth_encoding_rfc7617_section_2`, `test_basic_auth_colon_in_password` |

---

## Autobahn TestSuite artifact

Industry-standard `crossbario/autobahn-testsuite` fuzzingserver run (the same
suite tungstenite and fastwebsockets publish against). Run via `just autobahn`
(`scripts/autobahn.sh`); artifacts archived under
`docs/benchmarks/autobahn/<date>/`.

- **Artifact:** `docs/benchmarks/autobahn/2026-07-07/`
- **Gate:** PASSED — **zero cases graded FAILED**.
- **Agent `warpsock` (no deflate):** TOTAL=517 — OK=294, NON-STRICT=4, INFORMATIONAL=3, UNIMPLEMENTED=216, **FAILED=0**. The 216 UNIMPLEMENTED are the RFC 7692 compression cases (12.x/13.x) that only run when the client offers permessage-deflate.
- **Agent `warpsock-deflate` (`AUTOBAHN_DEFLATE=1`):** offers permessage-deflate so the RFC 7692 compression cases (12.x/13.x) execute. TOTAL=517 — OK=438, NON-STRICT=4, INFORMATIONAL=3, UNIMPLEMENTED=72, **FAILED=0**. Run via `AUTOBAHN_DEFLATE=1 bash scripts/autobahn.sh`.

Allowed non-FAILED grades: `OK`, `NON-STRICT`, `INFORMATIONAL`, `UNIMPLEMENTED`.

## Justified deviations (Chrome-fingerprint-driven)

Warpsock resolves fingerprint-accuracy vs strict-maximal-compliance ties in
favor of matching a real Chrome browser on the wire. These are deliberate and
MUST stay documented here:

| Deviation | Where | Rationale |
|---|---|---|
| Default permessage-deflate offer advertises `client_max_window_bits` with **no context-takeover parameters** (`PermessageDeflateOffer::default`), matching Chrome exactly, rather than the maximal parameter set | `src/websocket/extension.rs:80-88` | Chrome sends exactly `permessage-deflate; client_max_window_bits` and nothing else; fingerprint accuracy wins ties. Full negotiation (context takeover, bounded `server_max_window_bits`) remains available via `.permessage_deflate_with(offer)`. |
| `.permessage_deflate()` builder shortcut uses `no_context_takeover()` (both directions reset per-message) | `src/websocket/client.rs:101-104`, `src/websocket/extension.rs:96-101` | Bounded memory profile by default; context takeover is opt-in via explicit offer. No default-on context takeover (plan non-goal). |
| RFC 9218: client **emits** priority signals only; it does not implement server-side scheduling logic | `tests/rfc9218_priorities.rs` | Plan non-goal — a client emits signals, it does not schedule. |
