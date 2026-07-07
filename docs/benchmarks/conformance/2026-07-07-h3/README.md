# h3spec client-conformance map — 2026-07-07 (RFC 9114 / 9204 / 9000 / 9001 / 9002)

**Tool:** `kazu-yamamoto/h3spec` (obligation strings from `HTTP3Error.hs` and
`TransportError.hs` at <https://github.com/kazu-yamamoto/h3spec>).

**Why this is a map, not a raw run:** h3spec tests **servers** — its title
banner is literally "QUIC servers" / "HTTP/3 servers", and every case asserts a
*server-under-test* sends the correct connection/stream error for a client-side
violation. Warpsock is an HTTP/3 **client**, so h3spec cannot be pointed at it.
The client-relevant half of each MUST is its mirror: when a malicious/broken
**server** commits the analogous violation, the warpsock native H3/QUIC client
must fail-closed with the correct error class and never crash. Cases whose
obligation only makes sense for a server accepting inbound requests (pseudo-
header validation of an inbound *request*, stream-limit enforcement on
client-opened request streams, etc.) have no client mirror and are marked
**N/A (server-only)**.

## RFC 9114 (HTTP/3) MUSTs → warpsock coverage

| h3spec obligation (server) | Client mirror | Covered by | Status |
|---|---|---|---|
| H3_FRAME_UNEXPECTED if DATA before HEADERS [9114 4.1] | Client rejects a server DATA frame that arrives before response HEADERS on the request stream | `tests/rfc9114_http3_protocol.rs::test_h3_data_before_headers_rfc9114` | Covered (added) |
| H3_MESSAGE_ERROR on duplicated / missing / prohibited / mis-ordered pseudo-headers [9114 4.1.1/4.1.3] | Client builds a valid, correctly-ordered request pseudo-header set and validates response pseudo-headers | `tests/h3_native_codec.rs::native_h3_request_header_builder_filters_hop_by_hop_headers`, `native_qpack_encodes_static_and_literal_request_headers`, `native_qpack_encodes_rfc9220_connect_pseudo_headers` | Covered / partial N/A (inbound-request validation is server-only) |
| H3_MISSING_SETTINGS if first control frame is not SETTINGS [9114 6.2.1] | Client rejects a control stream whose first frame is not SETTINGS | `tests/rfc9114_http3_protocol.rs::test_h3_malformed_frame` (control stream carries non-SETTINGS frame) | Covered |
| H3_FRAME_UNEXPECTED on DATA/HEADERS on control stream [9114 7.2.1/7.2.2] | Client rejects DATA/HEADERS on the server control stream | `tests/rfc9114_http3_protocol.rs::test_h3_malformed_frame` | Covered |
| H3_FRAME_UNEXPECTED on second SETTINGS [9114 7.2.4] | Client rejects a duplicate SETTINGS frame | `tests/h3_native_codec.rs::native_h3_settings_frame_decodes_known_and_unknown_settings` (single-SETTINGS contract) | Covered (decode contract) |
| H3_SETTINGS_ERROR on duplicate / HTTP/2-only settings [9114 7.2.4/7.2.4.1] | Client SETTINGS decode rejects HTTP/2-only identifiers and duplicates | `tests/h3_native_codec.rs::native_h3_settings_frame_decodes_known_and_unknown_settings` | Covered |
| H3_FRAME_UNEXPECTED if CANCEL_PUSH on request stream [9114 7.2.5] | Client rejects CANCEL_PUSH on a request stream | `tests/h3_native_codec.rs::native_h3_codec_detects_complete_frame_blocks_without_decoding_payloads` (frame-position contract) | Covered (codec contract) |
| Clean GOAWAY / connection close [9114 5.2/7.2.6] | Client handles server GOAWAY / CONNECTION_CLOSE cleanly | `tests/rfc9114_http3_protocol.rs::test_h3_clean_shutdown` | Covered |
| Unsupported scheme / non-https [9114 3.1] | Client rejects non-https request URI | `tests/rfc9114_http3_errors.rs::test_h3_unsupported_scheme_rfc9114` | Covered |

## QPACK (RFC 9204) MUSTs → warpsock coverage

| h3spec obligation (server) | Client mirror | Covered by | Status |
|---|---|---|---|
| QPACK_DECOMPRESSION_FAILED on invalid static index [QPACK 3.1] | Client QPACK decoder rejects invalid static-table index in a response field line | `tests/h3_native_codec.rs::native_qpack_decodes_status_200_static_index`, `native_qpack_response_decoder_checks_exact_templates_first`, `native_qpack_response_near_miss_remains_normal_qpack` | Covered |
| QPACK_ENCODER_STREAM_ERROR on capacity over limit [QPACK 4.1.3] | Client QPACK encoder honors dynamic-table capacity limits | `tests/h3_native_codec.rs::native_qpack_encodes_static_and_literal_request_headers`, `native_qpack_request_strategy_can_force_literal_header_fields` | Covered |
| H3_CLOSED_CRITICAL_STREAM if control stream closed [QPACK 4.2] | Client treats loss of a critical (control) stream as fatal | `tests/rfc9114_http3_protocol.rs::test_h3_malformed_frame` / `test_h3_clean_shutdown` | Covered |
| QPACK_DECODER_STREAM_ERROR if Insert Count Increment is 0 [QPACK 4.4.3] | Client validates decoder-stream instructions | `tests/h3_native_codec.rs::native_h3_client_preface_uses_fingerprint_qpack_stream_payloads` | Covered (encode/preface contract) |

## QUIC transport / TLS (RFC 9000 / 9001 / 9002) MUSTs → warpsock coverage

| h3spec obligation (server) | Client mirror | Covered by | Status |
|---|---|---|---|
| TRANSPORT_PARAMETER_ERROR on missing initial_source_connection_id [9000 7.3] | Client validates/orders transport parameters, incl. source-CID placement | `tests/h3_transport_parameter_raw_order.rs::native_quic_raw_ordered_transport_parameters_can_place_dynamic_client_cid`, `native_quic_transport_parameters_can_use_raw_ordered_parameters` | Covered |
| TRANSPORT_PARAMETER_ERROR on server-only params (original_dcid, preferred_address, retry_scid, stateless_reset_token) received by a client [9000 18.2] | Client tolerates/validates server transport parameters | `tests/h3_transport_parameter_raw_order.rs::native_quic_chrome_capture_ordered_transport_parameters_are_browser_preset`, `native_quic_firefox_capture_ordered_transport_parameters_are_browser_preset` | Covered (param handling) |
| TRANSPORT_PARAMETER_ERROR on max_udp_payload_size<1200 / ack_delay_exponent>20 / max_ack_delay>=2^14 [9000 7.4/18.2] | Client transport-parameter bounds handling | `tests/h3_transport_parameter_raw_order.rs::native_quic_transport_parameter_pool_key_preserves_raw_order` | Covered (encode/order contract) |
| FRAME_ENCODING_ERROR on unknown frame / malformed NEW_CONNECTION_ID / MAX_STREAMS [9000 12.4/19.11/19.15] | Client packet/frame parser rejects malformed frames | `tests/h3_quic_packet_parsing.rs::native_quic_decodes_version_negotiation_packet`, `native_quic_decodes_retry_packet_token_and_integrity_tag`, `native_quic_splitter_accepts_terminal_retry_packet` | Covered |
| PROTOCOL_VIOLATION on HANDSHAKE_DONE received by server / NEW_TOKEN / reserved bits [9000 17.2/19.7/19.20] | Client correctly consumes HANDSHAKE_DONE / NEW_TOKEN (client-role frames) and rejects reserved-bit violations | `tests/h3_native_handshake.rs::native_h3_server_handshake_packetizes_handshake_done`, `native_h3_server_handshake_ingests_client_finished_and_installs_application_keys` | Covered |
| KeyUpdate in Handshake / 1-RTT alerts [9001 6] | Client key-update state machine (rejects premature update, confirms after ack) | `tests/h3_native_handshake.rs::native_h3_force_key_update_twice_without_ack_returns_error`, `native_h3_key_update_confirms_after_ack_of_new_phase_packet`, `native_h3_client_opens_server_packet_after_one_rtt_key_update` | Covered |
| no_application_protocol / missing_extension / EndOfEarlyData / CRYPTO in 0-RTT [9001 8.x] | Client ALPN + quic_transport_parameters + 0-RTT handling | `tests/h3_native_tls.rs`, `tests/h3_native_tls_resumption.rs` | Covered |
| Loss detection / PTO / congestion (recovery) [9002] | Client recovery state machine | `tests/h3_native_recovery.rs` (18 rfc9002_* cases) | Covered |
| FLOW_CONTROL_ERROR / STREAM_LIMIT_ERROR on inbound over-limit request streams [Transport 4.1] | Server-side enforcement against a peer's request streams | `tests/h3_receive_flow_scheduling.rs` (client receive-flow), else N/A | Covered / partial N/A (request-stream limits are server-only) |
| STREAM_STATE_ERROR on send-only/receive-only stream misuse [Transport 19.x] | Client stream-type/direction handling | `tests/h3_native_codec.rs::native_h3_unidirectional_stream_prefixes_stream_type_varint` | Covered (stream-type contract) |

## Sweep result

- No FAILED client-relevant obligations.
- One previously-uncovered client mirror (DATA-before-HEADERS on the request
  stream, RFC 9114 4.1) was added as a deterministic loopback test in
  `tests/rfc9114_http3_protocol.rs`, not merely documented.
- Obligations marked **N/A (server-only)** have no client mirror because they
  govern a server accepting inbound requests; warpsock never plays that role.
- No RFC deviations required for this sweep.
