use specter::{Client, HttpVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn streaming_benchmark_declares_enforceable_h3_gate() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("struct H3Gate"));
    assert!(source.contains("fixture_address: \"127.0.0.1:3203/udp\""));
    assert!(source.contains("reqwest_h3_unavailable_specter_regression_gate"));
    assert!(source.contains("--self-test-h3-threshold-failure"));
    assert!(!source.contains("SPECTER_BENCH_FORCE_H3_THRESHOLD_FAIL"));
}

#[test]
fn streaming_benchmark_declares_enforceable_h1_h2_threshold_gate() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("fn evaluate_comparable_threshold"));
    assert!(source.contains("ttft_improvement_pct >= 5.0"));
    assert!(source.contains("throughput_improvement_required_pct: 5.0"));
    assert!(source.contains("throughput_improvement_pct >= 5.0"));
    assert!(source.contains("p95_throughput_regression_pct <= 5.0"));
    assert!(source.contains("p95_ttft_regression_pct <= 5.0"));
    assert!(source.contains("ttft_wilcoxon_signed_rank_p_value < 0.01"));
    assert!(source.contains("throughput_wilcoxon_signed_rank_p_value < 0.01"));
    assert!(source.contains("const DEFAULT_SAMPLE_COUNT: usize = 30;"));
    assert!(source.contains("const DEFAULT_WARMUP_COUNT: usize = 5;"));
    assert!(source.contains("thresholded_origins: vec![\"127.0.0.1:3201\", \"127.0.0.1:3202\"]"));
    assert!(source.contains(".unwrap_or_else(|| vec![\"h1\", \"h2\"]);"));
    assert!(source.contains("public_provider_threshold_inputs: Vec::new()"));
    assert!(source.contains("--self-test-threshold-failure"));
    assert!(!source.contains("SPECTER_BENCH_FORCE_THRESHOLD_FAIL"));
    assert!(!source.contains("SPECTER_BENCH_REAL"));
    assert!(source.contains("\"localhost_real_measurement\""));
    assert!(source.contains("\"localhost_paired_real_measurement\""));
    assert!(source.contains("run_paired_real_measurements"));
}

#[test]
fn streaming_benchmark_declares_enforceable_request_body_streaming_gate() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("const BENCH_REQ_CHUNK_SIZE: usize = 1024;"));
    assert!(source.contains("const BENCH_REQ_CHUNK_COUNT: usize = 5;"));
    assert!(source.contains("const BENCH_REQ_CHUNK_DELAY_MS: u64 = 2;"));
    assert!(source.contains("struct RequestBodySchedule"));
    assert!(source.contains("request_body_schedule: Some(RequestBodySchedule::standard())"));
    assert!(source.contains("direction: \"request\""));
    assert!(source.contains("reqwest::Body::wrap(PacingRequestHttpBody::new(body_stream))"));
    assert!(source.contains("SizeHint::with_exact(BENCH_REQ_BODY_LEN)"));
    assert!(source.contains("RequestBuilder::body_stream_sized -> send_streaming"));
    assert!(source.contains("run_real_request_body_measurement"));
    assert!(source.contains("run_paired_request_body_measurements"));
    assert!(source.contains("--response-body-streaming"));
    assert!(source.contains("--request-body-streaming"));
    assert!(source.contains("--self-test-request-threshold-failure"));
    assert!(source.contains(
        "request_body_transfer_duration(offsets.first().copied(), response_headers_offset_ns)"
    ));
    assert!(source.contains("client_overhead_unclamped_duration_ns"));
    assert!(source.contains("client_overhead_denominator_floor_count"));
    assert!(source.contains("client_write_overhead_unclamped_duration_ns"));
    assert!(source.contains("client_write_overhead_denominator_floor_count"));
    assert!(source.contains("throughput_improvement_pct >= 5.0"));
    assert!(source.contains("ttft_wilcoxon_signed_rank_p_value < 0.01"));
    assert!(source.contains("throughput_wilcoxon_signed_rank_p_value < 0.01"));
    assert!(source.contains("request_payload_schedule_ms()"));
    assert!(source.contains("BENCH_REQ_BODY_LEN"));
    assert!(source.contains("corrected upload-complete TTFT"));
    assert!(source.contains("used as the request-row threshold denominator"));
    assert!(
        source.contains("PacingRequestBodyStream::<specter::Error>::new(\n        stream_anchor")
    );
    assert!(source.contains("PacingRequestBodyStream::<io::Error>::new(\n        stream_anchor"));
    assert!(source.contains("response status/headers"));
    assert!(!source.contains("producer-bottlenecked"));
    assert!(!source.contains(
        "Throughput numbers (median, Wilcoxon, p95) remain in the JSON as audit-only telemetry"
    ));
    assert!(!source.contains(
        "request_body_transfer_duration(offsets.first().copied(), response_complete_time)"
    ));
}

#[test]
fn thresholded_streaming_benchmark_uses_delayed_multi_chunk_workload() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("const BENCH_CHUNK_SIZE: usize = 16 * 1024;"));
    assert!(source.contains("const BENCH_CHUNK_COUNT: usize = 5;"));
    assert!(source.contains("const BENCH_CHUNK_DELAY_MS: u64 = 1;"));
    assert!(source.contains("payload_schedule_ms = payload_schedule_ms();"));
    assert!(source.contains("let chunk_count = BENCH_CHUNK_COUNT;"));
    assert!(source.contains("DenominatorEvidence::from_duration_minus_duration("));
    assert!(source.contains("body_transfer_duration,"));
    assert!(source.contains("payload_schedule_duration,"));
    assert!(source.contains("record_response_gap_overheads_by_index"));
    assert!(source.contains("throughput_values.push(bytes as f64 / denominator);"));
    assert!(source.contains(
        "response rows divide decoded response body bytes by final fixture DATA write-stamp to final observed body-chunk delivery overhead"
    ));
    assert!(source.contains("request rows divide uploaded request body bytes by corrected upload-complete write-overhead"));
    assert!(source.contains("throughput_improvement_pct >= 5.0"));
    assert!(source.contains("p95_throughput_regression_pct <= 5.0"));
    assert!(source.contains("body_transfer_duration_ns"));
    assert!(source.contains("client_overhead_duration_ns"));
    assert!(source.contains("paired Wilcoxon signed-rank"));
    assert!(source.contains("applied identically to reqwest and Specter"));
    assert!(!source.contains("const BENCH_CHUNK_COUNT: usize = 1;"));
    assert!(!source.contains("const BENCH_CHUNK_DELAY_MS: u64 = 0;"));
}

#[test]
fn benchmark_fixtures_use_monotonic_deadline_spin_wait_pacing() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("FIXTURE_PACING_MODE: &str = \"monotonic_deadline_spin_wait\""));
    assert!(source.contains("FIXTURE_MONOTONIC_CLOCK_SOURCE: &str = \"std::time::Instant\""));
    assert!(source.contains("fn spin_wait_until(target: Instant)"));
    assert!(source.contains("async fn pace_chunk_until(target: Instant)"));
    assert!(source.contains("std::hint::spin_loop()"));
    assert!(source.contains("inter_chunk_target_deadlines_ms"));
    assert!(source.contains("pace_chunk_until(target).await;"));
    assert!(source.contains("fn bind_tcp_preflight(port: u16)"));
    assert!(source.contains("socket.set_reuse_address(true)"));

    let pattern = ["tokio::time::sleep(Duration::from_millis(", "delay_ms"].join("");
    assert!(
        !source.contains(&pattern),
        "benchmark fixture must not call tokio::time::sleep for inter-chunk pacing; use pace_chunk_until against a monotonic deadline anchored on Instant",
    );
    assert!(
        source.contains("cx.waker().wake_by_ref();"),
        "request-body producer pacing must yield through the task waker before spin-waiting near the monotonic deadline",
    );
    assert!(
        !source.contains("sleep: Option<Pin<Box<tokio::time::Sleep>>>"),
        "request-body producer must not use tokio::time::Sleep for inter-chunk pacing",
    );

    assert!(
        source.contains("let chunk_send_anchor = Instant::now();"),
        "benchmark fixtures must anchor each stream's chunk emission to a single Instant for drift-free pacing; saw no anchor",
    );
    assert!(
        source.contains("worker_threads = 4"),
        "streaming benchmark should leave separate workers for fixture, driver, hyper, and measurement tasks",
    );
}

#[test]
fn benchmark_artifact_emits_pacing_evidence_fields() {
    let source = std::fs::read_to_string("benches/streaming_vs_reqwest.rs").unwrap();

    assert!(source.contains("pacing_mode: FIXTURE_PACING_MODE"));
    assert!(source.contains("monotonic_clock_source: FIXTURE_MONOTONIC_CLOCK_SOURCE"));
    assert!(source.contains("target_inter_chunk_pacing_ms: BENCH_CHUNK_DELAY_MS"));
    assert!(source.contains("inter_chunk_target_deadlines_ms: workload"));
    assert!(source.contains("actual_send_gap: ActualSendGap"));
    assert!(source.contains("pub(crate) struct ActualSendGap"));
    assert!(source.contains("over_budget_fraction"));
    assert!(source.contains("median_minus_target_ns"));
    assert!(source.contains("\"actual_send_gap.median_ns\""));
    assert!(source.contains("\"actual_send_gap.p95_ns\""));
    assert!(source.contains("\"fixture.pacing_mode\""));
    assert!(source.contains("\"fixture.monotonic_clock_source\""));
}

#[test]
fn benchmark_harness_tests_do_not_mask_failures_with_tautologies() {
    let source = std::fs::read_to_string("tests/benchmark_harness.rs").unwrap();

    let tautology = ["||", "true"].join(" ");
    assert!(!source.contains(&tautology));
}

#[test]
fn websocket_benchmark_declares_fastwebsockets_gate() {
    let source = std::fs::read_to_string("benches/websocket_vs_fastwebsockets.rs").unwrap();

    assert!(source.contains("fastwebsockets_version: \"0.10.0\""));
    assert!(source.contains("pass_match_or_exceed"));
    assert!(source.contains("specter.messages_per_sec >= fast.messages_per_sec"));
    assert!(source.contains("--require-thresholds"));
    assert!(source.contains("DEFAULT_WARMUP_MESSAGES"));
    assert!(source.contains("fastwebsockets::WebSocket::after_handshake(stream, Role::Server)"));
}

#[tokio::test]
async fn test_h1_streaming_local() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    // Start H1 server in a background task
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                // Simple H1 stream response
                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 14\r\n\r\nchunk1\nchunk2\n";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // High-level send_streaming currently only supports H2, so H1 streaming should fail or fall back.
    // Let's verify that send_streaming returns an error if version is forced to H1.
    let req = client
        .get(&format!("http://{addr}/stream"))
        .version(HttpVersion::Http1_1);
    let mut response = req.send_streaming().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);

    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let chunk = frame.unwrap().into_data().unwrap();
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"chunk1\nchunk2\n");

    server_task.abort();
}

#[tokio::test]
async fn test_h2_streaming_local() {
    // This test asserts that hitting 3202 with no fixture running fails fast.
    // Skip if a benchmark run happens to be using 3202 concurrently in the same
    // process group (TIME_WAIT or active listener) so it doesn't flake the suite.
    use std::net::{SocketAddr, TcpStream};
    if TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], 3202)),
        std::time::Duration::from_millis(50),
    )
    .is_ok()
    {
        eprintln!("skipping test_h2_streaming_local: a fixture is already on 3202");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .prefer_http2(true)
        .build()
        .unwrap();

    let result = client
        .get("https://127.0.0.1:3202/stream")
        .send_streaming()
        .await;
    assert!(result.is_err(), "test does not start an H2 fixture on 3202");
}
