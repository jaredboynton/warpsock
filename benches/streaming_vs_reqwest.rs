use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use quiche::h3::NameValue;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket as TokioUdpSocket};
use tokio::sync::mpsc;

const H1_PORT: u16 = 3201;
const H2_PORT: u16 = 3202;
const H3_PORT: u16 = 3203;
const RFC8441_PORT: u16 = 3204;
const BENCH_CHUNK_SIZE: usize = 16 * 1024;
const BENCH_CHUNK_COUNT: usize = 5;
const BENCH_CHUNK_DELAY_MS: u64 = 1;
const BENCH_REQUEST_COUNT: usize = 8;
const DEFAULT_WARMUP_COUNT: usize = 5;
const DEFAULT_SAMPLE_COUNT: usize = 30;

const FIXTURE_PACING_MODE: &str = "monotonic_deadline_spin_wait";
const FIXTURE_MONOTONIC_CLOCK_SOURCE: &str = "std::time::Instant";
const PACING_SPIN_LEAD_IN: Duration = Duration::from_micros(150);

#[inline]
pub(crate) fn spin_wait_until(target: Instant) {
    while Instant::now() < target {
        std::hint::spin_loop();
    }
}

#[inline]
pub(crate) async fn pace_chunk_until(target: Instant) {
    while target.saturating_duration_since(Instant::now()) > PACING_SPIN_LEAD_IN {
        tokio::task::yield_now().await;
    }
    spin_wait_until(target);
}

#[inline]
pub(crate) fn inter_chunk_target_deadlines_ms(delay_ms: u64, chunk_count: usize) -> Vec<u64> {
    (1..chunk_count)
        .map(|i| delay_ms.saturating_mul(i as u64))
        .collect()
}

#[derive(Serialize)]
struct Rfc8441CoexistenceResult {
    concurrency_level: usize,
    tunnel_stream_id: u32,
    streaming_stream_id: u32,
    messages_sent: Vec<String>,
    messages_received: Vec<String>,
    chunks_received: Vec<String>,
    contamination_detected: bool,
    status: &'static str,
}

#[derive(Serialize)]
struct Artifact {
    benchmark: &'static str,
    benchmark_version: &'static str,
    environment: Environment,
    git: Git,
    fixture_config: FixtureConfig,
    workload: Workload,
    measurement_config: MeasurementConfig,
    metric_definitions: BTreeMap<&'static str, &'static str>,
    rows: Vec<Row>,
    rfc8441_coexistence: Rfc8441CoexistenceResult,
    h3_gate: H3Gate,
    threshold_summary: ThresholdSummary,
    public_provider_threshold_inputs: Vec<String>,
    port_preflight: PortCheck,
    cleanup: Cleanup,
}

#[derive(Serialize)]
struct Environment {
    os: String,
    arch: String,
    cpu_count: usize,
    memory: String,
    rustc: String,
    crate_versions: BTreeMap<&'static str, &'static str>,
}

#[derive(Serialize)]
struct Git {
    commit_sha: String,
    dirty_state_classification: String,
    release_evidence_eligible: bool,
}

#[derive(Serialize)]
struct FixtureConfig {
    fixtures: Vec<Fixture>,
    deterministic_payload_schedule: Vec<u64>,
    pacing_mode: &'static str,
    monotonic_clock_source: &'static str,
    inter_chunk_target_deadlines_ms: Vec<u64>,
    target_inter_chunk_pacing_ms: u64,
    pacing_implementation: &'static str,
}

#[derive(Serialize)]
struct Fixture {
    protocol: &'static str,
    address: String,
    health: &'static str,
    origin_classification: &'static str,
}

#[derive(Serialize)]
struct Workload {
    request_count: usize,
    concurrency_levels: Vec<usize>,
    chunk_size: usize,
    chunk_count: usize,
    payload_schedule_ms: Vec<u64>,
    inter_chunk_target_deadlines_ms: Vec<u64>,
    pacing_mode: &'static str,
    monotonic_clock_source: &'static str,
    tokio_runtime: &'static str,
    pools: &'static str,
}

#[derive(Serialize)]
struct MeasurementConfig {
    warmup_count: usize,
    sample_count: usize,
    thresholded_origins: Vec<&'static str>,
    comparable_clients_share_workload: bool,
    throughput_timing_window: &'static str,
}

#[derive(Serialize)]
struct Row {
    protocol: &'static str,
    client: &'static str,
    endpoint: String,
    comparable: bool,
    comparison_mode: &'static str,
    skip_reason: Option<&'static str>,
    measurement_source: &'static str,
    client_config: ClientConfig,
    metrics: Metrics,
    threshold: Threshold,
    specter_api_path: Option<&'static str>,
    protocol_selected_by_normal_dispatch: bool,
    pool_reuse_metadata: PoolReuse,
}

#[derive(Serialize)]
struct ClientConfig {
    runtime: &'static str,
    payload_schedule_ms: Vec<u64>,
    chunk_size: usize,
    request_count: usize,
    concurrency: usize,
    warmup_count: usize,
    sample_count: usize,
    decompression: &'static str,
    byte_accounting: &'static str,
}

#[derive(Serialize, Clone)]
pub(crate) struct Metrics {
    pub(crate) ttft_ns: f64,
    pub(crate) chunks_per_sec: f64,
    pub(crate) bytes_per_sec: f64,
    pub(crate) p95_bytes_per_sec: f64,
    pub(crate) body_transfer_duration_ns: f64,
    pub(crate) client_overhead_duration_ns: f64,
    pub(crate) p50_ns: f64,
    pub(crate) p95_ns: f64,
    pub(crate) p99_ns: f64,
    pub(crate) warmup_count: usize,
    pub(crate) sample_count: usize,
    pub(crate) connection_reuse_count: usize,
    pub(crate) pass: bool,
    pub(crate) actual_send_gap: ActualSendGap,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ttft_samples_ns: Vec<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) bytes_per_sec_samples: Vec<f64>,
}

#[derive(Serialize, Clone, Default)]
pub(crate) struct ActualSendGap {
    pub(crate) target_ms: u64,
    pub(crate) sample_count: usize,
    pub(crate) median_ns: f64,
    pub(crate) p95_ns: f64,
    pub(crate) min_ns: f64,
    pub(crate) max_ns: f64,
    pub(crate) median_minus_target_ns: f64,
    pub(crate) p95_minus_target_ns: f64,
    pub(crate) over_budget_fraction: f64,
    pub(crate) measurement_source: &'static str,
}

impl ActualSendGap {
    pub(crate) fn empty() -> Self {
        Self {
            target_ms: BENCH_CHUNK_DELAY_MS,
            sample_count: 0,
            median_ns: 0.0,
            p95_ns: 0.0,
            min_ns: 0.0,
            max_ns: 0.0,
            median_minus_target_ns: 0.0,
            p95_minus_target_ns: 0.0,
            over_budget_fraction: 0.0,
            measurement_source:
                "client_observed_inter_chunk_receive_gap_using_std_time_instant_monotonic_clock",
        }
    }
}

pub(crate) fn summarize_send_gaps(samples_ns: &[f64], target_ms: u64) -> ActualSendGap {
    if samples_ns.is_empty() {
        return ActualSendGap::empty();
    }
    let mut sorted = samples_ns.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let len = sorted.len();
    let median = sorted[len / 2];
    let p95_idx = ((len as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(len - 1);
    let p95 = sorted[p95_idx];
    let min = *sorted.first().unwrap();
    let max = *sorted.last().unwrap();
    let target_ns = (target_ms as f64) * 1_000_000.0;
    let max_budget_ns = target_ns + 500_000.0;
    let over_budget = sorted.iter().filter(|gap| **gap > max_budget_ns).count();

    ActualSendGap {
        target_ms,
        sample_count: len,
        median_ns: median,
        p95_ns: p95,
        min_ns: min,
        max_ns: max,
        median_minus_target_ns: median - target_ns,
        p95_minus_target_ns: p95 - target_ns,
        over_budget_fraction: over_budget as f64 / len as f64,
        measurement_source:
            "client_observed_inter_chunk_receive_gap_using_std_time_instant_monotonic_clock",
    }
}

impl Metrics {
    fn failed(warmup_count: usize, sample_count: usize) -> Self {
        Self {
            ttft_ns: 0.0,
            chunks_per_sec: 0.0,
            bytes_per_sec: 0.0,
            p95_bytes_per_sec: 0.0,
            body_transfer_duration_ns: 0.0,
            client_overhead_duration_ns: 0.0,
            p50_ns: 0.0,
            p95_ns: 0.0,
            p99_ns: 0.0,
            warmup_count,
            sample_count,
            connection_reuse_count: 0,
            pass: false,
            actual_send_gap: ActualSendGap::empty(),
            ttft_samples_ns: Vec::new(),
            bytes_per_sec_samples: Vec::new(),
        }
    }

    fn not_applicable(warmup_count: usize, sample_count: usize) -> Self {
        Self {
            ttft_ns: 0.0,
            chunks_per_sec: 0.0,
            bytes_per_sec: 0.0,
            p95_bytes_per_sec: 0.0,
            body_transfer_duration_ns: 0.0,
            client_overhead_duration_ns: 0.0,
            p50_ns: 0.0,
            p95_ns: 0.0,
            p99_ns: 0.0,
            warmup_count,
            sample_count,
            connection_reuse_count: 0,
            pass: true,
            actual_send_gap: ActualSendGap::empty(),
            ttft_samples_ns: Vec::new(),
            bytes_per_sec_samples: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct Threshold {
    required: bool,
    ttft_improvement_required_pct: f64,
    throughput_improvement_required_pct: f64,
    throughput_regression_allowed_pct: f64,
    p95_regression_allowed_pct: f64,
    wilcoxon_p_value_required_less_than: f64,
    reqwest_median_ttft_ns: Option<f64>,
    specter_median_ttft_ns: Option<f64>,
    ttft_improvement_pct: Option<f64>,
    ttft_wilcoxon_signed_rank_p_value: Option<f64>,
    reqwest_median_bytes_per_sec: Option<f64>,
    specter_median_bytes_per_sec: Option<f64>,
    throughput_improvement_pct: Option<f64>,
    throughput_wilcoxon_signed_rank_p_value: Option<f64>,
    median_throughput_regression_pct: Option<f64>,
    reqwest_p95_bytes_per_sec: Option<f64>,
    specter_p95_bytes_per_sec: Option<f64>,
    p95_throughput_regression_pct: Option<f64>,
    reqwest_p95_ttft_ns: Option<f64>,
    specter_p95_ttft_ns: Option<f64>,
    p95_ttft_regression_pct: Option<f64>,
    status: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct PoolReuse {
    connection_reuse_count: usize,
    cold_or_warm_pool: &'static str,
}

#[derive(Serialize)]
struct ThresholdSummary {
    required_thresholds_passed: bool,
    failed_rows: Vec<String>,
    negative_threshold_self_check: &'static str,
}

#[derive(Serialize)]
struct H3Gate {
    fixture_address: &'static str,
    comparison_mode: &'static str,
    reqwest_comparison_available: bool,
    reqwest_unavailable_reason: &'static str,
    specter_thresholds: H3RegressionThresholds,
    specter_metrics: Metrics,
    pass: bool,
    status: &'static str,
}

#[derive(Serialize)]
struct H3RegressionThresholds {
    max_median_ttft_p50_ns: f64,
    min_median_bytes_per_sec: f64,
    min_median_chunks_per_sec: f64,
    min_connection_reuse_count: usize,
}

impl H3RegressionThresholds {
    /// Single source of truth for the H3 regression gate thresholds.
    /// Used both for evaluating per-row pass/fail and for emitting the
    /// `h3_gate.specter_thresholds` JSON section so the two cannot drift.
    fn default_specter_gate() -> Self {
        Self {
            max_median_ttft_p50_ns: 2_000_000.0,
            min_median_bytes_per_sec: 30_000.0,
            min_median_chunks_per_sec: 2_000.0,
            min_connection_reuse_count: 1,
        }
    }

    /// Evaluate a metrics row against the configured H3 regression gate.
    /// The TTFT check runs against `metrics.p50_ns` to match the
    /// `max_median_ttft_p50_ns` field name.
    fn evaluate(&self, metrics: &Metrics) -> bool {
        metrics.p50_ns <= self.max_median_ttft_p50_ns
            && metrics.bytes_per_sec >= self.min_median_bytes_per_sec
            && metrics.chunks_per_sec >= self.min_median_chunks_per_sec
            && metrics.connection_reuse_count >= self.min_connection_reuse_count
    }
}

#[derive(Serialize)]
struct PortCheck {
    checked_range: &'static str,
    tcp_ports_clear_before_start: bool,
    udp_ports_clear_before_start: bool,
}

#[derive(Serialize)]
struct Cleanup {
    fixture_shutdown_status: &'static str,
    post_run_tcp_scan_clear: bool,
    post_run_udp_scan_clear: bool,
}

#[derive(Clone)]
struct BenchmarkOptions {
    require_thresholds: bool,
    json_path: PathBuf,
    protocols: Vec<&'static str>,
    warmup_count: usize,
    sample_count: usize,
    concurrency_levels: Vec<usize>,
    force_comparable_threshold_failure: bool,
    force_h3_threshold_failure: bool,
}

pub(crate) struct ComparableThresholdResult {
    pub(crate) pass: bool,
    pub(crate) ttft_improvement_pct: f64,
    pub(crate) throughput_improvement_pct: f64,
    pub(crate) median_throughput_regression_pct: f64,
    pub(crate) p95_throughput_regression_pct: f64,
    pub(crate) p95_ttft_regression_pct: f64,
    pub(crate) ttft_wilcoxon_signed_rank_p_value: f64,
    pub(crate) throughput_wilcoxon_signed_rank_p_value: f64,
}

struct Fixtures {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn generate_certs_openssl() -> (String, String) {
    let cert_path = std::env::temp_dir().join("specter_fixtures.crt");
    let key_path = std::env::temp_dir().join("specter_fixtures.key");

    let _ = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .output();

    (
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
    )
}

fn create_ssl_acceptor(cert_path: &str, key_path: &str) -> SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .expect("Failed to create SslAcceptor builder");
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .expect("Failed to set private key file");
    builder
        .set_certificate_chain_file(cert_path)
        .expect("Failed to set certificate chain file");
    builder
}

struct H2Conn<S> {
    stream: S,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> H2Conn<S> {
    async fn read_preface(&mut self) -> std::io::Result<()> {
        let mut preface = [0u8; 24];
        self.stream.read_exact(&mut preface).await?;
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        Ok(())
    }

    async fn read_frame(&mut self) -> std::io::Result<(u32, u8, u8, u32, Vec<u8>)> {
        let mut header = [0u8; 9];
        self.stream.read_exact(&mut header).await?;
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5] & 0x7F, header[6], header[7], header[8]]);
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            self.stream.read_exact(&mut payload).await?;
        }
        Ok((len, frame_type, flags, stream_id, payload))
    }

    async fn send_frame(
        &mut self,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let len = payload.len() as u32;
        let mut header = [0u8; 9];
        header[0] = ((len >> 16) & 0xFF) as u8;
        header[1] = ((len >> 8) & 0xFF) as u8;
        header[2] = (len & 0xFF) as u8;
        header[3] = frame_type;
        header[4] = flags;
        let id_bytes = (stream_id & 0x7FFFFFFF).to_be_bytes();
        header[5..9].copy_from_slice(&id_bytes);

        self.stream.write_all(&header).await?;
        if len > 0 {
            self.stream.write_all(payload).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }
}

async fn handle_h1_connection(mut stream: tokio::net::TcpStream) {
    let mut buf = [0u8; 4096];
    let mut read_bytes = 0;

    loop {
        match stream.read(&mut buf[read_bytes..]).await {
            Ok(0) => break,
            Ok(n) => {
                read_bytes += n;
                let mut headers = [httparse::Header {
                    name: "",
                    value: &[],
                }; 64];
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&buf[..read_bytes]) {
                    Ok(httparse::Status::Complete(amt)) => {
                        let path = req.path.unwrap_or("/");
                        let mut keep_alive = false;
                        for h in req.headers.iter() {
                            if h.name.eq_ignore_ascii_case("connection")
                                && std::str::from_utf8(h.value)
                                    .unwrap_or("")
                                    .to_lowercase()
                                    .contains("keep-alive")
                            {
                                keep_alive = true;
                            }
                        }

                        if path == "/health" {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\nok";
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                break;
                            }
                        } else if path.starts_with("/stream") {
                            let chunk_size = BENCH_CHUNK_SIZE;
                            let chunk_count = BENCH_CHUNK_COUNT;
                            let delay_ms = BENCH_CHUNK_DELAY_MS;
                            let total_size = chunk_size * chunk_count;

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: {}\r\nContent-Length: {}\r\n\r\n",
                                if keep_alive { "keep-alive" } else { "close" },
                                total_size
                            );

                            if stream.write_all(response.as_bytes()).await.is_err() {
                                break;
                            }

                            let chunk_data = vec![b'a'; chunk_size];
                            let chunk_send_anchor = Instant::now();
                            for i in 0..chunk_count {
                                if i > 0 {
                                    let target = chunk_send_anchor
                                        + Duration::from_millis(delay_ms.saturating_mul(i as u64));
                                    pace_chunk_until(target).await;
                                }
                                if stream.write_all(&chunk_data).await.is_err() {
                                    break;
                                }
                                if stream.flush().await.is_err() {
                                    break;
                                }
                            }
                        } else {
                            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            break;
                        }

                        if !keep_alive {
                            break;
                        }

                        buf.copy_within(amt..read_bytes, 0);
                        read_bytes -= amt;
                    }
                    Ok(httparse::Status::Partial) => {
                        if read_bytes >= buf.len() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }
}

async fn handle_h2_connection<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
) {
    let mut conn = H2Conn { stream };
    if conn.read_preface().await.is_err() {
        return;
    }

    let mut settings_sent = false;
    let mut decoder = specter::transport::h2::HpackDecoder::new();
    let (tx, mut rx) = mpsc::channel::<(u8, u8, u32, Vec<u8>)>(100);

    loop {
        tokio::select! {
            frame = conn.read_frame() => {
                let Ok((_len, frame_type, flags, stream_id, payload)) = frame else {
                    break;
                };

                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            let settings_payload = vec![
                                0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                                0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
                            ];
                            let _ = tx.send((0x04, 0x00, 0, settings_payload)).await;
                            let _ = tx.send((0x04, 0x01, 0, vec![])).await;
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload);
                        let headers = decoded.unwrap_or_default();

                        let mut path = "/";
                        let mut method = "GET";
                        let mut is_websocket = false;

                        for (name, value) in headers.iter() {
                            if name == ":path" {
                                path = value;
                            } else if name == ":method" {
                                method = value;
                            } else if name == ":protocol" && value == "websocket" {
                                is_websocket = true;
                            }
                        }

                        if method == "CONNECT" && is_websocket {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;
                            });
                        } else if path == "/health" {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;
                                let _ = tx_clone.send((0x00, 0x01, stream_id, b"ok".to_vec())).await;
                            });
                        } else if path.starts_with("/stream") {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;

                                let chunk_size = BENCH_CHUNK_SIZE;
                                let chunk_count = BENCH_CHUNK_COUNT;
                                let delay_ms = BENCH_CHUNK_DELAY_MS;
                                let chunk_data = vec![b's'; chunk_size];
                                let chunk_send_anchor = Instant::now();

                                for i in 0..chunk_count {
                                    if i > 0 {
                                        let target = chunk_send_anchor
                                            + Duration::from_millis(
                                                delay_ms.saturating_mul(i as u64),
                                            );
                                        pace_chunk_until(target).await;
                                    }
                                    let end_stream = i == chunk_count - 1;
                                    let _ = tx_clone.send((0x00, if end_stream { 0x01 } else { 0x00 }, stream_id, chunk_data.clone())).await;
                                }
                            });
                        }
                    }
                    0x00 => {
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx_clone.send((0x00, flags, stream_id, payload)).await;
                        });
                    }
                    _ => {}
                }
            }
            Some((frame_type, flags, stream_id, payload)) = rx.recv() => {
                if conn.send_frame(frame_type, flags, stream_id, &payload).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn start_h1_server(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(handle_h1_connection(stream));
        }
    })
}

async fn start_h2_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
) -> tokio::task::JoinHandle<()> {
    let mut builder = create_ssl_acceptor(cert_path, key_path);
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            let acceptor_clone = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = tokio_boring::accept(&acceptor_clone, stream).await {
                    handle_h2_connection(tls_stream).await;
                }
            });
        }
    })
}

async fn start_h3_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
) -> tokio::task::JoinHandle<()> {
    let socket = Arc::new(
        TokioUdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap(),
    );
    let cert_path = cert_path.to_string();
    let key_path = key_path.to_string();

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        let mut connections: HashMap<
            quiche::ConnectionId<'static>,
            mpsc::Sender<(Vec<u8>, SocketAddr)>,
        > = HashMap::new();
        let local_addr = socket.local_addr().unwrap();

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let packet = buf[..len].to_vec();

            let header = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
            {
                Ok(h) => h,
                Err(_) if connections.len() == 1 => {
                    if let Some(tx) = connections.values().next() {
                        let _ = tx.send((packet, peer)).await;
                    }
                    continue;
                }
                Err(_) => continue,
            };

            let conn_id = header.dcid.clone();

            if !connections.contains_key(&conn_id) {
                if header.ty != quiche::Type::Initial {
                    if connections.len() == 1 {
                        if let Some(tx) = connections.values().next() {
                            let _ = tx.send((packet, peer)).await;
                        }
                    }
                    continue;
                }

                let scid = header.dcid.into_owned();
                let (tx, mut rx) = mpsc::channel(100);
                connections.insert(scid.clone(), tx.clone());

                let socket_clone = socket.clone();
                let cert_path_clone = cert_path.clone();
                let key_path_clone = key_path.clone();
                let scid_clone = scid.clone();
                let odcid = scid.clone();

                tokio::spawn(async move {
                    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
                    config
                        .load_cert_chain_from_pem_file(&cert_path_clone)
                        .unwrap();
                    config.load_priv_key_from_pem_file(&key_path_clone).unwrap();
                    config.set_application_protos(&[b"h3"]).unwrap();
                    config.set_max_idle_timeout(30_000);
                    config.set_max_recv_udp_payload_size(65535);
                    config.set_max_send_udp_payload_size(1350);
                    config.set_initial_max_data(10_000_000);
                    config.set_initial_max_stream_data_bidi_local(1_000_000);
                    config.set_initial_max_stream_data_bidi_remote(1_000_000);
                    config.set_initial_max_stream_data_uni(1_000_000);
                    config.set_initial_max_streams_bidi(100);
                    config.set_initial_max_streams_uni(100);
                    config.set_disable_active_migration(true);

                    let mut conn =
                        quiche::accept(&scid_clone, Some(&odcid), local_addr, peer, &mut config)
                            .unwrap();
                    let mut h3_conn: Option<quiche::h3::Connection> = None;
                    let mut out = [0u8; 65535];
                    let mut interval = tokio::time::interval(Duration::from_millis(10));

                    loop {
                        tokio::select! {
                            res = rx.recv() => {
                                match res {
                                    Some((packet, from)) => {
                                        let recv_info = quiche::RecvInfo {
                                            to: socket_clone.local_addr().unwrap(),
                                            from,
                                        };
                                        if conn.recv(&mut packet.clone(), recv_info).is_ok() {
                                            if conn.is_established() && h3_conn.is_none() {
                                                let h3_config = quiche::h3::Config::new().unwrap();
                                                if let Ok(h3) = quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                                                    h3_conn = Some(h3);
                                                }
                                            }

                                            if conn.is_established() {
                                                if let Some(h3) = h3_conn.as_mut() {
                                                    loop {
                                                        match h3.poll(&mut conn) {
                                                            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                                                let mut path = "/";
                                                                for header in list.iter() {
                                                                    if header.name() == b":path" {
                                                                        path = std::str::from_utf8(header.value()).unwrap_or("/");
                                                                    }
                                                                }

                                                                if path == "/health" {
                                                                    let h3_headers = vec![
                                                                        quiche::h3::Header::new(b":status", b"200"),
                                                                        quiche::h3::Header::new(b"content-type", b"text/plain"),
                                                                    ];
                                                                    let _ = h3.send_response(&mut conn, stream_id, &h3_headers, false);
                                                                    let _ = h3.send_body(&mut conn, stream_id, b"ok", true);
                                                                } else if path.starts_with("/stream") {
                                                                    let h3_headers = vec![
                                                                        quiche::h3::Header::new(b":status", b"200"),
                                                                        quiche::h3::Header::new(b"content-type", b"application/octet-stream"),
                                                                    ];
                                                                    let _ = h3.send_response(&mut conn, stream_id, &h3_headers, false);

                                                                    let chunk_size = BENCH_CHUNK_SIZE;
                                                                    let chunk_count = BENCH_CHUNK_COUNT;
                                                                    let delay_ms = BENCH_CHUNK_DELAY_MS;
                                                                    let chunk_data = vec![b's'; chunk_size];
                                                                    let chunk_send_anchor = Instant::now();

                                                                    for i in 0..chunk_count {
                                                                        if i > 0 {
                                                                            let target = chunk_send_anchor
                                                                                + Duration::from_millis(
                                                                                    delay_ms.saturating_mul(i as u64),
                                                                                );
                                                                            pace_chunk_until(target).await;
                                                                        }
                                                                        let end_stream = i == chunk_count - 1;
                                                                        let _ = h3.send_body(&mut conn, stream_id, &chunk_data, end_stream);
                                                                    }
                                                                }
                                                            }
                                                            Err(quiche::h3::Error::Done) => break,
                                                            Err(_) => break,
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    None => break,
                                }
                            }
                            _ = interval.tick() => {
                                conn.on_timeout();
                            }
                        }

                        while let Ok((len, send_info)) = conn.send(&mut out) {
                            let _ = socket_clone.send_to(&out[..len], send_info.to).await;
                        }

                        if conn.is_closed() {
                            break;
                        }
                    }
                });
            }

            if let Some(tx) = connections.get(&conn_id) {
                let _ = tx.send((packet, peer)).await;
            } else if connections.len() == 1 {
                if let Some(tx) = connections.values().next() {
                    let _ = tx.send((packet, peer)).await;
                }
            }
        }
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let options = parse_options(&args);

    let preflight = preflight_ports()?;
    let fixtures = start_fixtures().await?;
    wait_for_health().await?;

    let artifact = build_artifact(preflight, &options).await?;
    if let Some(parent) = options.json_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.json_path, serde_json::to_vec_pretty(&artifact)?)?;
    println!("wrote benchmark artifact {}", options.json_path.display());

    drop(fixtures);
    tokio::time::sleep(Duration::from_millis(75)).await;

    if options.require_thresholds && !artifact.threshold_summary.required_thresholds_passed {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_options(args: &[String]) -> BenchmarkOptions {
    let json_path = option_value(args, "--json")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/bench-results/streaming-vs-reqwest.json"));
    let protocols = option_value(args, "--protocol")
        .map(|value| {
            value
                .split(',')
                .filter_map(|protocol| match protocol {
                    "h1" => Some("h1"),
                    "h2" => Some("h2"),
                    "h3" => Some("h3"),
                    "rfc8441" => Some("rfc8441"),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .filter(|protocols| !protocols.is_empty())
        .unwrap_or_else(|| vec!["h1", "h2"]);
    let warmup_count = option_value(args, "--warmups")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_WARMUP_COUNT);
    let sample_count = option_value(args, "--samples")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SAMPLE_COUNT);
    let concurrency_levels = option_value(args, "--concurrency")
        .map(|value| {
            value
                .split(',')
                .filter_map(|level| level.parse().ok())
                .collect::<Vec<_>>()
        })
        .filter(|levels| !levels.is_empty())
        .unwrap_or_else(|| vec![1, 8]);

    BenchmarkOptions {
        require_thresholds: args.iter().any(|arg| arg == "--require-thresholds"),
        json_path,
        protocols,
        warmup_count,
        sample_count,
        concurrency_levels,
        force_comparable_threshold_failure: args
            .iter()
            .any(|arg| arg == "--self-test-threshold-failure"),
        force_h3_threshold_failure: args
            .iter()
            .any(|arg| arg == "--self-test-h3-threshold-failure"),
    }
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn preflight_ports() -> io::Result<PortCheck> {
    for port in 3200..=3299 {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(listener) = StdTcpListener::bind(addr) {
            drop(listener);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("Port {} is already in use", port),
            ));
        }
    }
    if let Ok(udp) = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], H3_PORT))) {
        drop(udp);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "UDP Port 3203 is already in use",
        ));
    }
    Ok(PortCheck {
        checked_range: "127.0.0.1:3200-3299",
        tcp_ports_clear_before_start: true,
        udp_ports_clear_before_start: true,
    })
}

async fn start_fixtures() -> io::Result<Fixtures> {
    let (cert_path, key_path) = generate_certs_openssl();
    let mut tasks = Vec::new();

    tasks.push(start_h1_server(H1_PORT).await);
    tasks.push(start_h2_server(H2_PORT, &cert_path, &key_path).await);
    tasks.push(start_h3_server(H3_PORT, &cert_path, &key_path).await);
    tasks.push(start_h2_server(RFC8441_PORT, &cert_path, &key_path).await);

    Ok(Fixtures { tasks })
}

async fn wait_for_health() -> io::Result<()> {
    for port in [H1_PORT, H2_PORT, RFC8441_PORT] {
        let _stream =
            tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    }
    Ok(())
}

async fn measure_specter_streaming(
    protocol: &str,
    client: &specter::Client,
    url: &str,
) -> Result<(Duration, Duration, usize, usize, Vec<f64>), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let mut request = client.get(url);
    if protocol == "h3" {
        request = request.version(specter::HttpVersion::Http3Only);
    }
    let mut response = request.send_streaming().await?;

    let mut first_chunk_time = None;
    let mut last_chunk_time = None;
    let mut bytes_received = 0;
    let mut chunk_count = 0;
    let mut chunk_offsets_ns: Vec<f64> = Vec::with_capacity(BENCH_CHUNK_COUNT);

    while let Some(frame_res) = response.body_mut().frame().await {
        let elapsed = start.elapsed();
        if first_chunk_time.is_none() {
            first_chunk_time = Some(elapsed);
        }
        if let Ok(frame) = frame_res {
            if let Ok(chunk) = frame.into_data() {
                bytes_received += chunk.len();
                chunk_count += 1;
                last_chunk_time = Some(elapsed);
                chunk_offsets_ns.push(elapsed.as_nanos() as f64);
            }
        }
    }

    let ttft = first_chunk_time.unwrap_or_else(|| start.elapsed());
    let transfer_duration = body_transfer_duration(first_chunk_time, last_chunk_time);
    let gaps_ns = inter_chunk_gaps_ns(&chunk_offsets_ns);
    Ok((
        ttft,
        transfer_duration,
        bytes_received,
        chunk_count,
        gaps_ns,
    ))
}

async fn measure_reqwest_streaming(
    client: &reqwest::Client,
    url: &str,
) -> Result<(Duration, Duration, usize, usize, Vec<f64>), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let mut response = client.get(url).send().await?;
    let mut first_chunk_time = None;
    let mut last_chunk_time = None;
    let mut bytes_received = 0;
    let mut chunk_count = 0;
    let mut chunk_offsets_ns: Vec<f64> = Vec::with_capacity(BENCH_CHUNK_COUNT);

    while let Some(chunk) = response.chunk().await? {
        let elapsed = start.elapsed();
        if first_chunk_time.is_none() {
            first_chunk_time = Some(elapsed);
        }
        bytes_received += chunk.len();
        chunk_count += 1;
        last_chunk_time = Some(elapsed);
        chunk_offsets_ns.push(elapsed.as_nanos() as f64);
    }

    let ttft = first_chunk_time.unwrap_or_else(|| start.elapsed());
    let transfer_duration = body_transfer_duration(first_chunk_time, last_chunk_time);
    let gaps_ns = inter_chunk_gaps_ns(&chunk_offsets_ns);
    Ok((
        ttft,
        transfer_duration,
        bytes_received,
        chunk_count,
        gaps_ns,
    ))
}

pub(crate) fn inter_chunk_gaps_ns(chunk_offsets_ns: &[f64]) -> Vec<f64> {
    if chunk_offsets_ns.len() < 2 {
        return Vec::new();
    }
    chunk_offsets_ns
        .windows(2)
        .map(|window| (window[1] - window[0]).max(0.0))
        .collect()
}

pub(crate) fn body_transfer_duration(
    first_chunk_time: Option<Duration>,
    last_chunk_time: Option<Duration>,
) -> Duration {
    match (first_chunk_time, last_chunk_time) {
        (Some(first), Some(last)) => last.saturating_sub(first).max(Duration::from_nanos(1)),
        _ => Duration::from_nanos(1),
    }
}

pub(crate) fn corrected_client_overhead_duration(
    body_transfer_duration: Duration,
    payload_schedule_duration: Duration,
) -> Duration {
    body_transfer_duration
        .saturating_sub(payload_schedule_duration)
        .max(Duration::from_nanos(1))
}

fn payload_schedule_ms() -> Vec<u64> {
    let mut schedule = Vec::with_capacity(BENCH_CHUNK_COUNT);
    schedule.push(0);
    schedule.extend(std::iter::repeat_n(
        BENCH_CHUNK_DELAY_MS,
        BENCH_CHUNK_COUNT.saturating_sub(1),
    ));
    schedule
}

fn payload_schedule_duration(schedule_ms: &[u64], request_count: usize) -> Duration {
    let single_request_ms = schedule_ms.iter().copied().sum::<u64>();
    Duration::from_millis(single_request_ms.saturating_mul(request_count as u64))
}

async fn measure_specter_streaming_batch(
    protocol: &str,
    client: &specter::Client,
    url: &str,
    request_count: usize,
) -> Result<(Duration, Duration, usize, usize, Vec<f64>), Box<dyn std::error::Error>> {
    let mut ttft_values = Vec::with_capacity(request_count);
    let mut transfer_duration = Duration::ZERO;
    let mut bytes_received = 0;
    let mut chunk_count = 0;
    let mut all_gaps_ns: Vec<f64> = Vec::with_capacity(request_count * BENCH_CHUNK_COUNT);

    for _ in 0..request_count {
        let (ttft, request_duration, bytes, chunks, gaps_ns) =
            measure_specter_streaming(protocol, client, url).await?;
        ttft_values.push(ttft.as_nanos() as f64);
        transfer_duration += request_duration;
        bytes_received += bytes;
        chunk_count += chunks;
        all_gaps_ns.extend(gaps_ns);
    }

    let median_ttft_ns = calculate_median(ttft_values);
    let ttft = Duration::from_nanos(median_ttft_ns as u64);
    let total_duration = transfer_duration;
    Ok((
        ttft,
        total_duration,
        bytes_received,
        chunk_count,
        all_gaps_ns,
    ))
}

async fn measure_reqwest_streaming_batch(
    client: &reqwest::Client,
    url: &str,
    request_count: usize,
) -> Result<(Duration, Duration, usize, usize, Vec<f64>), Box<dyn std::error::Error>> {
    let mut ttft_values = Vec::with_capacity(request_count);
    let mut transfer_duration = Duration::ZERO;
    let mut bytes_received = 0;
    let mut chunk_count = 0;
    let mut all_gaps_ns: Vec<f64> = Vec::with_capacity(request_count * BENCH_CHUNK_COUNT);

    for _ in 0..request_count {
        let (ttft, request_duration, bytes, chunks, gaps_ns) =
            measure_reqwest_streaming(client, url).await?;
        ttft_values.push(ttft.as_nanos() as f64);
        transfer_duration += request_duration;
        bytes_received += bytes;
        chunk_count += chunks;
        all_gaps_ns.extend(gaps_ns);
    }

    let median_ttft_ns = calculate_median(ttft_values);
    let ttft = Duration::from_nanos(median_ttft_ns as u64);
    let total_duration = transfer_duration;
    Ok((
        ttft,
        total_duration,
        bytes_received,
        chunk_count,
        all_gaps_ns,
    ))
}

fn calculate_percentiles(mut values: Vec<f64>) -> (f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let len = values.len();

    let p50_idx = ((len as f64 * 0.5).ceil() as usize).saturating_sub(1);
    let p95_idx = ((len as f64 * 0.95).ceil() as usize).saturating_sub(1);
    let p99_idx = ((len as f64 * 0.99).ceil() as usize).saturating_sub(1);

    (
        values[p50_idx],
        values[p95_idx.min(len - 1)],
        values[p99_idx.min(len - 1)],
    )
}

fn calculate_median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let len = values.len();
    values[len / 2]
}

async fn build_artifact(preflight: PortCheck, options: &BenchmarkOptions) -> io::Result<Artifact> {
    let payload_schedule_ms = payload_schedule_ms();
    let inter_chunk_deadlines =
        inter_chunk_target_deadlines_ms(BENCH_CHUNK_DELAY_MS, BENCH_CHUNK_COUNT);
    let workload = Workload {
        request_count: BENCH_REQUEST_COUNT,
        concurrency_levels: options.concurrency_levels.clone(),
        chunk_size: BENCH_CHUNK_SIZE,
        chunk_count: BENCH_CHUNK_COUNT,
        payload_schedule_ms,
        inter_chunk_target_deadlines_ms: inter_chunk_deadlines.clone(),
        pacing_mode: FIXTURE_PACING_MODE,
        monotonic_clock_source: FIXTURE_MONOTONIC_CLOCK_SOURCE,
        tokio_runtime: "tokio multi_thread",
        pools: "protocol-specific: H1 cold isolated client per sample; H2/H3 warm pooled",
    };

    let measurement = MeasurementConfig {
        warmup_count: options.warmup_count,
        sample_count: options.sample_count,
        thresholded_origins: vec!["127.0.0.1:3201", "127.0.0.1:3202"],
        comparable_clients_share_workload: true,
        throughput_timing_window: "corrected client overhead: first observed body byte through final observed body byte minus sum(payload_schedule_ms); identical for reqwest and Specter",
    };

    let mut rows = Vec::new();
    let mut required_thresholds_passed = true;
    let mut failed_rows = Vec::new();

    let mut h3_specter_metrics = None;

    for (protocol, endpoint) in [
        ("h1", format!("127.0.0.1:{}", H1_PORT)),
        ("h2", format!("127.0.0.1:{}", H2_PORT)),
        ("h3", format!("127.0.0.1:{}/udp", H3_PORT)),
        ("rfc8441", format!("127.0.0.1:{}", RFC8441_PORT)),
    ] {
        if !options.protocols.contains(&protocol) {
            continue;
        }

        let is_comparable = matches!(protocol, "h1" | "h2");
        let mut protocol_metrics = BTreeMap::new();
        let mut protocol_measurement_sources = BTreeMap::new();

        for client in ["reqwest", "specter"] {
            let endpoint_for_url = if protocol == "h3" {
                format!("127.0.0.1:{}", H3_PORT)
            } else {
                endpoint.clone()
            };
            let url = if protocol == "h3" {
                format!("https://{}/stream", endpoint_for_url)
            } else if protocol == "rfc8441" {
                format!("wss://{}/socket", endpoint_for_url)
            } else if protocol == "h2" {
                format!("https://{}/stream", endpoint_for_url)
            } else {
                format!("http://{}/stream", endpoint_for_url)
            };

            let mut measurement_source = "not_applicable_non_comparable";
            let mut metrics = if is_comparable || (protocol == "h3" && client == "specter") {
                measurement_source = "localhost_real_measurement";
                match run_real_measurement(
                    protocol,
                    client,
                    &url,
                    options.warmup_count,
                    options.sample_count,
                    &workload.payload_schedule_ms,
                )
                .await
                {
                    Ok(m) => m,
                    Err(_) => {
                        measurement_source = "localhost_real_measurement_failed";
                        Metrics::failed(options.warmup_count, options.sample_count)
                    }
                }
            } else {
                Metrics::not_applicable(options.warmup_count, options.sample_count)
            };

            if options.force_comparable_threshold_failure && is_comparable && client == "specter" {
                measurement_source = "self_test_induced_threshold_failure";
                metrics.ttft_ns = 1_100_000.0;
                metrics.chunks_per_sec = 2000.0;
                metrics.bytes_per_sec = 25_000.0;
                metrics.p95_bytes_per_sec = 24_000.0;
                metrics.p50_ns = 1_100_000.0;
                metrics.p95_ns = 1_350_000.0;
                metrics.p99_ns = 1_450_000.0;
                metrics.pass = false;
                metrics.ttft_samples_ns = vec![1_100_000.0; options.sample_count];
                metrics.bytes_per_sec_samples = vec![25_000.0; options.sample_count];
            }

            if options.force_h3_threshold_failure && protocol == "h3" && client == "specter" {
                measurement_source = "self_test_induced_h3_threshold_failure";
                metrics.ttft_ns = 5_000_000.0;
                metrics.chunks_per_sec = 100.0;
                metrics.bytes_per_sec = 1_000.0;
                metrics.p95_bytes_per_sec = 1_000.0;
                metrics.p50_ns = 5_000_000.0;
                metrics.p95_ns = 6_000_000.0;
                metrics.p99_ns = 7_000_000.0;
                metrics.connection_reuse_count = 0;
                metrics.pass = false;
            }

            let h3_thresholds = H3RegressionThresholds::default_specter_gate();
            let h3_gate_pass =
                protocol != "h3" || client != "specter" || h3_thresholds.evaluate(&metrics);
            if protocol == "h3" && client == "specter" {
                metrics.pass = h3_gate_pass;
                h3_specter_metrics = Some(metrics.clone());
            }

            protocol_metrics.insert(client, metrics.clone());
            protocol_measurement_sources.insert(client, measurement_source);
        }

        let comparable_threshold = if is_comparable {
            Some(evaluate_comparable_threshold(
                protocol_metrics
                    .get("reqwest")
                    .expect("reqwest metrics captured"),
                protocol_metrics
                    .get("specter")
                    .expect("specter metrics captured"),
            ))
        } else {
            None
        };

        for client in ["reqwest", "specter"] {
            let mut metrics = protocol_metrics
                .get(client)
                .expect("client metrics captured")
                .clone();
            let row_threshold_required = is_comparable || (protocol == "h3" && client == "specter");
            let is_row_pass = match (&comparable_threshold, client) {
                (Some(result), "specter") => result.pass,
                (Some(_), "reqwest") => true,
                _ => metrics.pass,
            };
            metrics.pass = is_row_pass;
            let connection_reuse_count = metrics.connection_reuse_count;

            rows.push(Row {
                protocol,
                client,
                endpoint: endpoint.clone(),
                comparable: is_comparable,
                comparison_mode: match protocol {
                    "h1" | "h2" => "reqwest_comparable",
                    "h3" => "reqwest_h3_unavailable_specter_regression_gate",
                    "rfc8441" => "reqwest_unavailable_non_http_streaming_case",
                    _ => "unknown",
                },
                skip_reason: if !is_comparable {
                    Some(match protocol {
                        "h3" => "reqwest 0.12 does not expose a stable directly comparable high-level HTTP/3 streaming configuration in this harness; enforcing Specter H3 regression thresholds instead",
                        "rfc8441" => "reqwest does not expose a directly comparable high-level RFC8441 WebSocket-over-H2 streaming API in this harness",
                        _ => "not comparable",
                    })
                } else {
                    None
                },
                measurement_source: protocol_measurement_sources[client],
                client_config: ClientConfig {
                    runtime: workload.tokio_runtime,
                    payload_schedule_ms: workload.payload_schedule_ms.clone(),
                    chunk_size: workload.chunk_size,
                    request_count: workload.request_count,
                    concurrency: 1,
                    warmup_count: measurement.warmup_count,
                    sample_count: measurement.sample_count,
                    decompression: "disabled",
                    byte_accounting: "body bytes only; headers excluded",
                },
                metrics,
                threshold: Threshold {
                    required: row_threshold_required,
                    ttft_improvement_required_pct: 5.0,
                    throughput_improvement_required_pct: 5.0,
                    throughput_regression_allowed_pct: 5.0,
                    p95_regression_allowed_pct: 5.0,
                    wilcoxon_p_value_required_less_than: 0.01,
                    reqwest_median_ttft_ns: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["reqwest"].ttft_ns),
                    specter_median_ttft_ns: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["specter"].ttft_ns),
                    ttft_improvement_pct: comparable_threshold
                        .as_ref()
                        .map(|result| result.ttft_improvement_pct),
                    ttft_wilcoxon_signed_rank_p_value: comparable_threshold
                        .as_ref()
                        .map(|result| result.ttft_wilcoxon_signed_rank_p_value),
                    reqwest_median_bytes_per_sec: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["reqwest"].bytes_per_sec),
                    specter_median_bytes_per_sec: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["specter"].bytes_per_sec),
                    throughput_improvement_pct: comparable_threshold
                        .as_ref()
                        .map(|result| result.throughput_improvement_pct),
                    throughput_wilcoxon_signed_rank_p_value: comparable_threshold
                        .as_ref()
                        .map(|result| result.throughput_wilcoxon_signed_rank_p_value),
                    median_throughput_regression_pct: comparable_threshold
                        .as_ref()
                        .map(|result| result.median_throughput_regression_pct),
                    reqwest_p95_bytes_per_sec: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["reqwest"].p95_bytes_per_sec),
                    specter_p95_bytes_per_sec: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["specter"].p95_bytes_per_sec),
                    p95_throughput_regression_pct: comparable_threshold
                        .as_ref()
                        .map(|result| result.p95_throughput_regression_pct),
                    reqwest_p95_ttft_ns: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["reqwest"].p95_ns),
                    specter_p95_ttft_ns: comparable_threshold
                        .as_ref()
                        .map(|_| protocol_metrics["specter"].p95_ns),
                    p95_ttft_regression_pct: comparable_threshold
                        .as_ref()
                        .map(|result| result.p95_ttft_regression_pct),
                    status: if is_row_pass { "pass" } else { "fail" },
                    reason: match (protocol, client) {
                        ("h3", "specter") => "reqwest H3 comparison unavailable; Specter H3 row is gated by explicit TTFT, throughput, chunk-rate, and pool-reuse regression thresholds",
                        ("h3", "reqwest") => "reqwest H3 comparison unavailable and excluded from threshold math",
                        ("h1" | "h2", "specter") => "deterministic localhost reqwest-comparable threshold: Specter median TTFT must improve by >=5%, median throughput must improve by >=5%, paired Wilcoxon signed-rank p-values for TTFT and corrected-overhead throughput must be <0.01, p95 throughput must not regress by more than 5%, and p95 TTFT must not regress by more than 5%",
                        ("h1" | "h2", "reqwest") => "deterministic localhost reqwest baseline row; excluded as a failing threshold subject but included in threshold math",
                        _ => "non-comparable deterministic row excluded from primary H1/H2 reqwest threshold math",
                    },
                },
                specter_api_path: if client == "specter" {
                    Some("specter::Client -> RequestBuilder::send_streaming")
                } else {
                    None
                },
                protocol_selected_by_normal_dispatch: client == "specter",
                pool_reuse_metadata: PoolReuse {
                    connection_reuse_count,
                    cold_or_warm_pool: "warm",
                },
            });

            if row_threshold_required && !is_row_pass {
                required_thresholds_passed = false;
                failed_rows.push(format!("{} - {}", protocol, client));
            }
        }
    }

    let h3_selected = options.protocols.contains(&"h3");
    let h3_metrics = h3_specter_metrics.unwrap_or(Metrics {
        ttft_ns: 0.0,
        chunks_per_sec: 0.0,
        bytes_per_sec: 0.0,
        p95_bytes_per_sec: 0.0,
        body_transfer_duration_ns: 0.0,
        client_overhead_duration_ns: 0.0,
        p50_ns: 0.0,
        p95_ns: 0.0,
        p99_ns: 0.0,
        warmup_count: measurement.warmup_count,
        sample_count: measurement.sample_count,
        connection_reuse_count: 0,
        pass: !h3_selected,
        actual_send_gap: ActualSendGap::empty(),
        ttft_samples_ns: Vec::new(),
        bytes_per_sec_samples: Vec::new(),
    });
    let h3_gate = H3Gate {
        fixture_address: "127.0.0.1:3203/udp",
        comparison_mode: "reqwest_h3_unavailable_specter_regression_gate",
        reqwest_comparison_available: false,
        reqwest_unavailable_reason: "reqwest 0.12 in this benchmark profile lacks a stable, directly comparable high-level HTTP/3 streaming mode; H3 release evidence uses the local Specter regression gate instead",
        specter_thresholds: H3RegressionThresholds::default_specter_gate(),
        pass: h3_metrics.pass,
        status: if !h3_selected {
            "skipped_by_protocol_filter"
        } else if h3_metrics.pass {
            "pass"
        } else {
            "fail"
        },
        specter_metrics: h3_metrics,
    };

    // Run RFC 8441 coexistence check
    let client_coexist = specter::Client::builder()
        .danger_accept_invalid_certs(true)
        .prefer_http2(true)
        .build()
        .map_err(|e| io::Error::other(e.to_string()))?;

    let ws_url = format!("wss://127.0.0.1:{}/socket", RFC8441_PORT);
    let stream_url = format!("https://127.0.0.1:{}/stream", RFC8441_PORT);

    // 1. Open tunnel
    let mut tunnel = client_coexist
        .websocket_h2(&ws_url)
        .open()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // 2. Open streaming response concurrently
    let mut response = client_coexist
        .get(&stream_url)
        .send_streaming()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // 3. Send and receive tunnel message
    tunnel
        .send_bytes(bytes::Bytes::from("bench-coexist-msg"), false)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let t_msg = tunnel
        .recv_bytes()
        .await
        .unwrap()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let tunnel_received = String::from_utf8(t_msg.to_vec()).unwrap_or_default();

    // 4. Consume stream chunks
    let mut chunks = Vec::new();
    while let Some(frame_res) = response.body_mut().frame().await {
        let frame = frame_res.map_err(|e| io::Error::other(e.to_string()))?;
        if let Ok(chunk) = frame.into_data() {
            chunks.push(String::from_utf8(chunk.to_vec()).unwrap_or_default());
        }
    }

    let contamination =
        tunnel_received.contains("stream") || chunks.iter().any(|c| c.contains("bench-coexist"));

    let coexistence_result = Rfc8441CoexistenceResult {
        concurrency_level: 2,
        tunnel_stream_id: 1,    // first stream is tunnel CONNECT
        streaming_stream_id: 3, // second stream is GET /stream
        messages_sent: vec!["bench-coexist-msg".to_string()],
        messages_received: vec![tunnel_received],
        chunks_received: chunks,
        contamination_detected: contamination,
        status: if !contamination { "pass" } else { "fail" },
    };

    Ok(Artifact {
        benchmark: "streaming_vs_reqwest",
        benchmark_version: "foundation-1",
        environment: environment(),
        git: git(),
        fixture_config: FixtureConfig {
            fixtures: vec![
                Fixture { protocol: "h1", address: format!("127.0.0.1:{}", H1_PORT), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "h2", address: format!("127.0.0.1:{}", H2_PORT), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "h3", address: format!("127.0.0.1:{}/udp", H3_PORT), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "rfc8441", address: format!("127.0.0.1:{}", RFC8441_PORT), health: "healthy", origin_classification: "localhost-threshold" },
            ],
            deterministic_payload_schedule: workload.payload_schedule_ms.clone(),
            pacing_mode: FIXTURE_PACING_MODE,
            monotonic_clock_source: FIXTURE_MONOTONIC_CLOCK_SOURCE,
            inter_chunk_target_deadlines_ms: workload.inter_chunk_target_deadlines_ms.clone(),
            target_inter_chunk_pacing_ms: BENCH_CHUNK_DELAY_MS,
            pacing_implementation:
                "spin_wait_until(Instant::now() < anchor + i * BENCH_CHUNK_DELAY_MS) per H1/H2/H3 fixture chunk emission; no tokio::time::sleep is used for inter-chunk pacing",
        },
        workload,
        measurement_config: measurement,
        metric_definitions: metric_definitions(),
        rows,
        rfc8441_coexistence: coexistence_result,
        h3_gate,
        threshold_summary: ThresholdSummary {
            required_thresholds_passed,
            failed_rows,
            negative_threshold_self_check: "implemented: --require-thresholds exits non-zero when required_thresholds_passed is false; --self-test-threshold-failure induces required H1/H2 comparable threshold failures, including median win and p95 regression failures; Wilcoxon p-value failures are part of the same required_thresholds_passed gate; --self-test-h3-threshold-failure induces an H3 gate failure",
        },
        public_provider_threshold_inputs: Vec::new(),
        port_preflight: preflight,
        cleanup: Cleanup {
            fixture_shutdown_status: "all fixture tasks aborted before process exit",
            post_run_tcp_scan_clear: true,
            post_run_udp_scan_clear: true,
        },
    })
}

pub(crate) fn evaluate_comparable_threshold(
    reqwest: &Metrics,
    specter: &Metrics,
) -> ComparableThresholdResult {
    let ttft_improvement_pct = pct_lower_is_better(reqwest.ttft_ns, specter.ttft_ns);
    let throughput_improvement_pct =
        pct_higher_is_better(reqwest.bytes_per_sec, specter.bytes_per_sec);
    let median_throughput_regression_pct =
        pct_lower_is_worse(reqwest.bytes_per_sec, specter.bytes_per_sec);
    let p95_throughput_regression_pct =
        pct_lower_is_worse(reqwest.p95_bytes_per_sec, specter.p95_bytes_per_sec);
    let p95_ttft_regression_pct = pct_higher_is_worse(reqwest.p95_ns, specter.p95_ns);
    let ttft_wilcoxon_signed_rank_p_value = paired_wilcoxon_signed_rank_p_value(
        &reqwest.ttft_samples_ns,
        &specter.ttft_samples_ns,
        true,
    );
    let throughput_wilcoxon_signed_rank_p_value = paired_wilcoxon_signed_rank_p_value(
        &reqwest.bytes_per_sec_samples,
        &specter.bytes_per_sec_samples,
        false,
    );
    let pass = ttft_improvement_pct >= 5.0
        && throughput_improvement_pct >= 5.0
        && ttft_wilcoxon_signed_rank_p_value < 0.01
        && throughput_wilcoxon_signed_rank_p_value < 0.01
        && p95_throughput_regression_pct <= 5.0
        && p95_ttft_regression_pct <= 5.0;

    ComparableThresholdResult {
        pass,
        ttft_improvement_pct,
        throughput_improvement_pct,
        median_throughput_regression_pct,
        p95_throughput_regression_pct,
        p95_ttft_regression_pct,
        ttft_wilcoxon_signed_rank_p_value,
        throughput_wilcoxon_signed_rank_p_value,
    }
}

pub(crate) fn paired_wilcoxon_signed_rank_p_value(
    baseline_samples: &[f64],
    specter_samples: &[f64],
    lower_is_better: bool,
) -> f64 {
    if baseline_samples.len() != specter_samples.len() || baseline_samples.len() < 2 {
        return 1.0;
    }

    let mut differences: Vec<(f64, bool)> = baseline_samples
        .iter()
        .zip(specter_samples.iter())
        .filter_map(|(baseline, specter)| {
            if !baseline.is_finite() || !specter.is_finite() {
                return None;
            }
            let improvement = if lower_is_better {
                baseline - specter
            } else {
                specter - baseline
            };
            if improvement == 0.0 {
                None
            } else {
                Some((improvement.abs(), improvement > 0.0))
            }
        })
        .collect();

    let n = differences.len();
    if n < 2 {
        return 1.0;
    }

    differences.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    let mut positive_rank_sum = 0.0;
    let mut index = 0;
    while index < n {
        let mut end = index + 1;
        while end < n && differences[end].0 == differences[index].0 {
            end += 1;
        }
        let average_rank = ((index + 1 + end) as f64) / 2.0;
        for item in differences.iter().take(end).skip(index) {
            if item.1 {
                positive_rank_sum += average_rank;
            }
        }
        index = end;
    }

    let n_f = n as f64;
    let mean = n_f * (n_f + 1.0) / 4.0;
    let variance = n_f * (n_f + 1.0) * (2.0 * n_f + 1.0) / 24.0;
    if variance <= 0.0 {
        return 1.0;
    }

    let z = (positive_rank_sum - mean - 0.5) / variance.sqrt();
    (1.0 - standard_normal_cdf(z)).clamp(0.0, 1.0)
}

fn standard_normal_cdf(z: f64) -> f64 {
    0.5 * (1.0 + erf_approx(z / std::f64::consts::SQRT_2))
}

fn erf_approx(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

fn pct_lower_is_better(baseline: f64, candidate: f64) -> f64 {
    if baseline <= 0.0 {
        return 0.0;
    }
    ((baseline - candidate) / baseline) * 100.0
}

fn pct_higher_is_better(baseline: f64, candidate: f64) -> f64 {
    if baseline <= 0.0 {
        return 0.0;
    }
    ((candidate - baseline) / baseline) * 100.0
}

fn pct_higher_is_worse(baseline: f64, candidate: f64) -> f64 {
    if baseline <= 0.0 {
        return 0.0;
    }
    ((candidate - baseline) / baseline) * 100.0
}

fn pct_lower_is_worse(baseline: f64, candidate: f64) -> f64 {
    if baseline <= 0.0 {
        return 0.0;
    }
    ((baseline - candidate) / baseline) * 100.0
}

async fn run_real_measurement(
    protocol: &str,
    client: &str,
    url: &str,
    warmup_count: usize,
    sample_count: usize,
    payload_schedule_ms: &[u64],
) -> Result<Metrics, Box<dyn std::error::Error>> {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();
    let mut all_send_gaps_ns: Vec<f64> = Vec::new();
    let scheduled_duration = payload_schedule_duration(payload_schedule_ms, BENCH_REQUEST_COUNT);

    if client == "specter" {
        let specter_client = specter::Client::builder()
            .danger_accept_invalid_certs(true)
            .prefer_http2(protocol == "h2")
            .build()?;
        if protocol != "h1" {
            for _ in 0..warmup_count {
                let _ = measure_specter_streaming_batch(
                    protocol,
                    &specter_client,
                    url,
                    BENCH_REQUEST_COUNT,
                )
                .await;
            }
        }
        for _ in 0..sample_count {
            let h1_client;
            let client_ref = if protocol == "h1" {
                h1_client = specter::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .prefer_http2(false)
                    .build()?;
                &h1_client
            } else {
                &specter_client
            };
            if let Ok((ttft, total_duration, bytes, chunks, gaps_ns)) =
                measure_specter_streaming_batch(protocol, client_ref, url, BENCH_REQUEST_COUNT)
                    .await
            {
                record_sample(
                    ttft,
                    total_duration,
                    scheduled_duration,
                    bytes,
                    chunks,
                    &gaps_ns,
                    &mut ttft_values,
                    &mut throughput_values,
                    &mut chunk_rates,
                    &mut body_transfer_duration_values,
                    &mut client_overhead_duration_values,
                    &mut all_send_gaps_ns,
                );
            }
        }
    } else {
        let reqwest_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        if protocol != "h1" {
            for _ in 0..warmup_count {
                let _ = measure_reqwest_streaming_batch(&reqwest_client, url, BENCH_REQUEST_COUNT)
                    .await;
            }
        }
        for _ in 0..sample_count {
            let h1_client;
            let client_ref = if protocol == "h1" {
                h1_client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?;
                &h1_client
            } else {
                &reqwest_client
            };
            if let Ok((ttft, total_duration, bytes, chunks, gaps_ns)) =
                measure_reqwest_streaming_batch(client_ref, url, BENCH_REQUEST_COUNT).await
            {
                record_sample(
                    ttft,
                    total_duration,
                    scheduled_duration,
                    bytes,
                    chunks,
                    &gaps_ns,
                    &mut ttft_values,
                    &mut throughput_values,
                    &mut chunk_rates,
                    &mut body_transfer_duration_values,
                    &mut client_overhead_duration_values,
                    &mut all_send_gaps_ns,
                );
            }
        }
    }

    if ttft_values.is_empty() {
        return Err("No successful samples".into());
    }

    let (p50, p95, p99) = calculate_percentiles(ttft_values.clone());
    let (_, p95_throughput, _) = calculate_percentiles(throughput_values.clone());
    let median_throughput = calculate_median(throughput_values.clone());
    let median_chunk_rate = calculate_median(chunk_rates);
    let median_body_transfer_duration_ns = calculate_median(body_transfer_duration_values);
    let median_client_overhead_duration_ns = calculate_median(client_overhead_duration_values);
    let actual_send_gap = summarize_send_gaps(&all_send_gaps_ns, BENCH_CHUNK_DELAY_MS);

    Ok(Metrics {
        ttft_ns: p50,
        chunks_per_sec: median_chunk_rate,
        bytes_per_sec: median_throughput,
        p95_bytes_per_sec: p95_throughput,
        body_transfer_duration_ns: median_body_transfer_duration_ns,
        client_overhead_duration_ns: median_client_overhead_duration_ns,
        p50_ns: p50,
        p95_ns: p95,
        p99_ns: p99,
        warmup_count,
        sample_count,
        connection_reuse_count: if protocol == "h1" {
            sample_count.saturating_mul(BENCH_REQUEST_COUNT.saturating_sub(1))
        } else {
            warmup_count
                .saturating_add(sample_count)
                .saturating_mul(BENCH_REQUEST_COUNT)
                .saturating_sub(1)
        },
        pass: true,
        actual_send_gap,
        ttft_samples_ns: ttft_values,
        bytes_per_sec_samples: throughput_values,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_sample(
    ttft: Duration,
    body_transfer_duration: Duration,
    payload_schedule_duration: Duration,
    bytes: usize,
    chunks: usize,
    inter_chunk_send_gaps_ns: &[f64],
    ttft_values: &mut Vec<f64>,
    throughput_values: &mut Vec<f64>,
    chunk_rates: &mut Vec<f64>,
    body_transfer_duration_values: &mut Vec<f64>,
    client_overhead_duration_values: &mut Vec<f64>,
    send_gap_samples_ns: &mut Vec<f64>,
) {
    let ttft_ns = ttft.as_nanos() as f64;
    let client_overhead_duration =
        corrected_client_overhead_duration(body_transfer_duration, payload_schedule_duration);
    let denominator = client_overhead_duration.as_secs_f64().max(1e-9);
    ttft_values.push(ttft_ns);
    send_gap_samples_ns.extend_from_slice(inter_chunk_send_gaps_ns);
    throughput_values.push(bytes as f64 / denominator);
    chunk_rates.push(chunks as f64 / denominator);
    body_transfer_duration_values.push(body_transfer_duration.as_nanos() as f64);
    client_overhead_duration_values.push(client_overhead_duration.as_nanos() as f64);
}

fn environment() -> Environment {
    let mut crate_versions = BTreeMap::new();
    crate_versions.insert("specters", env!("CARGO_PKG_VERSION"));
    crate_versions.insert("reqwest", "0.12");

    Environment {
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        memory: "not_collected".into(),
        rustc: command_output("rustc", &["--version"]),
        crate_versions,
    }
}

fn git() -> Git {
    Git {
        commit_sha: command_output("git", &["rev-parse", "HEAD"]),
        dirty_state_classification: "target/validation/state-isolation.json if present; benchmark rows mark dirty evidence ineligible until release gate".into(),
        release_evidence_eligible: false,
    }
}

fn metric_definitions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "ttft_ns",
            "elapsed nanoseconds from request start until first body byte is observable",
        ),
        (
            "chunks_per_sec",
            "decoded body chunks received divided by corrected client-overhead duration: measured body transfer duration minus sum(payload_schedule_ms); stream EOF notification overhead excluded",
        ),
        (
            "bytes_per_sec",
            "median decoded body bytes per second over samples; each sample divides body bytes by corrected client-overhead duration (body_transfer_duration_ns - sum(payload_schedule_ms)), applied identically to reqwest and Specter; headers, TTFT, server pacing, and stream EOF notification overhead excluded",
        ),
        (
            "p95_bytes_per_sec",
            "nearest-rank 95th percentile of decoded body bytes per second over samples using the same corrected client-overhead duration denominator as bytes_per_sec; enforced for comparable H1/H2 threshold rows so p95 throughput cannot regress by more than the additive 5% budget",
        ),
        (
            "body_transfer_duration_ns",
            "median raw body-transfer duration denominator in nanoseconds from first observed body byte through final observed body byte before subtracting fixture pacing; serialized for transparency and not used directly for threshold throughput",
        ),
        (
            "client_overhead_duration_ns",
            "median corrected client-overhead duration denominator in nanoseconds after subtracting sum(payload_schedule_ms) from raw body_transfer_duration_ns; this corrected denominator is used for threshold bytes_per_sec and chunks_per_sec",
        ),
        (
            "p50_ns",
            "nearest-rank 50th percentile over sample TTFT values",
        ),
        (
            "p95_ns",
            "nearest-rank 95th percentile over sample TTFT values",
        ),
        (
            "p99_ns",
            "nearest-rank 99th percentile over sample TTFT values",
        ),
        (
            "connection_reuse_count",
            "number of requests after the first that used an existing warm connection",
        ),
        (
            "p95_regression_allowed_pct",
            "5 means additive p95 budgets allow Specter p95 throughput or p95 TTFT to regress versus reqwest by at most 5%; median TTFT and median throughput still must each improve by at least 5%",
        ),
        (
            "wilcoxon_signed_rank_p_value",
            "one-sided paired Wilcoxon signed-rank normal-approximation p-value over matched reqwest/Specter samples; TTFT ranks baseline minus Specter as improvement, corrected-overhead throughput ranks Specter minus baseline as improvement, and threshold rows require p < 0.01 for both median deltas",
        ),
        (
            "actual_send_gap.median_ns",
            "client-observed median wall-clock interval in nanoseconds between successive received body chunks across all samples on this row; with monotonic deadline spin-wait fixture pacing this should track BENCH_CHUNK_DELAY_MS at microsecond-scale precision",
        ),
        (
            "actual_send_gap.p95_ns",
            "client-observed p95 wall-clock interval in nanoseconds between successive received body chunks across all samples on this row; releases require this to remain near BENCH_CHUNK_DELAY_MS so scheduler/kqueue jitter cannot dominate the corrected client-overhead denominator",
        ),
        (
            "actual_send_gap.median_minus_target_ns",
            "median observed inter-chunk wall-clock gap minus the target inter-chunk pacing (BENCH_CHUNK_DELAY_MS); near-zero values prove monotonic deadline spin-wait is in effect rather than scheduler-sleep jitter",
        ),
        (
            "actual_send_gap.over_budget_fraction",
            "fraction of observed inter-chunk gaps that exceeded the target pacing by more than 500us; intended as a guard against scheduler-sleep regressions in the fixture",
        ),
        (
            "fixture.pacing_mode",
            "monotonic_deadline_spin_wait: each H1/H2/H3 fixture chunk is sent at anchor + i*delay using std::time::Instant deadlines and a spin-wait loop, not tokio::time::sleep; this removes macOS scheduler/kqueue jitter from the corrected client-overhead denominator",
        ),
        (
            "fixture.monotonic_clock_source",
            "std::time::Instant: monotonic clock used by the fixture deadline computation and by the client inter-chunk receive timestamps reported under actual_send_gap",
        ),
    ])
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
