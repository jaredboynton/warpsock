//! Real Codex backend SSE streaming benchmark: Specter vs reqwest.
//!
//! Hits POST https://chatgpt.com/backend-api/codex/responses with paired
//! samples from both clients, measures TTFT and total end-to-end wall time
//! on a real production LLM streaming endpoint.
//!
//! Skips gracefully when ~/.codex/auth.json is absent.

use serde::Serialize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

const ENDPOINT: &str = "https://chatgpt.com/backend-api/codex/responses";
const MODEL: &str = "gpt-5.4-mini";
const PROMPT: &str = "List the numbers 1 through 10 spelled out in English, one per line.";
const INSTRUCTIONS: &str = "You are a helpful assistant. Be concise.";
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);
const INTER_REQUEST_DELAY: Duration = Duration::from_secs(2);
// Primary claim passes if at least 80% of samples meet pass conditions.
// Threshold scales with sample_count: ceil(0.8 * N), min 2.
fn primary_claim_threshold(sample_count: usize) -> usize {
    let scaled = (sample_count * 4).div_ceil(5); // ceil(0.8 * N)
    scaled.max(2)
}
const DEFAULT_SAMPLES: usize = 10;
const DEFAULT_WARMUP: usize = 3;
const MIN_SAMPLES: usize = 5;

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const SEC_CH_UA: &str =
    "\"Chromium\";v=\"146\", \"Not.A/Brand\";v=\"99\", \"Google Chrome\";v=\"146\"";

#[derive(Serialize, Clone)]
struct Row {
    client: &'static str,
    warmup: bool,
    sample_index: usize,
    pair_index: usize,
    lead_in_pair: bool,
    status: &'static str,
    status_code: u16,
    ttft_ms: f64,
    total_wall_time_ms: f64,
    total_chars: usize,
    delta_count: usize,
    completed: bool,
    chars_per_sec: f64,
    pool_reuse_delta_specter: Option<u64>,
    protocol_used: String,
    epoch_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Default)]
struct ClientSummary {
    median_ttft_ms: f64,
    p95_ttft_ms: f64,
    median_total_wall_time_ms: f64,
    p95_total_wall_time_ms: f64,
    median_chars_per_sec: f64,
    passing_samples: usize,
}

#[derive(Serialize)]
struct Comparison {
    ttft_difference_ms: f64,
    ttft_ci_95: [f64; 2],
    ttft_ci_covers_zero: bool,
    wall_time_difference_ms: f64,
    wall_time_ci_95: [f64; 2],
    wall_time_ci_covers_zero: bool,
    ttft_wilcoxon_p_value: f64,
    wall_time_wilcoxon_p_value: f64,
    interpretation: String,
}

#[derive(Serialize)]
struct Summary {
    specter: ClientSummary,
    reqwest: ClientSummary,
    protocol_used_specter: String,
    protocol_used_reqwest: String,
    protocol_mismatch: bool,
    comparison: Comparison,
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    specter_version: &'static str,
}

#[derive(Serialize)]
struct Artifact {
    benchmark: &'static str,
    benchmark_version: &'static str,
    date: String,
    endpoint: &'static str,
    model: &'static str,
    accept_encoding: &'static str,
    warmup_count: usize,
    sample_count: usize,
    inter_request_delay_ms: u64,
    lead_alternation: String,
    primary_claim: &'static str,
    primary_claim_passed: usize,
    primary_claim_total: usize,
    primary_claim_threshold: usize,
    primary_claim_definition: &'static str,
    failures: Vec<String>,
    environment: Environment,
    protocol_mismatch: bool,
    rows: Vec<Row>,
    summary: Summary,
}

struct SampleResult {
    status: &'static str,
    status_code: u16,
    ttft_ms: f64,
    total_wall_time_ms: f64,
    total_chars: usize,
    delta_count: usize,
    completed: bool,
    pool_reuse_delta: Option<u64>,
    protocol_used: String,
    error: Option<String>,
}

fn build_body() -> Vec<u8> {
    let body = serde_json::json!({
        "model": MODEL,
        "instructions": INSTRUCTIONS,
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": PROMPT}]
        }],
        "stream": true,
        "store": false,
        "reasoning": { "effort": "low", "summary": "auto" },
        "include": ["reasoning.encrypted_content"],
    });
    serde_json::to_vec(&body).expect("serialize body")
}

fn read_codex_auth() -> Option<(String, Option<String>)> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".codex/auth.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let token = v["tokens"]["access_token"].as_str()?.to_string();
    let account_id = v["tokens"]["account_id"].as_str().map(str::to_string);
    Some((token, account_id))
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn linear_interpolate_sorted(sorted: &[f64], pos: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let clamped = pos.clamp(0.0, (n - 1) as f64);
    let lower = clamped.floor() as usize;
    let upper = clamped.ceil() as usize;
    if lower == upper {
        return sorted[lower];
    }
    let weight = clamped - lower as f64;
    sorted[lower] * (1.0 - weight) + sorted[upper] * weight
}

fn percentile_type7(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let pos = q * (sorted.len() as f64 - 1.0);
    linear_interpolate_sorted(sorted, pos)
}

fn median_p95(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (percentile_type7(&v, 0.5), percentile_type7(&v, 0.95))
}

fn paired_wilcoxon_signed_rank_p_value(baseline: &[f64], candidate: &[f64]) -> f64 {
    if baseline.len() != candidate.len() || baseline.len() < 2 {
        return 1.0;
    }
    let mut differences: Vec<(f64, bool)> = baseline
        .iter()
        .zip(candidate.iter())
        .filter_map(|(b, c)| {
            if !b.is_finite() || !c.is_finite() {
                return None;
            }
            let improvement = b - c;
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
        let avg_rank = ((index + 1 + end) as f64) / 2.0;
        for item in differences.iter().take(end).skip(index) {
            if item.1 {
                positive_rank_sum += avg_rank;
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

fn t_value_95(df: usize) -> f64 {
    match df {
        1 => 12.706,
        2 => 4.303,
        3 => 3.182,
        4 => 2.776,
        5 => 2.571,
        6 => 2.447,
        7 => 2.365,
        8 => 2.306,
        9 => 2.262,
        10 => 2.228,
        11 => 2.201,
        12 => 2.179,
        13 => 2.160,
        14 => 2.145,
        15 => 2.131,
        16 => 2.120,
        17 => 2.110,
        18 => 2.101,
        19 => 2.093,
        20 => 2.086,
        21..=25 => 2.060,
        26..=30 => 2.042,
        _ => 1.960,
    }
}

fn t_ci_95(diffs: &[f64]) -> (f64, [f64; 2]) {
    if diffs.is_empty() {
        return (0.0, [0.0, 0.0]);
    }
    let n = diffs.len();
    let n_f = n as f64;
    let mean = diffs.iter().sum::<f64>() / n_f;
    if n < 2 {
        return (mean, [mean, mean]);
    }
    let var = diffs.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / (n_f - 1.0);
    let sd = var.sqrt();
    let half_width = t_value_95(n - 1) * sd / n_f.sqrt();
    (mean, [mean - half_width, mean + half_width])
}

fn normalize_proto(raw: &str) -> &'static str {
    if raw.starts_with("HTTP/2") {
        "HTTP/2"
    } else if raw.starts_with("HTTP/1.1") {
        "HTTP/1.1"
    } else if raw.starts_with("HTTP/1.0") {
        "HTTP/1.0"
    } else if raw.starts_with("HTTP/3") {
        "HTTP/3"
    } else {
        "unknown"
    }
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn today_iso() -> String {
    use chrono::Utc;
    Utc::now().format("%Y-%m-%d").to_string()
}

fn now_iso_compact() -> String {
    use chrono::Utc;
    Utc::now().format("%Y-%m-%dT%H%M%SZ").to_string()
}

/// Parses one SSE `data:` line. Returns (delta_text, completed, errored)
/// where exactly one of `Some(delta_text)`, `completed=true`, or
/// `errored=true` is signalled per parsed event. `[DONE]` returns
/// `(None, true, false)` to terminate the loop.
fn parse_sse_data(line: &str) -> Option<SseEvent> {
    let data = line
        .strip_prefix("data: ")
        .or_else(|| line.strip_prefix("data:"))?;
    let data = data.trim();
    if data == "[DONE]" {
        return Some(SseEvent::Done);
    }
    let v: serde_json::Value = serde_json::from_str(data).ok()?;
    let ty = v.get("type")?.as_str().unwrap_or("");
    match ty {
        "response.output_text.delta" => {
            let delta = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
            Some(SseEvent::TextDelta(delta.to_string()))
        }
        "response.completed" => Some(SseEvent::Completed),
        "response.failed" | "response.error" | "error" => {
            Some(SseEvent::Errored(data.chars().take(200).collect()))
        }
        _ => Some(SseEvent::Other),
    }
}

enum SseEvent {
    TextDelta(String),
    Completed,
    Errored(String),
    Done,
    Other,
}

struct StreamObservation {
    first_delta: Option<Instant>,
    last_delta: Option<Instant>,
    total_chars: usize,
    delta_count: usize,
    completed: bool,
    errored: bool,
    error_msg: Option<String>,
}

impl StreamObservation {
    fn new() -> Self {
        Self {
            first_delta: None,
            last_delta: None,
            total_chars: 0,
            delta_count: 0,
            completed: false,
            errored: false,
            error_msg: None,
        }
    }

    fn record(&mut self, ev: SseEvent, now: Instant) -> bool {
        // returns true if stream should terminate
        match ev {
            SseEvent::TextDelta(s) => {
                if self.first_delta.is_none() {
                    self.first_delta = Some(now);
                }
                self.last_delta = Some(now);
                self.total_chars += s.len();
                self.delta_count += 1;
                false
            }
            SseEvent::Completed => {
                self.completed = true;
                false
            }
            SseEvent::Errored(msg) => {
                self.errored = true;
                self.error_msg = Some(msg);
                true
            }
            SseEvent::Done => true,
            SseEvent::Other => false,
        }
    }
}

fn drain_lines(buf: &mut Vec<u8>, obs: &mut StreamObservation) -> bool {
    // returns true if stream should terminate
    while let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
        let line_bytes: Vec<u8> = buf.drain(..=nl_pos).collect();
        let line = std::str::from_utf8(&line_bytes)
            .unwrap_or("")
            .trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        if let Some(ev) = parse_sse_data(line) {
            let now = Instant::now();
            if obs.record(ev, now) {
                return true;
            }
        }
    }
    false
}

fn sample_summary_from(rows: &[Row], client: &str) -> ClientSummary {
    let passing: Vec<&Row> = rows
        .iter()
        .filter(|r| !r.warmup && r.client == client && r.status == "ok")
        .collect();
    if passing.is_empty() {
        return ClientSummary::default();
    }
    let ttfts: Vec<f64> = passing.iter().map(|r| r.ttft_ms).collect();
    let walls: Vec<f64> = passing.iter().map(|r| r.total_wall_time_ms).collect();
    let cps: Vec<f64> = passing.iter().map(|r| r.chars_per_sec).collect();
    let (ttft_med, ttft_p95) = median_p95(&ttfts);
    let (wall_med, wall_p95) = median_p95(&walls);
    let (cps_med, _) = median_p95(&cps);
    ClientSummary {
        median_ttft_ms: ttft_med,
        p95_ttft_ms: ttft_p95,
        median_total_wall_time_ms: wall_med,
        p95_total_wall_time_ms: wall_p95,
        median_chars_per_sec: cps_med,
        passing_samples: passing.len(),
    }
}

fn paired_diffs(rows: &[Row], field: impl Fn(&Row) -> f64) -> Vec<f64> {
    let mut by_pair_specter: std::collections::BTreeMap<usize, f64> = Default::default();
    let mut by_pair_reqwest: std::collections::BTreeMap<usize, f64> = Default::default();
    for r in rows.iter().filter(|r| !r.warmup && r.status == "ok") {
        match r.client {
            "specter" => {
                by_pair_specter.insert(r.pair_index, field(r));
            }
            "reqwest" => {
                by_pair_reqwest.insert(r.pair_index, field(r));
            }
            _ => {}
        }
    }
    by_pair_specter
        .iter()
        .filter_map(|(k, s)| by_pair_reqwest.get(k).map(|r| s - r))
        .collect()
}

// ---- Specter sample ----

async fn run_specter_sample(
    client: &specter::Client,
    token: &str,
    account_id: Option<&str>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    let body = build_body();
    let pool_before = client.connection_reuse_count();
    let mut req = client
        .post(ENDPOINT)
        .header("User-Agent", UA)
        .header("Accept", "text/event-stream")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "identity")
        .header("sec-ch-ua", SEC_CH_UA)
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"macOS\"")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-origin")
        .header("Origin", "https://chatgpt.com")
        .header("Referer", "https://chatgpt.com/")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(body);
    if let Some(aid) = account_id {
        req = req.header("ChatGPT-Account-Id", aid);
    }

    let start = Instant::now();
    let mut response = match req.send_streaming().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(SampleResult {
                status: "error",
                status_code: 0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                completed: false,
                pool_reuse_delta: None,
                protocol_used: "unknown".into(),
                error: Some(format!("specter send error: {e}")),
            });
        }
    };

    let status_code = u16::from(response.status());
    let protocol_used = normalize_proto(response.http_version()).to_string();
    if status_code != 200 {
        // Drain a little for diagnostics, then return http_error.
        let mut body_buf = Vec::new();
        let _ = timeout(Duration::from_secs(5), async {
            while let Some(c) = response.body_mut().chunk().await {
                if let Ok(chunk) = c {
                    body_buf.extend_from_slice(&chunk);
                    if body_buf.len() > 4096 {
                        break;
                    }
                } else {
                    break;
                }
            }
        })
        .await;
        let snippet = String::from_utf8_lossy(&body_buf)
            .chars()
            .take(256)
            .collect::<String>();
        return Ok(SampleResult {
            status: "http_error",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: 0,
            delta_count: 0,
            completed: false,
            pool_reuse_delta: None,
            protocol_used,
            error: Some(snippet),
        });
    }

    let mut obs = StreamObservation::new();
    let mut buf: Vec<u8> = Vec::new();

    let timed = timeout(STREAM_TIMEOUT, async {
        while let Some(chunk_res) = response.body_mut().chunk().await {
            let chunk = chunk_res?;
            buf.extend_from_slice(&chunk);
            if drain_lines(&mut buf, &mut obs) {
                break;
            }
        }
        // flush trailing partial line in case server omitted final newline
        if !buf.is_empty() {
            buf.push(b'\n');
            drain_lines(&mut buf, &mut obs);
        }
        Ok::<(), specter::Error>(())
    })
    .await;

    let pool_after = client.connection_reuse_count();
    let pool_reuse_delta = Some(pool_after.saturating_sub(pool_before) as u64);

    match timed {
        Ok(Ok(())) => finalize_sample(&obs, status_code, start, protocol_used, pool_reuse_delta),
        Ok(Err(e)) => Ok(SampleResult {
            status: "error",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: obs.total_chars,
            delta_count: obs.delta_count,
            completed: obs.completed,
            pool_reuse_delta,
            protocol_used,
            error: Some(format!("specter stream error: {e}")),
        }),
        Err(_) => Ok(SampleResult {
            status: "timeout",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: obs.total_chars,
            delta_count: obs.delta_count,
            completed: obs.completed,
            pool_reuse_delta,
            protocol_used,
            error: Some("specter 30s timeout".into()),
        }),
    }
}

// ---- reqwest sample ----

async fn run_reqwest_sample(
    client: &reqwest::Client,
    token: &str,
    account_id: Option<&str>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    let body = build_body();
    let mut req = client
        .post(ENDPOINT)
        .header("User-Agent", UA)
        .header("Accept", "text/event-stream")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "identity")
        .header("sec-ch-ua", SEC_CH_UA)
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"macOS\"")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-origin")
        .header("Origin", "https://chatgpt.com")
        .header("Referer", "https://chatgpt.com/")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(body);
    if let Some(aid) = account_id {
        req = req.header("ChatGPT-Account-Id", aid);
    }

    let start = Instant::now();
    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(SampleResult {
                status: "error",
                status_code: 0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                completed: false,
                pool_reuse_delta: None,
                protocol_used: "unknown".into(),
                error: Some(format!("reqwest send error: {e}")),
            });
        }
    };

    let status_code = response.status().as_u16();
    let protocol_used = reqwest_version_to_string(response.version());

    if status_code != 200 {
        let text = response.text().await.unwrap_or_default();
        let snippet = text.chars().take(256).collect::<String>();
        return Ok(SampleResult {
            status: "http_error",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: 0,
            delta_count: 0,
            completed: false,
            pool_reuse_delta: None,
            protocol_used,
            error: Some(snippet),
        });
    }

    let mut obs = StreamObservation::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut response = response;

    let timed = timeout(STREAM_TIMEOUT, async {
        while let Some(chunk) = response.chunk().await? {
            buf.extend_from_slice(&chunk);
            if drain_lines(&mut buf, &mut obs) {
                break;
            }
        }
        if !buf.is_empty() {
            buf.push(b'\n');
            drain_lines(&mut buf, &mut obs);
        }
        Ok::<(), reqwest::Error>(())
    })
    .await;

    match timed {
        Ok(Ok(())) => finalize_sample(&obs, status_code, start, protocol_used, None),
        Ok(Err(e)) => Ok(SampleResult {
            status: "error",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: obs.total_chars,
            delta_count: obs.delta_count,
            completed: obs.completed,
            pool_reuse_delta: None,
            protocol_used,
            error: Some(format!("reqwest stream error: {e}")),
        }),
        Err(_) => Ok(SampleResult {
            status: "timeout",
            status_code,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: obs.total_chars,
            delta_count: obs.delta_count,
            completed: obs.completed,
            pool_reuse_delta: None,
            protocol_used,
            error: Some("reqwest 30s timeout".into()),
        }),
    }
}

fn reqwest_version_to_string(v: reqwest::Version) -> String {
    if v == reqwest::Version::HTTP_2 {
        "HTTP/2".into()
    } else if v == reqwest::Version::HTTP_11 {
        "HTTP/1.1".into()
    } else if v == reqwest::Version::HTTP_10 {
        "HTTP/1.0".into()
    } else if v == reqwest::Version::HTTP_3 {
        "HTTP/3".into()
    } else {
        format!("{v:?}")
    }
}

fn finalize_sample(
    obs: &StreamObservation,
    status_code: u16,
    start: Instant,
    protocol_used: String,
    pool_reuse_delta: Option<u64>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    let ttft_ms = obs
        .first_delta
        .map(|t| t.duration_since(start).as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let total_wall_time_ms = obs
        .last_delta
        .map(|t| t.duration_since(start).as_secs_f64() * 1000.0)
        .unwrap_or(0.0);

    let (status, error) = if obs.errored {
        ("error", obs.error_msg.clone())
    } else if obs.completed && obs.delta_count > 0 {
        ("ok", None)
    } else if obs.delta_count > 0 {
        // got deltas but no completed event — treat as error
        ("error", Some("no response.completed received".into()))
    } else {
        (
            "error",
            obs.error_msg
                .clone()
                .or_else(|| Some("no deltas received".into())),
        )
    };

    Ok(SampleResult {
        status,
        status_code,
        ttft_ms,
        total_wall_time_ms,
        total_chars: obs.total_chars,
        delta_count: obs.delta_count,
        completed: obs.completed,
        pool_reuse_delta,
        protocol_used,
        error,
    })
}

fn row_from_sample(
    sample: SampleResult,
    client: &'static str,
    warmup: bool,
    sample_index: usize,
    pair_index: usize,
    lead_in_pair: bool,
) -> Row {
    let cps_denom = (sample.total_wall_time_ms - sample.ttft_ms).max(1.0);
    let chars_per_sec = if sample.delta_count >= 2 {
        (sample.total_chars as f64) / (cps_denom / 1000.0)
    } else {
        0.0
    };
    Row {
        client,
        warmup,
        sample_index,
        pair_index,
        lead_in_pair,
        status: leak_status(sample.status),
        status_code: sample.status_code,
        ttft_ms: sample.ttft_ms,
        total_wall_time_ms: sample.total_wall_time_ms,
        total_chars: sample.total_chars,
        delta_count: sample.delta_count,
        completed: sample.completed,
        chars_per_sec,
        pool_reuse_delta_specter: sample.pool_reuse_delta,
        protocol_used: sample.protocol_used,
        epoch_ms: now_epoch_ms(),
        error: sample.error,
    }
}

fn leak_status(s: &'static str) -> &'static str {
    // SampleResult.status is already &'static str
    s
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let sample_count = option_value(&args, "--samples")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES);
    let warmup_count = option_value(&args, "--warmup")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WARMUP);
    let json_path = option_value(&args, "--json")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "docs/benchmarks/codex-real-streaming/{}.json",
                now_iso_compact()
            ))
        });

    if sample_count < MIN_SAMPLES {
        eprintln!(
            "--samples must be >= {MIN_SAMPLES} (t-distribution CI is only valid for n >= 5)"
        );
        std::process::exit(1);
    }
    if !sample_count.is_multiple_of(2) {
        eprintln!("--samples must be even (paired interleaving); got {sample_count}");
        std::process::exit(1);
    }

    let (token, account_id) = match read_codex_auth() {
        Some(a) => a,
        None => {
            println!("SKIP: ~/.codex/auth.json not found or unreadable");
            return Ok(());
        }
    };

    println!(
        "Codex real-streaming bench: endpoint={ENDPOINT}, model={MODEL}, samples={sample_count}, warmup={warmup_count}"
    );

    let specter_client = specter::Client::builder()
        .fingerprint(specter::FingerprintProfile::Chrome146)
        .prefer_http2(true)
        .build()?;
    let reqwest_client = reqwest::Client::builder().build()?;

    let mut rows: Vec<Row> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    // Warmup: alternate S, R, S, R, ... discarded statistics-wise but kept in rows
    for w in 0..warmup_count {
        let lead_specter = w % 2 == 0;
        let order = if lead_specter { ["s", "r"] } else { ["r", "s"] };
        for (i, client) in order.iter().enumerate() {
            let sample = if *client == "s" {
                run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
            } else {
                run_reqwest_sample(&reqwest_client, &token, account_id.as_deref()).await?
            };
            let client_name = if *client == "s" { "specter" } else { "reqwest" };
            rows.push(row_from_sample(
                sample,
                client_name,
                true,
                w * 2 + i,
                w,
                i == 0,
            ));
            tokio::time::sleep(INTER_REQUEST_DELAY).await;
        }
    }

    // Counted samples: alternate lead each pair (SR / RS / SR / RS ...)
    let pair_count = sample_count / 2;
    for p in 0..pair_count {
        let lead_specter = p % 2 == 0;
        let order = if lead_specter {
            ("specter", "reqwest")
        } else {
            ("reqwest", "specter")
        };
        let pair_index = p;

        let sample1 = if order.0 == "specter" {
            run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
        } else {
            run_reqwest_sample(&reqwest_client, &token, account_id.as_deref()).await?
        };
        rows.push(row_from_sample(
            sample1,
            order.0,
            false,
            p * 2,
            pair_index,
            true,
        ));
        tokio::time::sleep(INTER_REQUEST_DELAY).await;

        let sample2 = if order.1 == "specter" {
            run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
        } else {
            run_reqwest_sample(&reqwest_client, &token, account_id.as_deref()).await?
        };
        rows.push(row_from_sample(
            sample2,
            order.1,
            false,
            p * 2 + 1,
            pair_index,
            false,
        ));
        if p < pair_count - 1 {
            tokio::time::sleep(INTER_REQUEST_DELAY).await;
        }
    }

    // Protocol check across non-warmup rows
    let mut proto_specter = "unknown".to_string();
    let mut proto_reqwest = "unknown".to_string();
    for r in rows.iter().filter(|r| !r.warmup) {
        if r.client == "specter" && r.protocol_used != "unknown" && proto_specter == "unknown" {
            proto_specter = r.protocol_used.clone();
        }
        if r.client == "reqwest" && r.protocol_used != "unknown" && proto_reqwest == "unknown" {
            proto_reqwest = r.protocol_used.clone();
        }
    }
    let protocol_mismatch = proto_specter != "HTTP/2" || proto_reqwest != "HTTP/2";

    // Pass count
    let counted_rows: Vec<&Row> = rows.iter().filter(|r| !r.warmup).collect();
    let mut passed_pairs = 0usize;
    for p in 0..pair_count {
        let s_ok = counted_rows.iter().any(|r| {
            r.pair_index == p
                && r.client == "specter"
                && r.status == "ok"
                && r.completed
                && r.delta_count >= 1
                && r.status_code == 200
        });
        let r_ok = counted_rows.iter().any(|r| {
            r.pair_index == p
                && r.client == "reqwest"
                && r.status == "ok"
                && r.completed
                && r.delta_count >= 1
                && r.status_code == 200
        });
        if s_ok && r_ok {
            passed_pairs += 1;
        } else {
            failures.push(format!("pair {p}: specter_ok={s_ok} reqwest_ok={r_ok}"));
        }
    }

    let threshold = primary_claim_threshold(sample_count);
    let primary_claim = if passed_pairs * 2 >= threshold {
        "pass"
    } else {
        "fail"
    };

    // Stats
    let specter_summary = sample_summary_from(&rows, "specter");
    let reqwest_summary = sample_summary_from(&rows, "reqwest");

    let ttft_diffs = paired_diffs(&rows, |r| r.ttft_ms);
    let wall_diffs = paired_diffs(&rows, |r| r.total_wall_time_ms);

    let (ttft_diff_mean, ttft_ci) = t_ci_95(&ttft_diffs);
    let (wall_diff_mean, wall_ci) = t_ci_95(&wall_diffs);

    // Wilcoxon needs paired vectors of the two clients, not the diff.
    let specter_ttfts: Vec<f64> = (0..pair_count)
        .filter_map(|p| {
            counted_rows
                .iter()
                .find(|r| r.pair_index == p && r.client == "specter" && r.status == "ok")
                .map(|r| r.ttft_ms)
        })
        .collect();
    let reqwest_ttfts: Vec<f64> = (0..pair_count)
        .filter_map(|p| {
            counted_rows
                .iter()
                .find(|r| r.pair_index == p && r.client == "reqwest" && r.status == "ok")
                .map(|r| r.ttft_ms)
        })
        .collect();
    let specter_walls: Vec<f64> = (0..pair_count)
        .filter_map(|p| {
            counted_rows
                .iter()
                .find(|r| r.pair_index == p && r.client == "specter" && r.status == "ok")
                .map(|r| r.total_wall_time_ms)
        })
        .collect();
    let reqwest_walls: Vec<f64> = (0..pair_count)
        .filter_map(|p| {
            counted_rows
                .iter()
                .find(|r| r.pair_index == p && r.client == "reqwest" && r.status == "ok")
                .map(|r| r.total_wall_time_ms)
        })
        .collect();

    let ttft_wilcoxon = paired_wilcoxon_signed_rank_p_value(&reqwest_ttfts, &specter_ttfts);
    let wall_wilcoxon = paired_wilcoxon_signed_rank_p_value(&reqwest_walls, &specter_walls);

    let ttft_ci_covers_zero = ttft_ci[0] <= 0.0 && ttft_ci[1] >= 0.0;
    let wall_ci_covers_zero = wall_ci[0] <= 0.0 && wall_ci[1] >= 0.0;

    let interpretation = if protocol_mismatch {
        format!(
            "Protocol mismatch: specter={proto_specter}, reqwest={proto_reqwest}. Comparison invalid."
        )
    } else if ttft_ci_covers_zero && wall_ci_covers_zero {
        format!(
            "Differences within network noise at n={pair_count} (TTFT 95% CI covers zero, wall 95% CI covers zero). Both clients streamed successfully from Codex over HTTP/2."
        )
    } else if !ttft_ci_covers_zero && ttft_diff_mean < 0.0 {
        format!(
            "Specter TTFT measurably faster: {ttft_diff_mean:.1} ms [{:.1}, {:.1}] (95% CI excludes zero). Wall-time CI {} zero.",
            ttft_ci[0],
            ttft_ci[1],
            if wall_ci_covers_zero { "covers" } else { "excludes" }
        )
    } else if !ttft_ci_covers_zero && ttft_diff_mean > 0.0 {
        format!(
            "reqwest TTFT measurably faster by {:.1} ms [{:.1}, {:.1}]. Investigate Specter HTTP/2 read loop.",
            ttft_diff_mean.abs(),
            ttft_ci[0],
            ttft_ci[1]
        )
    } else {
        format!("Mixed: TTFT CI={:.1?}, wall CI={:.1?}", ttft_ci, wall_ci)
    };

    let summary = Summary {
        specter: specter_summary,
        reqwest: reqwest_summary,
        protocol_used_specter: proto_specter,
        protocol_used_reqwest: proto_reqwest,
        protocol_mismatch,
        comparison: Comparison {
            ttft_difference_ms: ttft_diff_mean,
            ttft_ci_95: ttft_ci,
            ttft_ci_covers_zero,
            wall_time_difference_ms: wall_diff_mean,
            wall_time_ci_95: wall_ci,
            wall_time_ci_covers_zero: wall_ci_covers_zero,
            ttft_wilcoxon_p_value: ttft_wilcoxon,
            wall_time_wilcoxon_p_value: wall_wilcoxon,
            interpretation,
        },
    };

    let artifact = Artifact {
        benchmark: "codex_real_streaming",
        benchmark_version: "1",
        date: today_iso(),
        endpoint: ENDPOINT,
        model: MODEL,
        accept_encoding: "identity",
        warmup_count,
        sample_count,
        inter_request_delay_ms: INTER_REQUEST_DELAY.as_millis() as u64,
        lead_alternation: lead_alternation_string(pair_count),
        primary_claim,
        primary_claim_passed: passed_pairs * 2,
        primary_claim_total: pair_count * 2,
        primary_claim_threshold: threshold,
        primary_claim_definition: "status_code==200 AND delta_count>=1 AND response.completed received within 30s; pass if >=ceil(0.8*N) of N samples meet condition (counted per-pair, both clients must pass for the pair to count)",
        failures: failures.clone(),
        environment: Environment {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            specter_version: env!("CARGO_PKG_VERSION"),
        },
        protocol_mismatch,
        rows,
        summary,
    };

    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&artifact)?;
    std::fs::write(&json_path, &json)?;
    println!("wrote artifact: {}", json_path.display());

    println!(
        "primary_claim={primary_claim} ({}/{} samples; specter={}/{} pairs, reqwest={}/{} pairs)",
        passed_pairs * 2,
        pair_count * 2,
        passed_pairs,
        pair_count,
        passed_pairs,
        pair_count
    );
    println!(
        "interpretation: {}",
        artifact.summary.comparison.interpretation
    );

    if protocol_mismatch {
        eprintln!(
            "ERROR: protocol mismatch (specter={}, reqwest={})",
            artifact.summary.protocol_used_specter, artifact.summary.protocol_used_reqwest
        );
        std::process::exit(2);
    }

    Ok(())
}

fn lead_alternation_string(pair_count: usize) -> String {
    (0..pair_count)
        .map(|p| if p % 2 == 0 { "SR" } else { "RS" })
        .collect::<Vec<_>>()
        .join("/")
}
