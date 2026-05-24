//! Real Codex backend WebSocket streaming benchmark: Specter vs tokio-tungstenite.
//!
//! Hits wss://chatgpt.com/backend-api/codex/responses with paired samples
//! from both clients. Measures TTFT (time to first response.output_text.delta
//! text frame after sending response.create) and total wall time on a real
//! production LLM WebSocket endpoint.
//!
//! reqwest does not support WebSockets natively, so the baseline is
//! tokio-tungstenite — the canonical Rust WebSocket client.
//!
//! Skips gracefully when ~/.codex/auth.json is absent.

use serde::Serialize;
use specter::Message;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

const ENDPOINT: &str = "wss://chatgpt.com/backend-api/codex/responses";
const MODEL: &str = "gpt-5.4-mini";
const PROMPT: &str = "List the numbers 1 through 10 spelled out in English, one per line.";
const INSTRUCTIONS: &str = "You are a helpful assistant. Be concise.";
const OPENAI_BETA_HEADER: &str = "responses_websockets=2026-02-06";
const ORIGINATOR: &str = "specter_bench";
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const INTER_REQUEST_DELAY: Duration = Duration::from_secs(2);
const DEFAULT_SAMPLES: usize = 10;
const DEFAULT_WARMUP: usize = 3;
const MIN_SAMPLES: usize = 5;

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const SEC_CH_UA: &str =
    "\"Chromium\";v=\"146\", \"Not.A/Brand\";v=\"99\", \"Google Chrome\";v=\"146\"";

fn primary_claim_threshold(sample_count: usize) -> usize {
    let scaled = (sample_count * 4).div_ceil(5);
    scaled.max(2)
}

#[derive(Serialize, Clone)]
struct Row {
    client: &'static str,
    warmup: bool,
    sample_index: usize,
    pair_index: usize,
    lead_in_pair: bool,
    status: &'static str,
    handshake_status: u16,
    handshake_ms: f64,
    ttft_ms: f64,
    total_wall_time_ms: f64,
    total_chars: usize,
    delta_count: usize,
    frame_count: usize,
    completed: bool,
    chars_per_sec: f64,
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
    median_handshake_ms: f64,
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
    handshake_difference_ms: f64,
    handshake_ci_95: [f64; 2],
    handshake_ci_covers_zero: bool,
    ttft_wilcoxon_p_value: f64,
    wall_time_wilcoxon_p_value: f64,
    interpretation: String,
}

#[derive(Serialize)]
struct Summary {
    specter: ClientSummary,
    tungstenite: ClientSummary,
    comparison: Comparison,
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    specter_version: &'static str,
    specter_fingerprint: String,
    tokio_tungstenite_version: &'static str,
}

#[derive(Serialize)]
struct Artifact {
    benchmark: &'static str,
    benchmark_version: &'static str,
    date: String,
    endpoint: &'static str,
    model: &'static str,
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
    rows: Vec<Row>,
    summary: Summary,
}

struct SampleResult {
    status: &'static str,
    handshake_status: u16,
    handshake_ms: f64,
    ttft_ms: f64,
    total_wall_time_ms: f64,
    total_chars: usize,
    delta_count: usize,
    frame_count: usize,
    completed: bool,
    error: Option<String>,
}

fn build_create_message() -> String {
    let body = serde_json::json!({
        "type": "response.create",
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
    body.to_string()
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

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ---- stats helpers (copied verbatim from codex_real_streaming.rs concepts) ----

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

fn median(values: &[f64]) -> f64 {
    median_p95(values).0
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

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn today_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn now_iso_compact() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H%M%SZ").to_string()
}

// ---- Frame parsing (text JSON frames) ----

fn parse_response_frame(text: &str) -> FrameEvent {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return FrameEvent::Other,
    };
    let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    match ty {
        "response.output_text.delta" => {
            let delta = v.get("delta").and_then(|d| d.as_str()).unwrap_or("");
            FrameEvent::TextDelta(delta.to_string())
        }
        "response.completed" => FrameEvent::Completed,
        "response.failed" | "response.error" | "error" => {
            FrameEvent::Errored(text.chars().take(200).collect())
        }
        _ => FrameEvent::Other,
    }
}

enum FrameEvent {
    TextDelta(String),
    Completed,
    Errored(String),
    Other,
}

struct StreamObservation {
    first_delta: Option<Instant>,
    last_delta: Option<Instant>,
    total_chars: usize,
    delta_count: usize,
    frame_count: usize,
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
            frame_count: 0,
            completed: false,
            errored: false,
            error_msg: None,
        }
    }

    fn record(&mut self, ev: FrameEvent, now: Instant) -> bool {
        self.frame_count += 1;
        match ev {
            FrameEvent::TextDelta(s) => {
                if self.first_delta.is_none() {
                    self.first_delta = Some(now);
                }
                self.last_delta = Some(now);
                self.total_chars += s.len();
                self.delta_count += 1;
                false
            }
            FrameEvent::Completed => {
                self.completed = true;
                false
            }
            FrameEvent::Errored(msg) => {
                self.errored = true;
                self.error_msg = Some(msg);
                true
            }
            FrameEvent::Other => false,
        }
    }
}

// ---- Specter sample ----

async fn run_specter_sample(
    client: &specter::Client,
    token: &str,
    account_id: Option<&str>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    let request_id = uuid_v4();
    let session_id = uuid_v4();

    let handshake_start = Instant::now();
    let mut builder = client
        .websocket(ENDPOINT)
        .header("User-Agent", UA)
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("sec-ch-ua", SEC_CH_UA)
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"macOS\"")
        .header("Origin", "https://chatgpt.com")
        .header("Authorization", format!("Bearer {token}"))
        .header("OpenAI-Beta", OPENAI_BETA_HEADER)
        .header("originator", ORIGINATOR)
        .header("x-client-request-id", &request_id)
        .header("session_id", &session_id);
    if let Some(aid) = account_id {
        builder = builder.header("ChatGPT-Account-Id", aid);
    }

    let connect_fut = builder.connect();
    let ws_res = timeout(HANDSHAKE_TIMEOUT, connect_fut).await;
    let mut ws = match ws_res {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            return Ok(SampleResult {
                status: "handshake_error",
                handshake_status: 0,
                handshake_ms: handshake_start.elapsed().as_secs_f64() * 1000.0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                frame_count: 0,
                completed: false,
                error: Some(format!("specter handshake error: {e}")),
            });
        }
        Err(_) => {
            return Ok(SampleResult {
                status: "handshake_timeout",
                handshake_status: 0,
                handshake_ms: HANDSHAKE_TIMEOUT.as_secs_f64() * 1000.0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                frame_count: 0,
                completed: false,
                error: Some("specter handshake timeout".into()),
            });
        }
    };
    let handshake_ms = handshake_start.elapsed().as_secs_f64() * 1000.0;

    let send_start = Instant::now();
    let create_msg = build_create_message();
    if let Err(e) = ws.send_text(&create_msg).await {
        return Ok(SampleResult {
            status: "send_error",
            handshake_status: 101,
            handshake_ms,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: 0,
            delta_count: 0,
            frame_count: 0,
            completed: false,
            error: Some(format!("specter send_text error: {e}")),
        });
    }

    let mut obs = StreamObservation::new();
    let timed = timeout(STREAM_TIMEOUT, async {
        loop {
            match ws.next().await {
                Ok(Some(Message::Text(text))) => {
                    let now = Instant::now();
                    let ev = parse_response_frame(&text);
                    if obs.record(ev, now) {
                        break;
                    }
                    if obs.completed {
                        break;
                    }
                }
                Ok(Some(Message::Binary(_)))
                | Ok(Some(Message::Ping(_)))
                | Ok(Some(Message::Pong(_))) => {
                    obs.frame_count += 1;
                }
                Ok(Some(Message::Close(_))) => break,
                Ok(None) => break,
                Err(e) => {
                    return Err(format!("specter ws next error: {e}"));
                }
            }
        }
        Ok::<(), String>(())
    })
    .await;

    let _ = ws.close(None).await;

    finalize_sample(&obs, 101, handshake_ms, send_start, timed)
}

// ---- tokio-tungstenite sample ----

async fn run_tungstenite_sample(
    token: &str,
    account_id: Option<&str>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    use futures_util::SinkExt;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;
    use tokio_tungstenite::tungstenite::Message as TungMessage;

    let request_id = uuid_v4();
    let session_id = uuid_v4();

    let mut req = ENDPOINT.into_client_request()?;
    let host = req.uri().host().unwrap_or("chatgpt.com").to_string();
    let headers = req.headers_mut();
    headers.insert("Host", host.parse()?);
    headers.insert("Upgrade", "websocket".parse()?);
    headers.insert("Connection", "Upgrade".parse()?);
    headers.insert("Sec-WebSocket-Key", generate_key().parse()?);
    headers.insert("Sec-WebSocket-Version", "13".parse()?);
    headers.insert("User-Agent", UA.parse()?);
    headers.insert("Accept-Language", "en-US,en;q=0.9".parse()?);
    headers.insert("sec-ch-ua", SEC_CH_UA.parse()?);
    headers.insert("sec-ch-ua-mobile", "?0".parse()?);
    headers.insert("sec-ch-ua-platform", "\"macOS\"".parse()?);
    headers.insert("Origin", "https://chatgpt.com".parse()?);
    headers.insert("Authorization", format!("Bearer {token}").parse()?);
    headers.insert("OpenAI-Beta", OPENAI_BETA_HEADER.parse()?);
    headers.insert("originator", ORIGINATOR.parse()?);
    headers.insert("x-client-request-id", request_id.parse()?);
    headers.insert("session_id", session_id.parse()?);
    if let Some(aid) = account_id {
        headers.insert("ChatGPT-Account-Id", aid.parse()?);
    }

    let handshake_start = Instant::now();
    let connect_fut = tokio_tungstenite::connect_async(req);
    let res = timeout(HANDSHAKE_TIMEOUT, connect_fut).await;
    let (mut ws, response) = match res {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            let status_code = match &e {
                tokio_tungstenite::tungstenite::Error::Http(resp) => resp.status().as_u16(),
                _ => 0,
            };
            return Ok(SampleResult {
                status: "handshake_error",
                handshake_status: status_code,
                handshake_ms: handshake_start.elapsed().as_secs_f64() * 1000.0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                frame_count: 0,
                completed: false,
                error: Some(format!("tungstenite handshake error: {e}")),
            });
        }
        Err(_) => {
            return Ok(SampleResult {
                status: "handshake_timeout",
                handshake_status: 0,
                handshake_ms: HANDSHAKE_TIMEOUT.as_secs_f64() * 1000.0,
                ttft_ms: 0.0,
                total_wall_time_ms: 0.0,
                total_chars: 0,
                delta_count: 0,
                frame_count: 0,
                completed: false,
                error: Some("tungstenite handshake timeout".into()),
            });
        }
    };
    let handshake_status = response.status().as_u16();
    let handshake_ms = handshake_start.elapsed().as_secs_f64() * 1000.0;

    let send_start = Instant::now();
    let create_msg = build_create_message();
    if let Err(e) = ws.send(TungMessage::Text(create_msg)).await {
        return Ok(SampleResult {
            status: "send_error",
            handshake_status,
            handshake_ms,
            ttft_ms: 0.0,
            total_wall_time_ms: 0.0,
            total_chars: 0,
            delta_count: 0,
            frame_count: 0,
            completed: false,
            error: Some(format!("tungstenite send error: {e}")),
        });
    }

    let mut obs = StreamObservation::new();
    let timed = timeout(STREAM_TIMEOUT, async {
        loop {
            match ws.next().await {
                Some(Ok(TungMessage::Text(text))) => {
                    let now = Instant::now();
                    let ev = parse_response_frame(&text);
                    if obs.record(ev, now) {
                        break;
                    }
                    if obs.completed {
                        break;
                    }
                }
                Some(Ok(TungMessage::Binary(_)))
                | Some(Ok(TungMessage::Ping(_)))
                | Some(Ok(TungMessage::Pong(_)))
                | Some(Ok(TungMessage::Frame(_))) => {
                    obs.frame_count += 1;
                }
                Some(Ok(TungMessage::Close(_))) => break,
                None => break,
                Some(Err(e)) => {
                    return Err(format!("tungstenite next error: {e}"));
                }
            }
        }
        Ok::<(), String>(())
    })
    .await;

    let _ = ws.close(None).await;

    finalize_sample(&obs, handshake_status, handshake_ms, send_start, timed)
}

fn finalize_sample(
    obs: &StreamObservation,
    handshake_status: u16,
    handshake_ms: f64,
    send_start: Instant,
    timed: Result<Result<(), String>, tokio::time::error::Elapsed>,
) -> Result<SampleResult, Box<dyn std::error::Error>> {
    let ttft_ms = obs
        .first_delta
        .map(|t| t.duration_since(send_start).as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let total_wall_time_ms = obs
        .last_delta
        .map(|t| t.duration_since(send_start).as_secs_f64() * 1000.0)
        .unwrap_or(0.0);

    let (status, error) = match timed {
        Err(_) => ("timeout", Some("30s stream timeout".into())),
        Ok(Err(msg)) => ("error", Some(msg)),
        Ok(Ok(())) => {
            if obs.errored {
                ("error", obs.error_msg.clone())
            } else if obs.completed && obs.delta_count > 0 {
                ("ok", None)
            } else if obs.delta_count > 0 {
                ("error", Some("no response.completed received".into()))
            } else {
                (
                    "error",
                    obs.error_msg
                        .clone()
                        .or_else(|| Some("no deltas received".into())),
                )
            }
        }
    };

    Ok(SampleResult {
        status,
        handshake_status,
        handshake_ms,
        ttft_ms,
        total_wall_time_ms,
        total_chars: obs.total_chars,
        delta_count: obs.delta_count,
        frame_count: obs.frame_count,
        completed: obs.completed,
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
        status: sample.status,
        handshake_status: sample.handshake_status,
        handshake_ms: sample.handshake_ms,
        ttft_ms: sample.ttft_ms,
        total_wall_time_ms: sample.total_wall_time_ms,
        total_chars: sample.total_chars,
        delta_count: sample.delta_count,
        frame_count: sample.frame_count,
        completed: sample.completed,
        chars_per_sec,
        epoch_ms: now_epoch_ms(),
        error: sample.error,
    }
}

fn paired_diffs(
    rows: &[Row],
    client_a: &str,
    client_b: &str,
    field: impl Fn(&Row) -> f64,
) -> Vec<f64> {
    let mut by_pair_a: std::collections::BTreeMap<usize, f64> = Default::default();
    let mut by_pair_b: std::collections::BTreeMap<usize, f64> = Default::default();
    for r in rows.iter().filter(|r| !r.warmup && r.status == "ok") {
        if r.client == client_a {
            by_pair_a.insert(r.pair_index, field(r));
        } else if r.client == client_b {
            by_pair_b.insert(r.pair_index, field(r));
        }
    }
    by_pair_a
        .iter()
        .filter_map(|(k, a)| by_pair_b.get(k).map(|b| a - b))
        .collect()
}

fn paired_values(
    rows: &[Row],
    client: &str,
    pair_count: usize,
    field: impl Fn(&Row) -> f64,
) -> Vec<f64> {
    (0..pair_count)
        .filter_map(|p| {
            rows.iter()
                .find(|r| !r.warmup && r.pair_index == p && r.client == client && r.status == "ok")
                .map(&field)
        })
        .collect()
}

fn sample_summary(rows: &[Row], client: &str) -> ClientSummary {
    let passing: Vec<&Row> = rows
        .iter()
        .filter(|r| !r.warmup && r.client == client && r.status == "ok")
        .collect();
    if passing.is_empty() {
        return ClientSummary::default();
    }
    let ttfts: Vec<f64> = passing.iter().map(|r| r.ttft_ms).collect();
    let walls: Vec<f64> = passing.iter().map(|r| r.total_wall_time_ms).collect();
    let hs: Vec<f64> = passing.iter().map(|r| r.handshake_ms).collect();
    let cps: Vec<f64> = passing.iter().map(|r| r.chars_per_sec).collect();
    let (ttft_med, ttft_p95) = median_p95(&ttfts);
    let (wall_med, wall_p95) = median_p95(&walls);
    ClientSummary {
        median_ttft_ms: ttft_med,
        p95_ttft_ms: ttft_p95,
        median_total_wall_time_ms: wall_med,
        p95_total_wall_time_ms: wall_p95,
        median_handshake_ms: median(&hs),
        median_chars_per_sec: median(&cps),
        passing_samples: passing.len(),
    }
}

fn lead_alternation_string(pair_count: usize) -> String {
    (0..pair_count)
        .map(|p| if p % 2 == 0 { "SR" } else { "RS" })
        .collect::<Vec<_>>()
        .join("/")
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
                "docs/benchmarks/codex-ws-streaming/{}.json",
                now_iso_compact()
            ))
        });
    let specter_fingerprint = option_value(&args, "--specter-fingerprint")
        .unwrap_or_else(|| "chrome146".to_string());

    if sample_count < MIN_SAMPLES {
        eprintln!("--samples must be >= {MIN_SAMPLES}");
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
        "Codex WS streaming bench: endpoint={ENDPOINT}, model={MODEL}, samples={sample_count}, warmup={warmup_count}"
    );

    let specter_fp = match specter_fingerprint.as_str() {
        "none" => specter::FingerprintProfile::None,
        "chrome142" => specter::FingerprintProfile::Chrome142,
        "chrome143" => specter::FingerprintProfile::Chrome143,
        "chrome144" => specter::FingerprintProfile::Chrome144,
        "chrome145" => specter::FingerprintProfile::Chrome145,
        "chrome146" => specter::FingerprintProfile::Chrome146,
        other => {
            eprintln!("--specter-fingerprint must be one of: none, chrome142..146 (got {other})");
            std::process::exit(1);
        }
    };
    println!("specter_fingerprint={specter_fingerprint}");
    let specter_client = specter::Client::builder()
        .fingerprint(specter_fp)
        .build()?;

    let mut rows: Vec<Row> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    // Warmup
    for w in 0..warmup_count {
        let lead_specter = w % 2 == 0;
        let order = if lead_specter { ["s", "t"] } else { ["t", "s"] };
        for (i, c) in order.iter().enumerate() {
            let sample = if *c == "s" {
                run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
            } else {
                run_tungstenite_sample(&token, account_id.as_deref()).await?
            };
            let client_name = if *c == "s" { "specter" } else { "tungstenite" };
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

    // Counted samples
    let pair_count = sample_count / 2;
    for p in 0..pair_count {
        let lead_specter = p % 2 == 0;
        let order = if lead_specter {
            ("specter", "tungstenite")
        } else {
            ("tungstenite", "specter")
        };

        let sample1 = if order.0 == "specter" {
            run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
        } else {
            run_tungstenite_sample(&token, account_id.as_deref()).await?
        };
        rows.push(row_from_sample(sample1, order.0, false, p * 2, p, true));
        tokio::time::sleep(INTER_REQUEST_DELAY).await;

        let sample2 = if order.1 == "specter" {
            run_specter_sample(&specter_client, &token, account_id.as_deref()).await?
        } else {
            run_tungstenite_sample(&token, account_id.as_deref()).await?
        };
        rows.push(row_from_sample(
            sample2,
            order.1,
            false,
            p * 2 + 1,
            p,
            false,
        ));
        if p < pair_count - 1 {
            tokio::time::sleep(INTER_REQUEST_DELAY).await;
        }
    }

    // Pass counting
    let mut passed_pairs = 0usize;
    for p in 0..pair_count {
        let s_ok = rows.iter().any(|r| {
            !r.warmup
                && r.pair_index == p
                && r.client == "specter"
                && r.status == "ok"
                && r.completed
                && r.delta_count >= 1
        });
        let t_ok = rows.iter().any(|r| {
            !r.warmup
                && r.pair_index == p
                && r.client == "tungstenite"
                && r.status == "ok"
                && r.completed
                && r.delta_count >= 1
        });
        if s_ok && t_ok {
            passed_pairs += 1;
        } else {
            failures.push(format!("pair {p}: specter_ok={s_ok} tungstenite_ok={t_ok}"));
        }
    }

    let threshold = primary_claim_threshold(sample_count);
    let primary_claim = if passed_pairs * 2 >= threshold {
        "pass"
    } else {
        "fail"
    };

    // Stats
    let specter_summary = sample_summary(&rows, "specter");
    let tungstenite_summary = sample_summary(&rows, "tungstenite");

    let ttft_diffs = paired_diffs(&rows, "specter", "tungstenite", |r| r.ttft_ms);
    let wall_diffs = paired_diffs(&rows, "specter", "tungstenite", |r| r.total_wall_time_ms);
    let hs_diffs = paired_diffs(&rows, "specter", "tungstenite", |r| r.handshake_ms);

    let (ttft_diff_mean, ttft_ci) = t_ci_95(&ttft_diffs);
    let (wall_diff_mean, wall_ci) = t_ci_95(&wall_diffs);
    let (hs_diff_mean, hs_ci) = t_ci_95(&hs_diffs);

    let specter_ttfts = paired_values(&rows, "specter", pair_count, |r| r.ttft_ms);
    let tung_ttfts = paired_values(&rows, "tungstenite", pair_count, |r| r.ttft_ms);
    let specter_walls = paired_values(&rows, "specter", pair_count, |r| r.total_wall_time_ms);
    let tung_walls = paired_values(&rows, "tungstenite", pair_count, |r| r.total_wall_time_ms);

    let ttft_wilcoxon = paired_wilcoxon_signed_rank_p_value(&tung_ttfts, &specter_ttfts);
    let wall_wilcoxon = paired_wilcoxon_signed_rank_p_value(&tung_walls, &specter_walls);

    let ttft_ci_covers_zero = ttft_ci[0] <= 0.0 && ttft_ci[1] >= 0.0;
    let wall_ci_covers_zero = wall_ci[0] <= 0.0 && wall_ci[1] >= 0.0;
    let hs_ci_covers_zero = hs_ci[0] <= 0.0 && hs_ci[1] >= 0.0;

    let interpretation = if ttft_ci_covers_zero && wall_ci_covers_zero && hs_ci_covers_zero {
        format!(
            "All differences within network noise at n={pair_count}. Both clients streamed successfully from Codex WS."
        )
    } else if !ttft_ci_covers_zero && ttft_diff_mean < 0.0 {
        format!(
            "Specter WS TTFT measurably faster: {ttft_diff_mean:.1} ms [{:.1}, {:.1}] (95% CI excludes zero). Wall CI {}, handshake CI {}.",
            ttft_ci[0],
            ttft_ci[1],
            if wall_ci_covers_zero { "covers zero" } else { "excludes zero" },
            if hs_ci_covers_zero { "covers zero" } else { "excludes zero" }
        )
    } else if !ttft_ci_covers_zero && ttft_diff_mean > 0.0 {
        format!(
            "tungstenite WS TTFT measurably faster by {:.1} ms [{:.1}, {:.1}]. Investigate Specter WS read loop.",
            ttft_diff_mean.abs(),
            ttft_ci[0],
            ttft_ci[1]
        )
    } else {
        format!(
            "Mixed: TTFT CI={:.1?}, wall CI={:.1?}, handshake CI={:.1?}",
            ttft_ci, wall_ci, hs_ci
        )
    };

    let summary = Summary {
        specter: specter_summary,
        tungstenite: tungstenite_summary,
        comparison: Comparison {
            ttft_difference_ms: ttft_diff_mean,
            ttft_ci_95: ttft_ci,
            ttft_ci_covers_zero,
            wall_time_difference_ms: wall_diff_mean,
            wall_time_ci_95: wall_ci,
            wall_time_ci_covers_zero: wall_ci_covers_zero,
            handshake_difference_ms: hs_diff_mean,
            handshake_ci_95: hs_ci,
            handshake_ci_covers_zero: hs_ci_covers_zero,
            ttft_wilcoxon_p_value: ttft_wilcoxon,
            wall_time_wilcoxon_p_value: wall_wilcoxon,
            interpretation,
        },
    };

    let artifact = Artifact {
        benchmark: "codex_ws_streaming",
        benchmark_version: "1",
        date: today_iso(),
        endpoint: ENDPOINT,
        model: MODEL,
        warmup_count,
        sample_count,
        inter_request_delay_ms: INTER_REQUEST_DELAY.as_millis() as u64,
        lead_alternation: lead_alternation_string(pair_count),
        primary_claim,
        primary_claim_passed: passed_pairs * 2,
        primary_claim_total: pair_count * 2,
        primary_claim_threshold: threshold,
        primary_claim_definition: "WebSocket connect, send response.create, receive >=1 response.output_text.delta AND response.completed text frame within 30s; pass if >=ceil(0.8*N) of N samples (counted per-pair, both clients must pass)",
        failures: failures.clone(),
        environment: Environment {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            specter_version: env!("CARGO_PKG_VERSION"),
            specter_fingerprint: specter_fingerprint.clone(),
            tokio_tungstenite_version: "0.24",
        },
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
        "primary_claim={primary_claim} ({}/{} samples; {} pairs ok)",
        passed_pairs * 2,
        pair_count * 2,
        passed_pairs
    );
    println!(
        "interpretation: {}",
        artifact.summary.comparison.interpretation
    );

    Ok(())
}
