use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::future::poll_fn;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use specter::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};

const QUICHE_MAX_DATAGRAM_SIZE: usize = 1350;
const LOCAL_FIXTURE_MAX_STREAMS: u64 = 10_000;
const DEFAULT_ADAPTER_TIMEOUT_SECS: u64 = 30;
fn adapter_timeout() -> Duration {
    let secs = std::env::var("SPECTER_BENCH_ADAPTER_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ADAPTER_TIMEOUT_SECS);
    Duration::from_secs(secs)
}
const LOCAL_FIXTURE_CHUNK_SIZE: usize = 16 * 1024;
const LOCAL_FIXTURE_CHUNK_COUNT: usize = 5;
const LOCAL_FIXTURE_CHUNK_DELAY_MS: u64 = 1;
const LOCAL_FIXTURE_H3_STREAM_SEGMENT_SIZE: usize = 1_200;
const LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE: usize = 1_024;
const LOCAL_FIXTURE_TUNNEL_MIXED_MESSAGES: usize = 40;
const LOCAL_FIXTURE_TUNNEL_SLOW_CONSUMER_DELAY_MS: u64 = 25;
const LOCAL_FIXTURE_TUNNEL_SLOW_READ_DELAY_MS: u64 = 1;
const LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE: usize = 1_024;
const RFC9220_TUNNEL_MIN_SAMPLE_COUNT: usize = 100;
const QUINN_TRANSPORT_ALPN: &[u8] = b"specter-transport-bench";

#[derive(Debug, Serialize)]
struct Artifact {
    benchmark: &'static str,
    benchmark_version: &'static str,
    audited_at: &'static str,
    competitors: Vec<CompetitorSpec>,
    rows: Vec<BenchmarkRow>,
    fixture_events: Vec<FixtureEvent>,
    superiority_gate: SuperiorityGate,
    rfc9220_tunnel_superiority_gate: Rfc9220TunnelSuperiorityGate,
}

#[derive(Debug, Serialize)]
struct CompetitorSpec {
    id: &'static str,
    crate_name: &'static str,
    version: &'static str,
    role: &'static str,
    required_for_superiority: bool,
    invocation_notes: &'static str,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct BenchmarkRow {
    competitor_id: String,
    status: String,
    p50_ttft_ns: Option<f64>,
    p95_ttft_ns: Option<f64>,
    bytes_per_sec: Option<f64>,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sample_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureEvent {
    client: String,
    level: &'static str,
    kind: &'static str,
    classification: &'static str,
    category: &'static str,
    fatal: bool,
    message: String,
    datagram: Option<String>,
    app_ready: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FixtureErrorClassification {
    level: &'static str,
    kind: &'static str,
    classification: &'static str,
    category: &'static str,
    fatal: bool,
}

#[derive(Debug, Default)]
struct LocalFixtureMeasurements {
    rows: Vec<BenchmarkRow>,
    fixture_events: Vec<FixtureEvent>,
}

#[derive(Debug, Serialize)]
struct SuperiorityGate {
    status: &'static str,
    pass: bool,
    reason: &'static str,
    fastest_non_specter_h3_client: Option<&'static str>,
    no_h3_superiority_claim_without_all_required_rows: bool,
    required_h3_clients: Vec<&'static str>,
    missing_required_rows: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct Rfc9220TunnelSuperiorityGate {
    status: &'static str,
    pass: bool,
    reason: &'static str,
    fastest_non_specter_rfc9220_tunnel_client: Option<&'static str>,
    no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows: bool,
    minimum_sample_count: usize,
    required_rfc9220_tunnel_clients: Vec<&'static str>,
    missing_required_rfc9220_tunnel_rows: Vec<&'static str>,
    under_sampled_required_rfc9220_tunnel_rows: Vec<&'static str>,
    missing_required_rfc9220_tunnel_metrics: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct MeasuredMetrics {
    competitor_id: &'static str,
    p50_ttft_ns: f64,
    p95_ttft_ns: f64,
    bytes_per_sec: f64,
}

#[derive(Debug, Clone, Copy)]
struct AdapterSample {
    ttft_ns: f64,
    total_ns: f64,
    bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct RowContext {
    protocol: &'static str,
    workload: &'static str,
    default_payload_bytes: Option<usize>,
    notes: Option<&'static str>,
}

impl AdapterSample {
    fn new(ttft_ns: f64, total_ns: f64, bytes: u64) -> Self {
        Self {
            ttft_ns,
            total_ns,
            bytes,
        }
    }
}

fn specter_package_version() -> &'static str {
    include_str!("../../../Cargo.toml")
        .lines()
        .find_map(|line| line.trim().strip_prefix("version = "))
        .map(|version| version.trim_matches('"'))
        .unwrap_or("path ../..")
}

fn competitor_specs() -> Vec<CompetitorSpec> {
    vec![
        CompetitorSpec {
            id: "specter_native",
            crate_name: "specters",
            version: specter_package_version(),
            role: "candidate",
            required_for_superiority: true,
            invocation_notes: "Specter native H3 backend; no quiche in the package graph.",
        },
        CompetitorSpec {
            id: "specter_native_rfc9220_tunnel",
            crate_name: "specters",
            version: specter_package_version(),
            role: "h3_tunnel_workload",
            required_for_superiority: false,
            invocation_notes: "Specter native RFC 9220 WebSocket-over-H3 tunnel echo workload.",
        },
        CompetitorSpec {
            id: "specter_native_rfc9220_tunnel_close",
            crate_name: "specters",
            version: specter_package_version(),
            role: "h3_tunnel_workload",
            required_for_superiority: false,
            invocation_notes:
                "Specter native RFC 9220 tunnel echo with client FIN and server FIN timing.",
        },
        CompetitorSpec {
            id: "specter_native_rfc9220_tunnel_mixed",
            crate_name: "specters",
            version: specter_package_version(),
            role: "h3_tunnel_workload",
            required_for_superiority: false,
            invocation_notes:
                "Specter native RFC 9220 slow-consumer tunnel plus concurrent H3 streaming workload.",
        },
        CompetitorSpec {
            id: "quiche_direct_rfc9220_tunnel",
            crate_name: "quiche",
            version: "0.29.0",
            role: "h3_tunnel_comparator",
            required_for_superiority: false,
            invocation_notes:
                "Low-level quiche Extended CONNECT/WebSocket-over-H3 tunnel comparator adapter.",
        },
        CompetitorSpec {
            id: "tokio_quiche_rfc9220_tunnel",
            crate_name: "tokio-quiche",
            version: "0.19.0",
            role: "h3_tunnel_comparator",
            required_for_superiority: false,
            invocation_notes:
                "tokio-quiche Extended CONNECT/WebSocket-over-H3 tunnel comparator adapter.",
        },
        CompetitorSpec {
            id: "h3_quinn_rfc9220_tunnel",
            crate_name: "h3+h3-quinn",
            version: "h3 0.0.8 / h3-quinn 0.0.10",
            role: "unsupported_h3_tunnel_comparator",
            required_for_superiority: false,
            invocation_notes:
                "Unsupported in this harness: h3 0.0.8 has no WebSocket protocol surface for RFC 9220.",
        },
        CompetitorSpec {
            id: "reqwest_h3_rfc9220_tunnel",
            crate_name: "reqwest",
            version: "0.13.3",
            role: "unsupported_h3_tunnel_comparator",
            required_for_superiority: false,
            invocation_notes:
                "Unsupported in this harness: reqwest H3 exposes request/response APIs, not an RFC 9220 tunnel API.",
        },
        CompetitorSpec {
            id: "quiche_direct",
            crate_name: "quiche",
            version: "0.29.0",
            role: "h3_client",
            required_for_superiority: true,
            invocation_notes: "Direct Cloudflare quiche H3 client adapter.",
        },
        CompetitorSpec {
            id: "tokio_quiche",
            crate_name: "tokio-quiche",
            version: "0.19.0",
            role: "h3_client",
            required_for_superiority: true,
            invocation_notes: "Async Cloudflare quiche wrapper adapter.",
        },
        CompetitorSpec {
            id: "h3_quinn",
            crate_name: "h3+h3-quinn",
            version: "h3 0.0.8 / h3-quinn 0.0.10",
            role: "h3_client",
            required_for_superiority: true,
            invocation_notes: "hyperium h3 client over Quinn.",
        },
        CompetitorSpec {
            id: "reqwest_h3",
            crate_name: "reqwest",
            version: "0.13.3",
            role: "h3_client",
            required_for_superiority: true,
            invocation_notes:
                "Run with --features reqwest-h3 and RUSTFLAGS='--cfg reqwest_unstable'.",
        },
        CompetitorSpec {
            id: "tokio_tungstenite_rfc9220",
            crate_name: "tokio-tungstenite",
            version: "0.24.0",
            role: "unsupported_h3_websocket_client",
            required_for_superiority: false,
            invocation_notes:
                "RFC 6455-over-H1 WebSocket client; no RFC 9220/H3 transport in this harness.",
        },
        CompetitorSpec {
            id: "reqwest_rfc9220",
            crate_name: "reqwest",
            version: "0.13.3",
            role: "unsupported_h3_websocket_client",
            required_for_superiority: false,
            invocation_notes: "HTTP client with H3 support; no native WebSocket/RFC 9220 API.",
        },
        CompetitorSpec {
            id: "quinn_transport",
            crate_name: "quinn",
            version: "0.11.9",
            role: "quic_transport_baseline",
            required_for_superiority: false,
            invocation_notes: "QUIC transport-only baseline, not an H3 superiority gate member.",
        },
        CompetitorSpec {
            id: "s2n_quic_transport",
            crate_name: "s2n-quic",
            version: "1.80.0",
            role: "quic_transport_baseline",
            required_for_superiority: false,
            invocation_notes:
                "Optional QUIC transport-only baseline via --features s2n-quic-transport.",
        },
    ]
}

fn specter_row_from_streaming_artifact(artifact_json: &str) -> Option<BenchmarkRow> {
    let artifact: Value = serde_json::from_str(artifact_json).ok()?;
    let row = artifact.get("rows")?.as_array()?.iter().find(|row| {
        row.get("protocol").and_then(Value::as_str) == Some("h3")
            && row.get("client").and_then(Value::as_str) == Some("specter")
    })?;
    let metrics = row.get("metrics")?;
    let pass = metrics
        .get("pass")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let p50_ttft_ns = metrics
        .get("p50_ns")
        .or_else(|| metrics.get("ttft_ns"))
        .and_then(Value::as_f64);
    let p95_ttft_ns = metrics.get("p95_ns").and_then(Value::as_f64);
    let bytes_per_sec = metrics.get("bytes_per_sec").and_then(Value::as_f64);

    let mut row = BenchmarkRow {
        competitor_id: "specter_native".into(),
        status: if pass {
            "measured_pass"
        } else {
            "measured_fail"
        }
        .into(),
        p50_ttft_ns,
        p95_ttft_ns,
        bytes_per_sec,
        source: "streaming_vs_reqwest_h3_artifact".into(),
        ..BenchmarkRow::default()
    };
    apply_row_context(&mut row, None);
    Some(row)
}

fn competitor_rows_from_artifact(artifact_json: &str) -> Vec<BenchmarkRow> {
    #[derive(Deserialize)]
    struct RowsArtifact {
        rows: Vec<BenchmarkRow>,
    }

    serde_json::from_str::<RowsArtifact>(artifact_json)
        .map(|artifact| artifact.rows)
        .unwrap_or_default()
}

fn adapter_row_from_samples(
    competitor_id: &'static str,
    source: &'static str,
    samples: &[AdapterSample],
) -> BenchmarkRow {
    let mut ttft_samples = samples
        .iter()
        .map(|sample| sample.ttft_ns)
        .collect::<Vec<_>>();
    ttft_samples.sort_by(f64::total_cmp);
    let total_bytes = samples.iter().map(|sample| sample.bytes).sum::<u64>();
    let total_ns = samples.iter().map(|sample| sample.total_ns).sum::<f64>();

    let mut row = BenchmarkRow {
        competitor_id: competitor_id.into(),
        status: if samples.is_empty() {
            "measured_fail"
        } else {
            "measured_pass"
        }
        .into(),
        p50_ttft_ns: percentile(&ttft_samples, 0.50),
        p95_ttft_ns: percentile(&ttft_samples, 0.95),
        bytes_per_sec: if total_ns > 0.0 {
            Some((total_bytes as f64) * 1_000_000_000.0 / total_ns)
        } else {
            None
        },
        source: source.into(),
        ..BenchmarkRow::default()
    };
    apply_row_context(&mut row, Some(samples.len()));
    if let Some(payload_bytes) = uniform_payload_bytes(samples) {
        row.payload_bytes = Some(payload_bytes);
    }
    row
}

fn uniform_payload_bytes(samples: &[AdapterSample]) -> Option<usize> {
    let first = usize::try_from(samples.first()?.bytes).ok()?;
    samples
        .iter()
        .all(|sample| usize::try_from(sample.bytes).ok() == Some(first))
        .then_some(first)
}

#[cfg(test)]
fn quiche_direct_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("quiche_direct", "quiche_direct_adapter", samples)
}

#[cfg(test)]
fn specter_native_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("specter_native", "specter_native_adapter", samples)
}

fn specter_native_rfc9220_tunnel_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples(
        "specter_native_rfc9220_tunnel",
        "specter_native_rfc9220_tunnel_adapter",
        samples,
    )
}

fn specter_native_rfc9220_tunnel_close_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples(
        "specter_native_rfc9220_tunnel_close",
        "specter_native_rfc9220_tunnel_close_adapter",
        samples,
    )
}

fn specter_native_rfc9220_tunnel_mixed_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples(
        "specter_native_rfc9220_tunnel_mixed",
        "specter_native_rfc9220_tunnel_mixed_adapter",
        samples,
    )
}

fn quiche_direct_rfc9220_tunnel_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples(
        "quiche_direct_rfc9220_tunnel",
        "quiche_direct_rfc9220_tunnel_adapter",
        samples,
    )
}

fn tokio_quiche_rfc9220_tunnel_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples(
        "tokio_quiche_rfc9220_tunnel",
        "tokio_quiche_rfc9220_tunnel_adapter",
        samples,
    )
}

fn quinn_transport_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("quinn_transport", "quinn_transport_adapter", samples)
}

#[cfg(any(test, feature = "s2n-quic-transport"))]
fn s2n_quic_transport_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("s2n_quic_transport", "s2n_quic_transport_adapter", samples)
}

#[cfg(test)]
fn tokio_quiche_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("tokio_quiche", "tokio_quiche_adapter", samples)
}

#[cfg(test)]
fn h3_quinn_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("h3_quinn", "h3_quinn_adapter", samples)
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> Option<f64> {
    if sorted_samples.is_empty() {
        return None;
    }
    let rank = (percentile * sorted_samples.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted_samples.len() - 1);
    Some(sorted_samples[index])
}

fn row_context(competitor_id: &str) -> Option<RowContext> {
    match competitor_id {
        "specter_native" | "quiche_direct" | "tokio_quiche" | "h3_quinn" | "reqwest_h3" => {
            Some(RowContext {
                protocol: "h3",
                workload: "http3_streaming_get",
                default_payload_bytes: Some(LOCAL_FIXTURE_CHUNK_SIZE * LOCAL_FIXTURE_CHUNK_COUNT),
                notes: None,
            })
        }
        "specter_native_rfc9220_tunnel" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("Measured Specter raw byte tunnel over RFC9220 Extended CONNECT; not RFC6455 frame parsing."),
        }),
        "specter_native_rfc9220_tunnel_close" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_close_fin",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("Measures client DATA+FIN through echoed DATA and server FIN delivery on an RFC9220 tunnel."),
        }),
        "specter_native_rfc9220_tunnel_mixed" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "slow_consumer_tunnel_plus_http3_streaming",
            default_payload_bytes: Some(
                LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE * LOCAL_FIXTURE_TUNNEL_MIXED_MESSAGES
                    + LOCAL_FIXTURE_CHUNK_SIZE * LOCAL_FIXTURE_CHUNK_COUNT,
            ),
            notes: Some("Measures a delayed-reader RFC9220 tunnel while a same-origin H3 streaming response completes."),
        }),
        "quiche_direct_rfc9220_tunnel" | "tokio_quiche_rfc9220_tunnel" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("RFC9220 comparator adapter for raw byte echo over WebSocket Extended CONNECT; excluded from the HTTP/3 superiority gate."),
        }),
        "h3_quinn_rfc9220_tunnel" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("h3/h3-quinn is tracked as unsupported for RFC9220 WebSocket tunnels until its public protocol surface exposes websocket Extended CONNECT."),
        }),
        "reqwest_h3_rfc9220_tunnel" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("reqwest_h3 is tracked as unsupported for RFC9220 WebSocket tunnels because reqwest does not expose a bidirectional H3 tunnel API."),
        }),
        "tokio_tungstenite_rfc9220" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("tokio-tungstenite is an RFC6455-over-H1 client and has no RFC9220/H3 transport here; not a throughput comparator."),
        }),
        "reqwest_rfc9220" => Some(RowContext {
            protocol: "h3_rfc9220",
            workload: "websocket_over_h3_raw_tunnel_echo",
            default_payload_bytes: Some(LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE),
            notes: Some("reqwest can measure H3 HTTP rows but does not expose a native WebSocket/RFC9220 API; not a throughput comparator."),
        }),
        "quinn_transport" | "s2n_quic_transport" => Some(RowContext {
            protocol: "quic",
            workload: "bidirectional_echo_transport",
            default_payload_bytes: Some(LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE),
            notes: Some("QUIC transport-only echo baseline; not an H3 HTTP or RFC9220 comparator."),
        }),
        _ => None,
    }
}

fn apply_row_context(row: &mut BenchmarkRow, sample_count: Option<usize>) {
    let Some(context) = row_context(&row.competitor_id) else {
        if row.sample_count.is_none() {
            row.sample_count = sample_count;
        }
        return;
    };
    if row.protocol.is_none() {
        row.protocol = Some(context.protocol.into());
    }
    if row.workload.is_none() {
        row.workload = Some(context.workload.into());
    }
    if row.payload_bytes.is_none() {
        row.payload_bytes = context.default_payload_bytes;
    }
    if row.sample_count.is_none() {
        row.sample_count = sample_count;
    }
    if row.notes.is_none() {
        row.notes = context.notes.map(str::to_string);
    }
}

fn local_native_fixture_measurement_plan() -> Vec<&'static str> {
    let mut plan = vec![
        "specter_native",
        "quiche_direct",
        "tokio_quiche",
        "h3_quinn",
    ];
    #[cfg(feature = "reqwest-h3")]
    {
        plan.push("reqwest_h3");
    }
    plan.push("quinn_transport");
    #[cfg(feature = "s2n-quic-transport")]
    {
        plan.push("s2n_quic_transport");
    }
    plan.push("specter_native_rfc9220_tunnel");
    plan.push("specter_native_rfc9220_tunnel_close");
    plan.push("specter_native_rfc9220_tunnel_mixed");
    plan.push("quiche_direct_rfc9220_tunnel");
    plan.push("tokio_quiche_rfc9220_tunnel");
    plan
}

fn local_native_fixture_measurement_plan_for(
    selected_client: Option<&str>,
) -> anyhow::Result<Vec<&'static str>> {
    let plan = local_native_fixture_measurement_plan();
    if let Some(selected_client) = selected_client {
        if let Some(client) = plan
            .iter()
            .copied()
            .find(|client| *client == selected_client)
        {
            return Ok(vec![client]);
        }
        anyhow::bail!("unknown local native fixture client {selected_client}");
    }
    Ok(plan)
}

fn placeholder_rows(
    imported_specter_row: Option<BenchmarkRow>,
    imported_competitor_rows: &[BenchmarkRow],
) -> Vec<BenchmarkRow> {
    competitor_specs()
        .into_iter()
        .map(|spec| {
            if let Some(row) = best_imported_competitor_row(imported_competitor_rows, spec.id) {
                let mut row = row.clone();
                apply_row_context(&mut row, None);
                return row;
            }
            if spec.id == "specter_native" {
                if let Some(row) = imported_specter_row.as_ref() {
                    let mut row = row.clone();
                    apply_row_context(&mut row, None);
                    return row;
                }
            }
            if let Some(row) = unsupported_rfc9220_comparator_row(spec.id) {
                return row;
            }
            let mut row = BenchmarkRow {
                competitor_id: spec.id.into(),
                status: if spec.id == "specter_native" {
                    "pending_measurement"
                } else if matches!(
                    spec.id,
                    "quiche_direct_rfc9220_tunnel" | "tokio_quiche_rfc9220_tunnel"
                ) {
                    "pending_measurement"
                } else {
                    "pending_adapter"
                }
                .into(),
                p50_ttft_ns: None,
                p95_ttft_ns: None,
                bytes_per_sec: None,
                source: "native_h3_vs_rust_clients_harness".into(),
                ..BenchmarkRow::default()
            };
            apply_row_context(&mut row, None);
            row
        })
        .collect()
}

fn unsupported_rfc9220_comparator_row(competitor_id: &str) -> Option<BenchmarkRow> {
    matches!(
        competitor_id,
        "tokio_tungstenite_rfc9220"
            | "reqwest_rfc9220"
            | "h3_quinn_rfc9220_tunnel"
            | "reqwest_h3_rfc9220_tunnel"
    )
    .then(|| {
        let mut row = BenchmarkRow {
            competitor_id: competitor_id.into(),
            status: "unsupported_by_client".into(),
            source: "capability_audit".into(),
            ..BenchmarkRow::default()
        };
        apply_row_context(&mut row, None);
        row
    })
}

fn best_imported_competitor_row<'a>(
    rows: &'a [BenchmarkRow],
    competitor_id: &str,
) -> Option<&'a BenchmarkRow> {
    rows.iter()
        .filter(|row| row.competitor_id == competitor_id)
        .max_by_key(|row| imported_row_status_rank(row.status.as_str()))
}

fn imported_row_status_rank(status: &str) -> u8 {
    match status {
        "measured_pass" => 3,
        "measured_fail" => 2,
        "pending_adapter" | "pending_measurement" => 0,
        _ => 1,
    }
}

fn superiority_gate(rows: &[BenchmarkRow]) -> SuperiorityGate {
    let specs = competitor_specs();
    let required_h3_clients = specs
        .iter()
        .filter(|spec| spec.required_for_superiority && spec.role != "candidate")
        .map(|spec| spec.id)
        .collect::<Vec<_>>();
    let missing_required_rows = required_h3_clients
        .iter()
        .copied()
        .filter(|id| {
            rows.iter()
                .find(|row| row.competitor_id == *id)
                .is_none_or(|row| row.status != "measured_pass")
        })
        .collect::<Vec<_>>();

    let specter_metrics = measured_metrics(rows, "specter_native");
    let competitor_metrics = required_h3_clients
        .iter()
        .filter_map(|id| measured_metrics(rows, id))
        .collect::<Vec<_>>();
    let fastest_non_specter_h3_client =
        fastest_by_p50_then_p95_then_throughput(&competitor_metrics);

    let missing_metrics = missing_required_rows.is_empty()
        && (specter_metrics.is_none() || competitor_metrics.len() != required_h3_clients.len());
    let specter_beats_all_required = specter_metrics.is_some_and(|specter| {
        competitor_metrics.iter().all(|competitor| {
            specter.p50_ttft_ns < competitor.p50_ttft_ns
                && specter.p95_ttft_ns < competitor.p95_ttft_ns
                && specter.bytes_per_sec > competitor.bytes_per_sec
        })
    });
    let pass = missing_required_rows.is_empty() && !missing_metrics && specter_beats_all_required;

    SuperiorityGate {
        status: if pass {
            "pass"
        } else if missing_required_rows.is_empty() && !missing_metrics {
            "fail"
        } else {
            "incomplete"
        },
        pass,
        reason: if pass {
            "specter_native_is_faster_than_required_h3_competitors"
        } else if !missing_required_rows.is_empty() {
            "no_h3_superiority_claim_without_all_required_rows"
        } else if missing_metrics {
            "missing_required_h3_performance_metrics"
        } else {
            "specter_native_not_faster_than_required_h3_competitors"
        },
        fastest_non_specter_h3_client,
        no_h3_superiority_claim_without_all_required_rows: true,
        required_h3_clients,
        missing_required_rows,
    }
}

fn required_rfc9220_tunnel_clients() -> Vec<&'static str> {
    vec![
        "specter_native_rfc9220_tunnel",
        "quiche_direct_rfc9220_tunnel",
        "tokio_quiche_rfc9220_tunnel",
    ]
}

fn rfc9220_tunnel_superiority_gate(rows: &[BenchmarkRow]) -> Rfc9220TunnelSuperiorityGate {
    let required_rfc9220_tunnel_clients = required_rfc9220_tunnel_clients();
    let comparator_clients = required_rfc9220_tunnel_clients
        .iter()
        .copied()
        .filter(|id| *id != "specter_native_rfc9220_tunnel")
        .collect::<Vec<_>>();
    let missing_required_rfc9220_tunnel_rows = required_rfc9220_tunnel_clients
        .iter()
        .copied()
        .filter(|id| {
            rows.iter()
                .find(|row| row.competitor_id == *id)
                .is_none_or(|row| row.status != "measured_pass")
        })
        .collect::<Vec<_>>();
    let under_sampled_required_rfc9220_tunnel_rows = required_rfc9220_tunnel_clients
        .iter()
        .copied()
        .filter(|id| {
            rows.iter()
                .find(|row| row.competitor_id == *id && row.status == "measured_pass")
                .is_some_and(|row| {
                    row.sample_count
                        .is_none_or(|sample_count| sample_count < RFC9220_TUNNEL_MIN_SAMPLE_COUNT)
                })
        })
        .collect::<Vec<_>>();
    let missing_required_rfc9220_tunnel_metrics = if missing_required_rfc9220_tunnel_rows.is_empty()
        && under_sampled_required_rfc9220_tunnel_rows.is_empty()
    {
        required_rfc9220_tunnel_clients
            .iter()
            .copied()
            .filter(|id| {
                measured_metrics_with_min_sample_count(rows, id, RFC9220_TUNNEL_MIN_SAMPLE_COUNT)
                    .is_none()
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let specter_metrics = measured_metrics_with_min_sample_count(
        rows,
        "specter_native_rfc9220_tunnel",
        RFC9220_TUNNEL_MIN_SAMPLE_COUNT,
    );
    let comparator_metrics = comparator_clients
        .iter()
        .filter_map(|id| {
            measured_metrics_with_min_sample_count(rows, id, RFC9220_TUNNEL_MIN_SAMPLE_COUNT)
        })
        .collect::<Vec<_>>();
    let fastest_non_specter_rfc9220_tunnel_client =
        fastest_by_p50_then_p95_then_throughput(&comparator_metrics);

    let missing_required_n100_rows = !missing_required_rfc9220_tunnel_rows.is_empty()
        || !under_sampled_required_rfc9220_tunnel_rows.is_empty();
    let missing_metrics = !missing_required_rfc9220_tunnel_metrics.is_empty();
    let specter_beats_all_required = specter_metrics.is_some_and(|specter| {
        comparator_metrics.iter().all(|competitor| {
            specter.p50_ttft_ns < competitor.p50_ttft_ns
                && specter.p95_ttft_ns < competitor.p95_ttft_ns
                && specter.bytes_per_sec > competitor.bytes_per_sec
        })
    });
    let pass = !missing_required_n100_rows
        && !missing_metrics
        && comparator_metrics.len() == comparator_clients.len()
        && specter_beats_all_required;

    Rfc9220TunnelSuperiorityGate {
        status: if pass {
            "pass"
        } else if missing_required_n100_rows || missing_metrics {
            "incomplete"
        } else {
            "fail"
        },
        pass,
        reason: if pass {
            "specter_native_rfc9220_tunnel_is_faster_than_required_rfc9220_tunnel_competitors"
        } else if missing_required_n100_rows {
            "no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows"
        } else if missing_metrics {
            "missing_required_rfc9220_tunnel_performance_metrics"
        } else {
            "specter_native_rfc9220_tunnel_not_faster_than_required_rfc9220_tunnel_competitors"
        },
        fastest_non_specter_rfc9220_tunnel_client,
        no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows: true,
        minimum_sample_count: RFC9220_TUNNEL_MIN_SAMPLE_COUNT,
        required_rfc9220_tunnel_clients,
        missing_required_rfc9220_tunnel_rows,
        under_sampled_required_rfc9220_tunnel_rows,
        missing_required_rfc9220_tunnel_metrics,
    }
}

fn measured_metrics(rows: &[BenchmarkRow], competitor_id: &'static str) -> Option<MeasuredMetrics> {
    let row = rows
        .iter()
        .find(|row| row.competitor_id == competitor_id && row.status == "measured_pass")?;
    Some(MeasuredMetrics {
        competitor_id,
        p50_ttft_ns: row.p50_ttft_ns?,
        p95_ttft_ns: row.p95_ttft_ns?,
        bytes_per_sec: row.bytes_per_sec?,
    })
}

fn measured_metrics_with_min_sample_count(
    rows: &[BenchmarkRow],
    competitor_id: &'static str,
    minimum_sample_count: usize,
) -> Option<MeasuredMetrics> {
    let row = rows
        .iter()
        .find(|row| row.competitor_id == competitor_id && row.status == "measured_pass")?;
    if row.sample_count? < minimum_sample_count {
        return None;
    }
    Some(MeasuredMetrics {
        competitor_id,
        p50_ttft_ns: row.p50_ttft_ns?,
        p95_ttft_ns: row.p95_ttft_ns?,
        bytes_per_sec: row.bytes_per_sec?,
    })
}

fn fastest_by_p50_then_p95_then_throughput(rows: &[MeasuredMetrics]) -> Option<&'static str> {
    rows.iter()
        .min_by(|left, right| {
            left.p50_ttft_ns
                .total_cmp(&right.p50_ttft_ns)
                .then_with(|| left.p95_ttft_ns.total_cmp(&right.p95_ttft_ns))
                .then_with(|| right.bytes_per_sec.total_cmp(&left.bytes_per_sec))
        })
        .map(|row| row.competitor_id)
}

#[cfg(test)]
fn artifact_with_competitor_artifacts<S: AsRef<str>>(
    specter_streaming_artifact_json: Option<&str>,
    competitor_artifact_jsons: &[S],
) -> Artifact {
    artifact_with_competitor_rows(
        specter_streaming_artifact_json,
        competitor_artifact_jsons,
        &[],
    )
}

#[cfg(test)]
fn artifact_with_competitor_rows<S: AsRef<str>>(
    specter_streaming_artifact_json: Option<&str>,
    competitor_artifact_jsons: &[S],
    measured_competitor_rows: &[BenchmarkRow],
) -> Artifact {
    artifact_with_competitor_rows_and_fixture_events(
        specter_streaming_artifact_json,
        competitor_artifact_jsons,
        measured_competitor_rows,
        Vec::new(),
    )
}

fn artifact_with_competitor_rows_and_fixture_events<S: AsRef<str>>(
    specter_streaming_artifact_json: Option<&str>,
    competitor_artifact_jsons: &[S],
    measured_competitor_rows: &[BenchmarkRow],
    fixture_events: Vec<FixtureEvent>,
) -> Artifact {
    let imported_competitor_rows = competitor_artifact_jsons
        .iter()
        .flat_map(|artifact_json| competitor_rows_from_artifact(artifact_json.as_ref()))
        .chain(measured_competitor_rows.iter().cloned())
        .collect::<Vec<_>>();
    let rows = placeholder_rows(
        specter_streaming_artifact_json.and_then(specter_row_from_streaming_artifact),
        &imported_competitor_rows,
    );
    Artifact {
        benchmark: "native_h3_vs_rust_clients",
        benchmark_version: "matrix-1",
        audited_at: "2026-05-24",
        competitors: competitor_specs(),
        superiority_gate: superiority_gate(&rows),
        rfc9220_tunnel_superiority_gate: rfc9220_tunnel_superiority_gate(&rows),
        rows,
        fixture_events,
    }
}

fn requirement_failed(args: &[String], artifact: &Artifact) -> bool {
    (args.iter().any(|arg| arg == "--require-superiority") && !artifact.superiority_gate.pass)
        || (args
            .iter()
            .any(|arg| arg == "--require-rfc9220-tunnel-superiority")
            && !artifact.rfc9220_tunnel_superiority_gate.pass)
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn option_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}

fn option_usize(args: &[String], name: &str, default: usize) -> anyhow::Result<usize> {
    option_value(args, name)
        .map(|value| value.parse::<usize>())
        .transpose()
        .map(|value| value.unwrap_or(default))
        .map_err(|err| anyhow::anyhow!("invalid {name}: {err}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let specter_streaming_artifact_json = option_value(&args, "--specter-streaming-artifact")
        .map(fs::read_to_string)
        .transpose()?;
    let competitor_artifact_jsons = option_values(&args, "--competitor-artifact")
        .into_iter()
        .map(fs::read_to_string)
        .collect::<Result<Vec<_>, _>>()?;
    let mut measured_competitor_rows = Vec::new();
    let mut fixture_events = Vec::new();
    if args
        .iter()
        .any(|arg| arg == "--measure-local-native-fixture")
    {
        let measurements = measure_local_native_fixture(
            option_usize(&args, "--warmups", 3)?,
            option_usize(&args, "--samples", 30)?,
            option_value(&args, "--measure-local-native-fixture-client").as_deref(),
        )
        .await?;
        measured_competitor_rows.extend(measurements.rows);
        fixture_events.extend(measurements.fixture_events);
    }
    if let Some(url) = option_value(&args, "--measure-specter-native-url") {
        measured_competitor_rows.push(
            measure_specter_native(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-specter-native-rfc9220-tunnel-url") {
        measured_competitor_rows.push(
            measure_specter_native_rfc9220_tunnel(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-quiche-direct-rfc9220-tunnel-url") {
        measured_competitor_rows.push(
            measure_quiche_direct_rfc9220_tunnel(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-tokio-quiche-rfc9220-tunnel-url") {
        measured_competitor_rows.push(
            measure_tokio_quiche_rfc9220_tunnel(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-specter-native-rfc9220-tunnel-close-url") {
        measured_competitor_rows.push(
            measure_specter_native_rfc9220_tunnel_close(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(tunnel_url) =
        option_value(&args, "--measure-specter-native-rfc9220-tunnel-mixed-url")
    {
        let stream_url = option_value(
            &args,
            "--measure-specter-native-rfc9220-tunnel-mixed-stream-url",
        )
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--measure-specter-native-rfc9220-tunnel-mixed-url requires --measure-specter-native-rfc9220-tunnel-mixed-stream-url"
            )
        })?;
        measured_competitor_rows.push(
            measure_specter_native_rfc9220_tunnel_mixed(
                &stream_url,
                &tunnel_url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-quinn-transport-url") {
        measured_competitor_rows.push(
            measure_quinn_transport(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-s2n-quic-transport-url") {
        let cert_path = option_value(&args, "--s2n-quic-cert")
            .map(PathBuf::from)
            .ok_or_else(|| {
                anyhow::anyhow!("--measure-s2n-quic-transport-url requires --s2n-quic-cert")
            })?;
        measured_competitor_rows.push(
            measure_s2n_quic_transport(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
                &cert_path,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-reqwest-h3-url") {
        measured_competitor_rows.push(
            measure_reqwest_h3(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-quiche-direct-url") {
        measured_competitor_rows.push(measure_quiche_direct(
            &url,
            option_usize(&args, "--warmups", 3)?,
            option_usize(&args, "--samples", 30)?,
        )?);
    }
    if let Some(url) = option_value(&args, "--measure-tokio-quiche-url") {
        measured_competitor_rows.push(
            measure_tokio_quiche(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    if let Some(url) = option_value(&args, "--measure-h3-quinn-url") {
        measured_competitor_rows.push(
            measure_h3_quinn(
                &url,
                option_usize(&args, "--warmups", 3)?,
                option_usize(&args, "--samples", 30)?,
            )
            .await?,
        );
    }
    let artifact = artifact_with_competitor_rows_and_fixture_events(
        specter_streaming_artifact_json.as_deref(),
        &competitor_artifact_jsons,
        &measured_competitor_rows,
        fixture_events,
    );

    if args.iter().any(|arg| arg == "--list") {
        for competitor in &artifact.competitors {
            println!(
                "{}\t{}\t{}\t{}",
                competitor.id, competitor.crate_name, competitor.version, competitor.role
            );
        }
        return Ok(());
    }

    let json_path = option_value(&args, "--json")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/bench-results/native-h3-vs-rust-clients.json"));
    if let Some(parent) = json_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&json_path, serde_json::to_vec_pretty(&artifact)?)?;
    println!("wrote benchmark artifact {}", json_path.display());

    if requirement_failed(&args, &artifact) {
        std::process::exit(1);
    }

    Ok(())
}

async fn measure_local_native_fixture(
    warmups: usize,
    samples: usize,
    selected_client: Option<&str>,
) -> anyhow::Result<LocalFixtureMeasurements> {
    let mut rows = Vec::new();
    let mut fixture_events = Vec::new();
    for client in local_native_fixture_measurement_plan_for(selected_client)? {
        let fixture = LocalNativeH3Fixture::start(client).await?;
        let url = fixture.stream_url();
        let row = match client {
            "specter_native" => measure_specter_native(url, warmups, samples).await,
            "quiche_direct" => measure_quiche_direct(url, warmups, samples),
            "tokio_quiche" => measure_tokio_quiche(url, warmups, samples).await,
            "h3_quinn" => measure_h3_quinn(url, warmups, samples).await,
            "quinn_transport" => {
                let fixture = LocalQuinnTransportFixture::start().await?;
                measure_quinn_transport(fixture.url(), warmups, samples).await
            }
            #[cfg(feature = "s2n-quic-transport")]
            "s2n_quic_transport" => {
                let fixture = LocalS2nQuicTransportFixture::start().await?;
                measure_s2n_quic_transport(fixture.url(), warmups, samples, fixture.cert_path())
                    .await
            }
            #[cfg(feature = "reqwest-h3")]
            "reqwest_h3" => measure_reqwest_h3(url, warmups, samples).await,
            "specter_native_rfc9220_tunnel" => {
                let tunnel_url = fixture.tunnel_url();
                measure_specter_native_rfc9220_tunnel(&tunnel_url, warmups, samples).await
            }
            "specter_native_rfc9220_tunnel_close" => {
                let tunnel_url = fixture.tunnel_url();
                measure_specter_native_rfc9220_tunnel_close(&tunnel_url, warmups, samples).await
            }
            "specter_native_rfc9220_tunnel_mixed" => {
                let tunnel_url = fixture.tunnel_url();
                measure_specter_native_rfc9220_tunnel_mixed(
                    fixture.stream_url(),
                    &tunnel_url,
                    warmups,
                    samples,
                )
                .await
            }
            "quiche_direct_rfc9220_tunnel" => {
                let tunnel_url = fixture.tunnel_url();
                measure_quiche_direct_rfc9220_tunnel(&tunnel_url, warmups, samples).await
            }
            "tokio_quiche_rfc9220_tunnel" => {
                let tunnel_url = fixture.tunnel_url();
                measure_tokio_quiche_rfc9220_tunnel(&tunnel_url, warmups, samples).await
            }
            other => anyhow::bail!("unknown local native fixture client {other}"),
        }
        .with_context(|| format!("local native fixture {client} measurement failed"))?;
        fixture_events.extend(fixture.events());
        rows.push(row);
    }
    Ok(LocalFixtureMeasurements {
        rows,
        fixture_events,
    })
}

struct LocalNativeH3Fixture {
    url: String,
    task: tokio::task::JoinHandle<()>,
    events: Arc<Mutex<Vec<FixtureEvent>>>,
}

impl LocalNativeH3Fixture {
    async fn start(client: &str) -> anyhow::Result<Self> {
        let (cert_pem, key_pem) = generate_local_fixture_cert_pem()?;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
        let port = socket.local_addr()?.port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(run_local_native_h3_fixture(
            socket,
            cert_pem,
            key_pem,
            client.to_string(),
            events.clone(),
        ));
        Ok(Self {
            url: format!("https://127.0.0.1:{port}/stream"),
            task,
            events,
        })
    }

    fn stream_url(&self) -> &str {
        &self.url
    }

    fn tunnel_url(&self) -> String {
        self.url
            .replacen("https://", "wss://", 1)
            .replacen("/stream", "/tunnel", 1)
    }

    fn events(&self) -> Vec<FixtureEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl Drop for LocalNativeH3Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct LocalQuinnTransportFixture {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl LocalQuinnTransportFixture {
    async fn start() -> anyhow::Result<Self> {
        let server_config = quinn_transport_server_config()?;
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let port = endpoint.local_addr()?.port();
        let task = tokio::spawn(run_local_quinn_transport_fixture(endpoint));
        Ok(Self {
            url: format!("quic://127.0.0.1:{port}/transport"),
            task,
        })
    }

    fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for LocalQuinnTransportFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(feature = "s2n-quic-transport")]
struct LocalS2nQuicTransportFixture {
    url: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "s2n-quic-transport")]
impl LocalS2nQuicTransportFixture {
    async fn start() -> anyhow::Result<Self> {
        let (cert_path, key_path) = write_local_fixture_cert_files("specter_s2n_transport")?;
        let mut server = s2n_quic::Server::builder()
            .with_tls((cert_path.as_path(), key_path.as_path()))?
            .with_io("127.0.0.1:0")?
            .start()?;
        let port = server.local_addr()?.port();
        let task = tokio::spawn(async move {
            run_local_s2n_quic_transport_fixture(&mut server).await;
        });
        Ok(Self {
            url: format!("quic://127.0.0.1:{port}/transport"),
            cert_path,
            key_path,
            task,
        })
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn cert_path(&self) -> &Path {
        &self.cert_path
    }
}

#[cfg(feature = "s2n-quic-transport")]
impl Drop for LocalS2nQuicTransportFixture {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.cert_path);
        let _ = fs::remove_file(&self.key_path);
    }
}

async fn run_local_quinn_transport_fixture(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            while let Ok(stream) = connection.accept_bi().await {
                tokio::spawn(async move {
                    let _ = echo_quinn_transport_stream(stream).await;
                });
            }
        });
    }
}

async fn echo_quinn_transport_stream(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> anyhow::Result<()> {
    let bytes = recv
        .read_to_end(LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE * 8)
        .await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

#[cfg(feature = "s2n-quic-transport")]
async fn run_local_s2n_quic_transport_fixture(server: &mut s2n_quic::Server) {
    while let Some(mut connection) = server.accept().await {
        tokio::spawn(async move {
            while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
                tokio::spawn(async move {
                    let _ = echo_s2n_quic_transport_stream(&mut stream).await;
                });
            }
        });
    }
}

#[cfg(feature = "s2n-quic-transport")]
async fn echo_s2n_quic_transport_stream(
    stream: &mut s2n_quic::stream::BidirectionalStream,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.receive().await? {
        bytes.extend_from_slice(chunk.as_ref());
    }
    stream.send(Bytes::from(bytes)).await?;
    stream.close().await?;
    Ok(())
}

fn generate_local_fixture_cert_pem() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let cert_path = std::env::temp_dir().join(format!("specter_native_h3_{stamp}.crt"));
    let key_path = std::env::temp_dir().join(format!("specter_native_h3_{stamp}.key"));
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp key path"))?,
            "-out",
            cert_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp cert path"))?,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=CA:FALSE",
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "openssl fixture cert generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let cert_pem = fs::read(&cert_path)?;
    let key_pem = fs::read(&key_path)?;
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    Ok((cert_pem, key_pem))
}

#[cfg(feature = "s2n-quic-transport")]
fn write_local_fixture_cert_files(prefix: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let (cert_pem, key_pem) = generate_local_fixture_cert_pem()?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let cert_path = std::env::temp_dir().join(format!("{prefix}_{stamp}.crt"));
    let key_path = std::env::temp_dir().join(format!("{prefix}_{stamp}.key"));
    fs::write(&cert_path, cert_pem)?;
    fs::write(&key_path, key_pem)?;
    Ok((cert_path, key_path))
}

async fn run_local_native_h3_fixture(
    socket: Arc<tokio::net::UdpSocket>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    client: String,
    events: Arc<Mutex<Vec<FixtureEvent>>>,
) {
    use specter::transport::h3::quic::{split_long_header_datagram, LongHeaderType};

    let mut buf = [0u8; 65535];
    let mut connections: HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut next_connection_index = 0u64;

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(_) => break,
        };
        let packet = buf[..len].to_vec();
        let long_packets = split_long_header_datagram(&packet).ok();

        if let Some(first) = long_packets
            .as_ref()
            .and_then(|packets| packets.first())
            .filter(|packet| packet.packet_type == LongHeaderType::Initial)
        {
            let conn_id = first.destination_cid.as_bytes().to_vec();
            if !connections.contains_key(&conn_id) {
                let (tx, rx) = tokio::sync::mpsc::channel(100);
                let server_source_cid = local_native_h3_server_connection_id(next_connection_index);
                next_connection_index += 1;
                connections.insert(conn_id.clone(), tx.clone());
                connections.insert(server_source_cid.as_bytes().to_vec(), tx.clone());
                spawn_local_native_h3_connection(
                    socket.clone(),
                    peer,
                    rx,
                    cert_pem.clone(),
                    key_pem.clone(),
                    client.clone(),
                    events.clone(),
                    first.destination_cid.clone(),
                    first.source_cid.clone(),
                    server_source_cid,
                );
                let _ = tx.send(packet).await;
                continue;
            }
        }

        let registered_connection_ids = connections.keys().cloned().collect::<Vec<_>>();
        let tx_to_send = route_local_native_h3_connection_id(
            &packet,
            long_packets.as_deref(),
            &registered_connection_ids,
        )
        .and_then(|conn_id| connections.get(&conn_id).cloned())
        .or_else(|| {
            if connections.len() == 1 {
                connections.values().next().cloned()
            } else {
                None
            }
        });

        if let Some(tx) = tx_to_send {
            let _ = tx.send(packet).await;
        }
    }
}

fn spawn_local_native_h3_connection(
    socket: Arc<tokio::net::UdpSocket>,
    peer: SocketAddr,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    client: String,
    events: Arc<Mutex<Vec<FixtureEvent>>>,
    client_destination_cid: specter::transport::h3::quic::ConnectionId,
    client_source_cid: specter::transport::h3::quic::ConnectionId,
    server_source_cid: specter::transport::h3::quic::ConnectionId,
) {
    let mut fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
    fingerprint.transport.initial_max_streams_bidi = LOCAL_FIXTURE_MAX_STREAMS;
    fingerprint.transport.initial_max_streams_uni = LOCAL_FIXTURE_MAX_STREAMS;
    let Ok(handshake) = specter::transport::h3::handshake::NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        server_source_cid,
    ) else {
        return;
    };

    tokio::spawn(async move {
        let (response_tx, response_rx) = tokio::sync::mpsc::channel(100);
        LocalNativeH3Connection {
            socket,
            peer,
            handshake,
            fingerprint,
            handshake_done_sent: false,
            settings_sent: false,
            rx,
            response_tx,
            response_rx,
            client,
            events,
            tunnel_streams: HashSet::new(),
        }
        .run()
        .await;
    });
}

struct LocalNativeH3Response {
    stream_id: u64,
    bytes: Bytes,
    fin: bool,
}

struct LocalNativeH3Connection {
    socket: Arc<tokio::net::UdpSocket>,
    peer: SocketAddr,
    handshake: specter::transport::h3::handshake::NativeQuicServerHandshake,
    fingerprint: specter::fingerprint::Http3Fingerprint,
    handshake_done_sent: bool,
    settings_sent: bool,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    response_tx: tokio::sync::mpsc::Sender<LocalNativeH3Response>,
    response_rx: tokio::sync::mpsc::Receiver<LocalNativeH3Response>,
    client: String,
    events: Arc<Mutex<Vec<FixtureEvent>>>,
    tunnel_streams: HashSet<u64>,
}

impl LocalNativeH3Connection {
    async fn run(mut self) {
        loop {
            let server_application_ack_deadline = self.server_application_ack_deadline();
            let server_application_ack_delay = server_application_ack_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            let server_loss_detection_deadline = self.server_loss_detection_deadline();
            let server_loss_detection_delay = server_loss_detection_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            tokio::select! {
                _ = tokio::time::sleep(server_application_ack_delay), if server_application_ack_deadline.is_some() => {
                    if let Err(error) = self.send_delayed_application_ack().await {
                        eprintln!("local native H3 fixture delayed ACK error: {error}");
                    }
                }
                _ = tokio::time::sleep(server_loss_detection_delay), if server_loss_detection_deadline.is_some() => {
                    if let Err(error) = self.handle_loss_detection_timeout().await {
                        eprintln!("local native H3 fixture loss detection error: {error}");
                    }
                }
                packet = self.rx.recv() => {
                    let Some(packet) = packet else { break };
                    if let Err(error) = self.process_datagram(&packet).await {
                        let datagram = describe_local_native_h3_datagram(&packet);
                        let app_ready = self.handshake.is_application_ready();
                        let classification = classify_local_native_h3_packet_error_with_datagram(
                            &error, app_ready, &datagram,
                        );
                        if should_log_local_native_h3_fixture_event(&classification) {
                            eprintln!(
                                "local native H3 fixture packet error: {error}; {}; app_ready={}; category={}; fatal={}",
                                datagram,
                                app_ready,
                                classification.category,
                                classification.fatal
                            );
                        }
                        self.record_event(FixtureEvent {
                            client: self.client.clone(),
                            level: classification.level,
                            kind: classification.kind,
                            classification: classification.classification,
                            category: classification.category,
                            fatal: classification.fatal,
                            message: error.to_string(),
                            datagram: Some(datagram),
                            app_ready: Some(app_ready),
                        });
                    }
                }
                response = self.response_rx.recv() => {
                    let Some(response) = response else { break };
                    if let Err(error) = self.send_response_data(response).await {
                        eprintln!("local native H3 fixture response error: {error}");
                    }
                }
            }
        }
    }

    fn record_event(&self, event: FixtureEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    async fn process_datagram(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        use specter::transport::h3::quic::{split_long_header_datagram, LongHeaderType};

        if packet.first().is_some_and(|first| first & 0x80 != 0) {
            let packets = split_long_header_datagram(packet)?;
            if packets
                .iter()
                .any(|packet| packet.packet_type == LongHeaderType::Initial)
            {
                let flight = self.handshake.process_client_initial(packet)?;
                if !flight.datagram.is_empty() {
                    self.send_packet(flight.datagram).await?;
                }
                if let Some(packet) = self.handshake.build_server_initial_ack_packet()? {
                    self.send_packet(packet.packet).await?;
                }
            }
            if packets
                .iter()
                .any(|packet| packet.packet_type == LongHeaderType::Handshake)
            {
                self.handshake.process_client_handshake(packet)?;
                if let Some(packet) = self.handshake.build_server_handshake_ack_packet()? {
                    self.send_packet(packet.packet).await?;
                }
                self.send_settings_if_ready().await?;
            }
            return Ok(());
        }

        let events = self.handshake.open_client_h3_event_packet(packet)?;
        if self.handshake.close_state().is_draining() {
            return Ok(());
        }
        if let Some(packet) = self
            .handshake
            .build_server_application_ack_packet_after_or_delay(
                self.fingerprint.transport.ack_eliciting_threshold,
                Duration::from_millis(self.fingerprint.transport.max_ack_delay_ms),
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet(packet.packet).await?;
        }
        for packet in self
            .handshake
            .build_server_receive_flow_control_update_packets()?
        {
            self.send_packet(packet.packet).await?;
        }
        let retransmits = self
            .handshake
            .retransmit_lost_server_application_stream_packets()?;
        for packet in retransmits {
            self.send_packet(packet.packet).await?;
        }
        for event in events {
            self.apply_client_event(event).await?;
        }
        Ok(())
    }

    fn server_application_ack_deadline(&self) -> Option<Instant> {
        self.handshake
            .server_application_ack_deadline(Duration::from_millis(
                self.fingerprint.transport.max_ack_delay_ms,
            ))
    }

    fn server_loss_detection_deadline(&self) -> Option<Instant> {
        self.handshake.loss_detection_timer()
    }

    async fn handle_loss_detection_timeout(&mut self) -> anyhow::Result<()> {
        let Some(timer) = self.handshake.loss_detection_timer() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < timer {
            return Ok(());
        }
        let pto = self.handshake.application_pto();
        match self.handshake.on_loss_detection_timeout(now) {
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Application,
            } => {
                for packet in self
                    .handshake
                    .retransmit_pto_server_application_stream_packets(now, pto)?
                {
                    self.send_packet(packet.packet).await?;
                }
            }
            LossDetectionOutcome::Loss {
                space: PacketNumberSpace::Application,
                ..
            } => {
                let retransmits = self
                    .handshake
                    .retransmit_lost_server_application_stream_packets()?;
                for packet in retransmits {
                    self.send_packet(packet.packet).await?;
                }
            }
            LossDetectionOutcome::Pto { .. }
            | LossDetectionOutcome::Loss { .. }
            | LossDetectionOutcome::Idle => {}
        }
        Ok(())
    }

    async fn send_delayed_application_ack(&mut self) -> anyhow::Result<()> {
        if let Some(packet) = self
            .handshake
            .build_server_application_ack_packet_with_delay(
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet(packet.packet).await?;
        }
        Ok(())
    }

    async fn send_settings_if_ready(&mut self) -> anyhow::Result<()> {
        if !self.handshake.is_application_ready() {
            return Ok(());
        }
        if !self.handshake_done_sent {
            let packet = self.handshake.build_server_handshake_done_packet()?;
            self.handshake_done_sent = true;
            self.send_packet(packet.packet).await?;
        }
        if self.settings_sent {
            return Ok(());
        }
        let packet = self
            .handshake
            .build_server_h3_settings_packet(&self.fingerprint)?;
        self.settings_sent = true;
        self.send_packet(packet.packet).await
    }

    async fn apply_client_event(
        &mut self,
        event: specter::transport::h3::handshake::ClientH3Event,
    ) -> anyhow::Result<()> {
        let specter::transport::h3::handshake::ClientH3Event::Stream(event) = event else {
            return Ok(());
        };

        for frame in event.frames {
            match frame {
                specter::transport::h3::native::H3Frame::Headers(block) => {
                    let headers =
                        specter::transport::h3::native::decode_header_block(block.as_ref())?;
                    self.handle_request_headers(event.stream_id, headers)
                        .await?;
                }
                specter::transport::h3::native::H3Frame::Data(bytes) => {
                    self.handle_request_data(event.stream_id, bytes, event.fin)
                        .await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_request_headers(
        &mut self,
        stream_id: u64,
        headers: Vec<specter::transport::h3::native::H3Header>,
    ) -> anyhow::Result<()> {
        let path = headers
            .iter()
            .find(|header| header.name() == ":path")
            .map(|header| header.value())
            .unwrap_or("/");
        let method = headers
            .iter()
            .find(|header| header.name() == ":method")
            .map(|header| header.value());
        let protocol = headers
            .iter()
            .find(|header| header.name() == ":protocol")
            .map(|header| header.value());

        if method == Some("CONNECT") && protocol == Some("websocket") {
            self.tunnel_streams.insert(stream_id);
            self.send_response_packet(stream_id, "application/octet-stream", None, false)
                .await?;
        } else if path == "/health" {
            self.send_response_packet(
                stream_id,
                "text/plain",
                Some(Bytes::from_static(b"ok")),
                true,
            )
            .await?;
        } else if path.starts_with("/stream") {
            self.send_response_packet(stream_id, "application/octet-stream", None, false)
                .await?;
            let response_tx = self.response_tx.clone();
            tokio::spawn(async move {
                for index in 0..LOCAL_FIXTURE_CHUNK_COUNT {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(LOCAL_FIXTURE_CHUNK_DELAY_MS))
                            .await;
                    }
                    let end_stream = index == LOCAL_FIXTURE_CHUNK_COUNT - 1;
                    if response_tx
                        .send(LocalNativeH3Response {
                            stream_id,
                            bytes: Bytes::from(vec![b's'; LOCAL_FIXTURE_CHUNK_SIZE]),
                            fin: end_stream,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        Ok(())
    }

    async fn handle_request_data(
        &mut self,
        stream_id: u64,
        bytes: Bytes,
        fin: bool,
    ) -> anyhow::Result<()> {
        if !self.tunnel_streams.contains(&stream_id) {
            return Ok(());
        }
        if bytes.is_empty() && !fin {
            return Ok(());
        }
        let consumed_len = bytes.len() as u64;
        self.response_tx
            .send(LocalNativeH3Response {
                stream_id,
                bytes,
                fin,
            })
            .await
            .map_err(|_| anyhow::anyhow!("local native H3 fixture response queue closed"))?;
        if consumed_len > 0 {
            // Per RFC 9000 Section 4 the absolute MAX_DATA / MAX_STREAM_DATA
            // we are willing to advertise is `initial + consumed`. The local
            // fixture consumes inbound DATA on the same task it forwards on,
            // so we record the drain here for the receive-window emitter.
            self.handshake
                .record_server_stream_consumed(stream_id, consumed_len)?;
        }
        if fin {
            self.tunnel_streams.remove(&stream_id);
        }
        Ok(())
    }

    async fn send_response_packet(
        &mut self,
        stream_id: u64,
        content_type: &str,
        body: Option<Bytes>,
        fin: bool,
    ) -> anyhow::Result<()> {
        let headers = vec![
            specter::transport::h3::native::H3Header::new(":status", "200"),
            specter::transport::h3::native::H3Header::new("content-type", content_type),
        ];
        let packet = self
            .handshake
            .build_server_h3_response_packet(stream_id, headers, body, fin)?;
        self.send_packet(packet.packet).await
    }

    async fn send_response_data(&mut self, response: LocalNativeH3Response) -> anyhow::Result<()> {
        let encoded_data = specter::transport::h3::native::encode_frame(
            &specter::transport::h3::native::H3Frame::Data(response.bytes),
        );
        let stream_id = response.stream_id;
        let response_fin = response.fin;
        let mut chunks = encoded_data
            .chunks(LOCAL_FIXTURE_H3_STREAM_SEGMENT_SIZE)
            .peekable();
        while let Some(chunk) = chunks.next() {
            let fin = response_fin && chunks.peek().is_none();
            let packet = self.handshake.build_server_h3_raw_stream_packet(
                stream_id,
                Bytes::copy_from_slice(chunk),
                fin,
            )?;
            self.send_packet(packet.packet).await?;
        }
        Ok(())
    }

    async fn send_packet(&self, packet: Bytes) -> anyhow::Result<()> {
        self.socket.send_to(packet.as_ref(), self.peer).await?;
        Ok(())
    }
}

fn route_local_native_h3_connection_id(
    packet: &[u8],
    long_packets: Option<&[specter::transport::h3::quic::LongHeaderDatagramPacket]>,
    registered_server_cids: &[Vec<u8>],
) -> Option<Vec<u8>> {
    if let Some(first) = long_packets.and_then(|packets| packets.first()) {
        return Some(first.destination_cid.as_bytes().to_vec());
    }
    if packet.first().is_some_and(|first| first & 0x80 == 0) {
        return registered_server_cids
            .iter()
            .filter(|cid| !cid.is_empty())
            .filter(|cid| packet.len() >= 1 + cid.len() && packet[1..1 + cid.len()] == cid[..])
            .max_by_key(|cid| cid.len())
            .cloned();
    }
    None
}

fn local_native_h3_server_connection_id(index: u64) -> specter::transport::h3::quic::ConnectionId {
    specter::transport::h3::quic::ConnectionId::from_bytes(Bytes::from(format!(
        "bench-h3-{index:08x}"
    )))
    .expect("local fixture server connection id must fit QUIC CID limits")
}

fn describe_local_native_h3_datagram(packet: &[u8]) -> String {
    use specter::transport::h3::quic::split_long_header_datagram;

    if packet.first().is_some_and(|first| first & 0x80 != 0) {
        return match split_long_header_datagram(packet) {
            Ok(packets) => format!(
                "len={} long={:?}",
                packet.len(),
                packets
                    .iter()
                    .map(|packet| format!(
                        "{:?}:dcid_len={}:scid_len={}",
                        packet.packet_type,
                        packet.destination_cid.as_bytes().len(),
                        packet.source_cid.as_bytes().len()
                    ))
                    .collect::<Vec<_>>()
            ),
            Err(error) => format!("len={} malformed_long={error}", packet.len()),
        };
    }
    let prefix_len = packet.len().saturating_sub(1).min(20);
    format!(
        "len={} short_prefix={:02x?}",
        packet.len(),
        &packet[1..1 + prefix_len]
    )
}

fn classify_local_native_h3_packet_error(
    error: &anyhow::Error,
    app_ready: bool,
) -> FixtureErrorClassification {
    let message = error.to_string();
    if message.contains("QUIC packet open failed") && app_ready {
        FixtureErrorClassification {
            level: "warn",
            kind: "packet_error",
            classification: "post_application_packet_open_error",
            category: "non_fatal_packet_open_after_application_ready",
            fatal: false,
        }
    } else if message.contains("QUIC packet open failed") {
        FixtureErrorClassification {
            level: "error",
            kind: "packet_error",
            classification: "handshake_packet_open_error",
            category: "fatal_packet_open_before_application_ready",
            fatal: true,
        }
    } else if message.contains("Idle timeout") && app_ready {
        FixtureErrorClassification {
            level: "warn",
            kind: "packet_error",
            classification: "idle_timeout",
            category: "non_fatal_idle_timeout_after_application_ready",
            fatal: false,
        }
    } else if message.contains("Idle timeout") {
        FixtureErrorClassification {
            level: "error",
            kind: "packet_error",
            classification: "idle_timeout",
            category: "fatal_idle_timeout_before_application_ready",
            fatal: true,
        }
    } else if app_ready {
        FixtureErrorClassification {
            level: "warn",
            kind: "packet_error",
            classification: "packet_error",
            category: "non_fatal_packet_error_after_application_ready",
            fatal: false,
        }
    } else {
        FixtureErrorClassification {
            level: "error",
            kind: "packet_error",
            classification: "packet_error",
            category: "fatal_packet_error_before_application_ready",
            fatal: true,
        }
    }
}

fn classify_local_native_h3_packet_error_with_datagram(
    error: &anyhow::Error,
    app_ready: bool,
    datagram: &str,
) -> FixtureErrorClassification {
    let message = error.to_string();
    if message.contains("QUIC packet open failed")
        && app_ready
        && datagram.contains("short_prefix=")
    {
        return FixtureErrorClassification {
            level: "debug",
            kind: "packet_noise",
            classification: "post_application_short_header_packet_open_noise",
            category: "ignored_short_header_packet_open_after_application_ready",
            fatal: false,
        };
    }
    classify_local_native_h3_packet_error(error, app_ready)
}

fn should_log_local_native_h3_fixture_event(classification: &FixtureErrorClassification) -> bool {
    classification.level != "debug"
}

async fn measure_specter_native(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let mut fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
    fingerprint.transport.ack_eliciting_threshold = 128;
    fingerprint.transport.initial_max_streams_bidi = LOCAL_FIXTURE_MAX_STREAMS;
    fingerprint.transport.initial_max_streams_uni = LOCAL_FIXTURE_MAX_STREAMS;
    let client = specter::H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_http3_fingerprint(fingerprint)
        .with_max_idle_timeout(adapter_timeout().as_millis() as u64);
    let handle = client.handle(url).await?;
    let uri: http::Uri = url.parse()?;

    for _ in 0..warmups {
        let _ = measure_specter_native_once(&handle, &uri).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_specter_native_once(&handle, &uri).await?);
    }

    Ok(adapter_row_from_samples(
        "specter_native",
        "specter_native_adapter",
        &measured,
    ))
}

async fn measure_specter_native_once(
    handle: &specter::transport::h3::H3Handle,
    uri: &http::Uri,
) -> anyhow::Result<AdapterSample> {
    let start = Instant::now();
    let mut response = handle
        .send_streaming(
            http::Method::GET,
            uri,
            Vec::new(),
            specter::RequestBody::empty(),
        )
        .await?;
    if !(200..300).contains(&response.status_code()) {
        anyhow::bail!(
            "specter_native received non-success status {}",
            response.status_code()
        );
    }

    let mut first_byte_ns = Some(start.elapsed().as_nanos() as f64);
    let mut bytes = 0u64;
    while let Some(chunk) = response.body_mut().chunk().await {
        let chunk = chunk?;
        if !chunk.is_empty() {
            first_byte_ns.get_or_insert_with(|| start.elapsed().as_nanos() as f64);
            bytes = bytes.saturating_add(chunk.len() as u64);
        }
    }

    Ok(AdapterSample::new(
        first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
        start.elapsed().as_nanos() as f64,
        bytes,
    ))
}

async fn measure_specter_native_rfc9220_tunnel(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let client = specter_rfc9220_client()?;

    for _ in 0..warmups {
        let _ = measure_specter_native_rfc9220_tunnel_once(&client, url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_specter_native_rfc9220_tunnel_once(&client, url).await?);
    }

    Ok(specter_native_rfc9220_tunnel_row_from_samples(&measured))
}

fn specter_rfc9220_client() -> anyhow::Result<specter::Client> {
    let mut fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
    fingerprint.transport.ack_eliciting_threshold = 128;
    fingerprint.transport.initial_max_streams_bidi = LOCAL_FIXTURE_MAX_STREAMS;
    fingerprint.transport.initial_max_streams_uni = LOCAL_FIXTURE_MAX_STREAMS;
    Ok(specter::Client::builder()
        .danger_accept_invalid_certs(true)
        .h3_backend(specter::H3Backend::Native)
        .h3_fingerprint(fingerprint)
        .prefer_http2(false)
        .h3_upgrade(false)
        .total_timeout(adapter_timeout())
        .build()?)
}

async fn measure_specter_native_rfc9220_tunnel_close(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let client = specter_rfc9220_client()?;
    for _ in 0..warmups {
        let _ = measure_specter_native_rfc9220_tunnel_close_once(&client, url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_specter_native_rfc9220_tunnel_close_once(&client, url).await?);
    }

    Ok(specter_native_rfc9220_tunnel_close_row_from_samples(
        &measured,
    ))
}

async fn measure_specter_native_rfc9220_tunnel_mixed(
    stream_url: &str,
    tunnel_url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let client = specter_rfc9220_client()?;
    for _ in 0..warmups {
        let _ = measure_specter_native_rfc9220_tunnel_mixed_once(&client, stream_url, tunnel_url)
            .await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(
            measure_specter_native_rfc9220_tunnel_mixed_once(&client, stream_url, tunnel_url)
                .await?,
        );
    }

    Ok(specter_native_rfc9220_tunnel_mixed_row_from_samples(
        &measured,
    ))
}

async fn measure_specter_native_rfc9220_tunnel_once(
    client: &specter::Client,
    url: &str,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'w'; LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE]);
    let start = Instant::now();
    let mut tunnel = tokio::time::timeout(adapter_timeout(), client.websocket_h3(url).open())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel open timed out"))??;

    tunnel.send_bytes(payload.clone(), false).await?;

    let echoed = tokio::time::timeout(adapter_timeout(), tunnel.recv_bytes())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel echo timed out"))?
        .ok_or_else(|| anyhow::anyhow!("specter_native RFC 9220 tunnel closed before echo"))??;
    if echoed.len() != payload.len() {
        anyhow::bail!(
            "specter_native RFC 9220 tunnel echo length mismatch: expected {}, got {}",
            payload.len(),
            echoed.len()
        );
    }

    let total_ns = start.elapsed().as_nanos() as f64;
    Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64))
}

async fn measure_specter_native_rfc9220_tunnel_close_once(
    client: &specter::Client,
    url: &str,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'c'; LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE]);
    let start = Instant::now();
    let mut tunnel = tokio::time::timeout(adapter_timeout(), client.websocket_h3(url).open())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel close open timed out"))??;

    tunnel.send_bytes(payload.clone(), true).await?;

    let echoed = tokio::time::timeout(adapter_timeout(), tunnel.recv_bytes())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel close echo timed out"))?
        .ok_or_else(|| anyhow::anyhow!("specter_native RFC 9220 tunnel close before echo"))??;
    if echoed.len() != payload.len() {
        anyhow::bail!(
            "specter_native RFC 9220 close echo length mismatch: expected {}, got {}",
            payload.len(),
            echoed.len()
        );
    }

    let end = tokio::time::timeout(adapter_timeout(), tunnel.recv_bytes())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel server FIN timed out"))?;
    if let Some(extra) = end {
        let extra = extra?;
        anyhow::bail!(
            "specter_native RFC 9220 tunnel expected server FIN, got {} extra bytes",
            extra.len()
        );
    }

    let total_ns = start.elapsed().as_nanos() as f64;
    Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64))
}

async fn measure_specter_native_rfc9220_tunnel_mixed_once(
    client: &specter::Client,
    stream_url: &str,
    tunnel_url: &str,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'm'; LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE]);
    let expected_tunnel_bytes =
        LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE * LOCAL_FIXTURE_TUNNEL_MIXED_MESSAGES;
    let start = Instant::now();
    let mut tunnel =
        tokio::time::timeout(adapter_timeout(), client.websocket_h3(tunnel_url).open())
            .await
            .map_err(|_| {
                anyhow::anyhow!("specter_native RFC 9220 mixed tunnel open timed out")
            })??;

    for index in 0..LOCAL_FIXTURE_TUNNEL_MIXED_MESSAGES {
        tunnel
            .send_bytes(
                payload.clone(),
                index + 1 == LOCAL_FIXTURE_TUNNEL_MIXED_MESSAGES,
            )
            .await?;
    }

    let (stream_first_byte_ns, stream_bytes) =
        measure_specter_native_http3_stream_with_client(client, stream_url, start).await?;

    tokio::time::sleep(Duration::from_millis(
        LOCAL_FIXTURE_TUNNEL_SLOW_CONSUMER_DELAY_MS,
    ))
    .await;
    let mut echoed = 0usize;
    while echoed < expected_tunnel_bytes {
        tokio::time::sleep(Duration::from_millis(
            LOCAL_FIXTURE_TUNNEL_SLOW_READ_DELAY_MS,
        ))
        .await;
        let chunk = tokio::time::timeout(adapter_timeout(), tunnel.recv_bytes())
            .await
            .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 mixed tunnel drain timed out"))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "specter_native RFC 9220 mixed tunnel ended after {echoed} of {expected_tunnel_bytes} bytes"
                )
            })??;
        echoed = echoed.saturating_add(chunk.len());
    }
    if echoed != expected_tunnel_bytes {
        anyhow::bail!(
            "specter_native RFC 9220 mixed tunnel echo length mismatch: expected {expected_tunnel_bytes}, got {echoed}"
        );
    }

    let _ = tokio::time::timeout(adapter_timeout(), tunnel.recv_bytes()).await;
    Ok(AdapterSample::new(
        stream_first_byte_ns,
        start.elapsed().as_nanos() as f64,
        stream_bytes.saturating_add(echoed as u64),
    ))
}

async fn measure_specter_native_http3_stream_with_client(
    client: &specter::Client,
    url: &str,
    start: Instant,
) -> anyhow::Result<(f64, u64)> {
    let mut response = client
        .get(url)
        .version(specter::HttpVersion::Http3Only)
        .send_streaming()
        .await?;
    if !(200..300).contains(&response.status_code()) {
        anyhow::bail!(
            "specter_native mixed stream received non-success status {}",
            response.status_code()
        );
    }

    let mut first_byte_ns = None;
    let mut bytes = 0u64;
    while let Some(chunk) = response.body_mut().chunk().await {
        let chunk = chunk?;
        if !chunk.is_empty() {
            first_byte_ns.get_or_insert_with(|| start.elapsed().as_nanos() as f64);
            bytes = bytes.saturating_add(chunk.len() as u64);
        }
    }
    Ok((
        first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
        bytes,
    ))
}

async fn measure_quiche_direct_rfc9220_tunnel(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || {
        for _ in 0..warmups {
            let _ = measure_quiche_direct_rfc9220_tunnel_once(&url)?;
        }

        let mut measured = Vec::with_capacity(samples);
        for _ in 0..samples {
            measured.push(measure_quiche_direct_rfc9220_tunnel_once(&url)?);
        }

        Ok(quiche_direct_rfc9220_tunnel_row_from_samples(&measured))
    })
    .await
    .map_err(|error| anyhow::anyhow!("quiche RFC 9220 blocking task failed: {error}"))?
}

fn measure_quiche_direct_rfc9220_tunnel_once(url: &str) -> anyhow::Result<AdapterSample> {
    let url = parse_rfc9220_network_url(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(QUICHE_MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(QUICHE_MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let scid_seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes();
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    for (index, byte) in scid.iter_mut().enumerate() {
        *byte = scid_seed[index % scid_seed.len()] ^ (index as u8);
    }
    let scid = quiche::ConnectionId::from_ref(&scid);
    let server_name = url.host_str();
    let mut conn = quiche::connect(server_name, &scid, local_addr, peer_addr, &mut config)?;
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn = None;
    let mut req_sent = false;
    let mut stream_id = None;
    let mut echoed = Vec::new();
    let start = Instant::now();
    let deadline = start + adapter_timeout();
    let request_headers = quiche_rfc9220_tunnel_headers(&url)?;
    let payload = rfc9220_tunnel_payload(b'q');
    let mut recv_buf = [0u8; 65535];
    let mut out = [0u8; QUICHE_MAX_DATAGRAM_SIZE];

    flush_quiche_packets(&socket, &mut conn, &mut out)?;

    while Instant::now() < deadline {
        loop {
            match socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
                    if let Err(err) = conn.recv(&mut recv_buf[..len], recv_info) {
                        if err != quiche::Error::Done {
                            return Err(anyhow::anyhow!("quiche RFC 9220 recv failed: {err:?}"));
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        if conn.is_closed() {
            anyhow::bail!("quiche RFC 9220 connection closed before tunnel echo completed");
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let Some(http3) = h3_conn.as_mut() {
            if !req_sent {
                let opened_stream_id = http3.send_request(&mut conn, &request_headers, false)?;
                let written =
                    http3.send_body(&mut conn, opened_stream_id, payload.as_ref(), true)?;
                if written != payload.len() {
                    anyhow::bail!(
                        "quiche RFC 9220 partial tunnel write: expected {}, wrote {}",
                        payload.len(),
                        written
                    );
                }
                stream_id = Some(opened_stream_id);
                req_sent = true;
            }

            loop {
                match http3.poll(&mut conn) {
                    Ok((_, quiche::h3::Event::Headers { .. })) => {}
                    Ok((event_stream_id, quiche::h3::Event::Data)) => loop {
                        match http3.recv_body(&mut conn, event_stream_id, &mut recv_buf) {
                            Ok(read) => echoed.extend_from_slice(&recv_buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => {
                                return Err(anyhow::anyhow!(
                                    "quiche RFC 9220 h3 body failed: {err:?}"
                                ));
                            }
                        }
                    },
                    Ok((event_stream_id, quiche::h3::Event::Finished)) => {
                        if Some(event_stream_id) != stream_id {
                            anyhow::bail!(
                                "quiche RFC 9220 finished unexpected stream {event_stream_id}"
                            );
                        }
                        if echoed.as_slice() != payload.as_ref() {
                            anyhow::bail!(
                                "quiche RFC 9220 echo mismatch: expected {} bytes, got {} bytes",
                                payload.len(),
                                echoed.len()
                            );
                        }
                        let total_ns = start.elapsed().as_nanos() as f64;
                        return Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64));
                    }
                    Ok((_, quiche::h3::Event::Reset(error_code))) => {
                        anyhow::bail!("quiche RFC 9220 h3 stream reset: {error_code}");
                    }
                    Ok((_, quiche::h3::Event::PriorityUpdate | quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => {
                        return Err(anyhow::anyhow!("quiche RFC 9220 h3 poll failed: {err:?}"));
                    }
                }
            }
        }

        flush_quiche_packets(&socket, &mut conn, &mut out)?;

        if let Some(timeout) = conn.timeout() {
            if timeout.is_zero() {
                conn.on_timeout();
            } else {
                std::thread::sleep(timeout.min(Duration::from_millis(1)));
            }
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    anyhow::bail!(
        "quiche RFC 9220 tunnel timed out after {:?}; h3_ready={} req_sent={} stream_id={:?} echoed_bytes={}",
        adapter_timeout(),
        h3_conn.is_some(),
        req_sent,
        stream_id,
        echoed.len()
    )
}

async fn measure_tokio_quiche_rfc9220_tunnel(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    for _ in 0..warmups {
        let _ = measure_tokio_quiche_rfc9220_tunnel_once(url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_tokio_quiche_rfc9220_tunnel_once(url).await?);
    }

    Ok(tokio_quiche_rfc9220_tunnel_row_from_samples(&measured))
}

async fn measure_tokio_quiche_rfc9220_tunnel_once(url: &str) -> anyhow::Result<AdapterSample> {
    use tokio_quiche::http3::driver::{ClientH3Event, H3Event, NewClientRequest, OutboundFrame};

    let url = parse_rfc9220_network_url(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let host = url.host_str();
    let headers = tokio_quiche_rfc9220_tunnel_headers(&url)?;
    let payload = rfc9220_tunnel_payload(b't');
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.connect(peer_addr).await?;

    let start = Instant::now();
    let deadline = start + adapter_timeout();
    let (_, mut controller) = tokio_quiche::quic::connect(socket, host)
        .await
        .map_err(|error| anyhow::anyhow!("tokio_quiche RFC 9220 connect failed: {error}"))?;
    let (body_writer_tx, body_writer_rx) = tokio::sync::oneshot::channel();
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers,
            body_writer: Some(body_writer_tx),
        })
        .map_err(|_| anyhow::anyhow!("tokio_quiche RFC 9220 request driver is closed"))?;

    let body_sender = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        body_writer_rx,
    )
    .await
    .map_err(|_| anyhow::anyhow!("tokio_quiche RFC 9220 body writer timed out"))?
    .map_err(|_| anyhow::anyhow!("tokio_quiche RFC 9220 body writer dropped"))?;
    let raw_sender = body_sender
        .get_ref()
        .ok_or_else(|| anyhow::anyhow!("tokio_quiche RFC 9220 body sender unavailable"))?
        .clone();
    raw_sender
        .try_send(OutboundFrame::Body(payload.clone(), true))
        .map_err(|error| anyhow::anyhow!("tokio_quiche RFC 9220 body send failed: {error:?}"))?;

    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            anyhow::bail!(
                "tokio_quiche RFC 9220 timed out after {:?}",
                adapter_timeout()
            );
        };
        let event = tokio::time::timeout(remaining, controller.event_receiver_mut().recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "tokio_quiche RFC 9220 timed out after {:?}",
                    adapter_timeout()
                )
            })?
            .ok_or_else(|| anyhow::anyhow!("tokio_quiche RFC 9220 event stream closed"))?;

        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                return read_tokio_quiche_rfc9220_tunnel_echo(start, deadline, headers, payload)
                    .await;
            }
            ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                anyhow::bail!("tokio_quiche RFC 9220 stream reset: {stream_id}");
            }
            ClientH3Event::Core(H3Event::ConnectionError(error)) => {
                anyhow::bail!("tokio_quiche RFC 9220 connection error: {error:?}");
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(error)) => {
                anyhow::bail!("tokio_quiche RFC 9220 connection shutdown: {error:?}");
            }
            ClientH3Event::Core(H3Event::GoAway { id }) => {
                anyhow::bail!("tokio_quiche RFC 9220 received GOAWAY before response: {id}");
            }
            ClientH3Event::Core(H3Event::BodyBytesReceived { .. })
            | ClientH3Event::Core(H3Event::IncomingSettings { .. })
            | ClientH3Event::Core(H3Event::NewFlow { .. })
            | ClientH3Event::Core(H3Event::StreamClosed { .. })
            | ClientH3Event::NewOutboundRequest { .. } => {}
        }
    }
}

async fn read_tokio_quiche_rfc9220_tunnel_echo(
    start: Instant,
    deadline: Instant,
    headers: tokio_quiche::http3::driver::IncomingH3Headers,
    expected_payload: Bytes,
) -> anyhow::Result<AdapterSample> {
    let mut echoed = Vec::new();
    if headers.read_fin {
        anyhow::bail!("tokio_quiche RFC 9220 response ended before tunnel echo");
    }

    let mut recv = headers.recv;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            anyhow::bail!(
                "tokio_quiche RFC 9220 body timed out after {:?}",
                adapter_timeout()
            );
        };
        let frame = tokio::time::timeout(remaining, recv.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "tokio_quiche RFC 9220 body timed out after {:?}",
                    adapter_timeout()
                )
            })?
            .ok_or_else(|| anyhow::anyhow!("tokio_quiche RFC 9220 body stream closed"))?;
        match frame {
            tokio_quiche::http3::driver::InboundFrame::Body(chunk, fin) => {
                if !chunk.is_empty() {
                    echoed.extend_from_slice(chunk.as_ref());
                }
                if fin {
                    if echoed.as_slice() != expected_payload.as_ref() {
                        anyhow::bail!(
                            "tokio_quiche RFC 9220 echo mismatch: expected {} bytes, got {} bytes",
                            expected_payload.len(),
                            echoed.len()
                        );
                    }
                    let total_ns = start.elapsed().as_nanos() as f64;
                    return Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64));
                }
            }
            tokio_quiche::http3::driver::InboundFrame::Datagram(_) => {}
        }
    }
}

fn rfc9220_tunnel_payload(byte: u8) -> Bytes {
    Bytes::from(vec![byte; LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE])
}

fn parse_rfc9220_network_url(url: &str) -> anyhow::Result<url::Url> {
    if let Some(rest) = url.strip_prefix("wss://") {
        return Ok(url::Url::parse(&format!("https://{rest}"))?);
    }
    Ok(url::Url::parse(url)?)
}

fn rfc9220_request_path(url: &url::Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

fn rfc9220_request_authority(url: &url::Url) -> anyhow::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn quiche_rfc9220_tunnel_headers(url: &url::Url) -> anyhow::Result<Vec<quiche::h3::Header>> {
    let authority = rfc9220_request_authority(url)?;
    let path = rfc9220_request_path(url);
    Ok(vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"websocket"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche-direct-rfc9220"),
    ])
}

fn tokio_quiche_rfc9220_tunnel_headers(
    url: &url::Url,
) -> anyhow::Result<Vec<tokio_quiche::quiche::h3::Header>> {
    let authority = rfc9220_request_authority(url)?;
    let path = rfc9220_request_path(url);
    Ok(vec![
        tokio_quiche::quiche::h3::Header::new(b":method", b"CONNECT"),
        tokio_quiche::quiche::h3::Header::new(b":protocol", b"websocket"),
        tokio_quiche::quiche::h3::Header::new(b":scheme", b"https"),
        tokio_quiche::quiche::h3::Header::new(b":path", path.as_bytes()),
        tokio_quiche::quiche::h3::Header::new(b":authority", authority.as_bytes()),
        tokio_quiche::quiche::h3::Header::new(b"user-agent", b"tokio-quiche-rfc9220"),
    ])
}

async fn measure_quinn_transport(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let url = url::Url::parse(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr.parse()?)?;
    endpoint.set_default_client_config(quinn_transport_client_config()?);
    let server_name = url.host_str().unwrap_or("localhost");
    let connection = endpoint.connect(peer_addr, server_name)?.await?;

    for _ in 0..warmups {
        let _ = measure_quinn_transport_once(&connection).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_quinn_transport_once(&connection).await?);
    }

    connection.close(0u32.into(), b"benchmark complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;

    Ok(quinn_transport_row_from_samples(&measured))
}

async fn measure_quinn_transport_once(
    connection: &quinn::Connection,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'q'; LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE]);
    let start = Instant::now();
    let (mut send, mut recv) = tokio::time::timeout(adapter_timeout(), connection.open_bi())
        .await
        .map_err(|_| anyhow::anyhow!("quinn_transport open_bi timed out"))??;

    send.write_all(payload.as_ref()).await?;
    send.finish()?;
    let echoed = tokio::time::timeout(
        adapter_timeout(),
        recv.read_to_end(LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE * 8),
    )
    .await
    .map_err(|_| anyhow::anyhow!("quinn_transport echo timed out"))??;
    if echoed.as_slice() != payload.as_ref() {
        anyhow::bail!(
            "quinn_transport echo mismatch: expected {} bytes, got {} bytes",
            payload.len(),
            echoed.len()
        );
    }

    let total_ns = start.elapsed().as_nanos() as f64;
    Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64))
}

#[cfg(feature = "s2n-quic-transport")]
async fn measure_s2n_quic_transport(
    url: &str,
    warmups: usize,
    samples: usize,
    cert_path: &Path,
) -> anyhow::Result<BenchmarkRow> {
    let url = url::Url::parse(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let mut client = s2n_quic::Client::builder()
        .with_tls(cert_path)?
        .with_io(if peer_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?
        .start()?;
    let connect = s2n_quic::client::Connect::new(peer_addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;
    connection.keep_alive(true)?;

    for _ in 0..warmups {
        let _ = measure_s2n_quic_transport_once(&mut connection).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_s2n_quic_transport_once(&mut connection).await?);
    }

    connection.close(0u32.into());
    let _ = tokio::time::timeout(Duration::from_secs(1), client.wait_idle()).await;

    Ok(s2n_quic_transport_row_from_samples(&measured))
}

#[cfg(not(feature = "s2n-quic-transport"))]
async fn measure_s2n_quic_transport(
    _url: &str,
    _warmups: usize,
    _samples: usize,
    _cert_path: &Path,
) -> anyhow::Result<BenchmarkRow> {
    anyhow::bail!("--measure-s2n-quic-transport-url requires --features s2n-quic-transport")
}

#[cfg(feature = "s2n-quic-transport")]
async fn measure_s2n_quic_transport_once(
    connection: &mut s2n_quic::connection::Connection,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b's'; LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE]);
    let start = Instant::now();
    let mut stream =
        tokio::time::timeout(adapter_timeout(), connection.open_bidirectional_stream())
            .await
            .map_err(|_| {
                anyhow::anyhow!("s2n_quic_transport open_bidirectional_stream timed out")
            })??;

    stream.send(payload.clone()).await?;
    stream.finish()?;

    let mut echoed = Vec::with_capacity(payload.len());
    loop {
        let chunk = tokio::time::timeout(adapter_timeout(), stream.receive())
            .await
            .map_err(|_| anyhow::anyhow!("s2n_quic_transport echo timed out"))??;
        let Some(chunk) = chunk else {
            break;
        };
        echoed.extend_from_slice(chunk.as_ref());
    }

    if echoed.as_slice() != payload.as_ref() {
        anyhow::bail!(
            "s2n_quic_transport echo mismatch: expected {} bytes, got {} bytes",
            payload.len(),
            echoed.len()
        );
    }

    let total_ns = start.elapsed().as_nanos() as f64;
    Ok(AdapterSample::new(total_ns, total_ns, echoed.len() as u64))
}

fn quinn_transport_client_config() -> anyhow::Result<quinn::ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![QUINN_TRANSPORT_ALPN.to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)?,
    )))
}

fn quinn_transport_server_config() -> anyhow::Result<quinn::ServerConfig> {
    let (cert_der, key_der) = generate_local_fixture_cert_der()?;
    let cert_der = CertificateDer::from(cert_der);
    let key = PrivatePkcs8KeyDer::from(key_der);
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key.into())?;
    crypto.alpn_protocols = vec![QUINN_TRANSPORT_ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("quinn transport config unexpectedly shared"))?;
    transport_config.max_concurrent_uni_streams(0_u8.into());
    Ok(server_config)
}

fn generate_local_fixture_cert_der() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let cert_path = std::env::temp_dir().join(format!("specter_native_h3_{stamp}.der"));
    let key_pem_path = std::env::temp_dir().join(format!("specter_native_h3_{stamp}.key.pem"));
    let key_der_path = std::env::temp_dir().join(format!("specter_native_h3_{stamp}.key.der"));
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_pem_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp key path"))?,
            "-out",
            cert_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp cert path"))?,
            "-outform",
            "DER",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=CA:FALSE",
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "openssl fixture DER cert generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-inform",
            "PEM",
            "-outform",
            "DER",
            "-in",
            key_pem_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp key path"))?,
            "-out",
            key_der_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp DER key path"))?,
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "openssl fixture DER key conversion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let cert_der = fs::read(&cert_path)?;
    let key_der = fs::read(&key_der_path)?;
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_pem_path);
    let _ = fs::remove_file(key_der_path);
    Ok((cert_der, key_der))
}

async fn measure_tokio_quiche(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    for _ in 0..warmups {
        let _ = measure_tokio_quiche_once(url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_tokio_quiche_once(url).await?);
    }

    Ok(adapter_row_from_samples(
        "tokio_quiche",
        "tokio_quiche_adapter",
        &measured,
    ))
}

async fn measure_tokio_quiche_once(url: &str) -> anyhow::Result<AdapterSample> {
    use tokio_quiche::http3::driver::{ClientH3Event, H3Event, NewClientRequest};

    let url = url::Url::parse(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let host = url.host_str();
    let headers = tokio_quiche_request_headers(&url)?;
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.connect(peer_addr).await?;

    let start = Instant::now();
    let deadline = start + adapter_timeout();
    let (_, mut controller) = tokio_quiche::quic::connect(socket, host)
        .await
        .map_err(|error| anyhow::anyhow!("tokio_quiche connect failed: {error}"))?;
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers,
            body_writer: None,
        })
        .map_err(|_| anyhow::anyhow!("tokio_quiche request driver is closed"))?;

    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            anyhow::bail!("tokio_quiche timed out after {:?}", adapter_timeout());
        };
        let event = tokio::time::timeout(remaining, controller.event_receiver_mut().recv())
            .await
            .map_err(|_| anyhow::anyhow!("tokio_quiche timed out after {:?}", adapter_timeout()))?
            .ok_or_else(|| anyhow::anyhow!("tokio_quiche event stream closed"))?;

        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                return read_tokio_quiche_response_body(start, deadline, headers).await;
            }
            ClientH3Event::Core(H3Event::ResetStream { stream_id }) => {
                anyhow::bail!("tokio_quiche stream reset: {stream_id}");
            }
            ClientH3Event::Core(H3Event::ConnectionError(error)) => {
                anyhow::bail!("tokio_quiche connection error: {error:?}");
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(error)) => {
                anyhow::bail!("tokio_quiche connection shutdown: {error:?}");
            }
            ClientH3Event::Core(H3Event::GoAway { id }) => {
                anyhow::bail!("tokio_quiche received GOAWAY before response: {id}");
            }
            ClientH3Event::Core(H3Event::BodyBytesReceived { .. })
            | ClientH3Event::Core(H3Event::IncomingSettings { .. })
            | ClientH3Event::Core(H3Event::NewFlow { .. })
            | ClientH3Event::Core(H3Event::StreamClosed { .. })
            | ClientH3Event::NewOutboundRequest { .. } => {}
        }
    }
}

async fn read_tokio_quiche_response_body(
    start: Instant,
    deadline: Instant,
    headers: tokio_quiche::http3::driver::IncomingH3Headers,
) -> anyhow::Result<AdapterSample> {
    let mut first_byte_ns = Some(start.elapsed().as_nanos() as f64);
    let mut bytes = 0u64;
    if headers.read_fin {
        return Ok(AdapterSample::new(
            first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
            start.elapsed().as_nanos() as f64,
            bytes,
        ));
    }

    let mut recv = headers.recv;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            anyhow::bail!("tokio_quiche body timed out after {:?}", adapter_timeout());
        };
        let frame = tokio::time::timeout(remaining, recv.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!("tokio_quiche body timed out after {:?}", adapter_timeout())
            })?
            .ok_or_else(|| anyhow::anyhow!("tokio_quiche body stream closed"))?;
        match frame {
            tokio_quiche::http3::driver::InboundFrame::Body(chunk, fin) => {
                if !chunk.is_empty() {
                    first_byte_ns.get_or_insert_with(|| start.elapsed().as_nanos() as f64);
                    bytes = bytes.saturating_add(chunk.len() as u64);
                }
                if fin {
                    return Ok(AdapterSample::new(
                        first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
                        start.elapsed().as_nanos() as f64,
                        bytes,
                    ));
                }
            }
            tokio_quiche::http3::driver::InboundFrame::Datagram(_) => {}
        }
    }
}

fn tokio_quiche_request_headers(
    url: &url::Url,
) -> anyhow::Result<Vec<tokio_quiche::quiche::h3::Header>> {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;

    Ok(vec![
        tokio_quiche::quiche::h3::Header::new(b":method", b"GET"),
        tokio_quiche::quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        tokio_quiche::quiche::h3::Header::new(b":authority", authority.as_bytes()),
        tokio_quiche::quiche::h3::Header::new(b":path", path.as_bytes()),
        tokio_quiche::quiche::h3::Header::new(b"user-agent", b"tokio-quiche"),
    ])
}

async fn measure_h3_quinn(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let url = url::Url::parse(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let mut endpoint = quinn::Endpoint::client(bind_addr.parse()?)?;
    endpoint.set_default_client_config(h3_quinn_client_config()?);
    let server_name = url.host_str().unwrap_or("localhost");
    let connection = endpoint.connect(peer_addr, server_name)?.await?;
    let close_connection = connection.clone();
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
    let request_url = url.as_str().to_owned();

    for _ in 0..warmups {
        let _ = measure_h3_quinn_once(&mut send_request, &request_url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_h3_quinn_once(&mut send_request, &request_url).await?);
    }

    drop(send_request);
    close_connection.close(0u32.into(), b"benchmark complete");
    driver.abort();
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;

    Ok(adapter_row_from_samples(
        "h3_quinn",
        "h3_quinn_adapter",
        &measured,
    ))
}

async fn measure_h3_quinn_once(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    url: &str,
) -> anyhow::Result<AdapterSample> {
    let start = Instant::now();
    let mut request_stream = send_request
        .send_request(http::Request::get(url).body(())?)
        .await?;
    request_stream.finish().await?;
    let _response = request_stream.recv_response().await?;
    let mut first_byte_ns = Some(start.elapsed().as_nanos() as f64);
    let mut bytes = 0u64;
    while let Some(chunk) = request_stream.recv_data().await? {
        first_byte_ns.get_or_insert_with(|| start.elapsed().as_nanos() as f64);
        bytes = bytes.saturating_add(chunk.remaining() as u64);
    }
    Ok(AdapterSample::new(
        first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
        start.elapsed().as_nanos() as f64,
        bytes,
    ))
}

fn h3_quinn_client_config() -> anyhow::Result<quinn::ClientConfig> {
    let crypto = h3_quinn_rustls_client_config()?;
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)?,
    )))
}

fn h3_quinn_rustls_client_config() -> anyhow::Result<rustls::ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    Ok(crypto)
}

#[cfg(feature = "reqwest-h3")]
fn reqwest_h3_rustls_client_config() -> anyhow::Result<rustls::ClientConfig> {
    h3_quinn_rustls_client_config()
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn measure_quiche_direct(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    for _ in 0..warmups {
        let _ = measure_quiche_direct_once(url)?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_quiche_direct_once(url)?);
    }

    Ok(adapter_row_from_samples(
        "quiche_direct",
        "quiche_direct_adapter",
        &measured,
    ))
}

fn measure_quiche_direct_once(url: &str) -> anyhow::Result<AdapterSample> {
    let url = url::Url::parse(url)?;
    let peer_addr = url
        .socket_addrs(|| Some(443))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("URL resolved to no socket addresses"))?;
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(QUICHE_MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(QUICHE_MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let scid_seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes();
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    for (index, byte) in scid.iter_mut().enumerate() {
        *byte = scid_seed[index % scid_seed.len()] ^ (index as u8);
    }
    let scid = quiche::ConnectionId::from_ref(&scid);
    let server_name = url.host_str();
    let mut conn = quiche::connect(server_name, &scid, local_addr, peer_addr, &mut config)?;
    let h3_config = quiche::h3::Config::new()?;
    let mut h3_conn = None;
    let mut req_sent = false;
    let mut first_byte_ns = None;
    let mut bytes = 0u64;
    let start = Instant::now();
    let deadline = start + adapter_timeout();
    let request_headers = quiche_request_headers(&url)?;
    let mut recv_buf = [0u8; 65535];
    let mut out = [0u8; QUICHE_MAX_DATAGRAM_SIZE];

    flush_quiche_packets(&socket, &mut conn, &mut out)?;

    while Instant::now() < deadline {
        loop {
            match socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
                    if let Err(err) = conn.recv(&mut recv_buf[..len], recv_info) {
                        if err != quiche::Error::Done {
                            return Err(anyhow::anyhow!("quiche recv failed: {err:?}"));
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        if conn.is_closed() {
            anyhow::bail!("quiche connection closed before response completed");
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let Some(http3) = h3_conn.as_mut() {
            if !req_sent {
                http3.send_request(&mut conn, &request_headers, true)?;
                req_sent = true;
            }

            loop {
                match http3.poll(&mut conn) {
                    Ok((_, quiche::h3::Event::Headers { .. })) => {
                        first_byte_ns.get_or_insert_with(|| start.elapsed().as_nanos() as f64);
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match http3.recv_body(&mut conn, stream_id, &mut recv_buf) {
                            Ok(read) => {
                                first_byte_ns
                                    .get_or_insert_with(|| start.elapsed().as_nanos() as f64);
                                bytes = bytes.saturating_add(read as u64);
                            }
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => {
                                return Err(anyhow::anyhow!("quiche h3 body failed: {err:?}"))
                            }
                        }
                    },
                    Ok((_, quiche::h3::Event::Finished)) => {
                        return Ok(AdapterSample::new(
                            first_byte_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
                            start.elapsed().as_nanos() as f64,
                            bytes,
                        ));
                    }
                    Ok((_, quiche::h3::Event::Reset(error_code))) => {
                        anyhow::bail!("quiche h3 stream reset: {error_code}");
                    }
                    Ok((_, quiche::h3::Event::PriorityUpdate | quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(anyhow::anyhow!("quiche h3 poll failed: {err:?}")),
                }
            }
        }

        flush_quiche_packets(&socket, &mut conn, &mut out)?;

        if let Some(timeout) = conn.timeout() {
            if timeout.is_zero() {
                conn.on_timeout();
            } else {
                std::thread::sleep(timeout.min(Duration::from_millis(1)));
            }
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    anyhow::bail!("quiche_direct timed out after {:?}", adapter_timeout())
}

fn quiche_request_headers(url: &url::Url) -> anyhow::Result<Vec<quiche::h3::Header>> {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;

    Ok(vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche-direct"),
    ])
}

fn flush_quiche_packets(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> anyhow::Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => match socket.send_to(&out[..write], send_info.to) {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            },
            Err(quiche::Error::Done) => break,
            Err(err) => return Err(anyhow::anyhow!("quiche send failed: {err:?}")),
        }
    }
    Ok(())
}

#[cfg(feature = "reqwest-h3")]
async fn measure_reqwest_h3(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .local_address(std::net::IpAddr::from([0, 0, 0, 0]))
        .tls_backend_preconfigured(reqwest_h3_rustls_client_config()?)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    for _ in 0..warmups {
        let response = client
            .get(url)
            .version(http::Version::HTTP_3)
            .send()
            .await?;
        let _ = response.bytes().await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = std::time::Instant::now();
        let mut response = client
            .get(url)
            .version(http::Version::HTTP_3)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!(
                "reqwest_h3 received non-success status {}",
                response.status()
            );
        }
        let mut first_chunk_ns = Some(start.elapsed().as_nanos() as f64);
        let mut bytes = 0u64;
        while let Some(chunk) = response.chunk().await? {
            if first_chunk_ns.is_none() {
                first_chunk_ns = Some(start.elapsed().as_nanos() as f64);
            }
            bytes = bytes.saturating_add(chunk.len() as u64);
        }
        measured.push(AdapterSample::new(
            first_chunk_ns.unwrap_or_else(|| start.elapsed().as_nanos() as f64),
            start.elapsed().as_nanos() as f64,
            bytes,
        ));
    }

    Ok(adapter_row_from_samples(
        "reqwest_h3",
        "reqwest_h3_adapter",
        &measured,
    ))
}

#[cfg(not(feature = "reqwest-h3"))]
async fn measure_reqwest_h3(
    _url: &str,
    _warmups: usize,
    _samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    anyhow::bail!(
        "--measure-reqwest-h3-url requires --features reqwest-h3 and RUSTFLAGS='--cfg reqwest_unstable'"
    )
}

#[cfg(test)]
mod tests {
    fn measured_row(
        competitor_id: &'static str,
        p50_ttft_ns: f64,
        p95_ttft_ns: f64,
        bytes_per_sec: f64,
    ) -> super::BenchmarkRow {
        let mut row = super::BenchmarkRow {
            competitor_id: competitor_id.into(),
            status: "measured_pass".into(),
            p50_ttft_ns: Some(p50_ttft_ns),
            p95_ttft_ns: Some(p95_ttft_ns),
            bytes_per_sec: Some(bytes_per_sec),
            source: "test_fixture".into(),
            ..super::BenchmarkRow::default()
        };
        super::apply_row_context(&mut row, None);
        row
    }

    #[test]
    fn superiority_gate_rejects_measured_competitors_when_specter_is_slower() {
        let rows = vec![
            measured_row("specter_native", 2_000.0, 3_000.0, 1_000.0),
            measured_row("quiche_direct", 1_000.0, 2_000.0, 2_000.0),
            measured_row("tokio_quiche", 1_500.0, 2_500.0, 1_500.0),
            measured_row("h3_quinn", 1_600.0, 2_600.0, 1_400.0),
            measured_row("reqwest_h3", 1_700.0, 2_700.0, 1_300.0),
        ];

        let gate = super::superiority_gate(&rows);

        assert!(
            !gate.pass,
            "slower Specter row must not pass superiority gate"
        );
        assert_eq!(gate.status, "fail");
        assert_eq!(gate.fastest_non_specter_h3_client, Some("quiche_direct"));
        assert_eq!(gate.missing_required_rows, Vec::<&'static str>::new());
        assert_eq!(
            gate.reason,
            "specter_native_not_faster_than_required_h3_competitors"
        );
    }

    #[test]
    fn artifact_imports_competitor_rows_and_can_prove_superiority() {
        let specter_artifact_json = r#"{
          "rows": [
            {
              "protocol": "h3",
              "client": "specter",
              "metrics": {
                "p50_ns": 900.0,
                "p95_ns": 1900.0,
                "bytes_per_sec": 3000.0,
                "pass": true
              }
            }
          ]
        }"#;
        let competitor_artifact_json = r#"{
          "rows": [
            { "competitor_id": "quiche_direct", "status": "measured_pass", "p50_ttft_ns": 1000.0, "p95_ttft_ns": 2000.0, "bytes_per_sec": 2000.0, "source": "quiche_adapter" },
            { "competitor_id": "tokio_quiche", "status": "measured_pass", "p50_ttft_ns": 1100.0, "p95_ttft_ns": 2100.0, "bytes_per_sec": 1900.0, "source": "tokio_quiche_adapter" },
            { "competitor_id": "h3_quinn", "status": "measured_pass", "p50_ttft_ns": 1200.0, "p95_ttft_ns": 2200.0, "bytes_per_sec": 1800.0, "source": "h3_quinn_adapter" },
            { "competitor_id": "reqwest_h3", "status": "measured_pass", "p50_ttft_ns": 1300.0, "p95_ttft_ns": 2300.0, "bytes_per_sec": 1700.0, "source": "reqwest_h3_adapter" }
          ]
        }"#;

        let artifact = super::artifact_with_competitor_artifacts(
            Some(specter_artifact_json),
            &[competitor_artifact_json],
        );

        assert!(artifact.superiority_gate.pass);
        assert_eq!(artifact.superiority_gate.status, "pass");
        assert_eq!(
            artifact.superiority_gate.reason,
            "specter_native_is_faster_than_required_h3_competitors"
        );
        assert_eq!(
            artifact.superiority_gate.fastest_non_specter_h3_client,
            Some("quiche_direct")
        );
        assert!(artifact
            .rows
            .iter()
            .any(|row| row.competitor_id == "quiche_direct"
                && row.status == "measured_pass"
                && row.source == "quiche_adapter"));
    }

    #[test]
    fn artifact_accepts_direct_specter_native_measurement_row() {
        let specter_row = super::BenchmarkRow {
            competitor_id: "specter_native".into(),
            status: "measured_pass".into(),
            p50_ttft_ns: Some(100.0),
            p95_ttft_ns: Some(200.0),
            bytes_per_sec: Some(300.0),
            source: "specter_native_adapter".into(),
            ..super::BenchmarkRow::default()
        };
        let artifact =
            super::artifact_with_competitor_rows(None, &Vec::<&str>::new(), &[specter_row]);

        let row = artifact
            .rows
            .iter()
            .find(|row| row.competitor_id == "specter_native")
            .expect("direct Specter native row should be present");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(100.0));
        assert_eq!(row.source, "specter_native_adapter");
        assert_eq!(
            artifact.superiority_gate.reason,
            "no_h3_superiority_claim_without_all_required_rows"
        );
    }

    #[test]
    fn artifact_import_prefers_measured_rows_over_pending_placeholders() {
        let pending_artifact_json = r#"{
          "rows": [
            { "competitor_id": "s2n_quic_transport", "status": "pending_adapter", "p50_ttft_ns": null, "p95_ttft_ns": null, "bytes_per_sec": null, "source": "native_h3_vs_rust_clients_harness" }
          ]
        }"#;
        let measured_artifact_json = r#"{
          "rows": [
            { "competitor_id": "s2n_quic_transport", "status": "measured_pass", "p50_ttft_ns": 10.0, "p95_ttft_ns": 20.0, "bytes_per_sec": 30.0, "source": "s2n_quic_transport_adapter" }
          ]
        }"#;

        let artifact = super::artifact_with_competitor_artifacts(
            None,
            &[pending_artifact_json, measured_artifact_json],
        );

        let row = artifact
            .rows
            .iter()
            .find(|row| row.competitor_id == "s2n_quic_transport")
            .expect("s2n row should exist");

        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(10.0));
        assert_eq!(row.source, "s2n_quic_transport_adapter");
    }

    #[test]
    fn artifact_surfaces_rfc9220_comparator_capability_rows() {
        let artifact = super::artifact_with_competitor_artifacts(None, &Vec::<String>::new());

        for (competitor_id, expected_role, expected_status, expected_source) in [
            (
                "quiche_direct_rfc9220_tunnel",
                "h3_tunnel_comparator",
                "pending_measurement",
                "native_h3_vs_rust_clients_harness",
            ),
            (
                "tokio_quiche_rfc9220_tunnel",
                "h3_tunnel_comparator",
                "pending_measurement",
                "native_h3_vs_rust_clients_harness",
            ),
            (
                "quiche_direct_rfc9220_tunnel_close",
                "h3_tunnel_comparator",
                "pending_measurement",
                "native_h3_vs_rust_clients_harness",
            ),
            (
                "tokio_quiche_rfc9220_tunnel_close",
                "h3_tunnel_comparator",
                "pending_measurement",
                "native_h3_vs_rust_clients_harness",
            ),
            (
                "h3_quinn_rfc9220_tunnel",
                "unsupported_h3_tunnel_comparator",
                "unsupported_by_client",
                "capability_audit",
            ),
            (
                "reqwest_h3_rfc9220_tunnel",
                "unsupported_h3_tunnel_comparator",
                "unsupported_by_client",
                "capability_audit",
            ),
        ] {
            let spec = artifact
                .competitors
                .iter()
                .find(|spec| spec.id == competitor_id)
                .unwrap_or_else(|| panic!("{competitor_id} spec should be explicit"));
            assert_eq!(spec.role, expected_role);
            assert!(
                !spec.required_for_superiority,
                "{competitor_id} must not affect the HTTP/3 superiority gate"
            );

            let row = artifact
                .rows
                .iter()
                .find(|row| row.competitor_id == competitor_id)
                .unwrap_or_else(|| panic!("{competitor_id} row should be explicit"));
            assert_eq!(row.status, expected_status);
            assert_eq!(row.source, expected_source);
            assert_ne!(
                row.status, "pending_adapter",
                "{competitor_id} must not regress to pending_adapter once a real adapter exists"
            );
        }
    }

    #[test]
    fn artifact_promotes_rfc9220_comparator_rows_when_measurements_imported() {
        let measured_rows = vec![
            super::BenchmarkRow {
                competitor_id: "quiche_direct_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(2_750_000.0),
                p95_ttft_ns: Some(2_850_000.0),
                bytes_per_sec: Some(372_000.0),
                source: "quiche_direct_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "tokio_quiche_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(4_000_000.0),
                p95_ttft_ns: Some(4_600_000.0),
                bytes_per_sec: Some(236_000.0),
                source: "tokio_quiche_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
        ];

        let artifact =
            super::artifact_with_competitor_rows(None, &Vec::<&str>::new(), &measured_rows);

        for competitor_id in [
            "quiche_direct_rfc9220_tunnel",
            "tokio_quiche_rfc9220_tunnel",
        ] {
            let row = artifact
                .rows
                .iter()
                .find(|row| row.competitor_id == competitor_id)
                .unwrap_or_else(|| panic!("{competitor_id} row should be present"));
            assert_eq!(
                row.status, "measured_pass",
                "{competitor_id} row should reflect imported measurement"
            );
            assert_ne!(
                row.source, "native_h3_vs_rust_clients_harness",
                "{competitor_id} row source should reflect the adapter, not the pending placeholder"
            );
            assert_eq!(row.sample_count, Some(100));
            assert!(row.p50_ttft_ns.is_some());
            assert!(row.p95_ttft_ns.is_some());
        }
    }

    #[test]
    fn rfc9220_tunnel_superiority_gate_passes_independently_from_http_gate() {
        let measured_rows = vec![
            super::BenchmarkRow {
                competitor_id: "specter_native_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(200_000.0),
                p95_ttft_ns: Some(350_000.0),
                bytes_per_sec: Some(4_000_000.0),
                source: "specter_native_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "quiche_direct_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(2_700_000.0),
                p95_ttft_ns: Some(2_850_000.0),
                bytes_per_sec: Some(370_000.0),
                source: "quiche_direct_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "tokio_quiche_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(4_000_000.0),
                p95_ttft_ns: Some(4_600_000.0),
                bytes_per_sec: Some(235_000.0),
                source: "tokio_quiche_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
        ];
        let artifact =
            super::artifact_with_competitor_rows(None, &Vec::<&str>::new(), &measured_rows);
        let artifact_json = serde_json::to_value(&artifact).unwrap();
        let tunnel_gate = &artifact_json["rfc9220_tunnel_superiority_gate"];

        assert_eq!(artifact.superiority_gate.status, "incomplete");
        assert_eq!(
            tunnel_gate["required_rfc9220_tunnel_clients"],
            serde_json::json!([
                "specter_native_rfc9220_tunnel",
                "quiche_direct_rfc9220_tunnel",
                "tokio_quiche_rfc9220_tunnel"
            ])
        );
        assert_eq!(tunnel_gate["minimum_sample_count"], serde_json::json!(100));
        assert_eq!(tunnel_gate["pass"], serde_json::json!(true));
        assert_eq!(tunnel_gate["status"], serde_json::json!("pass"));
        assert_eq!(
            tunnel_gate["reason"],
            serde_json::json!(
                "specter_native_rfc9220_tunnel_is_faster_than_required_rfc9220_tunnel_competitors"
            )
        );
        assert_eq!(
            tunnel_gate["fastest_non_specter_rfc9220_tunnel_client"],
            serde_json::json!("quiche_direct_rfc9220_tunnel")
        );
    }

    #[test]
    fn rfc9220_tunnel_superiority_gate_requires_all_rows_at_n100() {
        let measured_rows = vec![
            super::BenchmarkRow {
                competitor_id: "specter_native_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(200_000.0),
                p95_ttft_ns: Some(350_000.0),
                bytes_per_sec: Some(4_000_000.0),
                source: "specter_native_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "quiche_direct_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(2_700_000.0),
                p95_ttft_ns: Some(2_850_000.0),
                bytes_per_sec: Some(370_000.0),
                source: "quiche_direct_rfc9220_tunnel_adapter".into(),
                sample_count: Some(99),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "tokio_quiche_rfc9220_tunnel".into(),
                status: "pending_measurement".into(),
                source: "native_h3_vs_rust_clients_harness".into(),
                ..super::BenchmarkRow::default()
            },
        ];
        let artifact =
            super::artifact_with_competitor_rows(None, &Vec::<&str>::new(), &measured_rows);
        let tunnel_gate =
            &serde_json::to_value(&artifact).unwrap()["rfc9220_tunnel_superiority_gate"];

        assert_eq!(tunnel_gate["pass"], serde_json::json!(false));
        assert_eq!(tunnel_gate["status"], serde_json::json!("incomplete"));
        assert_eq!(
            tunnel_gate["reason"],
            serde_json::json!("no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows")
        );
        assert_eq!(
            tunnel_gate["under_sampled_required_rfc9220_tunnel_rows"],
            serde_json::json!(["quiche_direct_rfc9220_tunnel"])
        );
        assert_eq!(
            tunnel_gate["missing_required_rfc9220_tunnel_rows"],
            serde_json::json!(["tokio_quiche_rfc9220_tunnel"])
        );
    }

    #[test]
    fn rfc9220_tunnel_requirement_flag_is_separate_from_http_requirement_flag() {
        let measured_rows = vec![
            super::BenchmarkRow {
                competitor_id: "specter_native_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(200_000.0),
                p95_ttft_ns: Some(350_000.0),
                bytes_per_sec: Some(4_000_000.0),
                source: "specter_native_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "quiche_direct_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(2_700_000.0),
                p95_ttft_ns: Some(2_850_000.0),
                bytes_per_sec: Some(370_000.0),
                source: "quiche_direct_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
            super::BenchmarkRow {
                competitor_id: "tokio_quiche_rfc9220_tunnel".into(),
                status: "measured_pass".into(),
                p50_ttft_ns: Some(4_000_000.0),
                p95_ttft_ns: Some(4_600_000.0),
                bytes_per_sec: Some(235_000.0),
                source: "tokio_quiche_rfc9220_tunnel_adapter".into(),
                sample_count: Some(100),
                ..super::BenchmarkRow::default()
            },
        ];
        let artifact =
            super::artifact_with_competitor_rows(None, &Vec::<&str>::new(), &measured_rows);

        assert!(!artifact.superiority_gate.pass);
        assert!(super::requirement_failed(
            &["bench".into(), "--require-superiority".into()],
            &artifact
        ));
        assert!(!super::requirement_failed(
            &[
                "bench".into(),
                "--require-rfc9220-tunnel-superiority".into()
            ],
            &artifact
        ));
    }

    #[test]
    fn local_native_fixture_plan_includes_feature_enabled_clients() {
        let mut expected = vec![
            "specter_native",
            "quiche_direct",
            "tokio_quiche",
            "h3_quinn",
        ];
        #[cfg(feature = "reqwest-h3")]
        expected.push("reqwest_h3");
        expected.push("quinn_transport");
        #[cfg(feature = "s2n-quic-transport")]
        expected.push("s2n_quic_transport");
        expected.push("specter_native_rfc9220_tunnel");
        expected.push("specter_native_rfc9220_tunnel_close");
        expected.push("specter_native_rfc9220_tunnel_mixed");
        expected.push("quiche_direct_rfc9220_tunnel");
        expected.push("tokio_quiche_rfc9220_tunnel");
        expected.push("quiche_direct_rfc9220_tunnel_close");
        expected.push("tokio_quiche_rfc9220_tunnel_close");

        assert_eq!(super::local_native_fixture_measurement_plan(), expected);
    }

    #[test]
    fn local_native_fixture_plan_can_select_one_client() {
        assert_eq!(
            super::local_native_fixture_measurement_plan_for(Some("h3_quinn")).unwrap(),
            vec!["h3_quinn"]
        );
        assert!(super::local_native_fixture_measurement_plan_for(Some("unknown")).is_err());
    }

    #[test]
    fn local_native_fixture_classifies_packet_open_errors_by_phase() {
        let error = anyhow::anyhow!("QUIC packet open failed: unknown BoringSSL error");

        let post_application = super::classify_local_native_h3_packet_error(&error, true);
        assert_eq!(
            post_application.classification,
            "post_application_packet_open_error"
        );
        assert_eq!(
            post_application.category,
            "non_fatal_packet_open_after_application_ready"
        );
        assert!(!post_application.fatal);

        let handshake = super::classify_local_native_h3_packet_error(&error, false);
        assert_eq!(handshake.classification, "handshake_packet_open_error");
        assert_eq!(
            handshake.category,
            "fatal_packet_open_before_application_ready"
        );
        assert!(handshake.fatal);
    }

    #[test]
    fn local_native_fixture_suppresses_post_application_short_header_packet_noise() {
        let error = anyhow::anyhow!("QUIC packet open failed: unknown BoringSSL error");
        let classification = super::classify_local_native_h3_packet_error_with_datagram(
            &error,
            true,
            "len=1200 short_prefix=[ab, cd]",
        );

        assert_eq!(classification.level, "debug");
        assert_eq!(classification.kind, "packet_noise");
        assert_eq!(
            classification.classification,
            "post_application_short_header_packet_open_noise"
        );
        assert_eq!(
            classification.category,
            "ignored_short_header_packet_open_after_application_ready"
        );
        assert!(!classification.fatal);
        assert!(!super::should_log_local_native_h3_fixture_event(
            &classification
        ));
    }

    #[test]
    fn artifact_emits_fixture_events_for_packet_error_audit() {
        let specter_row = super::BenchmarkRow {
            competitor_id: "specter_native".into(),
            status: "measured_pass".into(),
            p50_ttft_ns: Some(100.0),
            p95_ttft_ns: Some(200.0),
            bytes_per_sec: Some(300.0),
            source: "specter_native_adapter".into(),
            ..super::BenchmarkRow::default()
        };
        let event = super::FixtureEvent {
            client: "h3_quinn".into(),
            level: "warn",
            kind: "packet_error",
            classification: "post_application_packet_open_error",
            category: "non_fatal_packet_open_after_application_ready",
            fatal: false,
            message: "QUIC packet open failed".into(),
            datagram: Some("len=1200 short_prefix=[]".into()),
            app_ready: Some(true),
        };

        let artifact = super::artifact_with_competitor_rows_and_fixture_events(
            None,
            &Vec::<String>::new(),
            &[specter_row],
            vec![event],
        );

        assert_eq!(artifact.fixture_events.len(), 1);
        assert_eq!(
            artifact.fixture_events[0].classification,
            "post_application_packet_open_error"
        );
        assert_eq!(
            artifact.fixture_events[0].category,
            "non_fatal_packet_open_after_application_ready"
        );
        assert!(!artifact.fixture_events[0].fatal);

        let artifact_json = serde_json::to_value(&artifact).unwrap();
        let event_json = &artifact_json["fixture_events"][0];
        assert_eq!(
            event_json["category"],
            serde_json::json!("non_fatal_packet_open_after_application_ready")
        );
        assert_eq!(event_json["fatal"], serde_json::json!(false));
    }

    #[test]
    fn local_native_fixture_routes_short_header_by_registered_server_connection_id() {
        let registered = vec![b"srv-cid-a".to_vec(), b"srv-cid-bbb".to_vec()];
        let mut packet = vec![0x40];
        packet.extend_from_slice(b"srv-cid-bbb");
        packet.extend_from_slice(b"encrypted-payload");

        assert_eq!(
            super::route_local_native_h3_connection_id(&packet, None, &registered),
            Some(b"srv-cid-bbb".to_vec())
        );
    }

    #[test]
    fn local_native_fixture_stream_segments_fit_common_h3_udp_payloads() {
        assert!(
            super::LOCAL_FIXTURE_H3_STREAM_SEGMENT_SIZE <= 1_200,
            "fixture DATA STREAM payloads must leave QUIC/header/tag room under 1350-byte client UDP limits"
        );
    }

    #[test]
    fn local_native_fixture_cert_is_x509v3_with_localhost_san() {
        let (cert_pem, _) = super::generate_local_fixture_cert_pem().unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let cert_path =
            std::env::temp_dir().join(format!("specter_native_h3_cert_test_{stamp}.crt"));
        std::fs::write(&cert_path, cert_pem).unwrap();
        let output = std::process::Command::new("openssl")
            .args([
                "x509",
                "-in",
                cert_path.to_str().unwrap(),
                "-noout",
                "-text",
            ])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(cert_path);
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("Version: 3"));
        assert!(text.contains("DNS:localhost"));
        assert!(text.contains("IP Address:127.0.0.1"));
    }

    #[test]
    fn h3_quinn_client_config_constructs_without_crypto_provider_panic() {
        super::h3_quinn_client_config().unwrap();
    }

    #[test]
    fn h3_quinn_rustls_config_uses_native_fixture_cipher_suite() {
        let config = super::h3_quinn_rustls_client_config().unwrap();
        let suites = config
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>();

        assert_eq!(
            suites,
            vec![super::rustls::CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
    }

    #[cfg(feature = "reqwest-h3")]
    #[test]
    fn reqwest_h3_rustls_config_uses_native_fixture_cipher_suite() {
        let config = super::reqwest_h3_rustls_client_config().unwrap();
        let suites = config
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>();

        assert_eq!(
            suites,
            vec![super::rustls::CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn reqwest_h3_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(30.0, 300.0, 3_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::adapter_row_from_samples("reqwest_h3", "reqwest_h3_adapter", &samples);

        assert_eq!(row.competitor_id, "reqwest_h3");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(30.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "reqwest_h3_adapter");
    }

    #[test]
    fn specter_native_rfc9220_tunnel_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(40.0, 400.0, 4_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::specter_native_rfc9220_tunnel_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(40.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_adapter");
    }

    #[test]
    fn specter_native_rfc9220_tunnel_close_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(60.0, 600.0, 6_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(30.0, 300.0, 3_000),
        ];

        let row = super::specter_native_rfc9220_tunnel_close_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(30.0));
        assert_eq!(row.p95_ttft_ns, Some(60.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_close_adapter");
    }

    #[test]
    fn specter_native_rfc9220_tunnel_mixed_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(70.0, 700.0, 7_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(40.0, 400.0, 4_000),
        ];

        let row = super::specter_native_rfc9220_tunnel_mixed_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel_mixed");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(40.0));
        assert_eq!(row.p95_ttft_ns, Some(70.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_mixed_adapter");
    }

    #[test]
    fn quiche_direct_rfc9220_tunnel_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(40.0, 400.0, 4_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::quiche_direct_rfc9220_tunnel_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "quiche_direct_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(40.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "quiche_direct_rfc9220_tunnel_adapter");
        assert_eq!(row.protocol.as_deref(), Some("h3_rfc9220"));
        assert_eq!(
            row.workload.as_deref(),
            Some("websocket_over_h3_raw_tunnel_echo")
        );
    }

    #[test]
    fn quiche_direct_rfc9220_tunnel_close_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(60.0, 600.0, 6_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(30.0, 300.0, 3_000),
        ];

        let row = super::quiche_direct_rfc9220_tunnel_close_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "quiche_direct_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(30.0));
        assert_eq!(row.p95_ttft_ns, Some(60.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "quiche_direct_rfc9220_tunnel_close_adapter");
        assert_eq!(row.protocol.as_deref(), Some("h3_rfc9220"));
        assert_eq!(
            row.workload.as_deref(),
            Some("websocket_over_h3_raw_tunnel_close_fin")
        );
    }

    #[test]
    fn tokio_quiche_rfc9220_tunnel_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(50.0, 500.0, 5_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(30.0, 300.0, 3_000),
        ];

        let row = super::tokio_quiche_rfc9220_tunnel_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "tokio_quiche_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(30.0));
        assert_eq!(row.p95_ttft_ns, Some(50.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "tokio_quiche_rfc9220_tunnel_adapter");
        assert_eq!(row.protocol.as_deref(), Some("h3_rfc9220"));
        assert_eq!(
            row.workload.as_deref(),
            Some("websocket_over_h3_raw_tunnel_echo")
        );
    }

    #[test]
    fn tokio_quiche_rfc9220_tunnel_close_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(70.0, 700.0, 7_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(40.0, 400.0, 4_000),
        ];

        let row = super::tokio_quiche_rfc9220_tunnel_close_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "tokio_quiche_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(40.0));
        assert_eq!(row.p95_ttft_ns, Some(70.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "tokio_quiche_rfc9220_tunnel_close_adapter");
        assert_eq!(row.protocol.as_deref(), Some("h3_rfc9220"));
        assert_eq!(
            row.workload.as_deref(),
            Some("websocket_over_h3_raw_tunnel_close_fin")
        );
    }

    #[test]
    fn quinn_transport_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(40.0, 400.0, 4_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::quinn_transport_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "quinn_transport");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(40.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "quinn_transport_adapter");
    }

    #[test]
    fn s2n_quic_transport_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(40.0, 400.0, 4_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::s2n_quic_transport_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "s2n_quic_transport");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(40.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "s2n_quic_transport_adapter");
    }

    #[tokio::test]
    async fn specter_native_local_fixture_reuses_streaming_connection_for_multiple_samples() {
        let fixture = super::LocalNativeH3Fixture::start("specter_native")
            .await
            .unwrap();
        let client = specter::Client::builder()
            .danger_accept_invalid_certs(true)
            .h3_backend(specter::H3Backend::Native)
            .prefer_http2(false)
            .h3_upgrade(false)
            .total_timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();

        for index in 0..8 {
            let bytes = specter_native_fixture_stream_bytes(&client, fixture.stream_url())
                .await
                .unwrap_or_else(|error| panic!("request {index} failed: {error:?}"));
            assert_eq!(
                bytes,
                (super::LOCAL_FIXTURE_CHUNK_SIZE * super::LOCAL_FIXTURE_CHUNK_COUNT) as u64
            );
        }

        assert_eq!(client.connection_reuse_count(), 7);
    }

    #[tokio::test]
    async fn specter_native_local_fixture_measures_rfc9220_tunnel_echo() {
        let fixture = super::LocalNativeH3Fixture::start("specter_native_rfc9220_tunnel")
            .await
            .unwrap();

        let row = super::measure_specter_native_rfc9220_tunnel(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn specter_native_local_fixture_measures_rfc9220_tunnel_close_fin() {
        let fixture = super::LocalNativeH3Fixture::start("specter_native_rfc9220_tunnel_close")
            .await
            .unwrap();

        let row = super::measure_specter_native_rfc9220_tunnel_close(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_close_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn specter_native_local_fixture_measures_rfc9220_tunnel_slow_consumer_mixed_workload() {
        let fixture = super::LocalNativeH3Fixture::start("specter_native_rfc9220_tunnel_mixed")
            .await
            .unwrap();

        let row = super::measure_specter_native_rfc9220_tunnel_mixed(
            fixture.stream_url(),
            &fixture.tunnel_url(),
            0,
            1,
        )
        .await
        .unwrap();

        assert_eq!(row.competitor_id, "specter_native_rfc9220_tunnel_mixed");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "specter_native_rfc9220_tunnel_mixed_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn quiche_direct_local_fixture_measures_rfc9220_tunnel_echo() {
        let fixture = super::LocalNativeH3Fixture::start("quiche_direct_rfc9220_tunnel")
            .await
            .unwrap();

        let row = super::measure_quiche_direct_rfc9220_tunnel(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "quiche_direct_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "quiche_direct_rfc9220_tunnel_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn quiche_direct_local_fixture_measures_rfc9220_tunnel_close_fin() {
        let fixture = super::LocalNativeH3Fixture::start("quiche_direct_rfc9220_tunnel_close")
            .await
            .unwrap();

        let row = super::measure_quiche_direct_rfc9220_tunnel_close(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "quiche_direct_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "quiche_direct_rfc9220_tunnel_close_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn tokio_quiche_local_fixture_measures_rfc9220_tunnel_echo() {
        let fixture = super::LocalNativeH3Fixture::start("tokio_quiche_rfc9220_tunnel")
            .await
            .unwrap();

        let row = super::measure_tokio_quiche_rfc9220_tunnel(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "tokio_quiche_rfc9220_tunnel");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "tokio_quiche_rfc9220_tunnel_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn tokio_quiche_local_fixture_measures_rfc9220_tunnel_close_fin() {
        let fixture = super::LocalNativeH3Fixture::start("tokio_quiche_rfc9220_tunnel_close")
            .await
            .unwrap();

        let row = super::measure_tokio_quiche_rfc9220_tunnel_close(&fixture.tunnel_url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "tokio_quiche_rfc9220_tunnel_close");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "tokio_quiche_rfc9220_tunnel_close_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[tokio::test]
    async fn quinn_transport_fixture_measures_bidirectional_echo() {
        let fixture = super::LocalQuinnTransportFixture::start().await.unwrap();

        let row = super::measure_quinn_transport(fixture.url(), 0, 1)
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "quinn_transport");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "quinn_transport_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    #[cfg(feature = "s2n-quic-transport")]
    #[tokio::test]
    async fn s2n_quic_transport_fixture_measures_bidirectional_echo() {
        let fixture = super::LocalS2nQuicTransportFixture::start().await.unwrap();

        let row = super::measure_s2n_quic_transport(fixture.url(), 0, 1, fixture.cert_path())
            .await
            .unwrap();

        assert_eq!(row.competitor_id, "s2n_quic_transport");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.source, "s2n_quic_transport_adapter");
        assert!(row.p50_ttft_ns.is_some());
        assert!(row.p95_ttft_ns.is_some());
        assert!(row.bytes_per_sec.is_some_and(|throughput| throughput > 0.0));
    }

    async fn specter_native_fixture_stream_bytes(
        client: &specter::Client,
        url: &str,
    ) -> anyhow::Result<u64> {
        let mut response = client
            .get(url)
            .version(specter::HttpVersion::Http3Only)
            .send_streaming()
            .await?;
        let mut bytes = 0u64;
        while let Some(chunk) = response.body_mut().chunk().await {
            match chunk {
                Ok(chunk) => bytes = bytes.saturating_add(chunk.len() as u64),
                Err(error) => anyhow::bail!("stream failed after {bytes} bytes: {error}"),
            }
        }
        Ok(bytes)
    }

    #[test]
    fn quiche_direct_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(40.0, 400.0, 4_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(20.0, 200.0, 2_000),
        ];

        let row = super::quiche_direct_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "quiche_direct");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(20.0));
        assert_eq!(row.p95_ttft_ns, Some(40.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "quiche_direct_adapter");
    }

    #[test]
    fn h3_quinn_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(50.0, 500.0, 5_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(30.0, 300.0, 3_000),
        ];

        let row = super::h3_quinn_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "h3_quinn");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(30.0));
        assert_eq!(row.p95_ttft_ns, Some(50.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "h3_quinn_adapter");
    }

    #[test]
    fn tokio_quiche_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(60.0, 600.0, 6_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(30.0, 300.0, 3_000),
        ];

        let row = super::tokio_quiche_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "tokio_quiche");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(30.0));
        assert_eq!(row.p95_ttft_ns, Some(60.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "tokio_quiche_adapter");
    }

    #[test]
    fn specter_native_adapter_row_uses_measured_samples() {
        let samples = vec![
            super::AdapterSample::new(70.0, 700.0, 7_000),
            super::AdapterSample::new(10.0, 100.0, 1_000),
            super::AdapterSample::new(40.0, 400.0, 4_000),
        ];

        let row = super::specter_native_row_from_samples(&samples);

        assert_eq!(row.competitor_id, "specter_native");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(40.0));
        assert_eq!(row.p95_ttft_ns, Some(70.0));
        assert_eq!(row.bytes_per_sec, Some(10_000_000_000.0));
        assert_eq!(row.source, "specter_native_adapter");
    }

    #[test]
    fn imports_specter_native_h3_row_from_streaming_artifact() {
        let artifact_json = r#"{
          "rows": [
            {
              "protocol": "h3",
              "client": "specter",
              "metrics": {
                "p50_ns": 1234.0,
                "p95_ns": 2345.0,
                "bytes_per_sec": 3456.0,
                "pass": true
              }
            }
          ]
        }"#;

        let row = super::specter_row_from_streaming_artifact(artifact_json)
            .expect("Specter native H3 row should import");

        assert_eq!(row.competitor_id, "specter_native");
        assert_eq!(row.status, "measured_pass");
        assert_eq!(row.p50_ttft_ns, Some(1234.0));
        assert_eq!(row.p95_ttft_ns, Some(2345.0));
        assert_eq!(row.bytes_per_sec, Some(3456.0));
    }
}
