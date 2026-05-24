use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::future::poll_fn;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
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
use tokio::io::AsyncWriteExt;

const QUICHE_MAX_DATAGRAM_SIZE: usize = 1350;
const ADAPTER_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_FIXTURE_CHUNK_SIZE: usize = 16 * 1024;
const LOCAL_FIXTURE_CHUNK_COUNT: usize = 5;
const LOCAL_FIXTURE_CHUNK_DELAY_MS: u64 = 1;
const LOCAL_FIXTURE_H3_STREAM_SEGMENT_SIZE: usize = 1_200;
const LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE: usize = 1_024;
const LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE: usize = 1_024;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BenchmarkRow {
    competitor_id: String,
    status: String,
    p50_ttft_ns: Option<f64>,
    p95_ttft_ns: Option<f64>,
    bytes_per_sec: Option<f64>,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureEvent {
    client: String,
    level: &'static str,
    kind: &'static str,
    classification: &'static str,
    message: String,
    datagram: Option<String>,
    app_ready: Option<bool>,
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

    Some(BenchmarkRow {
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
    })
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

    BenchmarkRow {
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
    }
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

fn quinn_transport_row_from_samples(samples: &[AdapterSample]) -> BenchmarkRow {
    adapter_row_from_samples("quinn_transport", "quinn_transport_adapter", samples)
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

fn local_native_fixture_measurement_plan() -> Vec<&'static str> {
    #[cfg(feature = "reqwest-h3")]
    {
        let mut plan = vec![
            "specter_native",
            "quiche_direct",
            "tokio_quiche",
            "h3_quinn",
        ];
        plan.push("reqwest_h3");
        plan.push("quinn_transport");
        plan.push("specter_native_rfc9220_tunnel");
        plan
    }
    #[cfg(not(feature = "reqwest-h3"))]
    {
        vec![
            "specter_native",
            "quiche_direct",
            "tokio_quiche",
            "h3_quinn",
            "quinn_transport",
            "specter_native_rfc9220_tunnel",
        ]
    }
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
            if let Some(row) = imported_competitor_rows
                .iter()
                .find(|row| row.competitor_id == spec.id)
            {
                return row.clone();
            }
            if spec.id == "specter_native" {
                if let Some(row) = imported_specter_row.as_ref() {
                    return row.clone();
                }
            }
            BenchmarkRow {
                competitor_id: spec.id.into(),
                status: if spec.id == "specter_native" {
                    "pending_measurement"
                } else {
                    "pending_adapter"
                }
                .into(),
                p50_ttft_ns: None,
                p95_ttft_ns: None,
                bytes_per_sec: None,
                source: "native_h3_vs_rust_clients_harness".into(),
            }
        })
        .collect()
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
        rows,
        fixture_events,
    }
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

    if args.iter().any(|arg| arg == "--require-superiority") && !artifact.superiority_gate.pass {
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
            #[cfg(feature = "reqwest-h3")]
            "reqwest_h3" => measure_reqwest_h3(url, warmups, samples).await,
            "specter_native_rfc9220_tunnel" => {
                let tunnel_url = fixture.tunnel_url();
                measure_specter_native_rfc9220_tunnel(&tunnel_url, warmups, samples).await
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
            url: format!("quic://localhost:{port}/transport"),
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
    let fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
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
            tokio::select! {
                _ = tokio::time::sleep(server_application_ack_delay), if server_application_ack_deadline.is_some() => {
                    if let Err(error) = self.send_delayed_application_ack().await {
                        eprintln!("local native H3 fixture delayed ACK error: {error}");
                    }
                }
                packet = self.rx.recv() => {
                    let Some(packet) = packet else { break };
                    if let Err(error) = self.process_datagram(&packet).await {
                        let datagram = describe_local_native_h3_datagram(&packet);
                        let app_ready = self.handshake.is_application_ready();
                        let classification =
                            classify_local_native_h3_packet_error(&error, app_ready);
                        eprintln!(
                            "local native H3 fixture packet error: {error}; {}; app_ready={}",
                            datagram,
                            app_ready
                        );
                        self.record_event(FixtureEvent {
                            client: self.client.clone(),
                            level: "warn",
                            kind: "packet_error",
                            classification,
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
                    self.handle_request_headers(event.stream_id, headers).await?;
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
        self.response_tx
            .send(LocalNativeH3Response {
                stream_id,
                bytes,
                fin,
            })
            .await
            .map_err(|_| anyhow::anyhow!("local native H3 fixture response queue closed"))?;
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

fn classify_local_native_h3_packet_error(error: &anyhow::Error, app_ready: bool) -> &'static str {
    let message = error.to_string();
    if message.contains("QUIC packet open failed") && app_ready {
        "post_application_packet_open_error"
    } else if message.contains("QUIC packet open failed") {
        "handshake_packet_open_error"
    } else if message.contains("Idle timeout") {
        "idle_timeout"
    } else {
        "packet_error"
    }
}

async fn measure_specter_native(
    url: &str,
    warmups: usize,
    samples: usize,
) -> anyhow::Result<BenchmarkRow> {
    let mut fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
    fingerprint.transport.ack_eliciting_threshold = 128;
    let client = specter::H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_http3_fingerprint(fingerprint)
        .with_max_idle_timeout(ADAPTER_TIMEOUT.as_millis() as u64);
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
    let mut fingerprint = specter::fingerprint::Http3Fingerprint::chrome();
    fingerprint.transport.ack_eliciting_threshold = 128;
    let client = specter::Client::builder()
        .danger_accept_invalid_certs(true)
        .h3_backend(specter::H3Backend::Native)
        .h3_fingerprint(fingerprint)
        .prefer_http2(false)
        .h3_upgrade(false)
        .total_timeout(ADAPTER_TIMEOUT)
        .build()?;

    for _ in 0..warmups {
        let _ = measure_specter_native_rfc9220_tunnel_once(&client, url).await?;
    }

    let mut measured = Vec::with_capacity(samples);
    for _ in 0..samples {
        measured.push(measure_specter_native_rfc9220_tunnel_once(&client, url).await?);
    }

    Ok(specter_native_rfc9220_tunnel_row_from_samples(&measured))
}

async fn measure_specter_native_rfc9220_tunnel_once(
    client: &specter::Client,
    url: &str,
) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'w'; LOCAL_FIXTURE_TUNNEL_PAYLOAD_SIZE]);
    let start = Instant::now();
    let mut tunnel = tokio::time::timeout(ADAPTER_TIMEOUT, client.websocket_h3(url).open())
        .await
        .map_err(|_| anyhow::anyhow!("specter_native RFC 9220 tunnel open timed out"))??;

    tunnel.send_bytes(payload.clone(), false).await?;

    let echoed = tokio::time::timeout(ADAPTER_TIMEOUT, tunnel.recv_bytes())
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

async fn measure_quinn_transport_once(connection: &quinn::Connection) -> anyhow::Result<AdapterSample> {
    let payload = Bytes::from(vec![b'q'; LOCAL_FIXTURE_TRANSPORT_PAYLOAD_SIZE]);
    let start = Instant::now();
    let (mut send, mut recv) = tokio::time::timeout(ADAPTER_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| anyhow::anyhow!("quinn_transport open_bi timed out"))??;

    send.write_all(payload.as_ref()).await?;
    send.finish()?;
    let echoed = tokio::time::timeout(
        ADAPTER_TIMEOUT,
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
    let deadline = start + ADAPTER_TIMEOUT;
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
            anyhow::bail!("tokio_quiche timed out after {:?}", ADAPTER_TIMEOUT);
        };
        let event = tokio::time::timeout(remaining, controller.event_receiver_mut().recv())
            .await
            .map_err(|_| anyhow::anyhow!("tokio_quiche timed out after {:?}", ADAPTER_TIMEOUT))?
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
            anyhow::bail!("tokio_quiche body timed out after {:?}", ADAPTER_TIMEOUT);
        };
        let frame = tokio::time::timeout(remaining, recv.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!("tokio_quiche body timed out after {:?}", ADAPTER_TIMEOUT)
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
    let deadline = start + ADAPTER_TIMEOUT;
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

    anyhow::bail!("quiche_direct timed out after {:?}", ADAPTER_TIMEOUT)
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
        super::BenchmarkRow {
            competitor_id: competitor_id.into(),
            status: "measured_pass".into(),
            p50_ttft_ns: Some(p50_ttft_ns),
            p95_ttft_ns: Some(p95_ttft_ns),
            bytes_per_sec: Some(bytes_per_sec),
            source: "test_fixture".into(),
        }
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
    fn local_native_fixture_plan_includes_feature_enabled_clients() {
        #[cfg(not(feature = "reqwest-h3"))]
        let expected = vec![
            "specter_native",
            "quiche_direct",
            "tokio_quiche",
            "h3_quinn",
            "specter_native_rfc9220_tunnel",
        ];
        #[cfg(feature = "reqwest-h3")]
        let expected = vec![
            "specter_native",
            "quiche_direct",
            "tokio_quiche",
            "h3_quinn",
            "reqwest_h3",
            "specter_native_rfc9220_tunnel",
        ];

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

        assert_eq!(
            super::classify_local_native_h3_packet_error(&error, true),
            "post_application_packet_open_error"
        );
        assert_eq!(
            super::classify_local_native_h3_packet_error(&error, false),
            "handshake_packet_open_error"
        );
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
        };
        let event = super::FixtureEvent {
            client: "h3_quinn".into(),
            level: "warn",
            kind: "packet_error",
            classification: "post_application_packet_open_error",
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
