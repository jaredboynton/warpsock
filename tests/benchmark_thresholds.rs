#[path = "../benches/streaming_vs_reqwest.rs"]
#[allow(dead_code)]
mod streaming_vs_reqwest;

use std::time::Duration;

use streaming_vs_reqwest::{
    body_transfer_duration, corrected_client_overhead_duration, evaluate_comparable_threshold,
    inter_chunk_gaps_ns, pace_chunk_until, paired_wilcoxon_signed_rank_p_value,
    record_request_sample, record_sample, request_body_transfer_duration,
    response_client_overhead_from_gaps, spin_wait_until, summarize_send_gaps, ActualSendGap,
    DenominatorEvidence, Metrics,
};

fn metrics(ttft_ns: f64, bytes_per_sec: f64, p95_bytes_per_sec: f64, p95_ns: f64) -> Metrics {
    let ttft_samples_ns = vec![ttft_ns; 30];
    let bytes_per_sec_samples = vec![bytes_per_sec; 30];

    Metrics {
        ttft_ns,
        chunks_per_sec: 1_000.0,
        bytes_per_sec,
        p95_bytes_per_sec,
        body_transfer_duration_ns: 8_000_000.0,
        client_overhead_duration_ns: 1_000_000.0,
        client_overhead_unclamped_duration_ns: None,
        client_overhead_denominator_floor_count: 0,
        client_write_overhead_duration_ns: 0.0,
        client_write_overhead_unclamped_duration_ns: None,
        client_write_overhead_denominator_floor_count: 0,
        p50_ns: ttft_ns,
        p95_ns,
        p99_ns: p95_ns,
        warmup_count: 0,
        sample_count: 30,
        connection_reuse_count: 0,
        pass: true,
        actual_send_gap: ActualSendGap::empty(),
        ttft_samples_ns,
        bytes_per_sec_samples,
        response_gap_overhead_by_index_ns: Vec::new(),
    }
}

#[test]
fn comparable_threshold_fails_when_median_throughput_regresses() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 940.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.median_throughput_regression_pct > 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_median_throughput_is_equal() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_000.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert_eq!(result.throughput_improvement_pct, 0.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_median_throughput_win_is_under_five_percent() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_049.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.throughput_improvement_pct < 5.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_median_ttft_win_is_under_five_percent() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(951.0, 1_100.0, 1_100.0, 951.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct < 5.0);
    assert!(result.throughput_improvement_pct >= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_p95_throughput_regresses() {
    let reqwest = metrics(1_000.0, 1_000.0, 2_000.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_850.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct > 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_p95_ttft_regresses_over_five_percent() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_100.0, 1_051.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.throughput_improvement_pct >= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct > 5.0);
}

#[test]
fn comparable_threshold_emits_and_enforces_wilcoxon_p_values() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(result.pass);
    assert!(result.ttft_wilcoxon_signed_rank_p_value < 0.01);
    assert!(result.throughput_wilcoxon_signed_rank_p_value < 0.01);
}

#[test]
fn comparable_threshold_fails_when_wilcoxon_p_values_are_not_significant() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let mut specter = metrics(900.0, 1_100.0, 1_100.0, 900.0);
    specter.ttft_samples_ns = (0..30)
        .map(|idx| if idx < 16 { 900.0 } else { 2_000.0 })
        .collect();
    specter.bytes_per_sec_samples = (0..30)
        .map(|idx| if idx < 16 { 1_100.0 } else { 100.0 })
        .collect();

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.throughput_improvement_pct >= 5.0);
    assert!(result.ttft_wilcoxon_signed_rank_p_value >= 0.01);
    assert!(result.throughput_wilcoxon_signed_rank_p_value >= 0.01);
}

#[test]
fn comparable_threshold_enforces_throughput_for_request_rows_too() {
    // Specter wins TTFT by >5% but loses median throughput, p95 throughput,
    // and Wilcoxon throughput significance. The shared request/response gate
    // must still fail because throughput remains required.
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 900.0, 900.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.median_throughput_regression_pct > 5.0);
    assert!(result.p95_throughput_regression_pct > 5.0);
}

#[test]
fn comparable_threshold_still_enforces_ttft_p95_and_wilcoxon() {
    // p95 TTFT regresses past 5%, so the gate fails even when throughput wins.
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_100.0, 1_060.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);
    assert!(!result.pass);
    assert!(result.p95_ttft_regression_pct > 5.0);
}

#[test]
fn paired_wilcoxon_signed_rank_uses_direction_for_metric_semantics() {
    let baseline = vec![1_000.0; 30];
    let lower_specter = vec![900.0; 30];
    let higher_specter = vec![1_100.0; 30];

    assert!(paired_wilcoxon_signed_rank_p_value(&baseline, &lower_specter, true) < 0.01);
    assert!(paired_wilcoxon_signed_rank_p_value(&baseline, &higher_specter, false) < 0.01);
    assert!(paired_wilcoxon_signed_rank_p_value(&baseline, &higher_specter, true) > 0.99);
    assert!(paired_wilcoxon_signed_rank_p_value(&baseline, &lower_specter, false) > 0.99);
}

#[test]
fn throughput_sample_uses_corrected_client_overhead_duration_not_ttft_or_raw_duration() {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();
    let mut client_overhead_unclamped_duration_values = Vec::new();
    let mut client_overhead_denominator_floor_count = 0;
    let mut send_gap_samples_ns = Vec::new();

    record_sample(
        Duration::from_millis(2),
        Duration::from_millis(8),
        Duration::from_millis(7),
        DenominatorEvidence::from_unclamped_ns(1_000_000.0),
        5 * 1024,
        5,
        &[1_250_000.0, 1_250_000.0, 1_250_000.0, 1_250_000.0],
        &mut ttft_values,
        &mut throughput_values,
        &mut chunk_rates,
        &mut body_transfer_duration_values,
        &mut client_overhead_duration_values,
        &mut client_overhead_unclamped_duration_values,
        &mut client_overhead_denominator_floor_count,
        &mut send_gap_samples_ns,
    );

    assert_eq!(ttft_values, vec![2_000_000.0]);
    assert_eq!(body_transfer_duration_values, vec![8_000_000.0]);
    assert_eq!(client_overhead_duration_values, vec![1_000_000.0]);
    assert_eq!(client_overhead_unclamped_duration_values, vec![1_000_000.0]);
    assert_eq!(client_overhead_denominator_floor_count, 0);
    assert_eq!(throughput_values.len(), 1);
    assert!((throughput_values[0] - 5_120_000.0).abs() < f64::EPSILON);
    assert!((chunk_rates[0] - 5_000.0).abs() < f64::EPSILON);
    assert_eq!(send_gap_samples_ns.len(), 4);
}

#[test]
fn response_gap_overhead_diagnostic_uses_per_gap_pacing_overage_with_floor_evidence() {
    let evidence =
        response_client_overhead_from_gaps(&[1_250_000.0, 900_000.0, 1_100_000.0, 1_000_000.0]);

    assert_eq!(evidence.duration, Duration::from_nanos(350_000));
    assert_eq!(evidence.unclamped_duration_ns, 350_000.0);
    assert_eq!(evidence.floor_count, 0);

    let floor = response_client_overhead_from_gaps(&[900_000.0, 950_000.0]);
    assert_eq!(floor.duration, Duration::from_nanos(1));
    assert_eq!(floor.floor_count, 1);
}

#[test]
fn response_throughput_denominator_uses_supplied_delivery_evidence_not_decoded_gap_count() {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();
    let mut client_overhead_unclamped_duration_values = Vec::new();
    let mut client_overhead_denominator_floor_count = 0;
    let mut send_gap_samples_ns = Vec::new();

    record_sample(
        Duration::from_millis(2),
        Duration::from_millis(8),
        Duration::from_millis(7),
        DenominatorEvidence::from_unclamped_ns(1_000_000.0),
        5 * 1024,
        5,
        &[900_000.0, 950_000.0, 980_000.0, 990_000.0, 995_000.0],
        &mut ttft_values,
        &mut throughput_values,
        &mut chunk_rates,
        &mut body_transfer_duration_values,
        &mut client_overhead_duration_values,
        &mut client_overhead_unclamped_duration_values,
        &mut client_overhead_denominator_floor_count,
        &mut send_gap_samples_ns,
    );

    assert_eq!(client_overhead_duration_values, vec![1_000_000.0]);
    assert_eq!(client_overhead_unclamped_duration_values, vec![1_000_000.0]);
    assert_eq!(client_overhead_denominator_floor_count, 0);
    assert_eq!(throughput_values, vec![5_120_000.0]);
    assert_eq!(send_gap_samples_ns.len(), 5);
}

#[test]
fn request_body_transfer_duration_uses_upload_complete_not_response_complete() {
    let duration = request_body_transfer_duration(Some(2_000_000.0), 7_500_000.0);

    assert_eq!(duration, Duration::from_nanos(5_500_000));
}

#[test]
fn request_body_throughput_uses_upload_complete_denominator_and_emits_floor_evidence() {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();
    let mut client_overhead_unclamped_duration_values = Vec::new();
    let mut client_overhead_denominator_floor_count = 0;
    let mut client_write_overhead_duration_values = Vec::new();
    let mut client_write_overhead_unclamped_duration_values = Vec::new();
    let mut client_write_overhead_denominator_floor_count = 0;
    let mut send_gap_samples_ns = Vec::new();

    record_request_sample(
        Duration::from_millis(9),
        Duration::from_millis(8),
        Duration::from_millis(8),
        DenominatorEvidence::from_unclamped_ns(0.0),
        5 * 1024,
        5,
        &[2_000_000.0, 2_000_000.0, 2_000_000.0, 2_000_000.0],
        &mut ttft_values,
        &mut throughput_values,
        &mut chunk_rates,
        &mut body_transfer_duration_values,
        &mut client_overhead_duration_values,
        &mut client_overhead_unclamped_duration_values,
        &mut client_overhead_denominator_floor_count,
        &mut client_write_overhead_duration_values,
        &mut client_write_overhead_unclamped_duration_values,
        &mut client_write_overhead_denominator_floor_count,
        &mut send_gap_samples_ns,
    );

    assert_eq!(ttft_values, vec![1.0]);
    assert_eq!(body_transfer_duration_values, vec![8_000_000.0]);
    assert_eq!(client_overhead_unclamped_duration_values, vec![0.0]);
    assert_eq!(client_overhead_duration_values, vec![1.0]);
    assert_eq!(client_overhead_denominator_floor_count, 1);
    assert_eq!(client_write_overhead_unclamped_duration_values, vec![0.0]);
    assert_eq!(client_write_overhead_duration_values, vec![1.0]);
    assert_eq!(client_write_overhead_denominator_floor_count, 1);
    assert_eq!(throughput_values, vec![5_120_000_000_000.0]);
    assert_eq!(chunk_rates, vec![5_000_000_000.0]);
    assert_eq!(send_gap_samples_ns.len(), 4);
}

#[test]
fn request_body_gate_uses_write_overhead_not_first_to_header_window() {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();
    let mut client_overhead_unclamped_duration_values = Vec::new();
    let mut client_overhead_denominator_floor_count = 0;
    let mut client_write_overhead_duration_values = Vec::new();
    let mut client_write_overhead_unclamped_duration_values = Vec::new();
    let mut client_write_overhead_denominator_floor_count = 0;
    let mut send_gap_samples_ns = Vec::new();

    record_request_sample(
        Duration::from_millis(20),
        Duration::from_millis(9),
        Duration::from_millis(8),
        DenominatorEvidence::from_unclamped_ns(2_000_000.0),
        5 * 1024,
        5,
        &[],
        &mut ttft_values,
        &mut throughput_values,
        &mut chunk_rates,
        &mut body_transfer_duration_values,
        &mut client_overhead_duration_values,
        &mut client_overhead_unclamped_duration_values,
        &mut client_overhead_denominator_floor_count,
        &mut client_write_overhead_duration_values,
        &mut client_write_overhead_unclamped_duration_values,
        &mut client_write_overhead_denominator_floor_count,
        &mut send_gap_samples_ns,
    );

    assert_eq!(ttft_values, vec![2_000_000.0]);
    assert_eq!(client_overhead_duration_values, vec![2_000_000.0]);
    assert_eq!(client_overhead_unclamped_duration_values, vec![2_000_000.0]);
    assert_eq!(client_overhead_denominator_floor_count, 0);
    assert!((throughput_values[0] - 2_560_000.0).abs() < f64::EPSILON);
    assert_eq!(client_write_overhead_duration_values, vec![2_000_000.0]);
}

#[test]
fn body_transfer_duration_excludes_wait_until_first_body_byte() {
    let duration = body_transfer_duration(
        Some(Duration::from_millis(3)),
        Some(Duration::from_millis(11)),
    );

    assert_eq!(duration, Duration::from_millis(8));
}

#[test]
fn corrected_client_overhead_duration_subtracts_payload_schedule_with_floor() {
    assert_eq!(
        corrected_client_overhead_duration(Duration::from_millis(10), Duration::from_millis(8)),
        Duration::from_millis(2)
    );
    assert_eq!(
        corrected_client_overhead_duration(Duration::from_millis(8), Duration::from_millis(8)),
        Duration::from_nanos(1)
    );
}

#[test]
fn inter_chunk_gaps_ns_returns_pairwise_deltas_clamped_at_zero() {
    let offsets = vec![0.0, 1_000_000.0, 2_050_000.0, 3_010_000.0];
    let gaps = inter_chunk_gaps_ns(&offsets);
    assert_eq!(gaps.len(), 3);
    assert!((gaps[0] - 1_000_000.0).abs() < f64::EPSILON);
    assert!((gaps[1] - 1_050_000.0).abs() < f64::EPSILON);
    assert!((gaps[2] - 960_000.0).abs() < f64::EPSILON);

    let regression = vec![0.0, 5_000.0, 4_000.0];
    let monotonic_gaps = inter_chunk_gaps_ns(&regression);
    assert_eq!(monotonic_gaps[0], 5_000.0);
    assert_eq!(monotonic_gaps[1], 0.0);

    assert!(inter_chunk_gaps_ns(&[]).is_empty());
    assert!(inter_chunk_gaps_ns(&[1_000.0]).is_empty());
}

#[test]
fn summarize_send_gaps_proves_monotonic_deadline_pacing_when_gaps_track_target() {
    let mut samples = vec![1_001_000.0; 120];
    samples.push(1_080_000.0);

    let summary = summarize_send_gaps(&samples, 1);
    assert_eq!(summary.target_ms, 1);
    assert_eq!(summary.sample_count, 121);
    assert!((summary.median_ns - 1_001_000.0).abs() < f64::EPSILON);
    assert!(summary.median_minus_target_ns.abs() <= 5_000.0);
    assert!(summary.p95_minus_target_ns <= 100_000.0);
    assert!((summary.over_budget_fraction - 0.0).abs() < 1e-9);
}

#[test]
fn summarize_send_gaps_flags_scheduler_sleep_jitter_regressions() {
    let samples = vec![2_500_000.0; 100];

    let summary = summarize_send_gaps(&samples, 1);
    assert!(summary.median_minus_target_ns >= 1_000_000.0);
    assert!(summary.over_budget_fraction > 0.5);
}

#[test]
fn summarize_send_gaps_handles_empty_input_without_panic() {
    let summary = summarize_send_gaps(&[], 1);
    assert_eq!(summary.sample_count, 0);
    assert_eq!(summary.median_ns, 0.0);
    assert_eq!(summary.over_budget_fraction, 0.0);
}

#[test]
fn spin_wait_until_returns_immediately_when_target_in_past() {
    let target = std::time::Instant::now() - Duration::from_millis(5);
    let start = std::time::Instant::now();
    spin_wait_until(target);
    assert!(start.elapsed() < Duration::from_micros(500));
}

#[test]
fn spin_wait_until_holds_until_target_with_microsecond_precision() {
    let start = std::time::Instant::now();
    let target = start + Duration::from_micros(800);
    spin_wait_until(target);
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_micros(800));
    assert!(elapsed < Duration::from_millis(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pace_chunk_until_yields_then_spins_to_microsecond_precision() {
    let start = std::time::Instant::now();
    let target = start + Duration::from_millis(1);
    pace_chunk_until(target).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1),
        "pace_chunk_until returned before deadline: {:?}",
        elapsed
    );
    assert!(
        elapsed < Duration::from_millis(3),
        "pace_chunk_until exceeded reasonable upper bound: {:?}",
        elapsed
    );
    assert!(
        elapsed.saturating_sub(Duration::from_millis(1)) < Duration::from_micros(500),
        "pace_chunk_until overshot target by more than 500us: {:?}",
        elapsed
    );
}
