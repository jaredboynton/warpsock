#[test]
fn native_h3_competitor_benchmark_is_isolated_and_covers_known_fast_clients() {
    let main_manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");
    assert!(
        !main_manifest
            .lines()
            .any(|line| line.trim_start().starts_with("quiche =")),
        "Specter itself must stay quiche-free; competitor dependencies belong in the isolated benchmark crate"
    );

    let bench_manifest = std::fs::read_to_string("benches/native_h3_vs_rust_clients/Cargo.toml")
        .expect("isolated native H3 competitor benchmark manifest should exist");
    for required in [
        "quiche = { version = \"0.29.0\"",
        "tokio-quiche = \"0.19.0\"",
        "h3 = \"0.0.8\"",
        "h3-quinn = \"0.0.10\"",
        "reqwest = { version = \"0.13.3\"",
        "quinn = \"0.11.9\"",
        "s2n-quic = { version = \"1.80.0\"",
    ] {
        assert!(
            bench_manifest.contains(required),
            "competitor benchmark manifest must include {required}"
        );
    }
    assert!(
        bench_manifest.contains("reqwest-h3 = [\"reqwest/http3\"]"),
        "reqwest HTTP/3 must be explicitly enabled through the unstable HTTP/3 feature"
    );

    let bench_source = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("isolated native H3 competitor benchmark source should exist");
    for required in [
        "specter_native",
        "quiche_direct",
        "tokio_quiche",
        "h3_quinn",
        "reqwest_h3",
        "quinn_transport",
        "s2n_quic_transport",
        "--require-superiority",
        "--specter-streaming-artifact",
        "--measure-local-native-fixture",
        "--measure-specter-native-url",
        "--measure-quiche-direct-url",
        "--measure-tokio-quiche-url",
        "--measure-h3-quinn-url",
        "--measure-reqwest-h3-url",
        "--measure-quinn-transport-url",
        "--measure-s2n-quic-transport-url",
        "--s2n-quic-cert",
        "streaming_vs_reqwest_h3_artifact",
        "fastest_non_specter_h3_client",
        "no_h3_superiority_claim_without_all_required_rows",
    ] {
        assert!(
            bench_source.contains(required),
            "competitor benchmark source must include {required}"
        );
    }
}
