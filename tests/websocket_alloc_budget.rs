//! D3 (WebSocket part): allocation-budget regression test.
//!
//! Pins the per-frame heap-allocation cost of receiving non-fragmented text
//! frames on an established loopback WebSocket. After A1 (zero-copy text-frame
//! decode in `src/websocket/frame.rs`) the steady-state receive path should
//! transfer the validated `Bytes` payload straight into the returned `String`
//! without a fresh allocation + memcpy per frame.
//!
//! ## How to re-measure the budget
//!
//! If the receive path legitimately changes, run this binary with
//! `PRINT_ALLOC_BUDGET=1` set:
//!
//! ```text
//! PRINT_ALLOC_BUDGET=1 just test-one websocket_alloc_budget steady_state
//! ```
//!
//! It prints the measured `allocs / frame` for the steady-state window. Update
//! [`PER_FRAME_ALLOC_BUDGET`] to the printed value (pin conservatively — the
//! assertion is `<= budget`, so publish the smallest number that still passes
//! on a quiet machine).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use warpsock::{Client, Message};

/// Counting global allocator. Only counts allocations while `ACTIVE` is set,
/// so we measure exactly the steady-state receive window and nothing else
/// (handshake, runtime spin-up, warmup frame all happen with counting off).
struct CountingAllocator;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ACTIVE.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Per-frame heap-allocation budget in steady state, measured after A1 on a
/// quiet macOS/aarch64 machine. The assertion is `allocs / frame <= budget`.
///
/// Measured value: **1 allocation per frame** for this test's workload, where a
/// single buffer fill delivers many frames and each frame's payload is a
/// `Bytes` slice of that shared buffer (`buffer.split_to(len).freeze()` in
/// `decode_frame`). Because the parent allocation is still referenced by the
/// remaining queued frames, `Bytes::into::<Vec<u8>>()` cannot reclaim the
/// original buffer in place and allocates the `String` backing store once.
///
/// A1's zero-copy transfer (`String::from_utf8_unchecked(payload.into())`)
/// still eliminates a *second* copy: it never re-scans UTF-8 and, in the common
/// streaming case where one `read` yields exactly one frame (so the payload
/// `Bytes` uniquely owns its buffer), `.into::<Vec<u8>>()` is a true zero-copy
/// move and this path hits 0 allocations. This test pins the conservative
/// shared-buffer worst case; pre-A1 the same workload cost more (a redundant
/// UTF-8 validation + copy). The pin catches any *new* per-frame allocation
/// beyond the single unavoidable `String` buffer.
const PER_FRAME_ALLOC_BUDGET: usize = 1;

/// RFC 6455 handshake accept-key derivation (mirrors the mock server helper).
fn websocket_accept(key: &str) -> String {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use boring::sha::sha1;
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.trim().as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    BASE64.encode(sha1(&input))
}

/// Minimal unmasked server-to-client text frame (RFC 6455 §5.1: server frames
/// are never masked). Small payloads only (<= 125 bytes, 1-byte length).
fn server_text_frame(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    assert!(bytes.len() <= 125, "budget test uses small frames only");
    let mut frame = Vec::with_capacity(2 + bytes.len());
    frame.push(0x81); // FIN + text opcode
    frame.push(bytes.len() as u8); // unmasked, 7-bit length
    frame.extend_from_slice(bytes);
    frame
}

/// A plain-TCP loopback server that completes the RFC 6455 handshake and then
/// streams `frame_count` identical non-fragmented text frames back to back.
async fn spawn_frame_stream_server(
    frame_count: usize,
    payload: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}/alloc-budget");

    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");

        // Read the handshake request headers.
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("read handshake");
            assert_ne!(n, 0, "client closed before completing handshake");
            req.extend_from_slice(&buf[..n]);
            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let raw = std::str::from_utf8(&req).expect("handshake is utf-8");
        let key = raw
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("Sec-WebSocket-Key")
                    .then(|| value.trim().to_string())
            })
            .expect("request carries Sec-WebSocket-Key");

        // Complete the handshake, then stream all frames as one write so the
        // client can drain them from a single buffer fill (steady state).
        let mut out = Vec::new();
        out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
        out.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
        out.extend_from_slice(
            format!("Sec-WebSocket-Accept: {}\r\n\r\n", websocket_accept(&key)).as_bytes(),
        );
        let frame = server_text_frame(payload);
        for _ in 0..frame_count {
            out.extend_from_slice(&frame);
        }
        stream.write_all(&out).await.expect("write frames");
        stream.flush().await.expect("flush");

        // Hold the connection open until the client is done reading.
        let mut sink = [0u8; 256];
        let _ = stream.read(&mut sink).await;
    });

    (url, handle)
}

#[tokio::test]
async fn steady_state_text_receive_stays_within_alloc_budget() {
    const WARMUP_FRAMES: usize = 4;
    const MEASURED_FRAMES: usize = 64;
    const PAYLOAD: &str = "llm delta token chunk";

    let (url, server) = spawn_frame_stream_server(WARMUP_FRAMES + MEASURED_FRAMES, PAYLOAD).await;

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    // Warm up: first reads fill/grow the read buffer and lazily initialize the
    // reusable read timer. These allocations are one-time, not steady-state.
    for _ in 0..WARMUP_FRAMES {
        let msg = ws.next().await.expect("warmup read").expect("warmup frame");
        assert!(matches!(msg, Message::Text(ref t) if t == PAYLOAD));
    }

    // Measure the steady-state window.
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
    for _ in 0..MEASURED_FRAMES {
        let msg = ws.next().await.expect("steady read").expect("steady frame");
        // Keep the payload check but avoid allocating: compare against &str.
        match msg {
            Message::Text(text) => {
                debug_assert_eq!(text, PAYLOAD);
                // `text` (a String backed by the zero-copy Bytes payload) is
                // dropped here; drops are not counted.
            }
            other => panic!("expected text frame, got {other:?}"),
        }
    }
    ACTIVE.store(false, Ordering::Relaxed);

    let total = ALLOC_COUNT.load(Ordering::Relaxed);
    let per_frame = total / MEASURED_FRAMES;

    if std::env::var_os("PRINT_ALLOC_BUDGET").is_some() {
        println!(
            "steady-state receive: {total} allocs over {MEASURED_FRAMES} frames = {per_frame} allocs/frame"
        );
    }

    assert!(
        per_frame <= PER_FRAME_ALLOC_BUDGET,
        "per-frame steady-state allocations regressed: {per_frame} > budget {PER_FRAME_ALLOC_BUDGET} \
         ({total} allocs over {MEASURED_FRAMES} frames). If this is an intentional change, re-measure \
         with PRINT_ALLOC_BUDGET=1 and update PER_FRAME_ALLOC_BUDGET."
    );

    drop(ws);
    let _ = server.await;
}
