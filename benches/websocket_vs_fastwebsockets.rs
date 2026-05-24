use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use bytes::Bytes;
use fastwebsockets::{Frame, OpCode, Payload, Role};
use serde::Serialize;
use specter::{Client, Message};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_MESSAGES: usize = 2_000;
const DEFAULT_WARMUP_MESSAGES: usize = 200;
const DEFAULT_PAYLOAD_BYTES: usize = 1024;

#[derive(Serialize)]
struct Artifact {
    benchmark: &'static str,
    fastwebsockets_version: &'static str,
    workload: Workload,
    rows: Vec<Row>,
    comparison: Comparison,
}

#[derive(Serialize)]
struct Workload {
    protocol: &'static str,
    messages: usize,
    warmup_messages: usize,
    payload_bytes: usize,
    echo_server: &'static str,
}

#[derive(Serialize)]
struct Row {
    client: &'static str,
    elapsed_ns: u128,
    messages_per_sec: f64,
    bytes_per_sec: f64,
}

#[derive(Serialize)]
struct Comparison {
    specter_vs_fastwebsockets_messages_per_sec_pct: f64,
    pass_match_or_exceed: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let messages = option_value(&args, "--messages")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MESSAGES);
    let payload_bytes = option_value(&args, "--payload-bytes")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PAYLOAD_BYTES);
    let warmup_messages = option_value(&args, "--warmups")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_WARMUP_MESSAGES);
    let json_path = option_value(&args, "--json")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/bench-results/websocket-vs-fastwebsockets.json"));
    let require_thresholds = args.iter().any(|arg| arg == "--require-thresholds");

    let (addr, server_task) = start_echo_server().await?;
    let payload = Bytes::from(vec![0x5a; payload_bytes]);
    let fast = run_fastwebsockets(addr, warmup_messages, messages, &payload).await?;
    let specter = run_specter(addr, warmup_messages, messages, payload.clone()).await?;

    let pct = if fast.messages_per_sec > 0.0 {
        ((specter.messages_per_sec - fast.messages_per_sec) / fast.messages_per_sec) * 100.0
    } else {
        0.0
    };
    let comparison = Comparison {
        specter_vs_fastwebsockets_messages_per_sec_pct: pct,
        pass_match_or_exceed: specter.messages_per_sec >= fast.messages_per_sec,
    };

    let artifact = Artifact {
        benchmark: "websocket_vs_fastwebsockets",
        fastwebsockets_version: "0.10.0",
        workload: Workload {
            protocol: "h1_rfc6455",
            messages,
            warmup_messages,
            payload_bytes,
            echo_server: "fastwebsockets::WebSocket<Role::Server>",
        },
        rows: vec![fast, specter],
        comparison,
    };

    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&json_path, serde_json::to_vec_pretty(&artifact)?)?;
    println!("wrote benchmark artifact {}", json_path.display());

    server_task.abort();

    if require_thresholds && !artifact.comparison.pass_match_or_exceed {
        std::process::exit(1);
    }

    Ok(())
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

async fn start_echo_server(
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = handle_echo_connection(stream).await;
            });
        }
    });
    Ok((addr, task))
}

async fn handle_echo_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let key = request
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = std::str::from_utf8(line).ok()?.trim();
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key")
                .then(|| value.trim().to_string())
        })
        .ok_or("missing Sec-WebSocket-Key")?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        websocket_accept(&key)
    );
    stream.write_all(response.as_bytes()).await?;

    let mut ws = fastwebsockets::WebSocket::after_handshake(stream, Role::Server);
    loop {
        let frame = ws.read_frame().await?;
        if frame.opcode == OpCode::Close {
            break;
        }
        let echo = Frame::new(
            frame.fin,
            frame.opcode,
            None,
            Payload::Owned(frame.payload.to_vec()),
        );
        ws.write_frame(echo).await?;
    }
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + 36);
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    BASE64_STANDARD.encode(boring::sha::sha1(&input))
}

async fn run_specter(
    addr: std::net::SocketAddr,
    warmup_messages: usize,
    messages: usize,
    payload: Bytes,
) -> Result<Row, Box<dyn std::error::Error>> {
    let client = Client::builder().prefer_http2(false).build()?;
    let mut ws = client
        .websocket(format!("ws://{addr}/socket"))
        .connect()
        .await?;

    for _ in 0..warmup_messages {
        ws.send_binary(payload.clone()).await?;
        let _ = ws.next().await?;
    }

    let started = Instant::now();
    for _ in 0..messages {
        ws.send_binary(payload.clone()).await?;
        match ws.next().await? {
            Some(Message::Binary(bytes)) if bytes == payload => {}
            other => return Err(format!("unexpected Specter echo frame: {other:?}").into()),
        }
    }
    let elapsed = started.elapsed();
    ws.close(None).await?;
    Ok(row("specter", elapsed, messages, payload.len()))
}

async fn run_fastwebsockets(
    addr: std::net::SocketAddr,
    warmup_messages: usize,
    messages: usize,
    payload: &[u8],
) -> Result<Row, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    let key = BASE64_STANDARD.encode([7_u8; 16]);
    let request = format!(
        "GET /socket HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Err("fastwebsockets handshake closed".into());
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let mut ws = fastwebsockets::WebSocket::after_handshake(stream, Role::Client);
    for _ in 0..warmup_messages {
        ws.write_frame(Frame::binary(Payload::Borrowed(payload)))
            .await?;
        let _ = ws.read_frame().await?;
    }

    let started = Instant::now();
    for _ in 0..messages {
        ws.write_frame(Frame::binary(Payload::Borrowed(payload)))
            .await?;
        let frame = ws.read_frame().await?;
        if frame.opcode != OpCode::Binary || &frame.payload[..] != payload {
            return Err("unexpected fastwebsockets echo frame".into());
        }
    }
    let elapsed = started.elapsed();
    ws.write_frame(Frame::close(1000, b"")).await?;
    Ok(row("fastwebsockets", elapsed, messages, payload.len()))
}

fn row(client: &'static str, elapsed: Duration, messages: usize, payload_bytes: usize) -> Row {
    let seconds = elapsed.as_secs_f64();
    Row {
        client,
        elapsed_ns: elapsed.as_nanos(),
        messages_per_sec: messages as f64 / seconds,
        bytes_per_sec: (messages * payload_bytes) as f64 / seconds,
    }
}
