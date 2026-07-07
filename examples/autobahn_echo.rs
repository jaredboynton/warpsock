//! Autobahn TestSuite client-mode echo driver.
//!
//! Connects to a fuzzingserver case URL, echoes every received text/binary
//! message back verbatim, and honours control frames per RFC 6455. This is the
//! standard Autobahn "client under test" shape: the fuzzingserver drives every
//! protocol edge case and grades our responses.
//!
//! Not wired into the default test suite; invoked only by `scripts/autobahn.sh`
//! (which the `just autobahn` recipe runs). Requires Docker for the server.
//!
//! Usage:
//!   autobahn_echo <ws-url>
//! e.g.
//!   autobahn_echo 'ws://127.0.0.1:9001/runCase?case=1&agent=warpsock'
//!
//! When AUTOBAHN_PRINT_FIRST=1 is set, the driver prints the first received
//! text message to stdout and exits. This is used to read the integer returned
//! by the fuzzingserver's `getCaseCount` endpoint.
//!
//! When AUTOBAHN_DEFLATE=1 is set, the driver offers permessage-deflate
//! (RFC 7692) on the handshake so the compression cases (12.x/13.x) run.

use std::process::ExitCode;

use warpsock::{Client, Message};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let url = match args.next() {
        Some(url) => url,
        None => {
            eprintln!("usage: autobahn_echo <ws-url>");
            return ExitCode::from(2);
        }
    };

    let print_first = std::env::var("AUTOBAHN_PRINT_FIRST").is_ok_and(|v| v == "1");

    match run(&url, print_first).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // A protocol failure here is expected for the fuzzing cases that
            // probe our error handling; the fuzzingserver records the outcome
            // from the wire, not from our exit code. Log for humans and move on.
            eprintln!("autobahn_echo: {url}: {err}");
            // A non-zero code only matters for the getCaseCount probe.
            if print_first {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

async fn run(url: &str, print_first: bool) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new()?;
    // When AUTOBAHN_DEFLATE=1, offer permessage-deflate (RFC 7692) so the
    // fuzzingserver drives the compression cases (12.x/13.x) instead of
    // grading them UNIMPLEMENTED. Uses the Chrome-accurate default offer.
    let builder = client.websocket(url);
    let builder = if std::env::var("AUTOBAHN_DEFLATE").is_ok_and(|v| v == "1") {
        builder.permessage_deflate()
    } else {
        builder
    };
    let mut ws = builder.connect().await?;

    // Echo loop: text -> text, binary -> binary. `next()` already answers
    // incoming pings with pongs and replies to a server Close (returning
    // `None`), so we do not special-case control frames -- the point is to
    // measure conformance of the library's own frame handling.
    loop {
        match ws.next().await? {
            Some(Message::Text(text)) => {
                if print_first {
                    // getCaseCount probe: emit the integer and stop.
                    println!("{text}");
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                ws.send_text(text).await?;
            }
            Some(Message::Binary(bytes)) => {
                ws.send_binary(bytes).await?;
            }
            // Pings are auto-ponged inside `next()`; nothing to echo. Pongs are
            // unsolicited acknowledgements -- ignore per RFC 6455 5.5.3.
            Some(Message::Ping(_)) | Some(Message::Pong(_)) => {}
            // A Close message never surfaces as `Some`; `next()` maps it to
            // `None` after replying with a matching close. Guard anyway.
            Some(Message::Close(_)) | None => break,
        }
    }

    Ok(())
}
