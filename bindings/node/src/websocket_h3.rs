use bytes::Bytes;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use specter::transport::h3::H3TunnelEvent as RustH3TunnelEvent;
use specter::{Client as RustClient, Error as RustError};
use std::result::Result as StdResult;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

use crate::to_napi_err;
use crate::Client;

const FORBIDDEN_H3_TUNNEL_HEADERS: &[&str] = &[
    "connection",
    "upgrade",
    "host",
    "sec-websocket-key",
    "sec-websocket-accept",
    "sec-websocket-extensions",
];

#[napi(object)]
pub struct H3TunnelEvent {
    pub r#type: String,
    pub data: Option<Buffer>,
    pub reason: Option<String>,
    pub last_stream_id: Option<BigInt>,
}

#[napi]
pub struct WebSocketH3Builder {
    client: RustClient,
    url: String,
    headers: Vec<(String, String)>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[napi]
pub struct WebSocketH3Tunnel {
    send_tx: mpsc::Sender<SendCommand>,
    event_rx: Mutex<mpsc::Receiver<StdResult<Option<RustH3TunnelEvent>, RustError>>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

enum SendCommand {
    Bytes(Bytes, bool),
    Close,
}

impl WebSocketH3Builder {
    pub(crate) fn new(client: RustClient, url: String) -> Self {
        Self {
            client,
            url,
            headers: Vec::new(),
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

pub(crate) fn builder_for_client(client: &Client, url: String) -> WebSocketH3Builder {
    WebSocketH3Builder::new(client.inner.clone(), url)
}

#[napi]
impl WebSocketH3Builder {
    #[napi]
    pub fn header(&mut self, key: String, value: String) -> Result<&Self> {
        reject_forbidden_header(&key)?;
        self.headers.push((key, value));
        Ok(self)
    }

    #[napi]
    pub fn headers(&mut self, headers: Vec<Vec<String>>) -> Result<&Self> {
        let parsed = parse_headers(headers)?;
        for (key, _) in &parsed {
            reject_forbidden_header(key)?;
        }
        self.headers = parsed;
        Ok(self)
    }

    #[napi]
    pub fn subprotocol(&mut self, subprotocol: String) -> Result<&Self> {
        self.header("sec-websocket-protocol".to_string(), subprotocol)
    }

    #[napi]
    pub fn connect_timeout(&mut self, timeout_secs: f64) -> Result<&Self> {
        self.connect_timeout = Some(duration_from_secs(timeout_secs, "connectTimeout")?);
        Ok(self)
    }

    #[napi]
    pub fn read_timeout(&mut self, timeout_secs: f64) -> Result<&Self> {
        self.read_timeout = Some(duration_from_secs(timeout_secs, "readTimeout")?);
        Ok(self)
    }

    #[napi]
    pub fn write_timeout(&mut self, timeout_secs: f64) -> Result<&Self> {
        self.write_timeout = Some(duration_from_secs(timeout_secs, "writeTimeout")?);
        Ok(self)
    }

    #[napi]
    pub async fn connect(&self) -> Result<WebSocketH3Tunnel> {
        let mut builder = self.client.websocket_h3(self.url.as_str());
        for (key, value) in &self.headers {
            builder = builder.header(key.clone(), value.clone());
        }

        let open = builder.open();
        let tunnel = if let Some(timeout) = self.connect_timeout {
            tokio::time::timeout(timeout, open)
                .await
                .map_err(|_| {
                    Error::new(Status::GenericFailure, "websocketH3 connectTimeout elapsed")
                })?
                .map_err(to_napi_err)?
        } else {
            open.await.map_err(to_napi_err)?
        };

        Ok(WebSocketH3Tunnel::new(
            tunnel,
            self.read_timeout,
            self.write_timeout,
        ))
    }
}

impl WebSocketH3Tunnel {
    fn new(
        mut tunnel: specter::transport::h3::H3Tunnel,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Self {
        let (send_tx, mut send_rx) = mpsc::channel::<SendCommand>(32);
        let (event_tx, event_rx) =
            mpsc::channel::<StdResult<Option<RustH3TunnelEvent>, RustError>>(32);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = send_rx.recv() => {
                        let Some(command) = command else {
                            break;
                        };
                        let result = match command {
                            SendCommand::Bytes(bytes, fin) => tunnel.send_bytes(bytes, fin).await,
                            SendCommand::Close => tunnel.close_send().await,
                        };
                        if let Err(err) = result {
                            let _ = event_tx.send(Err(err)).await;
                            break;
                        }
                    }
                    event = tunnel.recv_event() => {
                        match event {
                            Some(Ok(event)) => {
                                if event_tx.send(Ok(Some(event))).await.is_err() {
                                    break;
                                }
                            }
                            Some(Err(err)) => {
                                let _ = event_tx.send(Err(err)).await;
                                break;
                            }
                            None => {
                                let _ = event_tx.send(Ok(None)).await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        Self {
            send_tx,
            event_rx: Mutex::new(event_rx),
            read_timeout,
            write_timeout,
        }
    }
}

#[napi]
impl WebSocketH3Tunnel {
    #[napi]
    pub async fn send_bytes(&self, data: Buffer, fin: Option<bool>) -> Result<()> {
        let command = SendCommand::Bytes(Bytes::copy_from_slice(data.as_ref()), fin.unwrap_or(false));
        self.send_command(command).await
    }

    #[napi]
    pub async fn close_send(&self) -> Result<()> {
        self.send_command(SendCommand::Close).await
    }

    #[napi]
    pub async fn recv_bytes(&self) -> Result<Option<Buffer>> {
        loop {
            let Some(event) = self.next_event().await? else {
                return Ok(None);
            };
            match event {
                RustH3TunnelEvent::Data(bytes) => return Ok(Some(Buffer::from(bytes.to_vec()))),
                RustH3TunnelEvent::EndStream => return Ok(None),
                RustH3TunnelEvent::Reset(reason) => {
                    return Err(Error::new(
                        Status::GenericFailure,
                        format!("H3 tunnel reset: {reason}"),
                    ));
                }
                RustH3TunnelEvent::GoAway { id } => {
                    return Err(Error::new(
                        Status::GenericFailure,
                        format!("H3 tunnel closed by GOAWAY lastStreamId={id}"),
                    ));
                }
            }
        }
    }

    #[napi]
    pub async fn recv_event(&self) -> Result<Option<H3TunnelEvent>> {
        let Some(event) = self.next_event().await? else {
            return Ok(None);
        };

        Ok(Some(match event {
            RustH3TunnelEvent::Data(bytes) => H3TunnelEvent {
                r#type: "data".to_string(),
                data: Some(Buffer::from(bytes.to_vec())),
                reason: None,
                last_stream_id: None,
            },
            RustH3TunnelEvent::EndStream => H3TunnelEvent {
                r#type: "endStream".to_string(),
                data: None,
                reason: None,
                last_stream_id: None,
            },
            RustH3TunnelEvent::Reset(reason) => H3TunnelEvent {
                r#type: "reset".to_string(),
                data: None,
                reason: Some(reason),
                last_stream_id: None,
            },
            RustH3TunnelEvent::GoAway { id } => H3TunnelEvent {
                r#type: "goAway".to_string(),
                data: None,
                reason: None,
                last_stream_id: Some(BigInt::from(id)),
            },
        }))
    }
}

impl WebSocketH3Tunnel {
    async fn send_command(&self, command: SendCommand) -> Result<()> {
        let send = self.send_tx.send(command);
        if let Some(timeout) = self.write_timeout {
            tokio::time::timeout(timeout, send)
                .await
                .map_err(|_| {
                    Error::new(Status::GenericFailure, "websocketH3 writeTimeout elapsed")
                })?
                .map_err(|_| Error::new(Status::GenericFailure, "H3 tunnel send channel closed"))
        } else {
            send.await
                .map_err(|_| Error::new(Status::GenericFailure, "H3 tunnel send channel closed"))
        }
    }

    async fn next_event(&self) -> Result<Option<RustH3TunnelEvent>> {
        let mut event_rx = self.event_rx.lock().await;
        let recv = event_rx.recv();
        let event = if let Some(timeout) = self.read_timeout {
            tokio::time::timeout(timeout, recv).await.map_err(|_| {
                Error::new(Status::GenericFailure, "websocketH3 readTimeout elapsed")
            })?
        } else {
            recv.await
        };

        match event {
            Some(Ok(event)) => Ok(event),
            Some(Err(err)) => Err(to_napi_err(err)),
            None => Ok(None),
        }
    }
}

fn parse_headers(headers: Vec<Vec<String>>) -> Result<Vec<(String, String)>> {
    headers
        .into_iter()
        .map(|pair| {
            if pair.len() != 2 {
                Err(Error::new(
                    Status::InvalidArg,
                    "Each header must be a [key, value] pair",
                ))
            } else {
                Ok((pair[0].clone(), pair[1].clone()))
            }
        })
        .collect()
}

fn reject_forbidden_header(key: &str) -> Result<()> {
    let lower = key.to_ascii_lowercase();
    if lower.starts_with(':') || FORBIDDEN_H3_TUNNEL_HEADERS.contains(&lower.as_str()) {
        return Err(Error::new(
            Status::InvalidArg,
            format!("Forbidden RFC 9220 header: {lower}"),
        ));
    }
    Ok(())
}

fn duration_from_secs(timeout_secs: f64, name: &str) -> Result<Duration> {
    if !timeout_secs.is_finite() || timeout_secs < 0.0 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{name} must be a finite non-negative number of seconds"),
        ));
    }
    Ok(Duration::from_secs_f64(timeout_secs))
}
