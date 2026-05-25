use base64::Engine;
use bytes::Bytes;
use http::Uri;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout as tokio_timeout;
use crate::url::{Host, Url};

use crate::headers::Headers;
use crate::transport::connector::MaybeHttpsStream;

use super::{WebSocketError, WebSocketResult};

const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct WebSocketUrl {
    pub(crate) original: Url,
    pub(crate) http_equivalent: Url,
    pub(crate) request_target: String,
    pub(crate) host_header: String,
    pub(crate) uri: Uri,
    pub(crate) secure: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct HandshakeRequest {
    pub(crate) url: WebSocketUrl,
    pub(crate) headers: Headers,
    pub(crate) key: String,
}

#[derive(Debug)]
pub(crate) struct HandshakeResponse {
    pub(crate) stream: MaybeHttpsStream,
    pub(crate) headers: Headers,
    pub(crate) buffered: Bytes,
    pub(crate) protocol: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HandshakeTimeouts {
    pub(crate) connect: Option<Duration>,
    pub(crate) handshake: Option<Duration>,
}

pub(crate) fn map_websocket_url(url: Url) -> WebSocketResult<WebSocketUrl> {
    let secure = match url.scheme() {
        "ws" => false,
        "wss" => true,
        scheme => {
            return Err(WebSocketError::protocol(
                &url,
                format!("unsupported WebSocket URL scheme `{}` for {}", scheme, url),
            ))
        }
    };

    if url.host_str().is_none() {
        return Err(WebSocketError::protocol(
            &url,
            format!("WebSocket URL missing host: {}", url),
        ));
    }

    let mut http_equivalent = url.clone();
    http_equivalent
        .set_scheme(if secure { "https" } else { "http" })
        .map_err(|_| WebSocketError::protocol(&url, "failed to map WebSocket URL scheme"))?;

    let request_target = origin_form_target(&url);
    let host_header = host_header(&url);
    let uri = http_equivalent
        .as_str()
        .parse::<Uri>()
        .map_err(|err| WebSocketError::protocol(&url, format!("invalid mapped URI: {}", err)))?;

    Ok(WebSocketUrl {
        original: url,
        http_equivalent,
        request_target,
        host_header,
        uri,
        secure,
    })
}

pub(crate) fn build_handshake_request(
    url: WebSocketUrl,
    default_headers: &Headers,
    user_headers: &Headers,
    subprotocols: &[String],
    cookie_header: Option<String>,
) -> WebSocketResult<HandshakeRequest> {
    let protocols = validate_subprotocols(&url.original, subprotocols)?;
    let key = generate_key(&url.original)?;
    let mut headers = Headers::new();

    copy_non_critical_headers(default_headers, &mut headers);
    copy_non_critical_headers(user_headers, &mut headers);

    if !headers.contains("host") {
        headers.insert("Host", url.host_header.clone());
    }

    if !headers.contains("cookie") {
        if let Some(cookie_header) = cookie_header {
            headers.insert("Cookie", cookie_header);
        }
    }

    headers.remove("upgrade");
    headers.remove("connection");
    headers.remove("sec-websocket-key");
    headers.remove("sec-websocket-version");
    headers.remove("sec-websocket-protocol");
    headers.remove("sec-websocket-extensions");

    headers.insert("Upgrade", "websocket");
    headers.insert("Connection", "Upgrade");
    headers.insert("Sec-WebSocket-Key", key.clone());
    headers.insert("Sec-WebSocket-Version", "13");
    if !protocols.is_empty() {
        headers.insert("Sec-WebSocket-Protocol", protocols.join(", "));
    }

    Ok(HandshakeRequest { url, headers, key })
}

pub(crate) async fn perform_handshake(
    mut stream: MaybeHttpsStream,
    request: &HandshakeRequest,
    offered_protocols: &[String],
    timeout: Option<Duration>,
) -> WebSocketResult<HandshakeResponse> {
    let request_bytes = serialize_request(request);
    let fut = async {
        stream
            .write_all(&request_bytes)
            .await
            .map_err(|err| WebSocketError::io(&request.url.original, err))?;
        stream
            .flush()
            .await
            .map_err(|err| WebSocketError::io(&request.url.original, err))?;

        let (headers, buffered) = read_response_headers(&request.url.original, &mut stream).await?;
        validate_response(
            &request.url.original,
            &headers,
            &request.key,
            offered_protocols,
        )?;
        let protocol = headers
            .get("sec-websocket-protocol")
            .map(|value| value.trim().to_string());

        Ok(HandshakeResponse {
            stream,
            headers,
            buffered,
            protocol,
        })
    };

    match timeout {
        Some(duration) => {
            tokio_timeout(duration, fut)
                .await
                .map_err(|_| WebSocketError::Timeout {
                    url: request.url.original.to_string(),
                    operation: format!("handshake after {:?}", duration),
                })?
        }
        None => fut.await,
    }
}

pub(crate) fn expected_accept(key: &str) -> String {
    let mut bytes = Vec::with_capacity(key.len() + ACCEPT_GUID.len());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(ACCEPT_GUID.as_bytes());
    let digest = boring::sha::sha1(&bytes);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

fn serialize_request(request: &HandshakeRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(format!("GET {} HTTP/1.1\r\n", request.url.request_target).as_bytes());
    for (name, value) in request.headers.iter_ordered() {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

async fn read_response_headers(
    url: &Url,
    stream: &mut MaybeHttpsStream,
) -> WebSocketResult<(Headers, Bytes)> {
    let mut buffer = Vec::with_capacity(4096);
    let mut scratch = [0u8; 1024];

    loop {
        if let Some(end) = find_header_end(&buffer) {
            let remainder = buffer.split_off(end + 4);
            let headers = parse_response(url, &buffer[..end + 4])?;
            return Ok((headers, Bytes::from(remainder)));
        }

        if buffer.len() >= MAX_HANDSHAKE_BYTES {
            return Err(WebSocketError::protocol(
                url,
                "WebSocket handshake response exceeded 65536 bytes",
            ));
        }

        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|err| WebSocketError::io(url, err))?;
        if read == 0 {
            return Err(WebSocketError::protocol(
                url,
                "connection closed before WebSocket handshake completed",
            ));
        }
        buffer.extend_from_slice(&scratch[..read]);
    }
}

fn parse_response(url: &Url, bytes: &[u8]) -> WebSocketResult<Headers> {
    let mut header_storage = [httparse::EMPTY_HEADER; 96];
    let mut response = httparse::Response::new(&mut header_storage);
    let status = response.parse(bytes).map_err(|err| {
        WebSocketError::protocol(url, format!("invalid handshake response: {}", err))
    })?;

    if !status.is_complete() {
        return Err(WebSocketError::protocol(
            url,
            "incomplete handshake response",
        ));
    }

    if response.code != Some(101) {
        return Err(WebSocketError::InvalidStatus {
            url: url.to_string(),
            status: response.code.unwrap_or(0),
        });
    }

    let mut headers = Headers::new();
    for header in response.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| WebSocketError::protocol(url, "handshake response header is not UTF-8"))?;
        headers.append(header.name.to_string(), value.to_string());
    }

    Ok(headers)
}

fn validate_response(
    url: &Url,
    headers: &Headers,
    key: &str,
    offered_protocols: &[String],
) -> WebSocketResult<()> {
    let upgrade = headers
        .get("upgrade")
        .ok_or_else(|| WebSocketError::protocol(url, "missing Upgrade header"))?;
    if !contains_token(upgrade, "websocket") {
        return Err(WebSocketError::protocol(url, "invalid Upgrade header"));
    }

    let connection = headers
        .get("connection")
        .ok_or_else(|| WebSocketError::protocol(url, "missing Connection header"))?;
    if !contains_token(connection, "upgrade") {
        return Err(WebSocketError::protocol(
            url,
            "Connection header does not contain Upgrade",
        ));
    }

    let accept =
        headers
            .get("sec-websocket-accept")
            .ok_or_else(|| WebSocketError::InvalidAccept {
                url: url.to_string(),
            })?;
    if accept.trim() != expected_accept(key) {
        return Err(WebSocketError::InvalidAccept {
            url: url.to_string(),
        });
    }

    if headers.contains("sec-websocket-extensions") {
        return Err(WebSocketError::UnexpectedExtension {
            url: url.to_string(),
        });
    }

    if let Some(protocol) = headers.get("sec-websocket-protocol") {
        let protocol = protocol.trim();
        if !offered_protocols.iter().any(|offered| offered == protocol) {
            return Err(WebSocketError::UnexpectedSubprotocol {
                url: url.to_string(),
            });
        }
    }

    Ok(())
}

fn validate_subprotocols(url: &Url, values: &[String]) -> WebSocketResult<Vec<String>> {
    let mut seen = Vec::<String>::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || !is_token(value) {
            return Err(WebSocketError::protocol(
                url,
                "WebSocket subprotocols must be non-empty RFC token values",
            ));
        }
        if seen.iter().any(|existing| existing == value) {
            return Err(WebSocketError::protocol(
                url,
                "WebSocket subprotocols must be unique",
            ));
        }
        seen.push(value.to_string());
    }
    Ok(seen)
}

fn copy_non_critical_headers(source: &Headers, target: &mut Headers) {
    for (name, value) in source.iter_ordered() {
        if !is_websocket_controlled_header(name) {
            target.append(name.to_string(), value.to_string());
        }
    }
}

fn is_websocket_controlled_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "sec-websocket-extensions"
    )
}

fn generate_key(url: &Url) -> WebSocketResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|err| WebSocketError::protocol(url, format!("failed to generate key: {}", err)))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn origin_form_target(url: &Url) -> String {
    let mut target = url.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn host_header(url: &Url) -> String {
    let host = match url.host() {
        Some(Host::Ipv6(addr)) => format!("[{}]", addr),
        Some(host) => host.to_string(),
        None => "localhost".to_string(),
    };
    match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host,
    }
}

fn contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn is_token(value: &str) -> bool {
    value.bytes().all(|byte| {
        matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
        )
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_wraps_ipv6_literals_with_brackets() {
        let url = Url::parse("ws://[::1]:9443/socket").unwrap();
        let mapped = map_websocket_url(url).unwrap();

        assert_eq!(mapped.host_header, "[::1]:9443");
    }
}
