//! Native HTTP/3 frame and SETTINGS codec.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Cow;
use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::fingerprint::{
    H3Settings, Http3Fingerprint, QpackHeaderBlockStrategy, QpackStringEncodingStrategy,
};
use crate::headers::{Headers, HeadersBuilder};
use crate::transport::h2::hpack_impl::{
    huffman_decode_bytes, huffman_encode_bytes, huffman_encode_if_smaller_bytes,
};

const FRAME_DATA: u64 = 0x0;
const FRAME_HEADERS: u64 = 0x1;
const FRAME_SETTINGS: u64 = 0x4;
const FRAME_GOAWAY: u64 = 0x7;
// RFC 9218 §7.2: PRIORITY_UPDATE frame for request streams (type 0xf0700).
const FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xf0700;
const FRAME_GREASE: u64 = 0x21;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
const SETTINGS_GREASE: u64 = 0x21;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Frame {
    Data(Bytes),
    Headers(Bytes),
    Settings(Vec<H3Setting>),
    GoAway {
        id: u64,
    },
    /// RFC 9218 §7.2 PRIORITY_UPDATE frame (request-stream form, type 0xf0700).
    /// Payload: a varint Prioritized Element ID (the request stream ID) followed
    /// by the ASCII priority field value (same structured-field encoding as the
    /// `priority` header). Sent on the control stream.
    PriorityUpdateRequest {
        prioritized_element_id: u64,
        field_value: Bytes,
    },
    Unknown {
        frame_type: u64,
        payload: Bytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Setting {
    QpackMaxTableCapacity(u64),
    MaxFieldSectionSize(u64),
    QpackBlockedStreams(u64),
    EnableConnectProtocol(u64),
    Additional(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3StreamType {
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    Grease(u64),
    Unknown(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3UnidirectionalStream {
    pub stream_type: H3StreamType,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Header {
    name: Cow<'static, str>,
    value: Cow<'static, str>,
}

pub(crate) fn data_frame_encoded_len(payload_len: usize) -> usize {
    varint_len(FRAME_DATA)
        .saturating_add(varint_len(payload_len as u64))
        .saturating_add(payload_len)
}

pub(crate) fn headers_frame_encoded_len(payload_len: usize) -> usize {
    varint_len(FRAME_HEADERS)
        .saturating_add(varint_len(payload_len as u64))
        .saturating_add(payload_len)
}

impl H3Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into()),
        }
    }

    pub(crate) fn from_static(name: &'static str, value: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(value),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn value(&self) -> &str {
        self.value.as_ref()
    }
}

pub fn encode_settings_payload(settings: &H3Settings) -> Vec<H3Setting> {
    if let Some(raw_settings) = &settings.raw_ordered_settings {
        return raw_settings
            .iter()
            .map(|(key, value)| h3_setting_from_wire_pair(*key, *value))
            .collect();
    }

    let mut payload = Vec::new();
    if let Some(value) = settings.qpack_max_table_capacity {
        payload.push(H3Setting::QpackMaxTableCapacity(value));
    }
    if let Some(value) = settings.qpack_blocked_streams {
        payload.push(H3Setting::QpackBlockedStreams(value));
    }
    if let Some(value) = settings.max_field_section_size {
        payload.push(H3Setting::MaxFieldSectionSize(value));
    }
    if settings.enable_extended_connect {
        payload.push(H3Setting::EnableConnectProtocol(1));
    }
    payload.extend(
        settings
            .additional_settings
            .iter()
            .map(|(key, value)| H3Setting::Additional(*key, *value)),
    );
    payload
}

fn h3_setting_from_wire_pair(key: u64, value: u64) -> H3Setting {
    match key {
        SETTINGS_QPACK_MAX_TABLE_CAPACITY => H3Setting::QpackMaxTableCapacity(value),
        SETTINGS_MAX_FIELD_SECTION_SIZE => H3Setting::MaxFieldSectionSize(value),
        SETTINGS_QPACK_BLOCKED_STREAMS => H3Setting::QpackBlockedStreams(value),
        SETTINGS_ENABLE_CONNECT_PROTOCOL => H3Setting::EnableConnectProtocol(value),
        _ => H3Setting::Additional(key, value),
    }
}

pub fn encode_fingerprint_settings_payload(fingerprint: &Http3Fingerprint) -> Vec<H3Setting> {
    let mut payload = encode_settings_payload(&fingerprint.settings);
    if fingerprint.stream.send_grease_frames
        && !payload.iter().any(
            |setting| matches!(setting, H3Setting::Additional(key, _) if *key == SETTINGS_GREASE),
        )
    {
        payload.push(H3Setting::Additional(SETTINGS_GREASE, 0));
    }
    payload
}

fn encode_control_stream_payload(fingerprint: &Http3Fingerprint) -> Bytes {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&encode_frame(&H3Frame::Settings(
        encode_fingerprint_settings_payload(fingerprint),
    )));
    if fingerprint.stream.send_grease_frames {
        payload.extend_from_slice(&encode_frame(&H3Frame::Unknown {
            frame_type: FRAME_GREASE,
            payload: Bytes::new(),
        }));
    }
    payload.freeze()
}

pub fn encode_client_preface_streams(
    fingerprint: &Http3Fingerprint,
) -> Vec<H3UnidirectionalStream> {
    let mut streams = Vec::new();
    let control_payload = encode_control_stream_payload(fingerprint);

    if fingerprint.stream.open_control_stream_first {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Control,
            payload: control_payload.clone(),
        });
    }

    let qpack_encoder = H3UnidirectionalStream {
        stream_type: H3StreamType::QpackEncoder,
        payload: Bytes::copy_from_slice(&fingerprint.stream.qpack_encoder_stream_payload),
    };
    let qpack_decoder = H3UnidirectionalStream {
        stream_type: H3StreamType::QpackDecoder,
        payload: Bytes::copy_from_slice(&fingerprint.stream.qpack_decoder_stream_payload),
    };

    if fingerprint.stream.open_qpack_encoder_before_decoder {
        streams.push(qpack_encoder);
        streams.push(qpack_decoder);
    } else {
        streams.push(qpack_decoder);
        streams.push(qpack_encoder);
    }

    if !fingerprint.stream.open_control_stream_first {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Control,
            payload: control_payload,
        });
    }

    if fingerprint.stream.send_grease_stream {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Grease(0x21),
            payload: Bytes::from_static(b"GREASE is the word"),
        });
    }

    streams
}

pub fn encode_unidirectional_stream(stream: &H3UnidirectionalStream) -> Bytes {
    let stream_type = encode_stream_type(stream.stream_type);
    let mut out = BytesMut::with_capacity(varint_len(stream_type) + stream.payload.len());
    put_varint(&mut out, stream_type);
    out.extend_from_slice(&stream.payload);
    out.freeze()
}

pub fn decode_unidirectional_stream(bytes: &[u8]) -> Result<H3UnidirectionalStream> {
    let mut input = Bytes::copy_from_slice(bytes);
    let stream_type = decode_stream_type(get_varint(&mut input)?);
    Ok(H3UnidirectionalStream {
        stream_type,
        payload: input,
    })
}

pub fn encode_frame(frame: &H3Frame) -> Bytes {
    let (frame_type, payload) = match frame {
        H3Frame::Data(data) => (FRAME_DATA, data.clone()),
        H3Frame::Headers(headers) => (FRAME_HEADERS, headers.clone()),
        H3Frame::Settings(settings) => (FRAME_SETTINGS, encode_settings(settings)),
        H3Frame::GoAway { id } => {
            let mut payload = BytesMut::new();
            put_varint(&mut payload, *id);
            (FRAME_GOAWAY, payload.freeze())
        }
        H3Frame::PriorityUpdateRequest {
            prioritized_element_id,
            field_value,
        } => {
            let mut payload = BytesMut::new();
            put_varint(&mut payload, *prioritized_element_id);
            payload.extend_from_slice(field_value);
            (FRAME_PRIORITY_UPDATE_REQUEST, payload.freeze())
        }
        H3Frame::Unknown {
            frame_type,
            payload,
        } => (*frame_type, payload.clone()),
    };

    let mut out = BytesMut::with_capacity(
        varint_len(frame_type) + varint_len(payload.len() as u64) + payload.len(),
    );
    put_varint(&mut out, frame_type);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out.freeze()
}

pub fn decode_frame(bytes: &[u8]) -> Result<H3Frame> {
    let mut input = Bytes::copy_from_slice(bytes);
    let frame_type = get_varint(&mut input)?;
    let len = get_varint(&mut input)? as usize;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated HTTP/3 frame".into()));
    }
    let payload = input.copy_to_bytes(len);

    decode_frame_payload(frame_type, payload)
}

fn decode_frame_payload(frame_type: u64, payload: Bytes) -> Result<H3Frame> {
    match frame_type {
        FRAME_DATA => Ok(H3Frame::Data(payload)),
        FRAME_HEADERS => Ok(H3Frame::Headers(payload)),
        FRAME_SETTINGS => Ok(H3Frame::Settings(decode_settings(payload)?)),
        FRAME_GOAWAY => {
            let mut payload = payload;
            Ok(H3Frame::GoAway {
                id: get_varint(&mut payload)?,
            })
        }
        FRAME_PRIORITY_UPDATE_REQUEST => {
            // RFC 9218 §7.2. A server MAY send PRIORITY_UPDATE; the client MUST
            // NOT error on it (§7). If the payload is malformed we still tolerate
            // it by falling back to an Unknown frame rather than failing the
            // connection.
            let mut body = payload.clone();
            match get_varint(&mut body) {
                Ok(prioritized_element_id) => Ok(H3Frame::PriorityUpdateRequest {
                    prioritized_element_id,
                    field_value: body,
                }),
                Err(_) => Ok(H3Frame::Unknown {
                    frame_type: FRAME_PRIORITY_UPDATE_REQUEST,
                    payload,
                }),
            }
        }
        frame_type => Ok(H3Frame::Unknown {
            frame_type,
            payload,
        }),
    }
}

pub fn decode_frames(bytes: &[u8]) -> Result<Vec<H3Frame>> {
    let mut input = Bytes::copy_from_slice(bytes);
    let mut frames = Vec::new();
    while input.has_remaining() {
        let frame_type = get_varint(&mut input)?;
        let len = get_varint(&mut input)? as usize;
        if input.remaining() < len {
            return Err(Error::HttpProtocol("truncated HTTP/3 frame".into()));
        }
        let payload = input.copy_to_bytes(len);
        frames.push(decode_frame_payload(frame_type, payload)?);
    }
    Ok(frames)
}

pub fn h3_frame_block_is_complete(bytes: &[u8]) -> Result<bool> {
    let mut input = bytes;
    while !input.is_empty() {
        let Some((_, used)) = peek_varint(input)? else {
            return Ok(false);
        };
        input = &input[used..];

        let Some((payload_len, used)) = peek_varint(input)? else {
            return Ok(false);
        };
        input = &input[used..];

        let payload_len = usize::try_from(payload_len)
            .map_err(|_| Error::HttpProtocol("HTTP/3 frame length exceeds usize".into()))?;
        if input.len() < payload_len {
            return Ok(false);
        }
        input = &input[payload_len..];
    }
    Ok(true)
}

fn peek_varint(input: &[u8]) -> Result<Option<(u64, usize)>> {
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Ok(None);
    }

    let value = match len {
        1 => u64::from(first) & 0x3f,
        2 => {
            let raw = u16::from_be_bytes([input[0], input[1]]);
            u64::from(raw & 0x3fff)
        }
        4 => {
            let raw = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
            u64::from(raw & 0x3fff_ffff)
        }
        8 => {
            let raw = u64::from_be_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]);
            raw & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!(),
    };
    Ok(Some((value, len)))
}

pub fn encode_request_stream(headers: &[H3Header], body: Option<Bytes>) -> Bytes {
    encode_request_stream_with_strategy(headers, body, QpackHeaderBlockStrategy::StaticThenLiteral)
}

pub fn encode_request_stream_with_fingerprint(
    headers: &[H3Header],
    body: Option<Bytes>,
    fingerprint: &Http3Fingerprint,
) -> Bytes {
    encode_request_stream_with_options(
        headers,
        body,
        fingerprint.stream.request_header_block_strategy,
        fingerprint.stream.request_string_encoding,
    )
}

fn encode_request_stream_with_strategy(
    headers: &[H3Header],
    body: Option<Bytes>,
    strategy: QpackHeaderBlockStrategy,
) -> Bytes {
    encode_request_stream_with_options(headers, body, strategy, QpackStringEncodingStrategy::Plain)
}

fn encode_request_stream_with_options(
    headers: &[H3Header],
    body: Option<Bytes>,
    strategy: QpackHeaderBlockStrategy,
    string_strategy: QpackStringEncodingStrategy,
) -> Bytes {
    let mut out = BytesMut::new();
    out.extend_from_slice(&encode_frame(&H3Frame::Headers(
        encode_header_block_with_options(headers, strategy, string_strategy),
    )));
    if let Some(body) = body {
        if !body.is_empty() {
            out.extend_from_slice(&encode_frame(&H3Frame::Data(body)));
        }
    }
    out.freeze()
}

pub fn build_websocket_connect_headers(
    uri: &http::Uri,
    headers: impl Into<Headers>,
) -> Result<Vec<H3Header>> {
    let headers = headers.into();
    let scheme = uri.scheme_str().ok_or_else(|| {
        Error::WebSocketUnsupported("RFC 9220 requires an https URI internally".into())
    })?;
    if scheme != "https" {
        return Err(Error::WebSocketUnsupported(
            "RFC 9220 WebSocket over HTTP/3 requires wss://".into(),
        ));
    }

    let authority = uri
        .authority()
        .ok_or_else(|| Error::HttpProtocol("RFC 9220 CONNECT requires :authority".into()))?
        .as_str();
    let path = crate::transport::origin_form_path(uri);

    let mut h3_headers = vec![
        H3Header::new(":method", "CONNECT"),
        H3Header::new(":protocol", "websocket"),
        H3Header::new(":scheme", scheme),
        H3Header::new(":path", path.as_ref()),
        H3Header::new(":authority", authority),
    ];

    for (name, value) in headers.iter_bytes() {
        let name = String::from_utf8_lossy(name);
        let value = String::from_utf8_lossy(value);
        let lower = name.to_ascii_lowercase();
        if name.starts_with(':') {
            return Err(Error::HttpProtocol(format!(
                "user pseudo-header {name} is not allowed on RFC 9220 CONNECT"
            )));
        }

        if matches!(
            lower.as_str(),
            "connection" | "upgrade" | "host" | "sec-websocket-key" | "sec-websocket-accept"
        ) {
            return Err(Error::WebSocketUnsupported(format!(
                "header {name} is not allowed on RFC 9220 WebSocket over HTTP/3"
            )));
        }

        if matches!(
            lower.as_str(),
            "keep-alive" | "proxy-connection" | "transfer-encoding"
        ) {
            continue;
        }

        h3_headers.push(H3Header::new(lower, value));
    }

    Ok(h3_headers)
}

pub fn build_request_headers(
    method: &http::Method,
    uri: &http::Uri,
    headers: impl Into<Headers>,
) -> Result<Vec<H3Header>> {
    let headers = headers.into();
    let scheme = uri.scheme_str().unwrap_or("https");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| uri.host())
        .unwrap_or("");
    let path = crate::transport::origin_form_path(uri);

    let mut h3_headers = vec![
        H3Header::new(":method", method.as_str()),
        H3Header::new(":scheme", scheme),
        H3Header::new(":authority", authority),
        H3Header::new(":path", path.as_ref()),
    ];

    for (name, value) in headers.iter_bytes() {
        let lower = if name.iter().all(|b| b.is_ascii_lowercase()) {
            String::from_utf8_lossy(name).into_owned()
        } else {
            name.iter()
                .map(|b| b.to_ascii_lowercase() as char)
                .collect()
        };
        if name.first() != Some(&b':')
            && lower != "connection"
            && lower != "keep-alive"
            && lower != "proxy-connection"
            && lower != "transfer-encoding"
            && lower != "upgrade"
        {
            h3_headers.push(H3Header::new(
                lower,
                String::from_utf8_lossy(value).into_owned(),
            ));
        }
    }

    Ok(h3_headers)
}

pub fn encode_header_block(headers: &[H3Header]) -> Bytes {
    encode_header_block_with_strategy(headers, QpackHeaderBlockStrategy::StaticThenLiteral)
}

pub fn encode_header_block_with_strategy(
    headers: &[H3Header],
    strategy: QpackHeaderBlockStrategy,
) -> Bytes {
    encode_header_block_with_options(headers, strategy, QpackStringEncodingStrategy::Plain)
}

fn encode_header_block_with_options(
    headers: &[H3Header],
    strategy: QpackHeaderBlockStrategy,
    string_strategy: QpackStringEncodingStrategy,
) -> Bytes {
    let mut out = BytesMut::new();
    put_prefixed_int(&mut out, 0, 0, 8);
    put_prefixed_int(&mut out, 0, 0, 7);

    for header in headers {
        if strategy == QpackHeaderBlockStrategy::StaticThenLiteral {
            if let Some((index, exact)) = static_lookup(header.name(), header.value()) {
                if exact {
                    put_prefixed_int(&mut out, index, 0xc0, 6);
                } else {
                    put_prefixed_int(&mut out, index, 0x50, 4);
                    put_prefixed_string_with_strategy(
                        &mut out,
                        header.value().as_bytes(),
                        0,
                        7,
                        string_strategy,
                    );
                }
                continue;
            }
        }
        put_prefixed_string_with_strategy(
            &mut out,
            header.name().as_bytes(),
            0x20,
            3,
            string_strategy,
        );
        put_prefixed_string_with_strategy(
            &mut out,
            header.value().as_bytes(),
            0,
            7,
            string_strategy,
        );
    }

    out.freeze()
}

pub fn decode_header_block(bytes: &[u8]) -> Result<Vec<H3Header>> {
    decode_header_block_bytes(Bytes::copy_from_slice(bytes))
}

pub(crate) fn decode_header_block_bytes(mut input: Bytes) -> Result<Vec<H3Header>> {
    let first = get_byte(&mut input)?;
    let _required_insert_count = get_prefixed_int(first, 8, &mut input)?;
    let first = get_byte(&mut input)?;
    let _delta_base = get_prefixed_int(first, 7, &mut input)?;

    let mut headers = Vec::new();
    while input.has_remaining() {
        let first = get_byte(&mut input)?;
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static indexed fields".into(),
                ));
            }
            let index = get_prefixed_int(first, 6, &mut input)?;
            let (name, value) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            headers.push(H3Header::from_static(name, value));
        } else if first & 0x40 != 0 {
            if first & 0x10 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static name refs".into(),
                ));
            }
            let index = get_prefixed_int(first, 4, &mut input)?;
            let (name, _) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            let value = get_prefixed_string(&mut input, 7)?;
            headers.push(H3Header::new(name, value));
        } else if first & 0x20 != 0 {
            let name = get_prefixed_string_with_first(first, 3, &mut input)?;
            let value = get_prefixed_string(&mut input, 7)?;
            headers.push(H3Header::new(name, value));
        } else {
            return Err(Error::HttpProtocol(
                "unsupported native QPACK field representation".into(),
            ));
        }
    }

    Ok(headers)
}

pub(crate) fn decode_response_headers(mut input: Bytes) -> Result<(Option<u16>, Headers)> {
    if let Some(decoded) = try_decode_response_headers_template(&input) {
        return Ok(decoded);
    }

    let first = get_byte(&mut input)?;
    let _required_insert_count = get_prefixed_int(first, 8, &mut input)?;
    let first = get_byte(&mut input)?;
    let _delta_base = get_prefixed_int(first, 7, &mut input)?;

    let mut status = None;
    let mut headers = HeadersBuilder::with_capacity(8, input.len());
    while input.has_remaining() {
        let first = get_byte(&mut input)?;
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static indexed fields".into(),
                ));
            }
            let index = get_prefixed_int(first, 6, &mut input)?;
            let (name, value) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            push_response_header_to_builder(
                Cow::Borrowed(name),
                Cow::Borrowed(value),
                &mut status,
                &mut headers,
            );
        } else if first & 0x40 != 0 {
            if first & 0x10 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static name refs".into(),
                ));
            }
            let index = get_prefixed_int(first, 4, &mut input)?;
            let (name, _) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            let value = get_prefixed_string(&mut input, 7)?;
            push_response_header_to_builder(
                Cow::Borrowed(name),
                Cow::Owned(value),
                &mut status,
                &mut headers,
            );
        } else if first & 0x20 != 0 {
            let name = get_prefixed_string_with_first(first, 3, &mut input)?;
            let value = get_prefixed_string(&mut input, 7)?;
            push_response_header_to_builder(
                Cow::Owned(name),
                Cow::Owned(value),
                &mut status,
                &mut headers,
            );
        } else {
            return Err(Error::HttpProtocol(
                "unsupported native QPACK field representation".into(),
            ));
        }
    }

    Ok((status, headers.build()))
}

static H3_RESPONSE_OCTET_STREAM_HEADERS: OnceLock<Headers> = OnceLock::new();
static H3_RESPONSE_TEXT_PLAIN_HEADERS: OnceLock<Headers> = OnceLock::new();

fn try_decode_response_headers_template(input: &Bytes) -> Option<(Option<u16>, Headers)> {
    match input.as_ref() {
        b"\x00\x00\xd9\x27\x05content-type\x18application/octet-stream" => Some((
            Some(200),
            H3_RESPONSE_OCTET_STREAM_HEADERS
                .get_or_init(|| {
                    Headers::from_static(vec![("content-type", "application/octet-stream")])
                })
                .clone(),
        )),
        b"\x00\x00\xd9\xf5" => Some((
            Some(200),
            H3_RESPONSE_TEXT_PLAIN_HEADERS
                .get_or_init(|| Headers::from_static(vec![("content-type", "text/plain")]))
                .clone(),
        )),
        _ => None,
    }
}

fn push_response_header_to_builder(
    name: Cow<'static, str>,
    value: Cow<'static, str>,
    status: &mut Option<u16>,
    headers: &mut HeadersBuilder,
) {
    if name.as_ref() == ":status" {
        *status = parse_h3_status(value.as_ref());
    } else if !name.as_ref().starts_with(':') {
        headers.push(name.as_ref().as_bytes(), value.as_ref().as_bytes());
    }
}

pub(crate) fn parse_h3_status(value: &str) -> Option<u16> {
    let bytes = value.as_bytes();
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        ((bytes[0] - b'0') as u16) * 100
            + ((bytes[1] - b'0') as u16) * 10
            + (bytes[2] - b'0') as u16,
    )
}

fn encode_stream_type(stream_type: H3StreamType) -> u64 {
    match stream_type {
        H3StreamType::Control => 0x00,
        H3StreamType::Push => 0x01,
        H3StreamType::QpackEncoder => 0x02,
        H3StreamType::QpackDecoder => 0x03,
        H3StreamType::Grease(value) | H3StreamType::Unknown(value) => value,
    }
}

fn decode_stream_type(stream_type: u64) -> H3StreamType {
    match stream_type {
        0x00 => H3StreamType::Control,
        0x01 => H3StreamType::Push,
        0x02 => H3StreamType::QpackEncoder,
        0x03 => H3StreamType::QpackDecoder,
        value if value % 0x1f == 0x21 % 0x1f => H3StreamType::Grease(value),
        value => H3StreamType::Unknown(value),
    }
}

fn encode_settings(settings: &[H3Setting]) -> Bytes {
    let mut out = BytesMut::new();
    for setting in settings {
        let (key, value) = match setting {
            H3Setting::QpackMaxTableCapacity(value) => (SETTINGS_QPACK_MAX_TABLE_CAPACITY, *value),
            H3Setting::MaxFieldSectionSize(value) => (SETTINGS_MAX_FIELD_SECTION_SIZE, *value),
            H3Setting::QpackBlockedStreams(value) => (SETTINGS_QPACK_BLOCKED_STREAMS, *value),
            H3Setting::EnableConnectProtocol(value) => (SETTINGS_ENABLE_CONNECT_PROTOCOL, *value),
            H3Setting::Additional(key, value) => (*key, *value),
        };
        put_varint(&mut out, key);
        put_varint(&mut out, value);
    }
    out.freeze()
}

fn decode_settings(mut payload: Bytes) -> Result<Vec<H3Setting>> {
    let mut settings = Vec::new();
    while payload.has_remaining() {
        let key = get_varint(&mut payload)?;
        let value = get_varint(&mut payload)?;
        settings.push(match key {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => H3Setting::QpackMaxTableCapacity(value),
            SETTINGS_MAX_FIELD_SECTION_SIZE => H3Setting::MaxFieldSectionSize(value),
            SETTINGS_QPACK_BLOCKED_STREAMS => H3Setting::QpackBlockedStreams(value),
            SETTINGS_ENABLE_CONNECT_PROTOCOL => H3Setting::EnableConnectProtocol(value),
            key => H3Setting::Additional(key, value),
        });
    }
    Ok(settings)
}

fn put_varint(out: &mut BytesMut, value: u64) {
    match value {
        0..=0x3f => out.put_u8(value as u8),
        0x40..=0x3fff => out.put_u16((value as u16) | 0x4000),
        0x4000..=0x3fff_ffff => out.put_u32((value as u32) | 0x8000_0000),
        _ => out.put_u64(value | 0xc000_0000_0000_0000),
    }
}

fn static_lookup(name: &str, value: &str) -> Option<(u64, bool)> {
    if name.eq_ignore_ascii_case(":authority") {
        return Some((0, false));
    }
    if name.eq_ignore_ascii_case("user-agent") {
        return Some((95, false));
    }
    if name.eq_ignore_ascii_case(":path") {
        return (value == "/").then_some((1, true));
    }
    if name.eq_ignore_ascii_case(":method") {
        return match value {
            "CONNECT" => Some((15, true)),
            "DELETE" => Some((16, true)),
            "GET" => Some((17, true)),
            "HEAD" => Some((18, true)),
            "OPTIONS" => Some((19, true)),
            "POST" => Some((20, true)),
            "PUT" => Some((21, true)),
            _ => None,
        };
    }
    if name.eq_ignore_ascii_case(":scheme") {
        return match value {
            "http" => Some((22, true)),
            "https" => Some((23, true)),
            _ => None,
        };
    }
    if name.eq_ignore_ascii_case(":status") {
        return match value {
            "103" => Some((24, true)),
            "200" => Some((25, true)),
            "304" => Some((26, true)),
            "404" => Some((27, true)),
            "503" => Some((28, true)),
            _ => None,
        };
    }
    if name.eq_ignore_ascii_case("accept") {
        return (value == "*/*").then_some((29, true));
    }
    if name.eq_ignore_ascii_case("content-type") {
        return (value == "text/plain").then_some((53, true));
    }
    if name.eq_ignore_ascii_case("range") {
        return (value == "bytes=0-").then_some((55, true));
    }
    None
}

fn static_by_index(index: u64) -> Option<(&'static str, &'static str)> {
    match index {
        0 => Some((":authority", "")),
        1 => Some((":path", "/")),
        15 => Some((":method", "CONNECT")),
        16 => Some((":method", "DELETE")),
        17 => Some((":method", "GET")),
        18 => Some((":method", "HEAD")),
        19 => Some((":method", "OPTIONS")),
        20 => Some((":method", "POST")),
        21 => Some((":method", "PUT")),
        22 => Some((":scheme", "http")),
        23 => Some((":scheme", "https")),
        24 => Some((":status", "103")),
        25 => Some((":status", "200")),
        26 => Some((":status", "304")),
        27 => Some((":status", "404")),
        28 => Some((":status", "503")),
        29 => Some(("accept", "*/*")),
        53 => Some(("content-type", "text/plain")),
        55 => Some(("range", "bytes=0-")),
        95 => Some(("user-agent", "")),
        _ => None,
    }
}

fn put_prefixed_string_with_strategy(
    out: &mut BytesMut,
    value: &[u8],
    first: u8,
    prefix: usize,
    strategy: QpackStringEncodingStrategy,
) {
    let (encoded, huffman) = match strategy {
        QpackStringEncodingStrategy::Plain => (value.to_vec(), false),
        QpackStringEncodingStrategy::Huffman => (huffman_encode_bytes(value), true),
        QpackStringEncodingStrategy::HuffmanIfSmaller => huffman_encode_if_smaller_bytes(value),
    };
    let huffman_bit = if huffman { 1u8 << prefix } else { 0 };
    put_prefixed_int(out, encoded.len() as u64, first | huffman_bit, prefix);
    out.extend_from_slice(&encoded);
}

fn put_prefixed_int(out: &mut BytesMut, mut value: u64, first: u8, prefix: usize) {
    let mask = (1u64 << prefix) - 1;
    if value < mask {
        out.put_u8(first | value as u8);
        return;
    }

    out.put_u8(first | mask as u8);
    value -= mask;
    while value >= 128 {
        out.put_u8((value % 128 + 128) as u8);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn get_byte(input: &mut Bytes) -> Result<u8> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol("truncated QPACK header block".into()));
    }
    Ok(input.get_u8())
}

fn get_prefixed_string(input: &mut Bytes, prefix: usize) -> Result<String> {
    let first = get_byte(input)?;
    get_prefixed_string_with_first(first, prefix, input)
}

fn get_prefixed_string_with_first(first: u8, prefix: usize, input: &mut Bytes) -> Result<String> {
    let huffman = first & (1 << prefix) != 0;
    let len = get_prefixed_int(first, prefix, input)? as usize;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QPACK string".into()));
    }
    let value = input.copy_to_bytes(len);
    let decoded = if huffman {
        huffman_decode_bytes(value.as_ref())
            .map_err(|err| Error::HttpProtocol(format!("invalid QPACK Huffman string: {err}")))?
    } else {
        value.to_vec()
    };
    String::from_utf8(decoded)
        .map_err(|e| Error::HttpProtocol(format!("invalid QPACK string utf8: {e}")))
}

fn get_prefixed_int(first: u8, prefix: usize, input: &mut Bytes) -> Result<u64> {
    let mask = (1u64 << prefix) - 1;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Ok(value);
    }

    let mut shift = 0;
    loop {
        let byte = get_byte(input)?;
        value += ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 56 {
            return Err(Error::HttpProtocol("QPACK integer overflow".into()));
        }
    }
}

fn get_varint(input: &mut Bytes) -> Result<u64> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol("missing HTTP/3 varint".into()));
    }
    let first = input[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated HTTP/3 varint".into()));
    }

    let value = match len {
        1 => input.get_u8() as u64 & 0x3f,
        2 => input.get_u16() as u64 & 0x3fff,
        4 => input.get_u32() as u64 & 0x3fff_ffff,
        8 => input.get_u64() & 0x3fff_ffff_ffff_ffff,
        _ => unreachable!(),
    };
    Ok(value)
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}
