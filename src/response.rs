//! HTTP response handling, decompression, and the public poll-based [`Body`].

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::url::Url;
use async_compression::tokio::bufread::{
    BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder,
};
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::fmt;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, BufReader, ReadBuf};

/// Public response body implementing [`http_body::Body`].
///
/// The cutover replaced the legacy `mpsc::Receiver<Result<Bytes>>` response
/// surface with this poll-based body. Buffered responses (returned by
/// `RequestBuilder::send`) carry their bytes inline and emit them as a single
/// data frame. H1 streaming responses poll the socket directly; other
/// transports use their current internal delivery until their poll-body
/// transport cutovers land.
///
/// Cloning a streaming body is rejected at runtime because the transport body
/// has a single consumer; only [`Body::Empty`]/buffered bodies clone cheaply.
pub struct Body {
    inner: BodyInner,
}

enum BodyInner {
    Empty,
    Buffered(Option<Bytes>),
    H1(crate::transport::h1::H1Body),
    H2(crate::transport::h2::H2Body),
    H2Direct(Box<crate::transport::h2::H2DirectBody>),
    H3(crate::transport::h3::H3Body),
    H3Direct(Box<crate::transport::h3::NativeH3DirectBody>),
    Decoded(Box<DecodedBody>),
}

type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + 'static>>;

const STREAM_DECODE_CHUNK_SIZE: usize = 16 * 1024;

struct DecodedBody {
    reader: BoxedAsyncRead,
    error_context: String,
    trailers_rx: Option<crate::transport::h2::TrailerReceiver>,
    protocol: BodyCapacityProtocol,
    ended: bool,
}

impl DecodedBody {
    fn new(mut body: Body, codings: &[String]) -> Self {
        let protocol = body.capacity().protocol;
        let trailers_rx = body.take_h2_trailers_rx();
        let mut reader: BoxedAsyncRead = Box::pin(BodyAsyncRead::new(body));
        let mut applied = Vec::new();

        for coding in codings.iter().rev() {
            match coding.as_str() {
                "gzip" | "x-gzip" => {
                    reader = Box::pin(GzipDecoder::new(BufReader::new(reader)));
                    applied.push("gzip");
                }
                "deflate" => {
                    reader = Box::pin(DeflateCompatDecoder::new(reader));
                    applied.push("deflate");
                }
                "br" => {
                    reader = Box::pin(BrotliDecoder::new(BufReader::new(reader)));
                    applied.push("br");
                }
                "zstd" => {
                    reader = Box::pin(ZstdDecoder::new(BufReader::new(reader)));
                    applied.push("zstd");
                }
                "identity" => {}
                _ => {}
            }
        }

        let error_context = if applied.is_empty() {
            "content-encoding".to_string()
        } else {
            format!("content-encoding {}", applied.join(", "))
        };

        Self {
            reader,
            error_context,
            trailers_rx,
            protocol,
            ended: false,
        }
    }

    async fn trailers(&mut self) -> Result<Option<Headers>> {
        let Some(rx) = self.trailers_rx.take() else {
            return Ok(None);
        };
        match rx.await {
            Err(_) => Ok(None),
            Ok(Err(e)) => Err(e),
            Ok(Ok(headers)) => Ok(Some(Headers::from(headers))),
        }
    }

    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }

        let mut buffer = [0_u8; STREAM_DECODE_CHUNK_SIZE];
        let mut read_buf = ReadBuf::new(&mut buffer);
        match self.reader.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    self.ended = true;
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
                }
            }
            Poll::Ready(Err(error)) => {
                self.ended = true;
                Poll::Ready(Some(Err(decode_stream_error(&self.error_context, error))))
            }
        }
    }
}

struct BodyAsyncRead {
    body: Body,
    current: Option<Bytes>,
    offset: usize,
}

impl BodyAsyncRead {
    fn new(body: Body) -> Self {
        Self {
            body,
            current: None,
            offset: 0,
        }
    }
}

impl AsyncRead for BodyAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.current.is_some() {
                let n = {
                    let chunk = self.current.as_ref().expect("checked current chunk");
                    let remaining = &chunk[self.offset..];
                    let n = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..n]);
                    n
                };
                self.offset += n;
                if self
                    .current
                    .as_ref()
                    .map(|chunk| self.offset == chunk.len())
                    .unwrap_or(false)
                {
                    self.current = None;
                    self.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.body).poll_chunk(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    self.current = Some(bytes);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(BodyReadError(error))));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
    }
}

struct DeflateCompatDecoder {
    state: DeflateCompatState,
}

enum DeflateCompatState {
    Probe {
        reader: Option<BoxedAsyncRead>,
        prefix: [u8; 2],
        len: usize,
    },
    Decode(BoxedAsyncRead),
}

impl DeflateCompatDecoder {
    fn new(reader: BoxedAsyncRead) -> Self {
        Self {
            state: DeflateCompatState::Probe {
                reader: Some(reader),
                prefix: [0; 2],
                len: 0,
            },
        }
    }
}

impl AsyncRead for DeflateCompatDecoder {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match &mut self.state {
                DeflateCompatState::Probe {
                    reader,
                    prefix,
                    len,
                } => {
                    while *len < prefix.len() {
                        let mut byte = [0_u8; 1];
                        let mut read_buf = ReadBuf::new(&mut byte);
                        match reader
                            .as_mut()
                            .expect("deflate probe reader present")
                            .as_mut()
                            .poll_read(cx, &mut read_buf)
                        {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(())) => {
                                let filled = read_buf.filled();
                                if filled.is_empty() {
                                    break;
                                }
                                prefix[*len] = filled[0];
                                *len += 1;
                            }
                        }
                    }

                    let reader = reader.take().expect("deflate probe reader present");
                    let prefix_bytes = Bytes::copy_from_slice(&prefix[..*len]);
                    let prefixed: BoxedAsyncRead =
                        Box::pin(PrefixedAsyncRead::new(prefix_bytes, reader));
                    let decoder: BoxedAsyncRead = if looks_like_zlib_header(&prefix[..*len]) {
                        Box::pin(ZlibDecoder::new(BufReader::new(prefixed)))
                    } else {
                        Box::pin(DeflateDecoder::new(BufReader::new(prefixed)))
                    };
                    self.state = DeflateCompatState::Decode(decoder);
                }
                DeflateCompatState::Decode(reader) => {
                    return reader.as_mut().poll_read(cx, buf);
                }
            }
        }
    }
}

struct PrefixedAsyncRead {
    prefix: Bytes,
    offset: usize,
    reader: BoxedAsyncRead,
}

impl PrefixedAsyncRead {
    fn new(prefix: Bytes, reader: BoxedAsyncRead) -> Self {
        Self {
            prefix,
            offset: 0,
            reader,
        }
    }
}

impl AsyncRead for PrefixedAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.offset += n;
            return Poll::Ready(Ok(()));
        }
        self.reader.as_mut().poll_read(cx, buf)
    }
}

fn looks_like_zlib_header(prefix: &[u8]) -> bool {
    if prefix.len() < 2 {
        return false;
    }
    let cmf = prefix[0];
    let flg = prefix[1];
    (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && ((u16::from(cmf) << 8) | u16::from(flg)) % 31 == 0
}

#[derive(Debug)]
struct BodyReadError(Error);

impl fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BodyReadError {}

fn decode_stream_error(context: &str, error: std::io::Error) -> Error {
    let message = error.to_string();
    match error.into_inner() {
        Some(inner) => match inner.downcast::<BodyReadError>() {
            Ok(body_error) => body_error.0,
            Err(inner) => Error::Decompression(format!("{}: {}", context, inner)),
        },
        None => Error::Decompression(format!("{}: {}", context, message)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyCapacityProtocol {
    Empty,
    Buffered,
    H1,
    H2,
    H2Direct,
    H3,
    H3Direct,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyCapacity {
    pub protocol: BodyCapacityProtocol,
    pub buffer_capacity: usize,
    pub buffered_chunks: usize,
    pub available_slots: usize,
    pub buffered_bytes: usize,
    pub closed: bool,
    pub ended: bool,
}

impl Body {
    /// Construct an empty body that completes without yielding any frames.
    pub fn empty() -> Self {
        Self {
            inner: BodyInner::Empty,
        }
    }

    /// Construct a buffered body that yields the given bytes once and then
    /// signals end-of-stream. Cheap to clone and to query for length.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            Self::empty()
        } else {
            Self {
                inner: BodyInner::Buffered(Some(bytes)),
            }
        }
    }

    /// Wrap an HTTP/1.1 socket-polling response body.
    pub(crate) fn from_h1(body: crate::transport::h1::H1Body) -> Self {
        Self {
            inner: BodyInner::H1(body),
        }
    }

    /// Wrap an HTTP/2 wakeable-slot response body.
    pub(crate) fn from_h2(body: crate::transport::h2::H2Body) -> Self {
        Self {
            inner: BodyInner::H2(body),
        }
    }

    /// Wrap an HTTP/2 direct-owned response body.
    pub(crate) fn from_h2_direct(body: crate::transport::h2::H2DirectBody) -> Self {
        Self {
            inner: BodyInner::H2Direct(Box::new(body)),
        }
    }

    /// Wrap an HTTP/3 wakeable-slot response body.
    pub(crate) fn from_h3(body: crate::transport::h3::H3Body) -> Self {
        Self {
            inner: BodyInner::H3(body),
        }
    }

    /// Wrap an HTTP/3 direct-owned response body.
    pub(crate) fn from_h3_direct(body: crate::transport::h3::NativeH3DirectBody) -> Self {
        Self {
            inner: BodyInner::H3Direct(Box::new(body)),
        }
    }

    pub(crate) fn with_content_decoding(self, codings: &[String]) -> Self {
        if !codings
            .iter()
            .any(|coding| is_streaming_content_coding(coding))
        {
            return self;
        }
        Self {
            inner: BodyInner::Decoded(Box::new(DecodedBody::new(self, codings))),
        }
    }

    fn is_content_decoded(&self) -> bool {
        matches!(self.inner, BodyInner::Decoded(_))
    }

    fn take_h2_trailers_rx(&mut self) -> Option<crate::transport::h2::TrailerReceiver> {
        match &mut self.inner {
            BodyInner::H2(body) => body.take_trailers_rx(),
            _ => None,
        }
    }

    /// Await HTTP/2 response trailers for this body, if any.
    ///
    /// Only H2 streaming bodies can carry trailers, and only when the caller
    /// requested them (`te: trailers`). Every other body variant returns
    /// `Ok(None)`. See [`crate::transport::h2::H2Body::trailers`] for the
    /// three-state contract (clean end and not-requested both map to
    /// `Ok(None)`; a stream reset maps to `Err`).
    ///
    /// Public so language bindings (node/python) can surface gRPC
    /// `grpc-status`/`grpc-message` trailers from a streaming [`Body`].
    pub async fn trailers(&mut self) -> Result<Option<Headers>> {
        match &mut self.inner {
            BodyInner::H2(body) => body.trailers().await,
            BodyInner::Decoded(body) => body.trailers().await,
            BodyInner::Empty
            | BodyInner::Buffered(_)
            | BodyInner::H1(_)
            | BodyInner::H2Direct(_)
            | BodyInner::H3(_)
            | BodyInner::H3Direct(_) => Ok(None),
        }
    }

    /// `true` for an empty buffered body. Streaming bodies report `false`
    /// because the buffered length is unknown until the body is drained.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            BodyInner::Empty => true,
            BodyInner::Buffered(Some(b)) => b.is_empty(),
            BodyInner::Buffered(None) => true,
            BodyInner::H1(_)
            | BodyInner::H2(_)
            | BodyInner::H2Direct(_)
            | BodyInner::H3(_)
            | BodyInner::H3Direct(_)
            | BodyInner::Decoded(_) => false,
        }
    }

    /// `true` if the body was created from a streaming transport channel.
    pub fn is_streaming(&self) -> bool {
        matches!(
            self.inner,
            BodyInner::H1(_)
                | BodyInner::H2(_)
                | BodyInner::H2Direct(_)
                | BodyInner::H3(_)
                | BodyInner::H3Direct(_)
                | BodyInner::Decoded(_)
        )
    }

    /// Return a reference to the buffered bytes when the body is fully
    /// materialized, or `None` if the body is streaming or already drained.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.inner {
            BodyInner::Buffered(Some(b)) => Some(b),
            _ => None,
        }
    }

    /// Buffered length when known, `None` for streaming bodies.
    pub fn buffered_len(&self) -> Option<usize> {
        match &self.inner {
            BodyInner::Empty => Some(0),
            BodyInner::Buffered(Some(b)) => Some(b.len()),
            BodyInner::Buffered(None) => Some(0),
            BodyInner::H1(_)
            | BodyInner::H2(_)
            | BodyInner::H2Direct(_)
            | BodyInner::H3(_)
            | BodyInner::H3Direct(_)
            | BodyInner::Decoded(_) => None,
        }
    }

    /// Snapshot H3 streaming response buffer pressure when this body is backed
    /// by the native HTTP/3 transport.
    pub fn h3_capacity(&self) -> Option<crate::transport::h3::H3BodyCapacity> {
        match &self.inner {
            BodyInner::H3(body) => Some(body.capacity()),
            BodyInner::H3Direct(body) => Some(body.capacity()),
            BodyInner::Decoded(_) => None,
            _ => None,
        }
    }

    /// Snapshot protocol-neutral response-body buffer pressure.
    ///
    /// H2 and native H3 streaming bodies report their actual bounded driver
    /// queues. H1 and direct-owned H2 bodies stream directly from the socket
    /// instead of a public queue, so they report zero queued capacity/bytes.
    /// Buffered and empty bodies report their materialized byte state.
    pub fn capacity(&self) -> BodyCapacity {
        match &self.inner {
            BodyInner::Empty => BodyCapacity {
                protocol: BodyCapacityProtocol::Empty,
                buffer_capacity: 0,
                buffered_chunks: 0,
                available_slots: 0,
                buffered_bytes: 0,
                closed: false,
                ended: true,
            },
            BodyInner::Buffered(bytes) => {
                let buffered_bytes = bytes.as_ref().map(Bytes::len).unwrap_or(0);
                BodyCapacity {
                    protocol: BodyCapacityProtocol::Buffered,
                    buffer_capacity: usize::from(buffered_bytes > 0),
                    buffered_chunks: usize::from(buffered_bytes > 0),
                    available_slots: usize::from(buffered_bytes == 0),
                    buffered_bytes,
                    closed: false,
                    ended: true,
                }
            }
            BodyInner::H1(_) => BodyCapacity {
                protocol: BodyCapacityProtocol::H1,
                buffer_capacity: 0,
                buffered_chunks: 0,
                available_slots: 0,
                buffered_bytes: 0,
                closed: false,
                ended: false,
            },
            BodyInner::H2(body) => {
                let capacity = body.capacity();
                BodyCapacity {
                    protocol: BodyCapacityProtocol::H2,
                    buffer_capacity: capacity.buffer_capacity,
                    buffered_chunks: capacity.buffered_chunks,
                    available_slots: capacity.available_slots,
                    buffered_bytes: capacity.buffered_bytes,
                    closed: capacity.closed,
                    ended: capacity.ended,
                }
            }
            BodyInner::H2Direct(_) => BodyCapacity {
                protocol: BodyCapacityProtocol::H2Direct,
                buffer_capacity: 0,
                buffered_chunks: 0,
                available_slots: 0,
                buffered_bytes: 0,
                closed: false,
                ended: false,
            },
            BodyInner::H3(body) => {
                let capacity = body.capacity();
                BodyCapacity {
                    protocol: BodyCapacityProtocol::H3,
                    buffer_capacity: capacity.buffer_capacity,
                    buffered_chunks: capacity.buffered_chunks,
                    available_slots: capacity.available_slots,
                    buffered_bytes: capacity.buffered_bytes,
                    closed: capacity.closed,
                    ended: capacity.ended,
                }
            }
            BodyInner::H3Direct(body) => {
                let capacity = body.capacity();
                BodyCapacity {
                    protocol: BodyCapacityProtocol::H3Direct,
                    buffer_capacity: capacity.buffer_capacity,
                    buffered_chunks: capacity.buffered_chunks,
                    available_slots: capacity.available_slots,
                    buffered_bytes: capacity.buffered_bytes,
                    closed: capacity.closed,
                    ended: capacity.ended,
                }
            }
            BodyInner::Decoded(body) => BodyCapacity {
                protocol: body.protocol,
                buffer_capacity: 0,
                buffered_chunks: 0,
                available_slots: 0,
                buffered_bytes: 0,
                closed: body.ended,
                ended: body.ended,
            },
        }
    }

    /// Convenience accessor for buffered bodies. Returns `0` for streaming
    /// bodies; callers wanting to detect streaming should use
    /// [`Body::buffered_len`] or [`Body::is_streaming`].
    pub fn len(&self) -> usize {
        self.buffered_len().unwrap_or(0)
    }

    /// Poll the next frame asynchronously. Returns `None` after end-of-stream.
    pub fn frame(&mut self) -> FrameFuture<'_> {
        FrameFuture { body: self }
    }

    /// Poll the next data chunk asynchronously. Returns `None` after end-of-stream.
    #[inline(always)]
    pub fn chunk(&mut self) -> ChunkFuture<'_> {
        ChunkFuture { body: self }
    }

    /// Drain the body into a contiguous [`Bytes`] buffer.
    ///
    /// For buffered bodies this is essentially a clone of the underlying
    /// bytes. For streaming bodies it polls the body to completion, so callers
    /// must opt in explicitly.
    pub async fn collect_to_bytes(&mut self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        while let Some(frame) = self.frame().await {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
        }
        Ok(buf.freeze())
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            BodyInner::Empty => f.debug_struct("Body::Empty").finish(),
            BodyInner::Buffered(Some(b)) => f
                .debug_struct("Body::Buffered")
                .field("len", &b.len())
                .finish(),
            BodyInner::Buffered(None) => f.debug_struct("Body::Buffered").field("len", &0).finish(),
            BodyInner::H1(_) => f.debug_struct("Body::H1Streaming").finish(),
            BodyInner::H2(_) => f.debug_struct("Body::H2Streaming").finish(),
            BodyInner::H2Direct(_) => f.debug_struct("Body::H2DirectStreaming").finish(),
            BodyInner::H3(_) => f.debug_struct("Body::H3Streaming").finish(),
            BodyInner::H3Direct(_) => f.debug_struct("Body::H3DirectStreaming").finish(),
            BodyInner::Decoded(_) => f.debug_struct("Body::DecodedStreaming").finish(),
        }
    }
}

impl Clone for Body {
    fn clone(&self) -> Self {
        match &self.inner {
            BodyInner::Empty => Self::empty(),
            BodyInner::Buffered(Some(b)) => Self {
                inner: BodyInner::Buffered(Some(b.clone())),
            },
            BodyInner::Buffered(None) => Self {
                inner: BodyInner::Buffered(None),
            },
            BodyInner::H1(_)
            | BodyInner::H2(_)
            | BodyInner::H2Direct(_)
            | BodyInner::H3(_)
            | BodyInner::H3Direct(_)
            | BodyInner::Decoded(_) => {
                panic!("warpsock::Body::clone is not supported for streaming bodies")
            }
        }
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self::from_bytes(value)
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.inner {
            BodyInner::Empty => Poll::Ready(None),
            BodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                _ => Poll::Ready(None),
            },
            BodyInner::H1(body) => Pin::new(body).poll_frame(cx),
            BodyInner::H2(body) => Pin::new(body).poll_frame(cx),
            BodyInner::H2Direct(body) => Pin::new(body.as_mut()).poll_frame(cx),
            BodyInner::H3(body) => Pin::new(body).poll_frame(cx),
            BodyInner::H3Direct(body) => Pin::new(body.as_mut()).poll_frame(cx),
            BodyInner::Decoded(body) => match body.poll_chunk(cx) {
                Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Empty => true,
            BodyInner::Buffered(None) => true,
            BodyInner::Buffered(Some(b)) => b.is_empty(),
            BodyInner::H1(body) => body.is_terminal(),
            BodyInner::H2(body) => body.is_terminal(),
            BodyInner::H2Direct(body) => body.is_terminal(),
            BodyInner::H3(body) => body.is_terminal(),
            BodyInner::H3Direct(body) => body.is_terminal(),
            BodyInner::Decoded(body) => body.ended,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            BodyInner::Empty => SizeHint::with_exact(0),
            BodyInner::Buffered(Some(b)) => SizeHint::with_exact(b.len() as u64),
            BodyInner::Buffered(None) => SizeHint::with_exact(0),
            BodyInner::H1(body) => body.size_hint(),
            BodyInner::H2(body) => body.size_hint(),
            BodyInner::H2Direct(body) => body.size_hint(),
            BodyInner::H3(body) => body.size_hint(),
            BodyInner::H3Direct(body) => body.size_hint(),
            BodyInner::Decoded(_) => SizeHint::new(),
        }
    }
}

impl Body {
    #[inline(always)]
    fn poll_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        match &mut self.inner {
            BodyInner::Empty => Poll::Ready(None),
            BodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(bytes))),
                _ => Poll::Ready(None),
            },
            BodyInner::H2(body) => Pin::new(body).poll_data_coalesced(cx),
            BodyInner::H2Direct(body) => Pin::new(body.as_mut()).poll_data(cx),
            BodyInner::H3Direct(body) => Pin::new(body.as_mut()).poll_data(cx),
            BodyInner::H1(body) => match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(bytes) => Poll::Ready(Some(Ok(bytes))),
                    Err(_) => Poll::Pending,
                },
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            BodyInner::H3(body) => Pin::new(body).poll_data(cx),
            BodyInner::Decoded(body) => body.poll_chunk(cx),
        }
    }
}

/// Future returned by [`Body::frame`].
pub struct FrameFuture<'a> {
    body: &'a mut Body,
}

impl<'a> Future for FrameFuture<'a> {
    type Output = Option<std::result::Result<Frame<Bytes>, Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let body = &mut *self.get_mut().body;
        match Pin::new(body).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(value) => Poll::Ready(value),
        }
    }
}

/// Future returned by [`Body::chunk`].
pub struct ChunkFuture<'a> {
    body: &'a mut Body,
}

impl<'a> Future for ChunkFuture<'a> {
    type Output = Option<std::result::Result<Bytes, Error>>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let body = &mut *self.get_mut().body;
        Pin::new(body).poll_chunk(cx)
    }
}

/// HTTP response with explicit decompression and a poll-based [`Body`].
#[derive(Debug, Clone)]
pub struct Response {
    pub(crate) status: u16,
    headers: Headers,
    body: Body,
    http_version: String,
    effective_url: Option<Url>,
}

impl Response {
    /// Construct a buffered response. Used by the non-streaming transport
    /// paths and by tests/cache code that already have the full body in
    /// memory.
    pub fn new(status: u16, headers: Headers, body: Bytes, http_version: String) -> Self {
        Self {
            status,
            headers,
            body: Body::from_bytes(body),
            http_version,
            effective_url: None,
        }
    }

    /// Construct a response that wraps an explicit [`Body`]. Used by the
    /// streaming transport paths to publish the poll-based body to callers.
    pub fn with_body(status: u16, headers: Headers, body: Body, http_version: String) -> Self {
        Self {
            status,
            headers,
            body,
            http_version,
            effective_url: None,
        }
    }

    pub(crate) fn decode_streaming_content(mut self) -> Self {
        if self.status == 206
            || !self.body.is_streaming()
            || self.body.is_content_decoded()
            || !self.headers.contains("content-encoding")
        {
            return self;
        }

        let codings = content_encoding_tokens(&self.headers);
        if !codings
            .iter()
            .any(|coding| is_streaming_content_coding(coding))
        {
            return self;
        }

        let body = std::mem::take(&mut self.body);
        self.body = body.with_content_decoding(&codings);
        self
    }

    pub(crate) fn into_status_headers_version(self) -> (u16, Headers, String) {
        (self.status, self.headers, self.http_version)
    }

    /// Set the effective URL (the URL that was actually requested).
    pub fn with_url(mut self, url: Url) -> Self {
        self.effective_url = Some(url);
        self
    }

    pub(crate) async fn into_buffered(mut self) -> Result<Self> {
        if self.body.is_streaming() {
            let bytes = self.body.collect_to_bytes().await?;
            self.body = Body::from_bytes(bytes);
        }
        Ok(self)
    }

    pub fn http_version(&self) -> &str {
        &self.http_version
    }

    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn status_code(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Await the HTTP/2 response trailers for this response, if any.
    ///
    /// gRPC carries `grpc-status`/`grpc-message` in a trailing HEADERS frame;
    /// this surfaces them. Three outcomes:
    /// - `Ok(Some(headers))` - a real trailers frame arrived.
    /// - `Ok(None)` - a clean trailer-less end, trailers were not requested
    ///   (`te: trailers` absent), or the response is buffered / non-H2.
    /// - `Err(_)` - the stream was reset (RST_STREAM / transport error) before
    ///   a clean end; distinct from `Ok(None)`.
    ///
    /// Await this only after the body stream has returned end: a resolved
    /// trailer channel does not imply the body has been fully drained.
    pub async fn trailers(&mut self) -> Result<Option<Headers>> {
        self.body.trailers().await
    }

    pub fn url(&self) -> Option<&Url> {
        self.effective_url.as_ref()
    }

    /// Reference to the public poll-based body.
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Mutable reference to the public poll-based body, used to drive
    /// [`Body::frame`] without consuming the response.
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Consume the response and return the body for poll-based draining.
    pub fn into_body(self) -> Body {
        self.body
    }

    /// Borrow the buffered body bytes, when the body is fully materialized.
    /// Returns `None` for streaming bodies; use [`Body::frame`] or
    /// [`Body::collect_to_bytes`] in that case.
    pub fn buffered_bytes(&self) -> Option<&Bytes> {
        self.body.as_bytes()
    }

    pub fn bytes_raw(&self) -> Result<Bytes> {
        self.body
            .as_bytes()
            .cloned()
            .ok_or_else(|| Error::HttpProtocol("response body is streaming, not buffered".into()))
    }

    pub fn bytes(&self) -> Result<Bytes> {
        self.decoded_body()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
    pub fn redirect_url(&self) -> Option<&str> {
        self.get_header("Location")
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        self.headers.get_all(name)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
    pub fn content_encoding(&self) -> Option<&str> {
        self.get_header("Content-Encoding")
    }

    /// Decode body based on Content-Encoding (gzip, deflate, br, zstd).
    /// Supports chained encodings (e.g., "gzip, deflate") by applying decodings in reverse order.
    /// Returns an error for streaming bodies; the caller must consume the
    /// streaming body via [`Body::frame`] before applying decompression.
    pub fn decoded_body(&self) -> Result<Bytes> {
        let body = self.body.as_bytes().ok_or_else(|| {
            Error::HttpProtocol("response body is streaming, not buffered".into())
        })?;

        let encodings = content_encoding_tokens(&self.headers);

        if !encodings.is_empty() {
            let mut data = body.clone();
            for encoding in encodings.iter().rev() {
                data = match encoding.as_str() {
                    "gzip" | "x-gzip" => decode_gzip(&data)?,
                    "deflate" => decode_deflate(&data)?,
                    "br" => decode_brotli(&data)?,
                    "zstd" => decode_zstd(&data)?,
                    "identity" => data,
                    _ => data,
                };
            }
            return Ok(data);
        }

        if body.len() >= 4
            && body[0] == 0x28
            && body[1] == 0xB5
            && body[2] == 0x2F
            && body[3] == 0xFD
        {
            return decode_zstd(body);
        }
        if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
            return decode_gzip(body);
        }

        Ok(body.clone())
    }

    pub fn text(&self) -> Result<String> {
        let decoded = self.decoded_body()?;
        String::from_utf8(decoded.to_vec())
            .map_err(|e| Error::Decompression(format!("UTF-8 decode error: {}", e)))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let text = self.text()?;
        serde_json::from_str(&text).map_err(Error::from)
    }

    pub fn error_for_status(self) -> Result<Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }

    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }
}

fn content_encoding_tokens(headers: &Headers) -> Vec<String> {
    headers
        .get_all("Content-Encoding")
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_streaming_content_coding(coding: &str) -> bool {
    matches!(coding, "gzip" | "x-gzip" | "deflate" | "br" | "zstd")
}

fn decode_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("gzip: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_deflate(data: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    if flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut decoded)
        .is_ok()
    {
        return Ok(Bytes::from(decoded));
    }
    decoded.clear();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("deflate: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("brotli: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_zstd(data: &[u8]) -> Result<Bytes> {
    zstd::stream::decode_all(data)
        .map(Bytes::from)
        .map_err(|e| Error::Decompression(format!("zstd: {}", e)))
}
