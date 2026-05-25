//! BoringSSL TLS connector.

use boring::ex_data::Index;
use boring::ssl::{NameType, Ssl, SslConnector, SslMethod, SslSessionCacheMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;
use http::Uri;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_boring::{SslStream, SslStreamBuilder};

use crate::error::Error;
use crate::fingerprint::tls::TlsFingerprint;
use crate::transport::dns::DnsConfig;
use crate::transport::session::{SessionCache, SessionCacheKey};
use crate::transport::tcp::{configure_tcp_socket_with_buffers, TcpFingerprint, TcpSocketBuffers};

// FFI bindings for BoringSSL extension control
use boring_sys::{CRYPTO_BUFFER, SSL, SSL_CTX, SSL_SESSION};
use std::os::raw::c_int;

extern "C" {
    pub fn SSL_CTX_set_grease_enabled(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
    pub fn SSL_CTX_set_permute_extensions(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
    pub fn SSL_CTX_set_early_data_enabled(ctx: *mut SSL_CTX, enabled: c_int);
    pub fn SSL_set_early_data_enabled(ssl: *mut SSL, enabled: c_int);
    pub fn SSL_in_early_data(ssl: *const SSL) -> c_int;
    pub fn SSL_early_data_accepted(ssl: *const SSL) -> c_int;
    pub fn SSL_get_early_data_reason(ssl: *const SSL) -> u32;
    pub fn SSL_SESSION_early_data_capable(session: *const SSL_SESSION) -> c_int;
}

/// Brotli certificate decompression callback for BoringSSL.
///
/// This function is called by BoringSSL when it receives a Brotli-compressed certificate.
/// It decompresses the input data and returns it in a CRYPTO_BUFFER.
unsafe extern "C" fn decompress_brotli_cert(
    _ssl: *mut SSL,
    out: *mut *mut CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    use std::slice;

    // Read compressed data
    let compressed = slice::from_raw_parts(in_, in_len);

    // Decompress using Brotli
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    let mut decoder = brotli::Decompressor::new(compressed, uncompressed_len);
    match decoder.read_to_end(&mut decompressed) {
        Ok(_) if decompressed.len() == uncompressed_len => {
            // Create CRYPTO_BUFFER from decompressed data
            // CRYPTO_BUFFER_new(data, len, pool) - pool can be null for one-off buffers
            let buffer = boring_sys::CRYPTO_BUFFER_new(
                decompressed.as_ptr(),
                decompressed.len(),
                std::ptr::null_mut(),
            );
            if buffer.is_null() {
                return 0; // Error
            }
            *out = buffer;
            // CRYPTO_BUFFER_new copies the data, so decompressed Vec can be dropped normally
            1 // Success
        }
        _ => 0, // Decompression failed or wrong size
    }
}

/// Zlib certificate decompression callback for BoringSSL.
///
/// This function is called by BoringSSL when it receives a Zlib-compressed certificate.
unsafe extern "C" fn decompress_zlib_cert(
    _ssl: *mut SSL,
    out: *mut *mut CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    use flate2::read::DeflateDecoder;
    use std::slice;

    // Read compressed data
    let compressed = slice::from_raw_parts(in_, in_len);

    // Decompress using Zlib (Deflate)
    let mut decoder = DeflateDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    match decoder.read_to_end(&mut decompressed) {
        Ok(_) if decompressed.len() == uncompressed_len => {
            // Create CRYPTO_BUFFER from decompressed data
            // CRYPTO_BUFFER_new(data, len, pool) - pool can be null for one-off buffers
            let buffer = boring_sys::CRYPTO_BUFFER_new(
                decompressed.as_ptr(),
                decompressed.len(),
                std::ptr::null_mut(),
            );
            if buffer.is_null() {
                return 0; // Error
            }
            *out = buffer;
            // CRYPTO_BUFFER_new copies the data, so decompressed Vec can be dropped normally
            1 // Success
        }
        _ => 0, // Decompression failed or wrong size
    }
}

/// Bridge between sync IO traits and async tokio IO traits for TLS handshakes.
struct AsyncStreamBridge<S> {
    stream: S,
    waker: Option<std::task::Waker>,
}

impl<S> AsyncStreamBridge<S> {
    fn new(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            stream,
            waker: None,
        }
    }

    fn set_waker(&mut self, ctx: Option<&mut Context<'_>>) {
        self.waker = ctx.map(|ctx| ctx.waker().clone());
    }

    fn with_context<F, R>(&mut self, f: F) -> R
    where
        S: Unpin,
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> R,
    {
        let mut ctx = Context::from_waker(self.waker.as_ref().expect("missing waker in bridge"));
        f(&mut ctx, Pin::new(&mut self.stream))
    }
}

impl<S> io::Read for AsyncStreamBridge<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.with_context(|ctx, stream| {
            let mut buf = ReadBuf::new(buf);
            match stream.poll_read(ctx, &mut buf)? {
                Poll::Ready(()) => Ok(buf.filled().len()),
                Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        })
    }
}

impl<S> io::Write for AsyncStreamBridge<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.with_context(|ctx, stream| stream.poll_write(ctx, buf)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.with_context(|ctx, stream| stream.poll_flush(ctx)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ConnectPort(u16);

static CONNECT_PORT_INDEX: OnceLock<Index<Ssl, ConnectPort>> = OnceLock::new();

fn connect_port_index() -> &'static Index<Ssl, ConnectPort> {
    CONNECT_PORT_INDEX.get_or_init(|| Ssl::new_ex_index().expect("SSL ex index"))
}

const DEFAULT_HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Outcome of a TLS 1.3 0-RTT early-data attempt on the TCP-TLS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyDataOutcome {
    /// Server accepted 0-RTT; early bytes are on the wire.
    Accepted,
    /// Server rejected 0-RTT; BoringSSL retransmits as 1-RTT data.
    Rejected { reason: u32 },
    /// No cached ticket, early data disabled, or payload not eligible.
    NotAttempted,
}

/// BoringSSL-based TLS connector for hyper.
#[derive(Clone)]
pub struct BoringConnector {
    tls_config: Option<TlsFingerprint>,
    tcp_fingerprint: Option<TcpFingerprint>,
    tcp_socket_buffers: TcpSocketBuffers,
    dns_config: DnsConfig,
    tcp_keepalive: TcpKeepaliveConfig,
    root_certs: Vec<Vec<u8>>,
    /// Load root certificates from the OS certificate store at runtime
    use_platform_roots: bool,
    /// Skip TLS certificate verification (DANGEROUS - for testing only)
    danger_accept_invalid_certs: bool,
    ssl_connectors: Arc<OnceLock<[Arc<SslConnector>; 2]>>,
    session_cache: Arc<SessionCache>,
    happy_eyeballs_delay: Duration,
    enable_early_data: bool,
}

#[derive(Clone, Default)]
struct TcpKeepaliveConfig {
    time: Option<Duration>,
    interval: Option<Duration>,
    retries: Option<u32>,
}

impl BoringConnector {
    /// Create a new connector with default TLS configuration.
    ///
    /// Note: By default, this does NOT load platform root certificates.
    /// Use `with_platform_roots(true)` to enable automatic loading of OS root CAs,
    /// which is required for cross-compiled builds (e.g., Windows builds from macOS).
    pub fn new() -> Self {
        Self::with_session_cache(Arc::new(SessionCache::new()))
    }

    fn with_session_cache(session_cache: Arc<SessionCache>) -> Self {
        Self {
            tls_config: None,
            tcp_fingerprint: None,
            tcp_socket_buffers: TcpSocketBuffers::none(),
            dns_config: DnsConfig::new(),
            tcp_keepalive: TcpKeepaliveConfig::default(),
            root_certs: Vec::new(),
            use_platform_roots: false,
            danger_accept_invalid_certs: false,
            ssl_connectors: Arc::new(OnceLock::new()),
            session_cache,
            happy_eyeballs_delay: DEFAULT_HAPPY_EYEBALLS_DELAY,
            enable_early_data: false,
        }
    }

    /// Share a TLS session cache across connector clones and client connectors.
    pub fn with_shared_session_cache(mut self, session_cache: Arc<SessionCache>) -> Self {
        self.session_cache = session_cache;
        self
    }

    /// Stagger dual-stack connection attempts (RFC 8305). Zero disables stagger.
    pub fn happy_eyeballs_delay(mut self, delay: Duration) -> Self {
        self.happy_eyeballs_delay = delay;
        self
    }

    /// Enable TLS 1.3 0-RTT early data on resumable TCP-TLS connections.
    pub fn with_early_data(mut self, enabled: bool) -> Self {
        self.enable_early_data = enabled;
        self
    }

    /// Create a connector with TLS fingerprint configuration.
    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self::with_session_cache(Arc::new(SessionCache::new())).with_fingerprint_inner(fp)
    }

    fn with_fingerprint_inner(mut self, fp: TlsFingerprint) -> Self {
        self.tls_config = Some(fp);
        self
    }

    /// Create a connector with both TLS and TCP fingerprint configuration.
    pub fn with_fingerprints(tls_fp: TlsFingerprint, tcp_fp: TcpFingerprint) -> Self {
        Self::with_session_cache(Arc::new(SessionCache::new()))
            .with_fingerprint_inner(tls_fp)
            .with_tcp_fingerprint(tcp_fp)
    }

    /// Set TCP fingerprint configuration.
    pub fn with_tcp_fingerprint(mut self, tcp_fp: TcpFingerprint) -> Self {
        self.tcp_fingerprint = Some(tcp_fp);
        self
    }

    /// Explicitly override TCP socket receive and send buffers.
    ///
    /// Defaults to OS autotuning. Set this only when a fixed socket buffer is
    /// required for a specific deployment or test.
    pub fn tcp_socket_buffers(mut self, buffers: TcpSocketBuffers) -> Self {
        self.tcp_socket_buffers = buffers;
        self
    }

    /// Set DNS resolution configuration.
    pub fn with_dns_config(mut self, dns_config: DnsConfig) -> Self {
        self.dns_config = dns_config;
        self
    }

    /// Set TCP keepalive idle time.
    pub fn tcp_keepalive(mut self, time: Option<Duration>) -> Self {
        self.tcp_keepalive.time = time;
        self
    }

    /// Set TCP keepalive probe interval.
    pub fn tcp_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.tcp_keepalive.interval = interval;
        self
    }

    /// Set TCP keepalive retry count.
    pub fn tcp_keepalive_retries(mut self, retries: Option<u32>) -> Self {
        self.tcp_keepalive.retries = retries;
        self
    }

    /// Add custom root certificates (DER or PEM).
    pub fn with_root_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.root_certs = certs;
        self
    }

    /// Load root certificates from the operating system's certificate store.
    ///
    /// This is REQUIRED for cross-compiled builds (e.g., building for Windows from macOS)
    /// because BoringSSL's default certificate store is empty when cross-compiling.
    ///
    /// On Windows, this loads certificates from the Windows Certificate Store (schannel).
    /// On macOS, this loads from the Keychain.
    /// On Linux, this loads from common certificate locations (/etc/ssl/certs, etc.).
    ///
    /// The `SSL_CERT_FILE` environment variable can override the certificate source.
    pub fn with_platform_roots(mut self, enabled: bool) -> Self {
        self.use_platform_roots = enabled;
        self
    }

    /// Skip TLS certificate verification.
    ///
    /// # Safety
    /// This is DANGEROUS and should only be used for testing with localhost
    /// or other trusted local development environments. Never use in production.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    fn ssl_connector(&self, alpn_mode: AlpnMode) -> Result<Arc<SslConnector>, Error> {
        let index = alpn_index(alpn_mode);
        if let Some(connectors) = self.ssl_connectors.get() {
            return Ok(connectors[index].clone());
        }
        let cached = [
            Arc::new(self.build_ssl_connector(AlpnMode::Default)?),
            Arc::new(self.build_ssl_connector(AlpnMode::Http1Only)?),
        ];
        if let Ok(()) = self.ssl_connectors.set(cached) {}
        Ok(self
            .ssl_connectors
            .get()
            .expect("connector cache initialized")[index]
            .clone())
    }

    fn build_ssl_connector(&self, alpn_mode: AlpnMode) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| Error::Tls(format!("Failed to create SSL connector: {}", e)))?;

        if self.danger_accept_invalid_certs {
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        }

        if self.use_platform_roots {
            let result = rustls_native_certs::load_native_certs();
            for err in &result.errors {
                tracing::warn!("Error loading platform certificate: {}", err);
            }
            let mut loaded = 0;
            for cert_der in result.certs {
                if let Ok(x509) = X509::from_der(cert_der.as_ref()) {
                    if builder.cert_store_mut().add_cert(x509).is_ok() {
                        loaded += 1;
                    }
                }
            }
            tracing::debug!("Loaded {} platform root certificates", loaded);
        }

        for cert_bytes in &self.root_certs {
            if let Ok(cert) = X509::from_der(cert_bytes) {
                let _ = builder.cert_store_mut().add_cert(cert);
            } else if let Ok(cert) = X509::from_pem(cert_bytes) {
                let _ = builder.cert_store_mut().add_cert(cert);
            }
        }

        if let Some(fp) = &self.tls_config {
            if !fp.cipher_list.is_empty() {
                let cipher_str = fp.cipher_list.join(":");
                builder
                    .set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }

            if !fp.curves.is_empty() {
                let curves_str = if fp.enable_kyber {
                    format!("X25519Kyber768Draft00:{}", fp.curves.join(":"))
                } else {
                    fp.curves.join(":")
                };
                builder
                    .set_curves_list(&curves_str)
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            } else if fp.enable_kyber {
                builder
                    .set_curves_list("X25519Kyber768Draft00")
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }

            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                builder.set_sigalgs_list(&sigalgs_str).map_err(|e| {
                    Error::Tls(format!("Failed to set signature algorithms: {}", e))
                })?;
            }

            unsafe {
                let ctx = builder.as_ptr() as *mut SSL_CTX;
                if fp.grease {
                    SSL_CTX_set_grease_enabled(ctx, 1);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                } else {
                    SSL_CTX_set_grease_enabled(ctx, 0);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                }

                match fp.cert_compression {
                    crate::fingerprint::CertCompression::Brotli => {
                        let _ = boring_sys::SSL_CTX_add_cert_compression_alg(
                            ctx,
                            boring_sys::TLSEXT_cert_compression_brotli as u16,
                            None,
                            Some(decompress_brotli_cert),
                        );
                    }
                    crate::fingerprint::CertCompression::Zlib => {
                        let _ = boring_sys::SSL_CTX_add_cert_compression_alg(
                            ctx,
                            boring_sys::TLSEXT_cert_compression_zlib as u16,
                            None,
                            Some(decompress_zlib_cert),
                        );
                    }
                    crate::fingerprint::CertCompression::None => {}
                }
            }

            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        } else {
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        }

        builder
            .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);

        if self.enable_early_data {
            unsafe {
                SSL_CTX_set_early_data_enabled(builder.as_ptr() as *mut SSL_CTX, 1);
            }
        }

        let session_cache = self.session_cache.clone();
        builder.set_new_session_callback(move |ssl, session| {
            let host = ssl
                .servername(NameType::HOST_NAME)
                .unwrap_or("")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let port = ssl
                .ex_data(*connect_port_index())
                .map(|ConnectPort(port)| *port)
                .unwrap_or(443);
            if host.is_empty() {
                return;
            }
            if let Ok(der) = session.to_der() {
                let early_data_capable =
                    unsafe { SSL_SESSION_early_data_capable(session.as_ptr()) != 0 };
                let max_age = Duration::from_secs(session.timeout() as u64);
                session_cache.store_session(
                    SessionCacheKey::new(&host, port),
                    der,
                    early_data_capable,
                    Some(max_age),
                );
            }
        });

        let alpn_protos = match alpn_mode {
            AlpnMode::Default => b"\x02h2\x08http/1.1".as_slice(),
            AlpnMode::Http1Only => b"\x08http/1.1".as_slice(),
        };
        builder
            .set_alpn_protos(alpn_protos)
            .map_err(|e| Error::Tls(format!("Failed to set ALPN: {}", e)))?;

        Ok(builder.build())
    }

    fn prepare_ssl(
        &self,
        ssl_connector: &SslConnector,
        host: &str,
        port: u16,
        enable_early_data: bool,
    ) -> Result<Ssl, Error> {
        let config = ssl_connector
            .configure()
            .map_err(|e| Error::Tls(format!("Failed to configure SSL: {}", e)))?;
        let mut ssl = config
            .into_ssl(host)
            .map_err(|e| Error::Tls(format!("Failed to prepare SSL: {}", e)))?;
        ssl.replace_ex_data(*connect_port_index(), ConnectPort(port));

        let cache_key = SessionCacheKey::new(host, port);
        if let Some(session) = self.session_cache.get_session(&cache_key) {
            unsafe {
                ssl.set_session(&session).map_err(|e| {
                    Error::Tls(format!("Failed to install cached TLS session: {}", e))
                })?;
            }
        }

        if enable_early_data && self.enable_early_data {
            unsafe {
                SSL_set_early_data_enabled(ssl.as_ptr(), 1);
            }
        }

        Ok(ssl)
    }

    async fn tls_handshake(
        &self,
        ssl_connector: &SslConnector,
        host: &str,
        port: u16,
        tcp_stream: TcpStream,
        early_data: Option<&[u8]>,
    ) -> Result<(SslStream<TcpStream>, EarlyDataOutcome), Error> {
        let attempt_early_data = early_data.is_some_and(|data| {
            !data.is_empty()
                && self.enable_early_data
                && self
                    .session_cache
                    .supports_zero_rtt(&SessionCacheKey::new(host, port))
        });
        let ssl = self.prepare_ssl(ssl_connector, host, port, attempt_early_data)?;

        if attempt_early_data {
            let early_data = early_data.expect("checked above");
            let mid = ssl.setup_connect(AsyncStreamBridge::new(tcp_stream));
            return drive_handshake_with_early_data(mid, early_data).await;
        }

        let stream = SslStreamBuilder::new(ssl, tcp_stream)
            .connect()
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;
        Ok((stream, EarlyDataOutcome::NotAttempted))
    }

    /// Access the shared TLS session cache (for tests and diagnostics).
    pub fn session_cache(&self) -> &Arc<SessionCache> {
        &self.session_cache
    }
}

/// ALPN configuration mode for TLS connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlpnMode {
    /// Advertise the default HTTP protocols: h2, then http/1.1.
    #[default]
    Default,
    /// Advertise only http/1.1 for callers that must avoid HTTP/2 negotiation.
    Http1Only,
}

/// Negotiated ALPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocol {
    /// HTTP/2 ("h2")
    H2,
    /// HTTP/1.1 ("http/1.1")
    Http1,
    /// No ALPN negotiated or unknown protocol
    Unknown,
}

impl AlpnProtocol {
    /// Check if HTTP/2 was negotiated.
    pub fn is_h2(&self) -> bool {
        matches!(self, Self::H2)
    }

    /// Check if HTTP/1.1 was negotiated.
    pub fn is_http1(&self) -> bool {
        matches!(self, Self::Http1)
    }
}

/// Stream that can be either HTTP (plain TCP) or HTTPS (TLS).
#[derive(Debug)]
pub enum MaybeHttpsStream {
    /// Plain TCP stream for HTTP.
    Http(TcpStream),
    /// TLS-wrapped stream for HTTPS.
    Https(SslStream<TcpStream>),
}

impl MaybeHttpsStream {
    /// Get the negotiated ALPN protocol.
    ///
    /// For HTTPS connections, returns the protocol negotiated during TLS handshake.
    /// For plain HTTP connections, returns `Unknown` (no TLS = no ALPN).
    ///
    /// **IMPORTANT**: Always check ALPN before using HTTP/2. If the server negotiated
    /// HTTP/1.1 (or no ALPN), attempting HTTP/2 will fail immediately.
    pub fn alpn_protocol(&self) -> AlpnProtocol {
        match self {
            MaybeHttpsStream::Http(_) => AlpnProtocol::Unknown,
            MaybeHttpsStream::Https(stream) => match stream.ssl().selected_alpn_protocol() {
                Some(b"h2") => AlpnProtocol::H2,
                Some(b"http/1.1") => AlpnProtocol::Http1,
                _ => AlpnProtocol::Unknown,
            },
        }
    }

    /// Check if HTTP/2 was negotiated via ALPN.
    ///
    /// Convenience method for `self.alpn_protocol().is_h2()`.
    pub fn is_h2(&self) -> bool {
        self.alpn_protocol().is_h2()
    }

    /// Whether the TLS session was resumed from the external session cache.
    pub fn session_reused(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(_) => false,
            MaybeHttpsStream::Https(stream) => stream.ssl().session_reused(),
        }
    }
}

impl AsyncRead for MaybeHttpsStream {
    #[inline(always)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeHttpsStream {
    #[inline(always)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    #[inline(always)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_flush(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    #[inline(always)]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl BoringConnector {
    /// Connect to a URI, returning either a plain TCP or TLS stream.
    pub async fn connect(&self, uri: &Uri) -> Result<MaybeHttpsStream, Error> {
        self.connect_with_alpn(uri, AlpnMode::Default).await
    }

    /// Connect to a URI while constraining TLS ALPN advertisement.
    pub async fn connect_with_alpn(
        &self,
        uri: &Uri,
        alpn_mode: AlpnMode,
    ) -> Result<MaybeHttpsStream, Error> {
        let (stream, _) = self
            .connect_with_alpn_and_early_data(uri, alpn_mode, None)
            .await?;
        Ok(stream)
    }

    /// Connect with optional TLS 1.3 0-RTT early data on resumable sessions.
    pub async fn connect_with_alpn_and_early_data(
        &self,
        uri: &Uri,
        alpn_mode: AlpnMode,
        early_data: Option<&[u8]>,
    ) -> Result<(MaybeHttpsStream, EarlyDataOutcome), Error> {
        let host = uri
            .host()
            .ok_or_else(|| Error::Connection("Missing host".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });

        let addrs = interleave_addresses(self.dns_config.resolve(host, port).await?);
        let tcp_stream =
            if self.tcp_fingerprint.is_some() || self.tcp_socket_buffers.is_configured() {
                connect_tcp_configured(
                    addrs,
                    self.tcp_fingerprint.clone(),
                    self.tcp_socket_buffers,
                    self.tcp_keepalive.clone(),
                    self.happy_eyeballs_delay,
                    host,
                    port,
                )
                .await?
            } else {
                connect_tcp_async(
                    addrs,
                    self.happy_eyeballs_delay,
                    self.tcp_keepalive.clone(),
                    host,
                    port,
                )
                .await?
            };

        tcp_stream
            .set_nodelay(true)
            .map_err(|e| Error::Connection(format!("Failed to set TCP_NODELAY: {}", e)))?;

        if uri.scheme_str() == Some("https") {
            let ssl_connector = self.ssl_connector(alpn_mode)?;
            let (ssl_stream, outcome) = self
                .tls_handshake(&ssl_connector, host, port, tcp_stream, early_data)
                .await?;
            Ok((MaybeHttpsStream::Https(ssl_stream), outcome))
        } else {
            Ok((
                MaybeHttpsStream::Http(tcp_stream),
                EarlyDataOutcome::NotAttempted,
            ))
        }
    }

    /// Connect to a URI advertising only HTTP/1.1 over TLS.
    pub async fn connect_h1_only(&self, uri: &Uri) -> Result<MaybeHttpsStream, Error> {
        self.connect_with_alpn(uri, AlpnMode::Http1Only).await
    }
}

impl Default for BoringConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn alpn_index(mode: AlpnMode) -> usize {
    match mode {
        AlpnMode::Default => 0,
        AlpnMode::Http1Only => 1,
    }
}

fn interleave_addresses(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v6 = addrs
        .iter()
        .copied()
        .filter(|addr| addr.is_ipv6())
        .collect::<Vec<_>>();
    let mut v4 = addrs
        .iter()
        .copied()
        .filter(|addr| addr.is_ipv4())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(addrs.len());
    loop {
        let mut progressed = false;
        if let Some(addr) = v6.first().copied() {
            v6.remove(0);
            out.push(addr);
            progressed = true;
        }
        if let Some(addr) = v4.first().copied() {
            v4.remove(0);
            out.push(addr);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    out
}

async fn connect_tcp_async(
    addrs: Vec<SocketAddr>,
    delay: Duration,
    keepalive: TcpKeepaliveConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, Error> {
    if addrs.is_empty() {
        return Err(Error::Connection(format!(
            "Failed to connect to {host}:{port}: no addresses resolved"
        )));
    }

    if delay.is_zero() || addrs.len() == 1 {
        let mut last_error = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    apply_tcp_keepalive_to_stream(&stream, &keepalive)?;
                    return Ok(stream);
                }
                Err(error) => last_error = Some(error),
            }
        }
        return Err(connection_error(host, port, last_error));
    }

    let mut join_set = JoinSet::new();
    for (index, addr) in addrs.into_iter().enumerate() {
        let stagger = delay.saturating_mul(index as u32);
        join_set.spawn(async move {
            if !stagger.is_zero() {
                tokio::time::sleep(stagger).await;
            }
            TcpStream::connect(addr).await
        });
    }

    let mut last_error = None;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                join_set.abort_all();
                apply_tcp_keepalive_to_stream(&stream, &keepalive)?;
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) => last_error = Some(error.into()),
        }
    }

    Err(connection_error(host, port, last_error))
}

/// Loser attempts in the fingerprint path may continue until their bounded
/// `connect_timeout` even after a winner is chosen.
async fn connect_tcp_configured(
    addrs: Vec<SocketAddr>,
    tcp_fp: Option<TcpFingerprint>,
    tcp_socket_buffers: TcpSocketBuffers,
    keepalive: TcpKeepaliveConfig,
    delay: Duration,
    host: &str,
    port: u16,
) -> Result<TcpStream, Error> {
    use socket2::{Domain, Socket, Type};

    if addrs.is_empty() {
        return Err(Error::Connection(format!(
            "Failed to connect to {host}:{port}: no addresses resolved"
        )));
    }

    let per_attempt_timeout = delay
        .saturating_add(Duration::from_millis(50))
        .max(Duration::from_millis(50));
    let mut join_set: JoinSet<Result<std::net::TcpStream, Error>> = JoinSet::new();
    for (index, addr) in addrs.into_iter().enumerate() {
        let stagger = delay.saturating_mul(index as u32);
        let tcp_fp = tcp_fp.clone();
        let keepalive = keepalive.clone();
        join_set.spawn_blocking(move || {
            if !stagger.is_zero() {
                std::thread::sleep(stagger);
            }
            let domain = match addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))
                .map_err(|e| Error::Connection(format!("Failed to create socket: {e}")))?;
            let tcp_fp = tcp_fp.unwrap_or_default();
            configure_tcp_socket_with_buffers(&socket, &tcp_fp, tcp_socket_buffers)
                .map_err(|e| Error::Connection(format!("Failed to configure TCP socket: {e}")))?;
            apply_tcp_keepalive(socket2::SockRef::from(&socket), &keepalive)?;
            socket
                .connect_timeout(&addr.into(), per_attempt_timeout)
                .map_err(|e| Error::Connection(format!("Failed to connect to {addr}: {e}")))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| Error::Connection(format!("Failed to set non-blocking: {e}")))?;
            Ok(socket.into())
        });
    }

    let mut last_error = None;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(std_stream)) => {
                join_set.abort_all();
                return TcpStream::from_std(std_stream).map_err(|e| {
                    Error::Connection(format!("Failed to convert to tokio stream: {e}"))
                });
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(error) => last_error = Some(error.to_string()),
        }
    }

    Err(Error::Connection(format!(
        "Failed to connect to {host}:{port}: {}",
        last_error.unwrap_or_else(|| "no addresses resolved".to_string())
    )))
}

fn connection_error(host: &str, port: u16, last_error: Option<io::Error>) -> Error {
    Error::Connection(format!(
        "Failed to connect to {host}:{port}: {}",
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses resolved".to_string())
    ))
}

async fn drive_handshake_with_early_data<S>(
    mut mid: boring::ssl::MidHandshakeSslStream<AsyncStreamBridge<S>>,
    early_data: &[u8],
) -> Result<(SslStream<S>, EarlyDataOutcome), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use boring::ssl::HandshakeError as SslHandshakeError;

    let mut early_offset = 0usize;

    loop {
        mid.get_mut().set_waker(None);
        match mid.handshake() {
            Ok(stream) => {
                let ssl = stream.ssl();
                let outcome = if unsafe { SSL_early_data_accepted(ssl.as_ptr()) != 0 } {
                    EarlyDataOutcome::Accepted
                } else {
                    EarlyDataOutcome::Rejected {
                        reason: unsafe { SSL_get_early_data_reason(ssl.as_ptr()) },
                    }
                };
                return Ok((wrap_tokio_ssl_stream(stream), outcome));
            }
            Err(SslHandshakeError::WouldBlock(mut pending)) => {
                if early_offset < early_data.len()
                    && unsafe { SSL_in_early_data(pending.ssl().as_ptr()) != 0 }
                {
                    let written =
                        write_tls_early_data(pending.ssl_mut(), &early_data[early_offset..])?;
                    early_offset += written;
                }
                mid = pending_handshake(pending).await?;
            }
            Err(SslHandshakeError::SetupFailure(err)) => {
                return Err(Error::Tls(format!("TLS handshake setup failed: {err}")));
            }
            Err(SslHandshakeError::Failure(err)) => {
                return Err(Error::Tls(format!("TLS handshake failed: {}", err.error())));
            }
        }
    }
}

fn wrap_tokio_ssl_stream<S>(stream: boring::ssl::SslStream<AsyncStreamBridge<S>>) -> SslStream<S> {
    // Both types are single-field newtypes over the same inner `SslStream<AsyncStreamBridge<S>>`.
    unsafe { std::mem::transmute(stream) }
}

async fn pending_handshake<S>(
    mid: boring::ssl::MidHandshakeSslStream<AsyncStreamBridge<S>>,
) -> Result<boring::ssl::MidHandshakeSslStream<AsyncStreamBridge<S>>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::future::Future;

    struct HandshakeWait<S> {
        mid: Option<boring::ssl::MidHandshakeSslStream<AsyncStreamBridge<S>>>,
        registered: bool,
    }

    impl<S> Future for HandshakeWait<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = boring::ssl::MidHandshakeSslStream<AsyncStreamBridge<S>>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if !self.registered {
                let mid = self.mid.as_mut().expect("mid missing");
                mid.get_mut().set_waker(Some(cx));
                mid.ssl_mut().set_task_waker(Some(cx.waker().clone()));
                self.registered = true;
                return Poll::Pending;
            }
            Poll::Ready(self.mid.take().expect("mid missing on wake"))
        }
    }

    Ok(HandshakeWait {
        mid: Some(mid),
        registered: false,
    }
    .await)
}

fn write_tls_early_data(ssl: &mut boring::ssl::SslRef, data: &[u8]) -> Result<usize, Error> {
    unsafe {
        let written = boring_sys::SSL_write(
            ssl.as_ptr() as *mut SSL,
            data.as_ptr() as *const std::ffi::c_void,
            data.len().try_into().unwrap_or(i32::MAX),
        );
        if written > 0 {
            return Ok(written as usize);
        }
        let code = boring_sys::SSL_get_error(ssl.as_ptr(), written);
        if code == boring_sys::SSL_ERROR_WANT_READ
            || code == boring_sys::SSL_ERROR_WANT_WRITE
        {
            return Ok(0);
        }
        Err(Error::Tls(format!(
            "Failed to write TLS early data (ssl error code {code})"
        )))
    }
}

fn apply_tcp_keepalive_to_stream(
    stream: &TcpStream,
    config: &TcpKeepaliveConfig,
) -> Result<(), Error> {
    apply_tcp_keepalive(socket2::SockRef::from(stream), config)
}

fn apply_tcp_keepalive(
    socket: socket2::SockRef<'_>,
    config: &TcpKeepaliveConfig,
) -> Result<(), Error> {
    let Some(params) = tcp_keepalive_params(config) else {
        return Ok(());
    };
    socket
        .set_tcp_keepalive(&params)
        .map_err(|e| Error::Connection(format!("Failed to set TCP keepalive: {e}")))
}

fn tcp_keepalive_params(config: &TcpKeepaliveConfig) -> Option<socket2::TcpKeepalive> {
    if config.time.is_none() && config.interval.is_none() && config.retries.is_none() {
        return None;
    }
    let mut params = socket2::TcpKeepalive::new();
    if let Some(time) = config.time {
        params = params.with_time(time);
    }
    if let Some(interval) = config.interval {
        params = params.with_interval(interval);
    }
    if let Some(retries) = config.retries {
        params = params.with_retries(retries);
    }
    Some(params)
}
