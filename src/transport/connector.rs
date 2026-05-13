//! BoringSSL TLS connector.

use boring::ssl::{SslConnector, SslMethod, SslSessionCacheMode, SslVersion};
use boring::x509::X509;
use http::Uri;
use std::io;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::error::Error;
use crate::fingerprint::tls::TlsFingerprint;
use crate::transport::tcp::{configure_tcp_socket, TcpFingerprint};

// FFI bindings for BoringSSL extension control
use boring_sys::{CRYPTO_BUFFER, SSL, SSL_CTX};
use std::os::raw::c_int;

extern "C" {
    /// Enable GREASE (Generate Random Extensions And Sustain Extensibility)
    pub fn SSL_CTX_set_grease_enabled(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
    /// Enable extension order permutation (Chrome 110+ behavior)
    pub fn SSL_CTX_set_permute_extensions(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
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

/// BoringSSL-based TLS connector for hyper.
#[derive(Clone)]
pub struct BoringConnector {
    tls_config: Option<TlsFingerprint>,
    tcp_fingerprint: Option<TcpFingerprint>,
    root_certs: Vec<Vec<u8>>,
    /// Load root certificates from the OS certificate store at runtime
    use_platform_roots: bool,
    /// Skip TLS certificate verification (DANGEROUS - for testing only)
    danger_accept_invalid_certs: bool,
}

impl BoringConnector {
    /// Create a new connector with default TLS configuration.
    ///
    /// Note: By default, this does NOT load platform root certificates.
    /// Use `with_platform_roots(true)` to enable automatic loading of OS root CAs,
    /// which is required for cross-compiled builds (e.g., Windows builds from macOS).
    pub fn new() -> Self {
        Self {
            tls_config: None,
            tcp_fingerprint: None,
            root_certs: Vec::new(),
            use_platform_roots: false,
            danger_accept_invalid_certs: false,
        }
    }

    /// Create a connector with TLS fingerprint configuration.
    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self {
            tls_config: Some(fp),
            tcp_fingerprint: None,
            root_certs: Vec::new(),
            use_platform_roots: false,
            danger_accept_invalid_certs: false,
        }
    }

    /// Create a connector with both TLS and TCP fingerprint configuration.
    pub fn with_fingerprints(tls_fp: TlsFingerprint, tcp_fp: TcpFingerprint) -> Self {
        Self {
            tls_config: Some(tls_fp),
            tcp_fingerprint: Some(tcp_fp),
            root_certs: Vec::new(),
            use_platform_roots: false,
            danger_accept_invalid_certs: false,
        }
    }

    /// Set TCP fingerprint configuration.
    pub fn with_tcp_fingerprint(mut self, tcp_fp: TcpFingerprint) -> Self {
        self.tcp_fingerprint = Some(tcp_fp);
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

    fn configure_ssl(&self, _domain: &str, alpn_mode: AlpnMode) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| Error::Tls(format!("Failed to create SSL connector: {}", e)))?;

        // Skip certificate verification if danger_accept_invalid_certs is enabled
        if self.danger_accept_invalid_certs {
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        }

        // Load platform root certificates if enabled
        // This is required for cross-compiled builds where BoringSSL can't find system certs
        if self.use_platform_roots {
            let result = rustls_native_certs::load_native_certs();

            // Log any errors encountered while loading certificates
            for err in &result.errors {
                tracing::warn!("Error loading platform certificate: {}", err);
            }

            // Add successfully loaded certificates to the trust store
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

        // Add custom root certs (in addition to platform roots)
        for cert_bytes in &self.root_certs {
            if let Ok(cert) = X509::from_der(cert_bytes) {
                let _ = builder.cert_store_mut().add_cert(cert);
            } else if let Ok(cert) = X509::from_pem(cert_bytes) {
                let _ = builder.cert_store_mut().add_cert(cert);
            } else {
                // Ignore invalid certs or log warning
            }
        }

        if let Some(fp) = &self.tls_config {
            // Set cipher list from fingerprint
            if !fp.cipher_list.is_empty() {
                let cipher_str = fp.cipher_list.join(":");
                builder
                    .set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }

            // Set curves/groups from fingerprint
            // If Kyber is enabled, prepend X25519Kyber768Draft00 to the curves list
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
                // If no curves specified but Kyber is enabled, set Kyber as the only group
                builder
                    .set_curves_list("X25519Kyber768Draft00")
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }

            // Set signature algorithms from fingerprint
            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                builder.set_sigalgs_list(&sigalgs_str).map_err(|e| {
                    Error::Tls(format!("Failed to set signature algorithms: {}", e))
                })?;
            }

            // Enable GREASE and extension permutation for Chrome-like behavior
            // Firefox also randomizes extensions but doesn't use GREASE
            unsafe {
                let ctx = builder.as_ptr() as *mut SSL_CTX;
                if fp.grease {
                    // Chrome: enable GREASE and extension permutation
                    SSL_CTX_set_grease_enabled(ctx, 1);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                } else {
                    // Firefox: enable extension permutation but NOT GREASE
                    SSL_CTX_set_grease_enabled(ctx, 0);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                }

                // Configure certificate compression (compress_certificate extension)
                // Chrome uses Brotli, Firefox does not use compression
                // Note: Certificate compression is configured via SSL_CTX_add_cert_compression_alg
                // which requires callback functions. We only implement decompression (client receives
                // compressed certs from server).
                match fp.cert_compression {
                    crate::fingerprint::CertCompression::Brotli => {
                        let _ = boring_sys::SSL_CTX_add_cert_compression_alg(
                            ctx,
                            boring_sys::TLSEXT_cert_compression_brotli as u16,
                            None, // No compression callback (client doesn't compress)
                            Some(decompress_brotli_cert),
                        );
                    }
                    crate::fingerprint::CertCompression::Zlib => {
                        let _ = boring_sys::SSL_CTX_add_cert_compression_alg(
                            ctx,
                            boring_sys::TLSEXT_cert_compression_zlib as u16,
                            None, // No compression callback (client doesn't compress)
                            Some(decompress_zlib_cert),
                        );
                    }
                    crate::fingerprint::CertCompression::None => {
                        // No certificate compression
                    }
                }

                // Note: ALPS (Application-Layer Protocol Settings) extension is deferred.
                // The API requires SSL_add_application_settings() which works on the SSL object
                // (not SSL_CTX), meaning it must be called after SSL object creation during
                // connection setup. This would require architectural changes to access the SSL
                // object before handshake completion.
            }

            // Note: extension_order field in TlsFingerprint is for reference only.
            // Modern browsers (Chrome 110+, Firefox 133+) randomize extension order,
            // so we cannot set a static order. The extension_order field is used for
            // JA3 fingerprint reference (though JA3 will vary due to randomization)
            // and JA4 fingerprinting (which sorts extensions alphabetically).

            // Set min/max TLS version
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        } else {
            // Default configuration
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        }

        // Enable session caching (browsers use this for session resumption)
        // This enables TLS session tickets and session ID caching
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        // Enable ALPN for HTTP/2 or constrain it for HTTP/1-only callers.
        let alpn_protos = match alpn_mode {
            AlpnMode::Default => b"\x02h2\x08http/1.1".as_slice(),
            AlpnMode::Http1Only => b"\x08http/1.1".as_slice(),
        };
        builder
            .set_alpn_protos(alpn_protos)
            .map_err(|e| Error::Tls(format!("Failed to set ALPN: {}", e)))?;

        Ok(builder.build())
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
}

impl AsyncRead for MaybeHttpsStream {
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_flush(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

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

        let addr = format!("{}:{}", host, port);

        // Configure TCP socket options if fingerprint is provided
        let tcp_stream = if let Some(ref tcp_fp) = self.tcp_fingerprint {
            // Create socket2 socket, configure it, then connect and convert to tokio TcpStream
            use socket2::{Domain, Socket, Type};
            use std::net::SocketAddr;
            use tokio::net::lookup_host;
            use tokio::task;

            // Resolve hostname to IP address (tokio handles async DNS resolution)
            let socket_addr: SocketAddr = lookup_host(&addr)
                .await
                .map_err(|e| {
                    Error::Connection(format!("DNS resolution failed for {}: {}", addr, e))
                })?
                .next()
                .ok_or_else(|| Error::Connection(format!("No addresses found for {}", addr)))?;

            let domain = match socket_addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };

            // Perform blocking socket operations in a blocking task
            let tcp_fp_clone = tcp_fp.clone();
            let socket_addr_copy = socket_addr;
            let std_stream = task::spawn_blocking(move || -> Result<std::net::TcpStream, Error> {
                let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))
                    .map_err(|e| Error::Connection(format!("Failed to create socket: {}", e)))?;

                // Configure TCP fingerprint options
                configure_tcp_socket(&socket, &tcp_fp_clone).map_err(|e| {
                    Error::Connection(format!("Failed to configure TCP socket: {}", e))
                })?;

                // Connect synchronously (socket2 handles this)
                socket
                    .connect(&socket_addr_copy.into())
                    .map_err(|e| Error::Connection(format!("Failed to connect: {}", e)))?;

                // Set to non-blocking mode for tokio compatibility (required by tokio 1.48+)
                socket
                    .set_nonblocking(true)
                    .map_err(|e| Error::Connection(format!("Failed to set non-blocking: {}", e)))?;

                // Convert to std::net::TcpStream
                Ok(socket.into())
            })
            .await
            .map_err(|e| Error::Connection(format!("Blocking task failed: {}", e)))??;

            // Convert to tokio TcpStream (socket is already non-blocking)
            TcpStream::from_std(std_stream).map_err(|e| {
                Error::Connection(format!("Failed to convert to tokio stream: {}", e))
            })?
        } else {
            // Default connection without TCP fingerprinting
            TcpStream::connect(&addr)
                .await
                .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", addr, e)))?
        };

        if uri.scheme_str() == Some("https") {
            let ssl_connector = self.configure_ssl(host, alpn_mode)?;

            let ssl_config = ssl_connector
                .configure()
                .map_err(|e| Error::Tls(format!("Failed to configure SSL: {}", e)))?;

            let ssl_stream = tokio_boring::connect(ssl_config, host, tcp_stream)
                .await
                .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

            Ok(MaybeHttpsStream::Https(ssl_stream))
        } else {
            Ok(MaybeHttpsStream::Http(tcp_stream))
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
