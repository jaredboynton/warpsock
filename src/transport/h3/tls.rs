//! Native QUIC/TLS helpers for HTTP/3.

use std::io::Read;
use std::os::raw::c_int;
use std::sync::{Arc, Mutex, OnceLock};

use boring::ex_data::Index;
use boring::pkey::PKey;
use boring::ssl::{
    AlpnError, Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use boring_sys as ffi;
use bytes::Bytes;
use foreign_types_shared::ForeignType;

use crate::error::{Error, Result};
use crate::fingerprint::{CertCompression, Http3Fingerprint, TlsFingerprint};
use crate::transport::h3::quic::{
    build_initial_crypto_packet, derive_initial_key_material,
    derive_packet_key_material_from_secret, encode_initial_header,
    encode_server_transport_parameters, encode_transport_parameters,
    encode_transport_parameters_with_initial_source_connection_id, ConnectionId, LongHeaderPacket,
    LongHeaderType, QuicPacketKeyMaterial,
};

const QUIC_VERSION_1: u32 = 1;
const CLIENT_INITIAL_PACKET_NUMBER: u64 = 0;
const CLIENT_INITIAL_PACKET_NUMBER_LEN: usize = 4;
const MIN_CLIENT_INITIAL_DATAGRAM_LEN: usize = 1200;
const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedClientInitial {
    pub crypto_data: Bytes,
    pub transport_parameters: Bytes,
    pub secrets: Vec<QuicTlsSecret>,
}

pub struct NativeQuicTlsSession {
    ssl: Ssl,
    state: SharedCaptureState,
    transport_parameters: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInitialPacket {
    pub packet: Bytes,
    pub header: Bytes,
    pub packet_number_offset: usize,
    pub crypto_data: Bytes,
    pub transport_parameters: Bytes,
    pub secrets: Vec<QuicTlsSecret>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicSecretDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicEncryptionLevel {
    Initial,
    EarlyData,
    Handshake,
    Application,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTlsSecret {
    pub direction: QuicSecretDirection,
    pub level: QuicEncryptionLevel,
    pub secret: Bytes,
}

impl QuicTlsSecret {
    pub fn packet_key_material(&self) -> Result<QuicPacketKeyMaterial> {
        derive_packet_key_material_from_secret(self.secret.clone())
    }
}

#[derive(Debug, Default)]
struct CaptureState {
    initial_crypto: Vec<u8>,
    early_crypto: Vec<u8>,
    handshake_crypto: Vec<u8>,
    application_crypto: Vec<u8>,
    secrets: Vec<QuicTlsSecret>,
}

type SharedCaptureState = Arc<Mutex<CaptureState>>;

pub fn capture_client_initial_crypto(
    server_name: &str,
    fingerprint: &Http3Fingerprint,
) -> Result<CapturedClientInitial> {
    let mut session = NativeQuicTlsSession::client(server_name, fingerprint)?;
    Ok(session.take_client_initial())
}

impl NativeQuicTlsSession {
    pub fn client(server_name: &str, fingerprint: &Http3Fingerprint) -> Result<Self> {
        let mut session = Self::new_client(server_name, fingerprint, None, None, true, &[], false)?;
        session.drive_handshake("QUIC ClientHello capture handshake")?;
        if session.crypto_len(QuicEncryptionLevel::Initial) == 0 {
            return Err(Error::Tls(
                "QUIC ClientHello capture produced no CRYPTO data".into(),
            ));
        }
        Ok(session)
    }

    pub fn server(fingerprint: &Http3Fingerprint, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let mut session = Self::new_server(fingerprint, cert_pem, key_pem, None, None, None)?;
        session.drive_handshake("QUIC server handshake")?;
        Ok(session)
    }

    pub fn server_with_connection_ids(
        fingerprint: &Http3Fingerprint,
        cert_pem: &[u8],
        key_pem: &[u8],
        original_destination_connection_id: &ConnectionId,
        initial_source_connection_id: &ConnectionId,
    ) -> Result<Self> {
        let mut session = Self::new_server(
            fingerprint,
            cert_pem,
            key_pem,
            Some(original_destination_connection_id),
            Some(initial_source_connection_id),
            None,
        )?;
        session.drive_handshake("QUIC server handshake")?;
        Ok(session)
    }

    pub fn client_with_tls_fingerprint(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        tls_fingerprint: Option<&TlsFingerprint>,
        verify_peer: bool,
    ) -> Result<Self> {
        let mut session = Self::new_client(
            server_name,
            fingerprint,
            None,
            tls_fingerprint,
            verify_peer,
            &[],
            false,
        )?;
        session.drive_handshake("QUIC ClientHello capture handshake")?;
        if session.crypto_len(QuicEncryptionLevel::Initial) == 0 {
            return Err(Error::Tls(
                "QUIC ClientHello capture produced no CRYPTO data".into(),
            ));
        }
        Ok(session)
    }

    pub fn client_with_initial_source_connection_id(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        initial_source_connection_id: &ConnectionId,
    ) -> Result<Self> {
        Self::client_with_initial_source_connection_id_and_verify_peer(
            server_name,
            fingerprint,
            initial_source_connection_id,
            None,
            true,
            &[],
            false,
        )
    }

    pub fn client_with_initial_source_connection_id_and_verify_peer(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        initial_source_connection_id: &ConnectionId,
        tls_fingerprint: Option<&TlsFingerprint>,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
    ) -> Result<Self> {
        let mut session = Self::new_client(
            server_name,
            fingerprint,
            Some(initial_source_connection_id),
            tls_fingerprint,
            verify_peer,
            root_certs,
            use_platform_roots,
        )?;
        session.drive_handshake("QUIC ClientHello capture handshake")?;
        if session.crypto_len(QuicEncryptionLevel::Initial) == 0 {
            return Err(Error::Tls(
                "QUIC ClientHello capture produced no CRYPTO data".into(),
            ));
        }
        Ok(session)
    }

    pub fn provide_crypto(&mut self, level: QuicEncryptionLevel, data: &[u8]) -> Result<()> {
        unsafe {
            if ffi::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                level.to_ffi(),
                data.as_ptr(),
                data.len(),
            ) != 1
            {
                return Err(Error::Tls("failed to provide server CRYPTO data".into()));
            }
        }
        self.drive_handshake("server CRYPTO")
    }

    pub fn take_client_initial(&mut self) -> CapturedClientInitial {
        CapturedClientInitial {
            crypto_data: self.take_crypto(QuicEncryptionLevel::Initial),
            transport_parameters: self.transport_parameters().clone(),
            secrets: self.secrets(),
        }
    }

    pub fn take_crypto(&mut self, level: QuicEncryptionLevel) -> Bytes {
        let mut state = self.state.lock().expect("QUIC TLS capture state poisoned");
        Bytes::from(match level {
            QuicEncryptionLevel::Initial => std::mem::take(&mut state.initial_crypto),
            QuicEncryptionLevel::EarlyData => std::mem::take(&mut state.early_crypto),
            QuicEncryptionLevel::Handshake => std::mem::take(&mut state.handshake_crypto),
            QuicEncryptionLevel::Application => std::mem::take(&mut state.application_crypto),
        })
    }

    pub fn secrets(&self) -> Vec<QuicTlsSecret> {
        self.state
            .lock()
            .expect("QUIC TLS capture state poisoned")
            .secrets
            .clone()
    }

    pub fn transport_parameters(&self) -> &Bytes {
        &self.transport_parameters
    }

    fn new_client(
        server_name: &str,
        fingerprint: &Http3Fingerprint,
        initial_source_connection_id: Option<&ConnectionId>,
        tls_fingerprint: Option<&TlsFingerprint>,
        verify_peer: bool,
        root_certs: &[Vec<u8>],
        use_platform_roots: bool,
    ) -> Result<Self> {
        let mut builder = SslContext::builder(SslMethod::tls_client())
            .map_err(|err| Error::Tls(format!("failed to create QUIC TLS context: {err}")))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| Error::Tls(format!("failed to set QUIC TLS minimum version: {err}")))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| Error::Tls(format!("failed to set QUIC TLS maximum version: {err}")))?;
        builder.set_grease_enabled(
            tls_fingerprint
                .map(|fingerprint| fingerprint.grease)
                .unwrap_or(fingerprint.transport.grease),
        );
        builder.set_permute_extensions(true);
        if let Some(tls_fingerprint) = tls_fingerprint {
            apply_tls_fingerprint(&mut builder, tls_fingerprint)?;
        }
        if verify_peer {
            builder.set_verify(SslVerifyMode::PEER);
            let _ = builder.set_default_verify_paths();
            apply_native_roots(&mut builder, root_certs, use_platform_roots);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }
        builder
            .set_alpn_protos(&wire_alpn_protocols(fingerprint)?)
            .map_err(|err| Error::Tls(format!("failed to set QUIC ALPN: {err}")))?;

        let context = builder.build();
        let mut ssl = Ssl::new(&context)
            .map_err(|err| Error::Tls(format!("failed to create QUIC TLS session: {err}")))?;
        ssl.set_hostname(server_name)
            .map_err(|err| Error::Tls(format!("failed to set QUIC SNI: {err}")))?;

        let state = Arc::new(Mutex::new(CaptureState::default()));
        ssl.replace_ex_data(capture_index(), state.clone());

        let transport_parameters =
            if let Some(initial_source_connection_id) = initial_source_connection_id {
                encode_transport_parameters_with_initial_source_connection_id(
                    &fingerprint.transport,
                    initial_source_connection_id,
                )
            } else {
                encode_transport_parameters(&fingerprint.transport)
            };
        unsafe {
            if ffi::SSL_set_quic_method(ssl.as_ptr(), quic_method()) != 1 {
                return Err(Error::Tls("failed to install QUIC TLS method".into()));
            }
            if ffi::SSL_set_quic_transport_params(
                ssl.as_ptr(),
                transport_parameters.as_ptr(),
                transport_parameters.len(),
            ) != 1
            {
                return Err(Error::Tls("failed to set QUIC transport parameters".into()));
            }
            ffi::SSL_set_connect_state(ssl.as_ptr());
        }

        Ok(Self {
            ssl,
            state,
            transport_parameters,
        })
    }

    fn new_server(
        fingerprint: &Http3Fingerprint,
        cert_pem: &[u8],
        key_pem: &[u8],
        original_destination_connection_id: Option<&ConnectionId>,
        initial_source_connection_id: Option<&ConnectionId>,
        retry_source_connection_id: Option<&ConnectionId>,
    ) -> Result<Self> {
        let mut builder = SslContext::builder(SslMethod::tls_server()).map_err(|err| {
            Error::Tls(format!("failed to create QUIC TLS server context: {err}"))
        })?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| {
                Error::Tls(format!(
                    "failed to set QUIC TLS server minimum version: {err}"
                ))
            })?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| {
                Error::Tls(format!(
                    "failed to set QUIC TLS server maximum version: {err}"
                ))
            })?;
        builder.set_verify(SslVerifyMode::NONE);

        let cert = X509::from_pem(cert_pem)
            .map_err(|err| Error::Tls(format!("failed to parse QUIC server certificate: {err}")))?;
        let key = PKey::private_key_from_pem(key_pem)
            .map_err(|err| Error::Tls(format!("failed to parse QUIC server private key: {err}")))?;
        builder
            .set_certificate(&cert)
            .map_err(|err| Error::Tls(format!("failed to set QUIC server certificate: {err}")))?;
        builder
            .set_private_key(&key)
            .map_err(|err| Error::Tls(format!("failed to set QUIC server private key: {err}")))?;
        builder
            .check_private_key()
            .map_err(|err| Error::Tls(format!("invalid QUIC server private key: {err}")))?;

        let alpn_protocols = fingerprint.alpn_protocols.clone();
        builder.set_alpn_select_callback(move |_ssl, client_protocols| {
            select_client_alpn(client_protocols, &alpn_protocols).ok_or(AlpnError::NOACK)
        });

        let context = builder.build();
        let mut ssl = Ssl::new(&context).map_err(|err| {
            Error::Tls(format!("failed to create QUIC TLS server session: {err}"))
        })?;

        let state = Arc::new(Mutex::new(CaptureState::default()));
        ssl.replace_ex_data(capture_index(), state.clone());

        let transport_parameters = match (
            original_destination_connection_id,
            initial_source_connection_id,
        ) {
            (Some(original_destination_connection_id), Some(initial_source_connection_id)) => {
                encode_server_transport_parameters(
                    &fingerprint.transport,
                    original_destination_connection_id,
                    initial_source_connection_id,
                    retry_source_connection_id,
                )
            }
            _ => encode_transport_parameters(&fingerprint.transport),
        };
        unsafe {
            if ffi::SSL_set_quic_method(ssl.as_ptr(), quic_method()) != 1 {
                return Err(Error::Tls(
                    "failed to install QUIC server TLS method".into(),
                ));
            }
            if ffi::SSL_set_quic_transport_params(
                ssl.as_ptr(),
                transport_parameters.as_ptr(),
                transport_parameters.len(),
            ) != 1
            {
                return Err(Error::Tls(
                    "failed to set QUIC server transport parameters".into(),
                ));
            }
            ffi::SSL_set_accept_state(ssl.as_ptr());
        }

        Ok(Self {
            ssl,
            state,
            transport_parameters,
        })
    }

    fn drive_handshake(&mut self, context: &str) -> Result<()> {
        unsafe {
            let ret = ffi::SSL_do_handshake(self.ssl.as_ptr());
            let err = ffi::SSL_get_error(self.ssl.as_ptr(), ret);
            if ret != 1 && err != ffi::SSL_ERROR_WANT_READ {
                return Err(Error::Tls(format!("{context} failed with SSL error {err}")));
            }
            Ok(())
        }
    }

    fn crypto_len(&self, level: QuicEncryptionLevel) -> usize {
        let state = self.state.lock().expect("QUIC TLS capture state poisoned");
        match level {
            QuicEncryptionLevel::Initial => state.initial_crypto.len(),
            QuicEncryptionLevel::EarlyData => state.early_crypto.len(),
            QuicEncryptionLevel::Handshake => state.handshake_crypto.len(),
            QuicEncryptionLevel::Application => state.application_crypto.len(),
        }
    }
}

fn apply_tls_fingerprint(
    builder: &mut SslContextBuilder,
    fingerprint: &TlsFingerprint,
) -> Result<()> {
    let tls12_ciphers = fingerprint
        .cipher_list
        .iter()
        .filter(|cipher| !cipher.starts_with("TLS_"))
        .copied()
        .collect::<Vec<_>>();
    if !tls12_ciphers.is_empty() {
        builder
            .set_cipher_list(&tls12_ciphers.join(":"))
            .map_err(|err| Error::Tls(format!("failed to set QUIC TLS cipher list: {err}")))?;
    }

    if !fingerprint.curves.is_empty() {
        let curves = if fingerprint.enable_kyber {
            format!("X25519Kyber768Draft00:{}", fingerprint.curves.join(":"))
        } else {
            fingerprint.curves.join(":")
        };
        builder
            .set_curves_list(&curves)
            .map_err(|err| Error::Tls(format!("failed to set QUIC TLS curves: {err}")))?;
    } else if fingerprint.enable_kyber {
        builder
            .set_curves_list("X25519Kyber768Draft00")
            .map_err(|err| Error::Tls(format!("failed to set QUIC TLS curves: {err}")))?;
    }

    if !fingerprint.sigalgs.is_empty() {
        builder
            .set_sigalgs_list(&fingerprint.sigalgs.join(":"))
            .map_err(|err| {
                Error::Tls(format!(
                    "failed to set QUIC TLS signature algorithms: {err}"
                ))
            })?;
    }

    apply_tls_cert_compression(builder, fingerprint.cert_compression)?;

    Ok(())
}

fn apply_tls_cert_compression(
    builder: &mut SslContextBuilder,
    cert_compression: CertCompression,
) -> Result<()> {
    let (algorithm, decompress) = match cert_compression {
        CertCompression::Brotli => (
            ffi::TLSEXT_cert_compression_brotli as u16,
            Some(decompress_brotli_cert as _),
        ),
        CertCompression::Zlib => (
            ffi::TLSEXT_cert_compression_zlib as u16,
            Some(decompress_zlib_cert as _),
        ),
        CertCompression::None => return Ok(()),
    };

    unsafe {
        if ffi::SSL_CTX_add_cert_compression_alg(builder.as_ptr(), algorithm, None, decompress) != 1
        {
            return Err(Error::Tls(
                "failed to configure QUIC TLS certificate compression".into(),
            ));
        }
    }

    Ok(())
}

unsafe extern "C" fn decompress_brotli_cert(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    let compressed = std::slice::from_raw_parts(input, input_len);
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    let mut decoder = brotli::Decompressor::new(compressed, uncompressed_len);
    write_decompressed_cert(
        out,
        uncompressed_len,
        decoder.read_to_end(&mut decompressed),
        &decompressed,
    )
}

unsafe extern "C" fn decompress_zlib_cert(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    let compressed = std::slice::from_raw_parts(input, input_len);
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    write_decompressed_cert(
        out,
        uncompressed_len,
        decoder.read_to_end(&mut decompressed),
        &decompressed,
    )
}

unsafe fn write_decompressed_cert(
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    result: std::io::Result<usize>,
    decompressed: &[u8],
) -> c_int {
    if !matches!(result, Ok(_) if decompressed.len() == uncompressed_len) {
        return 0;
    }

    let buffer = ffi::CRYPTO_BUFFER_new(
        decompressed.as_ptr(),
        decompressed.len(),
        std::ptr::null_mut(),
    );
    if buffer.is_null() {
        return 0;
    }
    *out = buffer;
    1
}

fn apply_native_roots(
    builder: &mut SslContextBuilder,
    root_certs: &[Vec<u8>],
    use_platform_roots: bool,
) {
    if use_platform_roots {
        let result = rustls_native_certs::load_native_certs();
        for err in &result.errors {
            tracing::warn!("Error loading platform certificate for native H3: {}", err);
        }
        for cert_der in result.certs {
            if let Ok(cert) = X509::from_der(cert_der.as_ref()) {
                let _ = builder.cert_store_mut().add_cert(cert);
            }
        }
    }

    for cert_bytes in root_certs {
        if let Ok(cert) = X509::from_der(cert_bytes) {
            let _ = builder.cert_store_mut().add_cert(cert);
        } else if let Ok(cert) = X509::from_pem(cert_bytes) {
            let _ = builder.cert_store_mut().add_cert(cert);
        }
    }
}

pub fn build_client_initial_packet(
    server_name: &str,
    fingerprint: &Http3Fingerprint,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
) -> Result<ClientInitialPacket> {
    let captured = capture_client_initial_crypto(server_name, fingerprint)?;
    build_client_initial_packet_from_capture_with_size(
        captured,
        destination_cid,
        source_cid,
        fingerprint.transport.initial_datagram_size,
    )
}

pub fn build_client_initial_packet_from_capture(
    captured: CapturedClientInitial,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
) -> Result<ClientInitialPacket> {
    build_client_initial_packet_from_capture_with_size(
        captured,
        destination_cid,
        source_cid,
        MIN_CLIENT_INITIAL_DATAGRAM_LEN,
    )
}

pub fn build_client_initial_packet_from_capture_with_size(
    captured: CapturedClientInitial,
    destination_cid: ConnectionId,
    source_cid: ConnectionId,
    initial_datagram_size: usize,
) -> Result<ClientInitialPacket> {
    let header_len_without_length =
        1 + 4 + 1 + destination_cid.as_bytes().len() + 1 + source_cid.as_bytes().len() + 1;
    let padded_plaintext_len = initial_plaintext_len(
        header_len_without_length,
        captured.crypto_data.len(),
        initial_datagram_size,
    );
    let payload_len = padded_plaintext_len + AES_GCM_TAG_LEN;
    let header = encode_initial_header(&LongHeaderPacket {
        packet_type: LongHeaderType::Initial,
        version: QUIC_VERSION_1,
        destination_cid: destination_cid.clone(),
        source_cid,
        token: Bytes::new(),
        packet_number: CLIENT_INITIAL_PACKET_NUMBER,
        packet_number_len: CLIENT_INITIAL_PACKET_NUMBER_LEN,
        payload_len,
    })?;
    let packet_number_offset = header
        .len()
        .checked_sub(CLIENT_INITIAL_PACKET_NUMBER_LEN)
        .ok_or_else(|| Error::HttpProtocol("invalid QUIC Initial header length".into()))?;
    let keys = derive_initial_key_material(destination_cid.as_bytes())?;
    let packet = build_initial_crypto_packet(
        &keys.client,
        CLIENT_INITIAL_PACKET_NUMBER,
        &header,
        packet_number_offset,
        CLIENT_INITIAL_PACKET_NUMBER_LEN,
        &captured.crypto_data,
        padded_plaintext_len,
    )?;

    Ok(ClientInitialPacket {
        packet,
        header,
        packet_number_offset,
        crypto_data: captured.crypto_data,
        transport_parameters: captured.transport_parameters,
        secrets: captured.secrets,
    })
}

fn initial_plaintext_len(
    header_len_without_length: usize,
    crypto_data_len: usize,
    initial_datagram_size: usize,
) -> usize {
    let target_datagram_len = initial_datagram_size.max(MIN_CLIENT_INITIAL_DATAGRAM_LEN);
    let crypto_frame_len = 1 + 1 + varint_len(crypto_data_len as u64) + crypto_data_len;
    let mut padded_len = crypto_frame_len;
    loop {
        let payload_len = padded_len + AES_GCM_TAG_LEN;
        let header_len = header_len_without_length
            + varint_len((payload_len + CLIENT_INITIAL_PACKET_NUMBER_LEN) as u64)
            + CLIENT_INITIAL_PACKET_NUMBER_LEN;
        if header_len + payload_len >= target_datagram_len {
            return padded_len;
        }
        padded_len = target_datagram_len - header_len - AES_GCM_TAG_LEN;
    }
}

fn wire_alpn_protocols(fingerprint: &Http3Fingerprint) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for protocol in &fingerprint.alpn_protocols {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(Error::Tls("invalid QUIC ALPN protocol length".into()));
        }
        out.push(protocol.len() as u8);
        out.extend_from_slice(protocol);
    }
    if out.is_empty() {
        return Err(Error::Tls("QUIC ALPN list cannot be empty".into()));
    }
    Ok(out)
}

fn select_client_alpn<'a>(
    client_protocols: &'a [u8],
    server_protocols: &[Vec<u8>],
) -> Option<&'a [u8]> {
    let mut cursor = 0;
    while cursor < client_protocols.len() {
        let len = *client_protocols.get(cursor)? as usize;
        cursor += 1;
        let end = cursor.checked_add(len)?;
        let protocol = client_protocols.get(cursor..end)?;
        if server_protocols
            .iter()
            .any(|server_protocol| server_protocol.as_slice() == protocol)
        {
            return Some(protocol);
        }
        cursor = end;
    }
    None
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

fn capture_index() -> Index<Ssl, SharedCaptureState> {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    let raw = *INDEX.get_or_init(|| {
        Ssl::new_ex_index::<SharedCaptureState>()
            .expect("QUIC TLS capture ex_data index")
            .as_raw()
    });
    unsafe { Index::from_raw(raw) }
}

fn quic_method() -> *const ffi::SSL_QUIC_METHOD {
    static METHOD: OnceLock<ffi::SSL_QUIC_METHOD> = OnceLock::new();
    METHOD.get_or_init(|| ffi::SSL_QUIC_METHOD {
        set_read_secret: Some(set_read_secret),
        set_write_secret: Some(set_write_secret),
        add_handshake_data: Some(add_handshake_data),
        flush_flight: Some(flush_flight),
        send_alert: Some(send_alert),
    }) as *const _
}

unsafe extern "C" fn set_read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    _cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    record_secret(ssl, QuicSecretDirection::Read, level, secret, secret_len)
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    _cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    record_secret(ssl, QuicSecretDirection::Write, level, secret, secret_len)
}

unsafe extern "C" fn add_handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(level) = QuicEncryptionLevel::from_ffi(level) else {
        return 0;
    };
    let state = ffi::SSL_get_ex_data(ssl, capture_index().as_raw()) as *const SharedCaptureState;
    if state.is_null() || (data.is_null() && len > 0) {
        return 0;
    }
    let data = std::slice::from_raw_parts(data, len);
    match (*state).lock() {
        Ok(mut state) => {
            match level {
                QuicEncryptionLevel::Initial => state.initial_crypto.extend_from_slice(data),
                QuicEncryptionLevel::EarlyData => state.early_crypto.extend_from_slice(data),
                QuicEncryptionLevel::Handshake => state.handshake_crypto.extend_from_slice(data),
                QuicEncryptionLevel::Application => {
                    state.application_crypto.extend_from_slice(data)
                }
            }
            1
        }
        Err(_) => 0,
    }
}

unsafe extern "C" fn flush_flight(_ssl: *mut ffi::SSL) -> c_int {
    1
}

unsafe extern "C" fn send_alert(
    _ssl: *mut ffi::SSL,
    _level: ffi::ssl_encryption_level_t,
    _alert: u8,
) -> c_int {
    1
}

unsafe fn record_secret(
    ssl: *mut ffi::SSL,
    direction: QuicSecretDirection,
    level: ffi::ssl_encryption_level_t,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let state = ffi::SSL_get_ex_data(ssl, capture_index().as_raw()) as *const SharedCaptureState;
    if state.is_null() || (secret.is_null() && secret_len > 0) {
        return 0;
    }
    let Some(level) = QuicEncryptionLevel::from_ffi(level) else {
        return 0;
    };
    let secret = std::slice::from_raw_parts(secret, secret_len);
    match (*state).lock() {
        Ok(mut state) => {
            state.secrets.push(QuicTlsSecret {
                direction,
                level,
                secret: Bytes::copy_from_slice(secret),
            });
            1
        }
        Err(_) => 0,
    }
}

impl QuicEncryptionLevel {
    fn to_ffi(self) -> ffi::ssl_encryption_level_t {
        match self {
            Self::Initial => ffi::ssl_encryption_level_t::ssl_encryption_initial,
            Self::EarlyData => ffi::ssl_encryption_level_t::ssl_encryption_early_data,
            Self::Handshake => ffi::ssl_encryption_level_t::ssl_encryption_handshake,
            Self::Application => ffi::ssl_encryption_level_t::ssl_encryption_application,
        }
    }

    fn from_ffi(level: ffi::ssl_encryption_level_t) -> Option<Self> {
        if level == ffi::ssl_encryption_level_t::ssl_encryption_initial {
            Some(Self::Initial)
        } else if level == ffi::ssl_encryption_level_t::ssl_encryption_early_data {
            Some(Self::EarlyData)
        } else if level == ffi::ssl_encryption_level_t::ssl_encryption_handshake {
            Some(Self::Handshake)
        } else if level == ffi::ssl_encryption_level_t::ssl_encryption_application {
            Some(Self::Application)
        } else {
            None
        }
    }
}
