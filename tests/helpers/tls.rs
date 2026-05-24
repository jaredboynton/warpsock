use boring::pkey::{PKey, Private};
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use boring::x509::X509;
use std::sync::OnceLock;

struct CachedTls {
    pkey: PKey<Private>,
    x509: X509,
    cert_pem: Vec<u8>,
}

fn cached() -> &'static CachedTls {
    static CACHE: OnceLock<CachedTls> = OnceLock::new();
    CACHE.get_or_init(|| {
        let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        let cert =
            rcgen::generate_simple_self_signed(subject_alt_names).expect("Failed to generate cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();
        let pkey =
            PKey::private_key_from_pem(key_pem.as_bytes()).expect("Failed to parse private key");
        let x509 = X509::from_pem(cert_pem.as_bytes()).expect("Failed to parse certificate");
        CachedTls {
            pkey,
            x509,
            cert_pem: cert_pem.into_bytes(),
        }
    })
}

/// Generate a self-signed certificate for 127.0.0.1 and return SslAcceptorBuilder + CA cert bytes.
///
/// The keypair and X509 are cached process-wide; only the SslAcceptorBuilder is rebuilt
/// per call so callers can attach an ALPN selector or other per-test config.
#[allow(dead_code)]
pub fn generate_cert_bundle() -> (SslAcceptorBuilder, Vec<u8>) {
    let c = cached();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .expect("Failed to create SslAcceptor builder");
    builder
        .set_private_key(&c.pkey)
        .expect("Failed to set private key");
    builder
        .set_certificate(&c.x509)
        .expect("Failed to set certificate");
    (builder, c.cert_pem.clone())
}

/// PEM bytes (cert and key) for components that load from PEM directly (e.g., quiche).
#[allow(dead_code)]
pub fn cached_cert_and_key_pem() -> (Vec<u8>, Vec<u8>) {
    let c = cached();
    let cert_pem = c.cert_pem.clone();
    let key_pem = c
        .pkey
        .private_key_to_pem_pkcs8()
        .expect("Failed to serialize cached private key to PEM");
    (cert_pem, key_pem)
}
