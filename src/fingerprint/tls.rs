//! TLS fingerprint configuration for browser impersonation.
//!
//! Chrome randomizes TLS extension order since v110, making static
//! JA3 fingerprints unreliable. Modern fingerprint detection systems use JA4 which sorts
//! extensions alphabetically. This implementation provides cipher suite,
//! signature algorithm, and curve ordering - but extension ordering may not
//! match real browsers.
//!
//! Current implementation: Chrome 142-146, Firefox 133
//!
//! ## Post-Quantum Cryptography (Kyber)
//!
//! Chrome 124+ enables X25519Kyber768 hybrid key exchange by default. This requires
//! BoringSSL compiled with post-quantum cryptography support. The `enable_kyber` flag
//! in `TlsFingerprint` will attempt to enable Kyber, but will silently fail if the
//! BoringSSL build does not support it.
//!
//! To verify Kyber support, check if connections show "X25519Kyber768" in the key
//! exchange algorithm when connecting to servers that support it (e.g., Google, Cloudflare).

/// Chrome 142-146 cipher suites in exact order.
/// Unchanged across Chrome 142 through 146.
pub const CHROME_CIPHER_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

/// Backwards-compatible alias for Chrome 142 cipher suites.
pub const CHROME_142_CIPHER_SUITES: &[&str] = CHROME_CIPHER_SUITES;

/// Chrome 142-146 signature algorithms.
/// Unchanged across Chrome 142 through 146.
pub const CHROME_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

/// Backwards-compatible alias for Chrome 142 signature algorithms.
pub const CHROME_142_SIGNATURE_ALGORITHMS: &[&str] = CHROME_SIGNATURE_ALGORITHMS;

/// Chrome 142-146 supported curves.
/// Unchanged across Chrome 142 through 146.
pub const CHROME_CURVES: &[&str] = &["x25519", "P-256", "P-384"];

/// Backwards-compatible alias for Chrome 142 curves.
pub const CHROME_142_CURVES: &[&str] = CHROME_CURVES;

/// Chrome 142-146 extension IDs in exact order.
/// Unchanged across Chrome 142 through 146.
pub const CHROME_EXTENSION_IDS: &[u16] =
    &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21];

/// Backwards-compatible alias for Chrome 142 extension IDs.
pub const CHROME_142_EXTENSION_IDS: &[u16] = CHROME_EXTENSION_IDS;

/// Firefox 133 cipher suites in exact order.
/// Firefox prefers AES-GCM over ChaCha20 (unlike some mobile-optimized builds).
pub const FIREFOX_133_CIPHER_SUITES: &[&str] = &[
    // TLS 1.3 cipher suites
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    // TLS 1.2 ECDHE cipher suites
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    // Legacy TLS 1.2 cipher suites
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

/// Firefox 133 signature algorithms.
/// Similar to Chrome but may have slight ordering differences.
pub const FIREFOX_133_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

/// Firefox 133 supported curves.
/// Firefox supports more curves than Chrome, including P-521.
/// BoringSSL uses curve names "P-256", "P-384", "P-521" rather than
/// the standard "secp256r1", "secp384r1", "secp521r1" identifiers.
pub const FIREFOX_133_CURVES: &[&str] = &["x25519", "P-256", "P-384", "P-521"];

/// Firefox 133 extension IDs.
/// Firefox 133 also randomizes extension order (similar to Chrome 110+),
/// so JA3 fingerprints will vary. JA4 sorts extensions for stable fingerprinting.
pub const FIREFOX_133_EXTENSION_IDS: &[u16] =
    &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21];

/// Certificate compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCompression {
    /// Brotli compression (Chrome uses this).
    Brotli,
    /// Zlib compression.
    Zlib,
    /// No certificate compression.
    None,
}

/// TLS fingerprint configuration.
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// Cipher suites in order.
    pub cipher_list: Vec<&'static str>,
    /// Signature algorithms.
    pub sigalgs: Vec<&'static str>,
    /// Supported curves/groups.
    pub curves: Vec<&'static str>,
    /// TLS extensions.
    pub extensions: Vec<u16>,
    /// Extension order (for JA3 fingerprint).
    pub extension_order: Vec<u16>,
    /// Enable GREASE values.
    pub grease: bool,
    /// Certificate compression algorithm (compress_certificate extension).
    /// Chrome 142 uses Brotli. Firefox does not use certificate compression.
    pub cert_compression: CertCompression,
    /// Enable post-quantum X25519Kyber768 hybrid key exchange.
    /// Chrome 124+ enables this by default. Requires BoringSSL with post-quantum support.
    /// Implemented by including "X25519Kyber768Draft00" in the curves/groups list.
    pub enable_kyber: bool,
}

impl Default for TlsFingerprint {
    fn default() -> Self {
        Self {
            cipher_list: vec![],
            sigalgs: vec![],
            curves: vec![],
            extensions: vec![],
            extension_order: vec![],
            grease: true,
            cert_compression: CertCompression::None,
            enable_kyber: false,
        }
    }
}

impl TlsFingerprint {
    /// Create a TLS fingerprint matching Chrome 142-146.
    /// The TLS configuration is identical across these versions.
    pub fn chrome() -> Self {
        Self {
            cipher_list: CHROME_CIPHER_SUITES.to_vec(),
            sigalgs: CHROME_SIGNATURE_ALGORITHMS.to_vec(),
            curves: CHROME_CURVES.to_vec(),
            extensions: CHROME_EXTENSION_IDS.to_vec(),
            extension_order: CHROME_EXTENSION_IDS.to_vec(),
            grease: true,
            cert_compression: CertCompression::Brotli,
            enable_kyber: true,
        }
    }

    /// Create a TLS fingerprint for Chrome 142.
    pub fn chrome_142() -> Self {
        Self::chrome()
    }

    /// Create a TLS fingerprint for Chrome 143.
    pub fn chrome_143() -> Self {
        Self::chrome()
    }

    /// Create a TLS fingerprint for Chrome 144.
    pub fn chrome_144() -> Self {
        Self::chrome()
    }

    /// Create a TLS fingerprint for Chrome 145.
    pub fn chrome_145() -> Self {
        Self::chrome()
    }

    /// Create a TLS fingerprint for Chrome 146.
    pub fn chrome_146() -> Self {
        Self::chrome()
    }

    /// Create a TLS fingerprint for Firefox 133.
    ///
    /// Firefox differs from Chrome in:
    /// - Cipher suite order (AES-GCM preferred, ChaCha20 third)
    /// - More curves supported (includes P-521)
    /// - No GREASE values (Firefox doesn't use GREASE)
    /// - Extension order randomization (like Chrome 110+)
    /// - No certificate compression (Firefox does not use compress_certificate)
    /// - Post-quantum Kyber disabled by default (requires manual flag)
    pub fn firefox_133() -> Self {
        Self {
            cipher_list: FIREFOX_133_CIPHER_SUITES.to_vec(),
            sigalgs: FIREFOX_133_SIGNATURE_ALGORITHMS.to_vec(),
            curves: FIREFOX_133_CURVES.to_vec(),
            extensions: FIREFOX_133_EXTENSION_IDS.to_vec(),
            extension_order: FIREFOX_133_EXTENSION_IDS.to_vec(),
            grease: false,                           // Firefox does NOT use GREASE
            cert_compression: CertCompression::None, // Firefox does not use certificate compression
            enable_kyber: false,                     // Firefox requires manual flag for Kyber
        }
    }

    /// Stable, explicit-field key suitable for use as a connection-pool discriminator.
    ///
    /// Unlike `format!("{self:?}")`, this representation enumerates each
    /// fingerprint-affecting field individually so adding new struct fields
    /// will not silently change the keying behavior of pooled connections.
    pub fn pool_key_string(&self) -> String {
        let cert_compression = match self.cert_compression {
            CertCompression::Brotli => "brotli",
            CertCompression::Zlib => "zlib",
            CertCompression::None => "none",
        };
        format!(
            "ciphers={}|sigalgs={}|curves={}|exts={}|order={}|grease={}|cc={}|kyber={}",
            self.cipher_list.join(","),
            self.sigalgs.join(","),
            self.curves.join(","),
            self.extensions
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(","),
            self.extension_order
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(","),
            self.grease,
            cert_compression,
            self.enable_kyber,
        )
    }
}
