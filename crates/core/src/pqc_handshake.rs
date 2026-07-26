use chrono::{DateTime, Utc};
use crate::pair_correlation::FiveTuple;

/// Re-export of chrono timestamp for handshake records.
pub type Timestamp = DateTime<Utc>;

/// TLS protocol version as a 2-byte enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    TlsV1_0,
    TlsV1_1,
    TlsV1_2,
    TlsV1_3,
    TlsV1_4,
    Unknown(u16),
}

impl TlsVersion {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0301 => TlsVersion::TlsV1_0,
            0x0302 => TlsVersion::TlsV1_1,
            0x0303 => TlsVersion::TlsV1_2,
            0x0304 => TlsVersion::TlsV1_3,
            0x0305 => TlsVersion::TlsV1_4,
            x => TlsVersion::Unknown(x),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            TlsVersion::TlsV1_0 => 0x0301,
            TlsVersion::TlsV1_1 => 0x0302,
            TlsVersion::TlsV1_2 => 0x0303,
            TlsVersion::TlsV1_3 => 0x0304,
            TlsVersion::TlsV1_4 => 0x0305,
            TlsVersion::Unknown(v) => *v,
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::TlsV1_0 => write!(f, "TLS 1.0"),
            TlsVersion::TlsV1_1 => write!(f, "TLS 1.1"),
            TlsVersion::TlsV1_2 => write!(f, "TLS 1.2"),
            TlsVersion::TlsV1_3 => write!(f, "TLS 1.3"),
            TlsVersion::TlsV1_4 => write!(f, "TLS 1.4"),
            TlsVersion::Unknown(v) => write!(f, "TLS 0x{v:04X}"),
        }
    }
}

/// KEM algorithm identifier (IANA codepoints, TLS 1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemId {
    /// ML-KEM-512 (Kyber-512)
    MlKem512,
    /// ML-KEM-768 (Kyber-768)
    MlKem768,
    /// ML-KEM-1024 (Kyber-1024)
    MlKem1024,
    /// FrodoKEM-640-AES
    FrodoKem640Aes,
    /// FrodoKEM-976-AES
    FrodoKem976Aes,
    /// FrodoKEM-1344-AES
    FrodoKem1344Aes,
    /// Classic McEliece-348864
    ClassicMcEliece348864,
    /// Classic McEliece-460896
    ClassicMcEliece460896,
    /// Classic McEliece-6688128
    ClassicMcEliece6688128,
    /// BIKE-L1 (level 1)
    BikeL1,
    /// BIKE-L3 (level 3)
    BikeL3,
    /// BIKE-L5 (level 5)
    BikeL5,
    /// HQC-128 (level 1)
    Hqc128,
    /// HQC-192 (level 3)
    Hqc192,
    /// HQC-256 (level 5)
    Hqc256,
    /// sntrup761 (Streamlined NTRU Prime 761)
    Sntrup761,
    /// Unrecognized KEM.
    Unknown(u16),
}

impl std::fmt::Display for KemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemId::MlKem512 => write!(f, "ML-KEM-512"),
            KemId::MlKem768 => write!(f, "ML-KEM-768"),
            KemId::MlKem1024 => write!(f, "ML-KEM-1024"),
            KemId::FrodoKem640Aes => write!(f, "FrodoKEM-640-AES"),
            KemId::FrodoKem976Aes => write!(f, "FrodoKEM-976-AES"),
            KemId::FrodoKem1344Aes => write!(f, "FrodoKEM-1344-AES"),
            KemId::ClassicMcEliece348864 => write!(f, "Classic McEliece-348864"),
            KemId::ClassicMcEliece460896 => write!(f, "Classic McEliece-460896"),
            KemId::ClassicMcEliece6688128 => write!(f, "Classic McEliece-6688128"),
            KemId::BikeL1 => write!(f, "BIKE-L1"),
            KemId::BikeL3 => write!(f, "BIKE-L3"),
            KemId::BikeL5 => write!(f, "BIKE-L5"),
            KemId::Hqc128 => write!(f, "HQC-128"),
            KemId::Hqc192 => write!(f, "HQC-192"),
            KemId::Hqc256 => write!(f, "HQC-256"),
            KemId::Sntrup761 => write!(f, "sntrup761"),
            KemId::Unknown(v) => write!(f, "KEM(0x{v:04X})"),
        }
    }
}

/// TLS named group (key exchange group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedGroup {
    /// secp256r1 (P-256)
    Secp256r1,
    /// secp384r1 (P-384)
    Secp384r1,
    /// secp521r1 (P-521)
    Secp521r1,
    /// x25519
    X25519,
    /// x448
    X448,
    /// FFDHE 2048-bit
    Ffdhe2048,
    /// FFDHE 3072-bit
    Ffdhe3072,
    /// FFDHE 4096-bit
    Ffdhe4096,
    /// FFDHE 6144-bit
    Ffdhe6144,
    /// FFDHE 8192-bit
    Ffdhe8192,
    /// Unrecognized group (raw codepoint stored).
    Unknown(u16),
}

impl NamedGroup {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0017 => NamedGroup::Secp256r1,
            0x0018 => NamedGroup::Secp384r1,
            0x0019 => NamedGroup::Secp521r1,
            0x001D => NamedGroup::X25519,
            0x001E => NamedGroup::X448,
            0x0100 => NamedGroup::Ffdhe2048,
            0x0101 => NamedGroup::Ffdhe3072,
            0x0102 => NamedGroup::Ffdhe4096,
            0x0103 => NamedGroup::Ffdhe6144,
            0x0104 => NamedGroup::Ffdhe8192,
            x => NamedGroup::Unknown(x),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            NamedGroup::Secp256r1 => 0x0017,
            NamedGroup::Secp384r1 => 0x0018,
            NamedGroup::Secp521r1 => 0x0019,
            NamedGroup::X25519 => 0x001D,
            NamedGroup::X448 => 0x001E,
            NamedGroup::Ffdhe2048 => 0x0100,
            NamedGroup::Ffdhe3072 => 0x0101,
            NamedGroup::Ffdhe4096 => 0x0102,
            NamedGroup::Ffdhe6144 => 0x0103,
            NamedGroup::Ffdhe8192 => 0x0104,
            NamedGroup::Unknown(v) => *v,
        }
    }

    pub fn is_pqc(&self) -> bool {
        matches!(self, NamedGroup::Unknown(_))
    }
}

impl std::fmt::Display for NamedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamedGroup::Secp256r1 => write!(f, "secp256r1"),
            NamedGroup::Secp384r1 => write!(f, "secp384r1"),
            NamedGroup::Secp521r1 => write!(f, "secp521r1"),
            NamedGroup::X25519 => write!(f, "x25519"),
            NamedGroup::X448 => write!(f, "x448"),
            NamedGroup::Ffdhe2048 => write!(f, "ffdhe2048"),
            NamedGroup::Ffdhe3072 => write!(f, "ffdhe3072"),
            NamedGroup::Ffdhe4096 => write!(f, "ffdhe4096"),
            NamedGroup::Ffdhe6144 => write!(f, "ffdhe6144"),
            NamedGroup::Ffdhe8192 => write!(f, "ffdhe8192"),
            NamedGroup::Unknown(v) => write!(f, "0x{v:04X}"),
        }
    }
}

/// PQC KEM operation data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcKem {
    pub algorithm: KemId,
    pub public_key: Option<Vec<u8>>,
    pub ciphertext: Option<Vec<u8>>,
    pub shared_secret: Option<Vec<u8>>,
}

impl std::fmt::Display for PqcKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.algorithm)?;
        if let Some(ct) = &self.ciphertext {
            write!(f, " ct={}B", ct.len())?;
        }
        if let Some(ss) = &self.shared_secret {
            write!(f, " ss={}B", ss.len())?;
        }
        Ok(())
    }
}

/// TLS signature algorithm (IANA SignatureScheme codepoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlgorithm {
    /// RSA PKCS#1 SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 SHA-512
    RsaPkcs1Sha512,
    /// ECDSA secp256r1 SHA-256
    EcdsaSecp256r1Sha256,
    /// ECDSA secp384r1 SHA-384
    EcdsaSecp384r1Sha384,
    /// ECDSA secp521r1 SHA-512
    EcdsaSecp521r1Sha512,
    /// RSA-PSS PSS-SHA256
    RsaPssRsaeSha256,
    /// RSA-PSS PSS-SHA384
    RsaPssRsaeSha384,
    /// RSA-PSS PSS-SHA512
    RsaPssRsaeSha512,
    /// Ed25519
    Ed25519,
    /// Ed448
    Ed448,
    /// ML-DSA-44 (Dilithium-3)
    MlDsa44,
    /// ML-DSA-65 (Dilithium-5)
    MlDsa65,
    /// ML-DSA-87 (Dilithium-5 high)
    MlDsa87,
    /// SLH-DSA-SHA2-128s (SPHINCS+)
    SlhDsaSha2128s,
    /// SLH-DSA-SHAKE-128s (SPHINCS+)
    SlhDsaShake128s,
    /// Falcon-512
    Falcon512,
    /// Falcon-1024
    Falcon1024,
    /// Unrecognized signature algorithm.
    Unknown(u16),
}

impl SigAlgorithm {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0401 => SigAlgorithm::RsaPkcs1Sha256,
            0x0501 => SigAlgorithm::RsaPkcs1Sha384,
            0x0601 => SigAlgorithm::RsaPkcs1Sha512,
            0x0403 => SigAlgorithm::EcdsaSecp256r1Sha256,
            0x0503 => SigAlgorithm::EcdsaSecp384r1Sha384,
            0x0603 => SigAlgorithm::EcdsaSecp521r1Sha512,
            0x0804 => SigAlgorithm::RsaPssRsaeSha256,
            0x0805 => SigAlgorithm::RsaPssRsaeSha384,
            0x0806 => SigAlgorithm::RsaPssRsaeSha512,
            0x0807 => SigAlgorithm::Ed25519,
            0x0808 => SigAlgorithm::Ed448,
            0x0700 => SigAlgorithm::MlDsa44,
            0x0701 => SigAlgorithm::MlDsa65,
            0x0702 => SigAlgorithm::MlDsa87,
            0x0706 => SigAlgorithm::SlhDsaSha2128s,
            0x0707 => SigAlgorithm::SlhDsaShake128s,
            0x0703 => SigAlgorithm::Falcon512,
            0x0704 => SigAlgorithm::Falcon1024,
            x => SigAlgorithm::Unknown(x),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            SigAlgorithm::RsaPkcs1Sha256 => 0x0401,
            SigAlgorithm::RsaPkcs1Sha384 => 0x0501,
            SigAlgorithm::RsaPkcs1Sha512 => 0x0601,
            SigAlgorithm::EcdsaSecp256r1Sha256 => 0x0403,
            SigAlgorithm::EcdsaSecp384r1Sha384 => 0x0503,
            SigAlgorithm::EcdsaSecp521r1Sha512 => 0x0603,
            SigAlgorithm::RsaPssRsaeSha256 => 0x0804,
            SigAlgorithm::RsaPssRsaeSha384 => 0x0805,
            SigAlgorithm::RsaPssRsaeSha512 => 0x0806,
            SigAlgorithm::Ed25519 => 0x0807,
            SigAlgorithm::Ed448 => 0x0808,
            SigAlgorithm::MlDsa44 => 0x0700,
            SigAlgorithm::MlDsa65 => 0x0701,
            SigAlgorithm::MlDsa87 => 0x0702,
            SigAlgorithm::SlhDsaSha2128s => 0x0706,
            SigAlgorithm::SlhDsaShake128s => 0x0707,
            SigAlgorithm::Falcon512 => 0x0703,
            SigAlgorithm::Falcon1024 => 0x0704,
            SigAlgorithm::Unknown(v) => *v,
        }
    }

    pub fn is_pqc(&self) -> bool {
        matches!(self,
            SigAlgorithm::MlDsa44 | SigAlgorithm::MlDsa65
            | SigAlgorithm::MlDsa87 | SigAlgorithm::SlhDsaSha2128s
            | SigAlgorithm::SlhDsaShake128s | SigAlgorithm::Falcon512
            | SigAlgorithm::Falcon1024
        )
    }
}

impl std::fmt::Display for SigAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigAlgorithm::RsaPkcs1Sha256 => write!(f, "RSA-PKCS1-SHA256"),
            SigAlgorithm::RsaPkcs1Sha384 => write!(f, "RSA-PKCS1-SHA384"),
            SigAlgorithm::RsaPkcs1Sha512 => write!(f, "RSA-PKCS1-SHA512"),
            SigAlgorithm::EcdsaSecp256r1Sha256 => write!(f, "ECDSA-SECP256R1-SHA256"),
            SigAlgorithm::EcdsaSecp384r1Sha384 => write!(f, "ECDSA-SECP384R1-SHA384"),
            SigAlgorithm::EcdsaSecp521r1Sha512 => write!(f, "ECDSA-SECP521R1-SHA512"),
            SigAlgorithm::RsaPssRsaeSha256 => write!(f, "RSA-PSS-SHA256"),
            SigAlgorithm::RsaPssRsaeSha384 => write!(f, "RSA-PSS-SHA384"),
            SigAlgorithm::RsaPssRsaeSha512 => write!(f, "RSA-PSS-SHA512"),
            SigAlgorithm::Ed25519 => write!(f, "Ed25519"),
            SigAlgorithm::Ed448 => write!(f, "Ed448"),
            SigAlgorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            SigAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            SigAlgorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            SigAlgorithm::SlhDsaSha2128s => write!(f, "SLH-DSA-SHA2-128s"),
            SigAlgorithm::SlhDsaShake128s => write!(f, "SLH-DSA-SHAKE-128s"),
            SigAlgorithm::Falcon512 => write!(f, "Falcon-512"),
            SigAlgorithm::Falcon1024 => write!(f, "Falcon-1024"),
            SigAlgorithm::Unknown(v) => write!(f, "0x{v:04X}"),
        }
    }
}

/// Per-TLS-connection PQC handshake state record.
#[derive(Debug, Clone)]
pub struct PqcHandshakeRecord {
    // ── Handshake ──
    pub connection_5tuple: FiveTuple,
    pub tls_version: TlsVersion,
    pub server_name: String,

    // ── Key Exchange ──
    pub client_kem_offers: Vec<KemId>,
    pub server_kem_selected: Option<KemId>,
    pub is_hybrid_kem: bool,
    pub classical_group: Option<NamedGroup>,
    pub pqc_kem: Option<PqcKem>,
    pub shared_secret_size: u16,

    // ── Signature ──
    pub cert_sig_algorithm: SigAlgorithm,
    pub is_pqc_signature: bool,
    pub is_composite_cert: bool,
    pub cert_chain_pqc_count: u8,

    // ── Performance ──
    pub pqc_kem_time_us: u64,
    pub pqc_sig_verify_us: u64,
    pub total_handshake_ms: u32,
    pub pqc_overhead_ms: i32,
    pub pqc_packet_size_extra: u16,

    // ── Metadata ──
    pub timestamp: Timestamp,
    pub is_success: bool,
    pub pqc_fallback_reason: Option<String>,
}

impl PqcHandshakeRecord {
    /// Create a new handshake record with the minimum required fields.
    pub fn new(
        five_tuple: FiveTuple,
        tls_version: TlsVersion,
        server_name: String,
        cert_sig_algorithm: SigAlgorithm,
        timestamp: Timestamp,
    ) -> Self {
        PqcHandshakeRecord {
            connection_5tuple: five_tuple,
            tls_version,
            server_name,
            client_kem_offers: Vec::new(),
            server_kem_selected: None,
            is_hybrid_kem: false,
            classical_group: None,
            pqc_kem: None,
            shared_secret_size: 0,
            cert_sig_algorithm,
            is_pqc_signature: cert_sig_algorithm.is_pqc(),
            is_composite_cert: false,
            cert_chain_pqc_count: 0,
            pqc_kem_time_us: 0,
            pqc_sig_verify_us: 0,
            total_handshake_ms: 0,
            pqc_overhead_ms: 0,
            pqc_packet_size_extra: 0,
            timestamp,
            is_success: true,
            pqc_fallback_reason: None,
        }
    }

    /// Return `true` if this handshake used any PQC algorithm.
    pub fn used_pqc(&self) -> bool {
        self.is_hybrid_kem
            || self.is_pqc_signature
            || self.is_composite_cert
            || self.server_kem_selected.is_some()
            || self.pqc_kem.is_some()
    }
}

/// Simple in-memory store of PQC handshake records.
#[derive(Debug, Clone)]
pub struct PqcHandshakeStore {
    pub records: Vec<PqcHandshakeRecord>,
}

impl PqcHandshakeStore {
    pub fn new() -> Self {
        PqcHandshakeStore { records: Vec::new() }
    }

    pub fn push(&mut self, record: PqcHandshakeRecord) {
        self.records.push(record);
    }

    pub fn total_handshakes(&self) -> usize {
        self.records.len()
    }

    pub fn pqc_handshakes(&self) -> usize {
        self.records.iter().filter(|r| r.used_pqc()).count()
    }

    pub fn successful_handshakes(&self) -> usize {
        self.records.iter().filter(|r| r.is_success).count()
    }
}

impl Default for PqcHandshakeStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_five_tuple() -> FiveTuple {
        FiveTuple {
            src_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            src_port: 54321,
            dst_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
            dst_port: 443,
            protocol: 6,
        }
    }

    #[test]
    fn tls_version_from_u16() {
        assert_eq!(TlsVersion::from_u16(0x0303), TlsVersion::TlsV1_2);
        assert_eq!(TlsVersion::from_u16(0x0304), TlsVersion::TlsV1_3);
        assert_eq!(TlsVersion::from_u16(0x0305), TlsVersion::TlsV1_4);
        assert_eq!(TlsVersion::from_u16(0x0300), TlsVersion::Unknown(0x0300));
    }

    #[test]
    fn tls_version_display() {
        assert_eq!(TlsVersion::TlsV1_3.to_string(), "TLS 1.3");
        assert_eq!(TlsVersion::TlsV1_4.to_string(), "TLS 1.4");
        assert_eq!(TlsVersion::Unknown(0x0300).to_string(), "TLS 0x0300");
    }

    #[test]
    fn named_group_roundtrip() {
        let groups = [0x0017, 0x0018, 0x0019, 0x001D, 0x001E, 0x0100, 0x0101];
        for &g in &groups {
            let ng = NamedGroup::from_u16(g);
            assert_eq!(ng.as_u16(), g);
        }
    }

    #[test]
    fn named_group_classical_is_not_pqc() {
        assert!(!NamedGroup::X25519.is_pqc());
    }

    #[test]
    fn sig_algorithm_roundtrip() {
        let algs = [0x0401, 0x0403, 0x0804, 0x0807, 0x0700, 0x0701, 0x0706, 0x0703];
        for &a in &algs {
            let sa = SigAlgorithm::from_u16(a);
            assert_eq!(sa.as_u16(), a);
        }
    }

    #[test]
    fn sig_algorithm_is_pqc() {
        assert!(SigAlgorithm::MlDsa65.is_pqc());
        assert!(SigAlgorithm::Falcon512.is_pqc());
        assert!(!SigAlgorithm::Ed25519.is_pqc());
        assert!(!SigAlgorithm::RsaPkcs1Sha256.is_pqc());
    }

    #[test]
    fn pqc_kem_display_includes_ct() {
        let kem = PqcKem {
            algorithm: KemId::MlKem768,
            public_key: None,
            ciphertext: Some(vec![0u8; 1088]),
            shared_secret: Some(vec![0u8; 32]),
        };
        let s = kem.to_string();
        assert!(s.contains("ML-KEM-768"));
        assert!(s.contains("ct=1088B"));
    }

    #[test]
    fn handshake_record_new() {
        let ft = test_five_tuple();
        let rec = PqcHandshakeRecord::new(
            ft,
            TlsVersion::TlsV1_3,
            "example.com".into(),
            SigAlgorithm::MlDsa65,
            Utc::now(),
        );
        assert_eq!(rec.server_name, "example.com");
        assert!(rec.used_pqc());
        assert!(rec.is_success);
    }

    #[test]
    fn handshake_record_no_pqc() {
        let ft = test_five_tuple();
        let rec = PqcHandshakeRecord::new(
            ft,
            TlsVersion::TlsV1_2,
            "example.com".into(),
            SigAlgorithm::RsaPkcs1Sha256,
            Utc::now(),
        );
        assert!(!rec.used_pqc());
    }

    #[test]
    fn handshake_store_counts() {
        let mut store = PqcHandshakeStore::new();
        let ft = test_five_tuple();

        let pqc = PqcHandshakeRecord::new(
            ft.clone(), TlsVersion::TlsV1_3, "pqc.example".into(),
            SigAlgorithm::MlDsa87, Utc::now(),
        );
        store.push(pqc);

        let classic = PqcHandshakeRecord::new(
            ft, TlsVersion::TlsV1_2, "classic.example".into(),
            SigAlgorithm::RsaPkcs1Sha256, Utc::now(),
        );
        store.push(classic);

        assert_eq!(store.total_handshakes(), 2);
        assert_eq!(store.pqc_handshakes(), 1);
        assert_eq!(store.successful_handshakes(), 2);
    }

    #[test]
    fn kem_id_display() {
        assert_eq!(KemId::MlKem768.to_string(), "ML-KEM-768");
        assert_eq!(KemId::FrodoKem1344Aes.to_string(), "FrodoKEM-1344-AES");
        assert_eq!(KemId::ClassicMcEliece348864.to_string(), "Classic McEliece-348864");
        assert_eq!(KemId::Unknown(0x9999).to_string(), "KEM(0x9999)");
    }
}
