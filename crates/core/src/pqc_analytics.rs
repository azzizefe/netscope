use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::models::Protocol;

/// PQC algorithm family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcAlgorithm {
    Kyber1024,
    Dilithium5,
    SphincsPlus,
    FrodoKem,
    ClassicMcEliece,
    BikeL5,
    Hqc,
    HybridKem,
    WireguardPqHybrid,
    WireguardKyberPoly,
    IpsecIkev2Pq,
    IpsecIkev2Frodo,
    OpenvpnPqCipher,
    TailscalePqNoise,
    NebulaPqHandshake,
    X509Composite,
    AcmePq,
    MigrationSignal,
    SshPqcKex,
    DnssecPqcSigning,
    PqcCertTransparency,
    OqsProviderTelemetry,
    PqcHsmBridge,
    Unknown,
}

impl std::fmt::Display for PqcAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqcAlgorithm::Kyber1024 => write!(f, "ML-KEM-1024 (Kyber)"),
            PqcAlgorithm::Dilithium5 => write!(f, "ML-DSA-87 (Dilithium 5)"),
            PqcAlgorithm::SphincsPlus => write!(f, "SLH-DSA (SPHINCS+)"),
            PqcAlgorithm::FrodoKem => write!(f, "FrodoKEM-AES"),
            PqcAlgorithm::ClassicMcEliece => write!(f, "Classic McEliece"),
            PqcAlgorithm::BikeL5 => write!(f, "BIKE-L5"),
            PqcAlgorithm::Hqc => write!(f, "HQC"),
            PqcAlgorithm::HybridKem => write!(f, "Hybrid KEM (ECDH + PQC)"),
            PqcAlgorithm::WireguardPqHybrid => write!(f, "WireGuard PQ Hybrid"),
            PqcAlgorithm::WireguardKyberPoly => write!(f, "WireGuard Kyber + Poly1305"),
            PqcAlgorithm::IpsecIkev2Pq => write!(f, "IPsec IKEv2 PQ"),
            PqcAlgorithm::IpsecIkev2Frodo => write!(f, "IPsec IKEv2 + FrodoKEM"),
            PqcAlgorithm::OpenvpnPqCipher => write!(f, "OpenVPN PQ Cipher"),
            PqcAlgorithm::TailscalePqNoise => write!(f, "Tailscale PQ Noise"),
            PqcAlgorithm::NebulaPqHandshake => write!(f, "Nebula PQ Handshake"),
            PqcAlgorithm::X509Composite => write!(f, "X.509 Composite PQ"),
            PqcAlgorithm::AcmePq => write!(f, "ACME PQ Challenge"),
            PqcAlgorithm::MigrationSignal => write!(f, "PQC Migration Signal"),
            PqcAlgorithm::SshPqcKex => write!(f, "SSH PQC KEX (sntrup761)"),
            PqcAlgorithm::DnssecPqcSigning => write!(f, "DNSSEC PQC Signing"),
            PqcAlgorithm::PqcCertTransparency => write!(f, "PQC Cert Transparency"),
            PqcAlgorithm::OqsProviderTelemetry => write!(f, "OQS Provider Telemetry"),
            PqcAlgorithm::PqcHsmBridge => write!(f, "PQC HSM Bridge"),
            PqcAlgorithm::Unknown => write!(f, "Unknown PQC"),
        }
    }
}

/// Cryptographic category of the PQC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcCategory {
    /// Key Encapsulation Mechanism (KEM) — e.g., Kyber, FrodoKEM
    Kem,
    /// Digital Signature — e.g., Dilithium, SPHINCS+
    Signature,
    /// Hybrid KEM combining classical (ECDH) with PQC
    HybridKem,
    /// Key exchange mechanism (non-KEM, e.g., FIPS-compliant)
    KeyExchange,
    /// Certificate / PKI related
    Certificate,
    /// Authentication / handshake related
    Authentication,
}

/// NIST security level (1 = AES-128, 3 = AES-192, 5 = AES-256 equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcSecurityLevel {
    Level1,
    Level3,
    Level5,
    Unknown,
}

/// Per-observation PQC metadata extracted from a single packet.
#[derive(Debug, Clone, PartialEq)]
pub struct PqcObservation {
    /// Which PQC algorithm was observed.
    pub algorithm: PqcAlgorithm,
    /// Cryptographic category.
    pub category: PqcCategory,
    /// NIST security level.
    pub security_level: PqcSecurityLevel,
    /// Whether this is a hybrid (classical + PQC) construction.
    pub is_hybrid: bool,
    /// TLS version string if applicable (e.g., "1.3", "1.2").
    pub tls_version: Option<String>,
    /// KEM algorithm name (e.g., "ML-KEM-1024", "FrodoKEM-AES-640").
    pub kem_name: Option<String>,
    /// Signature algorithm name (e.g., "ML-DSA-87", "SLH-DSA").
    pub signature_name: Option<String>,
    /// Raw payload snippet for debugging.
    pub snippet: String,
}

/// Aggregated PQC adoption metrics for a single connection.
#[derive(Debug, Clone)]
pub struct PqcConnectionMetrics {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_pqc_packets: u64,
    pub algorithms_used: Vec<PqcAlgorithm>,
    pub is_hybrid: bool,
    pub tls_version: Option<String>,
}

/// Global PQC adoption tracker — aggregates observations across connections.
#[derive(Debug, Clone)]
pub struct PqcAdoptionTracker {
    /// Per-connection metrics keyed by `src:port->dst:port`.
    connections: HashMap<String, PqcConnectionMetrics>,
    /// Global algorithm frequency count.
    algorithm_counts: HashMap<PqcAlgorithm, u64>,
    /// Global protocol frequency count (which TLS/VPN protocol).
    protocol_counts: HashMap<String, u64>,
    /// Total PQC packets observed.
    total_pqc_packets: u64,
    /// Total connections tracked.
    total_connections: u64,
    /// Split: (hybrid_count, pure_pqc_count).
    hybrid_vs_pure: (u64, u64),
}

impl PqcAdoptionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            algorithm_counts: HashMap::new(),
            protocol_counts: HashMap::new(),
            total_pqc_packets: 0,
            total_connections: 0,
            hybrid_vs_pure: (0, 0),
        }
    }

    /// Record a PQC observation, updating both connection and global metrics.
    pub fn record(
        &mut self,
        obs: &PqcObservation,
        protocol: &Protocol,
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
    ) {
        self.total_pqc_packets += 1;
        *self.algorithm_counts.entry(obs.algorithm).or_insert(0) += 1;
        *self
            .protocol_counts
            .entry(format!("{protocol}"))
            .or_insert(0) += 1;

        let key = format!("{src}:{src_port}->{dst}:{dst_port}");
        let now = Utc::now();

        if obs.is_hybrid {
            self.hybrid_vs_pure.0 += 1;
        } else {
            self.hybrid_vs_pure.1 += 1;
        }

        let entry = self.connections.entry(key).or_insert_with(|| {
            self.total_connections += 1;
            PqcConnectionMetrics {
                src: src.to_string(),
                dst: dst.to_string(),
                src_port,
                dst_port,
                protocol: protocol.clone(),
                first_seen: now,
                last_seen: now,
                total_pqc_packets: 0,
                algorithms_used: Vec::new(),
                is_hybrid: obs.is_hybrid,
                tls_version: obs.tls_version.clone(),
            }
        });
        entry.last_seen = now;
        entry.total_pqc_packets += 1;
        if !entry.algorithms_used.contains(&obs.algorithm) {
            entry.algorithms_used.push(obs.algorithm);
        }
        if obs.is_hybrid {
            entry.is_hybrid = true;
        }
        if obs.tls_version.is_some() {
            entry.tls_version = obs.tls_version.clone();
        }
    }

    /// Fraction of connections using PQC (0.0 - 1.0).
    pub fn adoption_rate(&self) -> f64 {
        if self.total_connections == 0 {
            return 0.0;
        }
        self.connections.len() as f64 / self.total_connections as f64
    }

    /// Fraction of PQC packets that use hybrid (vs pure PQC) constructions.
    pub fn hybrid_ratio(&self) -> f64 {
        let total = self.hybrid_vs_pure.0 + self.hybrid_vs_pure.1;
        if total == 0 {
            return 0.0;
        }
        self.hybrid_vs_pure.0 as f64 / total as f64
    }

    /// Top N algorithms by frequency.
    pub fn top_algorithms(&self, n: usize) -> Vec<(PqcAlgorithm, u64)> {
        let mut counts: Vec<_> = self
            .algorithm_counts
            .iter()
            .map(|(a, c)| (*a, *c))
            .collect();
        counts.sort_by_key(|e| std::cmp::Reverse(e.1));
        counts.truncate(n);
        counts
    }

    /// Top N protocols by frequency.
    pub fn top_protocols(&self, n: usize) -> Vec<(String, u64)> {
        let mut counts: Vec<_> = self
            .protocol_counts
            .iter()
            .map(|(p, c)| (p.clone(), *c))
            .collect();
        counts.sort_by_key(|e| std::cmp::Reverse(e.1));
        counts.truncate(n);
        counts
    }

    /// Security level distribution: (level1, level3, level5, unknown).
    pub fn security_level_distribution(&self) -> (u64, u64, u64, u64) {
        let mut l1 = 0u64;
        let mut l3 = 0u64;
        let mut l5 = 0u64;
        let mut unk = 0u64;
        for (&alg, count) in &self.algorithm_counts {
            let c = *count;
            match alg.security_level() {
                PqcSecurityLevel::Level5 => l5 += c,
                PqcSecurityLevel::Level3 => l3 += c,
                PqcSecurityLevel::Level1 => l1 += c,
                PqcSecurityLevel::Unknown => unk += c,
            }
        }
        (l1, l3, l5, unk)
    }

    pub fn total_pqc_packets(&self) -> u64 {
        self.total_pqc_packets
    }
    pub fn total_connections(&self) -> u64 {
        self.total_connections
    }
    pub fn unique_connections(&self) -> usize {
        self.connections.len()
    }
    pub fn connections(&self) -> &HashMap<String, PqcConnectionMetrics> {
        &self.connections
    }
    pub fn algorithm_counts(&self) -> &HashMap<PqcAlgorithm, u64> {
        &self.algorithm_counts
    }

    /// Generate a summary report string.
    pub fn report(&self) -> String {
        let (l1, l3, l5, unk) = self.security_level_distribution();
        let top_algs: Vec<String> = self
            .top_algorithms(5)
            .iter()
            .map(|(a, c)| format!("  {a}: {c}"))
            .collect();
        format!(
            "PQC Adoption Report\n\
             ──────────────────\n\
             Total PQC packets:  {}\n\
             Unique connections: {}\n\
             Adoption rate:      {:.1}%\n\
             Hybrid ratio:       {:.1}%\n\
             Security levels:    L1={l1}  L3={l3}  L5={l5}  unknown={unk}\n\
             \nTop algorithms:\n{}\n",
            self.total_pqc_packets,
            self.unique_connections(),
            self.adoption_rate() * 100.0,
            self.hybrid_ratio() * 100.0,
            top_algs.join("\n"),
        )
    }
}

impl Default for PqcAdoptionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a Protocol variant to its PQC algorithm metadata.
pub fn classify_pqc(protocol: &Protocol) -> Option<PqcObservation> {
    let (algorithm, category, security_level, is_hybrid, tls_version) = match protocol {
        Protocol::TlsKyber1024 => (
            PqcAlgorithm::Kyber1024,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsDilithium5 => (
            PqcAlgorithm::Dilithium5,
            PqcCategory::Signature,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsSphincsPlus => (
            PqcAlgorithm::SphincsPlus,
            PqcCategory::Signature,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsFrodoKem => (
            PqcAlgorithm::FrodoKem,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsClassicMcEliece => (
            PqcAlgorithm::ClassicMcEliece,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsBikeL5 => (
            PqcAlgorithm::BikeL5,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsHqc => (
            PqcAlgorithm::Hqc,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsHybridKem => (
            PqcAlgorithm::HybridKem,
            PqcCategory::HybridKem,
            PqcSecurityLevel::Level5,
            true,
            Some("1.3".into()),
        ),
        Protocol::WireguardPqHybrid => (
            PqcAlgorithm::WireguardPqHybrid,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::WireguardKyberPoly => (
            PqcAlgorithm::WireguardKyberPoly,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            false,
            None,
        ),
        Protocol::IpsecIkev2Pq => (
            PqcAlgorithm::IpsecIkev2Pq,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level3,
            true,
            None,
        ),
        Protocol::IpsecIkev2Frodo => (
            PqcAlgorithm::IpsecIkev2Frodo,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            false,
            None,
        ),
        Protocol::OpenvpnPqCipher => (
            PqcAlgorithm::OpenvpnPqCipher,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level3,
            true,
            None,
        ),
        Protocol::TailscalePqNoise => (
            PqcAlgorithm::TailscalePqNoise,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            false,
            None,
        ),
        Protocol::NebulaPqHandshake => (
            PqcAlgorithm::NebulaPqHandshake,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        Protocol::X509CompositeCerts => (
            PqcAlgorithm::X509Composite,
            PqcCategory::Certificate,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::AcmePqChallenge => (
            PqcAlgorithm::AcmePq,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        // §8.1.1 — PQC Monitoring Tools
        Protocol::TlsPqcHandshakeExt => (
            PqcAlgorithm::HybridKem,
            PqcCategory::HybridKem,
            PqcSecurityLevel::Level5,
            true,
            Some("1.3".into()),
        ),
        Protocol::TlsPqcCertChain => (
            PqcAlgorithm::X509Composite,
            PqcCategory::Certificate,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::TlsPqcMigrationSignal => (
            PqcAlgorithm::MigrationSignal,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsPqcWizardScan => (
            PqcAlgorithm::HybridKem,
            PqcCategory::HybridKem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::TlsCertTransparencyV3 => (
            PqcAlgorithm::PqcCertTransparency,
            PqcCategory::Certificate,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::TlsEchPqcInterop => (
            PqcAlgorithm::HybridKem,
            PqcCategory::HybridKem,
            PqcSecurityLevel::Level5,
            true,
            Some("1.3".into()),
        ),
        Protocol::TlsKeySharePrediction => (
            PqcAlgorithm::HybridKem,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            true,
            Some("1.3".into()),
        ),
        Protocol::TlsDowngradeDetector => (
            PqcAlgorithm::MigrationSignal,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            Some("1.3".into()),
        ),
        Protocol::PqcCveFeedIntegration => (
            PqcAlgorithm::OqsProviderTelemetry,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        Protocol::TlsPerfBenchmarkModel => (
            PqcAlgorithm::HybridKem,
            PqcCategory::HybridKem,
            PqcSecurityLevel::Level5,
            true,
            Some("1.3".into()),
        ),
        Protocol::TlsMiddleboxDetector => (
            PqcAlgorithm::MigrationSignal,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        Protocol::PqcComplianceChecker => (
            PqcAlgorithm::X509Composite,
            PqcCategory::Certificate,
            PqcSecurityLevel::Level5,
            false,
            None,
        ),
        Protocol::TlsSessionResumptionPqc => (
            PqcAlgorithm::HybridKem,
            PqcCategory::Kem,
            PqcSecurityLevel::Level5,
            false,
            Some("1.3".into()),
        ),
        Protocol::Ikev2PqcDhGroup => (
            PqcAlgorithm::IpsecIkev2Pq,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level3,
            true,
            None,
        ),
        Protocol::WireguardPqcHandshake => (
            PqcAlgorithm::WireguardPqHybrid,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::SshPqcKex => (
            PqcAlgorithm::SshPqcKex,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::DnssecPqcSigning => (
            PqcAlgorithm::DnssecPqcSigning,
            PqcCategory::Signature,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        Protocol::PqcCertTransparency => (
            PqcAlgorithm::PqcCertTransparency,
            PqcCategory::Certificate,
            PqcSecurityLevel::Level5,
            true,
            None,
        ),
        Protocol::OqsProviderTelemetry => (
            PqcAlgorithm::OqsProviderTelemetry,
            PqcCategory::Authentication,
            PqcSecurityLevel::Level3,
            false,
            None,
        ),
        Protocol::PqcHsmBridge => (
            PqcAlgorithm::PqcHsmBridge,
            PqcCategory::KeyExchange,
            PqcSecurityLevel::Level5,
            false,
            None,
        ),
        _ => return None,
    };

    Some(PqcObservation {
        algorithm,
        category,
        security_level,
        is_hybrid,
        tls_version,
        kem_name: if matches!(category, PqcCategory::Kem | PqcCategory::HybridKem) {
            Some(algorithm.to_string())
        } else {
            None
        },
        signature_name: if matches!(category, PqcCategory::Signature) {
            Some(algorithm.to_string())
        } else {
            None
        },
        snippet: String::new(),
    })
}

impl PqcAlgorithm {
    pub fn security_level(&self) -> PqcSecurityLevel {
        use PqcSecurityLevel::*;
        match self {
            PqcAlgorithm::Kyber1024
            | PqcAlgorithm::Dilithium5
            | PqcAlgorithm::SphincsPlus
            | PqcAlgorithm::FrodoKem
            | PqcAlgorithm::ClassicMcEliece
            | PqcAlgorithm::BikeL5
            | PqcAlgorithm::Hqc
            | PqcAlgorithm::HybridKem
            | PqcAlgorithm::WireguardPqHybrid
            | PqcAlgorithm::WireguardKyberPoly
            | PqcAlgorithm::IpsecIkev2Frodo
            | PqcAlgorithm::TailscalePqNoise
            | PqcAlgorithm::X509Composite
            | PqcAlgorithm::PqcCertTransparency
            | PqcAlgorithm::PqcHsmBridge
            | PqcAlgorithm::SshPqcKex => Level5,
            PqcAlgorithm::IpsecIkev2Pq
            | PqcAlgorithm::OpenvpnPqCipher
            | PqcAlgorithm::NebulaPqHandshake
            | PqcAlgorithm::AcmePq
            | PqcAlgorithm::MigrationSignal
            | PqcAlgorithm::DnssecPqcSigning
            | PqcAlgorithm::OqsProviderTelemetry => Level3,
            PqcAlgorithm::Unknown => Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    #[test]
    fn classify_kyber() {
        let obs = classify_pqc(&Protocol::TlsKyber1024).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::Kyber1024);
        assert_eq!(obs.category, PqcCategory::Kem);
        assert_eq!(obs.security_level, PqcSecurityLevel::Level5);
        assert!(!obs.is_hybrid);
        assert_eq!(obs.tls_version, Some("1.3".into()));
    }

    #[test]
    fn classify_hybrid_kem() {
        let obs = classify_pqc(&Protocol::TlsHybridKem).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::HybridKem);
        assert!(obs.is_hybrid);
    }

    #[test]
    fn classify_dilithium() {
        let obs = classify_pqc(&Protocol::TlsDilithium5).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::Dilithium5);
        assert_eq!(obs.category, PqcCategory::Signature);
    }

    #[test]
    fn classify_wireguard() {
        let obs = classify_pqc(&Protocol::WireguardPqHybrid).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::WireguardPqHybrid);
        assert!(obs.is_hybrid);
    }

    #[test]
    fn classify_ipsec() {
        let obs = classify_pqc(&Protocol::IpsecIkev2Frodo).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::IpsecIkev2Frodo);
        assert_eq!(obs.category, PqcCategory::KeyExchange);
    }

    #[test]
    fn classify_non_pqc_returns_none() {
        assert!(classify_pqc(&Protocol::Tcp).is_none());
        assert!(classify_pqc(&Protocol::Dns).is_none());
        assert!(classify_pqc(&Protocol::Http).is_none());
    }

    #[test]
    fn classify_x509() {
        let obs = classify_pqc(&Protocol::X509CompositeCerts).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::X509Composite);
        assert_eq!(obs.category, PqcCategory::Certificate);
    }

    #[test]
    fn classify_acme() {
        let obs = classify_pqc(&Protocol::AcmePqChallenge).unwrap();
        assert_eq!(obs.algorithm, PqcAlgorithm::AcmePq);
    }

    #[test]
    fn tracker_records_observation() {
        let mut tracker = PqcAdoptionTracker::new();
        let obs = classify_pqc(&Protocol::TlsKyber1024).unwrap();
        tracker.record(
            &obs,
            &Protocol::TlsKyber1024,
            "10.0.0.1",
            "10.0.0.2",
            443,
            443,
        );
        assert_eq!(tracker.total_pqc_packets(), 1);
        assert_eq!(tracker.total_connections(), 1);
        assert_eq!(tracker.unique_connections(), 1);
    }

    #[test]
    fn tracker_adoption_rate() {
        let mut tracker = PqcAdoptionTracker::new();
        assert_eq!(tracker.adoption_rate(), 0.0);
        let obs = classify_pqc(&Protocol::TlsKyber1024).unwrap();
        tracker.record(
            &obs,
            &Protocol::TlsKyber1024,
            "10.0.0.1",
            "10.0.0.2",
            443,
            443,
        );
        assert_eq!(tracker.unique_connections(), 1);
    }

    #[test]
    fn tracker_top_algorithms() {
        let mut tracker = PqcAdoptionTracker::new();
        let k = classify_pqc(&Protocol::TlsKyber1024).unwrap();
        let d = classify_pqc(&Protocol::TlsDilithium5).unwrap();
        tracker.record(&k, &Protocol::TlsKyber1024, "a", "b", 443, 443);
        tracker.record(&k, &Protocol::TlsKyber1024, "a", "b", 443, 443);
        tracker.record(&d, &Protocol::TlsDilithium5, "c", "d", 443, 443);
        let top = tracker.top_algorithms(5);
        assert_eq!(top[0].0, PqcAlgorithm::Kyber1024);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn tracker_security_distribution_simple() {
        let mut tracker = PqcAdoptionTracker::new();
        let k = PqcObservation {
            algorithm: PqcAlgorithm::Kyber1024,
            category: PqcCategory::Kem,
            security_level: PqcSecurityLevel::Level5,
            is_hybrid: false,
            tls_version: Some("1.3".into()),
            kem_name: None,
            signature_name: None,
            snippet: String::new(),
        };
        assert_eq!(k.algorithm.security_level(), PqcSecurityLevel::Level5);
        tracker.record(&k, &Protocol::TlsKyber1024, "a", "b", 443, 443);
        assert_eq!(tracker.algorithm_counts().len(), 1);
        let (_l1, _l3, l5, _unk) = tracker.security_level_distribution();
        assert_eq!(l5, 1, "expected Kyber1024 to be Level5");
    }

    #[test]
    fn tracker_report_does_not_panic() {
        let tracker = PqcAdoptionTracker::new();
        let report = tracker.report();
        assert!(report.contains("PQC Adoption Report"));
    }

    #[test]
    fn security_level_method() {
        assert_eq!(
            PqcAlgorithm::Kyber1024.security_level(),
            PqcSecurityLevel::Level5
        );
        assert_eq!(
            PqcAlgorithm::IpsecIkev2Pq.security_level(),
            PqcSecurityLevel::Level3
        );
        assert_eq!(
            PqcAlgorithm::Unknown.security_level(),
            PqcSecurityLevel::Unknown
        );
    }
}
