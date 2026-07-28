use std::net::IpAddr;

use crate::models::Protocol;
use crate::pqc_handshake::PqcHandshakeStore;
use crate::pqc_wizard::{ComplianceFramework, Tls13PqcWizard};

use super::DissectedResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{PqcHandshakeRecord, SigAlgorithm, TlsVersion};
    use chrono::Utc;

    fn test_ft() -> FiveTuple {
        FiveTuple {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 54321,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            protocol: 6,
        }
    }

    #[test]
    fn compliance_framework_label_nist() {
        assert_eq!(
            ComplianceFramework::NistSp800131a.label(),
            "NIST SP 800-131A"
        );
    }

    #[test]
    fn compliance_framework_label_bsi() {
        assert_eq!(ComplianceFramework::BsiTr02102.label(), "BSI TR-02102");
    }

    #[test]
    fn compliance_framework_label_anssi() {
        assert_eq!(ComplianceFramework::AnssiPqc.label(), "ANSSI PQC");
    }

    #[test]
    fn compliance_framework_label_cnsa() {
        assert_eq!(ComplianceFramework::Cnsa2.label(), "NSA CNSA 2.0");
    }

    #[test]
    fn compliance_framework_label_etsi() {
        assert_eq!(ComplianceFramework::EtsiTs119312.label(), "ETSI TS 119 312");
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_pqc_compliance_checker(None, None, 0, 0, &[]);
        assert_eq!(result.protocol, Protocol::PqcComplianceChecker);
        assert!(result.summary.contains("compliant"));
    }

    #[test]
    fn dissect_with_records() {
        crate::dissectors::tls::clear_tls_sessions();
        let ft = test_ft();
        let r = PqcHandshakeRecord::new(
            ft,
            TlsVersion::TlsV1_3,
            "example.com".into(),
            SigAlgorithm::MlDsa65,
            Utc::now(),
        );
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_pqc_compliance_checker(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("compliant"));
    }
}

pub fn dissect_pqc_compliance_checker(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();
    let mut store = PqcHandshakeStore::new();
    for r in records {
        store.push(r);
    }

    let report = Tls13PqcWizard::analyze(&store);
    let compliant_count = report.compliance.iter().filter(|c| c.compliant).count();
    let non_compliant_count = report.compliance.len() - compliant_count;

    let frameworks: Vec<String> = report
        .compliance
        .iter()
        .map(|c| {
            let status = if c.compliant { "✅" } else { "⚠️" };
            format!("{} {} — {}", status, c.framework.label(), c.note)
        })
        .collect();

    let summary = format!(
        "PQC Compliance Checker: {}/{} compliant ({} non-compliant) — {}",
        compliant_count,
        report.compliance.len(),
        non_compliant_count,
        frameworks.join("; "),
    );
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PqcComplianceChecker,
        summary,
    }
}

impl ComplianceFramework {
    fn label(&self) -> &'static str {
        match self {
            ComplianceFramework::NistSp800131a => "NIST SP 800-131A",
            ComplianceFramework::BsiTr02102 => "BSI TR-02102",
            ComplianceFramework::AnssiPqc => "ANSSI PQC",
            ComplianceFramework::Cnsa2 => "NSA CNSA 2.0",
            ComplianceFramework::EtsiTs119312 => "ETSI TS 119 312",
        }
    }
}
