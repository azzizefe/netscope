use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn gds_method(method: &str) -> &'static str {
    match method {
        "RegisterServer" => "RegisterServer",
        "FindServers" => "FindServers",
        "QueryServers" => "QueryServers",
        "GetCertificates" => "GetCertificates",
        "GetCertificateGroups" => "GetCertificateGroups",
        "GetTrustList" => "GetTrustList",
        "ApplyChanges" => "ApplyChanges",
        "PushCertificate" => "PushCertificate",
        "PullCertificate" => "PullCertificate",
        "CreateCertificateGroup" => "CreateCertificateGroup",
        "AddCertificate" => "AddCertificate",
        "RemoveCertificate" => "RemoveCertificate",
        "UpdateCertificate" => "UpdateCertificate",
        "CertificateExpired" => "CertificateExpired",
        "GetRejectedList" => "GetRejectedList",
        "StartSigningRequest" => "StartSigningRequest",
        "CertificateSigned" => "CertificateSigned",
        "GetCertificateStatus" => "GetCertificateStatus",
        "GetCertificateExpiry" => "GetCertificateExpiry",
        _ => "UnknownMethod",
    }
}

fn cert_group_type(type_id: u32) -> &'static str {
    match type_id {
        0 => "DefaultApplicationGroup",
        1 => "DefaultUserTokenGroup",
        2 => "DefaultHttpsGroup",
        3 => "DefaultUserTokenExternalGroup",
        4..=99 => "VendorGroup",
        _ => "Custom",
    }
}

fn cert_status(code: u32) -> &'static str {
    match code {
        0 => "Ok",
        1 => "Pending",
        2 => "Revoked",
        3 => "Expired",
        4 => "Rejected",
        5 => "Untrusted",
        _ => "Unknown",
    }
}

pub fn dissect_opc_ua_gds_cert_push(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaGdsCertPush, summary: s,
    };
    if payload.len() < 8 {
        return fallback("OPC UA GDS Cert Push (partial)".into());
    }
    let raw = String::from_utf8_lossy(payload);
    for method in ["PushCertificate", "PullCertificate", "RegisterServer", "FindServers", "GetTrustList", "GetCertificateGroups", "GetCertificates", "ApplyChanges", "GetRejectedList", "CertificateExpired", "AddCertificate", "RemoveCertificate", "UpdateCertificate"] {
        if raw.contains(method) {
            let method_name = gds_method(method);
            let group_hint = if raw.contains("DefaultApplicationGroup") { " appGroup" } else if raw.contains("DefaultUserTokenGroup") { " userTokenGroup" } else { "" };
            let push_mode = if raw.contains("push") || raw.contains("Push")  { " push" } else { "" };
            let pull_mode = if raw.contains("pull") || raw.contains("Pull") { " pull" } else { "" };
            return fallback(format!("OPC UA GDS Cert: {method_name}{group_hint}{push_mode}{pull_mode}"));
        }
    }
    fallback(format!("OPC UA GDS Cert Push ({})", super::bytes(payload.len() as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gds_cert_push() {
        let buf = b"PushCertificate:DefaultApplicationGroup:cert_data";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaGdsCertPush);
        assert!(r.summary.contains("PushCertificate"));
        assert!(r.summary.contains("appGroup"));
    }

    #[test]
    fn test_gds_cert_pull() {
        let buf = b"PullCertificate:DefaultUserTokenGroup:request";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("PullCertificate"));
        assert!(r.summary.contains("userTokenGroup"));
    }

    #[test]
    fn test_gds_register_server() {
        let buf = b"RegisterServer:uri=opc.tcp://gds.example.com";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("RegisterServer"));
    }

    #[test]
    fn test_gds_get_trust_list() {
        let buf = b"GetTrustList:DefaultApplicationGroup";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("GetTrustList"));
    }

    #[test]
    fn test_gds_get_certificate_groups() {
        let buf = b"GetCertificateGroups";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("GetCertificateGroups"));
    }

    #[test]
    fn test_gds_partial() {
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_gds_unknown() {
        let buf = b"some random data";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("bytes"));
    }

    #[test]
    fn test_gds_apply_changes() {
        let buf = b"ApplyChanges:DefaultApplicationGroup";
        let r = dissect_opc_ua_gds_cert_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("ApplyChanges"));
    }
}
