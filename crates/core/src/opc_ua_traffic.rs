use std::fmt;

/// OPC UA fully-qualified NodeId string (e.g. "ns=2;s=Temperature").
pub type NodeIdStr = String;

/// OPC UA security policy URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityPolicy {
    None,
    Basic128Rsa15,
    Basic256,
    Basic256Sha256,
    Aes128Sha256RsaOaep,
    Aes256Sha256RsaPss,
    Other(String),
}

impl SecurityPolicy {
    pub fn from_uri(uri: &str) -> Self {
        let name = uri
            .trim_start_matches("http://opcfoundation.org/UA/security/policy/")
            .trim_start_matches("http://opcfoundation.org/UA/SecurityPolicy#");
        match name {
            "None" => SecurityPolicy::None,
            "Basic128Rsa15" => SecurityPolicy::Basic128Rsa15,
            "Basic256" => SecurityPolicy::Basic256,
            "Basic256Sha256" => SecurityPolicy::Basic256Sha256,
            "Aes128_Sha256_RsaOaep" | "Aes128Sha256RsaOaep" => SecurityPolicy::Aes128Sha256RsaOaep,
            "Aes256_Sha256_RsaPss" | "Aes256Sha256RsaPss" => SecurityPolicy::Aes256Sha256RsaPss,
            _ => SecurityPolicy::Other(uri.to_string()),
        }
    }

    pub fn as_uri(&self) -> &str {
        match self {
            SecurityPolicy::None => "http://opcfoundation.org/UA/security/policy/None",
            SecurityPolicy::Basic128Rsa15 => "http://opcfoundation.org/UA/security/policy/Basic128Rsa15",
            SecurityPolicy::Basic256 => "http://opcfoundation.org/UA/security/policy/Basic256",
            SecurityPolicy::Basic256Sha256 => "http://opcfoundation.org/UA/security/policy/Basic256Sha256",
            SecurityPolicy::Aes128Sha256RsaOaep => "http://opcfoundation.org/UA/security/policy/Aes128_Sha256_RsaOaep",
            SecurityPolicy::Aes256Sha256RsaPss => "http://opcfoundation.org/UA/security/policy/Aes256_Sha256_RsaPss",
            SecurityPolicy::Other(s) => s,
        }
    }
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityPolicy::None => write!(f, "None"),
            SecurityPolicy::Basic128Rsa15 => write!(f, "Basic128Rsa15"),
            SecurityPolicy::Basic256 => write!(f, "Basic256"),
            SecurityPolicy::Basic256Sha256 => write!(f, "Basic256Sha256"),
            SecurityPolicy::Aes128Sha256RsaOaep => write!(f, "Aes128-Sha256-RsaOaep"),
            SecurityPolicy::Aes256Sha256RsaPss => write!(f, "Aes256-Sha256-RsaPss"),
            SecurityPolicy::Other(s) => write!(f, "{s}"),
        }
    }
}

/// OPC UA message security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityMode {
    Invalid,
    None,
    Sign,
    SignAndEncrypt,
}

impl SecurityMode {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => SecurityMode::Invalid,
            1 => SecurityMode::None,
            2 => SecurityMode::Sign,
            3 => SecurityMode::SignAndEncrypt,
            _ => SecurityMode::Invalid,
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            SecurityMode::Invalid => 0,
            SecurityMode::None => 1,
            SecurityMode::Sign => 2,
            SecurityMode::SignAndEncrypt => 3,
        }
    }
}

impl fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityMode::Invalid => write!(f, "Invalid"),
            SecurityMode::None => write!(f, "None"),
            SecurityMode::Sign => write!(f, "Sign"),
            SecurityMode::SignAndEncrypt => write!(f, "SignAndEncrypt"),
        }
    }
}

/// OPC UA user identity token type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserTokenType {
    Anonymous,
    UserName,
    X509,
    IssuedToken,
    Other(u32),
}

impl UserTokenType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => UserTokenType::Anonymous,
            1 => UserTokenType::UserName,
            2 => UserTokenType::X509,
            3 => UserTokenType::IssuedToken,
            _ => UserTokenType::Other(v),
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            UserTokenType::Anonymous => 0,
            UserTokenType::UserName => 1,
            UserTokenType::X509 => 2,
            UserTokenType::IssuedToken => 3,
            UserTokenType::Other(v) => *v,
        }
    }
}

impl fmt::Display for UserTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserTokenType::Anonymous => write!(f, "Anonymous"),
            UserTokenType::UserName => write!(f, "UserName"),
            UserTokenType::X509 => write!(f, "X509"),
            UserTokenType::IssuedToken => write!(f, "IssuedToken"),
            UserTokenType::Other(v) => write!(f, "Other({v})"),
        }
    }
}

/// OPC UA service type (type-id mapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    FindServers,
    FindServersOnNetwork,
    GetEndpoints,
    RegisterServer,
    RegisterServer2,
    OpenSecureChannel,
    CloseSecureChannel,
    SessionActivate,
    CreateSession,
    CloseSession,
    Cancel,
    AddNodes,
    AddReferences,
    DeleteNodes,
    DeleteReferences,
    Browse,
    BrowseNext,
    TranslateBrowsePathsToNodeIds,
    RegisterNodes,
    UnregisterNodes,
    QueryFirst,
    QueryNext,
    Read,
    Write,
    HistoryRead,
    HistoryUpdate,
    Call,
    CreateMonitoredItems,
    ModifyMonitoredItems,
    SetMonitoringMode,
    SetTriggering,
    DeleteMonitoredItems,
    CreateSubscription,
    ModifySubscription,
    SetPublishingMode,
    Publish,
    Republish,
    TransferSubscriptions,
    DeleteSubscriptions,
    AddPubSubConnection,
    RemovePubSubConnection,
    SetPublishedDataSet,
    RemovePublishedDataSet,
    AddDataSetFolder,
    RemoveDataSetFolder,
    AddDataSetWriter,
    RemoveDataSetWriter,
    SetWriterGroup,
    RemoveWriterGroup,
    AddReaderGroup,
    RemoveReaderGroup,
    ModifyReaderGroup,
    SetReaderGroup,
    ConfigureDataSetReader,
    DataSetReaderMessage,
    ModifyDataSetReader,
    RemoveDataSetReader,
    AddPublishedDataItems,
    RemovePublishedDataItems,
    AddPublishedEvents,
    RemovePublishedEvents,
    TransferResult,
    ReadRawModified,
    ReadProcessed,
    ReadAtTime,
    Other(u32),
}

impl ServiceType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            429 => ServiceType::FindServers,
            430 => ServiceType::FindServersOnNetwork,
            431 => ServiceType::GetEndpoints,
            432 => ServiceType::RegisterServer,
            433 => ServiceType::RegisterServer2,
            436 => ServiceType::OpenSecureChannel,
            437 => ServiceType::CloseSecureChannel,
            438 => ServiceType::SessionActivate,
            439 => ServiceType::CreateSession,
            440 => ServiceType::CloseSession,
            441 => ServiceType::Cancel,
            443 => ServiceType::AddNodes,
            444 => ServiceType::AddReferences,
            445 => ServiceType::DeleteNodes,
            446 => ServiceType::DeleteReferences,
            447 => ServiceType::Browse,
            448 => ServiceType::BrowseNext,
            449 => ServiceType::TranslateBrowsePathsToNodeIds,
            450 => ServiceType::RegisterNodes,
            451 => ServiceType::UnregisterNodes,
            452 => ServiceType::QueryFirst,
            453 => ServiceType::QueryNext,
            454 => ServiceType::Read,
            455 => ServiceType::Write,
            456 => ServiceType::HistoryRead,
            457 => ServiceType::HistoryUpdate,
            458 => ServiceType::Call,
            459 => ServiceType::CreateMonitoredItems,
            460 => ServiceType::ModifyMonitoredItems,
            461 => ServiceType::SetMonitoringMode,
            462 => ServiceType::SetTriggering,
            463 => ServiceType::DeleteMonitoredItems,
            464 => ServiceType::CreateSubscription,
            465 => ServiceType::ModifySubscription,
            466 => ServiceType::SetPublishingMode,
            467 => ServiceType::Publish,
            468 => ServiceType::Republish,
            469 => ServiceType::TransferSubscriptions,
            470 => ServiceType::DeleteSubscriptions,
            471 => ServiceType::AddPubSubConnection,
            472 => ServiceType::SetPublishedDataSet,
            473 => ServiceType::RemovePublishedDataSet,
            474 => ServiceType::AddDataSetFolder,
            475 => ServiceType::RemoveDataSetFolder,
            476 => ServiceType::AddDataSetWriter,
            477 => ServiceType::RemoveDataSetWriter,
            478 => ServiceType::SetWriterGroup,
            479 => ServiceType::RemoveWriterGroup,
            480 => ServiceType::AddReaderGroup,
            481 => ServiceType::RemoveReaderGroup,
            482 => ServiceType::ModifyReaderGroup,
            483 => ServiceType::SetReaderGroup,
            485 => ServiceType::ConfigureDataSetReader,
            486 => ServiceType::DataSetReaderMessage,
            487 => ServiceType::ModifyDataSetReader,
            488 => ServiceType::RemoveDataSetReader,
            491 => ServiceType::AddPublishedDataItems,
            492 => ServiceType::RemovePublishedDataItems,
            493 => ServiceType::AddPublishedEvents,
            494 => ServiceType::RemovePublishedEvents,
            534 => ServiceType::TransferResult,
            537 => ServiceType::ReadRawModified,
            538 => ServiceType::ReadProcessed,
            539 => ServiceType::ReadAtTime,
            511 => ServiceType::RemovePubSubConnection,
            _ => ServiceType::Other(v),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            ServiceType::FindServers => 429,
            ServiceType::FindServersOnNetwork => 430,
            ServiceType::GetEndpoints => 431,
            ServiceType::RegisterServer => 432,
            ServiceType::RegisterServer2 => 433,
            ServiceType::OpenSecureChannel => 436,
            ServiceType::CloseSecureChannel => 437,
            ServiceType::SessionActivate => 438,
            ServiceType::CreateSession => 439,
            ServiceType::CloseSession => 440,
            ServiceType::Cancel => 441,
            ServiceType::AddNodes => 443,
            ServiceType::AddReferences => 444,
            ServiceType::DeleteNodes => 445,
            ServiceType::DeleteReferences => 446,
            ServiceType::Browse => 447,
            ServiceType::BrowseNext => 448,
            ServiceType::TranslateBrowsePathsToNodeIds => 449,
            ServiceType::RegisterNodes => 450,
            ServiceType::UnregisterNodes => 451,
            ServiceType::QueryFirst => 452,
            ServiceType::QueryNext => 453,
            ServiceType::Read => 454,
            ServiceType::Write => 455,
            ServiceType::HistoryRead => 456,
            ServiceType::HistoryUpdate => 457,
            ServiceType::Call => 458,
            ServiceType::CreateMonitoredItems => 459,
            ServiceType::ModifyMonitoredItems => 460,
            ServiceType::SetMonitoringMode => 461,
            ServiceType::SetTriggering => 462,
            ServiceType::DeleteMonitoredItems => 463,
            ServiceType::CreateSubscription => 464,
            ServiceType::ModifySubscription => 465,
            ServiceType::SetPublishingMode => 466,
            ServiceType::Publish => 467,
            ServiceType::Republish => 468,
            ServiceType::TransferSubscriptions => 469,
            ServiceType::DeleteSubscriptions => 470,
            ServiceType::AddPubSubConnection => 471,
            ServiceType::RemovePubSubConnection => 511,
            ServiceType::SetPublishedDataSet => 472,
            ServiceType::RemovePublishedDataSet => 473,
            ServiceType::AddDataSetFolder => 474,
            ServiceType::RemoveDataSetFolder => 475,
            ServiceType::AddDataSetWriter => 476,
            ServiceType::RemoveDataSetWriter => 477,
            ServiceType::SetWriterGroup => 478,
            ServiceType::RemoveWriterGroup => 479,
            ServiceType::AddReaderGroup => 480,
            ServiceType::RemoveReaderGroup => 481,
            ServiceType::ModifyReaderGroup => 482,
            ServiceType::SetReaderGroup => 483,
            ServiceType::ConfigureDataSetReader => 485,
            ServiceType::DataSetReaderMessage => 486,
            ServiceType::ModifyDataSetReader => 487,
            ServiceType::RemoveDataSetReader => 488,
            ServiceType::AddPublishedDataItems => 491,
            ServiceType::RemovePublishedDataItems => 492,
            ServiceType::AddPublishedEvents => 493,
            ServiceType::RemovePublishedEvents => 494,
            ServiceType::TransferResult => 534,
            ServiceType::ReadRawModified => 537,
            ServiceType::ReadProcessed => 538,
            ServiceType::ReadAtTime => 539,
            ServiceType::Other(v) => v,
        }
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceType::FindServers => write!(f, "FindServers"),
            ServiceType::FindServersOnNetwork => write!(f, "FindServersOnNetwork"),
            ServiceType::GetEndpoints => write!(f, "GetEndpoints"),
            ServiceType::RegisterServer => write!(f, "RegisterServer"),
            ServiceType::RegisterServer2 => write!(f, "RegisterServer2"),
            ServiceType::OpenSecureChannel => write!(f, "OpenSecureChannel"),
            ServiceType::CloseSecureChannel => write!(f, "CloseSecureChannel"),
            ServiceType::SessionActivate => write!(f, "SessionActivate"),
            ServiceType::CreateSession => write!(f, "CreateSession"),
            ServiceType::CloseSession => write!(f, "CloseSession"),
            ServiceType::Cancel => write!(f, "Cancel"),
            ServiceType::AddNodes => write!(f, "AddNodes"),
            ServiceType::AddReferences => write!(f, "AddReferences"),
            ServiceType::DeleteNodes => write!(f, "DeleteNodes"),
            ServiceType::DeleteReferences => write!(f, "DeleteReferences"),
            ServiceType::Browse => write!(f, "Browse"),
            ServiceType::BrowseNext => write!(f, "BrowseNext"),
            ServiceType::TranslateBrowsePathsToNodeIds => write!(f, "TranslateBrowsePathsToNodeIds"),
            ServiceType::RegisterNodes => write!(f, "RegisterNodes"),
            ServiceType::UnregisterNodes => write!(f, "UnregisterNodes"),
            ServiceType::QueryFirst => write!(f, "QueryFirst"),
            ServiceType::QueryNext => write!(f, "QueryNext"),
            ServiceType::Read => write!(f, "Read"),
            ServiceType::Write => write!(f, "Write"),
            ServiceType::HistoryRead => write!(f, "HistoryRead"),
            ServiceType::HistoryUpdate => write!(f, "HistoryUpdate"),
            ServiceType::Call => write!(f, "Call"),
            ServiceType::CreateMonitoredItems => write!(f, "CreateMonitoredItems"),
            ServiceType::ModifyMonitoredItems => write!(f, "ModifyMonitoredItems"),
            ServiceType::SetMonitoringMode => write!(f, "SetMonitoringMode"),
            ServiceType::SetTriggering => write!(f, "SetTriggering"),
            ServiceType::DeleteMonitoredItems => write!(f, "DeleteMonitoredItems"),
            ServiceType::CreateSubscription => write!(f, "CreateSubscription"),
            ServiceType::ModifySubscription => write!(f, "ModifySubscription"),
            ServiceType::SetPublishingMode => write!(f, "SetPublishingMode"),
            ServiceType::Publish => write!(f, "Publish"),
            ServiceType::Republish => write!(f, "Republish"),
            ServiceType::TransferSubscriptions => write!(f, "TransferSubscriptions"),
            ServiceType::DeleteSubscriptions => write!(f, "DeleteSubscriptions"),
            ServiceType::AddPubSubConnection => write!(f, "AddPubSubConnection"),
            ServiceType::RemovePubSubConnection => write!(f, "RemovePubSubConnection"),
            ServiceType::SetPublishedDataSet => write!(f, "SetPublishedDataSet"),
            ServiceType::RemovePublishedDataSet => write!(f, "RemovePublishedDataSet"),
            ServiceType::AddDataSetFolder => write!(f, "AddDataSetFolder"),
            ServiceType::RemoveDataSetFolder => write!(f, "RemoveDataSetFolder"),
            ServiceType::AddDataSetWriter => write!(f, "AddDataSetWriter"),
            ServiceType::RemoveDataSetWriter => write!(f, "RemoveDataSetWriter"),
            ServiceType::SetWriterGroup => write!(f, "SetWriterGroup"),
            ServiceType::RemoveWriterGroup => write!(f, "RemoveWriterGroup"),
            ServiceType::AddReaderGroup => write!(f, "AddReaderGroup"),
            ServiceType::RemoveReaderGroup => write!(f, "RemoveReaderGroup"),
            ServiceType::ModifyReaderGroup => write!(f, "ModifyReaderGroup"),
            ServiceType::SetReaderGroup => write!(f, "SetReaderGroup"),
            ServiceType::ConfigureDataSetReader => write!(f, "ConfigureDataSetReader"),
            ServiceType::DataSetReaderMessage => write!(f, "DataSetReaderMessage"),
            ServiceType::ModifyDataSetReader => write!(f, "ModifyDataSetReader"),
            ServiceType::RemoveDataSetReader => write!(f, "RemoveDataSetReader"),
            ServiceType::AddPublishedDataItems => write!(f, "AddPublishedDataItems"),
            ServiceType::RemovePublishedDataItems => write!(f, "RemovePublishedDataItems"),
            ServiceType::AddPublishedEvents => write!(f, "AddPublishedEvents"),
            ServiceType::RemovePublishedEvents => write!(f, "RemovePublishedEvents"),
            ServiceType::TransferResult => write!(f, "TransferResult"),
            ServiceType::ReadRawModified => write!(f, "ReadRawModified"),
            ServiceType::ReadProcessed => write!(f, "ReadProcessed"),
            ServiceType::ReadAtTime => write!(f, "ReadAtTime"),
            ServiceType::Other(v) => write!(f, "Other({v})"),
        }
    }
}

/// OPC UA deep packet inspection record.
#[derive(Debug, Clone)]
pub struct OpcUaTrafficRecord {
    // ── Session ──
    pub session_id: u32,
    pub auth_token_id: u32,
    pub secure_channel_id: u32,
    pub endpoint_url: String,
    pub security_policy: SecurityPolicy,
    pub security_mode: SecurityMode,
    pub user_identity: UserTokenType,

    // ── Service Call ──
    pub service_type: ServiceType,
    pub request_handle: u32,
    pub status_code: u32,
    pub service_timing_us: u64,

    // ── Node / Data ──
    pub node_id_count: u16,
    pub node_id_list: Vec<NodeIdStr>,
    pub total_value_bytes: u32,
    pub data_type_count: u8,

    // ── PubSub ──
    pub pubsub_ds_group_id: Option<u16>,
    pub pubsub_writer_id: Option<u16>,
    pub pubsub_field_count: Option<u16>,
    pub pubsub_sequence: Option<u32>,
    pub pubsub_qos: Option<u8>,

    // ── Security Events ──
    pub is_bad_certificate: bool,
    pub is_security_violation: bool,
    pub is_access_denied: bool,
    pub is_subscription_late: bool,
}

impl OpcUaTrafficRecord {
    pub fn new() -> Self {
        OpcUaTrafficRecord {
            session_id: 0,
            auth_token_id: 0,
            secure_channel_id: 0,
            endpoint_url: String::new(),
            security_policy: SecurityPolicy::None,
            security_mode: SecurityMode::None,
            user_identity: UserTokenType::Anonymous,
            service_type: ServiceType::Other(0),
            request_handle: 0,
            status_code: 0,
            service_timing_us: 0,
            node_id_count: 0,
            node_id_list: Vec::new(),
            total_value_bytes: 0,
            data_type_count: 0,
            pubsub_ds_group_id: None,
            pubsub_writer_id: None,
            pubsub_field_count: None,
            pubsub_sequence: None,
            pubsub_qos: None,
            is_bad_certificate: false,
            is_security_violation: false,
            is_access_denied: false,
            is_subscription_late: false,
        }
    }

    pub fn status_code_name(&self) -> &'static str {
        status_code_name(self.status_code)
    }
}

impl Default for OpcUaTrafficRecord {
    fn default() -> Self {
        Self::new()
    }
}

fn status_code_name(code: u32) -> &'static str {
    match code {
        0x00000000 => "Good",
        0x80000000 => "BadUnexpectedError",
        0x80010000 => "BadInternalError",
        0x80020000 => "BadOutOfMemory",
        0x80030000 => "BadInvalidArgument",
        0x80040000 => "BadTimeout",
        0x80050000 => "BadConnectionRejected",
        0x80060000 => "BadNotConnected",
        0x80070000 => "BadCommunicationError",
        0x80080000 => "BadSecureChannelIdInvalid",
        0x80090000 => "BadNoCommunication",
        0x800A0000 => "BadSecurityChecksFailed",
        0x800B0000 => "BadCertificateInvalid",
        0x800C0000 => "BadCertificateTimeInvalid",
        0x800D0000 => "BadCertificateRevocationUnknown",
        0x800E0000 => "BadCertificateIssuerRevocationUnknown",
        0x800F0000 => "BadCertificateRevoked",
        0x80100000 => "BadCertificateIssuerRevoked",
        0x80110000 => "BadUserAccessDenied",
        0x80120000 => "BadIdentityTokenInvalid",
        0x80130000 => "BadIdentityTokenRejected",
        0x80140000 => "BadSecureChannelTokenUnknown",
        0x80150000 => "BadRequestTooLarge",
        0x80160000 => "BadResponseTooLarge",
        0x80170000 => "BadNoSubscription",
        0x80180000 => "BadServiceUnsupported",
        0x80190000 => "BadShutdown",
        0x80200000 => "BadNotImplemented",
        0x80210000 => "BadLicenseExpired",
        _ => "Unknown",
    }
}

impl fmt::Display for OpcUaTrafficRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OPC UA session={} channel={} service={} status={} ({})",
            self.session_id,
            self.secure_channel_id,
            self.service_type,
            self.status_code_name(),
            self.endpoint_url,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_policy_from_uri() {
        assert_eq!(SecurityPolicy::from_uri("http://opcfoundation.org/UA/security/policy/None"), SecurityPolicy::None);
        assert_eq!(SecurityPolicy::from_uri("http://opcfoundation.org/UA/security/policy/Basic256Sha256"), SecurityPolicy::Basic256Sha256);
        assert_eq!(SecurityPolicy::from_uri("http://opcfoundation.org/UA/security/policy/Aes256_Sha256_RsaPss"), SecurityPolicy::Aes256Sha256RsaPss);
    }

    #[test]
    fn test_security_mode_roundtrip() {
        for mode in &[SecurityMode::Invalid, SecurityMode::None, SecurityMode::Sign, SecurityMode::SignAndEncrypt] {
            assert_eq!(SecurityMode::from_u32(mode.as_u32()), *mode);
        }
    }

    #[test]
    fn test_user_token_type_roundtrip() {
        let tokens = vec![
            UserTokenType::Anonymous,
            UserTokenType::UserName,
            UserTokenType::X509,
            UserTokenType::IssuedToken,
            UserTokenType::Other(99),
        ];
        for tok in tokens {
            assert_eq!(UserTokenType::from_u32(tok.as_u32()), tok);
        }
    }

    #[test]
    fn test_service_type_roundtrip() {
        let cases = &[
            (ServiceType::Read, 454u32),
            (ServiceType::Write, 455),
            (ServiceType::Browse, 447),
            (ServiceType::Call, 458),
            (ServiceType::Publish, 467),
            (ServiceType::CreateSubscription, 464),
            (ServiceType::Other(0), 0),
        ];
        for (expected, id) in cases {
            assert_eq!(ServiceType::from_u32(*id), *expected);
            assert_eq!(expected.as_u32(), *id);
        }
    }

    #[test]
    fn test_record_default() {
        let r = OpcUaTrafficRecord::new();
        assert_eq!(r.session_id, 0);
        assert!(r.node_id_list.is_empty());
        assert_eq!(r.security_policy, SecurityPolicy::None);
        assert_eq!(r.security_mode, SecurityMode::None);
        assert!(r.pubsub_ds_group_id.is_none());
        assert!(!r.is_bad_certificate);
    }

    #[test]
    fn test_record_display() {
        let r = OpcUaTrafficRecord {
            session_id: 42,
            secure_channel_id: 7,
            service_type: ServiceType::Read,
            status_code: 0x00000000,
            endpoint_url: "opc.tcp://server:4840".into(),
            ..OpcUaTrafficRecord::new()
        };
        let s = r.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("Read"));
        assert!(s.contains("Good"));
    }

    #[test]
    fn test_status_code_name() {
        assert_eq!(status_code_name(0x00000000), "Good");
        assert_eq!(status_code_name(0x80110000), "BadUserAccessDenied");
        assert_eq!(status_code_name(0xDEADBEEF), "Unknown");
    }

    #[test]
    fn test_security_policy_display() {
        assert_eq!(SecurityPolicy::None.to_string(), "None");
        assert_eq!(SecurityPolicy::Basic256Sha256.to_string(), "Basic256Sha256");
        assert_eq!(SecurityPolicy::Other("custom".into()).to_string(), "custom");
    }

    #[test]
    fn test_security_policy_as_uri() {
        assert!(SecurityPolicy::None.as_uri().contains("None"));
        assert!(SecurityPolicy::Basic256Sha256.as_uri().contains("Basic256Sha256"));
    }

    #[test]
    fn test_record_isolation() {
        let mut a = OpcUaTrafficRecord::new();
        a.session_id = 1;
        a.node_id_list.push("ns=2;s=Temperature".into());
        let b = OpcUaTrafficRecord::new();
        assert_eq!(b.session_id, 0);
        assert!(b.node_id_list.is_empty());
    }
}
