use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

const OPCUA_MSG_TYPES: &[(&[u8; 3], &str)] = &[
    (b"HEL", "Hello"),
    (b"ACK", "Acknowledge"),
    (b"ERR", "Error"),
    (b"RHE", "ReverseHello"),
    (b"OPN", "OpenSecureChannel"),
    (b"CLO", "CloseSecureChannel"),
    (b"MSG", "Message"),
];

fn msg_type_name(msg_type: &[u8]) -> Option<&'static str> {
    if msg_type.len() < 3 {
        return None;
    }
    let t: &[u8; 3] = &[msg_type[0], msg_type[1], msg_type[2]];
    OPCUA_MSG_TYPES.iter().find(|(k, _)| *k == t).map(|(_, n)| *n)
}

fn chunk_name(chunk: u8) -> &'static str {
    match chunk {
        b'F' => "final",
        b'C' => "intermediate",
        b'A' => "abort",
        _ => "unknown",
    }
}

fn security_mode(mode: u32) -> &'static str {
    match mode {
        0 => "Invalid",
        1 => "None",
        2 => "Sign",
        3 => "SignAndEncrypt",
        _ => "Unknown",
    }
}

fn security_policy_uri(payload: &[u8], offset: &mut usize) -> String {
    if *offset + 4 > payload.len() {
        return "?".into();
    }
    let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize;
    *offset += 4;
    if len == 0 || len == 0xFFFFFFFF {
        return "None".into();
    }
    if *offset + len > payload.len() {
        return "?".into();
    }
    let s = String::from_utf8_lossy(&payload[*offset..*offset + len]);
    *offset += len;

    if s.contains("http://opcfoundation.org/UA/security/policy/") {
        let name = s.trim_start_matches("http://opcfoundation.org/UA/security/policy/");
        name.to_string()
    } else if s.is_empty() {
        "None".into()
    } else {
        s.to_string()
    }
}

fn ua_string(payload: &[u8], offset: &mut usize) -> String {
    if *offset + 4 > payload.len() {
        return "?".into();
    }
    let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize;
    *offset += 4;
    if len == 0 || len == 0xFFFFFFFF {
        return String::new();
    }
    if *offset + len > payload.len() {
        return "?".into();
    }
    let s = String::from_utf8_lossy(&payload[*offset..*offset + len]).to_string();
    *offset += len;
    s
}

fn byte_string(payload: &[u8], offset: &mut usize) -> String {
    if *offset + 4 > payload.len() {
        return "?".into();
    }
    let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize;
    *offset += 4;
    if len == 0 || len == 0xFFFFFFFF {
        return "(empty)".into();
    }
    if *offset + len > payload.len() {
        return "?".into();
    }
    let hex_len = len.min(32);
    let hex: String = payload[*offset..*offset + hex_len].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    *offset += len;
    if len > 32 {
        format!("({}, start: {hex}...)", super::bytes(len as u64))
    } else {
        format!("({}: {hex})", super::bytes(len as u64))
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

fn service_id_name(type_id: u32) -> &'static str {
    match type_id {
        0 => "Unknown",
        429 => "FindServers",
        430 => "FindServersOnNetwork",
        431 => "GetEndpoints",
        432 => "RegisterServer",
        433 => "RegisterServer2",
        436 => "OpenSecureChannel",
        437 => "CloseSecureChannel",
        438 => "SessionActivate",
        439 => "CreateSession",
        440 => "CloseSession",
        441 => "Cancel",
        443 => "AddNodes",
        444 => "AddReferences",
        445 => "DeleteNodes",
        446 => "DeleteReferences",
        447 => "Browse",
        448 => "BrowseNext",
        449 => "TranslateBrowsePathsToNodeIds",
        450 => "RegisterNodes",
        451 => "UnregisterNodes",
        452 => "QueryFirst",
        453 => "QueryNext",
        454 => "Read",
        455 => "Write",
        456 => "HistoryRead",
        457 => "HistoryUpdate",
        458 => "Call",
        459 => "CreateMonitoredItems",
        460 => "ModifyMonitoredItems",
        461 => "SetMonitoringMode",
        462 => "SetTriggering",
        463 => "DeleteMonitoredItems",
        464 => "CreateSubscription",
        465 => "ModifySubscription",
        466 => "SetPublishingMode",
        467 => "Publish",
        468 => "Republish",
        469 => "TransferSubscriptions",
        470 => "DeleteSubscriptions",
        471 => "AddPubSubConnection",
        472 => "SetPublishedDataSet",
        473 => "RemovePublishedDataSet",
        474 => "AddDataSetFolder",
        475 => "RemoveDataSetFolder",
        476 => "AddDataSetWriter",
        477 => "RemoveDataSetWriter",
        478 => "SetWriterGroup",
        479 => "RemoveWriterGroup",
        480 => "AddReaderGroup",
        481 => "RemoveReaderGroup",
        482 => "ModifyReaderGroup",
        483 => "SetReaderGroup",
        484 => "RemoveReaderGroup",
        485 => "ConfigureDataSetReader",
        486 => "DataSetReaderMessage",
        487 => "ModifyDataSetReader",
        488 => "RemoveDataSetReader",
        489 => "AddDataSetFolder",
        490 => "RemoveDataSetFolder",
        491 => "AddPublishedDataItems",
        492 => "RemovePublishedDataItems",
        493 => "AddPublishedEvents",
        494 => "RemovePublishedEvents",
        495 => "SetSubscription",
        496 => "ModifySubscription",
        497 => "SetPublishingMode",
        498 => "Publish",
        499 => "Republish",
        500 => "TransferSubscriptions",
        501 => "DeleteSubscriptions",
        502 => "DeleteMonitoredItems",
        503 => "CreateSubscription",
        504 => "ModifySubscription",
        505 => "SetPublishingMode",
        506 => "Publish",
        507 => "Republish",
        508 => "TransferSubscriptions",
        509 => "DeleteSubscriptions",
        510 => "AddPubSubConnection",
        511 => "RemovePubSubConnection",
        512 => "SetPublishedDataSet",
        513 => "RemovePublishedDataSet",
        514 => "AddDataSetFolder",
        515 => "RemoveDataSetFolder",
        516 => "AddDataSetWriter",
        517 => "RemoveDataSetWriter",
        518 => "SetWriterGroup",
        519 => "RemoveWriterGroup",
        520 => "AddReaderGroup",
        521 => "RemoveReaderGroup",
        522 => "ModifyReaderGroup",
        523 => "SetReaderGroup",
        524 => "RemoveReaderGroup",
        525 => "ConfigureDataSetReader",
        526 => "DataSetReaderMessage",
        527 => "ModifyDataSetReader",
        528 => "RemoveDataSetReader",
        529 => "AddPublishedDataItems",
        530 => "RemovePublishedDataItems",
        531 => "AddPublishedEvents",
        532 => "RemovePublishedEvents",
        533 => "HistoryUpdate",
        534 => "TransferResult",
        535 => "QueryFirst",
        536 => "QueryNext",
        537 => "ReadRawModified",
        538 => "ReadProcessed",
        539 => "ReadAtTime",
        540 => "HistoryRead",
        541 => "HistoryUpdate",
        542 => "CreateSession",
        _ => "Unknown",
    }
}

fn parse_opcua_header(payload: &[u8]) -> Option<(&'static str, &'static str, u32, &'static str)> {
    if payload.len() < 8 {
        return None;
    }
    let msg_name = msg_type_name(&payload[0..3])?;
    let ck = chunk_name(payload[3]);
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let full_name = match payload[3] {
        b'C' => "Intermediate",
        b'A' => "Abort",
        _ => "",
    };
    Some((msg_name, ck, size, full_name))
}

fn dissect_hello(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 20 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let proto_ver = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let send_buf = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let recv_buf = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    let max_msg = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    let max_chunk = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
    let mut off = 20;
    let endpoint = ua_string(body, &mut off);
    if endpoint.is_empty() || endpoint == "?" {
        format!("OPC UA {msg_name} v{proto_ver} buffers={send_buf}/{recv_buf} max_msg={max_msg} max_chunks={max_chunk}")
    } else {
        format!("OPC UA {msg_name} v{proto_ver} endpoint=\"{endpoint}\" buffers={send_buf}/{recv_buf}")
    }
}

fn dissect_acknowledge(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 20 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let proto_ver = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let send_buf = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let recv_buf = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    let max_msg = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    let max_chunk = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
    format!("OPC UA {msg_name} v{proto_ver} buffers={send_buf}/{recv_buf} max_msg={max_msg} max_chunks={max_chunk}")
}

fn dissect_error(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 4 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let code = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let code_name = status_code_name(code);
    let mut off = 4;
    let reason = ua_string(body, &mut off);
    if reason.is_empty() || reason == "?" {
        format!("OPC UA {msg_name} {code_name} (0x{code:08X})")
    } else {
        format!("OPC UA {msg_name} {code_name}: \"{reason}\"")
    }
}

fn dissect_open_secure_channel(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 8 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let channel_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let token_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let mut off = 8;
    if channel_id == 0 && off + 20 <= body.len() {
        let policy = security_policy_uri(body, &mut off);
        if off >= body.len() {
            return format!("OPC UA {msg_name} channel=0 token={token_id} policy={policy}");
        }
        let _cert = byte_string(body, &mut off);
        if off >= body.len() {
            return format!("OPC UA {msg_name} channel=0 token={token_id} policy={policy}");
        }
        let _thumbprint = byte_string(body, &mut off);
        if off + 16 > body.len() {
            return format!("OPC UA {msg_name} channel=0 token={token_id} policy={policy}");
        }
        let req_type = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
        let req_name = match req_type { 0 => "Issue", 1 => "Renew", _ => "?" };
        off += 4;
        if off + 4 > body.len() {
            return format!("OPC UA {msg_name} channel=0 token={token_id} policy={policy} {req_name}");
        }
        let sec_mode = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
        off += 4;
        let _nonce = byte_string(body, &mut off);
        if off + 4 > body.len() {
            return format!("OPC UA {msg_name} {req_name} mode={} policy={policy}", security_mode(sec_mode));
        }
        let lifetime = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
        format!("OPC UA {msg_name} {req_name} mode={} policy={policy} lifetime={lifetime}ms", security_mode(sec_mode))
    } else {
        format!("OPC UA {msg_name} channel={channel_id} token={token_id}")
    }
}

fn dissect_close_secure_channel(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 4 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let channel_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    format!("OPC UA {msg_name} channel={channel_id}")
}

fn dissect_message(payload: &[u8], msg_name: &str) -> String {
    if payload.len() < 8 {
        return format!("OPC UA {msg_name} (partial)");
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 8 {
        return format!("OPC UA {msg_name} (partial body)");
    }
    let channel_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let token_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    if body.len() < 12 {
        return format!("OPC UA {msg_name} channel={channel_id} token={token_id}");
    }
    let _ = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    if body.len() < 16 {
        return format!("OPC UA {msg_name} channel={channel_id} token={token_id}");
    }
    let request_id = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    if body.len() < 20 {
        return format!("OPC UA {msg_name} channel={channel_id} request={request_id}");
    }
    let type_id_bytes = &body[16..body.len().min(body.len())];
    if type_id_bytes.is_empty() {
        return format!("OPC UA {msg_name} channel={channel_id} token={token_id} request={request_id}");
    }
    let enc_mask = type_id_bytes[0];
    let service_hint = match enc_mask {
        0x01 => "TwoByte",
        0x02 => "FourByte",
        _ => "?",
    };
    let sid = if type_id_bytes.len() >= 4 {
        u32::from_le_bytes([type_id_bytes[1], type_id_bytes[2], type_id_bytes[3], type_id_bytes.get(4).copied().unwrap_or(0)]) % 1000
    } else { 0 };
    let service_name = service_id_name(sid);
    format!("OPC UA {msg_name} channel={channel_id} token={token_id} request={request_id} service={service_name}({service_hint})")
}

pub fn dissect_opc_ua_dpi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaDpi, summary: s,
    };

    if payload.len() < 8 {
        return fallback("OPC UA DPI (partial)".into());
    }

    let msg_type = &payload[0..3];
    let msg_name = match msg_type_name(msg_type) {
        Some(n) => n,
        None => return fallback("OPC UA DPI (unrecognized)".into()),
    };

    let summary = match msg_type {
        b"HEL" => dissect_hello(payload, msg_name),
        b"ACK" => dissect_acknowledge(payload, msg_name),
        b"ERR" => dissect_error(payload, msg_name),
        b"RHE" => format!("OPC UA {msg_name} (needs parsing)"),
        b"OPN" => dissect_open_secure_channel(payload, msg_name),
        b"CLO" => dissect_close_secure_channel(payload, msg_name),
        b"MSG" => dissect_message(payload, msg_name),
        _ => format!("OPC UA DPI {msg_name}"),
    };

    DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaDpi, summary,
    }
}

pub fn dissect_opc_ua_secure_conv(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaSecureConv, summary: s,
    };

    if payload.len() < 8 {
        return fallback("OPC UA SecureConversation (partial)".into());
    }

    if let Some((msg_name, _ck, size, _full)) = parse_opcua_header(payload) {
        let body = &payload[8..payload.len().min(size as usize)];
        if msg_name == "OpenSecureChannel" || msg_name == "Message" || msg_name == "CloseSecureChannel" {
            if body.len() >= 8 {
                let channel_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let token_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                let seq_info = if body.len() >= 16 {
                    let seq_num = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
                    let req_id = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
                    format!(" seq={seq_num} req={req_id}")
                } else {
                    String::new()
                };
                return fallback(format!("OPC UA SecureConversation {msg_name} channel={channel_id} token={token_id}{seq_info} ({size} bytes)"));
            }
        }
        return fallback(format!("OPC UA SecureConversation {msg_name} ({size} bytes)"));
    }
    fallback("OPC UA SecureConversation (unrecognized)".into())
}

pub fn looks_like_opcua_dpi(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let valid_chunk = matches!(payload[3], b'F' | b'C' | b'A');
    if !valid_chunk {
        return false;
    }
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if size < 8 || size > payload.len() + 65536 {
        return false;
    }
    matches!(&payload[0..3], b"HEL" | b"ACK" | b"ERR" | b"RHE" | b"OPN" | b"CLO" | b"MSG")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(msg_type: &[u8; 3], chunk: u8, body: &[u8]) -> Vec<u8> {
        let total_len = 8 + body.len();
        let mut p = Vec::with_capacity(total_len);
        p.extend_from_slice(msg_type);
        p.push(chunk);
        p.extend_from_slice(&(total_len as u32).to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    fn make_hello(endpoint: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let endpoint_bytes = endpoint.as_bytes();
        body.extend_from_slice(&(endpoint_bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(endpoint_bytes);
        make_msg(b"HEL", b'F', &body)
    }

    fn make_ack() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        make_msg(b"ACK", b'F', &body)
    }

    fn make_error(code: u32, reason: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&code.to_le_bytes());
        let r = reason.as_bytes();
        body.extend_from_slice(&(r.len() as u32).to_le_bytes());
        body.extend_from_slice(r);
        make_msg(b"ERR", b'F', &body)
    }

    fn make_opn_isuee(policy: &str, mode: u32, lifetime: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        let policy_bytes = policy.as_bytes();
        body.extend_from_slice(&(policy_bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(policy_bytes);
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&mode.to_le_bytes());
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&lifetime.to_le_bytes());
        make_msg(b"OPN", b'F', &body)
    }

    fn make_clo(channel_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&channel_id.to_le_bytes());
        make_msg(b"CLO", b'F', &body)
    }

    fn make_msg_frame(channel_id: u32, token_id: u32, seq_num: u32, req_id: u32, service_hint: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&channel_id.to_le_bytes());
        body.extend_from_slice(&token_id.to_le_bytes());
        body.extend_from_slice(&seq_num.to_le_bytes());
        body.extend_from_slice(&req_id.to_le_bytes());
        body.push(service_hint);
        body.push(0x01);
        body.extend_from_slice(&0u32.to_le_bytes());
        make_msg(b"MSG", b'F', &body)
    }

    #[test]
    fn test_dpi_hello() {
        let p = make_hello("opc.tcp://localhost:4840");
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert_eq!(r.protocol, Protocol::OpcUaDpi);
        assert!(r.summary.contains("Hello"));
        assert!(r.summary.contains("endpoint"));
    }

    #[test]
    fn test_dpi_acknowledge() {
        let p = make_ack();
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Acknowledge"));
        assert!(r.summary.contains("v0"));
        assert!(r.summary.contains("65536"));
    }

    #[test]
    fn test_dpi_error() {
        let p = make_error(0x80000000, "BadUnexpectedError");
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Error"));
        assert!(r.summary.contains("BadUnexpectedError"));
    }

    #[test]
    fn test_dpi_open_secure_channel() {
        let p = make_opn_isuee("http://opcfoundation.org/UA/security/policy/None", 1, 3600000);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("OpenSecureChannel"));
        assert!(r.summary.contains("Issue"));
    }

    #[test]
    fn test_dpi_open_secure_channel_renew() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&(b"http://opcfoundation.org/UA/security/policy/Basic256Sha256".len() as u32).to_le_bytes());
        body.extend_from_slice(b"http://opcfoundation.org/UA/security/policy/Basic256Sha256");
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        body.extend_from_slice(&3600000u32.to_le_bytes());
        let p = make_msg(b"OPN", b'F', &body);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("OpenSecureChannel"));
        assert!(r.summary.contains("Renew"));
        assert!(r.summary.contains("SignAndEncrypt"));
    }

    #[test]
    fn test_dpi_close_secure_channel() {
        let p = make_clo(5);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("CloseSecureChannel"));
        assert!(r.summary.contains("channel=5"));
    }

    #[test]
    fn test_dpi_message_service_call() {
        let p = make_msg_frame(1, 100, 1, 42, 0x02);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Message"));
        assert!(r.summary.contains("channel=1"));
        assert!(r.summary.contains("request=42"));
    }

    #[test]
    fn test_dpi_hello_with_endpoint_url() {
        let p = make_hello("opc.tcp://machine:4840/UA/Server");
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("machine"));
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_dpi_error_with_unknown_code() {
        let p = make_error(0xDEADBEEF, "");
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Error"));
        assert!(r.summary.contains("0xDEADBEEF"));
    }

    #[test]
    fn test_dpi_secure_conversation_open() {
        let body: Vec<u8> = [1u32, 100u32, 1u32, 42u32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let p = make_msg(b"OPN", b'F', &body);
        let r = dissect_opc_ua_secure_conv(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("SecureConversation"));
        assert!(r.summary.contains("channel=1"));
    }

    #[test]
    fn test_dpi_secure_conversation_msg() {
        let body: Vec<u8> = [2u32, 200u32, 5u32, 99u32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let p = make_msg(b"MSG", b'F', &body);
        let r = dissect_opc_ua_secure_conv(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("SecureConversation"));
        assert!(r.summary.contains("channel=2"));
        assert!(r.summary.contains("token=200"));
        assert!(r.summary.contains("seq=5"));
    }

    #[test]
    fn test_dpi_partial() {
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_dpi_unrecognized() {
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, b"GET / HTTP/1.1");
        assert!(r.summary.contains("unrecognized"));
    }

    #[test]
    fn test_dpi_looks_like() {
        assert!(looks_like_opcua_dpi(&make_hello("opc.tcp://host")));
        assert!(looks_like_opcua_dpi(&make_clo(1)));
        assert!(!looks_like_opcua_dpi(b""));
        assert!(!looks_like_opcua_dpi(b"GET /"));
    }

    #[test]
    fn test_dpi_secure_conv_partial() {
        let r = dissect_opc_ua_secure_conv(None, None, 50000, 4840, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_dpi_secure_conv_unrecognized() {
        let r = dissect_opc_ua_secure_conv(None, None, 50000, 4840, b"\x00\x01\x02\x03\x04\x05\x06\x07");
        assert!(r.summary.contains("unrecognized"));
    }

    #[test]
    fn test_dpi_hello_variant() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&8192u32.to_le_bytes());
        body.extend_from_slice(&8192u32.to_le_bytes());
        body.extend_from_slice(&4194304u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let endpoint = b"opc.tcp://plc01:4840";
        body.extend_from_slice(&(endpoint.len() as u32).to_le_bytes());
        body.extend_from_slice(endpoint);
        let p = make_msg(b"HEL", b'F', &body);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("v1"));
        assert!(r.summary.contains("8192"));
        assert!(r.summary.contains("plc01"));
    }

    #[test]
    fn test_dpi_intermediate_chunk() {
        let p = make_msg(b"MSG", b'C', &[0u8; 8]);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Message"));
    }

    #[test]
    fn test_dpi_security_policy_basic256() {
        let policy = "http://opcfoundation.org/UA/security/policy/Basic256Sha256";
        let p = make_opn_isuee(policy, 3, 600000);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Basic256Sha256"));
        assert!(r.summary.contains("SignAndEncrypt"));
    }

    #[test]
    fn test_dpi_security_policy_aes128() {
        let policy = "http://opcfoundation.org/UA/security/policy/Aes128Sha256RsaOaep";
        let p = make_opn_isuee(policy, 3, 600000);
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Aes128Sha256RsaOaep"));
    }

    #[test]
    fn test_dpi_empty_endpoint() {
        let p = make_hello("");
        let r = dissect_opc_ua_dpi(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_dpi_secure_conv_close() {
        let body: Vec<u8> = [3u32, 4u32]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let p = make_msg(b"CLO", b'F', &body);
        let r = dissect_opc_ua_secure_conv(None, None, 50000, 4840, &p);
        assert!(r.summary.contains("channel=3"));
    }
}
