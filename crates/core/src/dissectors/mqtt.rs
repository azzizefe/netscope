use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect an MQTT message (TCP 1883).
///
/// MQTT is the dominant IoT messaging protocol: sensors and devices PUBLISH to
/// topics and SUBSCRIBE to them via a broker. The fixed header is one byte —
/// message type in the high nibble, flags in the low — followed by a
/// variable-length "remaining length". We name the message and, for the ones
/// that carry a readable field, surface it: the topic on a PUBLISH, the client
/// id on a CONNECT.
pub fn dissect_mqtt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mqtt,
        summary,
    };

    if payload.is_empty() {
        return result("MQTT (empty)".into());
    }

    let msg_type = payload[0] >> 4;
    // Skip the fixed header (1 byte) + the variable-length "remaining length"
    // field to reach the variable header / payload.
    let Some(var_off) = remaining_length_end(&payload[1..]).map(|n| 1 + n) else {
        return result(format!("MQTT {}", type_name(msg_type)));
    };
    let var = payload.get(var_off..).unwrap_or(&[]);

    let summary = match msg_type {
        3 => {
            // PUBLISH: variable header starts with the topic name (2-byte length
            // prefixed UTF-8).
            match utf8_field(var) {
                Some(topic) => format!("MQTT PUBLISH — {}", truncate(&topic, 60)),
                None => "MQTT PUBLISH".to_string(),
            }
        }
        1 => {
            // CONNECT: protocol name, level, flags, keep-alive, then client id.
            match connect_client_id(var) {
                Some(id) => format!("MQTT CONNECT — client {}", truncate(&id, 40)),
                None => "MQTT CONNECT".to_string(),
            }
        }
        _ => format!("MQTT {}", type_name(msg_type)),
    };

    result(summary)
}

/// Whether a TCP payload plausibly begins an MQTT packet: a valid message type
/// (1..=14) and a decodable remaining-length field. Used to accept MQTT on
/// relocated ports.
pub fn looks_like_mqtt(payload: &[u8]) -> bool {
    match payload.first() {
        Some(&b) => {
            let t = b >> 4;
            (1..=14).contains(&t) && remaining_length_end(&payload[1..]).is_some()
        }
        None => false,
    }
}

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",
        _ => "reserved",
    }
}

/// Decode the MQTT "remaining length" (1–4 bytes, 7 bits each, high bit is a
/// continuation flag). Returns how many bytes it occupied.
fn remaining_length_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        let b = *buf.get(i)?;
        i += 1;
        if b & 0x80 == 0 {
            return Some(i);
        }
        if i >= 4 {
            return None;
        }
    }
}

/// Read a 2-byte-length-prefixed UTF-8 field (topic, client id, …).
fn utf8_field(buf: &[u8]) -> Option<String> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let end = 2 + len;
    let bytes = buf.get(2..end)?;
    Some(String::from_utf8_lossy(bytes).to_string())
}

/// From a CONNECT variable header, skip protocol name + level + flags +
/// keep-alive to reach the client id (the first field of the CONNECT payload).
fn connect_client_id(var: &[u8]) -> Option<String> {
    // protocol name: 2-byte length + name
    if var.len() < 2 {
        return None;
    }
    let name_len = u16::from_be_bytes([var[0], var[1]]) as usize;
    // + 1 (protocol level) + 1 (connect flags) + 2 (keep-alive)
    let payload_off = 2 + name_len + 1 + 1 + 2;
    let client = var.get(payload_off..)?;
    let id = utf8_field(client)?;
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_with_topic() {
        // type 3 (PUBLISH) << 4, remaining length, then topic "sensors/temp".
        let topic = b"sensors/temp";
        let mut var = Vec::new();
        var.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        var.extend_from_slice(topic);
        var.extend_from_slice(&[0x00, 0x01]); // packet id
        var.extend_from_slice(b"21.5"); // message

        let mut p = vec![0x30];
        p.push(var.len() as u8); // remaining length (short form)
        p.extend_from_slice(&var);

        let r = dissect_mqtt(None, None, 50000, 1883, &p);
        assert_eq!(r.protocol, Protocol::Mqtt);
        assert_eq!(r.summary, "MQTT PUBLISH — sensors/temp");
    }

    #[test]
    fn connect_with_client_id() {
        let mut var = Vec::new();
        var.extend_from_slice(&4u16.to_be_bytes());
        var.extend_from_slice(b"MQTT"); // protocol name
        var.push(4); // protocol level
        var.push(2); // connect flags
        var.extend_from_slice(&60u16.to_be_bytes()); // keep-alive
        var.extend_from_slice(&8u16.to_be_bytes());
        var.extend_from_slice(b"device01"); // client id

        let mut p = vec![0x10];
        p.push(var.len() as u8);
        p.extend_from_slice(&var);

        let r = dissect_mqtt(None, None, 50000, 1883, &p);
        assert_eq!(r.summary, "MQTT CONNECT — client device01");
    }

    #[test]
    fn pingreq() {
        let p = vec![0xc0, 0x00];
        let r = dissect_mqtt(None, None, 1883, 50000, &p);
        assert_eq!(r.summary, "MQTT PINGREQ");
    }

    #[test]
    fn detection() {
        assert!(looks_like_mqtt(&[0x30, 0x0a]));
        assert!(!looks_like_mqtt(&[0x00, 0x00]));
    }
}
