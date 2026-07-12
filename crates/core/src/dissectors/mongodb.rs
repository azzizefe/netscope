use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a MongoDB wire-protocol message (TCP 27017).
///
/// Every message begins with a 16-byte header, all little-endian: messageLength
/// (Int32, counting the header), requestID, responseTo, and opCode. Modern
/// drivers use OP_MSG (2013) almost exclusively; OP_QUERY (2004) and OP_REPLY
/// (1) are the legacy pair, and OP_COMPRESSED (2012) wraps a compressed body.
/// We name the opcode and, for OP_MSG/OP_QUERY, try to surface the command or
/// collection.
pub fn dissect_mongodb(
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
        protocol: Protocol::Mongodb,
        summary,
    };

    if payload.len() < 16 {
        return result("MongoDB (partial)".into());
    }

    let opcode = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let summary = match opcode {
        1 => "MongoDB OP_REPLY".to_string(),
        2004 => match op_query_collection(&payload[16..]) {
            Some(coll) => format!("MongoDB OP_QUERY — {coll}"),
            None => "MongoDB OP_QUERY".to_string(),
        },
        2012 => "MongoDB OP_COMPRESSED".to_string(),
        2013 => match op_msg_command(&payload[16..]) {
            Some(cmd) => format!("MongoDB OP_MSG — {cmd}"),
            None => "MongoDB OP_MSG".to_string(),
        },
        other => format!("MongoDB opcode {other}"),
    };

    result(summary)
}

/// OP_QUERY body: flags(Int32) + fullCollectionName (C-string). Return the
/// collection name.
fn op_query_collection(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let name = &body[4..];
    let end = memchr::memchr(0, name)?;
    let coll = String::from_utf8_lossy(&name[..end]).to_string();
    if coll.is_empty() {
        None
    } else {
        Some(coll)
    }
}

/// OP_MSG body: flagBits(Int32) + section(s). Section kind 0 carries a single
/// BSON document; the first element name of a command document is the command
/// verb (e.g. "find", "insert", "hello"). Peek it without a full BSON parse.
fn op_msg_command(body: &[u8]) -> Option<String> {
    if body.len() < 4 + 1 + 4 + 1 {
        return None;
    }
    // Skip flagBits(4). Expect a kind-0 section.
    if body[4] != 0 {
        return None;
    }
    // BSON doc starts at offset 5: length(Int32), then first element:
    // type(1) + key(C-string). The key of the first element is the command.
    let doc = &body[5..];
    let elem = &doc[4..]; // skip doc length
    if elem.is_empty() {
        return None;
    }
    let key = &elem[1..]; // skip element type byte
    let end = memchr::memchr(0, key)?;
    let verb = String::from_utf8_lossy(&key[..end]).to_string();
    if verb.is_empty() || !verb.chars().all(|c| c.is_ascii_graphic()) {
        None
    } else {
        Some(verb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(opcode: u32, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        let len = (16 + body.len()) as u32;
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes()); // requestID
        p.extend_from_slice(&0u32.to_le_bytes()); // responseTo
        p.extend_from_slice(&opcode.to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn op_msg_find() {
        // flagBits(0) + section kind 0 + BSON { "find": ... }
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flagBits
        body.push(0); // section kind 0
                      // BSON doc: length + type(0x02 string) + "find\0" + rest
        let mut doc = Vec::new();
        doc.push(0x02);
        doc.extend_from_slice(b"find\0");
        doc.extend_from_slice(b"\x05\x00\x00\x00test\0"); // string value (approx)
        doc.push(0x00); // doc terminator
        let mut full = Vec::new();
        full.extend_from_slice(&((doc.len() + 4) as u32).to_le_bytes());
        full.extend_from_slice(&doc);
        body.extend_from_slice(&full);

        let p = header(2013, &body);
        let r = dissect_mongodb(None, None, 50000, 27017, &p);
        assert_eq!(r.protocol, Protocol::Mongodb);
        assert_eq!(r.summary, "MongoDB OP_MSG — find");
    }

    #[test]
    fn op_query_collection_name() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.extend_from_slice(b"testdb.$cmd\0");
        let p = header(2004, &body);
        let r = dissect_mongodb(None, None, 50000, 27017, &p);
        assert_eq!(r.summary, "MongoDB OP_QUERY — testdb.$cmd");
    }

    #[test]
    fn partial_is_safe() {
        let r = dissect_mongodb(None, None, 27017, 50000, &[0, 1, 2]);
        assert!(r.summary.contains("partial"));
    }
}
