use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_sentencepiece_proto(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "SentencePiece Proto (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SentencePiece") && raw.contains("piece") || raw.contains("sp_model") {
            let end = raw.len().min(80);
            format!("SentencePiece Proto: {}", &raw[..end])
        } else if raw.contains("normalizer_rule") || raw.contains("byte_fallback") {
            let end = raw.len().min(80);
            format!("SentencePiece Proto: {}", &raw[..end])
        } else {
            format!("SentencePiece Proto ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SentencepieceProto,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentencepiece_proto_model() {
        let buf = b"model {\"SentencePiece\":true,\"piece\":[{\"piece\":\"hello\"}]}";
        let r = dissect_sentencepiece_proto(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SentencepieceProto);
        assert!(r.summary.contains("SentencePiece"));
    }

    #[test]
    fn test_sentencepiece_proto_malformed() {
        let buf = b"tiny";
        let r = dissect_sentencepiece_proto(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
