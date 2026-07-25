use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_triton_model_repo_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Triton Model Repo Stream (malformed)".into()
    } else {
        let opcode = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let chunk_seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let op_name = match opcode {
            0x00000001 => "Upload",
            0x00000002 => "Download",
            0x00000003 => "List",
            0x00000004 => "Delete",
            _ => "Unknown",
        };
        let extra = if payload.len() > 8 {
            let raw = String::from_utf8_lossy(&payload[8..]);
            let end = raw.len().min(50);
            format!(" {}", &raw[..end])
        } else {
            String::new()
        };
        format!("Triton Model Repo Stream op={} seq={}{}", op_name, chunk_seq, extra)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TritonModelRepoStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triton_model_repo_stream_upload() {
        let data = b"model.bin";
        let mut buf = vec![0u8; 8 + data.len()];
        buf[..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[8..].copy_from_slice(data);
        let r = dissect_triton_model_repo_stream(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::TritonModelRepoStream);
        assert!(r.summary.contains("Upload"));
    }

    #[test]
    fn test_triton_model_repo_stream_malformed() {
        let buf = vec![0x00u8; 4];
        let r = dissect_triton_model_repo_stream(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
