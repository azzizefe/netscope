// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::{Packet, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedSession {
    pub client_to_server: Vec<u8>,
    pub server_to_client: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFile {
    pub filename: String,
    pub file_type: String,
    pub start_offset: usize,
    pub size: usize,
    pub metadata: HashMap<String, String>,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u32,
    pub summary: String,
}

// 1. Session Reconstruction
pub fn reconstruct_tcp_streams(packets: &[Packet]) -> HashMap<String, ReconstructedSession> {
    let mut client_flows: HashMap<String, BTreeMap<u32, Vec<u8>>> = HashMap::new();
    let mut server_flows: HashMap<String, BTreeMap<u32, Vec<u8>>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != Protocol::Tcp
            && pkt.protocol != Protocol::Http
            && pkt.protocol != Protocol::Tls
        {
            continue;
        }

        let ip_src = pkt.src_addr.map(|ip| ip.to_string()).unwrap_or_default();
        let ip_dst = pkt.dst_addr.map(|ip| ip.to_string()).unwrap_or_default();
        let port_src = pkt.src_port.unwrap_or(0);
        let port_dst = pkt.dst_port.unwrap_or(0);

        if ip_src.is_empty() || ip_dst.is_empty() {
            continue;
        }

        let mut seq = 0u32;
        let mut tcp_payload = pkt.data.to_vec();

        if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(&pkt.data) {
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport {
                seq = tcp.sequence_number();
                tcp_payload = tcp.payload().to_vec();
            }
        } else if let Ok(sliced) = etherparse::SlicedPacket::from_ip(&pkt.data) {
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport {
                seq = tcp.sequence_number();
                tcp_payload = tcp.payload().to_vec();
            }
        }

        if tcp_payload.is_empty() {
            continue;
        }

        let flow_key_forward = format!("{}:{}-{}:{}", ip_src, port_src, ip_dst, port_dst);
        let flow_key_reverse = format!("{}:{}-{}:{}", ip_dst, port_dst, ip_src, port_src);

        if client_flows.contains_key(&flow_key_forward)
            || (!client_flows.contains_key(&flow_key_reverse) && port_src > port_dst)
        {
            client_flows
                .entry(flow_key_forward)
                .or_default()
                .insert(seq, tcp_payload);
        } else {
            server_flows
                .entry(flow_key_reverse)
                .or_default()
                .insert(seq, tcp_payload);
        }
    }

    let mut sessions = HashMap::new();
    for (key, client_map) in client_flows {
        let mut client_to_server = Vec::new();
        for (_, bytes) in client_map {
            client_to_server.extend_from_slice(&bytes);
        }

        let mut server_to_client = Vec::new();
        if let Some(server_map) = server_flows.remove(&key) {
            for (_, bytes) in server_map {
                server_to_client.extend_from_slice(&bytes);
            }
        }

        sessions.insert(
            key,
            ReconstructedSession {
                client_to_server,
                server_to_client,
            },
        );
    }

    for (key, server_map) in server_flows {
        let mut server_to_client = Vec::new();
        for (_, bytes) in server_map {
            server_to_client.extend_from_slice(&bytes);
        }
        sessions.insert(
            key,
            ReconstructedSession {
                client_to_server: Vec::new(),
                server_to_client,
            },
        );
    }

    sessions
}

// 2. File Carving & Metadata Extraction
pub fn carve_files(data: &[u8]) -> Vec<CarvedFile> {
    let mut files = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        // JPEG: \xFF\xD8\xFF
        if idx + 3 <= data.len() && &data[idx..idx + 3] == b"\xFF\xD8\xFF" {
            let mut end_idx = data.len();
            for j in (idx + 3)..(data.len() - 1) {
                if &data[j..j + 2] == b"\xFF\xD9" {
                    end_idx = j + 2;
                    break;
                }
            }
            let size = end_idx - idx;
            if size > 10 && size <= 5_000_000 {
                let carved_data = data[idx..end_idx].to_vec();
                let mut metadata = HashMap::new();
                metadata.insert("Dimensions".to_string(), "Unknown (JPEG)".to_string());

                for k in 2..(carved_data.len() - 4) {
                    if &carved_data[k..k + 2] == b"\xFF\xFE" {
                        let len =
                            ((carved_data[k + 2] as usize) << 8) | (carved_data[k + 3] as usize);
                        if k + 4 + len - 2 <= carved_data.len() {
                            let comment_bytes = &carved_data[k + 4..k + 4 + len - 2];
                            if let Ok(comment) = String::from_utf8(comment_bytes.to_vec()) {
                                metadata.insert("Comment".to_string(), comment.trim().to_string());
                            }
                        }
                    }
                }

                files.push(CarvedFile {
                    filename: format!("carved_{}.jpg", idx),
                    file_type: "JPEG Image".to_string(),
                    start_offset: idx,
                    size,
                    metadata,
                    data: carved_data,
                });
                idx = end_idx;
                continue;
            }
        }

        // PNG: \x89PNG\r\n\x1a\n
        if idx + 8 <= data.len() && &data[idx..idx + 8] == b"\x89PNG\r\n\x1a\n" {
            let mut end_idx = data.len();
            for j in (idx + 8)..(data.len() - 4) {
                if &data[j..j + 4] == b"IEND" {
                    end_idx = j + 8;
                    if end_idx > data.len() {
                        end_idx = data.len();
                    }
                    break;
                }
            }
            let size = end_idx - idx;
            if size > 20 && size <= 5_000_000 {
                let carved_data = data[idx..end_idx].to_vec();
                let mut metadata = HashMap::new();

                if carved_data.len() >= 24 && &carved_data[12..16] == b"IHDR" {
                    let w = u32::from_be_bytes(carved_data[16..20].try_into().unwrap_or([0; 4]));
                    let h = u32::from_be_bytes(carved_data[20..24].try_into().unwrap_or([0; 4]));
                    metadata.insert("Dimensions".to_string(), format!("{}x{}", w, h));
                }

                files.push(CarvedFile {
                    filename: format!("carved_{}.png", idx),
                    file_type: "PNG Image".to_string(),
                    start_offset: idx,
                    size,
                    metadata,
                    data: carved_data,
                });
                idx = end_idx;
                continue;
            }
        }

        // PDF: %PDF-
        if idx + 5 <= data.len() && &data[idx..idx + 5] == b"%PDF-" {
            let mut end_idx = data.len();
            for j in (idx + 5)..(data.len() - 5) {
                if &data[j..j + 5] == b"%%EOF" {
                    end_idx = j + 5;
                    break;
                }
            }
            let size = end_idx - idx;
            if size > 15 && size <= 10_000_000 {
                let carved_data = data[idx..end_idx].to_vec();
                let mut metadata = HashMap::new();

                let version_str = String::from_utf8_lossy(&carved_data[0..8]);
                metadata.insert("Version".to_string(), version_str.trim().to_string());

                let data_str = String::from_utf8_lossy(&carved_data);
                if let Some(t_idx) = data_str.find("/Title") {
                    if let Some(open) = data_str[t_idx..].find('(') {
                        if let Some(close) = data_str[t_idx + open..].find(')') {
                            metadata.insert(
                                "Title".to_string(),
                                data_str[t_idx + open + 1..t_idx + open + close].to_string(),
                            );
                        }
                    }
                }
                if let Some(a_idx) = data_str.find("/Author") {
                    if let Some(open) = data_str[a_idx..].find('(') {
                        if let Some(close) = data_str[a_idx + open..].find(')') {
                            metadata.insert(
                                "Author".to_string(),
                                data_str[a_idx + open + 1..a_idx + open + close].to_string(),
                            );
                        }
                    }
                }

                files.push(CarvedFile {
                    filename: format!("carved_{}.pdf", idx),
                    file_type: "PDF Document".to_string(),
                    start_offset: idx,
                    size,
                    metadata,
                    data: carved_data,
                });
                idx = end_idx;
                continue;
            }
        }

        // ZIP: PK\x03\x04
        if idx + 4 <= data.len() && &data[idx..idx + 4] == b"PK\x03\x04" {
            let mut end_idx = data.len();
            for j in (idx + 4)..(data.len() - 20) {
                if &data[j..j + 4] == b"PK\x05\x06" {
                    end_idx = j + 22;
                    if end_idx > data.len() {
                        end_idx = data.len();
                    }
                    break;
                }
            }
            let size = end_idx - idx;
            if size > 25 && size <= 10_000_000 {
                let carved_data = data[idx..end_idx].to_vec();
                let mut metadata = HashMap::new();
                metadata.insert("Archive Type".to_string(), "ZIP File".to_string());

                files.push(CarvedFile {
                    filename: format!("carved_{}.zip", idx),
                    file_type: "ZIP Archive".to_string(),
                    start_offset: idx,
                    size,
                    metadata,
                    data: carved_data,
                });
                idx = end_idx;
                continue;
            }
        }

        // PE: MZ
        if idx + 2 <= data.len() && &data[idx..idx + 2] == b"MZ" {
            let mut is_pe = false;
            if idx + 64 <= data.len() {
                let pe_offset =
                    u32::from_le_bytes(data[idx + 0x3C..idx + 0x40].try_into().unwrap_or([0; 4]))
                        as usize;
                if idx + pe_offset + 4 <= data.len()
                    && &data[idx + pe_offset..idx + pe_offset + 4] == b"PE\x00\x00"
                {
                    is_pe = true;
                }
            }
            if is_pe {
                let size = std::cmp::min(10_000_000, data.len() - idx);
                let carved_data = data[idx..idx + size].to_vec();
                let mut metadata = HashMap::new();
                metadata.insert("Format".to_string(), "Windows Executable (PE)".to_string());

                files.push(CarvedFile {
                    filename: format!("carved_{}.exe", idx),
                    file_type: "PE Binary".to_string(),
                    start_offset: idx,
                    size,
                    metadata,
                    data: carved_data,
                });
                idx += size;
                continue;
            }
        }

        // ELF: \x7fELF
        if idx + 4 <= data.len() && &data[idx..idx + 4] == b"\x7fELF" {
            let size = std::cmp::min(10_000_000, data.len() - idx);
            let carved_data = data[idx..idx + size].to_vec();
            let mut metadata = HashMap::new();
            metadata.insert("Format".to_string(), "Linux Executable (ELF)".to_string());

            files.push(CarvedFile {
                filename: format!("carved_{}.elf", idx),
                file_type: "ELF Binary".to_string(),
                start_offset: idx,
                size,
                metadata,
                data: carved_data,
            });
            idx += size;
            continue;
        }

        idx += 1;
    }

    files
}

// 3. Timeline Generator & Export
pub fn build_timeline(packets: &[Packet]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for p in packets {
        events.push(TimelineEvent {
            timestamp: p.timestamp.to_rfc3339(),
            src: p
                .src_addr
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".into()),
            dst: p
                .dst_addr
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".into()),
            protocol: format!("{:?}", p.protocol),
            length: p.length as u32,
            summary: p.summary.clone(),
        });
    }
    events
}

pub fn export_timeline_csv(events: &[TimelineEvent]) -> String {
    let mut csv = String::from("Timestamp,Source,Destination,Protocol,Length,Summary\n");
    for ev in events {
        let escaped_summary = ev.summary.replace('"', "\"\"");
        csv.push_str(&format!(
            "{},{},{},{},{},\"{}\"\n",
            ev.timestamp, ev.src, ev.dst, ev.protocol, ev.length, escaped_summary
        ));
    }
    csv
}

pub fn export_timeline_json(events: &[TimelineEvent]) -> String {
    serde_json::to_string_pretty(events).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_png() {
        let mut data = vec![0; 100];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00IEND\xae\x42\x60\x82");
        data.extend_from_slice(&[0; 50]);

        let carved = carve_files(&data);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].file_type, "PNG Image");
        assert_eq!(
            carved[0].metadata.get("Dimensions").map(|s| s.as_str()),
            Some("256x256")
        );
    }

    #[test]
    fn test_carve_pdf() {
        let mut data = vec![0; 50];
        data.extend_from_slice(b"%PDF-1.4\n/Title (Incident Report)\n/Author (Analyst)\n%%EOF");

        let carved = carve_files(&data);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].file_type, "PDF Document");
        assert_eq!(
            carved[0].metadata.get("Title").map(|s| s.as_str()),
            Some("Incident Report")
        );
        assert_eq!(
            carved[0].metadata.get("Author").map(|s| s.as_str()),
            Some("Analyst")
        );
    }

    #[test]
    fn test_timeline_export() {
        let events = vec![TimelineEvent {
            timestamp: "2026-07-15T18:30:00Z".into(),
            src: "10.0.0.1".into(),
            dst: "8.8.8.8".into(),
            protocol: "Dns".into(),
            length: 64,
            summary: "Standard query A google.com".into(),
        }];
        let csv = export_timeline_csv(&events);
        assert!(csv.contains("Timestamp,Source,Destination,Protocol,Length,Summary"));
        assert!(csv.contains(
            "2026-07-15T18:30:00Z,10.0.0.1,8.8.8.8,Dns,64,\"Standard query A google.com\""
        ));
    }
}
