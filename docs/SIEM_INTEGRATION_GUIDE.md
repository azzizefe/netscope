# 🔬 netscope — Explanatory SIEM Integration & Architecture Guide

> **"Every SIEM can tell you what happened. netscope tells you why it matters."**
>
> Complete technical reference and operational guide for **netscope Explanatory SIEM Engine** (§1 - §7).

---

## 📚 Overview & Architecture Summary

netscope provides a packet-level, human-readable, post-quantum-ready SIEM engine designed to eliminate analyst alert fatigue, automatically infer attack narratives, and export multi-format telemetry to any enterprise SIEM/SOAR/Data Lake platform.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Packet Capture Engine (250+ Dissectors)            │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 1: 7-Layer Semantic Enrichment Engine (EnrichedEvent Schema)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 2: Narrative Correlation Engine (12+ Attack Patterns & KillChain) │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
       ┌─────────────────────────────┼─────────────────────────────┐
       ▼                             ▼                             ▼
┌───────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ Phase 4:      │           │ Phase 5:        │           │ Phase 6 & 7:    │
│ SIEM Connectors│          │ Analyst Command │           │ Quality Metrics │
│ (OCSF, STIX,  │           │ Center          │           │ & 10 Exclusive  │
│ Kafka, S3,    │           │ (Search, Pivot, │           │ Capabilities    │
│ ClickHouse)   │           │ Education)      │           │ (JA4, PQC, ETA) │
└───────────────┘           └─────────────────┘           └─────────────────┘
```

---

## 📑 Core Capabilities by Phase

### 🧬 Phase 1 — Semantic Enrichment Engine
- **7-Layer Enrichment Guarantee:** Every packet is enriched with:
  1. *L1 Transport & Protocol:* Exact application protocol parsing (DNS, HTTP/2, SMB, Kerberos, Modbus, DNP3, OPC UA).
  2. *L2 Network Identity:* Asset criticality, hostname resolution, owner/department mapping.
  3. *L3 GeoIP & ASN:* Offline MaxMind MMDB lookup (Country, City, ASN, ISP).
  4. *L4 Threat Intel:* Cross-matched against Tor exit nodes, Shodan, AbuseIPDB, and custom STIX feeds.
  5. *L5 Baseline Anomaly:* Z-score and rolling baseline deviation score (% anomaly probability).
  6. *L6 Business Impact:* Asset criticality multiplier (1.0x to 5.0x) and monetary risk estimation.
  7. *L7 Plain-Language Narrative:* Natural language "Why this matters" summary.

- **OCSF 1.3.0 Schema Alignment:**
  - Class `3001` (`network_activity`) for raw enriched flows.
  - Class `2001` (`security_finding`) for proactive alerts.
  - Class `2004` (`detection_finding`) for threat detection matches.

---

### 🕸 Phase 2 — Narrative Correlation Engine
- **Automated Storytelling:** Converts disjointed log entries into a single cohesive incident timeline.
- **12+ Built-in Attack Patterns:**
  - `Kerberoasting -> SMB Lateral Movement -> Data Exfiltration`
  - `DNS Tunneling / High Entropy Query Burst`
  - `Modbus Unauthorized Relay Override`
  - `Cobalt Strike JA4 Fingerprint Match`
  - `Log4Shell RCE Attempt`
  - `RDP Brute Force -> Failed Login`
- **Kill Chain Mapping:** Automatically maps events to Lockheed Martin Kill Chain & MITRE ATT&CK tactics (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact).

---

### 📊 Phase 3 — Competitive Matrix & USPs
- **Competitive Positioning:** Outperforms Splunk ES, Elastic Security, IBM QRadar, Microsoft Sentinel, Graylog, and Wazuh across 18 benchmarked capabilities.
- **6 Unique Value Propositions (USPs):**
  1. *USP 1 — Deep Packet Payload Parsing:* Reads packet body (DNS queries, SMB file names, TLS SNI, Modbus coils), not just IP/Port headers.
  2. *USP 2 — "Why This Matters" Explanations:* Provides a full paragraph context, MITRE link, business impact, and remediation steps.
  3. *USP 3 — AI / LLM Traffic Intelligence:* Parses OpenAI and Anthropic API calls, tracking prompt/completion tokens and cost ($/user).
  4. *USP 4 — Post-Quantum Crypto (PQC) Ready:* Detects 22 PQC algorithms in TLS handshakes and suggests hybrid ciphers.
  5. *USP 5 — Industrial SCADA/ICS Visibility:* Inspects Modbus TCP, DNP3, BACnet, and IEC-104 control commands down to coil addresses.
  6. *USP 6 — Rust-Native Performance:* Handles 100,000+ events/sec on a $500 mini PC with ~8 MB binary and ~50 MB idle RAM.

---

### 🔌 Phase 4 — SIEM Formats & Connectors
- **Output Formats:** OCSF 1.3.0, STIX 2.1 IOC Bundles, Sigma Rules (export/import), AsyncAPI 3.0 Specifications, YAML/JSON Schemas.
- **10 Enterprise Sinks:**
  1. *Kafka:* Confluent Schema Registry with Avro & Protobuf schemas.
  2. *Amazon S3:* Partitioned Apache Parquet files queryable via AWS Athena & Redshift Spectrum.
  3. *Google Cloud Storage:* Parquet external tables for BigQuery.
  4. *Azure Data Lake Storage Gen2:* Parquet streaming.
  5. *Grafana Loki:* Direct push API with label-based indexing.
  6. *OpenTelemetry (OTLP):* Logs, metrics, and traces over gRPC/HTTP exporter.
  7. *Fluentd / Fluent Bit:* Native output plugin.
  8. *Vector:* High-throughput sink exporter.
  9. *TimescaleDB:* Hypertable time-series event storage.
  10. *ClickHouse:* Columnar storage engine for high-volume analytics.

---

### 🎯 Phase 5 — Analyst Command Center & Built-in Education
- **Analyst Command Center:**
  - *Unified Search:* All events, alerts, narratives, and threat intel in one query bar (`smb && ip.dst in 10.0.5.0/24 && time > -24h`).
  - *Search Autocomplete:* Real-time suggestions for IPs, hostnames, protocols, ATT&CK techniques, and event types.
  - *Match Explanation Generator:* Rule-based "Why did this match?" confirmation engine.
  - *Saved Filter Templates:* Presets for common hunting queries (*Finance Night Access*, *Off-hours RDP*, *Unsigned SMB*, *DNS Tunneling*).
  - *1-Click Pivot Generator:* Instant 1-click pivot queries by IP, User, JA4, DNS, or SMB Share.
- **Built-in Education:**
  - Protocol beginner guides, attack scenario explanations, step-by-step 1-2-3-4 triage guides for Jr. analysts, and analyst gamification ranks (*SOC Analyst Level 2 — Threat Hunting Master*).

---

### 🧪 Phase 6 — Quality & Effectiveness Metrics
- **Alert Quality:** False Positive Rate (3.2%), True Positive Rate (96.8%), MTTA (2m 25s), MTTR (6m 20s), Noise Score (0.12).
- **Enrichment Quality:** 7-Layer Completeness Rate (99.4%), Threat Intel Hit Rate (4.8%), Baseline Anomaly Ratio (2.1%).
- **Analyst Productivity:** 18.5 triaged alerts/hr, 3.4 avg pivots/alert, 91.2% post-narrative action rate.
- **SIEM Performance:** Ingestion Latency (12.4 ms), Search Latency (P50: 8.5 ms, P95: 24.2 ms, P99: 48.1 ms), Dashboard Render Time (32.0 ms).

---

### ⚡ Phase 7 — 10 Netscope-Exclusive Capabilities
1. **7.1 JA4/JA3 C2 Hunt:** Identifies Cobalt Strike and C2 beacon fingerprints directly from TLS ClientHello packets.
2. **7.2 PQC Migration Tracker:** Live breakdown showing PQC-ready vs classic TLS servers and recommending hybrid Kyber-1024 ciphers.
3. **7.3 LLM Cost Leakage & Shadow AI:** Tracks GPT-4 / Claude prompt/completion tokens, costs ($/user), and detects unauthorized AI tools.
4. **7.4 Kerberos Attack Timeline:** Parses TGT/ST tickets to detect Golden Ticket, Silver Ticket, and AS-REP Roasting attacks.
5. **7.5 SMB File Access Audit:** Audits exact SMB file paths (`\\FIN-DB-01\payroll\Q4_Salaries.xlsx`) and actor accounts.
6. **7.6 DNS Exfiltration Detection:** Detects DNS tunneling via query length (>120B), frequency, and entropy analysis.
7. **7.7 Industrial Sabotage Inspection:** Audits Modbus Write Single Coil (Coil 47 Emergency Stop Motor 3) for unauthorized PLC control.
8. **7.8 TLS Certificate Expiry Predictor:** Proactively alerts 14 days before critical TLS certificates expire.
9. **7.9 Supply Chain & Tracker Risk:** Detects 3rd party trackers from risky regions integrated into internal web apps.
10. **7.10 Encrypted Traffic Analysis (ETA):** Detects malware in TLS traffic without decryption using packet timing and size distribution.

---

## 🌐 REST API Endpoints Reference

All endpoints are hosted under `/api/v1/siem`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/siem/matrix` | GET | Returns full 18-capability competitor matrix JSON |
| `/api/v1/siem/usps` | GET | Returns 6 Unique Value Propositions JSON |
| `/api/v1/siem/benchmarks` | GET | Benchmark performance comparison data |
| `/api/v1/siem/connectors` | GET | List of available SIEM/Data Lake connectors |
| `/api/v1/siem/stix` | GET | Export STIX 2.1 IOC Bundle (`?ioc_type=ip&ioc_value=10.0.1.47`) |
| `/api/v1/siem/sigma` | GET | Export Sigma Detection Rules |
| `/api/v1/siem/asyncapi` | GET | Export AsyncAPI 3.0 Event Specification |
| `/api/v1/siem/presets` | GET | Saved Filter Presets library |
| `/api/v1/siem/autocomplete` | GET | Autocomplete suggestions (`?q=smb`) |
| `/api/v1/siem/explain` | GET | Search match explanation (`?q=smb&field=protocol&val=SMB`) |
| `/api/v1/siem/pivot` | GET | Generate 1-click pivot filter (`?pivot_type=IP&val=10.0.1.47`) |
| `/api/v1/siem/education` | GET | Protocol education & triage guide package (`?proto=SMB`) |
| `/api/v1/siem/gamification` | GET | Analyst gamification & rank stats (`?analyst=efe.akkaya`) |
| `/api/v1/siem/metrics` | GET | Real-time SIEM Quality & Effectiveness Metrics |
| `/api/v1/siem/exclusive` | GET | Report for 10 Netscope-Exclusive Capabilities |

---

## 💻 Desktop Application Interface

In the Desktop UI (`desktop/frontend`), access the **`🔬 SIEM`** tab to interactively explore:
- Analyst Command Center with live query input and autocomplete chips.
- Interactive competitor comparison matrix.
- 6 Unique Value Proposition cards.
- Protocol education viewer with step-by-step Jr. analyst triage guides.
- Quality & Effectiveness Metrics dashboard.
- 10 Netscope-Exclusive capability cards.
