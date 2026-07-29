# netscope — Mimari

## Genel Bakış

```
┌──────────────────────────────────────────────────────────┐
│                        Kullanıcı                          │
├──────────┬───────────────┬──────────┬────────────────────┤
│  TUI CLI │  Desktop GUI  │  WASM    │  Fleet (server +   │
│ (ratatui)│  (Tauri v2)   │ (filter) │   agent, web UI)   │
└────┬─────┴──────┬────────┴────┬─────┴──────────┬─────────┘
     │            │             │                │
     │      ┌─────┴──────┐     │                │
     │      │ frontend/  │     │                │
     │      │ (svelte/   │     │                │
     │      │  vanilla)  │     │                │
     │      └─────┬──────┘     │                │
     │            │            │                │
┌────┴────────────┴────────────┴────────────────┴──────────┐
│                    netscope-core (kütüphane)              │
├──────────────────────────────────────────────────────────┤
│  dissectors/   │  capture/    │  filter/     │  siem/    │
│  ~500 modül    │  pcap/pcapng │  BPF parser  │  CEF/LEEF │
├────────────────┼──────────────┼──────────────┼───────────┤
│  stats/        │  expert/     │  alerting/   │  flows/   │
│  bandwidth,    │  severity    │  rule-based  │  TCP/IP   │
│  protocol hiy. │  sınıflama   │  tetikleme   │  akış     │
├────────────────┼──────────────┼──────────────┼───────────┤
│  remote/       │  pipeline/   │  registry/   │  models/  │
│  SSH, USBPcap  │  producer/   │  2500+       │  Packet   │
│  extcap        │  consumer    │  protokol    │  Protocol │
└────────────────┴──────────────┴──────────────┴───────────┘
```

## Katmanlar

### 1. `netscope-core` — Paylaşılan kütüphane

Tüm üst katmanların kullandığı ortak motor. Hiçbir çalıştırılabilir dosya doğrudan `pcap` crate'ine bağlanmaz; tüm yakalama mantığı burada.

- **Dissectors (`dissectors/`)**: ~500 dosya, ~2,500 protokol. Her biri ham baytları alıp `DissectedResult` döndüren bir `dissect_*()` fonksiyonu.
- **Capture (`capture/`)**: Canlı yakalama, ring buffer, durdurma koşulları. libpcap üzerinden Npcap (Windows) / pcap (Linux/macOS).
- **Filter (`filter.rs`)**: BPF benzeri filtre dili. Ayrıştırma + eşleştirme. WASM'e de derlenir.
- **Registry (`registry.rs`)**: Protokol sabitleri ve isim tablosu. `Protocol` enum'ı + insan adı.
- **Pipeline (`pipeline.rs`)**: Producer/Consumer pattern. Yakalanan frame'leri dissect edip istatistik toplar.
- **Stats (`stats/`)**: Bant genişliği, protokol hiyerarşisi, en çok konuşan uçlar.
- **Expert (`expert.rs`)**: Paket özetlerini severity'a göre sınıflandırır (Chat, Note, Warn, Error).
- **Alerting (`alerting.rs`)**: Kural tabanlı uyarı motoru. SIEM'e besleme yapar.
- **SIEM (`siem.rs`)**: CEF, LEEF, JSON formatlarında olay normalizasyonu ve dışa aktarım.
- **Remote (`remote.rs`)**: SSH üzerinden tcpdump, USBPcap, extcap pipe.
- **Education (`education.rs`)**: Protokol öğrenme modülü (ders + quiz).
- **WASM uyumu**: `cfg(not(target_arch = "wasm32"))` ile socket/thread/file gerektiren modüller kapatılır; WASM build'i sadece filter/models/registry/kalanı içerir.

### 2. `netscope-tui` — Terminal arayüzü

`clap` ile CLI argümanları, `ratatui` ile TUI. 7 görünüm: packet list, tree, hex dump, statistics, dashboard, connections, protocol hierarchy.

- `--headless` modu: plain text çıktı (piped)
- `--json` modu: JSON Lines çıktı
- `--serve PORT` modu: embed REST API
- Alt komutlar: `merge`, `split`, `info` (mergecap/editcap/capinfos eşdeğeri)

### 3. `netscope-desktop` — Masaüstü (Tauri v2)

Tauri v2 + webview (svelte/vanilla JS). 33 Tauri komutu: capture control, TLS keylog, GeoIP, eğitim dersleri, firewall yönetimi.

### 4. `netscope-wasm` — Tarayıcı filtresi

`netscope_core::filter`'ı wasm32-unknown-unknown hedefine derler. 154 KB. `WasmFilter::compile()` + `.matches()`.

### 5. `netscope-server` — Fleet yönetimi (derlenmiyor)

Axum HTTP + Tonic gRPC. PostgreSQL, Redis, RBAC, JWT, SOAR, WebSocket, SIEM sorgulama. Şu an derlenme hatası var.

### 6. `netscope-agent` — Sensör ajanı

WebSocket üzerinden server'a bağlanır, heartbeat gönderir, remote capture yapar, kendini günceller.

## Veri Akışı

```
libpcap/Npcap → Raw Frame → Pipeline → Dissector Chain → Packet
                                               ↓
                                    Filter Match? → UI'da göster
                                               ↓
                                    Stats Engine → Protocol Hiyerarşisi
                                               ↓
                                    Expert System → Severity
                                               ↓
                                    Alert Engine → SIEM Export
                                               ↓
                                    Notifications → Email/Webhook/WebSocket
```

## Bağımlılıklar

| Crate | Önemli Bağımlılıklar |
|---|---|
| core | `pcap`, `etherparse`, `crossbeam-channel`, `anyhow`, `chrono`, `serde` |
| tui | `ratatui`, `clap`, `crossterm` |
| desktop | `tauri` v2, `tauri-plugin-*` |
| server | `axum`, `tonic`, `sqlx`, `tower-http`, `redis` |
| agent | `tokio-tungstenite`, `reqwest` |
| wasm | `wasm-bindgen`, `serde-wasm-bindgen` |

## Test Stratejisi

- Birim test: her `.rs` içinde `#[cfg(test)] mod tests`
- Entegrasyon: `crates/core/tests/integration_test.rs` + `fixtures/` pcap dosyaları
- Frontend: Vitest + Node.js VM sandbox (tarayıcı gerekmez)
- Benchmark: `crates/core/benches/`
