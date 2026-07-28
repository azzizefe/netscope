# Netscope — Eksik Kritik Bileşenler & Kritik Hatalar

## 🔴 Kritik (CRITICAL)

| # | Sorun | Detay |
|---|---|---|
| 1 | **`unreachable!()` panic riski — `filter.rs:561`** | `CmpOp::Contains` kolunda `unreachable!()` çağrılıyor. Hiçbir `match` guard yok — bu kod yoluna gelinirse **process panic** olur. |
| 2 | **3 adet `unwrap()` üretim kodunda** | `crates/core/src/dissectors/ip.rs:42`, `tcp.rs:28`, `udp.rs:21` — `from_slice()` sonucu `unwrap()` ile açılıyor. Bozuk/malformed paketlerde **panic**. |
| 3 | **`sqlx-postgres` 0.8.0 — Rust 2024 uyumsuzluğu** | `cargo report future-incompatibilities` çıktısına göre: `!` (never type) `()` fallback kullanımı **Rust 2024'te hard error**. Güncelleme gerekli (`>= 0.8.1`). |
| 4 | **Derleme uyarısı — Kullanılmayan import** | `bindings.rs:35-44`: `edge_pytorch_mobile`, `nxp_eiq_inference`, `stm_stm32cube_ai` import edilmiş ama kullanılmıyor (port satırları silinmiş, importlar kalmış). |
| 5 | **8 commit pushlenmemiş** | `main`, `origin/main`'in **8 commit önünde**. Yerel değişiklikler remote'da yok — veri kaybı riski. |
| 6 | **2 değiştirilmiş dosya stage edilmemiş** | `bindings.rs` + `tcp.rs` — değişiklikler commit'lenmemiş, üstelik `bindings.rs` warning üretiyor. |

## 🟠 Yüksek (HIGH)

| # | Sorun | Detay |
|---|---|---|
| 7 | **npcap-sdk `gitignore`'da ama build bağımlı** | `.gitignore` `npcap-sdk/`'yı kapsıyor, ama `.cargo/config.toml` `LIBPCAP_LIBDIR` olarak `npcap-sdk/Lib/x64`'ü gösteriyor. **Fresh clone'da build kırılır.** |
| 8 | **`target/` şişkinliği — onlarca GB stale incremental cache** | Yüzlerce `dep-graph.bin` (10-58 MB) ve `query-cache.bin` (10-44 MB) dosyası. **Hiçbiri `gitignore`'da değil** (sadece `/target` ignore). |
| 9 | **`.env.example` yok** | `.gitignore` `!.env.example` ile referans veriyor ama dosya mevcut değil. Server/agent yapılandırması için belirsizlik. |
| 10 | **WASM binary çok büyük (56.6 MB)** | `netscope_wasm.wasm` debug build = **56.6 MB**. Frontend yükleme süresi olumsuz etkilenir. Release'de optimize edilmeli. |
| 11 | **TUI test kapsamı hala sıfır** | UNTESTED.md "TUI 30 test" dense de, `crates/tui/src/` altında **hiç test modülü yok**. |
| 12 | **Frontend `console.log` kalıntıları** | `app.js`'de 8 adet `console.log` — üretim kodunda temizlenmemiş debug çıktısı. |

## 🟡 Orta (MEDIUM)

| # | Sorun | Detay |
|---|---|---|
| 13 | **Desktop Tauri komutları — 9/11 test edilmemiş** | `start_capture`, `stop_capture`, `save_pcap`, `block_ip` gibi kritik komutların **testi yok**. |
| 14 | **Bütünleşik test (integration test) — %0** | TUI+core, Desktop+core, filtre+pcap uçtan uca senaryoların **hiçbiri otomatik test edilmiyor**. |
| 15 | **CRLF/ LF satır sonu karışıklığı** | Git `LF will be replaced by CRLF` uyarısı veriyor. Platformlar arası sorun çıkarabilir. |
| 16 | **WASM glue code'da TODO** | `desktop/frontend/wasm/netscope_wasm.js:328` — otomatik üretilmiş kodda açık TODO. |
| 17 | **20+ dissector'da hata yolu testi yok** | Sadece happy path test edilmiş. QUIC, TLS, DNS (CNAME/MX/TXT), SIP (BYE/CANCEL) gibi protokoller test dışı. |
| 18 | **StatsEngine bandwidth sampling testi yok** | `tick()` saniye bazlı örnekleme, 60sn rolling window limiti, concurrent `record_packet()` — test edilmemiş. |
