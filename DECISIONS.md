# netscope — Mimari Karar Kayıtları (ADR)

## ADR-001: Neden `pcap` crate'i (raw FFI değil)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Paket yakalama için libpcap/Npcap API'sine ihtiyaç vardı. Seçenekler: `pcap` crate'i, doğrudan FFI bindings, veya `libpcap-sys` + wrapper.

**Karar:** `pcap` crate'i kullanıldı.

**Gerekçe:**
- Olgun, bakımı yapılan, 1M+ indirme
- Windows (Npcap), macOS, Linux'ta aynı API
- Canlı yakalama + offline pcap okuma + filtre derleme hepsini tek crate'te sunar
- Doğrudan FFI yazmak hata ayıklama yükünü artırır, sağladığı esneklik değmez

## ADR-002: Neden `ratatui` (termbox / cursive değil)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Terminal arayüzü framework'ü seçimi.

**Karar:** `ratatui` (eski `tui-rs`).

**Gerekçe:**
- `tui-rs`'in aktif olarak geliştirilen fork'u
- Widget tabanlı mimari (layout, paragraph, table, list) → TUI kolayca 7 görünüme ayrılır
- `crossterm` backend ile Windows/macOS/Linux'ta aynı davranış
- `ncurses`/`termbox` gerektirmez → bağımlılık sayısı düşük

## ADR-003: Neden Tauri v2 (Electron / Sciter değil)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Masaüstü uygulaması framework'ü.

**Karar:** Tauri v2.

**Gerekçe:**
- **Boyut:** Electron ~150 MB vs Tauri ~5 MB (sistem WebView ile)
- **Dil:** Rust backend → `netscope-core`'u tekrar yazmadan doğrudan kullan
- **Güvenlik:** Content Security Policy, izin tabanlı Tauri API, izole webview
- **Platform:** Windows (NSIS/MSI), macOS (DMG), Linux (DEB/AppImage) tek build pipeline
- **Topluluk:** Tauri v2 kararlı, geniş plugin ekosistemi (updater, dialog, fs, shell)

## ADR-004: Neden `anyhow` (`thiserror` değil)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Hata yönetimi yaklaşımı.

**Karar:** Birincil olarak `anyhow::Result`, özel hata tipleri için elle `Display + Error` impl.

**Gerekçe:**
- `thiserror` sadece `#[derive(Error)]` için — bir makro için ek bağımlılık değmez
- Proje genelinde tanımlanmış ~5 özel hata tipi var (FilterError, vs.) — elle implementasyon yeterli
- `anyhow`'un `.context()` ve `.bail!()` makrosu kodun çoğu yerinde yeterli

## ADR-005: Neden WASM (tarayıcıda çalışan filtre)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Web sitesinde canlı pcap analizi demo'su için filtre motoru gerekiyordu.

**Karar:** `netscope-core`'un filter modülünü wasm32-unknown-unknown hedefine derle.

**Gerekçe:**
- Filtre mantığı saf Rust (socket/thread/file yok) → WASM'e derlemesi kolay
- Ayrı bir JavaScript filter engine yazmak → 2 kod tabanı = 2 kat hata
- `wasm-bindgen` ile JS'den çağırmak basit: `WasmFilter::compile()` + `.matches()`
- Boyut: 154 KB — sayfa yüklenmesini etkilemez

## ADR-006: Neden gRPC + REST (sadece REST değil)

**Durum:** Kabul edildi · **Tarih:** 2026-07

**Bağlam:** netscope-server API katmanı.

**Karar:** Çift API: Axum REST (kullanıcı arayüzü) + Tonic gRPC (sensör ajanları ve fleet).

**Gerekçe:**
- REST: tarayıcı, curl, 3. parti entegrasyonlar için düşük eşik
- gRPC: sensör ajanları için streaming, bidir, protobuf şema sözleşmesi
- Fleet yönetiminde REST'in polling modeli yerine gRPC streaming → gerçek zamanlı olay iletimi
- Deco uyumu: aynı portta çift protokol çalıştırma (CORS/HTTP2)

## ADR-007: Neden PostgreSQL (SQLite değil)

**Durum:** Kabul edildi · **Tarih:** 2026-07

**Bağlam:** netscope-server veritabanı.

**Karar:** PostgreSQL (sqlx ile).

**Gerekçe:**
- Fleet senaryosu: çoklu sensör → merkezi veritabanı → SQLite uygun değil
- RBAC, SOAR, alert notes, scheduled reports → JOIN ağırlıklı iş yükü → PostgreSQL'in optimizer'ı avantajlı
- `sqlx`: compile-time sorgu doğrulama, migrasyonlar, pooling
- Redis: cache katmanı (opsiyonel)

## ADR-008: Neden `crossbeam-channel` (tokio::sync değil)

**Durum:** Kabul edildi · **Tarih:** 2026-06

**Bağlam:** Pipeline'da producer/consumer arası iletişim.

**Karar:** `crossbeam-channel`.

**Gerekçe:**
- Pipeline hem sync (capture thread) hem de async (UI) tarafları içerir
- `crossbeam-channel` sync/async arasında köprü olarak çalışır: `Sender` sync, `Receiver` async tarafa geçer
- `tokio::sync::mpsc` sadece async tarafta kullanılabilir
- Performans: `crossbeam-channel` segment-based queue ile yüksek throughput
