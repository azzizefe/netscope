# Netscope — Eksik Kritik Bileşenler & Kritik Hatalar

> Son doğrulama: **2026-07-29**. Aşağıdaki her satır o gün `cargo check` /
> `cargo test` / `cargo clippy` / `cargo fmt` çalıştırılarak yeniden ölçüldü.
> Bir maddeyi kapatmadan önce **doğrulama komutunu çalıştır** — bu dosyanın
> önceki sürümü, çoktan düzeltilmiş 12 maddeyi açık gösteriyordu.

## 🔴 Kritik (CRITICAL)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 1 | **`netscope-server` derlenmiyor** | `api/hunt.rs`: `queries::CreateRule` private, ayrıca 3 tip uyuşmazlığı (`enabled`, `severity`, `actions`). `main` şu an derlenmeyen halde commit'li. Diğer 5 crate temiz. | `cargo check -p netscope-server` |

## 🟠 Yüksek (HIGH)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 2 | **145 dissector modülü dispatch'ten erişilemiyor** | Modüller derleniyor, kendi testleri geçiyor, ama hiçbir çağrı yolu yok. Çoğunun **tanıma imzası yok** (magic byte / `looks_like_*` yok) — bu yüzden basit "wiring" ile çözülmez. **Tahmini porta bağlamak yasak**: bu depoda 3 kez gerçek hataya yol açtı (`bindings.rs` başındaki kurala bak). | `cargo test -p netscope-core --lib every_dissector_module_is_reachable -- --ignored` |
| 3 | **1938 protokol registry'de ama hiçbir dissector üretmiyor** | `registry.rs` tablosunda tanımlı, fakat hiçbir kod yolu bu `Protocol` değerini atamıyor. Filtre/renk/eğitim içeriği bu satırlardan türediği için kullanıcıya asla görünmeyen protokoller listeleniyor. | `cargo test -p netscope-core --lib every_protocol_is_produced_by_some_dissector -- --ignored` |
| 4 | **4 yeni PQC modülü imzasız** | `pqc_cve_feed_integration`, `tls_cert_transparency_v3`, `tls_ech_pqc_interop`, `tls_session_resumption_pqc`. **Sınıflandırma sorusu kapandı (2026-07-29):** dördü de `payload`'ı sabit offset'ten **doğrulamasız** okuyor (`parse_sct_version` herhangi bir baytın ilkini SCT sürümü sayar), dolayısıyla hiçbiri `HELPER_MODULES`'a ("no wire form") ait **değil**. Madde 2'deki backlog'a aitler: önce gerçek bir imza gerekiyor. Madde 2'nin sayısını 141'den 145'e çıkaran bunlar. | `dissectors.rs:3073` `HELPER_MODULES` |
| 5 | **npcap-sdk taze klonda build'i kırıyor** | `.gitignore` `npcap-sdk/`'yı dışlıyor, `.cargo/config.toml` ise `LIBPCAP_LIBDIR`'ı repo köküne göreli `npcap-sdk/Lib/x64`'e sabitliyor. CI çalışıyor çünkü SDK'yı `$TEMP`'e indirip env değişkenini set ediyor (env, config.toml'u ezer). **Yerel taze klon link hatası verir.** README artık doğru konumu belgeliyor (2026-07-29). | `README.md` § Prerequisites → Windows |

## 🟡 Orta (MEDIUM)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 6 | **`netscope-server` clippy uyarıları** | `AlertNote` / `AlertDetail` hiç construct edilmiyor, `assigned_to` hiç okunmuyor, `sensors.rs:644` manuel `+=`. Yeni alert-notes özelliği yarım. | `cargo clippy -p netscope-server` |
| 7 | **`netscope-server` formatlanmamış** | `api/alerts.rs`, `api/sensors.rs`, `db/queries.rs` — CI'ın fmt job'ı bu haliyle kırmızı kalır. Diğer crate'ler temiz. | `cargo fmt --all --check` |
| 8 | **`target/` 29 GB** | Git sorunu **değil** (`/target` ignore'lu, doğru). Sadece disk: bayat incremental cache. | `cargo clean` |
| 9 | **Desktop komutlarının 25/33'ü test edilmemiş** | 2026-07-29'da 5/33'ten 8/33'e çıktı (`get_lessons`, `tls_keylog_*`, `get_alert_rules` eklendi). Kalanların çoğu donanım (`start_capture`, `arp_scan`, `list_interfaces`), yükseltilmiş yetki (`block_ip`, `list_blocked`) veya Tauri `State` gerektiriyor — bunlar birim testle değil, ancak uçtan uca koşumla kapsanabilir. | `cargo test -p netscope-desktop` |
| 10 | **Bütünleşik test kapsamı dar** | `crates/core/tests/integration_test.rs` tek dosya. TUI+core ve Desktop+core uçtan uca senaryolar hâlâ kapsanmıyor. | — |
| 11 | **WASM glue'da otomatik üretilmiş TODO** | `desktop/frontend/wasm/netscope_wasm.js` — wasm-bindgen çıktısı, elle düzeltilmemeli. Düşük öncelik. | — |

## ✅ Doğrulanıp Kapatılanlar (2026-07-29)

Bu maddeler dosyanın önceki sürümünde açıktı; hepsi ölçülerek kapatıldı:

| Eski # | Sorun | Bulgu |
|---|---|---|
| 1 | `unreachable!()` — `filter.rs:561` | `crates/` altında **hiç** `unreachable!` yok. |
| 2 | 3 `unwrap()` (`ip.rs`/`tcp.rs`/`udp.rs`) | `from_slice().unwrap()` kalmamış. Kalan `unwrap()`'lar test kodunda ve mutex `lock()`'ta — normal. |
| 3 | `sqlx-postgres` 0.8.0 Rust 2024 uyumsuz | Artık **0.8.6**. `cargo report future-incompatibilities` → rapor yok. |
| 4 | `bindings.rs` kullanılmayan import | Derleme **sıfır uyarı**. Üç uydurma port bağlaması da kaldırılmış. |
| 5, 6 | Pushlanmamış / stage edilmemiş değişiklikler | Çalışma ağacı temiz. (Not: `origin/main` hâlâ geride — push edilmeli.) |
| 9 | `.env.example` yok | Dosya mevcut (992 B). |
| 10 | WASM 56.6 MB | `netscope_wasm_bg.wasm` = **154 KB**. |
| 11 | TUI testi sıfır | 10 modülde test var, **44 test** geçiyor. |
| 12 | `app.js`'de 8 `console.log` | **0** kaldı. |
| 18 | StatsEngine bandwidth testi yok | 4 test mevcut (`bandwidth_tick_*`, `bandwidth_rolling_window_capped_at_60`, `snapshot_bandwidth_values`). |
| — | **`"compound"` tetikleyici tipi** (2026-07-29'da bulundu) | `RuleTrigger::trigger_type` dokümantasyonu `"compound"`'u destekleniyor gösteriyordu, ama `check`'te hiçbir `match` kolu onu ele almıyordu — `_ => {}`'e düşüyordu. Bu tiple yazılan bir kural UI'da kurulu görünüp **hiç tetiklenmiyordu**. Doküman düzeltildi, `RuleTrigger::SUPPORTED_TYPES` + `is_supported()` eklendi ve `supported_types_match_the_engine` ile sabitlendi. |

## Sağlık Durumu (2026-07-29)

| Ölçüm | Durum |
|---|---|
| `cargo check` (core, agent, tui, desktop, wasm) | ✅ sıfır uyarı |
| `cargo check -p netscope-server` | ❌ 4 hata (madde 1) |
| Test | ✅ **2 284 geçti**, 0 başarısız (server hariç) |
| `cargo clippy` (server hariç) | ✅ sıfır uyarı |
| `cargo fmt --check` (server hariç) | ✅ temiz |

> `cargo test` **`RUST_MIN_STACK=134217728` gerektirir** — `.cargo/config.toml`
> bunu zaten set ediyor. Ortamda daha küçük bir değer export edilmişse cargo onu
> ezmez ve codegen `STATUS_STACK_OVERFLOW` ile ölür.
