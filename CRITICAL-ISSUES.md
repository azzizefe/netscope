# Netscope — Eksik Kritik Bileşenler & Kritik Hatalar

> Son doğrulama: **2026-07-29 (akşam)**. Aşağıdaki her satır `cargo check` /
> `cargo test` / `cargo clippy` / `cargo fmt` çalıştırılarak yeniden ölçüldü.
> Bir maddeyi kapatmadan önce **doğrulama komutunu çalıştır**.

## 🔴 Kritik (CRITICAL)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| *(yok)* | Tüm crate'ler derleniyor | — | `cargo check --workspace --exclude netscope-desktop` |

## 🟠 Yüksek (HIGH)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| ~~12~~ | ~~**Taze klon build edilemiyor: 3 build-kritik dosya `.gitignore` tarafından yutulmuş**~~ | ~~`.cargo/config.toml` (`.cargo/` ignore'lu → `RUST_MIN_STACK` ve `LIBPCAP_LIBDIR` yok), `fixtures/*.pcap` (`*.pcap` ignore'lu → `integration_test.rs` fail), `.env.example` (`.env.*` ignore'lu).~~ **✅ Kurallar daraltıldı, üçü de commit'lendi.** `*.pcap` binary olarak işaretlendi (CRLF bozulmasına karşı). | `git clone` → `ls .cargo/config.toml fixtures/ .env.example` |
| ~~13~~ | ~~**npcap-sdk ikilileri depoda (lisans ihlali riski)**~~ | ~~`.gitignore` `npcap-sdk/`'yı dışlamasına rağmen 28 dosya (`wpcap.lib`, `Packet.lib` dâhil) izleniyordu — Npcap lisansı yeniden dağıtıma izin vermiyor, MIT depoda yayınlanamaz.~~ **✅ `git rm --cached`.** Disk üzerinde kalıyor, `tools/ensure-npcap-sdk.ps1` indiriyor. **Not: git geçmişinde hâlâ duruyor**; halka açılmadan önce history rewrite gerekir. | `git ls-files npcap-sdk` → boş |
| ~~14~~ | ~~**Frontend testleri taze klonda çöküyor**~~ | ~~`desktop/frontend-tests/load-app.js` `desktop/frontend/wasm/netscope_wasm.js` + `_bg.wasm` dosyalarını doğrudan okuyor; bunlar build çıktısı (ignore'lu) ve hiçbir yerde belgelenmemişti.~~ **✅ `tools/build-wasm.{ps1,sh}` eklendi**, README/CONTRIBUTING/setup.md'de belgelendi. | `.\tools\build-wasm.ps1` → `npm test` (173 test) |
| 2 | **145 dissector modülü dispatch'ten erişilemiyor** | Modüller derleniyor, kendi testleri geçiyor, ama hiçbir çağrı yolu yok. Çoğunun **tanıma imzası yok** (magic byte / `looks_like_*` yok) — bu yüzden basit "wiring" ile çözülmez. **Tahmini porta bağlamak yasak**: bu depoda 3 kez gerçek hataya yol açtı (`bindings.rs` başındaki kurala bak). | `cargo test -p netscope-core --lib every_dissector_module_is_reachable -- --ignored` |
| 3 | **1938 protokol registry'de ama hiçbir dissector üretmiyor** | `registry.rs` tablosunda tanımlı, fakat hiçbir kod yolu bu `Protocol` değerini atamıyor. Filtre/renk/eğitim içeriği bu satırlardan türediği için kullanıcıya asla görünmeyen protokoller listeleniyor. | `cargo test -p netscope-core --lib every_protocol_is_produced_by_some_dissector -- --ignored` |
| ~~4~~ | ~~**4 yeni PQC modülü imzasız**~~ | ~~`pqc_cve_feed_integration`, `tls_cert_transparency_v3`, `tls_ech_pqc_interop`, `tls_session_resumption_pqc`~~. **✅ HELPER_MODULES'a eklendi** (analiz geçişleri, tel üzerinde protokol değil). | `dissectors.rs:3073` `HELPER_MODULES` |
| ~~5~~ | ~~**npcap-sdk taze klonda build'i kırıyor**~~ | ~~`.gitignore` `npcap-sdk/`'yı dışlıyor, `.cargo/config.toml` ise `LIBPCAP_LIBDIR`'ı repo köküne göreli `npcap-sdk/Lib/x64`'e sabitliyor.~~ **✅ Düzeltildi:** `tools/ensure-npcap-sdk.ps1` eklendi, README güncellendi. Taze klonda `.\tools\ensure-npcap-sdk.ps1` çalıştırmak yeterli. | `tools/ensure-npcap-sdk.ps1` |

## 🟡 Orta (MEDIUM)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 8 | **`target/` 29 GB** | Git sorunu **değil** (`/target` ignore'lu, doğru). Sadece disk: bayat incremental cache. | `cargo clean` |
| 9 | **Desktop komutlarının 25/38'i test edilmemiş** | 2026-07-29 akşam: 10/38'den 13/38'e çıktı (+`save_object`, `list_plugins`, `is_elevated`; 6 yeni test eklendi, toplam 18). Kalanlar donanım (`start_capture`, `arp_scan`, `list_interfaces`), yükseltilmiş yetki (`block_ip`, `list_blocked`) veya Tauri `State` gerektiriyor. | `cargo test -p netscope-desktop` → 18 passed |
| 10 | **Bütünleşik test kapsamı dar** | `crates/core/tests/integration_test.rs` tek dosya. TUI+core ve Desktop+core uçtan uca senaryolar hâlâ kapsanmıyor. | — |
| 11 | **WASM glue'da otomatik üretilmiş TODO** | `desktop/frontend/wasm/netscope_wasm.js` — wasm-bindgen çıktısı, elle düzeltilmemeli. Düşük öncelik. | — |
| 15 | **npcap-sdk ikilileri git geçmişinde** | HEAD'den çıkarıldı (#13), ama `fe556b8` ve öncesi commit'lerde `wpcap.lib` / `Packet.lib` duruyor. Depo halka açılmadan önce `git filter-repo --path npcap-sdk --invert-paths` ile geçmişten silinmeli — **destructive, force-push gerektirir**, o yüzden bilinçli bir kararla yapılmalı. | `git log --all --oneline -- npcap-sdk \| head` |

## ✅ Doğrulanıp Kapatılanlar (2026-07-29 akşam)

| Eski # | Sorun | Bulgu |
|---|---|---|
| 1 | `netscope-server` derlenmiyor | **✅ Derleniyor.** 3 clippy uyarısı düzeltildi, format temizlendi. |
| 6 | `netscope-server` clippy uyarıları | **✅ Sıfır uyarı.** `assign_op_pattern` + 2x `useless_format` düzeltildi. |
| 7 | `netscope-server` formatlanmamış | **✅ `cargo fmt --check` temiz.** |
| 4 | PQC modülleri imzasız | **✅ HELPER_MODULES'a eklendi.** |
| 5 | npcap-sdk taze klonda build kırılıyor | **✅ `tools/ensure-npcap-sdk.ps1` + README güncellemesi.** |
| — | Önceki kapatılanlar (2026-07-29 sabih) | 12 madde: `unreachable!`, `unwrap()`, sqlx uyumu, import, stage, `.env.example`, WASM boyutu, TUI test, console.log, bandwidth test, "compound" trigger. |

## Sağlık Durumu (2026-07-29 akşam)

| Ölçüm | Durum |
|---|---|
| `cargo check --workspace --exclude netscope-desktop` | ✅ sıfır hata |
| `cargo clippy --workspace --exclude netscope-desktop -- -D warnings` | ✅ sıfır uyarı |
| `cargo fmt --check` | ✅ temiz |
| Test | ✅ **2 290 geçti**, 0 başarısız |

> `cargo test` **`RUST_MIN_STACK=134217728` gerektirir** — `.cargo/config.toml`
> bunu zaten set ediyor. Ortamda daha küçük bir değer export edilmişse cargo onu
> ezmez ve codegen `STATUS_STACK_OVERFLOW` ile ölür.
