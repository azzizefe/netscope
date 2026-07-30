# Netscope — Eksik Kritik Bileşenler & Kritik Hatalar

> Son doğrulama: **2026-07-30**. Aşağıdaki her satır `cargo check` /
> `cargo test` / `cargo clippy` / `cargo fmt` çalıştırılarak yeniden ölçüldü.
> Bir maddeyi kapatmadan önce **doğrulama komutunu çalıştır**.
>
> ⚠️ **Ölçümlerin hepsi Windows'ta yapıldı.** macOS ve Linux için tek kanıt
> kaynağı CI'dır ve CI şu an kırmızıdır (#17) — "üç platformda da çalışıyor"
> cümlesi bugün kurulamaz.

## 🔴 Kritik (CRITICAL)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 17 | **CI `main` üzerinde kırmızı — üç platformda birden** | Son 3 koşu (28/29/30 Temmuz) `failure`. En son koşu commit `6cc9bac5`: lint, Tests(ubuntu), Tests(macos), Tests(windows) ve Frontend hepsi exit 101/1. **Ama `6cc9bac5` yerelin 9 commit gerisinde** ve o commitlerden biri (`39bd7ef`) wasm32 gating'ini düzeltiyor. Yerelde HEAD'de clippy/fmt/test temiz. **Depo halka açılmadan önce push edilip CI'ın yeşile dönmesi görülmeli** — açık kaynak bir depoda ilk izlenim kırmızı rozet olmamalı. Loglar admin gerektirdiği için (API 403) kök neden yalnız CI'da doğrulanabilir. | `git push` → Actions |
| 18 | **macOS'ta Intel (x86_64) yapı yok, imza/notarization yok** | `release.yml` yalnız `aarch64-apple-darwin` TUI ve `macos-latest` üstünde arm64 `.dmg` üretiyor. Notarization adımı kodda açıkça "placeholder, does nothing". Sonuç: Intel Mac kullanıcısı hiçbir şey indiremiyor, Apple Silicon kullanıcısı Gatekeeper duvarına çarpıyor. README artık bunu yazıyor; **çözüm** `universal-apple-darwin` hedefi + `APPLE_*` secret'ları ile notarization. | `.github/workflows/release.yml` |

## 🟠 Yüksek (HIGH)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| ~~12~~ | ~~**Taze klon build edilemiyor: 3 build-kritik dosya `.gitignore` tarafından yutulmuş**~~ | ~~`.cargo/config.toml` (`.cargo/` ignore'lu → `RUST_MIN_STACK` ve `LIBPCAP_LIBDIR` yok), `fixtures/*.pcap` (`*.pcap` ignore'lu → `integration_test.rs` fail), `.env.example` (`.env.*` ignore'lu).~~ **✅ Kurallar daraltıldı, üçü de commit'lendi.** `*.pcap` binary olarak işaretlendi (CRLF bozulmasına karşı). | `git clone` → `ls .cargo/config.toml fixtures/ .env.example` |
| ~~13~~ | ~~**npcap-sdk ikilileri depoda (lisans ihlali riski)**~~ | ~~`.gitignore` `npcap-sdk/`'yı dışlamasına rağmen 28 dosya (`wpcap.lib`, `Packet.lib` dâhil) izleniyordu — Npcap lisansı yeniden dağıtıma izin vermiyor, MIT depoda yayınlanamaz.~~ **✅ `git rm --cached`.** Disk üzerinde kalıyor, `tools/ensure-npcap-sdk.ps1` indiriyor. **Not: git geçmişinde hâlâ duruyor**; halka açılmadan önce history rewrite gerekir. | `git ls-files npcap-sdk` → boş |
| ~~14~~ | ~~**Frontend testleri taze klonda çöküyor**~~ | ~~`desktop/frontend-tests/load-app.js` `desktop/frontend/wasm/netscope_wasm.js` + `_bg.wasm` dosyalarını doğrudan okuyor; bunlar build çıktısı (ignore'lu) ve hiçbir yerde belgelenmemişti.~~ **✅ `tools/build-wasm.{ps1,sh}` eklendi**, README/CONTRIBUTING/setup.md'de belgelendi. | `.\tools\build-wasm.ps1` → `npm test` (173 test) |
| 2 | **141 dissector modülü dispatch'ten erişilemiyor** (2026-07-30 ölçümü) | Modüller derleniyor, kendi testleri geçiyor, ama hiçbir çağrı yolu yok. Çoğunun **tanıma imzası yok** (magic byte / `looks_like_*` yok) — bu yüzden basit "wiring" ile çözülmez. **Tahmini porta bağlamak yasak**: bu depoda 3 kez gerçek hataya yol açtı (`bindings.rs` başındaki kurala bak). | `cargo test -p netscope-core --lib every_dissector_module_is_reachable -- --ignored` |
| ~~3~~ | ~~**1941 protokol registry'de ama hiçbir dissector üretmiyor**~~ | 2531 satırın 590'ı üretiliyor. **✅ Kullanıcıya yalan söylenmiyor artık:** her satırda `status: Dissected \| Declared` var, listeleme yüzeyleri (`filtre`, Learn sekmesi, protokol sayacı) `Protocol::produced()` kullanıyor. `Protocol::ALL` ve `protocol_table()` bilinçli olarak tam kalıyor — *çözümleme* her satıra cevap vermeli, *listeleme* ise bir vaat. Denetim testi artık `#[ignore]` değil ve alanı **iki yönde** zorluyor. **Kalan iş: 1941 satırı gerçekten bağlamak** (madde 2 ile aynı iş). | `cargo test -p netscope-core --lib declared_status_matches_the_dispatch` |
| ~~4~~ | ~~**4 yeni PQC modülü imzasız**~~ | ~~`pqc_cve_feed_integration`, `tls_cert_transparency_v3`, `tls_ech_pqc_interop`, `tls_session_resumption_pqc`~~. **✅ HELPER_MODULES'a eklendi** (analiz geçişleri, tel üzerinde protokol değil). | `dissectors.rs:3073` `HELPER_MODULES` |
| ~~5~~ | ~~**npcap-sdk taze klonda build'i kırıyor**~~ | ~~`.gitignore` `npcap-sdk/`'yı dışlıyor, `.cargo/config.toml` ise `LIBPCAP_LIBDIR`'ı repo köküne göreli `npcap-sdk/Lib/x64`'e sabitliyor.~~ **✅ Düzeltildi:** `tools/ensure-npcap-sdk.ps1` eklendi, README güncellendi. Taze klonda `.\tools\ensure-npcap-sdk.ps1` çalıştırmak yeterli. | `tools/ensure-npcap-sdk.ps1` |

## 🟡 Orta (MEDIUM)

| # | Sorun | Detay | Doğrulama |
|---|---|---|---|
| 8 | **`target/` 29 GB** | Git sorunu **değil** (`/target` ignore'lu, doğru). Sadece disk: bayat incremental cache. | `cargo clean` |
| 9 | **Desktop komutlarının 25/38'i test edilmemiş** | 2026-07-29 akşam: 10/38'den 13/38'e çıktı (+`save_object`, `list_plugins`, `is_elevated`; 6 yeni test eklendi, toplam 18). Kalanlar donanım (`start_capture`, `arp_scan`, `list_interfaces`), yükseltilmiş yetki (`block_ip`, `list_blocked`) veya Tauri `State` gerektiriyor. | `cargo test -p netscope-desktop` → 18 passed |
| 10 | **Bütünleşik test kapsamı dar** | `crates/core/tests/integration_test.rs` tek dosya. TUI+core ve Desktop+core uçtan uca senaryolar hâlâ kapsanmıyor. | — |
| 11 | **WASM glue'da otomatik üretilmiş TODO** | `desktop/frontend/wasm/netscope_wasm.js` — wasm-bindgen çıktısı, elle düzeltilmemeli. Düşük öncelik. | — |
| ~~19~~ | ~~**4 sahte yakalama arka ucu kullanıcıya yalan söylüyordu**~~ | ~~`CaptureBackend::{AfPacket, AfXdp, PfRing, Dpdk}` seçildiğinde "AF_XDP: Initializing eBPF redirect program…" gibi bir satır basıp sıradan libpcap döngüsünü çalıştırıyordu; yakalama çalıştığı için kimse şüphelenmiyordu.~~ **✅ 2026-07-30: 4 sahte döngü silindi, seçilmeleri artık açık hata.** Hiç okunmayan `fanout_group_id` / `cpu_affinity` / `adaptive_sampling` / `timestamp_precision` alanları da kaldırıldı. SOC raporundaki "DPDK/eBPF-XDP **sağlandı**" iddiası düzeltildi. | `capture.rs` `CaptureBackend` |
| ~~20~~ | ~~**`netscope-agent --service install` Linux/macOS'ta sessizce yanlış çalışıyordu**~~ | ~~Bayrak her platformda clap tarafından kabul ediliyor ama yalnız `cfg(windows)` işliyordu; Unix'te komut servis kurmak yerine ön planda ajan başlatıyor, başarılı görünüyordu.~~ **✅ Unix'te açık hata + systemd/launchd yönlendirmesi.** | `crates/agent/src/main.rs` |
| 21 | **Firewall bloklama yalnız Windows** | `firewall.rs`: `is_supported()` = `cfg!(windows)`; macOS/Linux'ta `block`/`unblock` hata döndürüyor (sessiz no-op **değil**, bu doğru davranış). Sorun kodda değil, **iddiadaydı**: README "installs a real OS firewall rule" diyordu, platform kaydı yoktu. **✅ README düzeltildi.** Kalan iş: `pf` (macOS) ve `nftables` (Linux) arka uçları. | `cargo test -p netscope-core --lib support_flag_matches_platform` |
| 15 | **npcap-sdk ikilileri git geçmişinde** | HEAD'den çıkarıldı (#13), ama `e5c1275` ve `5caf177` commit'lerinde 6 `.lib` (x64/ARM64/root `wpcap.lib`+`Packet.lib`) + başlıklar duruyor. Npcap lisansı yeniden dağıtıma izin vermiyor. **Runbook aşağıda (§Geçmiş temizliği).** ⚠️ Depo hâlihazırda **public** olduğu için bu dosyalar zaten dışarıda; temizlik ileriye dönük, geriye dönük değil. | `git log --all --oneline -- npcap-sdk \| head` |
| 22 | **Kendi build çıktılarımız da geçmişte (47 MB)** | `dist/windows/netscope.exe` (19.6 MB), `dist/netscope-windows-v0.1.0-x64.zip` (16.4 MB), `.msi` (6.4 MB), `-setup.exe` (4.2 MB). Lisans sorunu değil — sadece `.git`'i 82 MB'a şişiriyorlar; taze klon herkese bu bedeli ödetiyor. #15 temizliğiyle **aynı geçişte** silinmeli. | `du -sh .git` → 82M |

## Geçmiş temizliği — runbook (#15 + #22)

**Yıkıcı.** Tüm commit SHA'ları değişir, force-push gerekir, klonu olan herkes
yeniden klonlamak zorunda kalır. Sırayla:

```bash
# 0) Geri dönüşü olan bir yedek — bu adımı atlama
git clone --mirror . ../netscope-history-backup.git

# 1) Aracı kur (git filter-branch değil; upstream artık bunu öneriyor)
pip install git-filter-repo

# 2) Çalışma ağacı temiz olmalı
git status --short          # boş olmalı

# 3) Npcap SDK'yı ve kendi ikililerimizi tek geçişte sil
git filter-repo --invert-paths \
  --path npcap-sdk \
  --path dist/windows/netscope.exe \
  --path dist/windows/netscope_0.1.0_x64-setup.exe \
  --path dist/windows/netscope_0.1.0_x64_en-US.msi \
  --path dist/netscope-windows-v0.1.0-x64.zip

# 4) Doğrula — üçü de boş dönmeli
git log --all --oneline -- npcap-sdk
git rev-list --objects --all | grep -i npcap-sdk
git rev-list --objects --all | grep -iE "\.(exe|msi|zip)$"

# 5) filter-repo remote'u siler, geri ekle
git remote add origin https://github.com/azzizefe/netscope.git

# 6) Force-push (etiketler dâhil — v0.1.0/v0.2.0 da yeniden yazılır)
git push --force --all origin
git push --force --tags origin
```

**Force-push'tan sonra da bitmiyor:** GitHub eski commit'leri bir süre daha
doğrudan SHA ile erişilebilir tutar. Kalıcı silme için GitHub Support'a
"unreachable objects GC" talebi açılmalı. Alternatif: açık kaynak lansmanını
**temiz geçmişli yeni bir depoda** yapmak — geçmiş zaten public olduğu için tek
gerçek "temiz sayfa" budur.

## ✅ Doğrulanıp Kapatılanlar (2026-07-29 akşam)

| Eski # | Sorun | Bulgu |
|---|---|---|
| 1 | `netscope-server` derlenmiyor | **✅ Derleniyor.** 3 clippy uyarısı düzeltildi, format temizlendi. |
| 6 | `netscope-server` clippy uyarıları | **✅ Sıfır uyarı.** `assign_op_pattern` + 2x `useless_format` düzeltildi. |
| 7 | `netscope-server` formatlanmamış | **✅ `cargo fmt --check` temiz.** |
| 4 | PQC modülleri imzasız | **✅ HELPER_MODULES'a eklendi.** |
| 5 | npcap-sdk taze klonda build kırılıyor | **✅ `tools/ensure-npcap-sdk.ps1` + README güncellemesi.** |
| — | Önceki kapatılanlar (2026-07-29 sabih) | 12 madde: `unreachable!`, `unwrap()`, sqlx uyumu, import, stage, `.env.example`, WASM boyutu, TUI test, console.log, bandwidth test, "compound" trigger. |

## Sağlık Durumu (2026-07-30, Windows / `x86_64-pc-windows-gnu`)

| Ölçüm | Durum |
|---|---|
| `cargo clippy --workspace --exclude netscope-desktop -- -D warnings` | ✅ sıfır uyarı |
| `cargo fmt --check` | ✅ temiz |
| `cargo test -p core -p tui -p server -p agent` | ✅ **2 397 geçti**, 0 başarısız, 4 ignored |
| Frontend `npm test` (vitest) | ✅ **173/173** |
| `cargo test -p netscope-desktop` | ⚠️ **ölçülemedi** — eşzamanlı `cargo tauri dev` `netscope-desktop.exe`'yi kilitliyor, `build.rs` os error 32 ile düşüyor. Kod hatası değil; uygulama kapalıyken yeniden ölç |
| macOS / Linux | ⚠️ **bu makineden ölçülemez.** Tek kanıt CI ve CI `main`'de kırmızı (madde #17) |

> `cargo test` **`RUST_MIN_STACK=134217728` gerektirir** — `.cargo/config.toml`
> bunu zaten set ediyor. Ortamda daha küçük bir değer export edilmişse cargo onu
> ezmez ve codegen `STATUS_STACK_OVERFLOW` ile ölür.
