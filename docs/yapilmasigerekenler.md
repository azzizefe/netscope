# Netscope Tamamlama Master Checklist (Yapılması Gerekenler)

Bu dosya, Netscope sistemini sıfır hata ile tamamlamak ve yayına hazır hale getirmek için çalıştırmanız gereken komutları, yapmanız gereken kod değişikliklerini ve doğrulama aşamalarını adım adım takip edebilmeniz için hazırlanmıştır.

---

## 1. Adım: Depo Temizliği & Lisans Güvenliği (Git History Cleanup)
> [!CAUTION]
> Npcap SDK binary dosyalarının geçmişten silinmesi yasal uyumluluk için zorunludur.

- [x] **1.1. Deponun yedeğini alın:**
  ```bash
  git clone --mirror . ../netscope-mirror-backup.git
  ```
- [x] **1.2. Geçmişteki `npcap-sdk` ve büyük binary dosyalarını temizleyin:**
  ```bash
  git filter-repo --invert-paths \
    --path npcap-sdk \
    --path dist/windows/netscope.exe \
    --path dist/windows/netscope_0.1.0_x64-setup.exe \
    --path dist/windows/netscope_0.1.0_x64_en-US.msi \
    --path dist/netscope-windows-v0.1.0-x64.zip
  ```
- [x] **1.3. Uzak depo adresini (remote) yeniden bağlayın:**
  ```bash
  git remote add origin https://github.com/azzizefe/netscope.git
  ```
- [x] **1.4. Geçmişi force-push ile güncelleyin:**
  ```bash
  git push --force --all origin
  git push --force --tags origin
  ```

---

## 2. Adım: Yerel Geliştirme Ortamı & İlk Derleme (Local Compilation)
- [x] **2.1. Npcap SDK'yı yerel çalışma alanınıza indirin:**
  PowerShell üzerinden `[ensure-npcap-sdk.ps1](file:///c:/Users/efe/Desktop/netscope/tools/ensure-npcap-sdk.ps1)` script'ini çalıştırın:
  ```powershell
  .\tools\ensure-npcap-sdk.ps1
  ```
- [x] **2.2. WebAssembly modülünü derleyin:**
  Masaüstü arayüzünün filtreleme yetenekleri için WASM glue kodlarını üretin:
  ```powershell
  .\tools\build-wasm.ps1
  ```
- [x] **2.3. Tüm çalışma alanını derleyin (Debug):**
  ```bash
  cargo check --workspace
  ```

---

## 3. Adım: Çekirdek Kod Tabanı & Çözümleyiciler (Dissectors Integration)
- [x] **3.1. 141 imzasız dissector modülüne tanıma fonksiyonu ekleyin:**
  Erişilemeyen dissector modüllerine (örn. `[can.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/can.rs)`, `[qpack.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/qpack.rs)`) sihirli bayt (magic byte) veya `looks_like_*` tanıma algoritmaları yazın.
- [x] **3.2. Çözümleyicileri dispatch tablosuna bağlayın:**
  `[bindings.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/bindings.rs)` dosyasındaki `TCP_PORTS` veya `UDP_PORTS` statik dizilerine port eşleşmelerini ekleyin.
- [x] **3.3. Testi aktifleştirin ve doğrulayın:**
  `[dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs)` altındaki `every_dissector_module_is_reachable` entegrasyon testinin `#[ignore]` etiketini kaldırın ve testi koşturun:
  ```bash
  cargo test -p netscope-core --lib every_dissector_module_is_reachable
  ```

---

## 4. Adım: Çoklu Platform Güvenlik Duvarı (Multi-Platform Firewall)
- [x] **4.1. Linux `nftables` desteğini ekleyin:**
  `[firewall.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs)` altındaki `cfg(not(windows))` modülünü düzenleyerek Linux için `Command::new("nft")` çağrıları ile kural ekleme/silme (block/unblock) mantığını implemente edin.
- [x] **4.2. macOS `pfctl` desteğini ekleyin:**
  `[firewall.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs)` içerisine macOS için `pfctl` anchor manipülasyon kodlarını ekleyin.
- [x] **4.3. Platform destek flag'ini güncelleyin:**
  `is_supported()` fonksiyonunun Windows, Linux ve macOS için `true` dönmesini sağlayın.
- [x] **4.4. Testleri çalıştırın:**
  ```bash
  cargo test -p netscope-core --lib support_flag_matches_platform
  ```

---

## 5. Adım: Test Kapsamı & Masaüstü Uygulaması (Tauri v2)
- [x] **5.1. Eksik Tauri Komut Testlerini Yazın:**
  `[main.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/src/main.rs)`'teki 25 adet testsiz komut (örn. `start_capture`, `arp_scan`) için mock Tauri `State` yapıları oluşturarak test kapsamını genişletin.
- [x] **5.2. Masaüstü testlerini koşturun:**
  ```bash
  cargo test -p netscope-desktop
  ```
- [x] **5.3. Arayüz (Frontend) birim testlerini çalıştırın:**
  `desktop/frontend-tests/` dizininde:
  ```bash
  npm test
  ```

---

## 6. Adım: Ajan & Sunucu Entegrasyonu (Fleet & Security Hardening)
- [x] **6.1. Güvenli Ajan Güncellemesini Kurun:**
  `[upgrade.rs](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/upgrade.rs)` modülünde, güncellemeleri doğrulamak için Ed25519 asimetrik anahtar kontrolünü aktifleştirin.
- [x] **6.2. gRPC mTLS Entegrasyonu:**
  Sunucu ([`netscope-server`](file:///c:/Users/efe/Desktop/netscope/crates/server)) ve Ajan ([`netscope-agent`](file:///c:/Users/efe/Desktop/netscope/crates/agent)) arasındaki bağlantılara TLS 1.3/mTLS desteği ekleyin.

---

## 7. Adım: Windows Paketleme & Dağıtım (Production Build)
- [x] **7.1. Kod İmzalama Sertifikasını Tanımlayın:**
  PowerShell üzerinde PFX sertifikanızı ve şifrenizi ortam değişkeni olarak export edin:
  ```powershell
  $env:TAURI_SIGNING_PRIVATE_KEY = "C:\yol\sertifika.pfx"
  $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "SertifikaSifreniz"
  ```
- [x] **7.2. Yükleyici Paketlerini Derleyin (MSI / NSIS):**
  ```bash
  cargo tauri build
  ```
- [x] **7.3. Çıktı Paketlerini Manuel Test Edin:**
  Oluşan setup dosyalarını ([`WINDOWS_BUILD_GUIDE.md`](file:///c:/Users/efe/Desktop/netscope/docs/WINDOWS_BUILD_GUIDE.md) referansıyla) temiz bir Windows makinede veya sandbox ortamında kurarak UAC yetki istemlerini ve paket yakalamayı doğrulayın.

---

## 8. Adım: Manuel QA Kontrolleri (Son Doğrulama)
- [x] **8.1. Disk Doluluk Tolerans Testi:**
  Diski yapay olarak doldurarak `rotate.rs` modülünün sorunsuzca durduğunu ve arayüzde hata mesajı gösterildiğini test edin.
- [x] **8.2. Bozuk Paket Giriş Testi (Crash Prevention):**
  Bozuk/kesik byte'lar içeren pcap dosyalarını sürükleyip bırakarak uygulamanın panik yapmadan (crash) çalıştığını doğrulayın.
- [x] **8.3. Sürüm Öncesi Kontrol Listesini Tamamlayın:**
  `[MANUAL_TESTING_GUIDE.md](file:///c:/Users/efe/Desktop/netscope/docs/MANUAL_TESTING_GUIDE.md)` altındaki test formunu doldurup onaylayın.
