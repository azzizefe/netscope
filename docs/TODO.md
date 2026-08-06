# Netscope Kıdemli Geliştirici Teknik Yapılacaklar Listesi (Senior Backlog & TODO)

Bu döküman, Netscope sistemini yayın öncesi olgunluğa ulaştırmak amacıyla, codebase içerisindeki mimari boşlukları kapatacak senior seviyesindeki teknik görevleri ve çözüm yönergelerini içerir.

---

## 1. Depo Sağlığı & Güvenlik (Repository Health & Compliance)

### 1.1. Git Depo Geçmişinin Arındırılması
*   **Sorun:** Npcap SDK'ya ait statik ve dinamik kütüphaneler (`npcap-sdk/Lib/x64/wpcap.lib` vb.) geçmiş commit'lerde yer almaktadır. Lisans uyumluluğu açısından deponun geçmişinden bu izlerin tamamen kaldırılması gerekir. Ayrıca `dist/` altındaki build çıktılarından arındırılarak `.git/` boyutunun küçültülmesi elzemdir.
*   **Görevler:**
    - [x] `git-filter-repo` kullanarak geçmişteki `npcap-sdk` dizinini ve `dist/` binary dosyalarını temizleyin.
    - [x] Force-push sonrası eski commit'lerin GitHub sunucularında önbellekten silinmesi için Garbage Collection (GC) talebi açın veya depoyu temiz geçmişle yeni bir URL'e taşıyın.
    - [x] `[ensure-npcap-sdk.ps1](file:///c:/Users/efe/Desktop/netscope/tools/ensure-npcap-sdk.ps1)` script'inin taze klonlarda sorunsuz çalıştığını onaylayın.

### 1.2. CI/CD Pipeline Yeşillendirilmesi
*   **Sorun:** `main` dalındaki son commit'lerde wasm32 derleme koşulları yerelde çözülmüş olsa da CI üzerinde lint ve testler hata vermektedir.
*   **Görevler:**
    - [x] `.github/workflows/ci.yml` altındaki runner yetki ve paket bağımlılıklarını güncelleyin.
    - [x] Linux ortamı için `libpcap-dev` kütüphanesini ve `CAP_NET_RAW` yetkilerini test adımlarına entegre edin.
    - [x] Wasm platformu bağımlılıklarının (`wasm-bindgen-cli`) CI runner'ında doğru versiyonla kurulu olduğunu teyit edin.

---

## 2. Çekirdek Protokol Motoru (Dissectors & Engine Architecture)

### 2.1. Dissector Modüllerinin Dispatch Mekanizmasına Bağlanması
*   **Sorun:** Çekirdekte derlenen 141 dissector modülü (`[can.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/can.rs)`, `[qpack.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/qpack.rs)` vb.) hiçbir paket yakalama veya okuma yolu tarafından tetiklenmemektedir. Tanıma imzaları (magic bytes) eksiktir.
*   **Görevler:**
    - [x] Erişim sağlanamayan dissector modüllerine `looks_like_*` veya header bazlı imza tanıma fonksiyonları ekleyin.
    - [x] Bu modülleri `[bindings.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/bindings.rs)` içerisindeki statik `TCP_PORTS` veya `UDP_PORTS` arama tablolarına veya `[dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs)`'deki yapısal sniff aşamalarına bağlayın.
    - [x] Port atamalarında "guessing" (tahmin) yapmaktan kaçının; sadece IANA kayıtlı standart portları veya güvenli yapısal eşleşmeleri (structural sniffs) kullanın.
    - [x] `cargo test -p netscope-core --lib every_dissector_module_is_reachable` entegrasyon testini aktifleştirin ve geçmesini sağlayın.

### 2.2. ProtocolRegistry Uyumluluğu
*   **Sorun:** 1,938 protokol beyan edilmiş (Declared) ancak dissector tarafında karşılığı üretilmemektedir (Dissected).
*   **Görevler:**
    - [x] Beyan edilen protokollerin gerçekten çözümlenebilmesi için dissector modüllerinin gövdelerini doldurun.
    - [x] Çözümleme adımlarında `Protocol::produced()` fonksiyonunun doğru veri döndürdüğünü doğrulayın.

---

## 3. Platforma Özel Yetenekler (OS Integrations)

### 3.1. Çoklu Platform Güvenlik Duvarı Bloklama (Firewall Driver)
*   **Sorun:** `[firewall.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs)` üzerindeki IP engelleme mantığı yalnızca Windows işletim sisteminde `netsh` üzerinden çalışmaktadır. Unix sistemler stub modundadır.
*   **Görevler:**
    - [x] **Linux Backend:** `nftables` entegrasyonunu yazın. Uygulama ilk yetki kontrolünde bir `netscope` tablosu ve `filter` zinciri tanımlamalı, ardından IP engellemek için bu zincire kurallar eklemelidir:
        ```bash
        nft add table inet netscope
        nft add chain inet netscope filter { type filter hook input priority filter \; policy accept \; }
        nft add rule inet netscope filter ip saddr <ip> drop
        ```
    - [x] **macOS Backend:** `pfctl` (Packet Filter) tabanlı engelleme geliştirin. Dinamik anchor yapıları üzerinden kural ekleyip silme mantığını implemente edin.
    - [x] `is_supported()` fonksiyonunu hedef platforma göre dinamik hale getirin.
    - [x] Bloklanan IP kurallarının temizlenmesi için `unblock_all` metodunun Unix tarafında düzgün çalışmasını (kural zincirinin temizlenmesini) sağlayın.

### 3.2. macOS Notarization & Universal Binary Paketleme
*   **Sorun:** macOS masaüstü sürümü sadece Apple Silicon (`aarch64`) üstünde paketlenmekte ve Gatekeeper doğrulamalarından geçmemektedir.
*   **Görevler:**
    - [x] `.github/workflows/release.yml` içerisine `universal-apple-darwin` hedef mimarisini ekleyin ve `lipo` kullanarak binary'leri birleştirin.
    - [x] Apple Developer hesabı bilgilerini GitHub Secrets üzerinden `xcrun notarytool` aracına aktaracak release adımlarını yazın.

---

## 4. Masaüstü Uygulaması & Tauri Arayüz Kararlılığı

### 4.1. Tauri Command Test Kapsamının Artırılması
*   **Sorun:** `[main.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/src/main.rs)` içerisindeki 38 Tauri komutunun 25'i test edilmemiştir. Birçok komut donanım veya yetki bağımlıdır.
*   **Görevler:**
    - [x] Donanım arayüzü sorgulayan (`start_capture`, `list_interfaces`) komutlar için bağımlılık enjeksiyonu (Dependency Injection) yapısını kurarak donanım katmanını soyutlayın.
    - [x] Tauri `State` objelerini mock'layabilmek için test ortamında `tauri::mock::mock_builder()` yapısını kullanın.
    - [x] `cargo test -p netscope-desktop` komutunun test kapsamını artırarak regresyonları engelleyin.

### 4.2. WASM Filtre Motoru Entegrasyon Testleri
*   **Sorun:** Arayüz tarafında çalışan `netscope-wasm` modülünün UI veri akışıyla olan entegrasyonu otomatik test edilmemiştir.
*   **Görevler:**
    - [x] `desktop/frontend-tests/` dizinindeki vitest testlerine, WASM modülünün Tauri'den gelen paket datasıyla etkileşime girdiği uçtan uca senaryoları ekleyin.

---

## 5. Ajan & Sunucu (Fleet Management Architecture)

### 5.1. Güvenli Ajan Güncelleme Flow'u (Self-Upgrade Hardening)
*   **Sorun:** `[upgrade.rs](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/upgrade.rs)` modülü imzasız güncelleme paketlerini reddetmektedir ancak imzalama/doğrulama akışı production anahtarlarıyla test edilmemiştir.
*   **Görevler:**
    - [x] Güncelleme doğrulaması için Ed25519 asimetrik şifreleme altyapısını kurun. Gömülü public key'i ajan binary'sine gömün.
    - [x] CI/CD pipeline'ına, release üretildiğinde agent binary'sini private key ile imzalayıp imza dosyasını (`.sig`) üreten bir adım ekleyin.
    - [x] Pozitif upgrade senaryolarını test etmek amacıyla test fixture'larına geçerli imzalı test ajanları ekleyin.

### 5.2. gRPC/REST İletişim Güvenliği
*   **Sorun:** Fleet yönetimindeki haberleşme kanalları TLS zorunluluğuna sahip değildir.
*   **Görevler:**
    - [x] Sunucu ve ajan arasındaki haberleşmede karşılıklı TLS (mTLS) zorunluluğunu aktif edin.
    - [x] Ajan bazlı scoped API key yetkilendirme katmanını gRPC interceptor'ları ile entegre edin.

---

## 6. Manuel Test Doğrulama (QA Automation Fallbacks)

Birim testleriyle doğrulanamayan aşağıdaki kritik yolları sürümler öncesi test matrisine dahil edin:
*   [x] **Ring Buffer Disk Basıncı:** Disk doluluğunda `rotate.rs` modülünün eski dosyaları başarıyla sildiğini ve programın çökmediğini doğrulayın (Bkz. `[UNTESTED.md](file:///c:/Users/efe/Desktop/netscope/UNTESTED.md)` Bölüm 1).
*   [x] **Canlı SSH Tcpdump Tünelleme:** Ajanın uzak sunucularda `RemoteSpec` üzerinden başlattığı SSH tcpdump paket akışını canlı arayüze aktarabildiğini manuel doğrulayın.
*   [x] **Fuzzing ve Bozuk Paketler:** Hatalı IP header'ları veya kesik TCP paketleri gönderildiğinde dissector motorlarının panik yapmadan (unwrap/panic) hata ayıklayabildiğini teyit edin.
