# Netscope Açık Kaynak Lansmanı & Windows .EXE Dağıtım Rehberi

Netscope uygulamasını Windows üzerinde çalıştırılabilir bir `.exe` (veya yükleyici paketi) haline getirip **GitHub üzerinde açık kaynak (Open Source) olarak paylaşmadan önce** yapılması gereken kritik yasal, teknik ve dağıtımsal adımlar aşağıda listelenmiştir.

Bu rehber, senior seviyesinde bir açık kaynak lansman check-list'i sunar.

---

## 1. Yasal Uyum & Temizlik (Deponun Açık Kaynağa Hazırlanması)

Projeyi halka açık (public) hale getirmeden önce kod geçmişindeki yasal risklerin temizlenmesi gerekir.

### 1.1. Npcap SDK Lisans Temizliği (Kritik)
*   **Açıklama:** Npcap (Windows için paket yakalama sürücüsü) lisansı, SDK kütüphanelerinin (`wpcap.lib`, `Packet.lib`) ticari veya kontrolsüz olarak başka depolarda yeniden dağıtılmasına izin vermez.
*   **Yapılması Gerekenler:**
    - [ ] `[yapilmasigerekenler.md](file:///c:/Users/efe/Desktop/netscope/docs/yapilmasigerekenler.md)` Adım 1'de belirtilen `git-filter-repo` komutlarını çalıştırarak `npcap-sdk` dizinini geçmiş commit'lerden tamamen silin.
    - [ ] Kullanıcılar için `[ensure-npcap-sdk.ps1](file:///c:/Users/efe/Desktop/netscope/tools/ensure-npcap-sdk.ps1)` script'ini açık kaynak kodda referans gösterin; kullanıcılar SDK'yı doğrudan resmi Npcap sitesinden bu script ile çekmelidir.

### 1.2. Hassas Veri (Secret) Kontrolü
*   **Yapılması Gerekenler:**
    - [ ] Kod tabanında yanlışlıkla commit edilmiş hiçbir yerel API Key, TLS özel anahtarı (private key), veritabanı şifresi veya test credential'ı olmadığından emin olun (örn. `.env` dosyası ignore edilmiştir fakat geçmişte kalıp kalmadığı kontrol edilmelidir).

---

## 2. Windows .EXE Derleme ve İmzalanması (SmartScreen Çözümü)

İmzasız `.exe` dosyaları Windows Defender ve SmartScreen tarafından bloke edilir. Açık kaynak projenizin ilk indirenler tarafından güvenle çalıştırılabilmesi için aşağıdaki adımları izleyin.

### 2.1. Kod İmzalama (Code Signing)
*   **Geliştirici Sertifikası Kullanımı:**
    - [ ] Eğer kurumsal bir yayınlama yapacaksanız, Certum, DigiCert veya Sectigo gibi yetkili otoritelerden bir **EV Code Signing Certificate (Sertifika)** edinin.
    - [ ] CI/CD tarafında imzalama yapmak için PFX sertifikanızı GitHub Secrets (`WINDOWS_PFX_FILE`, `WINDOWS_PFX_PASSWORD`) olarak ekleyin.
*   **Açık Kaynak Alternatifi (SignPath & SignPath Foundation):**
    - [ ] Açık kaynak projeleri için ücretsiz kod imzalama sertifikası sunan **SignPath Foundation** programına başvurun. Bu sayede GitHub Actions üzerinden derlenen `.exe` dosyalarınız ücretsiz olarak imzalanabilir.

### 2.2. UAC (Yönetici Yetkisi) Açıklaması
*   **Açıklama:** Netscope, ham ağ paketlerini yakaladığı ve IP bloklayabildiği için Windows'ta yönetici yetkilerine (`requireAdministrator`) ihtiyaç duyar.
*   **Yapılması Gerekenler:**
    - [ ] `[build.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/build.rs)` içerisindeki manifest yapılandırmasının release modda UAC penceresini tetiklediğini doğrulayın.
    - [ ] README dosyanıza, uygulamanın neden yönetici yetkisi istediğini açıkça yazarak topluluğun güvenini kazanın.

---

## 3. GitHub Depo Hazırlıkları (Açık Kaynak Standartları)

Projenin GitHub'da yıldız (star) alması ve katkıcı (contributor) çekebilmesi için gerekli standart dokümanlar:

### 3.1. README.md Güncellemesi
*   **Yapılması Gerekenler:**
    - [ ] Projenin ne işe yaradığını gösteren yüksek kaliteli görseller (ekran görüntüleri / TUI GIF'leri) ekleyin.
    - [ ] Windows için Npcap gereksinimini açıkça belirtin.
    - [ ] Hızlı kurulum (Quick Start) komutlarını ve `.exe` indirme butonlarını en başa koyun.

### 3.2. Katkı Sağlama Kılavuzu (CONTRIBUTING.md)
*   **Yapılması Gerekenler:**
    - [ ] Yeni bir dissector modülünün nasıl yazılacağını, testlerin nasıl çalıştırılacağını (`cargo test --workspace`) açıklayan katkıcı rehberi hazırlayın.

### 3.3. GitHub Issue & PR Şablonları
*   **Yapılması Gerekenler:**
    - [ ] `.github/ISSUE_TEMPLATE/` altında **Bug Report** ve **Feature Request** şablonları oluşturun.
    - [ ] Çözümleyici (dissector) istekleri için özel bir şablon ekleyin (örn: *"Hangi protokolü istiyorsunuz? RFC linki veya örnek PCAP dosyası ekleyin"*).

---

## 4. Yayınlama ve Topluluk Lansmanı Stratejisi

### 4.1. GitHub Releases Entegrasyonu
*   **Yapılması Gerekenler:**
    - [ ] `.github/workflows/release.yml` dosyasının, her `v*.*.*` etiketinde (tag) otomatik olarak yeni bir release oluşturup imzalı `.exe`, `.msi` ve `.zip` dosyalarını release asset olarak eklediğini doğrulayın.

### 4.2. Windows WinGet Dağıtımı
Kullanıcıların uygulamayı terminalden tek komutla kurabilmesi açık kaynak projelerin popülaritesini artırır.
*   **Yapılması Gerekenler:**
    - [ ] Projeyi Windows Package Manager (WinGet) reposuna eklemek için bir winget manifest hazırlayın. Kullanıcılar şu şekilde kurabilmelidir:
      ```powershell
      winget install netscope
      ```

### 4.3. Lansman Kanalları (Nerede Duyurmalıyım?)
Proje kararlı hale geldikten sonra duyuru yapabileceğiniz en etkili platformlar:
1.  **Reddit (r/rust & r/networking):** Rust topluluğu ağ programlama araçlarını çok sever. "Pure Rust Network Analyzer with Tauri & Ratatui" başlığı ile paylaşın.
2.  **Hacker News:** Teknik detayı yüksek, performans odaklı (ring buffer, multi-queue RSS load balancer detayları içeren) bir blog yazısı ile HN'de paylaşım yapın.
3.  **Rust Weekly (Weekly Rust Newsletter):** Projeyi haftalık Rust bültenine submit edin.
