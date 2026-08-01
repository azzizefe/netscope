# Netscope Uçtan Uca Manuel Test Kılavuzu

Bu kılavuz, Netscope sisteminin otomatik birim/entegrasyon testleriyle tam olarak doğrulanamayan platforma özel, donanım bağımlı ve yetki gerektiren tüm özelliklerini uçtan uca manuel olarak nasıl test edeceğinizi açıklamaktadır.

---

## 1. Hazırlık ve Çevresel Kurulumlar

Manuel testleri yapabilmek için ilgili platformlarda aşağıdaki ön gereksinimlerin kurulmuş olması gerekir:

### 1.1. Windows İşletim Sistemi
*   **Npcap Sürücüsü:** Paket yakalayabilmek için [Npcap](https://npcap.com/) kurulu olmalıdır. Kurulum sırasında *"Install Npcap in WinPcap API-compatible Mode"* seçeneği işaretlenmelidir.
*   **Yönetici Yetkisi:** Güvenlik duvarı bloklama ve canlı paket yakalama testleri için PowerShell/CMD penceresi **"Yönetici Olarak Çalıştır"** (Elevated) ile açılmalıdır.
*   **USB Yakalama (İsteğe bağlı):** USB trafiği yakalamak için USBPcap kurulumu yapılmış olmalıdır.

### 1.2. Linux İşletim Sistemi
*   **libpcap Geliştirici Kitleri:** Canlı yakalama için:
    ```bash
    sudo apt install libpcap-dev nftables
    ```
*   **Ağ Ayrıcalıkları:** Root olmadan paket yakalayabilmek için netscope binary'sine özel yetki verilmelidir:
    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip <binary_yolu>
    ```

### 1.3. macOS İşletim Sistemi
*   **BPF Aygıt Yetkileri:** macOS üzerinde paket yakalama aygıtlarına (`/dev/bpf*`) erişebilmek için terminalin okuma yazma yetkisi olmalıdır:
    ```bash
    sudo chown $USER /dev/bpf*
    ```

---

## 2. Senaryo 1: Canlı Paket Yakalama & Çekirdek (Core Engine) Testleri
Bu senaryo, [capture.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/capture.rs) modülünün gerçek donanım ile etkileşimini test eder.

### 2.1. Ağ Arayüzü Listeleme & Seçim
1.  Netscope TUI veya Desktop uygulamasını başlatın.
2.  Canlı yakalama arayüz listesinde aktif ağ kartınızı (örn. `ethernet_0`, `wlan0`, `en0`) bulun.
3.  Ip adresi alan kartı seçerek yakalamayı başlatın.
4.  **Doğrulama:** Arayüzün yanında IP adresinin ve o karttan anlık akan paket sayacının arttığını doğrulayın.

### 2.2. Paket Yakalama Durdurma Koşulları
Paket yakalayıcının limit yapılandırmalarına doğru yanıt verip vermediğini test edin.
1.  **Paket Limiti Testi:** Ayarlar kısmından yakalama limitini 100 paket olarak ayarlayın. Canlı yakalamayı başlatın. 100 pakete ulaşıldığında yakalamanın otomatik durduğunu doğrulayın.
2.  **Boyut Limiti Testi:** Limiti 1 MB (1.048.576 byte) olarak yapılandırın. Ağda veri indirin. Yakalamanın bu sınıra ulaştığında güvenli bir şekilde sonlandığını doğrulayın.
3.  **Süre Limiti Testi:** Süre limitini 10 saniye yapın. Yakalamayı başlatıp kronometre tutun. 10. saniyede yakalamanın bittiğini görün.

### 2.3. Dosya Rotasyonu (Ring Buffer) & Budama
Bu adım [rotate.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/capture.rs) (ring buffer) davranışını uzun vadeli canlı kullanımda doğrular.
1.  Yakalama ayarlarından maksimum dosya boyutunu `5MB` ve maksimum dosya adedini `3` olarak sınırlayın.
2.  Durdurma koşulu olmadan canlı yakalamayı başlatın ve internetten büyük bir dosya indirerek trafik üretin.
3.  Yakalama dizinine (örn. `target/captures/`) giderek `.pcap` veya `.pcapng` uzantılı dosyaların oluşmasını gözlemleyin.
4.  **Doğrulama:** 4. dosya oluşmaya başladığında en eski dosyanın (1. dosya) otomatik silindiğini ve disk doluluğunun asla belirlenen limiti (15MB) aşmadığını doğrulayın.

---

## 3. Senaryo 2: TUI (Terminal Arayüzü) Manuel Testleri
Bu adımlar, [crates/tui/src/main.rs](file:///c:/Users/efe/Desktop/netscope/crates/tui/src/main.rs) arayüzünü elle kontrol etmek içindir.

### 3.1. PCAP Dosyası ile Çevrimdışı Başlatma
1.  Konsoldan fixture dizinindeki hazır bir paket dosyasını TUI ile açın:
    ```bash
    cargo run -p netscope-tui -- -r fixtures/mixed.pcap
    ```
2.  Arayüzün açıldığını ve paket listesinin yüklendiğini doğrulayın.

### 3.2. Ekranlar Arası Geçiş & Navigasyon
1.  **Sekme Değiştirme:** Klavyeden `Tab` tuşuna basarak 7 ana ekran (Packet List, Protocol Tree, Hex View, Stats, Dashboard, Settings, Alerts) arasında geçiş yapın.
2.  **Yön Tuşları:** Packet List ekranında `Yukarı` ve `Aşağı` ok tuşlarını kullanarak paketler arasında gezinin. Seçilen paketin detayının (alt paneldeki ağaç yapısı ve hex dump) anında değiştiğini doğrulayın.
3.  **Arama/Filtreleme:** `F` tuşuna basarak filtre moduna geçin, `tcp.port == 443` yazıp `Enter` tuşuna basın. Listede sadece HTTPS trafiğinin kaldığını doğrulayın. `Esc` ile filtreyi temizleyin.

### 3.3. Headless Mod Doğrulaması
1.  Aşağıdaki komutla TUI'yi arayüzsüz (headless) çalıştırarak analiz edin:
    ```bash
    cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless
    ```
2.  **Doğrulama:** Terminal arayüzü çizilmeden doğrudan analiz özetinin (paket sayısı, protokol dağılımı, kritik uyarılar) stdout'a basıldığını doğrulayın.

---

## 4. Senaryo 3: Desktop Arayüzü (Tauri v2) Testleri
Bu adımlar, [desktop/src-tauri/src/main.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/src/main.rs) masaüstü uygulamasını test eder.

### 4.1. Dev Modunda Çalıştırma
1.  Öncelikle WASM bağımlılıklarını derleyin:
    ```powershell
    .\tools\build-wasm.ps1
    ```
2.  Tauri uygulamasını başlatın:
    ```bash
    npx tauri dev
    ```
3.  Uygulama penceresinin açıldığını ve modern karanlık tema arayüzünün (glassmorphism/vibrant effects) eksiksiz yüklendiğini doğrulayın.

### 4.2. Canlı Yakalama Kontrolleri (Play/Pause/Stop/Clear)
1.  Arayüz listesinden yerel ağ kartınızı seçip **Play** (Oynat) butonuna basın.
2.  Paket listesinin saniyeler içinde yeni gelen satırlarla güncellendiğini doğrulayın.
3.  **Pause** (Duraklat) butonuna basın. Listeye yeni paket eklenmediğini fakat arka planda arabelleğe (ring buffer) yazılmaya devam ettiğini doğrulayın. Yeniden Play'e basınca biriken paketlerin listelendiğini doğrulayın.
4.  **Stop** (Durdur) butonuna basın. Paket alımının tamamen kesildiğini doğrulayın.
5.  **Clear** (Temizle) butonuna basarak listenin sıfırlandığını doğrulayın.

### 4.3. Veri Gizliliği (PII Maskeleme) Testi
1.  Tasarım gereği, log veri tabanına ve arayüze TC Kimlik No, e-posta veya Kredi Kartı gibi kişisel veriler maskelenerek yansıtılmalıdır.
2.  İçinde örnek kredi kartı numaraları ve e-postalar geçen bir test PCAP dosyasını masaüstü uygulamasına sürükleyip bırakın (Drag & Drop).
3.  **Doğrulama:** Paket detayında kredi kartı numarasının `XXXX-XXXX-XXXX-1234` formatında maskelendiğini, e-postaların da sansürlendiğini doğrulayın.

### 4.4. WASM Filtreleme Testi
1.  Arama barına `ip.src == 192.168.1.1` veya `dns.flags.response` benzeri filtreler yazın.
2.  **Doğrulama:** WASM filtreleme motorunun tarayıcı (WebView) tarafında hatasız çalışarak listeyi anında süzdüğünü doğrulayın.

---

## 5. Senaryo 4: Güvenlik Duvarı (Firewall) Bloklama Testleri
Bu testler, [firewall.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs) modülünün yetkilendirme ve işletim sistemi entegrasyonunu doğrular.

> [!IMPORTANT]
> Güvenlik duvarı testi için uygulamanın **Yönetici/Root** olarak çalıştırılması zorunludur.

### 5.1. Yetkisiz Kullanıcı Davranışı
1.  Uygulamayı sıradan bir kullanıcı olarak (elevated olmadan) başlatın.
2.  Bir IP adresini engellemeye çalışın.
3.  **Doğrulama:** Uygulamanın işlemi reddettiğini ve kullanıcıya *"blocking needs Administrator / Root"* hatasını gösterdiğini doğrulayın.

### 5.2. Windows (netsh) Bloklama Testi
1.  PowerShell'i Yönetici olarak açın ve TUI veya Desktop uygulamasını başlatın.
2.  Bir test IP adresini (örn: `8.8.8.8`) arayüzden "Blokla" (Block) seçeneğiyle engelleyin.
3.  İşletim sistemi güvenlik duvarını sorgulayın:
    ```powershell
    netsh advfirewall firewall show rule name=all | Select-String "netscope-block-8.8.8.8"
    ```
4.  **Doğrulama:** Windows Güvenlik Duvarı'nda `netscope-block-8.8.8.8` kuralının oluşturulduğunu ve `Action=Block` (Gelen ve Giden) olarak tanımlandığını doğrulayın.
5.  Cmd/PowerShell üzerinden `ping 8.8.8.8` komutunu gönderin. Ping paketlerinin iletilemediğini ("General failure" veya istek zaman aşımı) gözlemleyin.
6.  Arayüzden engeli kaldırın (Unblock). `ping 8.8.8.8` komutunun tekrar başarıyla çalıştığını doğrulayın.

### 5.3. macOS/Linux Bloklama Testi (İleride Eklenecek Arka Uçlar İçin)
1.  Linux üzerinde test yaparken:
    ```bash
    sudo nft list ruleset | grep netscope-block
    ```
    zincirinde engellenen IP'nin yer aldığını doğrulayın.
2.  macOS üzerinde test yaparken:
    ```bash
    sudo pfctl -sr | grep netscope-block
    ```
    kurallarını inceleyin.

---

## 6. Senaryo 5: Ajan & Sunucu (Fleet Management) Testleri
Bu senaryo, sensör ajanları ile merkezi yönetim sunucusu arasındaki haberleşmeyi test eder.

### 6.1. Ajan Kurulumu (Service Install)
1.  Windows/Linux üzerinde ajanı servis olarak kurun:
    ```bash
    # Windows
    netscope-agent.exe --service install
    
    # Linux (Systemd yönlendirmesini doğrulayın)
    ./netscope-agent --service install
    ```
2.  **Doğrulama:** Servisin arka planda kurulduğunu ve servis yöneticisinde (`services.msc` veya `systemctl status netscope-agent`) listelendiğini doğrulayın.

### 6.2. Sunucu Bağlantısı & WebSocket Heartbeat
1.  [crates/server/src/main.rs](file:///c:/Users/efe/Desktop/netscope/crates/server/src/main.rs) gRPC/REST sunucusunu ayağa kaldırın.
2.  Ajanı ([crates/agent/src/main.rs](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/main.rs)) çalıştırarak sunucuya kayıt (register) olmasını sağlayın.
3.  **Doğrulama:** Sunucu loglarında WebSocket üzerinden her 10-30 saniyede bir ajan kalp atışı (heartbeat) ve güncel yapılandırma senkronizasyon loglarının aktığını doğrulayın.

### 6.3. Ajan Kendi Kendini Güncelleme (Self-Upgrade)
Bu adım, [upgrade.rs](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/upgrade.rs) modülünü test eder.
1.  Ajanın dinlediği güncelleme dizinine bilerek bozuk/imzasız bir binary dosyası bırakın. Ajanın bu dosyayı reddettiğini ve güncelleme yapmadığını doğrulayın.
2.  Güvenli imzalama anahtarı ile imzalanmış geçerli bir Netscope Agent güncelleme paketini sisteme yükleyin.
3.  **Doğrulama:** Ajanın imzayı doğruladığını, mevcut servisi durdurup kendini güncelledikten sonra yeni sürümle tekrar ayağa kalktığını doğrulayın.

---

## 7. Senaryo 6: SIEM İhracat ve Tehdit Motoru Testleri
Bu senaryo, [threat.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/threat.rs) tehdit algılama motorunu doğrular.

### 7.1. Canlı Suricata Kural Yükleme & Rate Limiting
1.  Netscope kurallar dizinine (`rules/`) yeni bir Suricata kuralı ekleyin:
    ```text
    alert tcp any any -> any 80 (msg:"HTTP Test Alarmi"; sid:1000001; rev:1;)
    ```
2.  Yakalama çalışırken kural dosyasını kaydedin.
3.  **Doğrulama:** Çekirdeğin kuralları paket kaçırmadan sıcak yüklediğini (hot reload) doğrulayın.
4.  Ağ üzerinde HTTP (port 80) trafiği oluşturun.
5.  **Rate Limit Doğrulaması:** Kısa sürede 100 HTTP isteği gönderin. Arayüzde alarm sayısının boğulmayı engellemek için bastırıldığını (suppressed/rate limited) doğrulayın.

### 7.2. Deterministik Risk Puanı & Triage Doğrulaması
1.  Zararlı trafik barındıran pcap fixturunu replay edin veya TUI ile analiz edin.
2.  **Doğrulama:** Risk skorunun (0-100) deterministik olarak hesaplandığını ve tetiklenen alarmın risk gerekçesinin (Triage Explanation) insan tarafından okunabilir şekilde döküldüğünü inceleyin.

---

## 8. Hata Senaryoları (Chaos Engineering)

Aşağıdaki olağanüstü durumları elle simüle ederek sistemin kararlılığını test edin:

*   **Disk Doluluğu Hatası:** Yakalama dizininin bulunduğu disk alanını geçici olarak yapay dosyalarla doldurun. Netscope'un çökmeden yakalamayı durdurduğunu ve TUI/Desktop arayüzünde *"Disk full - capturing stopped"* uyarısını verdiğini doğrulayın.
*   **Ağ Bağlantısının Kopması:** Canlı yakalama sırasında ağ kablosunu çekin veya Wi-Fi'ı kapatın. Netscope'un kilitlenip donmadığını, bağlantı koptuğunda arayüz listelemeyi sonlandırıp beklemeye geçtiğini teyit edin.
*   **Bozuk Paket Replay (Fuzzing fallback):** Tamamlanmamış, kesik veya çöp byte'lar içeren PCAP dosyalarını uygulamaya yükleyin. Programın panik yapmadan (crash) bozuk paketleri atladığını doğrulayın.

---

## 9. Manuel Test Takip Formu (Sürüm Öncesi)

Her büyük sürüm (Release) öncesinde aşağıdaki checklist doldurulmalıdır:

| Test Edilen Modül | Açıklama | Sonuç | Tarih | Test Eden |
|---|---|---|---|---|
| Canlı Yakalama | Limit durdurma koşulları (paket, boyut, süre) | [ ] OK / [ ] FAIL | | |
| TUI | 7 Sekme geçişi ve Hex/Tree senkronizasyonu | [ ] OK / [ ] FAIL | | |
| Desktop App | Drag & Drop PCAP yükleme ve WASM süzgeçleri | [ ] OK / [ ] FAIL | | |
| Gizlilik | Luhn algoritması CC maskeleme, TC maskeleme | [ ] OK / [ ] FAIL | | |
| Güvenlik Duvarı | Windows netsh rule ekleme ve ping testi | [ ] OK / [ ] FAIL | | |
| Ajan/Server | WebSocket register ve heartbeat logları | [ ] OK / [ ] FAIL | | |
| Chaos Testi | Ağ kopması ve bozuk pcap yükleme toleransı | [ ] OK / [ ] FAIL | | |
