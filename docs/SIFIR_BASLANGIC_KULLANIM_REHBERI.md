# 📘 NetScope — Sıfırdan Başlayanlar İçin Eksiksiz Ağ Analizi ve Kullanım Rehberi

> **Bu rehberin amacı:**  
> Ağ analizi, paket yakalama veya siber güvenlik konusunda **hiçbir geçmişi olmayan** kullanıcıların NetScope'u sıfırdan kurmasını, ağ paketlerini süzmesini, tehditleri tespit etmesini ve sistemin tüm gelişmiş özelliklerini mastering seviyesinde kullanabilmesini sağlamaktır.

---

## 📌 İçindekiler

1. [Ağ (Network) Analizi Temelleri — Paketler Nasıl Çalışır?](#1-ağ-network-analizi-temelleri--paketler-nasıl-çalışır)
2. [NetScope Nedir & Wireshark ile Karşılaştırma](#2-netscope-nedir--wireshark-ile-karşılaştırma)
3. [Detaylı Kurulum ve Sistem Gereksinimleri](#3-detaylı-kurulum-ve-sistem-gereksinimleri)
   - [Windows Kurulumu (Npcap Uyarısı)](#windows-kurulumu)
   - [macOS Kurulumu](#macos-kurulumu)
   - [Linux Kurulumu & Root Yetki Ayarı (`setcap`)](#linux-kurulumu--root-yetki-ayarı)
4. [Çalıştırma Modları (Masaüstü GUI vs Terminal TUI vs Headless CLI)](#4-çalıştırma-modları-masaüstü-gui-vs-terminal-tui-vs-headless-cli)
5. [Adım Adım İlk Ağ Paketini Yakalama & PCAP Yükleme](#5-adım-adım-i̇lk-ağ-paketini-yakalama--pcap-yükleme)
6. [NetScope Ekranı & 9 Özel Görünüm Rehberi](#6-netscope-ekranı--9-özel-görünüm-rehberi)
   - [Arayüz Bölümleri & Renk Kodları](#arayüz-bölümleri--renk-kodları)
   - [Özel Görünümler (Views 1 - 9)](#özel-görünümler-views-1---9)
   - [Kapsamlı Kısayol Tuşları Tablosu](#kapsamlı-kısayol-tuşları-tablosu)
7. [Filtreleme Rehberi ve BPF Aşçılık Kitabı (Cookbook)](#7-filtreleme-rehberi-ve-bpf-aşçılık-kitabı-cookbook)
8. [Akıllı Tehdit Tespiti, MITRE ATT&CK & Sezgisel Triage Motoru](#8-akıllı-tehdit-tespiti-mitre-attck--sezgisel-triage-motoru)
9. [SOC 7x24 Operasyonları, SIEM/SOAR & Kurumsal Güvenlik](#9-soc-7x24-operasyonları-siemsoar--kurumsal-güvenlik)
10. [Ekip Bildirimleri ve Webhook Entegrasyonu (Telegram, Discord, Slack, SMTP)](#10-ekip-bildirimleri-ve-webhook-entegrasyonu)
11. [Sıkça Sorulan Sorular ve Detaylı Sorun Giderme (FAQ)](#11-sıkça-sorulan-sorular-ve-detaylı-sorun-giderme-faq)

---

## 1. Ağ (Network) Analizi Temelleri — Paketler Nasıl Çalışır?

İnternette bir web sitesini ziyaret ettiğinizde, e-posta gönderdiğinizde veya bir oyun oynadığınızda verileriniz dijital dünyada tek bir büyük blok halinde taşınmaz. Veriler **paket (packet)** adı verilen küçük veri zarflarına bölünür.

Bir ağ paketinin içerisinde şu katmanlar bulunur (OSI Modeli):

```
+-----------------------------------------------------------------------+
| 📦 Uygulama Katmanı (L7): HTTP, DNS, TLS (google.com metni)           |
+-----------------------------------------------------------------------+
| 🚪 Taşıma Katmanı (L4): TCP / UDP (Port 443 -> Kapı Numarası)          |
+-----------------------------------------------------------------------+
| 🌐 İnternet Katmanı (L3): IPv4 / IPv6 (192.168.1.50 -> 142.250.74.46)  |
+-----------------------------------------------------------------------+
| 🔗 Ağ Erişimi Katmanı (L2): Ethernet MAC Adresi (aa:bb:cc:dd:ee:ff)   |
+-----------------------------------------------------------------------+
```

### 🗝️ Temel Terimler Sözlüğü:

* 🌐 **IP Adresi:** Bilgisayarınızın internetteki ev adresidir (Örn: `192.168.1.50`).
* 🚪 **Port:** Bilgisayarınızdaki uygulamanın kapı numarasıdır. Örneğin web siteleri için `80` (HTTP) veya `443` (HTTPS/TLS), DNS için `53`, SSH için `22`.
* 📜 **Protokol:** Cihazların iletişim kurmak için konuştuğu dildir (Örn: DNS, HTTP, TLS, SMB, ARP).
* 📦 **Yük (Payload):** Paketin taşıdığı asıl veridir (Örn: Görüntülenen web sayfasının HTML kodu).

NetScope, bilgisayarınızın ağ kartından geçen bu paketleri canlı olarak dinler, paketleri katman katman ayrıştırır ve siber güvenlik açıklarını tespit eder.

---

## 2. NetScope Nedir & Wireshark ile Karşılaştırma

Wireshark gibi geleneksel araçlar paketleri olduğu gibi ham hex ve karmaşık sayısal parametrelerle gösterir. **NetScope**, yüksek performanslı Rust çekirdeği ile yazılmış modern bir analiz ve tehdit tespit motorudur.

| Özellik | Wireshark | NetScope |
|---|---|---|
| **Özet Görünümü** | `Standard query 0x1234 A google.com` | `google.com → 142.250.74.46 (TLS 1.3 Şifreli Web Bağlantısı)` |
| **Tehdit Tespiti** | Manuel kural/filtre yazımı gerektirir | Otomatik **Expert System** (Zayıf şifreleme, port taraması, açık parola uyarıları) |
| **Kuantum Sonrası Analiz (PQC)** | Desteklemiyor | **Dahili PQC Analiz Motoru** (Kuantum tehdit uyarısı) |
| **Ekip Bildirimleri** | Yok | **Telegram, Discord, Slack, Webhook, SMTP** entegre |
| **Kullanıcı Arayüzü** | Ağır C++ GUI | Çift mod: Tüy siklet **TUI (Terminal)** & Modern **Tauri Masaüstü** |

---

## 3. Detaylı Kurulum ve Sistem Gereksinimleri

### Windows Kurulumu

> ⚠️ **KRİTİK UYARI:** Windows üzerinde Npcap veya WinPcap yüklenmeden NetScope **canlı paket yakalayamaz**. Npcap kurulmadan uygulama başlatılırsa canlı dinleme modunda ağ kartları listelenmez.

1. **Npcap Sürücüsünü İndirin:**  
   [https://npcap.com/#download](https://npcap.com/#download) adresinden `Npcap Installer` (.exe) dosyasını indirin.
2. **Kurulum Aşamasındaki Önemli Ayar:**  
   Yükleyiciyi çalıştırın ve kurulum seçenekleri ekranında şu kutucuğu **MUTLAKA işaretleyin**:  
   ✅ *"Install Npcap in WinPcap API-compatible Mode"*
3. Kurulumu bitirin ve bilgisayarınızı gerekirse yeniden başlatın.

### macOS Kurulumu

macOS sistemlerinde `libpcap` paket yakalama kütüphanesi yerleşik olarak bulunur. Herhangi bir sürücü yüklemeniz gerekmez.

### Linux Kurulumu & Root Yetki Ayarı

Linux dağıtımlarında (Debian/Ubuntu/Fedora/Arch) `libpcap` kütüphanesini yükleyin:
```bash
# Debian / Ubuntu
sudo apt update && sudo apt install libpcap-dev -y

# Fedora / RHEL
sudo dnf install libpcap-devel -y
```

> 💡 **Linux Yetki İpucu:** NetScope'u `sudo` kullanmadan normal kullanıcı hesabınızla canlı ağ paketlerini yakalayacak şekilde çalıştırmak için biner dosyasına yetki verin:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/netscope-tui
```

---

## 4. Çalıştırma Modları

NetScope ihtiyacınıza göre 3 farklı modda çalıştırılabilir:

### 1. 🖥️ Masaüstü Uygulaması (NetScope Desktop)
Grafiksel kullanıcı arayüzünü (GUI) tercih edenler için Tauri v2 tabanlı modern moddur.
```bash
cargo tauri dev
```

### 2. 💻 Terminal Arayüzü (NetScope TUI)
Terminal sunucularında veya tüy siklet performans isteyenler için klavyeyle yönetilen renklendirilmiş TUI modudur.
```bash
cargo run -p netscope-tui
```

### 3. 🤖 Headless / Otomasyon Modu (CLI)
Script'ler veya CI/CD boru hatları için arayüzsüz JSON/Düz metin çıktı modudur.
```bash
# Örnek: 100 paket yakalayıp JSON olarak çıktı ver
cargo run -p netscope-tui -- --headless --json -c 100
```

---

## 5. Adım Adım İlk Ağ Paketini Yakalama & PCAP Yükleme

### Canlı Ağ Paketini Yakalama:
1. NetScope'u açın.
2. **Ağ Kartınızı Seçin:**
   * Kablosuz internet kullanıyorsanız: `Wi-Fi` / `wlan0` / `en0`
   * Kablolu internet kullanıyorsanız: `Ethernet` / `eth0`
3. **Yakalamayı Başlatın:** Kartı seçtiğiniz anda paketler ekranda akmaya başlar.
4. **Yakalamayı Durdurun:** İnceleme yapmak için **`Space` (Boşluk)** tuşuna basarak akışı durdurun.

### Çevrimdışı PCAP Dosyası Analiz Etme:
Daha önce Wireshark veya başka bir araçla kaydedilmiş bir `.pcap` / `.pcapng` dosyasını incelemek için:
* **Masaüstü Arayüzünde:** Dosyayı pencere üzerine sürükleyip bırakın veya **Dosya Aç (Open PCAP)** butonunu kullanın.
* **Terminal Arayüzünde:**
```bash
cargo run -p netscope-tui -- -r fixtures/mixed.pcap
```

---

## 6. NetScope Ekranı & 9 Özel Görünüm Rehberi

### Arayüz Bölümleri & Renk Kodları

```
+-------------------------------------------------------------------------------+
| 🔍 Filtre Çubuğu: [ http || dns                                            ] |
+-------------------------------------------------------------------------------+
| #   | Zaman    | Kaynak IP      | Hedef IP       | Protokol | Özet           |
|-----+----------+----------------+----------------+----------+-----------------|
| 1   | 14:02:01 | 192.168.1.50   | 142.250.74.46  | TLS      | google.com      |
| 2   | 14:02:02 | 192.168.1.50   | 1.1.1.1        | DNS      | A query example |
+-------------------------------------------------------------------------------+
| 🌳 Paket Detay Ağacı (Packet Detail Tree):                                    |
|  ▸ Layer 2: Ethernet (MAC: aa:bb:cc:dd:ee:ff)                                 |
|  ▸ Layer 3: IPv4 (Src: 192.168.1.50, Dst: 142.250.74.46)                       |
|  ▸ Layer 4: TCP (Src Port: 54321, Dst Port: 443)                              |
+-------------------------------------------------------------------------------+
| 🔢 Hex & ASCII Dökümü (Ham Baytlar):                                          |
| 0000  45 00 00 3c a1 b2 40 00 40 06 ... E..<..@.@.                         |
+-------------------------------------------------------------------------------+
```

#### 🎨 Renk Kodlarının Anlamı:
* 🟢 **Yeşil (Güvenli):** Standart şifreli HTTPS/TLS trafiği.
* 🔵 **Mavi (Altyapı):** DNS isim sorguları, ARP veya ICMP Ping trafiği.
* 🟡 **Sarı (Zayıflık/Warning):** Şifresiz HTTP/Telnet trafiği, zayıf parola veya eski protokol kullanımı.
* 🔴 **Kırmızı (Tehdit/Error):** Port taraması, bilinen saldırı imzası veya malformed paket.

---

### Özel Görünümler (Views 1 - 9)

NetScope içerisinde klavyedeki `1` ile `9` tuşlarına basarak veya sekme menüsünden geçiş yapabileceğiniz özel analiz modları bulunur:

1. 📋 **1. Paket Tablosu (Packets):** Tüm gelen/giden paketlerin canlı listesi.
2. 🔌 **2. Bağlantılar & Akışlar (Connections/Flows):** Aktif TCP/UDP oturumlarının matris görünümü.
3. 💡 **3. Güvenlik İpuçları (Insights):** Ağdaki anomali ve zayıflık özetleri.
4. 📊 **4. Performans & Dashboard:** Gerçek zamanlı bant genişliği grafikleri ve en çok konuşan IP'ler (Top Talkers).
5. 🌐 **5. Pasif DNS Kayıtları (DNS Log):** Ağda sorgulanan tüm alan adlarının ve IP eşleşmelerinin dökümü.
6. 🛡️ **6. Kuantum Sonrası Kriptografi (PQC Wizard):** Şifreli trafiğin kuantum bilgisayar tehditlerine karşı risk analiz raporu.
7. 🤖 **7. AI & LLM Trafiği (AI Traffic):** OpenAI, Anthropic, Ollama ve HuggingFace yapay zekâ isteklerinin tespiti.
8. 🏭 **8. Endüstriyel OT & Edge (Industrial OT):** Modbus, BACnet, OPC UA ve DNP3 fabrika otomasyon protokollerinin canlı izlenmesi.
9. 📚 **9. Bütünleşik Eğitim Kütüphanesi (Learn):** 2500+ protokol hakkında dahili Türkçe/İngilizce bilgi bankası.

---

### Kapsamlı Kısayol Tuşları Tablosu

| Tuş | İşlev |
|---|---|
| **`Space` (Boşluk)** | Canlı paket yakalamayı duraklatır / devam ettirir. |
| **`f`** | Filtre çubuğuna odaklanır. |
| **`c`** | Mevcut aktif filtreyi temizler. |
| **`1` - `9`** | Özel analiz görünümleri arasında geçiş yapar. |
| **`Up` / `Down`** | Paket listesinde yukarı ve aşağı gezinir. |
| **`Enter`** | Seçili paketin detay ağacını açar / kapatır. |
| **`Esc`** | Filtre çubuğundan çıkar veya pencereleri kapatır. |
| **`q`** | NetScope uygulamasından güvenli çıkış yapar. |

---

## 7. Filtreleme Rehberi ve BPF Aşçılık Kitabı (Cookbook)

Ağınızda akan binlerce paket arasından aradığınız veriyi saniyeler içinde bulmak için filtre çubuğunu kullanabilirsiniz:

### 🍳 Hazır Filtre Tarifleri:

* **Sadece Web Trafiğini Gör (HTTP ve HTTPS):**
  ```text
  http || tls
  ```
* **Sadece Şifrelenmemiş (Tehlikeli) Web Trafiğini Gör:**
  ```text
  http
  ```
* **Sadece DNS Alan Adı Sorgularını Gör:**
  ```text
  dns
  ```
* **Belirli Bir IP Adresinin Trafiğini Gör:**
  ```text
  ip == 192.168.1.50
  ```
* **Belirli Bir Port Üzerindeki Trafiği Gör (Örn: PostgreSQL 5432):**
  ```text
  port 5432
  ```
* **Sadece Hata ve Uyarı İçeren Paketleri Süz:**
  ```text
  severity == Warning || severity == Error
  ```
* **Karmaşık Filtre Örneği (Belirli IP'nin Şifresiz HTTP Trafiği):**
  ```text
  ip == 192.168.1.50 && http
  ```

---

---

## 8. Akıllı Tehdit Tespiti, MITRE ATT&CK & Sezgisel Triage Motoru

NetScope sadece paket yakalamaz; arka planda çalışan **Deterministik Triage Motoru (0-100 Risk Scoring)** ile ağdaki tüm olayları derecelendirir:

### 🎯 0 - 100 Deterministik Risk Puanlaması

Her tespit edilen paket/olay için 4 bileşenden oluşan sayısal bir risk skoru hesaplanır:
$$\text{Risk Skoru} = \text{Ciddiyet} + \text{Varlık Kritikliği} + \text{Baseline Anomali Z-Skoru} + \text{Tehdit İstihbaratı Eşleşmesi}$$

| Risk Skoru | Öncelik Seviyesi | Örnek Olaylar | SOC Analist Aksiyonu |
|---|---|---|---|
| **0 - 29** | 🟢 **Düşük (Low/Note)** | Normal HTTPS web trafiği, rutin DNS sorguları | Yalnızca günlük kaydı (Log). |
| **30 - 59** | 🟡 **Orta (Medium/Warning)** | Zayıf TLS 1.0 şifreleme, şifresiz HTTP POST, mesai dışı giden trafik | İncelenmek üzere sıraya alınır. |
| **60 - 84** | 🟠 **Yüksek (High/Error)** | Port taraması (`T1595`), şifresiz FTP/Telnet parola iletimi, C2 beaconing | 15 dakika içinde analist müdahalesi. |
| **85 - 100** | 🔴 **Kritik (Critical Breach)** | Şifreli veri sızıntısı (Exfiltration), bilinen zararlı yazılım imzaları | Otomatik izolasyon ve On-call çağrı. |

### 🛡️ MITRE ATT&CK & Cyber Kill Chain Haritalaması

NetScope tespit edilen her şüpheli trafiği doğrudan **MITRE ATT&CK** taktik/teknik kodlarına bağlar:

* **Reconnaissance (Keşif):** `T1595 - Active Scanning` (Port ve servis taramaları).
* **Initial Access (İlk Erişim):** `T1190 - Exploit Public-Facing Application` (Açık web servislerine saldırı).
* **Lateral Movement (Yanal İlerleme):** `T1021.002 - SMB/Windows Admin Shares` (Ağ içi yetkisiz yanal yayılma).
* **Command and Control (C2):** `T1071 - Application Layer Protocol` (DNS/HTTP tünelleme üzerinden dış komut kontrolü).
* **Exfiltration (Veri Sızıntısı):** `T1041 - Exfiltration Over C2 Channel` (Hassas verilerin ağ dışına çıkarılması).

---

## 9. SOC 7x24 Operasyonları, SIEM/SOAR & Kurumsal Güvenlik

NetScope bir SOC (Security Operations Center) ortamında 7/24 izleme ve adli analiz için tam entegre çalışır:

### 🔄 1-Tık Pivot Motoru & Naratif Açıklayıcı (Layer 7)

Analiz yaparken bir IP veya şüpheli veri gördünüzde **1-Tık Pivot** motoru devreye girer:
* **IP / Hostname Pivot:** Seçilen IP adresinin tüm geçmiş konuşmalarını, bant genişliğini ve bağlandığı sunucuları tek tıkla listeler.
* **JA4 Fingerprint Pivot:** İstemcinin TLS el sıkışma parmak izini eşleştirerek zararlı yazılım istemcilerini (C2 implant) tespit eder.
* **Katman 7 Naratifi ("Bunu Neden Önemsemeliyim?"):** Karmaşık teknik loglar yerine *"10.0.1.47 IP'li İK bilgisayarı, Üretim Veritabanına (10.0.5.18) mesai saatleri dışında 50 MB veri aktardı — Olası Veri Sızıntısı ⚠️"* şeklinde insan tarafından okunabilir özet üretir.

### 🔌 Kurumsal SIEM / SOAR Entegrasyonu (Connectors)

NetScope ürettiği uyarıları kurumsal SIEM/SOAR platformlarınıza standart formatlarda aktarır:
* **Syslog RFC 5424 (UDP/TCP 514):** Splunk, QRadar, ArcSight entegrasyonu.
* **CEF & LEEF Formatları:** Micro Focus ArcSight ve IBM QRadar için yapılandırılmış formatlar.
* **STIX 2.1 & Sigma Kuralları:** Tehdit istihbarat paylaşımı (IoC) ve Sigma kural dışa aktarımı.
* **Windows Event Log:** Windows Olay Görüntüleyicisi (Application Log) doğrudan entegrasyonu.

### 🔐 KVKK / GDPR Gizlilik Motoru & Kurcalanamaz Denetim Günlüğü

* **Luhn Algoritması ile Kredi Kartı Sansürleme:** Paket içeriğinde geçen kredi kartı numaralarını `XXXX-XXXX-XXXX-1234` şeklinde otomatik maskeler.
* **PII & IP Anonimleştirme:** E-posta, telefon ve IP adreslerini (`192.168.1.0/24`) log veri tabanına yazılmadan önce sansürler.
* **Kriptografik SHA-256 Denetim Günlüğü (Tamper-Proof Audit):** Tüm denetim kayıtları kriptografik hash zincirleme ile saklanır. Logların dışarıdan değiştirilmediği `netscope-cli audit verify` komutuyla adli olarak kanıtlanabilir.

---

## 10. Ekip Bildirimleri ve Webhook Entegrasyonu

NetScope kritik bir güvenlik ihlali veya saldırı tespit ettiğinde ekibinize Telegram, Discord, Slack veya E-posta kanallarından anlık bildirim atabilir.

### 📱 Telegram Bot Entegrasyonu Kurulumu:
1. Telegram'da `@BotFather` ile konuşarak kendi botunuzu oluşturun ve size verilen **API Token** değerini kopyalayın.
2. Telegram gruplarınızdan birine botu ekleyin veya kendi Chat ID'nizi öğrenin.
3. NetScope ayarlarından bildirim kanalını aktifleştirin:
   ```toml
   [notifications]
   telegram_token = "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
   telegram_chat_id = "987654321"
   ```
4. Saldırı anında telefona anlık bildirim mesajı iletilir.

---

## 11. Sıkça Sorulan Sorular ve Detaylı Sorun Giderme (FAQ)

### S1: Windows'ta `wpcap.dll bulunamadı` hatası alıyorum ve uygulama kapanıyor?
* **Çözüm:** Npcap bilgisayarınızda yüklü değildir. [https://npcap.com/#download](https://npcap.com/#download) adresinden Npcap'i indirin ve kurulum sırasında *"Install Npcap in WinPcap API-compatible Mode"* kutucuğunu işaretleyin.

### S2: NetScope açılıyor ancak paket listesi bomboş kalıyor, hiç paket akmıyor?
* **Çözüm 1:** Doğru ağ kartını seçtiğinizden emin olun (Wi-Fi kullanıyorsanız Wi-Fi kartını seçmelisiniz).
* **Çözüm 2:** Uygulamayı **Yönetici Olarak (Run as Administrator)** veya Linux'ta `sudo` ile çalıştırın.

### S3: Şifreli HTTPS / TLS trafiğinin içindeki şifreli metinleri görebilir miyim?
* **Çözüm:** NetScope varsayılan olarak şifreli içeriği korur ve gizliliği bozmaz. Ancak geliştiriciler için SSLKEYLOGFILE değişkenini tanımlayarak kendi şifreli trafiğinizi çözebilirsiniz.

---

*Rehber NetScope v0.2.0 sürümüne tam uygun olarak hazırlanmıştır.*
