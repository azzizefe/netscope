# Netscope — Kurumsal Kullanım Analizi 🏢

> **Amaç:** Netscope'un kurumsal BT ortamlarında konumlandırılması, rakiplere
> karşı avantajları, mevcut eksiklikleri ve kurumsal hazırlık yol haritası.
>
> **Tarih:** 2026-07-25
> **Sürüm:** v1.0

---

## İçindekiler

1. [Yönetici Özeti (CISO için 2 dakika)](#yönetici-özeti-ciso-için-2-dakika)
2. [Netscope Kurumsalda Nereye Oturur?](#netscope-kurumsalda-nereye-oturur)
3. [Neden Netscope? — 10 Maddede Kurumsal Değer Teklifi](#neden-netscope--10-maddede-kurumsal-değer-teklifi)
4. [Hangi Ekipler, Hangi Amaçla Kullanır?](#hangi-ekipler-hangi-amaçla-kullanır)
5. [Rakip Karşılaştırması](#rakip-karşılaştırması)
6. [Mevcut Durum: Kurumsal Gözle Neler Var, Neler Yok?](#mevcut-durum-kurumsal-gözle-neler-var-neler-yok)
7. [Kritik Eksiklikler (Ne Eksik?)](#kritik-eksiklikler-ne-eksik)
8. [Kurumsal Dağıtım Senaryoları](#kurumsal-dağıtım-senaryoları)
9. [Güvenlik ve Uyumluluk (KVKK, GDPR, PCI-DSS)](#güvenlik-ve-uyumluluk-kvkk-gdpr-pci-dss)
10. [Toplam Sahip Olma Maliyeti (TCO) Karşılaştırması](#toplam-sahip-olma-maliyeti-tco-karşılaştırması)
11. [Kurumsal Yol Haritası](#kurumsal-yol-haritası)
12. [Sonuç: Bugün Kurumsalda Kullanılır mı?](#sonuç-bugün-kurumsalda-kullanılır-mı)

---

## Yönetici Özeti (CISO için 2 dakika)

**Netscope**, Wireshark'a modern, hafif ve insan-okunur bir alternatif olarak
geliştirilmiş, Rust tabanlı açık kaynak bir ağ analiz platformudur.

### Bugün kurumsalda ne için hazır?

| Kullanım | Durum | Açıklama |
|----------|-------|----------|
| Bireysel paket analizi & troubleshooting | ✅ **Hazır** | Wireshark'ın yaptığı işi daha hızlı, daha anlaşılır yapıyor |
| Güvenlik analizi (tek seferlik) | ✅ **Hazır** | Insights, Privacy X-Ray, JA3/JA4, imza tarama gömülü |
| Adli bilişim (tek analist) | ✅ **Hazır** | pcap analizi, stream takibi, hex → kod çevrimi |
| Uzaktan yakalama (SSH) | ✅ **Hazır** | Kendi agent'ını kurmadan uzak sunucudan paket çekme |
| Headless/otomasyon | ✅ **Hazır** | JSON çıktı, script console, CI/CD'ye gömme |

### Bugün kurumsalda ne için hazır değil?

| Kullanım | Durum |
|----------|-------|
| SOC / 7×24 izleme | ❌ Merkezi sunucu, SIEM çıktısı, alerting yok |
| Ekip olarak kullanım | ❌ Çok kullanıcılı, RBAC, audit log yok |
| Uyumluluk denetimi | ❌ KVKK/GDPR/PCI-DSS rapor şablonu yok |
| Büyük ölçekli dağıtım | ❌ Merkezi yönetim konsolu, GPO/MDM paketi yok |
| Kurumsal destek | ❌ SLA, öncelikli destek, profesyonel hizmet yok |

> **Özet:** Netscope bugün, Wireshark'ın kurumsalda kullanıldığı her senaryoda
> **bire bir alternatif**. Hatta birçok yerde daha iyi (Insights, Learn modu,
> performans). Ama kurumsal **platform** özellikleri (merkezi yönetim, SIEM,
> RBAC) henüz yok — yol haritasında.

---

## Netscope Kurumsalda Nereye Oturur?

### Kurumsal ağ izleme yığınında Netscope'un yeri

```
                        ┌─────────────────────────┐
                        │     CISO / Yönetim       │
                        │     Risk & Uyum Paneli   │  ← Netscope CISO Dashboard (planlanan)
                        ├─────────────────────────┤
                        │       SIEM / SOAR        │
                        │  Splunk · ELK · Sentinel │  ← Netscope → syslog/CEF (planlanan)
                        ├─────────────────────────┤
                        │   Ağ Performans İzleme   │
                        │  SolarWinds · PRTG · Zabbix│ ← Netscope Dashboard (kısmen hazır)
                        ├─────────────────────────┤
          ┌─────────────┤   PAKET ANALİZİ          ├─────────────┐
          │             │   Netscope · Wireshark    │             │
          │             └─────────────────────────┘             │
          │                                                     │
   ┌──────▼──────┐                                       ┌──────▼──────┐
   │  Netscope   │                                       │  Netscope   │
   │  Agent      │  ← Her kritik segmentte bir tane      │  Agent      │
   │  (DMZ)      │                                       │  (İç Ağ)    │
   └─────────────┘                                       └─────────────┘
```

Netscope, yığında **paket analizi katmanında** konumlanır. SIEM ve NPM
ürünlerinin rakibi değil, **tamamlayıcısıdır**. SIEM log toplar, Netscope
**paketi açar ve ne olduğunu anlatır**.

### Wireshark'ın kurumsaldaki rolünü almak

Wireshark kurumsalda nasıl kullanılıyorsa, Netscope da öyle kullanılır:

- Ağ ekibi: "Sunucuya ulaşılamıyor" → paket yakala, TCP retransmission'ları gör
- Güvenlik ekibi: "Şüpheli trafik var" → pcap'i aç, Insights taramasını çalıştır
- Uygulama ekibi: "API yavaş" → TLS çöz, HTTP istek/yanıt sürelerini ölç

Fark: Netscope bunları daha hızlı ve daha az uzmanlıkla yapmanı sağlar.

---

## Neden Netscope? — 10 Maddede Kurumsal Değer Teklifi

### 1. ⚡ Wireshark'tan kat kat hızlı

```
Paket işleme hızı karşılaştırması (tek thread):
  Netscope:  ████████████████████████████ 3.1M pkt/s
  Wireshark: ████████ 800K pkt/s

Büyük pcap açılış süresi (1 GB pcap):
  Netscope:  ~3 saniye
  Wireshark: ~25 saniye
```

**Kurumsal değer:** Incident response'ta her dakika önemlidir. 25 saniye yerine
3 saniyede pcap açmak, olay müdahale süresini kısaltır.

### 2. 🧠 İnsan-okunur, eğitim gerektirmez

Wireshark: `00 01 00 01 00 00 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d`
Netscope: **`DNS Query: www.google.com → A kaydı soruluyor`**

**Kurumsal değer:** Ağ analizini sadece kıdemli ağ mühendisleri değil, tüm BT
personeli yapabilir. Eğitim maliyeti düşer, MTTR (Mean Time to Resolve) kısalır.

### 3. 🛡️ Yerleşik güvenlik analizi (Wireshark'ta yok!)

Wireshark size **her şeyi gösterir, hiçbir şey yorumlamaz**. Netscope **Insights**
sekmesi otomatik olarak şunları tarar:

- 🔴 Açık parolalar (HTTP Basic Auth, FTP, Telnet, SMTP, POP3)
- 🟠 Şüpheli domainler (DGA paternleri, yeni kaydedilmiş domainler)
- 🟡 Port taramaları, SYN flood'lar, connection reset fırtınaları
- 🟡 Şifresiz HTTP trafiği, plaintext DNS
- 🔵 Şifreli vs şifresiz trafik oranı
- 🟢 JA3/JA4 parmak izleri (tehdit avı için)

**Kurumsal değer:** Güvenlik analisti olmayan ekipler bile anomali tespit
edebilir. Her bulgu için "bu nasıl istismar edilir?" ve "nasıl düzeltilir?"
açıklamaları var.

### 4. 🔓 TLS çözme — offline, yerel

Wireshark ile aynı yöntem, aynı ortam değişkenleri (`SSLKEYLOGFILE`, `TLS_RSA_PRIVATE_KEY`):

- TLS 1.3 + TLS 1.2 ECDHE (GCM & ChaCha20)
- Anahtarlar local kalır, dışarı çıkmaz
- JA3/JA4 ile şifreli de olsa **nasıl** konuştuğunu görürsün

**Kurumsal değer:** SSL decrypt appliance'a gerek kalmadan uygulama trafiğini
analiz etme. Regülasyon uyumu için şifreleme denetimi.

### 5. 📦 ~8 MB — dağıtımı zahmetsiz

| Araç | Boyut |
|------|-------|
| Netscope Desktop | ~8 MB |
| Wireshark (Windows) | ~85 MB |
| SolarWinds NPM | ~500 MB+ |
| ExtraHop (appliance) | Fiziksel cihaz |

**Kurumsal değer:** GPO, SCCM, Intune ile dağıtım saniyeler içinde. İstemci
bilgisayarlara bile kurulabilir. Güncelleme maliyeti düşük.

### 6. 🎯 Sıfır konfigürasyon, anında üretkenlik

Wireshark'ı ilk açtığınızda: "Hangi interface?" → "Promiscuous mode?" → "BPF filtre?"
Netscope'u ilk açtığınızda: Wi-Fi/Ethernet otomatik seçilir, yakalamaya başlar.

**Kurumsal değer:** "Şu an ağda ne oluyor?" sorusunun cevabı 5 saniyede.
Help desk personeli bile kullanabilir.

### 7. ⛔ Canlı trafik engelleme (Wireshark'ta yok!)

Paketi gördün, IP'yi seçtin, `b`'ye bastın → o IP'ye giden trafik **OS güvenlik
duvarı kuralıyla** kesildi.

**Kurumsal değer:** Tehdit tespitinden aksiyona geçiş süresi: saniyeler.
SOC talimatı → ağ ekibi → firewall kuralı zincirini kısaltır.

### 8. 🔌 Script console — dışa aktarma yok

Wireshark'ta: pcap'i dışa aktar → Python/Scapy betiği yaz → çalıştır.
Netscope'ta: Uygulama içinde JavaScript yaz, `Ctrl+Enter`, sonuçlar anında.

```javascript
// Örnek: Açık parola içeren tüm paketleri bul
packets.filter(p =>
  p.layers.some(l => l.contains("password") || l.contains("Authorization: Basic"))
);
```

**Kurumsal değer:** Her analist kendi kontrolünü yazabilir. Python/Scapy
kurulumu, kütüphane yönetimi yok. Sıfır bağımlılık.

### 9. 🌍 Tamamen offline jeo-konum

MaxMind GeoLite2 `.mmdb` dosyasını gösterdiğinde, IP → ülke/şehir/organizasyon
çözümlemesi tamamen local, sıfır network çağrısı.

**Kurumsal değer:** Askeri, finans, sağlık gibi regüle sektörlerde IP
lookup'larının dış servise gitmesi kabul edilemez. Netscope bu sorunu çözer.

### 10. 🇹🇷 Türkçe arayüz ve dokümantasyon

7 dil desteği, bunlardan biri **Türkçe**. Dökümantasyon, eğitim içeriği,
hata mesajları — hepsi Türkçe mevcut.

**Kurumsal değer:** Türkiye'deki kurumlar, kamu ve üniversiteler için
dil bariyeri yok. KVKK uyum dokümanları Türkçe.

---

## Hangi Ekipler, Hangi Amaçla Kullanır?

| Ekip | Kullanım Amacı | Netscope Özelliği | Hazır mı? |
|------|---------------|-------------------|-----------|
| **Ağ Yönetimi** | Troubleshooting, kapasite planlama | Dashboard, paket analizi, connections | ✅ |
| **BT Güvenlik** | Tehdit tespiti, forensics, incident response | Insights, Privacy X-Ray, imza tarama | ✅ |
| **SOC** | 7×24 izleme, olay korelasyonu | (SIEM entegrasyonu gelince) | ❌ |
| **Uygulama Geliştirme** | API debugging, performans analizi | TLS çözme, JSON/XML beautifier, replay | ✅ |
| **Uyumluluk/Denetim** | KVKK, GDPR, PCI-DSS uyum kontrolü | (Uyum raporları gelince) | ❌ |
| **İş Zekası / FinOps** | Bulut trafik maliyeti, kapasite tahmini | (Dashboard + tahmin modeli) | ⚠️ |
| **Yardım Masası (Help Desk)** | "İnternet yavaş" teşhisi | Basit arayüz, otomatik interface seçimi | ✅ |
| **Dış Denetçiler** | Periyodik ağ güvenlik denetimi | (Denetim rapor şablonları gelince) | ❌ |

---

## Rakip Karşılaştırması

### Doğrudan rakipler (paket analizi)

| Özellik | **Netscope** | Wireshark | tcpdump | TShark |
|---------|-------------|-----------|---------|--------|
| GUI | ✅ TUI + Desktop | ✅ (Qt) | ❌ | ❌ |
| Paket çözme derinliği | ⭐⭐⭐ 250 protokol | ⭐⭐⭐⭐⭐ 3000+ | ⭐ Temel header | ⭐⭐⭐ Wireshark motoru |
| Performans (pkt/s) | ⭐⭐⭐⭐⭐ 3.1M | ⭐⭐⭐ 800K | ⭐⭐⭐⭐ 2M+ | ⭐⭐⭐ 800K |
| Otomatik güvenlik analizi | ✅ **Var** | ❌ Yok | ❌ Yok | ❌ Yok |
| Öğrenme eğrisi | ⭐ Kolay | ⭐⭐⭐ Zor | ⭐⭐ Orta | ⭐⭐ Orta |
| Kurulum boyutu | ~8 MB | ~85 MB | ~1 MB | Wireshark ile gelir |
| TLS çözme | ✅ | ✅ | ❌ | ✅ |
| Canlı IP engelleme | ✅ **Var** | ❌ | ❌ | ❌ |
| Headless/JSON | ✅ | ❌ (PDML/PSML) | ✅ (ham) | ✅ |
| Script desteği | ✅ JS (içte) | ❌ Lua (harici) | ❌ | ❌ |
| Fiyat | **Ücretsiz (MIT)** | Ücretsiz (GPL) | Ücretsiz (BSD) | Ücretsiz (GPL) |

### Endirekt rakipler (ağ izleme platformları)

| Özellik | **Netscope** | SolarWinds NPM | ExtraHop Reveal(x) | Darktrace |
|---------|-------------|---------------|-------------------|-----------|
| Paket derinliği | ✅ Tam çözüm | ⚠️ NetFlow/sFlow | ✅ Tam çözüm | ⚠️ Meta veri |
| Merkezi yönetim | ❌ (planlanan) | ✅ | ✅ | ✅ |
| SIEM çıktısı | ❌ (planlanan) | ✅ | ✅ | ✅ |
| AI/ML anomali | ❌ | ⚠️ Temel | ✅ | ✅ (temel ürün) |
| Uyumluluk raporu | ❌ | ✅ | ✅ | ✅ |
| Dağıtım modeli | Yazılım | Yazılım | Appliance | Appliance |
| Yıllık maliyet | **Ücretsiz** | ~$3,000+ | ~$50,000+ | ~$100,000+ |
| Açık kaynak | ✅ | ❌ | ❌ | ❌ |

### Netscope'un kurumsal rakiplere karşı konumlanması

```
Düşük maliyet
      ↑
      │  Netscope ●
      │  (ücretsiz, tam paket analizi)
      │
      │                        SolarWinds NPM ■
      │                        (~$3K, yüzeysel paket)
      │
      │           Wireshark ▲               ExtraHop ◆
      │           (ücretsiz,              (~$50K, tam çözüm)
      │            manuel)
      │
      │                                      Darktrace ★
      │                                      (~$100K, AI odaklı)
      └─────────────────────────────────────────────→
                Temel özellik                 Kurumsal özellik
                (manuel analiz)           (merkezi yönetim, SIEM, AI)
```

Netscope şu an **sol üst köşede**: ücretsiz, temel analizde mükemmel.
Yol haritasıyla **sağa doğru** ilerleyip kurumsal özellikleri eklemek.

---

## Mevcut Durum: Kurumsal Gözle Neler Var, Neler Yok?

### ✅ Kurumsal kullanıma hazır olanlar

| Özellik | Kurumsal değeri |
|----------|-----------------|
| 250 protokol çözücü | IT ve OT protokolleri tek araçta (Modbus, PROFINET, DICOM, FIX...) |
| Insights güvenlik taraması | Her analist = junior güvenlik analisti seviyesinde içgörü |
| JA3/JA4 parmak izi | Şifreli trafikte tehdit avı (C2 sunucu tespiti) |
| TLS çözme (offline) | SSL decrypt cihazı olmadan uygulama trafiği analizi |
| Privacy X-Ray | 3. parti tracker ve veri sızıntısı denetimi |
| Headless JSON modu | CI/CD boru hattına göm, otomatik test |
| Remote capture (SSH) | Uzak ofis/sunucuda ajan kurmadan paket yakala |
| Multi-interface capture | DMZ + iç ağı aynı anda izle |
| Jeo-konum (offline MaxMind) | Regüle sektörlerde güvenli IP lookup |
| Canlı IP engelleme | Tespitten aksiyona saniyeler |
| Replay (Repeater) | Güvenlik testi ve uygulama hata ayıklama |
| Script console (JS) | Özel analiz betikleri, dış araç gerektirmez |

### ⚠️ Kısmen hazır, geliştirilmesi gerekenler

| Özellik | Ne var? | Ne eksik? |
|----------|---------|-----------|
| Dashboard | Canlı metrikler, sparkline, top talkers | Uzun vadeli trend, SLA takibi, kapasite tahmini |
| Raporlama | Markdown rapor, tek tık | PDF, zamanlanmış dağıtım, uyumluluk şablonları |
| Filtreleme | BPF + display filter | Kayıtlı filtre kütüphanesi, ekip paylaşımı |
| Profiller | Kaydedilebilir çalışma profilleri | Merkezi profil dağıtımı |
| Performans | 3.1M pkt/s | Dağıtık capture'da yük dengeleme |

### ❌ Henüz olmayan, kritik eksiklikler

| Eksik | Neden kritik? |
|-------|---------------|
| Çok kullanıcılı yapı | Tek analist = tek instance. Ekipler kullanamaz |
| RBAC (rol tabanlı erişim) | Stajyer tüm paketleri görebilir = güvenlik riski |
| Merkezi yönetim konsolu | 50 ajanı tek tek yönetemezsin |
| SIEM entegrasyonu | SOC'a veri gönderemezsin |
| Audit log | Kim ne yapmış, kanıt yok = uyumluluk sıkıntısı |
| SSO / LDAP / AD | Kurumsal kimlik sistemiyle çalışamaz |
| API (REST/WebSocket) | Dış sistemler entegre olamaz |
| Lisans yönetimi | Kurumsal satın alma modeli yok |
| Uyumluluk raporları | KVKK/GDPR/PCI-DSS denetiminden geçemez |
| GPO/MDM dağıtımı | 1000 bilgisayara tek tek kuramazsın |
| Yüksek erişilebilirlik | Manager sunucusu single point of failure |

---

## Kritik Eksiklikler (Ne Eksik?)

### Eksik #1: Merkezi Sunucu ve Ajan Mimarisi

```
MEVCUT:                          OLMASI GEREKEN:

┌──────────┐                    ┌──────────────────────┐
│ Netscope │                    │  Netscope Manager    │
│ Desktop  │                    │  (Web UI + REST API) │
│ (tek)    │                    └────────┬─────────────┘
└──────────┘                             │
                                  ┌──────┼──────┐
                                  │      │      │
                             ┌────▼─┐ ┌──▼──┐ ┌▼────┐
                             │Agent │ │Agent│ │Agent│
                             │ DMZ  │ │ İç  │ │ Uzak│
                             └──────┘ └─────┘ └─────┘
```

**Etkisi:** Bugün kurumsalda sadece "bir analistin bilgisayarına kurup manuel
analiz yaptığı" araç olarak kalır. SOC, 7×24 izleme, dağıtık sensör senaryoları
imkansız.

### Eksik #2: SIEM Entegrasyonu

Netscope'un en güçlü yanı olan **Insights** bulguları, kurumsalın merkezi sinir
sistemi olan SIEM'e aktarılamıyor.

```
Olması gereken:
  Netscope Agent → Ağda anomali tespit etti
       → syslog/CEF/JSON → Splunk / ELK / Sentinel
       → SIEM korelasyon kuralı tetiklendi
       → SOAR playbook'u çalıştı
       → ITSM bileti açıldı
```

### Eksik #3: Çok Kullanıcılı Yapı ve RBAC

Bugün Netscope'u açan herkes **tüm paket içeriğini** görür. Bu, şu anlama gelir:

- Stajyer, CEO'nun e-posta trafiğini görebilir
- Dış denetçiye seçici erişim veremezsin
- Kimin neyi görüntülediğini loglayamazsın
- Hassas veri içeren paketleri maskeleyemezsin

**Kurumsal gereksinim:** En az 4 rol — Admin, Analist, İzleyici (read-only),
Denetçi (sadece raporlar).

### Eksik #4: Uyumluluk Raporlaması

Türkiye'de KVKK, Avrupa'da GDPR, finansta PCI-DSS, sağlıkta HIPAA...

Netscope ağdaki **hassas veri akışını görebiliyor** ama bunu bir **uyumluluk
raporuna** dönüştüremiyor.

```
Olmasi gereken:
  "PCI-DSS Uyum Raporu — Q3 2026"
  ├─ Kart verisi içeren paketler: 12 (❌)
  ├─ Şifresiz kanalda kart verisi: 3 (🔴 Kritik)
  ├─ TLS 1.0/1.1 kullanan servisler: 2 (🟠 Yüksek)
  └─ Uyum skoru: 72/100
```

### Eksik #5: Kurumsal Dağıtım ve Yönetim

100 bilgisayara Netscope kurmak için bugünkü yöntem: her birine git, indir, kur,
Npcap'i unutma, yönetici olarak çalıştır...

```
Olmasi gereken:
  Group Policy → "Netscope Agent" MSI → tüm domain bilgisayarlarına otomatik kur
  Intune / Jamf → Buluttan yönetilen cihazlara push
  Netscope Manager → "103 agent online, 2 güncel değil, 1 hata veriyor"
```

---

## Kurumsal Dağıtım Senaryoları

### Senaryo 1: Tek Analist (Bugün mümkün ✅)

```
┌──────────────────────────────────────┐
│  Ağ Mühendisi / Güvenlik Analisti    │
│                                      │
│  Kendi bilgisayarında Netscope       │
│  Gerektiğinde pcap analizi yapıyor   │
│  Wireshark yerine kullanıyor         │
└──────────────────────────────────────┘

Avantaj: Wireshark'tan hızlı, Insights ile otomatik bulgular
Dezavantaj: Tek başına, kurumsal entegrasyon yok
Maliyet: Sıfır
```

### Senaryo 2: Küçük Ekip (3-10 kişi) (Bugün kısmen ⚠️)

```
┌──────────────────────────────────────────────┐
│  BT Ekibi (3-10 kişi)                        │
│                                              │
│  Herkes kendi bilgisayarında Netscope        │
│  Ortak profil ve filtreleri manuel paylaşıyor│
│  Troubleshooting ve güvenlik analizi         │
└──────────────────────────────────────────────┘

Avantaj: Hızlı onboarding (Learn modu), düşük eğitim maliyeti
Eksik: Ortak filtre/profil paylaşımı, audit log, merkezi görünürlük
Maliyet: Sıfır (lisanssız)
```

### Senaryo 3: Kurumsal SOC (Planlanan 📋)

```
┌─────────────────────────────────────────────────────────┐
│                     SOC Ekibi                            │
│                                                         │
│  Netscope Manager (merkezi sunucu)                      │
│  ├─ DMZ Agent (2 adet) — sürekli yakalama               │
│  ├─ İç Ağ Agent (4 adet) — segment bazlı izleme         │
│  └─ Uzak Ofis Agent (3 adet) — VPN trafik analizi       │
│                                                         │
│  SIEM (Splunk) ← syslog ← Netscope Manager              │
│  SOAR → otomatik playbook                               │
│  ITSM (Jira SM) → otomatik bilet                        │
└─────────────────────────────────────────────────────────┘

Avantaj: Tam entegre, 7×24, otomatik alert
İhtiyaç: Manager, agent mimarisi, SIEM connector (Faz 3)
Tahmini maliyet: Açık kaynak çekirdek ücretsiz + opsiyonel kurumsal destek
```

### Senaryo 4: Regüle Sektör (Banka, Sağlık, Kamu) (Planlanan 📋)

```
┌─────────────────────────────────────────────────────────┐
│                 Finans / Sağlık / Kamu                   │
│                                                         │
│  Netscope Manager (on-prem, hava boşluklu)              │
│  ├─ PCI-DSS / HIPAA uyum raporlaması                    │
│  ├─ Tüm veri on-prem, dışarı çıkmaz                     │
│  ├─ Offline jeo-konum (MaxMind .mmdb)                   │
│  ├─ Detaylı audit log (denetim için)                    │
│  ├─ DLP (TC Kimlik, kredi kartı tespiti)                │
│  └─ Adli bilişim modu (delil bütünlüğü hash zinciri)    │
└─────────────────────────────────────────────────────────┘

Avantaj: Regülatör denetiminden geçer, veri dışarı çıkmaz
İhtiyaç: Uyumluluk modülleri, DLP, adli mod (Faz 3)
```

---

## Güvenlik ve Uyumluluk (KVKK, GDPR, PCI-DSS)

### Netscope'un bugünkü uyumluluk durumu

| Standart | Gereklilik | Netscope Durumu |
|----------|-----------|-----------------|
| **KVKK** | Kişisel veri tespiti ve maskeleme | ⚠️ IP anonimleştirme var, içerik maskeleme yok |
| **KVKK** | Veri minimizasyonu | ⚠️ Tüm paket içeriği yakalanıyor, seçici filtre yok |
| **KVKK** | İşleme amacıyla sınırlılık | ❌ Yakalama amacı belirtme/segmentasyon yok |
| **KVKK** | Saklama süresi politikası | ❌ Otomatik veri temizleme yok |
| **GDPR** | Right to erasure (silme hakkı) | ❌ Yakalanan veriden tek kişiyi silme yok |
| **GDPR** | Data Protection Impact Assessment | ❌ DPIA şablonu/çıktısı yok |
| **PCI-DSS** | Kart verisi tespiti | ⚠️ İmza tarama ile kısmen (regex pattern) |
| **PCI-DSS** | Şifresiz kanal kontrolü | ✅ Insights → HTTP vs HTTPS oranı var |
| **ISO 27001** | Ağ erişim kontrolü loglama | ❌ Sistematik log yok |
| **ISO 27001** | Anomali izleme | ⚠️ Insights var ama sürekli değil, manuel tetikleniyor |

### Yapılması gerekenler (uyumluluk için)

1. **PII (Kişisel Veri) Maskeleme Motoru**
   - E-posta, TC Kimlik No, telefon, kredi kartı, IP → otomatik regex + format tespiti
   - Paket içeriğini göstermeden önce maskele
   - Maskelenmemiş veriyi sadece yetkili roller görsün

2. **Veri Saklama Politikası Yöneticisi**
   - "Yakalama verisini X gün sakla, sonra otomatik sil"
   - "Şu IP aralığını saklama"
   - "PCI verisi içeren paketleri saklama/süresini kısalt"

3. **Uyumluluk Rapor Şablonları**
   - KVKK uyum raporu (Türkçe)
   - GDPR compliance report (İngilizce)
   - PCI-DSS SAQ desteği
   - ISO 27001 denetim kanıt paketi

4. **Adli Bilişim Modu**
   - Delil bütünlüğü için hash zinciri
   - Zaman damgası doğrulama
   - Write-blocker modu (orijinal pcap değiştirilemez)
   - Chain of custody kaydı

---

## Toplam Sahip Olma Maliyeti (TCO) Karşılaştırması

### 50 kişilik BT ekibi olan bir kurum için 3 yıllık maliyet

| Kalem | Netscope | Wireshark | SolarWinds NPM | ExtraHop |
|-------|----------|-----------|---------------|----------|
| **Lisans** | $0 (MIT) | $0 (GPL) | ~$15,000 (50 cihaz) | ~$150,000 (appliance) |
| **Donanım** | Mevcut bilgisayarlar | Mevcut bilgisayarlar | +$5,000 (sunucu) | Cihaz fiyata dahil |
| **Kurulum** | 0.5 gün | 1 gün | 10 gün danışmanlık | 15 gün profesyonel |
| **Eğitim** | ~$0 (Learn modu) | ~$5,000 (eğitmen) | ~$7,500 (resmi eğitim) | ~$10,000 |
| **Bakım (yıllık)** | $0 | $0 | ~$3,000 (yenileme) | ~$22,500 (%15 yenileme) |
| **Yönetim (yıllık)** | 0.1 FTE | 0.25 FTE | 0.5 FTE | 1 FTE |
| **3 yıllık TCO** | **~$15,000** | **~$42,500** | **~$92,500** | **~$360,000** |

> Hesaplama varsayımları: FTE maliyeti $50,000/yıl. Eğitim maliyetleri
> ortalama piyasa fiyatlarıdır. Netscope kurumsal destek paketi (Faz 3)
> fiyata dahil değildir — tahmini $5,000-15,000/yıl olacaktır.

### Görünür maliyet vs gizli maliyet

Wireshark "ücretsiz" ama:

- 🕐 **Zaman:** Paket başına manuel analiz süresi Netscope'un 3-5 katı
- 🎓 **Eğitim:** Her yeni ekip üyesine Wireshark öğretme maliyeti
- 🔍 **Gözden kaçan bulgular:** Otomatik Insights taraması olmadığı için atlanan güvenlik olayları
- 🧩 **Entegrasyon:** Harici araçlarla (Python/Scapy) ek geliştirme maliyeti

---

## Kurumsal Yol Haritası

### Faz 1: Temel Kurumsal Altyapı (0-6 Ay) 🏗️

```
Ay 1-2 │ Netscope Server MVP
       │  ├─ REST API (axum) + WebSocket streaming
       │  ├─ JWT + API Key authentication
       │  └─ PostgreSQL (SQLite'tan geçiş)
       │
Ay 3-4 │ Kullanıcı Yönetimi
       │  ├─ Çok kullanıcılı yapı
       │  ├─ RBAC: Admin, Analist, İzleyici, Denetçi
       │  └─ Detaylı audit log
       │
Ay 5-6 │ Web Arayüzü (Netscope Web)
       │  ├─ Dashboard, paket listesi, canlı akış
       │  ├─ Kullanıcı girişi ve rol yönetimi
       │  └─ Filtreleme ve arama
```

### Faz 2: Entegrasyon ve Yönetim (6-12 Ay) 🔗

```
Ay 6-8 │ SIEM ve Uyarı Entegrasyonu
       │  ├─ Syslog / CEF / JSON formatında log çıktısı
       │  ├─ Splunk, ELK, Sentinel bağlayıcıları
       │  ├─ SMTP / Webhook alerting
       │  └─ SOAR playbook tetikleme
       │
Ay 8-10│ Ajan Mimarisi
       │  ├─ Hafif ajan (mevcut core + HTTP/WS client)
       │  ├─ Manager'a kayıt, heartbeat, config çekme
       │  ├─ Merkezden yakalama başlat/durdur
       │  └─ Ajan sağlık durumu ve alert
       │
Ay 10-12│ Merkezi Yönetim Konsolu
       │  ├─ Ajan envanteri ve durum paneli
       │  ├─ Toplu politika dağıtımı
       │  ├─ Profil/filtre paylaşımı
       │  └─ Lisans yönetimi
```

### Faz 3: Uyumluluk ve İleri Özellikler (12-18 Ay) 🛡️

```
Ay 12-14│ Uyumluluk Modülleri
        │  ├─ PII maskeleme motoru
        │  ├─ KVKK/GDPR uyum raporu
        │  ├─ PCI-DSS denetim paketi
        │  └─ ISO 27001 kanıt toplama
        │
Ay 14-16│ Adli Bilişim ve DLP
        │  ├─ Adli mod (hash zinciri, write-blocker)
        │  ├─ DLP: Kredi kartı, TCKN, telefon, eposta tespiti
        │  └─ Veri saklama politikası yöneticisi
        │
Ay 16-18│ Kurumsal Dağıtım ve Ölçekleme
        │  ├─ HA / Cluster mimarisi
        │  ├─ GPO, Intune, Jamf dağıtım paketleri
        │  ├─ K8s Helm chart
        │  └─ Kurumsal destek portalı ve SLA
```

---

## Sonuç: Bugün Kurumsalda Kullanılır mı?

### Kısa cevap: **Evet, Wireshark'ın kullanıldığı her senaryoda.**

Netscope bugün **bireysel analist** seviyesinde üretime hazır. Wireshark'tan:

- ✅ Daha hızlı
- ✅ Daha anlaşılır
- ✅ Daha güvenli (Insights otomatik tarama)
- ✅ Daha hafif
- ✅ Daha kolay öğrenilir

### Hangi kurumlar bugün geçebilir?

| Kurum tipi | Geçiş tavsiyesi |
|------------|-----------------|
| Küçük-orta BT ekibi (1-10 kişi) | ✅ **Hemen geçin.** Wireshark'tan kaybedeceğiniz hiçbir şey yok. |
| Büyük kurum (>50 kişi BT) | ⚠️ **Hibrit.** Analistler Netscope kullansın, SOC ve SIEM için Wireshark/TShark kalsın. |
| Regüle sektör (finans, sağlık) | ⚠️ **Manuel analiz için kullanın.** Denetim/uyumluluk için Faz 3'ü bekleyin. |
| SOC / 7×24 operasyon | ❌ **Henüz değil.** SIEM entegrasyonu ve merkezi yönetim gelene kadar bekleyin. |
| Kamu / Askeriye | ⚠️ **Offline analiz için kullanın.** Hava boşluklu ortamda çalışır, veri dışarı çıkmaz. |

### Alt çizgi

Netscope'un kurumsal yolculuğu 3 aşamalı:

1. **Bugün:** Wireshark alternatifi — bireysel analistler için üstün bir araç
2. **6-12 ay:** Kurumsal altyapı — çok kullanıcı, SIEM, merkezi yönetim
3. **12-18 ay:** Tam kurumsal platform — uyumluluk, adli bilişim, büyük ölçek

Kurumsal benimseme için **en büyük engel** teknik değil, **organizasyonel:**
"Wireshark varken neden değiştirelim?" sorusuna cevap, Netscope'un **otomatik
analiz, düşük eğitim maliyeti ve hız** avantajlarında yatıyor.

---

> **Not:** Bu belge canlı bir dokümandır. Netscope'un kurumsal özellikleri
> geliştikçe güncellenmelidir.
>
> **Demo ve iletişim:** [netscope.app/kurumsal](https://netscope.app/kurumsal)
> _(deploy edildiğinde)_ · [GitHub Issues](https://github.com/azzizefe/netscope/issues)
