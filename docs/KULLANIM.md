# netscope — Kullanım ve Kurulum Kılavuzu (Türkçe)

> **netscope**, Wireshark'a modern ve sade bir alternatif olan bir ağ paket analiz aracıdır.
> Ham hex dökümleri yerine insan tarafından okunabilir özetler gösterir:
> `google.com → 142.250.74.46` gibi.

---

## İçindekiler

1. [Bu uygulama ne işe yarar?](#bu-uygulama-ne-işe-yarar)
2. [Kullanmak için neler gerekli? (İndirilmesi gerekenler)](#kullanmak-için-neler-gerekli)
3. [Kurulum adım adım](#kurulum-adım-adım)
4. [Sistem nasıl çalışıyor? (Mimari)](#sistem-nasıl-çalışıyor)
5. [Terminal uygulaması (TUI) kullanımı](#terminal-uygulaması-tui)
6. [Görünümler (Views)](#görünümler)
7. [Komut satırı seçenekleri](#komut-satırı-seçenekleri)
8. [Masaüstü uygulaması](#masaüstü-uygulaması)
9. [Wireshark ile karşılaştırma](#wireshark-ile-karşılaştırma)
10. [Sorun giderme](#sorun-giderme)

---

## Bu uygulama ne işe yarar?

Bilgisayarınızın ağ trafiğini **canlı olarak izler** veya daha önce kaydedilmiş
`.pcap` dosyalarını analiz eder. Hangi sitelere bağlanıldığını (DNS, TLS SNI),
hangi HTTP isteklerinin yapıldığını, hangi IP'lerin en çok konuştuğunu gösterir.

Üç farklı şekilde kullanılabilir:

| Bileşen | Ne zaman kullanılır |
|---------|--------------------|
| **TUI** (`netscope-tui`) | Terminalde canlı izleme — renkli, klavyeyle gezilebilir arayüz |
| **Headless mod** (`--headless` / `--json`) | Script'ler ve otomasyon için düz metin/JSON çıktısı |
| **Masaüstü uygulaması** (`netscope-desktop`) | Terminal sevmeyenler için grafiksel arayüz (Tauri) |

---

## Kullanmak için neler gerekli?

### Hazır derlenmiş sürümü çalıştırmak için

| Platform | İndirilmesi gereken | Neden gerekli |
|----------|--------------------|---------------|
| **Windows** | [Npcap](https://npcap.com) (ücretsiz) | Paket yakalama sürücüsü. `wpcap.dll` olmadan uygulama hiç açılmaz, sürücü olmadan canlı yakalama yapılamaz. |
| **macOS** | Hiçbir şey | libpcap sistemde hazır gelir |
| **Linux** | Hiçbir şey (libpcap genelde kuruludur) | Yoksa: `sudo apt install libpcap0.8` |

> ⚠️ **Windows'ta en sık yapılan hata:** Npcap kurulmadan uygulamayı açmaya çalışmak.
> Sonuç: sessiz çökme veya "wpcap.dll bulunamadı" hatası. Önce Npcap'i kurun.

### Kaynak koddan derlemek için (ek olarak)

- **Rust** araç zinciri (1.95+): [rustup.rs](https://rustup.rs) üzerinden kurulur
- **Windows'ta:** Visual Studio Build Tools (C++ derleyicisi) — rustup kurulumu sizi yönlendirir
- **Masaüstü uygulaması için:** WebView2 (Windows 10/11'de genellikle hazır gelir)

---

## Kurulum adım adım

### Windows

1. **Npcap'i kurun:** <https://npcap.com/#download> adresinden en son yükleyiciyi indirin.
2. Yükleyiciyi çalıştırın ve şu seçeneği **mutlaka işaretleyin**:
   ✅ *"Install Npcap in WinPcap API-compatible Mode"*
3. Projeyi derleyin:
   ```powershell
   git clone https://github.com/azzizefe/netscope.git
   cd netscope
   cargo build --release
   ```
4. Çalıştırın:
   ```powershell
   .\target\release\netscope-tui.exe -D          # arayüzleri listele
   .\target\release\netscope-tui.exe             # canlı yakalama başlat
   ```
   > Canlı yakalama için terminali **yönetici olarak** çalıştırmanız gerekebilir
   > (Npcap kurulumunda "restrict to administrators" seçtiyseniz).

### Linux

```bash
git clone https://github.com/azzizefe/netscope.git
cd netscope
cargo build --release

# Root olmadan yakalama izni ver:
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/netscope-tui

./target/release/netscope-tui
```

### macOS

```bash
git clone https://github.com/azzizefe/netscope.git
cd netscope
cargo build --release
sudo ./target/release/netscope-tui    # BPF cihazlarına erişim için sudo
```

### Kurulum yapmadan denemek

Npcap sürücüsü kurmadan bile **kayıtlı pcap dosyalarını** analiz edebilirsiniz
(sadece `wpcap.dll`'in erişilebilir olması yeterli). Projede hazır örnek
dosyalar var:

```bash
netscope-tui -r fixtures/mixed.pcap --headless
```

---

## Sistem nasıl çalışıyor?

Proje üç katmandan oluşur; tüm mantık **bir kez** yazılır, her arayüz onu paylaşır:

```
┌─────────────────────────────────────────────────────┐
│                    Ağ kartı / .pcap dosyası          │
└────────────────────────┬────────────────────────────┘
                         │ libpcap / Npcap
┌────────────────────────▼────────────────────────────┐
│  crates/core — MOTOR (paylaşılan çekirdek)           │
│  • capture.rs   → yakalama motoru (ayrı thread)      │
│  • dissectors/  → protokol çözücüler (zincir):       │
│      Ethernet → IPv4/IPv6 → TCP/UDP/ICMP(v6)/ARP     │
│                → DNS, HTTP, TLS (SNI)                │
│  • flows.rs     → bağlantı takibi (konuşma bazlı)    │
│  • names.rs     → pasif DNS: IP → alan adı önbelleği │
│  • stats.rs     → canlı istatistik (bant genişliği,  │
│                   top talkers, protokol dağılımı)    │
│  • models.rs    → Packet, Protocol, ConnectionInfo   │
└──────────┬──────────────────────────┬───────────────┘
           │ crossbeam kanalı         │
┌──────────▼───────────┐   ┌──────────▼───────────────┐
│ crates/tui           │   │ desktop/ (Tauri)          │
│ Terminal arayüzü     │   │ Masaüstü GUI              │
│ (ratatui+crossterm)  │   │ (HTML/CSS/JS ön yüz)      │
└──────────────────────┘   └───────────────────────────┘
```

**Veri akışı:** Yakalama motoru ayrı bir thread'de paketleri okur → her paketi
dissector zincirinden geçirir (asla çökmez, bozuk paket = "Unknown") → çözülen
paket bir kanala yazılır → arayüz her 50 ms'de kanaldan paketleri çekip
istatistik motoruna, akış tablosuna ve ekrana işler.

**Neden hızlı?** Rust-native; dissector zinciri saniyede 100.000+ paketi
işleyebilir (test paketinde `bench_dissect_throughput` ile doğrulanır).

**Alan adları nereden geliyor?** netscope yakaladığı DNS yanıtlarını izler ve
hangi IP'nin hangi alan adına ait olduğunu öğrenir. Böylece paket listesinde
`93.184.216.34:80` yerine `example.com:80` görürsünüz. Bu tamamen **pasiftir**:
netscope kendi başına hiçbir DNS sorgusu göndermez, ağa tek bayt eklemez.
(Yakalama başlamadan önce yapılmış sorguların IP'leri öğrenilemez — siteyi
netscope açıkken ziyaret ederseniz isim görünür.)

**Arayüz nasıl otomatik seçiliyor?** `-i` vermezseniz netscope tüm arayüzleri
puanlar: bağlı (connected) olması, gerçek bir IPv4 adresi taşıması artı puan;
loopback ve sanal bağdaştırıcılar (WAN Miniport, Hyper-V, Wi-Fi Direct) eksi
puan alır. Böylece komut tek başına çalıştırıldığında gerçek Wi-Fi/Ethernet
kartınıza düşer.

---

## Terminal uygulaması (TUI)

```bash
netscope-tui                     # ilk arayüzde otomatik yakalama
netscope-tui -i "\Device\NPF_{...}"   # belirli arayüzde (Windows adları -D ile görülür)
netscope-tui -r kayit.pcap       # kayıtlı dosyayı incele
```

### Klavye kısayolları

| Tuş | İşlev |
|-----|-------|
| `↑`/`↓` veya `j`/`k` | Paket listesinde gezin |
| `Enter` | Paket detayını aç/kapat (katman katman) |
| `Tab` / `Shift+Tab` | Görünümler arası geçiş |
| *(herhangi bir harf)* | Filtre yaz — anında süzer (IP, protokol, alan adı...) |
| `Esc` | Filtreyi temizle / yardımı kapat |
| `Space` | Yakalamayı duraklat / sürdür |
| `h` | Hex dökümünü aç/kapat |
| `?` | Yardım penceresi |
| `q` | Çıkış |

---

## Görünümler

`Tab` tuşuyla dört görünüm arasında geçiş yapılır:

### 1. Packets (Paketler)
Canlı paket akışı. Her satır protokole göre renklidir ve insan-okunur özet içerir:
`DNS Query — example.com`, `HTTP GET /api (HTTP/1.1)`, `TLS — github.com (HTTPS)`.

### 2. Dashboard (Panel)
Gerçek zamanlı istatistikler: toplam paket/bayt, anlık ve ortalama bant
genişliği, protokol dağılımı, en çok konuşan IP'ler (top talkers), en çok
sorgulanan alan adları.

### 3. Connections (Bağlantılar) — *Wireshark'taki "Conversations" karşılığı*
Paketleri **konuşma bazında** gruplar. Aynı IP:port çiftleri arasındaki gidiş
ve dönüş trafiği tek satırda birleşir:

| Sütun | Anlamı |
|-------|--------|
| Client / Server | Bağlantıyı başlatan taraf / karşı taraf |
| Proto | Görülen en spesifik protokol (TCP üstünde HTTP görüldüyse HTTP yazar) |
| Pkts | Toplam paket sayısı |
| ⇄ | Yön dağılımı (giden↑ / gelen↓) |
| Bytes | Toplam veri miktarı |
| Duration | İlk ve son paket arasındaki süre |
| Last activity | Son paketin özeti |

### 4. DNS Log
Tüm DNS sorgu ve yanıtları tek listede — hangi alan adlarına erişildiğini
bir bakışta görürsünüz.

---

## Komut satırı seçenekleri

```
netscope-tui [SEÇENEKLER]

  -i, --interface <ARAYÜZ>   Yakalama yapılacak ağ arayüzü
  -r, --read <DOSYA>         Kayıtlı .pcap dosyasını oku
  -w, --write <DOSYA>        Yakalanan paketleri .pcap olarak kaydet
  -f, --filter <BPF>         BPF filtresi (ör. "tcp port 443", "host 8.8.8.8")
  -D, --list-interfaces      Kullanılabilir arayüzleri listele
      --headless             TUI olmadan düz metin çıktı (pipe dostu)
      --json                 Satır başına bir JSON nesnesi (--headless'ı ima eder)
  -h, --help                 Yardım
```

### Örnekler

```bash
# Sadece HTTPS trafiğini yakala ve dosyaya da kaydet
netscope-tui -i eth0 -f "tcp port 443" -w https-kaydi.pcap

# Kayıtlı dosyayı JSON'a çevirip jq ile işle
netscope-tui -r kayit.pcap --json | jq -r '.summary'

# DNS trafiğini canlı izle (script'te)
netscope-tui -i eth0 -f "udp port 53" --headless
```

BPF filtre sözdizimi Wireshark/tcpdump ile aynıdır:
`host 1.2.3.4`, `net 192.168.0.0/16`, `tcp port 80`, `udp`, `icmp` vb.

---

## Masaüstü uygulaması

Terminal kullanmak istemeyenler için aynı motoru kullanan Tauri tabanlı GUI:

```bash
# Geliştirme derlemesi
cargo build -p netscope-desktop
./target/debug/netscope-desktop

# Dağıtılabilir kurulum paketi (NSIS .exe / .dmg / .AppImage)
cargo tauri build
```

Özellikler: arayüz seçici, başlat/durdur, renkli paket tablosu, filtre çubuğu,
pcap aç/kaydet (yerel dosya diyalogları).

---

## Wireshark ile karşılaştırma

| Özellik | Wireshark | netscope |
|---------|-----------|----------|
| Canlı yakalama | ✅ | ✅ |
| BPF yakalama filtresi | ✅ | ✅ |
| pcap okuma/yazma | ✅ | ✅ |
| Protokol çözümleme | ✅ 3000+ protokol | ✅ Temel set: Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP/ICMPv6, DNS, HTTP/1.x, TLS (SNI) |
| Conversations / akış görünümü | ✅ | ✅ Connections görünümü |
| İstatistik / top talkers | ✅ (menülerde gömülü) | ✅ Dashboard'da ön planda |
| Hex döküm | ✅ | ✅ (`h` ile açılır) |
| İnsan-okunur özetler | ❌ | ✅ Varsayılan |
| JSON çıktı / script entegrasyonu | Kısıtlı (tshark) | ✅ `--json` |
| Boyut | ~200 MB | ~5 MB tek binary |
| TLS şifre çözme, paket enjeksiyonu, derin L7 analizi | ✅ | ❌ Bilinçli olarak kapsam dışı (basitlik ilkesi) |

**Özet:** Günlük "ağımda ne oluyor?" sorusu için netscope; derin adli analiz
için Wireshark.

---

## Sorun giderme

### "wpcap.dll bulunamadı" / uygulama hiç açılmıyor (Windows)
Npcap kurulu değil. <https://npcap.com> adresinden kurun ve
*"WinPcap API-compatible Mode"* seçeneğini işaretleyin. Kurulumdan sonra
terminali yeniden açın.

### "Failed to open interface" hatası
- **Windows:** Npcap **sürücüsü** çalışmıyor olabilir. `sc query npcap` ile
  kontrol edin; kurulumda "restrict to administrators" işaretliyse terminali
  yönetici olarak açın.
- **Linux:** `sudo` ile çalıştırın veya `setcap` komutunu uygulayın (yukarıda).
- **macOS:** `sudo` ile çalıştırın.

### `-D` sadece loopback gösteriyor / gerçek ağ kartları görünmüyor
Npcap sürücüsü yüklü değil veya servis durmuş demektir. Npcap'i yeniden kurun.

### Yakalama çalışıyor ama hiç paket gelmiyor
- Doğru arayüzü seçtiğinizden emin olun (`-D` ile listeleyin).
- BPF filtreniz çok dar olabilir (`-f` olmadan deneyin).
- Wi-Fi'da monitör modu olmadan yalnızca kendi trafiğinizi görürsünüz — bu normaldir.

### Derleme hatası: "linker `link.exe` not found" (Windows)
Visual Studio Build Tools eksik. `rustup` size kurulum bağlantısını verir;
"Desktop development with C++" iş yükünü seçin.

### Masaüstü uygulaması boş/yanlış sayfa gösteriyor
Debug derlemesi `tauri.conf.json` içindeki `devUrl`'e bağlanmaya çalışıyor
olabilir. Bu projede `devUrl` kaldırılmıştır; ön yüz doğrudan
`desktop/frontend` klasöründen yüklenir. Sorun sürerse `cargo build -p
netscope-desktop` ile yeniden derleyin.
