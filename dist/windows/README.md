# netscope for Windows ⚡

**İnsanlar için ağ analizi.** Wireshark'a modern, hızlı bir alternatif.

---

## 📦 Bu Klasördekiler

| Dosya | Boyut | Açıklama |
|---|---|---|
| `netscope_0.1.0_x64-setup.exe` | ~4.2 MB | ⭐ **Önerilen:** Windows kurulum sihirbazı (NSIS) — Başlat Menüsü kısayolu, masaüstü simgesi, kaldırıcı |
| `netscope_0.1.0_x64_en-US.msi` | ~6.5 MB | Windows Installer paketi (MSI) — kurumsal dağıtım için |
| `netscope.exe` | ~20 MB | Taşınabilir sürüm — kurulumsuz, her yerden çalışır |

---

## ⚙️ Sistem Gereksinimleri

| Gereksinim | Detay |
|---|---|
| **İşletim Sistemi** | Windows 10 sürüm 1809+ veya Windows 11 |
| **Mimari** | x64 (64-bit) |
| **Yakalama sürücüsü** | [Npcap](https://npcap.com/#download) **gerekli** (canlı yakalama için) |
| **RAM** | ~50 MB boşta, ~200 MB yoğun yakalamada |
| **Disk** | ~25 MB |

### 🔌 Npcap Kurulumu (canlı paket yakalama için zorunlu)

1. **[npcap.com](https://npcap.com/#download)** adresinden son Npcap kurucusunu indirin
2. **Yönetici olarak** çalıştırın
3. ✅ **"Install Npcap in WinPcap API-compatible Mode"** işaretleyin
4. ✅ **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"** *(Wi-Fi için isteğe bağlı)*
5. Gerekirse yeniden başlatın

> 💡 Npcap olmadan da kayıtlı `.pcap`/`.pcapng` dosyalarını açıp analiz edebilirsiniz.

---

## 🚀 Hızlı Başlangıç

### Seçenek A: Kurulum Sihirbazı (önerilen) ⭐

1. `netscope_0.1.0_x64-setup.exe` dosyasını çalıştırın
2. Kurulum adımlarını takip edin
3. **Başlat Menüsü**'nden veya masaüstü kısayolundan başlatın

### Seçenek B: Taşınabilir

1. `netscope.exe` dosyasını herhangi bir klasöre kopyalayın
2. Çift tıklayarak çalıştırın
3. netscope birincil ağ arayüzünüzü otomatik algılar ve yakalamaya başlar

---

## 🎮 İlk Çalıştırma

netscope açıldığında:

1. **Arayüz seçin** — netscope gerçek Wi-Fi/Ethernet adaptörünüzü otomatik seçer (loopback, sanal adaptörler, WAN Miniport atlanır)
2. **Yakalamayı başlatın** — paketler anında listede belirir
3. **Herhangi bir pakete tıklayın** — alt panelde **protokol ağacı** (Frame → IP → TCP/UDP → Uygulama katmanı) ve **hex/ASCII görünümü** açılır
4. **Filtre çubuğunu kullanın** — IP, port, protokol veya alan adı yazın; sonuçlar anında filtrelenir
5. **Sekmeleri keşfedin**:
   - **📋 Packets** — üç panelli klasik paket inceleyici
   - **🔗 Connections** — TCP/UDP konuşma listesi; **Follow** ile akış verilerini okuyun
   - **🛡 Insights** — otomatik güvenlik taraması (açık metin şifreler, port taramaları, DGA alan adları...)
   - **📊 Dashboard** — canlı bant genişliği, en çok konuşanlar, protokol dağılımı
   - **🗺 Topology** — kimin kiminle konuştuğunu gösteren canlı graf
   - **⚡ Script** — yakalanan paketler üzerinde JavaScript çalıştırın

---

## ⌨️ Klavye Kısayolları

| Tuş | İşlev |
|---|---|
| `Ctrl+O` | pcap dosyası aç |
| `Ctrl+S` | yakalamayı kaydet |
| `Ctrl+E` | pcap olarak dışa aktar |
| `Ctrl+F` | filtre çubuğuna odaklan |
| `Ctrl+Enter` | script çalıştır (Script sekmesi) |
| `F5` | yakalamayı yeniden başlat |
| `Escape` | filtreyi temizle |
| `b` | seçili IP'yi engelle (Windows Güvenlik Duvarı kuralı) |
| `↑` / `↓` | paketler arası gezin |
| `Enter` | paket detayını aç |

---

## 🛡 Insights — Güvenlik & Gizlilik Taraması

**🛡 Insights** sekmesi otomatik olarak şunları tespit eder:

- 🔴 **Açık metin şifreler** (HTTP Basic, FTP, Telnet, SMTP...)
- 🟠 **Şifrelenmemiş HTTP** trafiği (URL'ler, çerezler, form verileri)
- 🟠 **Port tarama tespiti** — portlar arası bağlantı denemesi patlaması
- 🟡 **Açık metin DNS** — makinenizin sorguladığı tüm alan adları
- 🟡 **DGA benzeri alan adları** — algoritmik üretilmiş alan adları (olası zararlı yazılım C2)
- 📊 **Şifreli vs. açık metin oranı** — trafiğinizin ne kadarı güvende

---

## 🔧 Sorun Giderme

### "Hiçbir arayüz bulunamadı"
- **[Npcap](https://npcap.com/#download)** kurun (yukarıdaki talimatlara bakın)
- Npcap sürücüsü algılanmazsa netscope'u **Yönetici olarak** çalıştırın
- netscope, kurulum boyunca size rehberlik eden dahili bir sürücü algılama diyaloğuna sahiptir

### "Erişim engellendi" veya "İzin reddedildi"
- Canlı yakalama için Yönetici yetkileri gerekir
- netscope gerektiğinde yükseltme isteyecektir

### Uygulama başlamıyor / çöküyor
- **Windows 10 sürüm 1809+** veya Windows 11 gereklidir
- Son **[Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)** (x64) sürümünü yükleyin
- Windows Olay Görüntüleyicisi'ni kontrol edin

### Yüksek CPU / bellek kullanımı
- Filtre çubuğuna `tcp port 443` yazarak paketleri azaltın
- Ayarlar'dan **yakalama arabellek boyutunu** düşürün

---

## 🏗 Kaynak Koddan Derleme

```bash
# Gereksinimler: Rust 1.95+, Tauri CLI 2.x, Npcap SDK
git clone https://github.com/azzizefe/netscope.git
cd netscope
cargo tauri dev     # geliştirme modu
cargo tauri build   # Windows kurucusu oluştur
```

---

## 📝 Lisans

[MIT](https://github.com/azzizefe/netscope/blob/main/LICENSE) © azzizefe

---

## 🔗 Bağlantılar

- **GitHub:** [github.com/azzizefe/netscope](https://github.com/azzizefe/netscope)
- **Npcap:** [npcap.com](https://npcap.com/#download)
- **Sorun bildir:** [GitHub Issues](https://github.com/azzizefe/netscope/issues)

---

# netscope for Windows ⚡

**Network analysis for humans.** A modern, lightning-fast alternative to Wireshark.

## 📦 What's in this folder

| File | Size | Description |
|---|---|---|
| `netscope_0.1.0_x64-setup.exe` | ~4.2 MB | ⭐ **Recommended:** NSIS installer — Start Menu shortcut, desktop icon, uninstaller |
| `netscope_0.1.0_x64_en-US.msi` | ~6.5 MB | MSI installer — for enterprise deployment |
| `netscope.exe` | ~20 MB | Portable executable — run anywhere, no install |

## ⚙️ System Requirements

- **OS:** Windows 10 version 1809+ or Windows 11
- **Architecture:** x64 (64-bit)
- **Capture driver:** [Npcap](https://npcap.com/#download) required for live capture
- **RAM:** ~50 MB idle, ~200 MB under heavy capture

## 🚀 Quick Start

### Option A: Installer (recommended) ⭐

Run `netscope_0.1.0_x64-setup.exe` and follow the wizard.

### Option B: Portable

Copy `netscope.exe` anywhere and double-click to run.

## 🔧 Troubleshooting

- **"No interfaces found":** Install [Npcap](https://npcap.com/#download) with "WinPcap API-compatible Mode" checked
- **"Access denied":** Run as Administrator for live capture
- **App won't start:** Install [VC++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe) (x64)
- **High resource usage:** Apply a capture filter or reduce buffer size in Settings

## 📝 License

[MIT](https://github.com/azzizefe/netscope/blob/main/LICENSE) © azzizefe
