# netscope — Otomatik Testle Doğrulanamayan Yollar

> **Son güncelleme:** 3 Ağustos 2026

Bu doküman bir **kapsam raporu değil.** Kapsam sayısı CI'ın işi: `cargo test`
her push'ta koşuyor ve sayıyı orada görürsün. Burada yazan şey, **birim testinin
prensip olarak doğrulayamayacağı** yollar — gerçek donanım, gerçek ayrıcalık
seviyesi ya da gerçek bir uzak makine gerektirenler. Bunlar bir sürüm öncesi
elle doğrulanmalıdır.

**Bugünkü test sayısı:** 2330 core + 44 TUI + 18 agent + 25 server + 24 desktop
+ 1 wasm Rust testi (workspace toplamı 2.462 geçiyor, 4'ü `#[ignore]`).

---

## 1. Donanım ve ortam bağımlı yakalama yolları

Saf mantık kısımları birim testli; sağdaki sütun gerçek donanımda elle
doğrulanmalı.

| Alan | Testli (birim) | Elle doğrulanmalı |
|---|---|---|
| **Ring buffer** (`rotate.rs`) | Boyut/dosya rotasyonu, budama, tek-büyük-paket, geçersiz yapılandırma | Uzun süreli canlı yakalamada disk davranışı |
| **Akış ayrıştırıcı** (`remote.rs` `PcapStreamReader`) | pcap LE/BE µs/ns, pcapng SHB/IDB/EPB/SPB, tsresol, kesik akış, çöp akış | — |
| **SSH komut kurma** (`RemoteSpec`) | Argüman/komut dizgisi, kabuk-alıntı, filtre çevirisi | **Gerçek SSH bağlantısı, tcpdump çıktısı, auth hataları** (`start_remote`) |
| **extcap pipe** (`spawn_pipe_source`) | extcap arayüz satırı ayrıştırma | **Alt-süreç yaşam döngüsü, stderr yakalama, kill-on-stop** |
| **USB** (`usb.rs`) | USBPcap + usbmon sözde-başlık çözme | **Gerçek USBPcapCMD.exe / usbmon yakalaması** |
| **Bluetooth HCI** (`bluetooth.rs`) | H4 komut/olay/ACL/LE, phdr yön | **Gerçek `bluetoothN` yakalaması** |
| **CAN** (`can.rs`) | Std/ext/RTR/ERR/FD çerçeve özeti | **Gerçek SocketCAN (`can0`) yakalaması** |
| **Durdurma koşulları** (`capture.rs`) | Paket/bayt limiti (stream ile), yapılandırma reddi | Süre limiti gerçek zamanlı canlı yakalamada |
| **Arayüz sayımı** (`list_interfaces`) | Dönen her satırın biçimi: boş olmayan ad, bilinen `kind`, tekrarsız isim | **Gerçek bir adaptörün listelenmesi** — sürücüsüz makinede liste boş döner, bu meşru bir sonuç |
| **Desktop komutları** | — | `start_remote_capture`, USBPcap seçimi, `capture-stopped` olayı (UI render + payload eşleme) |

`usbpcap_cmd_path` / `usbpcap_interfaces` yalnızca Windows'ta ve USBPcap kurulu
olduğunda anlamlı sonuç döndürür; kurulu değilse boş liste — bu fallback test
edilebilir, gerçek yakalama değil.

---

## 2. Platforma özel yollar

| Platform | Özellik | Neden otomatikleştirilemiyor |
|---|---|---|
| Windows | Npcap kurulu değilken verilen hata mesajı | CI runner'ında Npcap SDK var, sürücü yok |
| Windows | `netsh advfirewall` kural ekleme/silme | Yönetici yetkisi gerekir |
| Windows | Monitor mode reddi | Npcap monitor mode'u desteklemeyen kartlarda değişiyor |
| Linux | `CAP_NET_RAW` olmadan verilen hata | CI'da denenebilir — henüz denenmedi |
| Linux | Monitor mode (rfmon) | Kart ve sürücü bağımlı |
| macOS | Kök yetkisiz `/dev/bpf` erişimi | CI runner'ının yetki modeli farklı |

---

## 3. Agent'ın kendi kendini güncellemesi

`upgrade.rs` içindeki **ret yolları** testli: anahtar gömülü değilse, imza
yoksa, anahtar ya da imza bozuksa reddediyor. **Doğrulamanın başarılı olduğu
yol test edilemiyor** — bir anahtar çiftinin gizli yarısını gerektirir.

Sürüm hattı gerçek bir imzalama anahtarı üretince, imzalı bir yapıyı fixture
olarak eklemek ve pozitif yolu da teste bağlamak gerekiyor. Ayrıntılar için
`SECURITY.md`'deki "Fleet deployment" bölümü.

---

## Bu dokümanda ne yoktu, neden çıkarıldı

7 Temmuz 2026'da oluşturulan hâli bir kapsam boşluğu raporuydu: TUI'nin sıfır
testi olduğunu, 8 Tauri komutunun test edilmediğini, toplam 213 test bulunduğunu
söylüyordu. **Bu boşlukların hepsi kapandı** — TUI'nin 36 testi var, komut sayısı
otuzu aştı, toplam test 2200'ü geçti. Rapordaki satır numaraları da o günden beri
kaydı.

Kapanmış boşlukları listeleyen bir doküman, okuyanı var olmayan bir işe
yönlendirir. Tarihsel hâli git geçmişinde duruyor:

```bash
git log --follow -p UNTESTED.md
```
