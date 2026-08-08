# netscope — Manuel ve İleri Seviye Test Rehberi (TESTING2.md)

Bu rehber, `netscope` projesinde birim (unit) ve entegrasyon testlerinin ötesinde gerçekleştirilebilecek **manuel test senaryolarını**, **CLI komutlarını**, **veri üretme araçlarını** ve **gelişmiş bellek/kapsama doğrulama adımlarını** içerir.

---

## 1. Manuel TUI & CLI Test Senaryoları

Yönetici (Admin/root) yetkisi veya canlı ağ kartı olmadan, `fixtures/` klasöründeki pcap dosyalarını kullanarak `netscope-tui` uygulamasını manuel olarak test edebilirsiniz.

### A. Offline Pcap ile Terminal Arayüzü (TUI) Testi
Terminal kullanıcı arayüzünü (ratatui) çevrimdışı paket dosyasıyla başlatmak için:

```bash
cargo run -p netscope-tui -- -r fixtures/mixed.pcap
```

* **Test Edilecek Manuel İşlemler:**
  * `Tab` / Yön Tuşları: Paket listesinde gezinti.
  * `Enter`: Paket detay (dissection tree) ve hex izleyicisini açma.
  * `/` Tuşu: Ekran üzeri canlı filtreleme yapma (örn: `tcp.port == 80`).
  * `q` / `Esc`: Arayüzden çıkış.

### B. Headless (Metin) & JSON Çıktı Testi
Arayüz başlatmadan doğrudan paket ayrıştırma sonuçlarını stdout'a yazdırmak için:

```bash
# Düz metin (Headless)
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless

# Satır bazlı JSON (JSON Lines) çıktı
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --json
```

### C. Pcap Yönetim Araçları (Subcommands)
`netscope-tui` dahili olarak `capinfos`, `mergecap` ve `editcap` işlevlerini destekler:

```bash
# 1. Pcap Bilgisi ve Özet İstatistikleri (Info / Capinfos)
cargo run -p netscope-tui -- info fixtures/mixed.pcap

# 2. İki Pcap Dosyasını Kronolojik Olarak Birleştirme (Merge)
cargo run -p netscope-tui -- merge fixtures/http_request.pcap fixtures/dns_query.pcap -w target/merged.pcap

# 3. Pcap Dosyasını Paket Sayısına Göre Bölme (Split)
cargo run -p netscope-tui -- split fixtures/mixed.pcap -w target/split_output --packets 2
```

### D. REST API Sunucu Modu Testi (`--serve`)
TUI'yi bir REST API sunucusu olarak çalıştırıp HTTP endpoint'lerini test etmek için:

```bash
# 8080 portunda REST API sunucusu başlatır
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --serve 8080
```
Başka bir terminal penceresinden endpoint'leri test edin:
```bash
curl http://localhost:8080/api/packets
```

---

## 2. Canlı ve Yönetici Yetkili Manuel Testler

*Not: Windows üzerinde canlı paket yakalama Npcap SDK gerektirir ve Yönetici (Administrator) terminali ile çalıştırılmalıdır.*

### A. Ağ Arayüzlerini Listeleme
```bash
cargo run -p netscope-tui -- -D
```

### B. Belirli Bir Arayüzde Canlı Paket Yakalama ve BPF Filtreleme
```bash
# Windows Npcap cihaz yolu ile canlı paket yakalama (Örn: Wi-Fi kartı)
cargo run -p netscope-tui -- -i "\Device\NPF_{C0414F13-D55D-45D8-9A1A-3B802457A27D}" -f "tcp port 443" -w target/dump.pcap
```

### C. Otomatik Durdurma (Autostop) ve Ring-Buffer Testi
```bash
# 100 paket yakalayınca otomatik dur:
cargo run -p netscope-tui -- -i "\Device\NPF_{C0414F13-D55D-45D8-9A1A-3B802457A27D}" -a packets:100

# Dosya boyutu 1000 KB olunca yeni pcap dosyasına dön (Ring buffer):
cargo run -p netscope-tui -- -i "\Device\NPF_{C0414F13-D55D-45D8-9A1A-3B802457A27D}" -w target/ring.pcap -b filesize:1000
```

### D. Güvenlik Duvarı Engellerini Listeleme ve Temizleme
```bash
# Engellenen IP'leri listele
cargo run -p netscope-tui -- --list-blocked

# Tüm netscope güvenlik duvarı kurallarını kaldır
cargo run -p netscope-tui -- --unblock-all
```

---

## 3. Pcap Test Verisi Üreteci (`gen-fixtures`)

Test pcap dosyalarını yeniden üretmek veya özel durum paketleri oluşturmak için dahili `gen-fixtures` aracını çalıştırabilirsiniz:

```bash
cargo run -p gen-fixtures
```
*Bu komut `fixtures/` dizinindeki `mixed.pcap`, `http_request.pcap`, `dns_query.pcap`, `tls_handshake.pcap` gibi dosyaları sıfırdan oluşturur.*

---

## 4. Dağıtık Sunucu & Sensor Ajanı Manuel Testleri

### A. Central gRPC & REST Server (`netscope-server`)
```bash
# Sunucuyu başlatma (Varsayılan REST: 8080, gRPC: 50051)
cargo build -p netscope-server
cargo run -p netscope-server
```

### B. Sensor Agent (`netscope-agent`)
```bash
# Sensor ajanını konsol modunda çalıştırma
cargo run -p netscope-agent
```

* **Windows Servis Modu Testi (Yönetici Yetkisi ile):**
  ```powershell
  # Servis kurulumu
  cargo run -p netscope-agent -- --service install

  # Servisi başlatma
  cargo run -p netscope-agent -- --service start

  # Servisi kaldırma
  cargo run -p netscope-agent -- --service uninstall
  ```

---

## 5. Masaüstü Uygulaması (Tauri & WASM) Testleri

### A. WASM Filtreleme Modülünü Derleme
Frontend Vitest testleri ve Tauri masaüstü uygulaması WASM modülünü kullanır:

```powershell
.\tools\build-wasm.ps1
```

### B. Frontend Vitest Testlerini Çalıştırma
```bash
cd desktop/frontend-tests
npm ci
npm test
```

---

## 6. Gelişmiş Otomatik Doğrulama Araçları

### A. Miri ile Saf Bellek & Undefined Behavior (UB) Doğrulaması
Miri, Rust kodundaki tanımsız davranışları (undefined behavior) ve bellek sızıntılarını yakalar:

```powershell
.\scripts\miri.ps1
```
*Veya belirli bir modül için tekil:*
```powershell
$env:MIRIFLAGS = "-Zmiri-disable-isolation"
cargo +nightly miri test -p netscope-core -- dissectors::
```

### B. Kod Kapsaması (Code Coverage) Raporu
Windows MSVC profiler ile tüm workspace için HTML kapsama raporu üretir:

```powershell
.\scripts\coverage.ps1 -Html
```
*Rapor konumu:* `target/llvm-cov/html/index.html`

### C. Clippy & Format Denetimi
```bash
# Clippy uyarısızlık testi
cargo clippy --workspace --exclude netscope-desktop -- -D warnings

# Kod formatlama denetimi
cargo fmt --check
```

---

## 7. Manuel Test Komutları Özet Tablosu

| Test Türü | Komut | Açıklama |
|---|---|---|
| **Manuel TUI** | `cargo run -p netscope-tui -- -r fixtures/mixed.pcap` | TUI arayüzünü offline pcap ile başlatır |
| **Metin / JSON** | `cargo run -p netscope-tui -- -r fixtures/mixed.pcap --json` | JSON formatında paket dökümü |
| **Capinfos** | `cargo run -p netscope-tui -- info fixtures/mixed.pcap` | Pcap istatistik ve başlık özeti |
| **Pcap Merge** | `cargo run -p netscope-tui -- merge f1.pcap f2.pcap -w out.pcap` | İki pcap dosyasını birleştirir |
| **Pcap Split** | `cargo run -p netscope-tui -- split in.pcap -w out_prefix --packets 100` | Pcap dosyasını parçalar |
| **REST Server** | `cargo run -p netscope-tui -- -r fixtures/mixed.pcap --serve 8080` | REST API sunucusu açar |
| **Pcap Generator** | `cargo run -p gen-fixtures` | `fixtures/*.pcap` dosyalarını yeniden üretir |
| **Miri UB Check** | `.\scripts\miri.ps1` | Miri ile bellek güvenliği denetimi |
| **Kapsama Raporu** | `.\scripts\coverage.ps1 -Html` | HTML formatında test coverage üretir |
| **WASM Build** | `.\tools\build-wasm.ps1` | Frontend için WASM modülünü derler |
