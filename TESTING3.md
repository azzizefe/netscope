# netscope — Yayınlama ve Prodüksiyon Öncesi Tam Test Rehberi (TESTING3.md)

Bu doküman, `netscope` sistemini canlıya (production/release) almadan önce çalıştırılması gereken **tüm otomatik Rust testlerini**, **manuel TUI/CLI senaryolarını**, **dağıtık servis doğrulama adımlarını**, **güvenlik/bellek analizlerini** ve **yayınlama öncesi son kontrol matrisini (Master Release Checklist)** bir arada sunar.

---

## 📑 İçindekiler

1. [Otomatik Rust Testleri](#1-otomatik-rust-testleri)
2. [Benchmark ve Performans Testleri](#2-benchmark-ve-performans-testleri)
3. [Manuel TUI & Canlı Paket Yakalama Testleri](#3-manuel-tui--canlı-paket-yakalama-testleri)
4. [Dağıtık Sunucu & Sensor Ajanı Testleri](#4-dağıtık-sunucu--sensor-ajanı-testleri)
5. [Masaüstü (Tauri) ve WASM Testleri](#5-masaüstü-tauri-ve-wasm-testleri)
6. [Güvenlik, Statik Analiz ve Bellek Doğrulama](#6-güvenlik-statik-analiz-ve-bellek-doğrulama)
7. [Yayınlama Öncesi Master Kontrol Listesi (Pre-Release Checklist)](#7-yayınlama-öncesi-master-kontrol-listesi-pre-release-checklist)

---

## 1. Otomatik Rust Testleri

Sistemdeki tüm birim (unit) ve entegrasyon testlerinin hatasız geçtiğinden emin olun.

### A. Tüm Workspace Testleri
```bash
# Tüm Rust paketlerini sessiz modda test edin (-- --quiet binlerce satır dökümünü engeller)
cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent -- --quiet
```

### B. Paket (Crate) Bazlı Detaylı Testler
```bash
# Sadece Core paketi testleri
cargo test -p netscope-core -- --quiet

# Sadece TUI paketi testleri
cargo test -p netscope-tui -- --quiet

# Sadece gRPC Server paketi testleri
cargo test -p netscope-server -- --quiet

# Sadece Sensor Agent paketi testleri
cargo test -p netscope-agent -- --quiet

# Desktop (Windows/macOS) testi
cargo test -p netscope-desktop
```

### C. Tekil Fonksiyon ve Entegrasyon Testleri
```bash
# Tek bir modül testi (Örn: HTTP dissector)
cargo test -p netscope-core --lib dissectors::http::tests

# pcap entegrasyon testleri (fixtures/ klasörünü kullanır)
cargo test -p netscope-core --test integration_test
```

---

## 2. Benchmark ve Performans Testleri

Sistemin paket işleme başarımını ve bellek tüketimini doğrulamak için Criterion benchmark'larını çalıştırın.

```bash
# 1. Paket Ayrıştırma Hızı (Dissection Throughput)
cargo bench -p netscope-core --bench parse_throughput

# 2. Filtre Eşleşme Hızı (Display Filter Throughput)
cargo bench -p netscope-core --bench filter_match

# 3. Bellek Kullanımı İstatistikleri
cargo bench -p netscope-core --bench mem_usage

# 4. Pipeline İşleme Kapasitesi
cargo bench -p netscope-core --bench pipeline_throughput
```

*Özel Not: Criterion benchmark komutlarında `-- --quick` parametresi kullanmayın (Criterion bu parametreyi regex filtresi olarak algılar).*

---

## 3. Manuel TUI & Canlı Paket Yakalama Testleri

### A. Ağ Arayüzlerini Listeleme (Npcap)
```bash
cargo run -p netscope-tui -- -D
```

### B. Npcap Cihaz Yolu İle Canlı Yakalama (Windows)
Windows ortamında Npcap cihaz yollarını (`\Device\NPF_{...}`) kullanın:

```bash
# 1. Wi-Fi arayüzünde canlı yakalama ve BPF filtresi
cargo run -p netscope-tui -- -i "\Device\NPF_{C0414F13-D55D-45D8-9A1A-3B802457A27D}" -f "tcp port 443" -w target/dump.pcap

# 2. Yerel Loopback trafiği yakalama
cargo run -p netscope-tui -- -i "\Device\NPF_Loopback"

# 3. Otomatik durdurma (Autostop - 100 pakette dur)
cargo run -p netscope-tui -- -i "\Device\NPF_Loopback" -a packets:100

# 4. Dönen dosya kaydı (Ring-Buffer - 1000 KB'da bir yeni pcap)
cargo run -p netscope-tui -- -i "\Device\NPF_Loopback" -w target/ring.pcap -b filesize:1000
```

### C. Offline Pcap ve CLI Araçları
```bash
# 1. İnteraktif TUI Testi (Pcap Okuma)
cargo run -p netscope-tui -- -r fixtures/mixed.pcap

# 2. Headless Düz Metin Çıktısı
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless

# 3. JSON Lines Çıktısı
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --json

# 4. Pcap Dosya Özeti (info)
cargo run -p netscope-tui -- info fixtures/mixed.pcap

# 5. Pcap Birleştirme (merge)
cargo run -p netscope-tui -- merge fixtures/http_request.pcap fixtures/dns_query.pcap -w target/merged.pcap

# 6. Pcap Bölme (split)
cargo run -p netscope-tui -- split fixtures/mixed.pcap -w target/split_output --packets 2
```

### D. Live REST API Sunucu Modu
```bash
# Terminal 1: Canlı yakalama ile REST API sunucusu başlatın
cargo run -p netscope-tui -- -i "\Device\NPF_Loopback" --serve 8080

# Terminal 2: HTTP endpoint'ini sorgulayın
curl http://localhost:8080/api/packets
```

---

## 4. Dağıtık Sunucu & Sensor Ajanı Testleri

### A. Central gRPC & REST Server (`netscope-server`)
```bash
# Sunucuyu derleyin ve başlatın (REST: 8080, gRPC: 50051)
cargo build -p netscope-server
cargo run -p netscope-server
```

### B. Sensor Agent (`netscope-agent`)
```bash
# Konsol modunda çalıştırma
cargo run -p netscope-agent

# Windows Servis İşlemleri (Yönetici Yetkili PowerShell):
cargo run -p netscope-agent -- --service install
cargo run -p netscope-agent -- --service start
cargo run -p netscope-agent -- --service uninstall
```

---

## 5. Masaüstü (Tauri) ve WASM Testleri

### A. WASM Filtre Modülünün Hazırlanması
Masaüstü ve Vitest testlerinin bağımlı olduğu WASM modülünü derleyin:
```powershell
.\tools\build-wasm.ps1
```

### B. Frontend Vitest Sandbox Testleri
```bash
cd desktop/frontend-tests
npm ci
npm test
```

### C. Tauri Uygulaması Derleme ve Testi
```bash
# Dev modunda başlatma
cd desktop/src-tauri
cargo tauri dev

# Prodüksiyon derlemesi (Release Binary / Installer)
cargo build -p netscope-desktop --release
```

---

## 6. Güvenlik, Statik Analiz ve Bellek Doğrulama

### A. Clippy Lint Kontrolü (Sıfır Uyarısızlık Şartı)
```bash
cargo clippy --workspace --exclude netscope-desktop -- -D warnings
```

### B. Kod Formatı Kontrolü
```bash
cargo fmt --check
```

### C. Miri ile Saf Bellek & Undefined Behavior (UB) Doğrulaması
```powershell
.\scripts\miri.ps1
```

### D. Kod Kapsaması (Code Coverage) Raporu
```powershell
.\scripts\coverage.ps1 -Html
```
*Üretilen HTML Raporu:* `target/llvm-cov/html/index.html`

---

## 7. Yayınlama Öncesi Master Kontrol Listesi (Pre-Release Checklist)

Sistemi canlıya almadan veya yayınlamadan önce aşağıdaki maddelerin tamamının onaylandığından emin olun:

- [ ] **Tüm Rust Unit & Entegrasyon Testleri Başarılı:** `cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent -- --quiet` sıfır hata ile tamamlandı.
- [ ] **Clippy Uyarısızlık (Zero Warnings):** `cargo clippy --workspace --exclude netscope-desktop -- -D warnings` temiz geçti.
- [ ] **Formatlama Uygunluğu:** `cargo fmt --check` hatasız bitti.
- [ ] **WASM Modülü Güncel:** `.\tools\build-wasm.ps1` hatasız derlendi.
- [ ] **Frontend Vitest Testleri Başarılı:** `npm test` tüm JS/WASM testlerinden geçti.
- [ ] **Miri Bellek Güvenliği Doğrulandı:** `.\scripts\miri.ps1` tanımsız davranış (UB) ve sızıntı tespit etmedi.
- [ ] **Release Derlemesi Başarılı:** `cargo build --workspace --release` kilitlenme veya linkleme hatası olmadan derlendi.
- [ ] **Pcap Araçları Doğrulandı:** `info`, `merge`, `split` komutları beklendiği gibi çalışıyor.
- [ ] **Npcap Canlı Paket Yakalama Doğrulandı:** NPF aygıt yolu ile paket yakalama ve BPF filtresi çalışıyor.
- [ ] **Servis Kurulumu Doğrulandı:** `netscope-agent --service install` servisi sorunsuz kaydetti.
