# netscope — Test Edilmeyen & Çalışmayan Kod Raporu

> **Oluşturma:** 2026-07-07 | **Test sonucu:** 213 test geçti, 0 başarısız  
> **Amaç:** Testi olmayan kod yollarını, hata senaryolarını ve doğrulanmamış özellikleri listelemek

> **Güncelleme (2026-07-13):** Bu rapordaki sayılar eskidi. Güncel durum:
> **355 Rust testi** (core 322, TUI 30, desktop 2, doc-test 1) + **72 frontend
> testi**, tamamı geçiyor. Rapordaki en kritik bulgu olan
> "TUI sıfır test" kapatıldı: `app.rs` (tick/eviction/seçim takibi, tuş
> yönetimi, filtre fallback), `headless.rs` (plain/JSON çıktı),
> `views/connections.rs` (formatlayıcılar), `detail.rs`, `insights.rs`,
> `stream.rs`, `colors.rs` artık test kapsamında. §1.2'deki "paused'da kanal
> boşaltılmıyor" ve filtreli görünümde seçim taşması bug'ları düzeltildi.
> Aşağıdaki liste tarihsel referans olarak korunuyor.

> **Güncelleme (2026-07-14) — Uzaktan/USB/BT/CAN yakalama + durdurma
> koşulları:** **378 core testi** geçiyor (yeni: 41 test). Yeni modüllerin
> saf-mantık kısımları birim testli; **donanım/ortam bağımlı yollar birim
> testiyle doğrulanamaz** ve gerçek donanımda elle test edilmelidir:
>
> | Alan | Testli (birim) | Elle doğrulanmalı (donanım/ortam) |
> |---|---|---|
> | **Ring buffer** (`rotate.rs`) | Boyut/dosya rotasyonu, budama, tek-büyük-paket, geçersiz yapılandırma | Uzun süreli canlı yakalamada disk davranışı |
> | **Akış ayrıştırıcı** (`remote.rs` `PcapStreamReader`) | pcap LE/BE µs/ns, pcapng SHB/IDB/EPB/SPB, tsresol, kesik akış, çöp akış | — |
> | **SSH komut kurma** (`RemoteSpec`) | Argüman/komut dizgisi, kabuk-alıntı, filtre çevirisi | **Gerçek SSH bağlantısı, tcpdump çıktısı, auth hataları** (`start_remote`) |
> | **extcap pipe** (`spawn_pipe_source`) | extcap arayüz satırı ayrıştırma | **Alt-süreç yaşam döngüsü, stderr yakalama, kill-on-stop** |
> | **USB** (`usb.rs`) | USBPcap + usbmon sözde-başlık çözme | **Gerçek USBPcapCMD.exe / usbmon yakalaması** |
> | **Bluetooth HCI** (`bluetooth.rs`) | H4 komut/olay/ACL/LE, phdr yön | **Gerçek `bluetoothN` yakalaması** |
> | **CAN** (`can.rs`) | Std/ext/RTR/ERR/FD çerçeve özeti | **Gerçek SocketCAN (`can0`) yakalaması** |
> | **Durdurma koşulları** (`capture.rs`) | Paket/bayt limiti (stream ile), yapılandırma reddi | Süre limiti gerçek zamanlı canlı yakalamada |
> | **Desktop komutları** | — | `start_remote_capture`, USBPcap seçimi, `capture-stopped` olayı elle doğrulandı (UI render + payload eşleme, IPC hariç) |
>
> `usbpcap_cmd_path`/`usbpcap_interfaces` yalnızca Windows'ta ve USBPcap kurulu
> olduğunda anlamlı sonuç döndürür; kurulu değilse boş liste (test edilebilir
> fallback).

---

## 📊 Yönetici Özeti

```
                 Test Durumu
┌──────────────────────────────────────────┐
│  Rust (core):      157/157 ✅           │
│  Rust (desktop):     2/2   ✅           │
│  Rust (TUI):         0/0   🔴 TEST YOK │
│  Frontend (vitest): 54/54  ✅           │
│  ─────────────────────────              │
│  Toplam geçen:     213                  │
│  Toplam başarısız:  0                  │
│  EKSİK TEST:       ~80+ fonksiyon      │
└──────────────────────────────────────────┘
```

**Kritik bulgu:** Testlerin tamamı geçiyor — fakat bu, kodun hatasız olduğu anlamına gelmiyor. **TUI kodu sıfır test kapsamına sahip**, 8 Tauri komutunun testi yok, ve hata yollarının çoğu test edilmemiş.

---

## 1. 🔴 TUI Kodu — SIFIR Test Kapsamı

`crates/tui/` içinde **hiçbir test modülü yok.** 12 dosya, 500+ satır, 22 render fonksiyonu — hiçbiri test edilmemiş.

### 1.1 Test Edilmeyen TUI Dosyaları

| Dosya | Satır | Test Edilmeyen Fonksiyonlar | Risk |
|---|---|---|---|
| `app.rs` | 331 | `App::new()`, `run()`, `tick()`, `handle_key()`, `filtered_packets()`, `toggle_block_selected()`, `notify()`, `active_status()`, `elapsed_secs()` | 🔴 Kritik |
| `ui.rs` | 181 | `render()`, `render_status_bar()`, `render_keybinding_bar()`, `render_main_content()`, `render_help_overlay()` | 🔴 Kritik |
| `headless.rs` | 107 | `run()`, `format_plain()`, `format_json()` | 🟠 Yüksek |
| `colors.rs` | 36 | Protocol → color mapping | 🟡 Düşük |
| `views/packets.rs` | ~250 | `render()`, `render_packet_list()`, `render_detail_panel()`, `render_hex_dump()` | 🔴 Kritik |
| `views/connections.rs` | ~130 | `render()`, `format_bytes()`, `format_duration()` | 🟠 Yüksek |
| `views/dashboard.rs` | ~150 | `render()`, `render_stats_panel()`, `render_protocol_distribution()`, `render_bandwidth_panel()`, `render_top_talkers()` | 🟠 Yüksek |
| `views/dns_log.rs` | ~60 | `render()` | 🟡 Orta |
| `views/learn.rs` | ~120 | `render()` | 🟡 Orta |
| `main.rs` | 130 | CLI arg parsing (`clap`), `run_tui()`, dispatch logic | 🟡 Orta |

### 1.2 TUI'de Test Edilseydi Yakalanabilecek Potansiyel Bug'lar

```rust
// app.rs:185 — paused durumunda tick() hiçbir şey yapmaz.
// Ama capture engine çalışmaya devam eder → kanal şişer → bellek büyür.
// Test: "paused mode does not leak memory" — YOK
if self.paused { return; }

// app.rs:194 — MAX_PACKETS = 10_000, pop_front + selected offset.
// Seçili paket pop_front ile silinirse selected out-of-bounds olabilir.
// Test: "selection stays valid after buffer eviction" — YOK
if self.packets.len() >= MAX_PACKETS {
    self.packets.pop_front();
    if self.selected > 0 { self.selected -= 1; }
}

// app.rs:307-309 — filter parse başarısız olursa substring fallback'e geçer.
// Ama display filter tamamen geçerliyken bile fallback'e düşebilir.
// Test: "valid filter does not fall back to substring" — YOK
if let Ok(filter) = Filter::parse(&self.filter_text) { ... }
// substring fallback — TEST YOK

// connections.rs:236 — conn_selected arttırılıyor ama flow listesi boşsa?
// Test: "navigation on empty flow list" — YOK
if n > 0 && self.conn_selected + 1 < n { self.conn_selected += 1; }

// headless.rs:70 — format_json() manuel JSON üretiyor.
// Özel karakterler (quote, backslash, newline) escape edilmiyor.
// Test: "JSON output escapes special characters" — YOK
```

---

## 2. 🟠 Desktop Tauri Komutları — 8/11 Test Edilmemiş

`desktop/src-tauri/src/lib.rs` — 11 Tauri komutu var, sadece 2'si test edilmiş:

| Komut | Test Durumu | Risk |
|---|---|---|
| `list_interfaces` | ❌ Test yok | 🟡 Npcap olmayan sistemde hata dönüşü test edilmemiş |
| `start_capture` | ❌ Test yok | 🔴 En karmaşık komut — thread spawn, channel, state yönetimi |
| `stop_capture` | ❌ Test yok | 🔴 Mutex lock, engine.take(), thread join |
| `open_pcap` | ❌ Test yok | 🟠 Geçersiz dosya, boş pcap, büyük pcap senaryoları |
| `save_pcap` | ❌ Test yok | 🟠 Boş buffer, geçersiz path, write hatası |
| `get_lessons` | ❌ Test yok | 🟢 Basit data mapping |
| `get_glossary` | ❌ Test yok | 🟢 Basit data mapping |
| `is_elevated` | ❌ Test yok | 🟡 Admin/non-admin durumları |
| `list_blocked` | ❌ Test yok | 🟡 Firewall kuralı parse hatası |
| `block_ip` | ❌ Test yok | 🟠 Geçersiz IP, yetki hatası |
| `unblock_ip` | ❌ Test yok | 🟠 Var olmayan kural |
| `replay_packet` | ✅ 2 test | 🟢 TCP echo + bilinmeyen protokol |

### 2.1 Test Edilmeyen Kod Yolları (Desktop)

```rust
// lib.rs:269 — savefile oluşturma hatası sadece stderr'a yazılır.
// Test: "capture continues when savefile fails" — YOK
.and_then(|path| match cap.savefile(path) {
    Ok(sf) => Some(sf),
    Err(e) => {
        eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
        None  // ← bu path'e hiç girildi mi?
    }
});

// lib.rs:309-313 — packet buffer taşması (100k → 50k drain).
// Test: "buffer drains oldest when full" — YOK
g.names.observe(&pkt);
let info = packet_to_info(&pkt, &g.names);
g.packet_buffer.push(pkt);
if g.packet_buffer.len() > 100_000 {
    g.packet_buffer.drain(..50_000);  // ← drain doğru çalışıyor mu?
}

// lib.rs:331-337 — stop_capture, engine.take() sonrası state.
// Test: "stop during capture cleans up threads" — YOK
let mut guard = state.lock().map_err(|e| e.to_string())?;
guard.running.store(false, Ordering::SeqCst);
if let Some(mut engine) = guard.engine.take() {
    engine.stop();  // ← engine.stop() thread'i temizliyor mu?
}

// lib.rs:389-433 — save_pcap manuel pcap formatı yazıyor.
// Test: "saved pcap is valid and contains expected packets" — YOK
// Yazılan dosya tshark/wireshark ile açılabiliyor mu?
```

---

## 3. 🟡 Core Dissector'lar — Hata Yolları Test Edilmemiş

Tüm dissector testleri **sadece geçerli (happy path) paketleri** test ediyor. Hata durumları için sadece "malformed" ve "truncated" testleri var.

### 3.1 `unwrap()` Kullanan Dissector'lar

Bu `unwrap()` çağrıları geçersiz paketlerde panic üretir. Fuzz test 1000 rastgele paketle panic yakalamadıysa da teorik risk var:

```rust
// dissectors/ip.rs:42 — etherparse Ipv4Header::from_slice() hata döndürebilir
let header = Ipv4Header::from_slice(payload).unwrap();  // ⚠ PANIC RISKI

// dissectors/tcp.rs:28 — aynı risk
let header = TcpHeader::from_slice(payload).unwrap();  // ⚠ PANIC RISKI

// dissectors/udp.rs:21 — aynı risk
let header = UdpHeader::from_slice(payload).unwrap();  // ⚠ PANIC RISKI

// dissectors/ethernet.rs — 6 adet unwrap() test helper'larında
```

**Eksik testler:**
- `etherparse` parse hatası aldığında ne olur? → Test yok
- Payload tam ortada kesilirse ne olur? → Kısmen test var
- `from_slice` None döndürürse? → Test yok (fuzz test'e güveniliyor)

### 3.2 Ağ Seviyesinde Test Edilmeyenler

| Protokol | Eksik Test |
|---|---|
| QUIC | Sadece header detection, Version Negotiation / Retry testi yok |
| TLS | Sadece SNI extraction, ServerHello / Certificate parsing testi yok |
| DNS | AAAA dışında CNAME, MX, TXT, SOA kayıtları test edilmemiş |
| SIP | Sadece INVITE ve REGISTER, BYE/CANCEL/ACK testi yok |
| 802.11 | Sadece beacon ve probe, association/auth/deauth/data frame testi kısmi |
| VLAN | QinQ testi yok, sadece tek tag test edilmiş |

---

## 4. 🟡 Core Modüller — Kısmi Test Kapsamı

### 4.1 CapturedEngine — Eksik Testler

| Fonksiyon | Test | Eksik |
|---|---|---|
| `translate_bpf_filter()` | ✅ 14 test | Tüm protokoller test edilmiş |
| `list_interfaces()` | ❌ | Npcap yoksa hata dönüşü test edilmemiş |
| `default_interface()` | ❌ | Scoring algoritması test edilmemiş |
| `interface_score()` | ❌ | Loopback, connected, virtual adapter cezaları |
| `friendly_name()` | ❌ | `desc` varsa/yoksa durumları |
| `start_live()` | ❌ | Bütünleşik test yok — thread spawn, savefile, BPF |
| `start_offline()` | ❌ | Bütünleşik test yok |
| `stop()` | ❌ | Thread join testi yok |
| `is_running()` | ❌ | Başlangıç/bitiş durum geçişleri |

### 4.2 Error Path'leri — Hiç Test Edilmemiş

```rust
// capture.rs:269 — savefile hatası
// Test: "capture continues when savefile creation fails" — YOK
Err(e) => {
    eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
    None
}

// capture.rs:289 — yakalama hatası
// Test: "capture stops on non-timeout error" — YOK
Err(e) => {
    eprintln!("Capture error: {e}");
    break;
}

// capture.rs:283 — channel kopması
// Test: "capture thread exits when receiver is dropped" — YOK
if packet_tx.send(packet).is_err() {
    break;
}
```

### 4.3 StatsEngine — Eksik Testler

| Durum | Test | Not |
|---|---|---|
| `record_packet()` — 1 paket | ✅ | |
| `record_packet()` — çoklu protokol | ✅ | |
| `record_packet()` — top talkers | ✅ | |
| `record_packet()` — DNS domains | ✅ | |
| `tick()` — bant genişliği örneklemesi | ❌ | Saniye bazlı örnekleme testi yok |
| `snapshot()` — boş | ✅ | |
| `snapshot()` — 60+ saniye rolling window | ❌ | 60 örnek limiti test edilmemiş |
| Concurrent `record_packet()` | ❌ | Thread-safe değil, ama test yok |

### 4.4 NameCache — Eksik Testler

| Durum | Test |
|---|---|
| MAX_ENTRIES (50k) limiti | ❌ Limit aşımı test edilmemiş |
| DNS CNAME record'ları | ❌ Sadece A ve AAAA test edilmiş |
| Eşzamanlı observe çağrıları | ❌ Thread-safe değil |

### 4.5 FlowTable — Eksik Testler

| Durum | Test |
|---|---|
| 10,000+ akış performansı | ❌ |
| `clear()` + yeniden kayıt | ✅ `clear_resets_table` var |
| `flows()` boş liste | ❌ `is_empty()` kullanılıyor ama görüntülenme testi yok |

---

## 5. 🟡 Frontend — Eksik Test Alanları

### 5.1 Vitest'te Test Edilmeyen Frontend Fonksiyonları

| Fonksiyon Grubu | Test Durumu |
|---|---|
| `renderPacketList()` | ❌ Test yok — en karmaşık render fonksiyonu |
| `buildDetailTree()` | ❌ Test yok — protokol ağacı oluşturma |
| `showDetail()` | ❌ Test yok — tüm detay paneli |
| `hexDump()` | ❌ Test yok |
| `openFollowStream()` | ❌ Test yok |
| `analyzeCapture()` | ✅ Kısmen — sadece `flags cleartext credentials` |
| `renderInsights()` | ❌ Test yok |
| `renderDashboard()` | ❌ Test yok |
| `buildTopologyGraph()` | ❌ Test yok |
| `layoutTopology()` | ❌ Test yok |
| `runScript()` | ❌ Test yok |
| `applyProfile()` | ❌ Test yok |
| `lookupGeo()` | ❌ Test yok (ağ çağrısı) |
| `packetToCurl()` | ✅ 1 test |
| `bytesToCode()` | ✅ 1 test |

### 5.2 Frontend'de Test Edilmeyen Hata Senaryoları

```javascript
// app.js — 8 adet console.log var (debugging kalıntısı)
// Test: "no console.log in production" — YOK

// filter.js — compile() null döndüğünde fallback çalışıyor mu?
// Test: "filter fallback is triggered" — KISMEN var

// Dosya yükleme (drag-drop, file dialog) — tamamen test dışı
```

---

## 6. 🔴 Bütünleşik (Integration) Testler — HİÇ YOK

Aşağıdaki uçtan uca senaryoların hiçbiri otomatik test edilmiyor:

```
1. TUI başlat → pcap aç → paketleri listele → paket seç → detay göster
   Durum: ❌ TEST YOK

2. Desktop başlat → capture başlat → 100 paket al → durdur → pcap kaydet
   Durum: ❌ TEST YOK

3. Filtre yaz → sonuçları gör → filtreyi temizle → tüm paketleri gör
   Durum: ❌ TEST YOK

4. TCP stream'i takip et → stream içeriğini doğrula
   Durum: ❌ TEST YOK

5. Firewall: IP engelle → kuralı doğrula → engeli kaldır
   Durum: ❌ TEST YOK (admin yetkisi gerekiyor)

6. Pcap kaydet → kaydedilen dosyayı Wireshark'ta aç
   Durum: ❌ TEST YOK

7. Monitor mode → 802.11 paketleri yakala → beacon/SSID doğrula
   Durum: ❌ TEST YOK (donanım bağımlı)
```

---

## 7. 🟠 Platform'a Özel Test Edilmeyen Kodlar

| Platform | Özellik | Test Durumu |
|---|---|---|
| **Windows** | Npcap olmadan hata mesajı | ❌ Test yok |
| **Windows** | `netsh advfirewall` kural ekleme/silme | ❌ Admin yetkisi gerek |
| **Windows** | Monitor mode reddi (açık hata mesajı) | ❌ Test yok |
| **Linux** | `CAP_NET_RAW` olmadan hata mesajı | ❌ Linux CI'da test edilebilir |
| **Linux** | Monitor mode (rfmon) | ❌ Donanım bağımlı |
| **macOS** | libpcap built-in | ❌ macOS CI var ama test sonucu bilinmiyor |

---

## 8. Test Edilmeyen Kodların Risk Matrisi

| Risk Seviyesi | Sayı | En Kritik 3 |
|---|---|---|
| 🔴 **Kritik** | 15+ | 1. `App::tick()` — paket buffer yönetimi ve seçim kaydırma<br>2. `start_capture` — thread spawn ve state yönetimi<br>3. Dissector `unwrap()` zinciri — teorik panic riski |
| 🟠 **Yüksek** | 25+ | 4. `save_pcap` — manuel binary format yazımı<br>5. `stop_capture` — thread cleanup<br>6. TUI render fonksiyonları (5 görünüm) |
| 🟡 **Orta** | 20+ | 7. headless JSON/plain format<br>8. StatsEngine bandwidth sampling<br>9. NameCache 50k limit |
| 🟢 **Düşük** | 15+ | 10. colors.rs mapping<br>11. get_lessons/get_glossary |

---

## 9. Nasıl Test Edilir? — Önerilen Yaklaşımlar

### 9.1 TUI Snapshot Testleri (insta crate)

```rust
// crates/tui/src/views/packets.rs — eklenecek test
#[test]
fn packet_list_renders_correctly() {
    let mut app = test_app_with_packets(5);
    let mut buffer = TestBackend::new(80, 24);
    terminal.draw(|f| render_packet_list(f, area, &app)).unwrap();
    // insta::assert_snapshot!(buffer);  // snapshot karşılaştırma
}
```

### 9.2 Desktop Tauri Integration Testleri

```rust
// desktop/src-tauri/tests/capture_test.rs — eklenecek
#[test]
fn start_and_stop_capture_integration() {
    let app = tauri::test::mock_app(tauri::generate_context!());
    // start_capture → 1 saniye bekle → stop_capture → packet_buffer boş değil
}
```

### 9.3 Error Path Testleri

```rust
// crates/core/src/capture.rs — eklenecek test
#[test]
fn start_live_fails_on_nonexistent_interface() {
    let mut engine = CaptureEngine::new();
    let (tx, _rx) = crossbeam_channel::unbounded();
    let result = engine.start_live("nonexistent999", None, None, tx, false);
    assert!(result.is_err());
}
```

### 9.4 Property-Based Testler (proptest)

```rust
// Herhangi bir byte dizisi dissector'da panic üretmemeli
proptest! {
    #[test]
    fn arbitrary_bytes_dont_panic(data in any::<Vec<u8>>()) {
        let _ = dissect(&data);  // asla panic olmamalı
    }
}
```

---

## A. Genel Değerlendirme

| Metrik | Değer |
|---|---|
| Toplam test | 213 |
| Başarısız test | 0 |
| Test kapsamı (core) | ~%40 tahmini |
| Test kapsamı (TUI) | **%0** |
| Test kapsamı (desktop backend) | ~%10 (2/11 komut) |
| Test kapsamı (frontend) | ~%15 (yardımcı fonksiyonlar, render yok) |
| Eksik test edilen fonksiyon | **80+** |
| Eksik hata yolu testi | **50+** |
| Bütünleşik test | **0** |

> **Sonuç:** Kod temiz (sıfır clippy, sıfır unsafe), testlerin geçtiği kısım sağlam. Ancak **TUI ve Desktop komutlarındaki sıfır test kapsamı**, büyük bir risk oluşturuyor. Bir sonraki sprint'te öncelikle TUI snapshot testleri ve `start_capture`/`stop_capture` integration testleri eklenmeli.
