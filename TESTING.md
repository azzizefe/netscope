# netscope — Test Rehberi

## Test Komutları

```bash
# Tüm Rust testleri (core hariç her şey)
cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent

# Sadece core
cargo test -p netscope-core

# Sadece tek bir test
cargo test -p netscope-core --lib filter::tests::test_filter_tcp_port

# Ignored test yok — 2026-08-03'ten beri sıfır.
# Dördü de kaldırıldı, çünkü ignore edilen bir test kimse için çalışmaz ve bu
# depoda tam olarak bu yüzden iki koruma sessizce devre dışı kaldı:
#   * iki throughput testi criterion bench'lerine taşındı (`cargo bench`),
#   * erişilebilirlik backlog'u `UNREACHABLE_BACKLOG` ile sabitlendi,
#   * 65.536 portluk sweep, eşdeğerliği kanıtlanmış bir örneklemle değiştirildi.

# Benchmark
cargo bench -p netscope-core --bench parse_throughput -- --quick

# Kod kapsaması. Düz `cargo llvm-cov` Windows'ta çalışmaz (aşağıdaki nota bak),
# script doğru toolchain'i kendisi seçiyor:
.\scripts\coverage.ps1            # terminalde özet
.\scripts\coverage.ps1 -Html      # target/llvm-cov/html/index.html

# Fuzzing — Windows'ta iki şart var ve ikisi de hata mesajından anlaşılmıyor:
#   1. nightly + MSVC toolchain. Varsayılan windows-gnu'da libfuzzer-sys'in
#      kendi libFuzzer kopyası derlenmiyor (Windows desteği MSVC'ye özgü).
#   2. ASan runtime DLL'i PATH'te olmalı, yoksa binary derlenir ama
#      STATUS_DLL_NOT_FOUND (0xc0000135) ile başlamaz — mesaj DLL adını vermez.
# Ayrıntı ve tam yollar: fuzz/README.md
$asan = "C:\Program Files\Microsoft Visual Studio\<sürüm>\<edition>\VC\Tools\MSVC\<toolset>\bin\Hostx64\x64"
$env:PATH = "$asan;$env:PATH"
cargo +nightly-x86_64-pc-windows-msvc fuzz run parse_packet_fuzz \
  --target x86_64-pc-windows-msvc -- -max_total_time=60

# Miri (Bellek Doğrulama & Undefined Behavior Denetimi)
# Chrono/SystemTime çağrılarının izolasyon engeline takılmaması için:
$env:MIRIFLAGS = "-Zmiri-disable-isolation"
cargo +nightly miri test -p netscope-core -- tcp_syn

# Frontend testleri
cd desktop/frontend-tests && npm test

# Clippy
cargo clippy --workspace --exclude netscope-desktop -- -D warnings
```

## Test Türleri

### Birim Testleri (Rust)

Her kaynak dosyanın altında `#[cfg(test)] mod tests { ... }` bloğu içinde. Private fonksiyonlara `use super::*` ile erişir.

**Desen:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_setup() -> Packet {
        // ...
    }

    #[test]
    fn test_basic_parsing() {
        let p = fixture_setup();
        assert!(p.protocol == Protocol::Tcp);
    }
}
```

### Entegrasyon Testleri

`crates/core/tests/integration_test.rs` — Gerçek pcap dosyalarını `fixtures/` dizininden okur. Sadece public API kullanır.

**Desen:**
```rust
use netscope_core::capture::*;

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures"))
}

#[test]
fn pcap_http_request() {
    let pkts = run_pcap(fixtures().join("http-request.pcap"));
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].protocol, Protocol::Http);
}
```

### Frontend Testleri (Vitest)

`desktop/frontend-tests/` — Node.js VM sandbox'ında çalışır. `load-app.js` gerçek kaynak kodunu yükler, DOM/Tauri globallerini stub'lar.

**Desen:**
```javascript
import { describe, it, expect } from 'vitest';
import { loadFilter, tcpFrame } from './load-app.js';

const F = loadFilter();

describe('filter', () => {
    it('matches TCP port', () => {
        expect(F.matches(tcpFrame(443), 'tcp.port == 443')).toBe(true);
    });
});
```

### Benchmark'lar (Rust)

`crates/core/benches/` — `#[cfg(test)]` kodunu göremez, bu yüzden yardımcı fonksiyonlar `common/mod.rs`'de tekrar tanımlanır.

**Desen:**
```rust
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

mod common;

fn bench_parse(c: &mut Criterion) {
    let packets = common::build_mixed_packets(1_000);
    let mut g = c.benchmark_group("parse_throughput");
    g.throughput(Throughput::Elements(packets.len() as u64));
    g.bench_function("dissect_mixed", |b| {
        b.iter(|| {
            for p in &packets {
                netscope_core::dissectors::dissect(black_box(p));
            }
        })
    });
    g.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
```

## Windows'ta neden bazı araçlar varsayılan toolchain'de çalışmıyor

Bu depoda üç araç aynı sebeple `stable-x86_64-pc-windows-gnu` üzerinde
başarısız oluyor, ve **üçünün de hata mesajı sebebi söylemiyor**. Hepsi LLVM'in
çalışma zamanı bileşenlerine ihtiyaç duyuyor; rustup bunları windows-gnu için
dağıtmıyor, MSVC için dağıtıyor.

| Araç | windows-gnu'daki hata | Gerçek sebep | Çözüm |
|---|---|---|---|
| `cargo llvm-cov` | ``can't find crate for `profiler_builtins` `` | Kapsama sayaçları profiler runtime'ı ister; gnu toolchain'inde bu kütüphane hiç yok | `.\scripts\coverage.ps1` |
| `cargo fuzz` (derleme) | `FuzzerExtFunctionsWindows.cpp: expected constructor…` | libfuzzer-sys kendi libFuzzer kopyasını derliyor; Windows desteği `__pragma(comment(linker, …))` kullanıyor | MSVC Nightly Toolchain (`+nightly-x86_64-pc-windows-msvc`) |
| `cargo fuzz` (çalıştırma) | `STATUS_DLL_NOT_FOUND (0xc0000135)` | ASan runtime'ı Windows'ta ayrı bir DLL (`clang_rt.asan_dynamic-x86_64.dll`) ve PATH'te değil | PATH'e ASan DLL ekleme + `cargo fuzz run` |

Çözüm üçü için de aynı: **MSVC toolchain'ini kullan.**

### 1. Kod Kapsaması (Coverage)
```powershell
.\scripts\coverage.ps1
```

### 2. Fuzzing Derleme & Çalıştırma
```powershell
# 1. ASan DLL yolunu PATH'e ekle (Visual Studio MSVC toolset dizini)
$asan = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64"
$env:PATH = "$asan;$env:PATH"

# 2. MSVC Nightly toolchain ile fuzzing çalıştır
cargo +nightly-x86_64-pc-windows-msvc fuzz run parse_packet_fuzz --target x86_64-pc-windows-msvc -- -max_total_time=60
```

Denenip **işe yaramayan** yol (bir daha denememek için): gnu toolchain'ine
`rustup target add x86_64-pc-windows-msvc` ile msvc hedefini eklemek ve
`--target` vermek. Hedef tarafı için profiler runtime'ı geliyor, ama
cargo-llvm-cov build script'lerini de enstrümante ediyor ve onlar **host** için
derleniyor — host hâlâ gnu. Değişmesi gereken şey hedef değil, toolchain.

Son ölçüm (2026-08-04, **tüm workspace** — 2471 test):
**%75,1 region · %81,7 fonksiyon · %76,2 satır.**

Bu sayı bir önceki ölçümden (%75,7) düşük, çünkü kapsam genişledi:
`netscope-desktop` dışarıda tutulmuyor artık. Dışlanmasının sebebi, Tauri
hedeflerinin MSVC altında linklenmemesiydi — manifest resource'unun iki kez
linklenmesi. `desktop/src-tauri/build.rs` arşivi artık `-tests` kapsamıyla
veriyor, dışlamaya gerek kalmadı; ayrıntısı oradaki yorumda. Desktop crate'i
kendi başına %30,2 region, ortalamayı aşağı çeken kısım o.

Fuzzing ayrıca nightly istiyor; tam komut ve ASan yolu için `fuzz/README.md`.

Linux'ta bunların hiçbiri gerekmiyor — bileşenler toolchain'le geliyor. CI
Linux'ta koştuğu için orada ek bir ayar yok.

## Test Yardımcıları

| Yardımcı | Yer | Kapsam | Açıklama |
|---|---|---|---|
| `test_helpers::build_tcp_packet(...)` | [dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs#L1248) | `pub(crate)` | Core içi Ethernet + IPv4 + TCP paket baytları üretir |
| `test_helpers::build_udp_packet(...)` | [dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs#L1281) | `pub(crate)` | Core içi Ethernet + IPv4 + UDP paket baytları üretir |
| `test_helpers::build_dns_query(...)` | [dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs#L1335) | `pub(crate)` | Minimal DNS A-record sorgu paketi üretir |
| `test_helpers::build_arp_packet(...)` | [dissectors.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors.rs#L1309) | `pub(crate)` | ARP request/reply paketi üretir |
| `run_pcap(path)` | [integration_test.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/tests/integration_test.rs#L13) | Entegrasyon | Offline pcap dosyasını pipeline'dan geçirir ve `Vec<Packet>` döner |
| `load-app.js` helpers | [load-app.js](file:///c:/Users/efe/Desktop/netscope/desktop/frontend-tests/load-app.js) | Frontend Testleri | `tcpFrame()`, `loadFilter()` gibi Vitest test ortamı yardımcıları |

**Desen Örnekleri:**

```rust
// Core Unit Testlerinde Paket Üretimi
use crate::dissectors::test_helpers::{build_tcp_packet, TcpFlags};

let raw_pkt = build_tcp_packet(
    [10, 0, 0, 1], [10, 0, 0, 2],
    12345, 80,
    TcpFlags { syn: true, ..Default::default() },
    b"GET / HTTP/1.1\r\n\r\n"
);
```

```javascript
// Frontend Vitest Yardımcıları Kullanımı
import { loadFilter, tcpFrame } from './load-app.js';

const F = loadFilter();
const frame = tcpFrame(443);
expect(F.matches(frame, 'tcp.port == 443')).toBe(true);
```

## Test Yazma Kuralları

1. **Her dissector modülüne test ekle**: En az bir "iyi yol" testi (bilinen protokolü parse eder) + bir "hata yolu" (eksik/bozuk veri).
2. **Mock kullanma**: Gerçek paket üretimi (`build_tcp_packet`) veya gerçek pcap dosyası (`fixtures/`) kullan.
3. **Test fonksiyon adları**: `test_<ne_test_edildiği>` veya `<senaryo_açıklaması>`, örn. `test_arp_request_parsing`.
4. **İsimlendirme tutarlılığı**: Entegrasyon testleri `pcap_<protokol>_<yön>` desenini takip eder.
5. **Kaynak dosyadaki test module**: Test edilen kodun hemen altında, aynı dosyada `#[cfg(test)] mod tests { ... }`.
6. **Assertion mesajı**: Karmaşık assertion'larda hata mesajı ekle (`assert!(expr, "beklenen {} alınan {}", a, b)`).
7. **Yavaş testi `#[ignore]` ile susturma — hızlandır ya da taşı**:
   - **Zamanlama iddiası mı?** Criterion bench'ine taşı (`benches/`).
   - **Kapatılamayan bir backlog mu?** Kümenin listeye *eşit* olduğunu iddia et (`UNREACHABLE_BACKLOG`).
   - **Yavaşlık tekrar mı?** Port sweep'lerini temsil edici bir örneklem ile değiştir.

### Örnek Test Desenleri

**1. İyi Yol & Hata Yolu Test Deseni (Dissector Testi):**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// İyi Yol (Happy Path): Geçerli paket doğru protokolle ayrıştırılır.
    #[test]
    fn test_valid_packet_parsing() {
        let raw = [0x01, 0x02, 0x03, 0x04];
        let r = dissect_custom(&raw);
        assert_eq!(r.protocol, Protocol::Custom);
        assert!(r.summary.contains("valid"), "Alınan özet: {}", r.summary);
    }

    /// Hata Yolu (Error Path / Malformed): Eksik veya bozuk veri paniklemez.
    #[test]
    fn test_truncated_packet_is_malformed() {
        let raw = [0x01]; // Eksik başlık
        let r = dissect_custom(&raw);
        assert!(matches!(r.protocol, Protocol::Unknown(_)));
    }
}
```

**2. Mock Kullanmadan Entegrasyon Testi Deseni:**
```rust
#[test]
fn pcap_http_request() {
    // Mock nesneler yerine fixtures/ altındaki gerçek pcap dosyaları kullanılır
    let pkts = run_pcap(fixtures().join("http-request.pcap"));
    assert_eq!(pkts.len(), 1, "Beklenen paket sayısı: 1, Alınan: {}", pkts.len());
    assert_eq!(pkts[0].protocol, Protocol::Http);
}
```
