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

## Windows'ta neden bazı araçlar varsayılan toolchain'de çalışmıyor

Bu depoda üç araç aynı sebeple `stable-x86_64-pc-windows-gnu` üzerinde
başarısız oluyor, ve **üçünün de hata mesajı sebebi söylemiyor**. Hepsi LLVM'in
çalışma zamanı bileşenlerine ihtiyaç duyuyor; rustup bunları windows-gnu için
dağıtmıyor, MSVC için dağıtıyor.

| Araç | windows-gnu'daki hata | Gerçek sebep |
|---|---|---|
| `cargo llvm-cov` | ``can't find crate for `profiler_builtins` `` | Kapsama sayaçları profiler runtime'ı ister; gnu toolchain'inde bu kütüphane hiç yok (`lib/rustlib/*/lib` altında sıfır dosya, MSVC'de iki tane) |
| `cargo fuzz` (derleme) | `FuzzerExtFunctionsWindows.cpp: expected constructor…` | libfuzzer-sys kendi libFuzzer kopyasını derliyor; Windows desteği `__pragma(comment(linker, …))` kullanıyor, GCC bunu reddediyor |
| `cargo fuzz` (çalıştırma) | `STATUS_DLL_NOT_FOUND (0xc0000135)` | ASan runtime'ı Windows'ta ayrı bir DLL ve PATH'te değil |

Çözüm üçü için de aynı: **MSVC toolchain'ini kullan.** Kapsama için bunu
hatırlamak zorunda değilsin, script yapıyor:

```powershell
.\scripts\coverage.ps1
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

| Yardımcı | Yer | Kapsam |
|---|---|---|
| `test_helpers::build_tcp_packet(...)` | `crates/core/src/dissectors.rs` | `pub(crate)` — tüm core içinde |
| `test_helpers::build_dns_query(...)` | `crates/core/src/dissectors.rs` | `pub(crate)` |
| Her dissector'un kendi helpers | `dissectors/<name>.rs` | `pub(crate)` |
| `run_pcap(path)` | `tests/integration_test.rs` | Integration tests |
| `load-app.js` helpers | `desktop/frontend-tests/` | Frontend tests |

## Test Yazma Kuralları

1. **Her dissector modülüne test ekle**: En az bir "iyi yol" testi (bilinen protokolü parse eder) + bir "hata yolu" (eksik/bozuk veri).
2. **Mock kullanma**: Gerçek paket üretimi (`build_tcp_packet`) veya gerçek pcap dosyası kullan.
3. **Test fonksiyon adları**: `test_<ne_test_edildiği>`, örn. `test_arp_request_parsing`.
4. **İsimlendirme tutarlılığı**: Her test `pcap_<protokol>_<yön>` desenini takip edebilir.
5. **Kaynak dosyadaki test module**: Test edilen kodun hemen altında, aynı dosyada.
6. **Assertion mesajı**: Karmaşık assertion'larda hata mesajı ekle (`assert!(expr, "beklenen {} alınan {}", a, b)`).
7. **Yavaş testi `#[ignore]` ile susturma — hızlandır ya da taşı.** Bu kural
   daha önce "1 saniyeyi geçen testlere `#[ignore]` ekle" diyordu ve dördü de
   öyle eklenmişti. Sonuç: ignore edilen test kimse için çalışmaz, dolayısıyla
   *içindeki doğruluk iddiaları da* çalışmaz — bu depoda bir koruma iki kez
   sessizce devre dışı kaldı ve erişilemez modül sayısı 140'tan 145'e kimse
   fark etmeden çıktı. Dördünün de gerçek çözümü vardı:
   - **Zamanlama iddiası mı?** Criterion bench'ine taşı (`benches/`). Bir duvar
     saati ölçümü `cargo test`'in paralel yükü altında makinenin ne kadar
     meşgul olduğunu ölçer; criterion örnekleyip aykırı değeri işaretler.
   - **Kapatılamayan bir backlog mu?** Listeyi sabitle ve kümenin listeye *eşit*
     olduğunu iddia et (`UNREACHABLE_BACKLOG` böyle). Sayı yalnızca düşebilir.
   - **Yavaşlık tekrar mı?** Neyin tekrarlandığına bak. 65.536 portluk sweep 589
     saniyeydi; portların ~65.000'i aynı yolu izlediği için eşdeğerlik
     kanıtlanıp örneklemle değiştirildi: 0,37 saniye, aynı kapsam.
