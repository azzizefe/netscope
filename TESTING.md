# netscope — Test Rehberi

## Test Komutları

```bash
# Tüm Rust testleri (core hariç her şey)
cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent

# Sadece core
cargo test -p netscope-core

# Sadece tek bir test
cargo test -p netscope-core --lib filter::tests::test_filter_tcp_port

# Ignored testler (yavaş/özellik testleri)
cargo test -p netscope-core -- --ignored

# Benchmark
cargo bench -p netscope-core --bench parse_throughput -- --quick

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
7. **Yavaş testleri işaretle**: 1 saniyeyi geçen testlere `#[ignore]` ekle.
