# netscope — Kod Stili Rehberi

## Genel Kurallar

- Rust edition 2021, MIT license
- `cargo fmt` ile biçimlendir (varsayılan rustfmt, özel yapılandırma yok)
- `cargo clippy --workspace --exclude netscope-desktop -- -D warnings` ile lint
- Clippy override'ları root `Cargo.toml` > `[workspace.lints.clippy]`; her crate `[lints] workspace = true` ile dahil olur
- Her dosyada SPDX başlığı: `// SPDX-License-Identifier: MIT` + `// Copyright (c) 2026 netscope contributors`

## Dil & Araçlar

| Konu | Kural |
|---|---|
| Hata yönetimi | `anyhow::Result` (birincil), elle `Display + Error` impl (özel tipler için) |
| `thiserror` | **Kullanma** — bağımlılık yok |
| `unsafe` | **Kullanma** — sadece `memmap2::Mmap::map` için 1 yerde izinli |
| `unwrap()` | Testlerde serbest; production'da sadece `lock().unwrap()` (Mutex) ve sabit veri `.parse()` için |
| `expect()` | Kritik initialization'da zorunlu — **açıklayıcı mesajla** |
| `panic!` | Production'da kullanma; testlerde nadir |
| `todo!` / `unreachable!` | Production'da kullanma |

## Modül Organizasyonu

```
lib.rs / main.rs
├── pub mod filter;          →  filter.rs           (düz dosya)
├── pub mod dissectors;      →  dissectors.rs       (düz dosya)
├── pub mod fieldbus;        →  fieldbus/mod.rs     (alt modüller için)
│   ├── pub mod decode_strategy;
│   ├── pub mod manifest;
│   └── pub mod quality;
└── pub mod models;
```

- `mod.rs`: alt modülleri `pub use` ile yeniden dışa aktar (glob `pub use *` kullanma)
- Görünürlük: `lib.rs`'te `pub mod` (dışa açık), alt modüllerde `pub(crate)` veya private
- `#[cfg()]` modülleri: unconditional modüller önce, gated modüller sonra

## İçe Aktarma Sırası (3 Grup)

```rust
use std::net::IpAddr;                    // 1. std::*
use std::sync::Arc;

use anyhow::{Context, Result};           // 2. Üçüncü taraf (alfabetik)
use crossbeam_channel::Sender;

use crate::models::Packet;               // 3. crate::* / super::* (alfabetik)
use crate::pipeline::Pipeline;
```

Dissector alt modüllerinde `super::` önce gelebilir:
```rust
use crate::models::Protocol;
use super::DissectedResult;
```

## Adlandırma

| Şey | Kural | Örnek |
|---|---|---|
| Tipler / enum'lar | `PascalCase` | `DissectedResult`, `Packet`, `FilterError` |
| Enum varyantları | `PascalCase` | `ArpOperation::Request` |
| Fonksiyonlar | `snake_case` | `dissect_arp()`, `list_interfaces()` |
| Değişkenler | `snake_case` | `ethertype`, `vlan_id` |
| Sabitler | `SCREAMING_SNAKE_CASE` | `DLT_EN10MB`, `ETHERTYPE_IPV4` |
| Test fonksiyonları | `snake_case` (betimleyici) | `test_arp_request_parsing` |
| Dissector girişleri | `dissect_<protokol>()` | `dissect_dns`, `dissect_tls` |

## Dokümantasyon

- **Modül seviyesi**: `//!` — lisanstan sonra ilk şey. Ne işe yaradığını açıkla, gerekirse format/örnek ekle.
- **Public API**: `///` — tüm `pub` struct, fonksiyon, enum, field'larda zorunlu. İlk satır özet, sonra ayrıntı.
- **Inline yorum**: `//` — **ne değil, neden** yapıldığını açıkla. Referans varsa (`ROADMAP §2.4`) ekle.
- **Section başlıkları**: `// ---- Adı ----` deseni (büyük harf, tirelerle çevrili).

## Dissector Kuralları

1. Her dissector modülü `dissectors/<name>.rs` içinde, `protocols!(...)` makrosuna kayıtlı
2. `dissect_*()` fonksiyonu `(&[u8], &mut DissectedResult)` imzasına sahip
3. Yardımcı test fonksiyonları `pub(crate) mod test_helpers { ... }` içinde (test dışı modül, ama sadece testler kullanır)
4. `build_<protokol>_<şey>()` fonksiyonlarıyla gerçek wire-format frame üret

## Feature Gating

```rust
#[cfg(not(target_arch = "wasm32"))]
pub mod alerting;
```
Sadece `wasm32` için gate'le. Socket/thread/file/db gerektiren modülleri kapat.

Stub pattern (gerekirse):
```rust
#[cfg(not(feature = "ot"))]
pub mod lin {
    pub fn dissect_lin(_: &[u8], _: &mut DissectedResult) {}
}
```

## Crate Yapısı

- `Cargo.toml`: `version.workspace = true`, `edition.workspace = true`, `[lints] workspace = true`
- Kullanılmayan bağımlılık ekleme
- Her bağımlılığa neden gerektiğini açıklayan yorum ekle (`# pcap: FFI bindings for packet capture`)
