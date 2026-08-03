# netscope — Proje İlerleme Raporu

> Son güncelleme: **2026-08-03**
> Bu dosyadaki her sayı o gün `cargo test --workspace` ve kaynak ağacı
> sayımıyla ölçüldü. Sayıyı elle güncellemeyin — yeniden ölçün.

---

## Genel Durum

| Ölçüm | Değer |
|---|---|
| Rust kaynak dosyası | 659 (6 crate) |
| Test (Rust, tüm workspace) | **2.470 geçiyor, 0 başarısız, 4 `#[ignore]`** |
| Dissector modülü | 501 dosya |
| Registry satırı | 2.528 protokol |
| **Bir dissector'ın gerçekten ürettiği protokol** | **458** |
| Sadece bildirilmiş (`Declared`) protokol | 2.070 |
| Lint | ✅ `cargo clippy --workspace --all-targets -- -D warnings` temiz, `cargo fmt --check` temiz |

---

## Bileşen Bazında İlerleme

| Bileşen | Durum | Test | Detay |
|---|---|---|---|
| **netscope-core** | ✅ Hazır | 2.330 (+4 ignore) | Capture engine, dissectors, alerting, SIEM, stats, expert system, education |
| **netscope-tui** | ✅ Hazır | 44 | 7 görünüm (packet list, tree, hex, stats, dashboard, vs.) |
| **netscope-wasm** | ✅ Hazır | 1 | Filter modülü, wasm32-unknown-unknown |
| **netscope-server** | ✅ Derleniyor | 27 | gRPC + REST API (TLS/mTLS), SOAR, RBAC, migrations |
| **netscope-agent** | ✅ Hazır | 20 | Sensor agent, heartbeat, imzalı upgrade, WebSocket, remote config |
| **netscope-desktop** | ✅ Hazır | 28 | Tauri v2, 39 komut; kapsanan şey sarmalayıcı değil, çıkarılmış mantık |

---

## Açık Kritik Sorunlar

| # | Sorun | Etki | Detay |
|---|---|---|---|
| 🟠 1 | 144 dissector modülü dispatch'ten erişilemez | Bu protokoller hiçbir pakette görünmez | `every_dissector_module_is_reachable` (`--ignored`) listeliyor. Neredeyse hepsinin **imzası yok**: sabit ofset okuyup hiçbir şey doğrulamıyorlar. Port uydurarak bağlamayın — bu depoda dört kez gerçek hataya dönüştü. |
| 🟠 2 | 2.070 protokol registry'de ama üretilmiyor | Ders içerikleri var, filtre/renk yok | Bunlar `Declared` olarak işaretli ve **kasıtlı olarak** filtre listesinden, Learn sekmesinden ve protokol sayısından dışarıda tutuluyor — yani kullanıcıya yalan söylemiyorlar. Kapatmanın tek yolu dissector yazmak. |

---

## 2026-08-03: Doğruluk Onarımı

1 Ağustos'taki toplu commitler, kod tabanının kendi korumalarını devre dışı
bırakmıştı. Bu oturumda geri alındı — ayrıntılı gerekçeler ilgili dosyaların
doc yorumlarında duruyor:

| Ne bulundu | Nerede | Ne yapıldı |
|---|---|---|
| Erişilebilirlik koruması susturulmuş: 140 modül toptan `HELPER_MODULES`'a eklenmiş, `#[ignore]` aynı diff'te silinmiş | `dissectors.rs` | Liste 62 gerçek helper'a döndürüldü, `#[ignore]` geri kondu, hiçbir modülü adlandırmayan 1.330 hayalet girdi silindi ve `helper_modules_name_real_modules` testi eklendi |
| Bunun üzerine 128 registry satırı `Declared` → `Dissected` çevrilmiş | `registry.rs` | 128'i geri çevrildi; `declared_status_matches_the_dispatch` yeniden anlamlı |
| AF_XDP ve DPDK arka uçları **uydurma paket üretip** canlı boru hattına `hw_timestamp = true` ile basıyordu | `ebpf_xdp.rs`, `dpdk.rs`, `capture.rs` | İki dosya silindi; pcap dışı her arka uç yine hata döndürüyor, `every_backend_but_pcap_refuses_to_start` bunu sabitliyor |
| `assert!(x.is_ok() \|\| x.is_err())` gibi tanımı gereği geçen testler | `desktop/src-tauri/src/lib.rs` | Gerçek iddialarla değiştirildi |
| Var olmayan arayüz adı, **başka bir arayüzün** komşularını döndürüyordu | `discover.rs` | Adlandırılmış arayüz artık ya kendisine çözülür ya hiçbir şeye |
| Ephemeral aralıkta (32768-60999), içerik koruması olmayan 5 port bağlaması | `dissectors/bindings.rs` | Kaldırıldı (41100, 44819, 48400, 48898, 48899); gerekçe dosyaya yazıldı, `an_ephemeral_source_port_is_not_a_protocol` genişletildi |
| `firewall.rs` "nftables destekliyor" diyordu, hiçbir yerde `nft` çağrısı yok | `firewall.rs` | Doc düzeltildi (`iptables`/`ip6tables`) |

---

## Sıradaki Adımlar

Sıra ve gerekçe için [`%100.md`](%100.md):

1. ~~CI yeşillendirme — Adım 5~~ ✅ **2026-08-03** (zaten yapılmıştı; clippy'nin `--all-targets` boşluğu kapatıldı)
2. ~~Fleet güvenliği — Adım 6~~ ✅ **2026-08-03** (gRPC TLS/mTLS eklendi, imza doğrulamanın pozitif yolu teste bağlandı)
3. ~~macOS binary + notarization — Adım 3~~ ✅ **2026-08-03** (zaten yapılmıştı; kalan tek şey Apple secret'larının depoya girilmesi)
4. ~~Tauri komut test kapsamı — Adım 4~~ ✅ **2026-08-03** (mantık çıkarıldı ve testlendi; runtime gerektirenler UNTESTED.md'de)
5. **Web sitesi (Astro) + WASM demo + auto-update** — Adım 7
6. **Git geçmişi temizliği** (yıkıcı, force-push, en sona) — Adım 1
