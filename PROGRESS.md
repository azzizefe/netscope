# netscope — Proje İlerleme Raporu

> Son güncelleme: **2026-08-03**
> Bu dosyadaki her sayı o gün `cargo test --workspace` ve kaynak ağacı
> sayımıyla ölçüldü. Sayıyı elle güncellemeyin — yeniden ölçün.

---

## Genel Durum

| Ölçüm | Değer |
|---|---|
| Rust kaynak dosyası | 659 (6 crate) |
| Test (Rust, tüm workspace) | **2.474 geçiyor, 0 başarısız, 0 `#[ignore]`** |
| Dissector modülü | 501 dosya |
| Registry satırı | 2.528 protokol |
| **Bir dissector'ın gerçekten ürettiği protokol** | **457** |
| Sadece bildirilmiş (`Declared`) protokol | 2.071 |
| Test (frontend, vitest) | **174 geçiyor** |
| Lint | ✅ `cargo clippy --workspace --all-targets -- -D warnings` temiz, `cargo fmt --check` temiz |

---

## Bileşen Bazında İlerleme

| Bileşen | Durum | Test | Detay |
|---|---|---|---|
| **netscope-core** | ✅ Hazır | 2.332 | Capture engine, dissectors, alerting, SIEM, stats, expert system, education |
| **netscope-tui** | ✅ Hazır | 44 | 7 görünüm (packet list, tree, hex, stats, dashboard, vs.) |
| **netscope-wasm** | ✅ Hazır | 1 | Filter modülü, wasm32-unknown-unknown |
| **netscope-server** | ✅ Derleniyor | 27 | gRPC + REST API (TLS/mTLS), SOAR, RBAC, migrations |
| **netscope-agent** | ✅ Hazır | 20 | Sensor agent, heartbeat, imzalı upgrade, WebSocket, remote config |
| **netscope-desktop** | ✅ Hazır | 28 | Tauri v2, 39 komut; kapsanan şey sarmalayıcı değil, çıkarılmış mantık |

---

## Açık Kritik Sorunlar

| # | Sorun | Etki | Detay |
|---|---|---|---|
| 🟠 1 | 144 dissector modülü dispatch'ten erişilemez | Bu protokoller hiçbir pakette görünmez | Liste `UNREACHABLE_BACKLOG`'da sabitlendi ve `every_dissector_module_is_reachable` artık **ignore'suz**: yeni bir erişilemez modül de, listeden silinmeden bağlanan bir modül de derlemeyi kırar. Yani sayı yalnızca düşebilir. Neredeyse hepsinin **imzası yok**: sabit ofset okuyup hiçbir şey doğrulamıyorlar. Port uydurarak bağlamayın — bu depoda dört kez gerçek hataya dönüştü. |
| 🟠 2 | 2.071 protokol registry'de ama üretilmiyor | Ders içerikleri var, filtre/renk yok | Bunlar `Declared` olarak işaretli ve **kasıtlı olarak** filtre listesinden, Learn sekmesinden ve protokol sayısından dışarıda tutuluyor — yani kullanıcıya yalan söylemiyorlar. Kapatmanın tek yolu dissector yazmak. |

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
| Uyumluluk raporları %100 uyumlu diyordu — her kontrol sabit `true`, skor `uyumlu/toplam × 100` yani tanımı gereği 100.0 | `compliance_reports.rs` | Modül silindi (hiçbir yerden çağrılmıyordu) |
| **API'den servis edilen** üç uydurma uç: Cobalt Strike C2 bulgusu + iç IP'ler, SOC KPI panosu, kişiye özel analist performans kaydı | `api/siem.rs` + iki core modülü | Uçlar ve modüller silindi; statik referans veri dönen uçlar kaldı |
| GDPR/KVKK skorları sabit 92.0 ve 90.0, `overall_score`'un 2/5'ini oluşturuyordu; veri yokken 94.5 / 89.0 / 100.0 | `db/queries.rs`, `models.rs`, `dashboard.html` | Hepsi `Option<f64>`; ölçülmeyen `None`, pano "—" çiziyor; skorlar örneklem sayısıyla birlikte |
| "7 günlük baseline" iki sabitten ibaretti, oranlar o sabitlere karşı hesaplanıyordu | `enriched_event.rs` | `Option`/`None`; gerçek `baseline.rs` motoruna bağlanana kadar "bilinmiyor" |
| `risk_score: 92` ve sabit süre, gerçekten hesaplanan `confidence_pct`'in yanında | `narrative_correlation.rs` | İkisi de kaldırıldı |
| `test_strategy.rs`'in tamamı uydurma test sonucu: kapsama `85.4` sabiti, entegrasyon `true`, PCAP replay dosya varsa `5`, chaos senaryolarının üçü de dirençli, soak testi `memory_leak_detected: false` | `test_strategy.rs` + iki SOC dokümanı | Modül silindi; dokümanlardaki "sıfır bellek sızıntısı garantisi" iddiası kaldırıldı |
| DeviceNet `Dissected` işaretliydi ama koruması `-> bool { false }` — dallanma hiç alınamıyordu | `dissectors.rs`, `can.rs`, `registry.rs` | Ölü dallanma ve stub kaldırıldı, satır `Declared`'a çevrildi, gerekçe `can.rs`'e yazıldı |
| `test_data.rs`: "sentetik trafik üreteci" `pps × süre` çarpıyordu, "zararlı PCAP kütüphanesi"nin beş dosyası depoda yok, "100 GB veri seti" bir `Default` struct'tı | `test_data.rs` + iki SOC dokümanı | Modül silindi, dokümanlar düzeltildi |
| `BenchmarkData`: 108.500 eps'e karşı "rakip ortalaması 25.000", 8,4 MB'a karşı 850 MB — iki taraf da ölçülmemiş, `/api/v1/siem/benchmarks`ten servis ediliyordu | `siem_comparison.rs`, `api/siem.rs` | Fonksiyon, tip ve uç kaldırıldı; gerçek ölçüm `cargo bench`te |
| **Masaüstü VoIP paneli:** RTP paketi yokken SSRC `0x00c0ffee`, jitter `1.8 ms` ve **MOS `4.3`** gösteriyordu — medya içermeyen bir yakalama için "çağrı kalitesi iyi" demek | `views/voip.js` | Uydurma fallback kaldırıldı, üçü de "—" kalıyor; RTP yoksa oynatma düğmesi kapalı ve nedeni yazıyor |
| **Masaüstü "Play Audio":** RTP çözülmüyor, jitter'a göre modüle edilmiş bir osilatör çalıyordu; kullanıcı çağrıyı dinlediğini sanabilirdi | `views/voip.js`, `index.html` | "Play Synthesised Tone" olarak etiketlendi, dalga formu başlığı ve durum metni ne olduğunu açıkça söylüyor |
| **Masaüstü "10 Exclusive Features":** 10 yetenekten **5'i mevcut değil** — Kerberos Golden/Silver Ticket tespiti, Modbus "Coil 47 Emergency Stop Motor 3" denetimi (silinen sahte veri modülünden birebir kopya), sertifika son kullanma uyarısı, tracker risk analizi, ETA | `views/siem.js` | Her yetenek `built`/`planned` olarak işaretlendi; olmayanlar "Not implemented" diyor ve kesikli çerçeveyle çiziliyor |
| **Masaüstü karşılaştırma tablosu:** dissector sayısı `590` (eski), MITRE "Every event", ve hiçbir kod yolunun üretmediği "Narrative attack chain ✅" | `views/siem.js` | 457'ye düzeltildi, MITRE kapsamı "Alerts & SIEM export" oldu, narrative satırı kaldırıldı |
| **Masaüstü CVE bulgusu:** Apache deseni `2\.4\.(4[0-9]\|50)` idi ama etiketi CVE-2021-41773 — o CVE yalnızca 2.4.49'u etkiler. Yakalamadaki her 2.4.4x sunucusu "uzaktan istismar edilebilir" diye raporlanıyordu | `app.js` | Tam eşleşmeye çevrildi ve iki ayrı CVE'ye ayrıldı (2.4.50 → CVE-2021-42013); eşleşmemesi gereken sürümler teste bağlandı |
| **11 TCP portu gerçek HTTP ve TLS trafiğini yutuyordu** — 4841 (IANA `opcua-tls`), 6002 (X11 :2), 8001/8087/8090/8910 (alternatif HTTP) ve diğerleri; dissector'lar hiçbir şey doğrulamıyor ve tam port eşleşmesi tüm yapısal sezgileri geçiyor | `dissectors/tcp.rs` | `UNVERIFIED_VENDOR_PORTS` + `looks_like_http_message` / `looks_like_tls_record`; FANUC FOCAS (8193) ve OMRON FINS (9600) gerçek portlar olduğu için listede yok |
| **3 UDP portu DTLS'i yutuyordu** — 2224 (CIP Safety aslında EtherNet/IP 2222 içinde), 5100 (PROFINET 34962-34964'te), 5500 (MECHATROLINK IP bile değil) | `dissectors/udp.rs` | Aynı koruma; `looks_like_dtls` artık port tablosundan önce çalışıyor |
| **ICMP "Time Exceeded" kod baytını yok sayıyordu** — kod 1 parça birleştirme zaman aşımıdır, TTL bitmesi değil; ikisi de "Time-to-live exceeded" diye raporlanıyordu (RFC 792, RFC 4443 §3.3) | `dissectors/icmp.rs` | Kod ayrımı eklendi |
| **ICMPv6 Router Advertisement, SLAAC prefix iddiasını bayt taramasıyla yapıyordu** — mesajın herhangi bir yerindeki `03 04` yetiyordu, örneğin router lifetime 0x0304 ise | `dissectors/icmp.rs` | RFC 4861 §4.2'ye göre opsiyon zinciri yürünüyor; yanlış pozitif üreten iki girdi teste bağlandı |

---

## Sıradaki Adımlar

Sıra ve gerekçe için [`%100.md`](%100.md):

1. ~~CI yeşillendirme — Adım 5~~ ✅ **2026-08-03** (zaten yapılmıştı; clippy'nin `--all-targets` boşluğu kapatıldı)
2. ~~Fleet güvenliği — Adım 6~~ ✅ **2026-08-03** (gRPC TLS/mTLS eklendi, imza doğrulamanın pozitif yolu teste bağlandı)
3. ~~macOS binary + notarization — Adım 3~~ ✅ **2026-08-03** (zaten yapılmıştı; kalan tek şey Apple secret'larının depoya girilmesi)
4. ~~Tauri komut test kapsamı — Adım 4~~ ✅ **2026-08-03** (mantık çıkarıldı ve testlendi; runtime gerektirenler UNTESTED.md'de)
5. **Web sitesi (Astro) + WASM demo + auto-update** — Adım 7
6. **Git geçmişi temizliği** (yıkıcı, force-push, en sona) — Adım 1
