# netscope — Proje İlerleme Raporu

> Son güncelleme: **2026-07-29 (akşam)**

---

## Genel Durum

| Ölçüm | Değer |
|---|---|
| Rust kaynak dosyası | ~621 (6 crate) |
| Test sayısı (Rust) | ~2,323 geçiyor, 0 başarısız |
| Test sayısı (vitest) | 88 frontend testi |
| Dissector modülü | 501 dosya, ~2,500 protokol |
| Çalışan crate'ler | core, tui, wasm, desktop |
| Derlenmeyen crate | *(yok)* — tümü derleniyor |
| Lint | ✅ clippy + fmt temiz (server hariç) |

---

## Bileşen Bazında İlerleme

| Bileşen | Durum | Test | Detay |
|---|---|---|---|
| **netscope-core** | ✅ Hazır | 2,227 test | Capture engine, dissectors, alerting, SIEM, stats, expert system, education |
| **netscope-tui** | ✅ Hazır | 44 test | 7 görünüm (packet list, tree, hex, stats, dashboard, vs.) |
| **netscope-wasm** | ✅ Hazır | 1 test | Filter modülü, wasm32-unknown-unknown, 154 KB |
| **netscope-server** | ✅ Derleniyor | 25 test | gRPC + REST API, SOAR, RBAC, migrations — **clippy temiz** |
| **netscope-agent** | ✅ Hazır | 18 test | Sensor agent, heartbeat, upgrade, WebSocket, remote config |
| **netscope-desktop** | ✅ Hazır | 18 test | Tauri v2, 38 komut (13 testli), NSIS/MSI/DMG/DEB/AppImage |
| **Frontend (vitest)** | ✅ Hazır | 88 test | PII detection, UI unit tests |

---

## Branch Yapısı

| Branch | Amaç |
|---|---|
| `main` | Aktif geliştirme — her şey burada |
| `backup-local-main` | Yerel yedek |
| `feature/dissectors-expansion` | Dissector genişletme |
| `feature/failure-reasons-dns-and-routing` | DNS/routing hata analizi |
| `feature/protocol-registry-and-expansion` | Protocol registry |
| `fix/desktop-test-manifest` | Windows test manifest fix |
| `release/tauri-msi-versioning` | MSI versiyonlama |

---

## Açık Kritik Sorunlar

| # | Sorun | Etki | Detay |
|---|---|---|---|
| 🔴 1 | `netscope-server` derlenmiyor | Tüm fleet management tier (auth, RBAC, gRPC, SOAR) kullanılamaz | `api/hunt.rs`: `queries::CreateRule` private, 3 tip uyuşmazlığı |
| 🟠 2 | 145 dissector modülü dispatch'ten erişilemez | Kullanıcıya gösterilmeyen protokoller | İmza/magic byte eksik |
| 🟠 3 | 1,938 protocol registry'de ama üretilmiyor | Filtre/renk/eğitim içeriği boş | Hiçbir kod yolu `Protocol` değerini atamıyor |

---

## Proje Büyüklüğü

| Kategori | Sayı |
|---|---|
| Dissector modülü | 501 `.rs` dosyası |
| Toplam Rust testi | ~2,327 |
| Toplam frontend testi | 88 |
| SIEM formatı | 3 (CEF, LEEF, JSON) |
| Desktop komutu | 33 Tauri command |
| Veritabanı migration | 8 SQL dosyası |
| GitHub Actions workflow | 3 (ci, publish, release) |
| PQC güvenlik modülü | 4 (CVE feed, CT v3, ECH interop, session resumption) |
| Doküman | 14 dosya (`docs/`) + SOC roadmap |

---

## Geçmiş Kilometre Taşları

- ✅ Core engine + 500+ dissector
- ✅ TUI (ratatui) tüm görünümler
- ✅ WASM filter (tarayıcıda çalışan)
- ✅ Tauri desktop uygulaması (Windows/macOS/Linux)
- ✅ Alert engine + rule-based triggering
- ✅ Expert system (packet severity classification)
- ✅ SIEM export (CEF, LEEF, JSON)
- ✅ SOC 7x24 monitoring dokümantasyonu
- ✅ gRPC + REST API iskeleti
- ✅ CI/CD pipeline (lint, test, bench, frontend)
- ✅ Release pipeline (TUI binary + desktop installer)
- ✅ Multi-platform release artifact (NSIS, MSI, DMG, DEB, AppImage)

---

## Sıradaki Adımlar

1. **🟠 145 imzasız dissector'a imza ekle** — dispatch'e bağlanabilir hale getir
2. **🟠 Protocol registry üretim bağlantısı** — her `Protocol` değeri bir dissector tarafından atanmalı
3. **📈 Desktop command test coverage** — 38 komuttan 25'i hâlâ testsiz
4. **🌐 Web sitesi (Astro + Vercel)** — ROADMAP.md Faz 1
5. **🔄 Auto-update** — Tauri updater plugin + Vercel serverless
