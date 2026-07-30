# 🧭 NetScope Yol Haritası

> **Hedef:** NetScope'u Vercel'de yayına almak, masaüstü uygulamasını siteden indirilebilir kılmak ve eğitim içerikleriyle kullanıcı kitlesi oluşturmak.

---

## 📋 Mevcut Durum

| Bileşen | Durum | Açıklama |
|---------|-------|----------|
| Rust core (`crates/core`) | ✅ Hazır | Paket yakalama, ~2500 protokol dissector, analiz motoru, `education.rs` öğrenme modülü |
| TUI (`crates/tui`) | ✅ Hazır | Terminal tabanlı arayüz (ratatui), 7 farklı görünüm |
| WASM (`crates/wasm`) | ✅ Hazır | Tarayıcıda paket filtresi, önceden derlenmiş (`desktop/frontend/wasm/`) |
| Tauri masaüstü (`desktop/`) | ✅ Hazır | Windows/macOS/Linux (Tauri v2), NSIS/MSI/DMG/DEB/AppImage |
| CI/CD (GitHub Actions) | ✅ Var | `ci.yml` (lint+test+bench), `release.yml` (TUI binary + desktop installer), `publish.yml` |
| Mevcut dokümanlar | ✅ Var | `docs/` altında 14 dosya (mimari, kurulum, SSS, KULLANIM.md, filtreler...) |
| Paketleme şablonları | ✅ Var | `dist/packaging/` (Homebrew Cask, Snap, WinGet) |
| Pre-built binary | ✅ Var | `dist/netscope-windows-v0.1.0-x64.zip` (17 MB) |
| **Web sitesi / Landing page** | ❌ **Yok** | Sıfırdan oluşturulacak |
| **Vercel deploy** | ❌ **Yok** | Yapılandırılacak |
| **Web eğitim içerikleri** | ❌ **Yok** | Markdown/MDX formatında hazırlanacak |
| **Auto-update mekanizması** | ❌ **Yok** | Tauri updater plugin entegre edilecek |

---

## 🗺️ Faz 1 — Web Sitesi ve Landing Page (1-2 Hafta)

### 1.1 Next.js / Astro Landing Page Kurulumu

```
netscope-site/
├── public/
│   ├── downloads/          # Masaüstü uygulaması binary'leri
│   ├── screenshots/        # Uygulama ekran görüntüleri
│   └── favicon.ico
├── src/
│   ├── pages/
│   │   ├── index.astro     # Landing page
│   │   ├── download.astro  # İndirme sayfası
│   │   ├── docs/           # Dokümantasyon
│   │   ├── learn/          # Eğitim içerikleri
│   │   └── blog/           # Blog
│   ├── components/
│   │   ├── Hero.astro
│   │   ├── Features.astro
│   │   ├── DownloadCard.astro
│   │   ├── ProtocolBrowser.astro  # WASM demo
│   │   └── Nav.astro
│   └── layouts/
│       └── Base.astro
├── astro.config.mjs
├── tailwind.config.js
└── package.json
```

**Önerilen teknoloji:** [Astro](https://astro.build) + Tailwind CSS
- Statik site üretimi → Vercel'de ücretsiz ve hızlı
- Markdown/MDX ile eğitim içerikleri
- Gerektiğinde React/Vue/Svelte adacıkları eklenebilir
- WASM modülü kolayca entegre edilebilir

### 1.2 Landing Page İçeriği

- **Hero bölümü:** NetScope nedir, tek cümlelik değer önerisi
- **Özellikler:** Protokol analizi, gerçek zamanlı yakalama, 2480+ protokol, şifreleme tespiti
- **Canlı demo:** WASM modülü ile tarayıcıda örnek `.pcap` analizi
- **İndirme CTA:** Platform seçimi (Windows/macOS/Linux)
- **Trust badges:** Açık kaynak (GitHub), MIT lisans, topluluk

### 1.3 Vercel İlk Deploy

```bash
# vercel.json (site/ kök dizininde)
{
  "buildCommand": "astro build",
  "outputDirectory": "dist",
  "installCommand": "npm install"
}
```

- [ ] Vercel hesabı oluştur / bağla
- [ ] GitHub repo'yu Vercel'e bağla
- [ ] `netscope.vercel.app` üzerinde canlıya al
- [ ] Özel domain ayarla (isteğe bağlı: `netscope.io`, `netscope.app` vb.)

---

## 🗺️ Faz 2 — Masaüstü Uygulaması Build & Dağıtım (1-2 Hafta)

> **💡 Mevcut durum:** `.github/workflows/release.yml` zaten var! TUI binary'leri ve masaüstü installer'ları (NSIS/MSI/DMG/DEB/AppImage) için multi-platform CI/CD pipeline'ı çalışıyor. Bu faz mevcut pipeline'ı genişletmeye ve Vercel sitesiyle entegre etmeye odaklanıyor.

### 2.1 Mevcut Release Pipeline'ını Genişlet

Mevcut `.github/workflows/release.yml` üzerinde yapılacak iyileştirmeler:

- [ ] Release artifact'larına **imzalı Windows installer** ekle (Authenticode)
- [ ] macOS build'ine **Apple notarization** ekle
- [ ] Release notlarına **changelog** otomatik oluştur (`git cliff` veya `release-drafter`)
- [ ] Vercel deploy hook — yeni release çıkınca siteyi otomatik güncelle (indirme linkleri)
- [ ] Versiyon senkronizasyonu: `Cargo.toml`, `tauri.conf.json`, `package.json` tek kaynaktan

### 2.2 Vercel Sitesinde İndirme Sayfası

- [ ] `/download` sayfası: GitHub API ile en son release'i çek, her platform için dinamik link
- [ ] Otomatik platform tespiti (JS ile `navigator.platform`)
- [ ] Sürüm geçmişi / changelog sayfası (`CHANGELOG.md` → siteye render)
- [ ] Sistem gereksinimleri (Npcap, Windows 10+, WebView2)
- [ ] `dist/packaging/` şablonlarını sayfaya entegre et (Homebrew: `brew install netscope`, Snap: `snap install netscope`, WinGet: `winget install netscope`)
- [ ] SHA-256 checksum'ları (güvenlik)

### 2.3 Auto-Update Mekanizması

- [ ] Tauri updater plugin'ini `desktop/src-tauri/`'ye entegre et
- [ ] Update manifest endpoint'i: Vercel'de `/api/update.json` (veya `update.netscope.app`)
- [ ] Uygulama içi "yeni sürüm var" toast bildirimi
- [ ] Sessiz arka plan güncelleme (Windows) / kullanıcı onaylı (macOS)

---

## 🗺️ Faz 3 — Eğitim ve Dokümantasyon Sitesi (3-4 Hafta)

> **💡 Mevcut durum:** `docs/` altında 14 doküman (mimari, kurulum, SSS, KULLANIM.md, filtreler...) ve `crates/core/src/education.rs` öğrenme modülü zaten var. Bu faz mevcut içerikleri web sitesine taşımaya ve yeni eğitim içerikleri üretmeye odaklanıyor.

### 3.1 Mevcut Dokümanları Siteye Taşı

`docs/` dizinindeki mevcut 14 dokümanı Astro MDX sayfalarına dönüştür:

| Mevcut Dosya | Site Sayfası |
|-------------|-------------|
| `docs/KULLANIM.md` (Türkçe) | `/tr/docs/kullanim` |
| `docs/setup.md` | `/docs/setup` |
| `docs/architecture.md` | `/docs/architecture` |
| `docs/filters.md` | `/docs/filter-language` |
| `docs/dissectors.md` | `/docs/dissectors` |
| `docs/faq.md` | `/docs/faq` |
| `docs/desktop.md` | `/docs/desktop-app` |
| `docs/core.md` | `/docs/core-engine` |
| `docs/tui.md` | `/docs/tui` |

### 3.2 İçerik Mimarisi

```
/learn/
├── index.astro              # Eğitim merkezi ana sayfa
├── getting-started/
│   ├── installation.mdx     # Kurulum rehberi
│   ├── first-capture.mdx    # İlk paket yakalama
│   └── interface-tour.mdx   # Arayüz turu
├── protocols/
│   ├── tcp-deep-dive.mdx    # TCP analizi
│   ├── tls-inspection.mdx   # TLS/HTTPS trafiği
│   ├── dns-analysis.mdx     # DNS sorgu analizi
│   └── http2-grpc.mdx       # HTTP/2 ve gRPC
├── use-cases/
│   ├── malware-traffic.mdx  # Zararlı trafik tespiti
│   ├── network-debug.mdx    # Ağ sorun giderme
│   └── iot-analysis.mdx     # IoT cihaz trafiği
├── advanced/
│   ├── custom-dissectors.mdx
│   ├── filter-language.mdx  # Filtreleme dili (BPF)
│   └── scripting.mdx        # Lua/Python scripting
└── glossary/
    └── index.mdx            # Protokol sözlüğü
```

### 3.2 İçerik Stratejisi

| Tür | Platform | Frekans |
|-----|----------|---------|
| Blog yazıları | `/blog/` | Haftada 1 |
| Protokol rehberleri | `/learn/protocols/` | Haftada 1-2 |
| Video eğitimler | YouTube (gömülü) | Ayda 2 |
| İnteraktif demo | `/demo/` (WASM) | Sürekli canlı |
| Sık sorulan sorular | `/faq/` | Sürekli güncel |

### 3.3 Blog / CMS Entegrasyonu

- [ ] MDX tabanlı blog (Astro Content Collections)
- [ ] Kategori ve etiket sistemi
- [ ] RSS feed
- [ ] Arama (Pagefind veya benzeri statik arama)

---

## 🗺️ Faz 4 — İnteraktif Demo ve Web Analizör (2-3 Hafta)

### 4.1 WASM Demo Sayfası

- [ ] `/demo` sayfası: Mevcut `netscope_wasm` modülünü kullan
- [ ] Kullanıcı `.pcap` dosyası yükleyip tarayıcıda analiz edebilsin
- [ ] Örnek `.pcap` dosyaları (indirilebilir)
- [ ] Paket listesi, protokol hiyerarşisi, istatistikler

### 4.2 Web Tabanlı Hafif Analizör

- [ ] WASM ile canlı filtreleme
- [ ] Protokol renklendirme
- [ ] Flow görselleştirme (basit)
- [ ] "Pro'ya geç" CTA → masaüstü uygulamasına yönlendirme

---

## 🗺️ Faz 5 — Topluluk ve Büyüme (Sürekli)

### 5.1 Topluluk Altyapısı

- [ ] GitHub Discussions aktif kullanımı
- [ ] Discord sunucusu
- [ ] Issue template'leri (bug report, feature request, protocol request)
- [ ] CONTRIBUTING.md

### 5.2 SEO ve Keşfedilebilirlik

- [ ] Tüm sayfalar için meta etiketleri ve Open Graph
- [ ] `sitemap.xml` ve `robots.txt`
- [ ] Yapılandırılmış veri (JSON-LD)
- [ ] Google Analytics veya Plausible

### 5.3 Sosyal Kanıt

- [ ] Testimonial / kullanıcı yorumları bölümü
- [ ] "Kimler kullanıyor?" logosu
- [ ] GitHub star sayısı canlı gösterimi

---

## 📅 Zaman Çizelgesi Özeti

```
Ay 1                    Ay 2                    Ay 3
├───────────────────────┼───────────────────────┼───────────────────────┤
│ Faz 1: Landing Page   │ Faz 3: Eğitim İçerik  │ Faz 5: Topluluk       │
│ + Vercel Deploy       │ + Blog başlangıcı     │ + Sürekli içerik      │
├───────────────────────┤                       │                       │
│ Faz 2: CI/CD Build    │ Faz 4: İnteraktif Demo│                       │
│ + İndirme Sayfası     │ + WASM Analizör       │                       │
└───────────────────────┴───────────────────────┴───────────────────────┘
```

---

## 🎯 Öncelik Sırası (MVP)

İlk sürüm için minimum canlıya alma checklist'i:

1. **🔴 Kritik — Hafta 1-2**
   - [ ] Astro site kurulumu (repo içinde `site/` dizini)
   - [ ] Landing page (Hero + Features + indirme CTA)
   - [ ] Mevcut `CHANGELOG.md` ve `README.md` içeriğini siteye uyarla
   - [ ] Vercel deploy + domain bağlama
   - [ ] `/download` sayfası (GitHub Releases API ile dinamik)

2. **🟡 Önemli — Hafta 3-4**
   - [ ] Mevcut `docs/` içeriğini Astro siteye taşı
   - [ ] Release pipeline'ına Vercel deploy hook ekle
   - [ ] İlk 3 eğitim içeriği (kurulum, ilk yakalama, arayüz turu)
   - [ ] WASM demo sayfası (mevcut `netscope_wasm` ile basit `.pcap` yükleme)

3. **🟢 İyi — Hafta 5-8**
   - [ ] Tauri updater plugin + `/api/update.json` endpoint'i
   - [ ] Blog + 5-10 içerik
   - [ ] SEO optimizasyonu (sitemap, OG, JSON-LD)
   - [ ] Discord + topluluk sayfası
   - [ ] `dist/packaging/` (Homebrew/Snap/WinGet) sayfaya entegre

---

## 🔧 Teknik Notlar

### Şu anki projede DEĞİŞMEYECEK olanlar:
- Rust workspace yapısı aynen kalacak
- Tauri masaüstü uygulaması aynen kalacak
- Mevcut `desktop/frontend/` (Tauri webview içi) değişmeyecek
- WASM crate'i aynen kalacak

### YENİ eklenecekler:
- `site/` dizini — Astro landing page + eğitim sitesi (mevcut repoya eklenecek)
- `.github/workflows/` — **zaten var**, sadece Vercel deploy hook eklenecek
- `desktop/src-tauri/` — **tauri-updater plugin** entegrasyonu
- `/api/update.json` — Vercel serverless function (auto-update manifest)

### Neden Astro?
- **Sıfır JS** ile statik site → Vercel'de anında yüklenir
- **MDX** desteği → eğitim içerikleri için ideal
- **Island architecture** → WASM demo için React adacığı gömülebilir
- **Content Collections** → tip güvenli blog/doküman yönetimi
- Ücretsiz, açık kaynak, Vercel-native

---

## 📊 Başarı Metrikleri

| Metrik | 3 Ay | 6 Ay | 12 Ay |
|--------|------|------|-------|
| Aylık site ziyareti | 500 | 2.000 | 10.000 |
| Masaüstü indirme | 100 | 500 | 2.000 |
| GitHub star | 50 | 200 | 1.000 |
| Eğitim içeriği sayısı | 10 | 30 | 60+ |
| Discord üye | 50 | 200 | 500 |

---

> **Son güncelleme:** 25 Temmuz 2026
> **Sonraki adım:** Faz 1 başlangıcı — Astro site kurulumu ve ilk Vercel deploy.
