# Netscope — Vercel Deployment, Eğitim ve Kurumsal Kullanım Rehberi 🚀🎓🏢

> **Amaç:** Netscope'un Vercel'de nasıl deploy edileceğini sıfırdan anlatmak;
> web sitesi üzerinden eğitim içeriği sunmak, masaüstü uygulamasını dağıtmak,
> ve kurumsal kullanım senaryolarını yapılandırmak.
>
> **Tarih:** 2026-07-25
> **Sürüm:** v2.0
> **Durum:** Canlı doküman — uygulandıkça güncellenecek

---

## İçindekiler

1. [Başlamadan: Ne, Neden, Nasıl?](#başlamadan-ne-neden-nasıl)
2. [Proje Yapısını Hazırlama](#proje-yapısını-hazırlama)
3. [Adım Adım Vercel Deployment](#adım-adım-vercel-deployment)
4. [Web Sitesi İçeriği ve Sayfa Yapısı](#web-sitesi-içeriği-ve-sayfa-yapısı)
5. [Masaüstü Uygulamasını Dağıtma](#masaüstü-uygulamasını-dağıtma)
6. [Eğitim İçeriği Stratejisi](#eğitim-içeriği-stratejisi)
7. [Kurumsal Kullanım Analizi](#kurumsal-kullanım-analizi)
8. [Eksiklikler ve Yol Haritası](#eksiklikler-ve-yol-haritası)
9. [Ek A: SWOT Analizi](#ek-a-swot-analizi)
10. [Ek B: Rakip Karşılaştırması](#ek-b-rakip-karşılaştırması)

---

## Başlamadan: Ne, Neden, Nasıl?

### Netscope nedir?

Netscope, Wireshark'a modern bir alternatif olarak geliştirilmiş, **Rust** tabanlı
bir ağ analiz aracıdır. 250+ protokol çözümleyicisi, insan-okunur paket özetleri,
otomatik güvenlik taraması (Insights), TLS parmak izi (JA3/JA4), ve Learn modu ile
**ağ analizini herkes için erişilebilir kılar.**

İki sürümü var:

| Sürüm | Açıklama | Dosya |
|-------|----------|------|
| **🖥️ Masaüstü (Desktop)** | Tauri tabanlı, native pencere, tam özellikli GUI | `.exe` / `.dmg` / `.AppImage` |
| **⌨️ TUI** | Terminal arayüzü, hafif, headless mod desteği | tek binary |

### Neden Vercel?

Vercel, **static site'ler ve frontend uygulamaları** için optimize edilmiş ücretsiz
bir deployment platformudur. Netscope için Vercel'i kullanma nedenlerimiz:

| Avantaj | Açıklama |
|---------|----------|
| 🆓 **Ücretsiz** | Hobi projeleri ve küçük-orta trafik için tamamen ücretsiz |
| ⚡ **Hızlı** | Global CDN, otomatik SSL, anında deploy |
| 🔄 **GitHub entegrasyonu** | `git push` yapınca otomatik deploy |
| 🌍 **Özel domain** | `netscope.app` gibi kendi domainini bağlayabilirsin |
| 📊 **Analytics** | Vercel Analytics ile ziyaretçi takibi |
| 🎯 **Basitlik** | Sıfır sunucu yönetimi, sıfır DevOps |

### Ne deploy edeceğiz?

Netscope'un kendisi bir **masaüstü uygulaması** — doğrudan Vercel'de çalışmaz.
Vercel'de deploy edeceğimiz şey **Netscope'un web varlığı (landing page)**:

```
┌──────────────────────────────────────────────────────┐
│                 netscope.app (Vercel)                 │
│                                                      │
│  🏠 Ana sayfa        — "Netscope nedir?" tanıtım    │
│  📥 İndir            — Masaüstü & TUI download       │
│  📚 Dökümantasyon     — Kullanım kılavuzları          │
│  🎓 Eğitim           — Dersler, lab'lar, quiz'ler    │
│  🏢 Kurumsal         — Kurumsal özellikler, fiyat    │
│  📝 Blog             — Duyurular, rehberler           │
│                                                      │
│  Kullanıcı siteyi ziyaret eder → indirir → masaüstü  │
│  uygulamasını kendi bilgisayarına kurar.             │
└──────────────────────────────────────────────────────┘
```

---

## Proje Yapısını Hazırlama

### Dizin yapısı

Netscope reposu içinde `web/` adında yeni bir dizin oluşturacağız.
Bu dizin tamamen Vercel'e deploy edilecek statik siteyi içerecek.

```
netscope/                       ← mevcut repo
├── crates/                     ← Rust kodları (core, tui, wasm, python)
├── desktop/                    ← Tauri masaüstü uygulaması
├── docs/                       ← Markdown dokümantasyon
├── fixtures/                   ← Örnek pcap dosyaları
├── web/                        ← 🆕 Vercel'e deploy edilecek site
│   ├── index.html              ← Ana sayfa
│   ├── download.html           ← İndirme sayfası
│   ├── docs/                   ← Dökümantasyon sayfaları
│   │   ├── index.html
│   │   ├── setup.html
│   │   └── ...
│   ├── egitim/                 ← Eğitim içerikleri
│   │   ├── index.html
│   │   ├── dersler/
│   │   └── lab/
│   ├── kurumsal/               ← Kurumsal sayfalar
│   │   └── index.html
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── main.js
│   ├── assets/
│   │   ├── logo.svg
│   │   ├── screenshots/
│   │   └── favicon.ico
│   ├── vercel.json             ← Vercel yapılandırması
│   └── robots.txt
└── ...
```

### Teknoloji seçimi

Sıfırdan başlıyoruz — şu seçenekler var:

| Seçenek | Zorluk | Artıları | Eksileri |
|---------|--------|----------|----------|
| **Düz HTML + CSS + JS** | ⭐ Kolay | Sıfır bağımlılık, hızlı, Vercel'de anında çalışır | Büyüdükçe yönetimi zor |
| **Astro** | ⭐⭐ Orta | Markdown'dan sayfa üretir, hızlı, SEO dostu | Öğrenme eğrisi var |
| **Next.js** | ⭐⭐⭐ İleri | React ekosistemi, SSR, geniş topluluk | Gereksiz ağır olabilir |
| **Vite + vanilla** | ⭐⭐ Orta | Hızlı dev server, optimize build | Build adımı gerekir |

> **Öneri:** **Düz HTML + CSS + JS** ile başlayın. Site büyüdükçe Astro'ya
> geçmek kolaydır. Bu rehber düz HTML üzerinden ilerler.

### `vercel.json` — Vercel yapılandırması

```json
{
  "version": 2,
  "name": "netscope",
  "buildCommand": null,
  "outputDirectory": "web",
  "cleanUrls": true,
  "trailingSlash": false,
  "headers": [
    {
      "source": "/assets/(.*)",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=31536000, immutable"
        }
      ]
    },
    {
      "source": "/download/(.*)",
      "headers": [
        {
          "key": "Content-Disposition",
          "value": "attachment"
        }
      ]
    }
  ],
  "redirects": [
    {
      "source": "/docs",
      "destination": "/docs/index.html",
      "permanent": true
    },
    {
      "source": "/egitim",
      "destination": "/egitim/index.html",
      "permanent": true
    },
    {
      "source": "/kurumsal",
      "destination": "/kurumsal/index.html",
      "permanent": true
    },
    {
      "source": "/indir",
      "destination": "/download.html",
      "permanent": true
    }
  ]
}
```

**Bu dosya ne işe yarar?**
- `cleanUrls: true` → `/docs/setup.html` yerine `/docs/setup` yazılır (`.html` gizlenir)
- `headers` → asset'ler 1 yıl cache'lenir (tekrar ziyarette şimşek hızlı)
- `redirects` → eski/kısa URL'leri yeni sayfalara yönlendirir

> Vercel, `vercel.json` olmasa bile düz HTML sitesini otomatik algılar ve
> çalıştırır. Bu dosya "iyi" bir yapılandırma için — zorunlu değil.

---

## Adım Adım Vercel Deployment

### Ön Koşullar

1. **GitHub hesabı** → [github.com/signup](https://github.com/signup) (ücretsiz)
2. **Vercel hesabı** → [vercel.com/signup](https://vercel.com/signup) — **GitHub ile
   kaydol** (tek tık)
3. **Git** → Bilgisayarında kurulu olmalı (`git --version` ile kontrol et)
4. **Netscope reposu** → GitHub'a push'lanmış olmalı

### 1. Adım: Vercel'e GitHub bağlantısı ver

1. [vercel.com](https://vercel.com)'a git, GitHub hesabınla giriş yap
2. Sağ üstte **"New Project"** butonuna tıkla
3. GitHub repolarının listesi çıkacak — `azzizefe/netscope` (veya senin fork'un)
   reposunu bul ve **"Import"** a tıkla

### 2. Adım: Proje ayarlarını yap

Vercel seni bir yapılandırma ekranına götürecek. Şu ayarları gir:

| Ayar | Değer | Açıklama |
|------|-------|----------|
| **Framework Preset** | `Other` (veya boş bırak) | Düz HTML kullanıyoruz |
| **Root Directory** | _(boş bırak)_ | Proje kök dizini |
| **Build Command** | _(boş bırak)_ | Statik site, build yok |
| **Output Directory** | `web` | `web/` dizinindeki her şey deploy edilecek |
| **Install Command** | _(boş bırak)_ | npm paketi yok, install yok |

> **Not:** Bu ayarları `vercel.json` dosyasına da yazabilirsin. Vercel
> otomatik olarak `vercel.json`'ı okur ve ayarları oradan alır.
> Yukarıdaki `vercel.json` örneğini kullanıyorsan burada hiçbir şey
> değiştirmene gerek yok — Vercel her şeyi otomatik algılar.

### 3. Adım: Deploy et!

Mavi **"Deploy"** butonuna tıkla. Vercel:

1. Reponu klonlar
2. `web/` dizinini bulur
3. Global CDN'ine dağıtır
4. Sana `netscope.vercel.app` gibi bir URL verir

⏱️ **İlk deploy ~30 saniye sürer.**

### 4. Adım: Canlı siteyi gör

Deploy tamamlandığında Vercel sana bir **"Congratulations!"** ekranı gösterir.
Üstünde siteye gitmek için bir link vardır — tıkla, siten yayında! 🎉

```
https://netscope.vercel.app        ← Vercel'in verdiği ücretsiz domain
```

### 5. Adım: Özel domain bağlama (opsiyonel)

Kendi domainini bağlamak istersen (örn: `netscope.app`):

1. Vercel dashboard'da projene git
2. Sol menüden **"Settings"** → **"Domains"**
3. Domainini yaz (örn: `netscope.app`)
4. Vercel sana DNS kayıtlarını verecek — domain sağlayıcında (Namecheap,
   Cloudflare, vb.) bu kayıtları ekle:

```
Tip: CNAME
Ad:  @
Değer: cname.vercel-dns.com
```

5. SSL sertifikası otomatik olarak oluşturulur (Let's Encrypt) — bekleme süresi ~1 dakika.

### 6. Adım: Otomatik deploy (CI/CD)

Bu adımda hiçbir şey yapmana gerek yok! 🎉

**Vercel + GitHub entegrasyonu sayesinde:**

- `main` branch'ine her `git push` yaptığında → **Production** ortamı otomatik güncellenir
- Her Pull Request açtığında → Vercel otomatik bir **Preview** ortamı oluşturur,
  PR'ın altına link bırakır. Merge etmeden önce değişiklikleri canlı görürsün.

```bash
# Sen bir değişiklik yaparsın:
cd netscope/web
# ... index.html'i düzenle ...

# Commit ve push:
git add web/
git commit -m "Ana sayfa güncellendi"
git push origin main

# ⏱️ ~30 saniye sonra site otomatik güncellenmiş olur.
# Senin hiçbir şey yapmana gerek yok.
```

### Özet: Tüm deployment akışı

```
Sen: git push → GitHub
              ↓
         Vercel (otomatik)
              ↓
         ┌─────────────────────┐
         │  1. Repoyu klonla   │
         │  2. web/ dizinini al│
         │  3. CDN'e dağıt     │
         │  4. SSL bağla       │
         │  5. Domain güncelle │
         └─────────┬───────────┘
                   ↓
         https://netscope.app
              ↓
         Kullanıcı siteyi ziyaret eder →
         İndirme sayfasına gider →
         Masaüstü uygulamasını indirir →
         Kendi bilgisayarına kurar ✅
```

---

## Web Sitesi İçeriği ve Sayfa Yapısı

### Site haritası

```
netscope.app
├── /                          ← Ana sayfa (hero, özellikler, CTA)
├── /indir                     ← İndirme sayfası
│   ├── /indir/windows
│   ├── /indir/macos
│   └── /indir/linux
├── /docs                      ← Dökümantasyon ana sayfası
│   ├── /docs/setup            ← Kurulum rehberi
│   ├── /docs/tui              ← TUI kılavuzu
│   ├── /docs/desktop          ← Desktop kılavuzu
│   ├── /docs/filters          ← Filtre yemek kitabı
│   └── /docs/faq              ← SSS
├── /egitim                    ← Eğitim ana sayfası
│   ├── /egitim/dersler        ← Ders listesi
│   │   ├── /egitim/dersler/tcp-ip-temelleri
│   │   ├── /egitim/dersler/dns-nasil-calisir
│   │   ├── /egitim/dersler/tls-el-sikismasi
│   │   └── ...
│   ├── /egitim/lab            ← Lab kütüphanesi
│   └── /egitim/sertifika      ← Sertifika programları
├── /kurumsal                  ← Kurumsal sayfa
│   ├── /kurumsal/ozellikler   ← Kurumsal özellikler
│   ├── /kurumsal/fiyat        ← Fiyatlandırma
│   └── /kurumsal/iletisim     ← İletişim / demo talebi
└── /blog                      ← Blog (opsiyonel)
```

### Ana sayfa (`index.html`) — ne içermeli

```html
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Netscope — Ağ Analizi, İnsanlar İçin</title>
  <meta name="description" content="Netscope, Wireshark'a modern alternatif. 250+ protokol, insan-okunur özetler, otomatik güvenlik taraması. Ücretsiz ve açık kaynak.">

  <!-- Open Graph (sosyal medya paylaşımı) -->
  <meta property="og:title" content="Netscope — Ağ Analizi, İnsanlar İçin">
  <meta property="og:description" content="Wireshark'a modern, hızlı, anlaşılır alternatif.">
  <meta property="og:image" content="https://netscope.app/assets/og-image.png">
  <meta property="og:url" content="https://netscope.app">

  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  <!-- Navigasyon -->
  <nav>
    <a href="/">🦈 Netscope</a>
    <div>
      <a href="/docs">Dökümantasyon</a>
      <a href="/egitim">Eğitim</a>
      <a href="/kurumsal">Kurumsal</a>
      <a href="/indir" class="btn-primary">⬇ İndir</a>
    </div>
  </nav>

  <!-- Hero -->
  <section class="hero">
    <h1>Ağ analizi, <em>sonunda</em> anlaşılır.</h1>
    <p>
      250+ protokol, insan dilinde paket özetleri, otomatik güvenlik taraması.
      Wireshark'a modern alternatif. <strong>Ücretsiz ve açık kaynak.</strong>
    </p>
    <div class="cta-buttons">
      <a href="/indir" class="btn-primary">⬇ Netscope'u İndir</a>
      <a href="#ozellikler" class="btn-secondary">Özellikleri Gör →</a>
    </div>
  </section>

  <!-- Özellikler grid -->
  <section id="ozellikler">
    <h2>Neden Netscope?</h2>
    <div class="features-grid">
      <div class="feature-card">
        <h3>🧠 İnsan-okunur özetler</h3>
        <p>Ham hex yok. <code>google.com → 142.250.74.46</code> gibi herkesin anlayacağı özetler.</p>
      </div>
      <div class="feature-card">
        <h3>🛡️ Otomatik güvenlik taraması</h3>
        <p>Insights sekmesi: açık parolalar, şüpheli domainler, port taramaları, DLP ihlalleri — tek ekranda.</p>
      </div>
      <div class="feature-card">
        <h3>🎓 Learn modu</h3>
        <p>Hiç ağ bilgisine ihtiyacın yok. Her protokolü sade dille anlatan built-in eğitim.</p>
      </div>
      <div class="feature-card">
        <h3>⚡ 3.1M pkt/s</h3>
        <p>Rust ile yazıldı. Wireshark'tan kat kat hızlı. ~8 MB boyut.</p>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer>
    <p>© 2026 Netscope · <a href="https://github.com/azzizefe/netscope">GitHub</a> · MIT Lisansı</p>
  </footer>
</body>
</html>
```

### İndirme sayfası (`download.html`) — kritik

Bu sayfa kullanıcının masaüstü uygulamasını indirdiği yer. **En önemli sayfalardan biri.**

İçermesi gerekenler:

1. **Platform seçimi** — Windows / macOS / Linux sekmeleri
2. **Sistem gereksinimleri** — (Npcap, WebView2 vs.)
3. **Kurulum talimatları** — Her platform için adım adım
4. **Release linkleri** — GitHub Releases'dan son sürüm

```html
<!-- download.html yapısı -->
<section class="download">
  <h1>Netscope'u İndir</h1>

  <!-- Platform sekmeleri -->
  <div class="platform-tabs">
    <button onclick="showPlatform('win')" class="active">🪟 Windows</button>
    <button onclick="showPlatform('mac')">🍎 macOS</button>
    <button onclick="showPlatform('lnx')">🐧 Linux</button>
  </div>

  <!-- Windows -->
  <div id="platform-win" class="platform-content active">
    <h2>Windows için Netscope</h2>
    <p class="version">Son sürüm: v1.x.y</p>

    <!-- Uyarı: Npcap -->
    <div class="warning-box">
      ⚠️ <strong>Önce Npcap'i kurun!</strong>
      Netscope'u çalıştırmadan önce <a href="https://npcap.com" target="_blank">Npcap</a>'i
      indirip kurun. Kurulum sırasında <em>"WinPcap API-compatible Mode"</em> seçeneğini
      işaretleyin.
    </div>

    <a href="https://github.com/azzizefe/netscope/releases/latest/download/netscope_x64-setup.exe"
       class="download-btn">
      ⬇ Netscope Setup (x64) .exe
    </a>
    <p class="file-info">~8 MB · Windows 10/11 · Yönetici olarak çalıştırın</p>
  </div>

  <!-- macOS, Linux için aynı yapı -->
</section>
```

### Dökümantasyon sayfaları

Mevcut `docs/*.md` dosyalarını HTML'e çevireceğiz. İki yaklaşım:

**Yaklaşım A: Elle HTML yazmak**
- Küçük site için uygun
- Her güncellemede elle senkronize etmek gerekir
- Başlangıç için yeterli

**Yaklaşım B: Markdown → HTML dönüştürücü**
- `docs/` altındaki `.md` dosyalarını otomatik HTML'e çeviren küçük bir script
- GitHub Actions ile her push'ta çalıştırılır
- Büyüdükçe daha sürdürülebilir

```bash
# Yaklaşım B için örnek: pandoc ile md → html
pandoc docs/setup.md -o web/docs/setup.html \
  --standalone --template=web/templates/doc.html
```

### Eğitim sayfaları

Eğitim içerikleri sitenin **en değerli** bölümü olacak. Detay için
[Eğitim İçeriği Stratejisi](#eğitim-içeriği-stratejisi) bölümüne bak.

### Kurumsal sayfa

Kurumsal kullanıcılar için özel bir sayfa. İçeriği için
[Kurumsal Kullanım Analizi](#kurumsal-kullanım-analizi) bölümüne bak.

---

## Masaüstü Uygulamasını Dağıtma

### Kullanıcı akışı

```
1. Kullanıcı netscope.app'i ziyaret eder
2. Ana sayfadaki "İndir" butonuna tıklar
3. İşletim sistemini seçer (Windows/macOS/Linux)
4. .exe / .dmg / .AppImage dosyasını indirir
5. Kurar ve çalıştırır
```

### Dosyalar nerede duracak?

Masaüstü uygulamasının binary dosyaları (`.exe`, `.dmg`, `.AppImage`)
**Vercel'de değil, GitHub Releases'da** duracak.

| Dosya | Konum |
|-------|-------|
| `netscope_x.y.z_x64-setup.exe` | GitHub Releases |
| `netscope_x.y.z_universal.dmg` | GitHub Releases |
| `netscope_x.y.z_amd64.AppImage` | GitHub Releases |
| Web sitesi (HTML/CSS/JS) | Vercel |
| Dökümantasyon (HTML) | Vercel |
| Eğitim içeriği (HTML) | Vercel |

> **Neden?** Vercel'in ücretsiz planında 100 MB deployment limiti var.
> Masaüstü binary'leri bu limiti aşabilir. Ayrıca GitHub Releases zaten
> CI ile otomatik üretiliyor — tekrar Vercel'e koymak gereksiz.

### İndirme sayfasından GitHub Releases'a link

```html
<!-- Windows için -->
<a href="https://github.com/azzizefe/netscope/releases/latest/download/netscope_x64-setup.exe"
   class="download-btn">
  ⬇ Netscope Setup (x64) .exe
</a>

<!-- macOS için -->
<a href="https://github.com/azzizefe/netscope/releases/latest/download/netscope_universal.dmg"
   class="download-btn">
  ⬇ Netscope (Universal) .dmg
</a>

<!-- Linux için -->
<a href="https://github.com/azzizefe/netscope/releases/latest/download/netscope_amd64.AppImage"
   class="download-btn">
  ⬇ Netscope .AppImage
</a>
```

> **GitHub Releases link formatı:**
> `https://github.com/KULLANICI/REPO/releases/latest/download/DOSYA_ADI`
> Bu link her zaman **en son release'teki** dosyayı döndürür — siteyi
> her release'te güncellemek zorunda kalmazsın.

### Otomatik sürüm gösterme

JavaScript ile GitHub API'den son sürüm numarasını çekip sayfada gösterebilirsin:

```javascript
// js/releases.js — Sayfa yüklendiğinde son sürümü getir
async function getLatestVersion() {
  try {
    const res = await fetch('https://api.github.com/repos/azzizefe/netscope/releases/latest');
    const data = await res.json();
    document.querySelectorAll('.latest-version').forEach(el => {
      el.textContent = data.tag_name; // "v1.2.3"
    });
  } catch {
    // GitHub API limit dolduysa sessizce geç
  }
}
getLatestVersion();
```

---

## Eğitim İçeriği Stratejisi

### Hedef kitle

| Kitle | İhtiyaç | Ne sunacağız? |
|-------|---------|---------------|
| **Lise öğrencileri** | Temel ağ kavramları | Görsel dersler, basit lab'lar |
| **Üniversite öğrencileri** | Protokol analizi, güvenlik | İleri dersler, CTF soruları |
| **BT profesyonelleri** | Sertifika hazırlık, tool mastery | CCNA/Network+ paketleri |
| **Kendi kendine öğrenenler** | Yapılandırılmış öğrenme yolu | Learning Path, rozetler |
| **Öğretmenler/Eğitmenler** | Sınıf yönetimi, ödev sistemi | Öğretmen konsolu, quiz motoru |

### Ders kategorileri

```
📚 Netscope Eğitim
├── 🌱 Başlangıç (Yeni başlayanlar)
│   ├── "Ağ nedir? Paket nedir?"
│   ├── "IP Adresleri ve Portlar"
│   └── "İlk paket yakalamam"
│
├── 🧱 Temeller
│   ├── "TCP/IP Modeli"
│   ├── "3'lü El Sıkışma (TCP Handshake)"
│   ├── "DNS: İnternetin Telefon Rehberi"
│   ├── "HTTP: Web'in Dili"
│   └── "TLS: Şifreli İletişim"
│
├── 🛡️ Güvenlik
│   ├── "ARP Zehirlenmesi Tespiti"
│   ├── "DNS Tünelleme Analizi"
│   ├── "TLS Sertifika Doğrulama"
│   ├── "Port Taraması Tespiti"
│   └── "Veri Sızıntısı (DLP) Tespiti"
│
├── 🔬 Adli Bilişim
│   ├── "Şüpheli Trafik Analizi"
│   ├── "JA3/JA4 Parmak İzi ile Tehdit Avı"
│   └── "Olay Müdahale (Incident Response) Temelleri"
│
└── 🏭 Endüstriyel Protokoller
    ├── "Modbus Trafiğini Anlamak"
    ├── "PROFINET ve Endüstriyel Ağlar"
    └── "CAN Bus Araç Ağı Analizi"
```

### Ders formatı

Her ders şu bileşenlerden oluşur:

```markdown
# Ders: DNS Nasıl Çalışır?

## 🎯 Hedef
Bu dersi bitirdiğinde DNS sorgu/yanıt döngüsünü anlayacak ve
bir pcap dosyasında DNS trafiğini analiz edebileceksin.

## 📖 Teori
DNS (Domain Name System), alan adlarını IP adreslerine çeviren
sistemdir. `google.com` yazdığında bilgisayarın önce DNS sunucusuna
gider ve "google.com'un IP'si ne?" diye sorar...

## 🧪 Lab: DNS Sorgusunu Yakala
1. Netscope'u aç
2. Filtre kutusuna `dns` yaz
3. Tarayıcıdan herhangi bir siteye git
4. DNS sorgularını ve yanıtlarını izle

## 📦 Örnek Pcap
[⬇ dns-query.pcap indir](/egitim/lab/dns-query.pcap)

## ✅ Quiz
1. DNS'in açılımı nedir?
2. A (Address) kaydı ne işe yarar?
3. Bir DNS sorgusu hangi portu kullanır?
```

> Bu dersler web sitesinde **HTML olarak** duracak. Kullanıcı siteyi ziyaret
> eder, dersi okur, örnek pcap dosyasını indirir, Netscope masaüstü
> uygulamasında açar ve pratik yapar.

### Lab kütüphanesi

`web/egitim/lab/` dizininde **kategorize edilmiş .pcap dosyaları**:

```
web/egitim/lab/
├── normal-traffic/
│   ├── http-browse.pcap
│   ├── dns-queries.pcap
│   └── tls-handshake.pcap
├── attacks/
│   ├── syn-flood.pcap
│   ├── arp-spoof.pcap
│   └── dns-tunnel.pcap
├── industrial/
│   ├── modbus-read.pcap
│   └── s7comm.pcap
└── README.md           ← Her lab'ın açıklaması
```

Bu `.pcap` dosyaları statik dosya olarak Vercel'de sunulur. Kullanıcı
indirip Netscope'ta açar.

### Eğitim sayfası (`/egitim/index.html`) yapısı

```html
<section class="education">
  <h1>🎓 Netscope ile Öğren</h1>
  <p>İster sıfırdan başla, ister uzmanlığını kanıtla.</p>

  <!-- Öğrenme yolu -->
  <div class="learning-path">
    <div class="path-node done">
      <span>🌱</span> Başlangıç
    </div>
    <div class="path-arrow">→</div>
    <div class="path-node current">
      <span>🧱</span> Temeller
    </div>
    <div class="path-arrow">→</div>
    <div class="path-node">
      <span>🛡️</span> Güvenlik
    </div>
    <div class="path-arrow">→</div>
    <div class="path-node">
      <span>🔬</span> Adli Bilişim
    </div>
  </div>

  <!-- Ders listesi -->
  <div class="lesson-grid">
    <a href="/egitim/dersler/dns-nasil-calisir" class="lesson-card">
      <h3>DNS: İnternetin Telefon Rehberi</h3>
      <p>DNS sorgu/yanıt döngüsünü paket seviyesinde anla.</p>
      <span class="badge">🧱 Temeller</span>
      <span class="duration">⏱ 20 dk</span>
    </a>
    <!-- ... daha fazla ders kartı ... -->
  </div>
</section>
```

### Gelecek: İnteraktif eğitim (Faz 2)

Şu an için eğitim içeriği **statik HTML sayfaları** olarak sunuluyor.
Gelecekte (bkz. [Yol Haritası](#önceliklendirilmiş-yol-haritası)):

- **Web tabanlı Netscope Lite** — WASM ile tarayıcıda çalışan hafif
  paket analizörü (mevcut `crates/wasm` temeli var!)
- **İnteraktif quiz** — JavaScript ile çalışan, anında geri bildirim
- **Öğrenci girişi** — İlerleme takibi, rozetler, sertifika
- **Öğretmen konsolu** — Sınıf yönetimi, ödev atama, notlandırma

---

## Kurumsal Kullanım Analizi

### Netscope kurumsalda nerede konumlanır?

```
Kurumsal Ağ İzleme Piramidi:

        ┌─────────┐
        │  CISO   │  ← Yönetici özet panosu (Netscope CISO Dashboard)
        │Paneli   │
        ├─────────┤
        │  SIEM   │  ← Splunk / ELK / Sentinel (Netscope → syslog/CEF)
        │ SOAR    │  ← Otomatik playbook (Netscope → webhook)
        ├─────────┤
        │  Netscope│  ← Paket analizi, tehdit tespiti, adli bilişim
        │  Manager │     Merkezi yönetim konsolu
        ├─────────┤
        │  Netscope│  ← Dağıtılmış sensörler (her alt ağda bir tane)
        │  Agent   │     Paket yakalama + ilk seviye analiz
        └─────────┘
```

### Kurumsal sayfa (`/kurumsal/index.html`) yapısı

```html
<section class="enterprise">
  <h1>🏢 Kurumlar için Netscope</h1>
  <p>
    Açık kaynak çekirdek, kurumsal eklentiler.
    Kendi altyapında çalışır, verilerin dışarı çıkmaz.
  </p>

  <!-- Kurumsal özellik kartları -->
  <div class="enterprise-features">
    <div class="ent-card">
      <h3>🔐 RBAC & SSO</h3>
      <p>Active Directory, LDAP, SAML ile entegre kimlik yönetimi.</p>
    </div>
    <div class="ent-card">
      <h3>📋 Uyumluluk Raporları</h3>
      <p>KVKK, GDPR, PCI-DSS, ISO 27001 için hazır rapor şablonları.</p>
    </div>
    <div class="ent-card">
      <h3>🔗 SIEM Entegrasyonu</h3>
      <p>Splunk, ELK, QRadar, Sentinel'e syslog/CEF/JSON çıktı.</p>
    </div>
    <div class="ent-card">
      <h3>🏗️ Merkezi Yönetim</h3>
      <p>Tüm ajanları tek konsoldan yönet, politika dağıt, güncelle.</p>
    </div>
  </div>

  <!-- Fiyatlandırma (örnek) -->
  <h2>Fiyatlandırma</h2>
  <div class="pricing-grid">
    <div class="price-card">
      <h3>Topluluk</h3>
      <p class="price">Ücretsiz</p>
      <ul>
        <li>✅ Tüm protokol desteği</li>
        <li>✅ TUI + Desktop</li>
        <li>✅ Açık kaynak (MIT)</li>
        <li>❌ Merkezi yönetim</li>
        <li>❌ Kurumsal raporlama</li>
      </ul>
      <a href="/indir" class="btn-secondary">İndir</a>
    </div>
    <div class="price-card featured">
      <h3>Kurumsal</h3>
      <p class="price">İletişime geçin</p>
      <ul>
        <li>✅ Topluluk'taki her şey</li>
        <li>✅ Merkezi yönetim konsolu</li>
        <li>✅ RBAC + SSO</li>
        <li>✅ Uyumluluk raporları</li>
        <li>✅ SIEM entegrasyonu</li>
        <li>✅ Öncelikli destek</li>
      </ul>
      <a href="/kurumsal/iletisim" class="btn-primary">Demo Talep Et</a>
    </div>
  </div>
</section>
```

---

## Eksiklikler ve Yol Haritası

### Mevcut durum özeti

Netscope **bireysel kullanım** için üretime hazır. Eğitim ve kurumsal
kullanım için aşağıdaki boşluklar var:

| Alan | Durum |
|------|-------|
| Masaüstü uygulaması | ✅ Hazır |
| TUI | ✅ Hazır |
| Web sitesi (landing page) | 🔨 Bu dokümanla başlıyor |
| Vercel deployment | 🔨 Bu dokümanla başlıyor |
| Eğitim içeriği (statik) | 🔨 İlk dersler yazılacak |
| Eğitim platformu (interaktif) | 📋 Planlandı (Faz 2) |
| Kurumsal yönetim konsolu | 📋 Planlandı (Faz 3) |
| SIEM/SOAR entegrasyonu | 📋 Planlandı (Faz 3) |

### Önceliklendirilmiş yol haritası

#### 🏗️ Faz 1: Web Varlığı (Şimdi — 1 Ay)

```
Hafta 1    │ Web sitesi iskeleti
           │  ├─ web/ dizini oluşturma
           │  ├─ index.html (ana sayfa)
           │  ├─ css/style.css (tasarım)
           │  └─ vercel.json (yapılandırma)
           │
Hafta 2    │ Vercel deployment
           │  ├─ GitHub'a push
           │  ├─ Vercel proje oluşturma
           │  ├─ Özel domain bağlama
           │  └─ Otomatik deploy testi
           │
Hafta 3    │ İçerik sayfaları
           │  ├─ download.html (indirme sayfası)
           │  ├─ docs/* (dökümantasyon sayfaları)
           │  └─ egitim/index.html (eğitim ana sayfa)
           │
Hafta 4    │ İlk eğitim içeriği + kurumsal sayfa
           │  ├─ 5 temel ders sayfası
           │  ├─ 10+ örnek pcap dosyası
           │  └─ kurumsal/index.html
```

**Çıktı:** `netscope.app` canlı, ziyaretçiler siteyi görüp uygulamayı
indirebiliyor, temel dersler okunabiliyor.

#### 🎓 Faz 2: Eğitim Platformu (1-6 Ay)

```
Ay 1-2     │ Ders içeriği genişletme
           │  ├─ 20+ ders (tüm kategoriler)
           │  ├─ Her ders için quiz
           │  └─ 50+ lab pcap dosyası
           │
Ay 3-4     │ Web tabanlı paket görüntüleyici
           │  ├─ WASM display filter engine (mevcut crates/wasm)
           │  ├─ Tarayıcıda pcap yükleme ve görüntüleme
           │  └─ Ders sayfalarına gömülü interaktif analiz
           │
Ay 5-6     │ Öğrenci sistemi
           │  ├─ Kayıt/giriş (Vercel + Supabase/Upstash)
           │  ├─ İlerleme takibi
           │  └─ Rozetler ve sertifika
```

#### 🏢 Faz 3: Kurumsal Hazırlık (6-18 Ay)

```
Ay 6-9     │ Netscope Server MVP
           │  ├─ REST API (axum)
           │  ├─ WebSocket streaming
           │  ├─ JWT + RBAC
           │  └─ PostgreSQL
           │
Ay 9-12    │ Agent mimarisi
           │  ├─ Merkeze bağlanan hafif ajan
           │  ├─ Uzaktan yapılandırma
           │  └─ Merkezi politika dağıtımı
           │
Ay 12-18   │ Kurumsal özellikler
           │  ├─ SIEM/SOAR entegrasyonu
           │  ├─ Uyumluluk raporları (KVKK/GDPR/PCI-DSS)
           │  ├─ Adli bilişim modu
           │  └─ HA/Cluster, K8s, GPO/MDM
```

---

## Ek A: SWOT Analizi

### Güçlü Yönler (Strengths)

- 🚀 **Performans:** Rust-native, 3.1M pkt/s dissect
- 🎯 **Kullanıcı deneyimi:** İnsan-okunur özetler, Learn modu, sade arayüz
- 📦 **Hafiflik:** ~8 MB binary (Wireshark: 85+ MB)
- 🔌 **Genişletilebilir:** Plugin sistemi, WASM/Python binding
- 🔓 **Açık kaynak:** MIT lisansı, topluluk katkısına açık
- 🌍 **Cross-platform:** Windows, macOS, Linux; TUI + Desktop
- 🛡️ **Yerleşik güvenlik:** Insights, Privacy X-Ray, JA3/JA4, TLS çözme

### Zayıf Yönler (Weaknesses)

- 👤 **Tek kullanıcılı:** Sunucu/istemci mimarisi yok
- 📚 **Sınırlı eğitim içeriği:** 8 fixture pcap, yapılandırılmamış dersler
- 🔗 **Entegrasyon eksikliği:** SIEM, SOAR, ITSM bağlantısı yok
- 🌐 **Web arayüzü yok:** Sadece TUI ve Desktop
- 📊 **Kurumsal raporlama yok:** PDF, uyumluluk şablonu, zamanlanmış rapor
- 📖 **Dokümantasyon:** Geliştirici odaklı; eğitmen/yönetici kılavuzu yok
- 🏢 **Lisans modeli yok:** Kurumsal satın alma/sağlama modeli belirsiz
- 🔐 **Kimlik doğrulama yok:** SSO, RBAC, MFA eksik

### Fırsatlar (Opportunities)

- 🎓 **Eğitim pazarı:** Wireshark eğitimde zor; Netscope'un Learn modu büyük avantaj
- 🏢 **Kurumsal maliyet:** Wireshark ücretsiz ama kurumsal alternatifler
  (Riverbed, ExtraHop) çok pahalı (~$50K+/yıl)
- 🤖 **AI/LLM trafik analizi:** Büyüyen pazar; Netscope protokol listesi rekabet avantajı
- 🇹🇷 **Yerel pazar:** Türkçe arayüz ve dokümantasyon; kamu/üniversitelerde tercih sebebi
- ☁️ **SaaS modeli:** Bulut tabanlı ağ izleme pazarı büyüyor
- 🔒 **KVKK/GDPR:** Yerleşik IP anonimleştirme ve gizlilik araçları uyumluluk avantajı

### Tehditler (Threats)

- 🐘 **Wireshark hakimiyeti:** 25+ yıllık marka, 3000+ protokol, geniş topluluk
- 💰 **Kurumsal rakipler:** SolarWinds, Riverbed, ExtraHop, Darktrace
- 👥 **Topluluk büyüklüğü:** Wireshark'ın devasa geliştirici ve eğitmen topluluğu
- 📉 **Artan şifreleme:** Ağ trafiğinin şifrelenme oranı paket analizini zorlaştırıyor

---

## Ek B: Rakip Karşılaştırması

### Eğitim alanı

| Özellik | Netscope | Wireshark | Packet Tracer | GNS3 |
|---------|----------|-----------|---------------|------|
| Gerçek paket analizi | ✅ | ✅ | ❌ (simülasyon) | ⚠️ kısmen |
| Öğrenme eğrisi | ⭐ Kolay | ⭐⭐⭐ Zor | ⭐⭐ Orta | ⭐⭐⭐ Zor |
| Eğitim içeriği | ⚠️ Learn modu | ❌ | ✅ Müfredat | ❌ |
| Sınıf yönetimi | ❌ | ❌ | ✅ (NetAcad) | ❌ |
| Fiyat | ✅ Ücretsiz | ✅ Ücretsiz | ✅ Ücretsiz | ✅ Ücretsiz |
| Platform | TUI + Desktop | GUI | GUI | GUI |

### Kurumsal alan

| Özellik | Netscope | Wireshark | SolarWinds | ExtraHop | Darktrace |
|---------|----------|-----------|------------|----------|-----------|
| Paket analizi | ✅ | ✅ | ⚠️ NetFlow | ✅ | ⚠️ |
| Merkezi yönetim | ❌ | ❌ | ✅ | ✅ | ✅ |
| SIEM entegrasyonu | ❌ | ❌ | ✅ | ✅ | ✅ |
| ML/AI anomali | ❌ | ❌ | ⚠️ | ✅ | ✅ |
| Uyumluluk raporu | ❌ | ❌ | ✅ | ✅ | ✅ |
| Fiyat (yıllık) | Ücretsiz | Ücretsiz | ~$3K+ | ~$50K+ | ~$100K+ |

---

## Sık Sorulan Sorular

### Vercel tarafı

**S: Vercel ücretsiz mi kalacak?**
Evet. Hobi planı: 100 GB bant genişliği/ay, 100 MB deployment boyutu,
günde 2000 deployment. Küçük-orta ölçekli bir site için fazlasıyla yeterli.

**S: Siteye her güncellemede tekrar deploy mu yapmam gerek?**
Hayır! `git push` yaptığın anda Vercel otomatik olarak yeni sürümü deploy eder.
Senin hiçbir şey yapmana gerek yok.

**S: Custom domain nasıl bağlarım?**
Domainini satın al, Vercel Settings → Domains → domaini gir → DNS'e CNAME ekle.
SSL otomatik. 5 dakikada biter.

**S: Birden fazla ortam (staging/production) olabilir mi?**
Evet. `main` branch = production. Diğer branch'ler ve PR'lar = preview.
Her PR'a özel `.vercel.app` linki verilir.

**S: Form (iletişim, demo talebi) çalışır mı?**
Statik sitede form çalıştırmak için:
- [formspree.io](https://formspree.io) (ücretsiz, 50 submission/ay)
- [web3forms.com](https://web3forms.com) (ücretsiz, 250 submission/ay)
- Vercel Serverless Functions (küçük bir API endpoint yazarsın)

### Masaüstü tarafı

**S: Netscope neden doğrudan web'de çalışmıyor?**
Paket yakalama (packet capture) işletim sistemi seviyesinde çalışır —
Npcap/libpcap sürücülerine ihtiyaç duyar. Tarayıcıdan bu sürücülere
erişilemez. Bu yüzden masaüstü uygulaması şart.

**S: WASM ile tarayıcıda paket analizi mümkün değil mi?**
Kısmen. Mevcut `crates/wasm` ile **pcap dosyası yükleme ve görüntüleme**
tarayıcıda çalışabilir. Ama **canlı paket yakalama** için masaüstü
uygulaması şart. Eğitim sayfalarında "yükle ve incele" tipi interaktif
demo'lar WASM ile yapılabilir.

**S: Kullanıcılar indirme sayfasından son sürümü nasıl görecek?**
GitHub API ile otomatik olarak son release bilgisi çekilir. Yukarıdaki
[JavaScript örneğine](#otomatik-sürüm-gösterme) bak.

---

## Sonuç: Bugün Ne Yapmalı?

### Hemen (bu hafta)

1. [ ] `web/` dizinini oluştur
2. [ ] `index.html` (ana sayfa) yaz
3. [ ] `css/style.css` (tasarım) yaz
4. [ ] `vercel.json` oluştur
5. [ ] GitHub'a push yap
6. [ ] Vercel'e GitHub reponu bağla → deploy et 🚀

### Kısa vadeli (1 ay)

7. [ ] `download.html` indirme sayfası
8. [ ] `docs/` dökümantasyon sayfaları (mevcut `.md`'lerden HTML)
9. [ ] `egitim/` ilk 5 ders
10. [ ] `kurumsal/` kurumsal sayfa
11. [ ] Özel domain bağlama
12. [ ] Vercel Analytics ekleme

### Orta vadeli (1-6 ay)

13. [ ] İnteraktif quiz'ler (JavaScript)
14. [ ] WASM ile tarayıcıda pcap görüntüleme
15. [ ] Kullanıcı girişi (Supabase)
16. [ ] Blog bölümü
17. [ ] Arama (Pagefind — statik site araması)

---

> **Not:** Bu belge canlı bir dokümandır. Web sitesi ve deployment ilerledikçe
> güncellenmelidir. Her fazın başında ve sonunda gözden geçirilmesi önerilir.
>
> **Hazırlayan:** Netscope Geliştirme Ekibi
> **İletişim:** [GitHub Issues](https://github.com/azzizefe/netscope/issues)
> **Demo:** [netscope.vercel.app](https://netscope.vercel.app) _(deploy edildiğinde)_
