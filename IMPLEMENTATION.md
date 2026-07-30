# 🔧 NetScope Web Sitesi — Senior-Level Uygulama Rehberi

> **Hedef:** NetScope masaüstü uygulamasının indirilebildiği, eğitim içeriklerinin yayınlandığı, Vercel'de host edilen statik bir web sitesi.

---

## 📐 Mimari Kararlar & Trade-off'lar

### Neden Astro (Next.js değil)?

| Kriter | Astro | Next.js |
|--------|-------|---------|
| Bundle boyutu | 0 KB JS (statik sayfalar) | ~80-120 KB framework overhead |
| Build çıktısı | Salt HTML + CSS | React hydration + runtime |
| İçerik yönetimi | Content Collections (MDX native) | Harici CMS veya manuel MDX |
| Vercel uyumu | Sıfır konfigürasyon | Sıfır konfigürasyon |
| Lighthouse skoru | Varsayılan 100 | 85-95 (optimizasyonla) |
| İnteraktif adacıklar | React/Vue/Svelte gömülebilir | Her şey React |
| WASM entegrasyonu | `<script>` veya React island | Next.js plugin zinciri |

**Karar:** Astro. Bu bir **içerik + indirme** sitesi, SaaS dashboard değil. Statik sayfalarda framework runtime'ı taşımak anlamsız. Tek interaktif yüzey WASM demo — o da React island olarak sadece `/demo` rotasında yüklenecek.

### Neden GitHub Releases API (direkt binary host değil)?

- Vercel serverless function limit: 4.5 MB body (binary'lerimiz 17 MB)
- Vercel statik asset limit: 100 MB total, tek dosya 25 MB max
- GitHub Releases: **sınırsız bant genişliği, ücretsiz**, 2 GB per file
- Tauri updater zaten GitHub Releases'ten çekmek üzere tasarlanmış

**Karar:** Binary'ler **GitHub Releases'te** kalacak, web sitesi sadece **GitHub API'den en son release metadata'sını çekip** indirme linklerini dinamik render edecek.

### Mimari Diyagramı

```
┌──────────────────────────────────────────────────────────────┐
│                        GitHub Repo                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐               │
│  │ crates/  │  │ desktop/ │  │ site/        │               │
│  │ (Rust)   │  │ (Tauri)  │  │ (Astro SSG)  │               │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘               │
│       │              │               │                        │
└───────┼──────────────┼───────────────┼────────────────────────┘
        │              │               │
        │   ┌──────────▼──────────┐    │  git push → Vercel auto-deploy
        │   │ GitHub Actions      │    │
        │   │ release.yml         │    │
        │   │ ┌─────────────────┐ │    │
        │   │ │ cargo tauri     │ │    │
        │   │ │ build           │ │    │
        │   │ └────────┬────────┘ │    │
        │   │          ▼          │    │
        │   │ ┌─────────────────┐ │    │
        │   │ │ GitHub Release  │ │◄───┼─── site /download sayfası
        │   │ │ .msi .dmg .deb  │ │    │    GitHub API ile çekiyor
        │   │ └────────┬────────┘ │    │
        │   │          │          │    │
        │   │   Vercel Deploy    │────┼─── Vercel re-deploy trigger
        │   │   Hook (POST)      │    │    (yeni release → site güncel)
        │   └────────────────────┘    │
        │                             │
        ▼                             ▼
┌──────────────────┐    ┌──────────────────────────────┐
│ Signed installer │    │ Vercel (netscope.vercel.app) │
│ (GitHub Release) │    │                              │
│ netscope-tui     │    │ /         → Landing page     │
└──────────────────┘    │ /download → İndirme sayfası  │
                        │ /docs/*   → Dokümantasyon     │
                        │ /learn/*  → Eğitimler (MDX)   │
                        │ /demo     → WASM analizör     │
                        │ /api/update → Auto-update     │
                        │              manifest (SSR)   │
                        └──────────────────────────────┘
```

---

## 🏗️ Adım 1 — Proje İskeleti

### 1.1 Dizin Yapısı

Mevcut repo içinde `site/` dizini oluştur. Mono-repo, tek kaynak:

```
netscope/                        # mevcut repo kökü
├── Cargo.toml                   # değişmeyecek
├── crates/                      # değişmeyecek
├── desktop/                     # değişmeyecek
├── site/                        # 🆕 tüm web sitesi burada
│   ├── package.json
│   ├── astro.config.mjs
│   ├── tailwind.config.mjs
│   ├── tsconfig.json
│   ├── vercel.json
│   ├── public/
│   │   ├── screenshots/
│   │   │   ├── dashboard.webp
│   │   │   ├── packets.webp
│   │   │   └── insights.webp
│   │   ├── og-default.png
│   │   └── robots.txt
│   └── src/
│       ├── pages/
│       │   ├── index.astro
│       │   ├── download.astro
│       │   ├── demo.astro
│       │   ├── docs/
│       │   │   ├── index.astro
│       │   │   └── [...slug].astro
│       │   ├── learn/
│       │   │   ├── index.astro
│       │   │   └── [...slug].astro
│       │   ├── blog/
│       │   │   ├── index.astro
│       │   │   └── [...slug].astro
│       │   └── rss.xml.ts
│       ├── content/
│       │   ├── docs/           # MDX dokümanlar
│       │   ├── learn/          # MDX eğitimler
│       │   └── blog/           # MDX blog yazıları
│       ├── components/
│       │   ├── Nav.astro
│       │   ├── Footer.astro
│       │   ├── Hero.astro
│       │   ├── FeatureGrid.astro
│       │   ├── DownloadCard.astro
│       │   ├── SEO.astro
│       │   └── ProtocolBadge.astro
│       ├── lib/
│       │   ├── github.ts       # GitHub Releases API client
│       │   ├── platform.ts     # OS detection
│       │   └── constants.ts
│       ├── layouts/
│       │   ├── Base.astro
│       │   ├── DocLayout.astro
│       │   └── BlogPost.astro
│       └── styles/
│           └── globals.css
```

### 1.2 Terminal Komutlarıyla Kurulum

```bash
# Repo kökünde
cd netscope

# Astro'yu site/ içinde scaffold et
npm create astro@latest site -- --template basics --typescript strict

cd site

# Tailwind CSS entegrasyonu (Astro v5+ native)
npx astro add tailwind

# İçerik için MDX desteği
npx astro add mdx

# Vercel adapter (varsayılan, zaten kurulu gelir)
# astro.config.mjs'de output: 'static' olarak kalacak

# Geliştirme sunucusu
npm run dev          # http://localhost:4321
```

### 1.3 Kritik Konfigürasyon Dosyaları

**`site/astro.config.mjs`**
```js
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://netscope.vercel.app', // deploy sonrası gerçek domain ile güncelle
  integrations: [
    tailwind(),
    mdx(),
    sitemap(),
  ],
  output: 'static',         // SSG — Vercel'de edge'den serve
  trailingSlash: 'never',
  build: {
    assets: 'assets',
  },
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: true,
    },
  },
});
```

**`site/vercel.json`**
```json
{
  "buildCommand": "astro build",
  "outputDirectory": "dist",
  "installCommand": "npm install",
  "framework": "astro",
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
      "source": "/screenshots/(.*)",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=604800"
        }
      ]
    },
    {
      "source": "/download",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=3600, stale-while-revalidate=86400"
        }
      ]
    }
  ],
  "redirects": [
    { "source": "/docs", "destination": "/docs/index", "permanent": true },
    { "source": "/learn", "destination": "/learn/index", "permanent": true }
  ]
}
```

**`site/src/lib/github.ts` — GitHub Releases API Client (EN KRİTİK DOSYA)**

```typescript
/**
 * GitHub Releases API'den en son release'in metadata'sını çeker.
 * Binary'leri Vercel'de HOST ETMİYORUZ — sadece download URL'lerini
 * GitHub'dan alıp sayfada gösteriyoruz.
 *
 * Rate limit (unauthenticated): 60 req/saat/IP
 * Rate limit (GITHUB_TOKEN ile): 5000 req/saat
 * Statik build'de bu fonksiyon BUILD TIME'da bir kere çalışır
 * → ISR veya SSR yapmadığımız sürece rate limit sorunu YAŞANMAZ.
 */

export interface ReleaseAsset {
  name: string;
  browser_download_url: string;
  size: number;
  download_count: number;
  platform: 'windows' | 'macos' | 'linux';
  arch: 'x64' | 'arm64';
  ext: 'msi' | 'exe' | 'dmg' | 'deb' | 'AppImage';
}

export interface LatestRelease {
  tag: string;
  version: string;
  published_at: string;
  body: string;           // changelog markdown
  assets: ReleaseAsset[];
  total_downloads: number;
}

const REPO_OWNER = 'azzizefe';
const REPO_NAME = 'netscope';
const GITHUB_API = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}`;

function classifyAsset(name: string): Pick<ReleaseAsset, 'platform' | 'arch' | 'ext'> {
  const lower = name.toLowerCase();

  const platform = lower.includes('windows') || lower.endsWith('.msi') || lower.endsWith('.exe')
    ? 'windows' as const
    : lower.includes('darwin') || lower.endsWith('.dmg')
    ? 'macos' as const
    : 'linux' as const;

  const arch = lower.includes('arm64') || lower.includes('aarch64') ? 'arm64' as const : 'x64' as const;

  const ext = lower.endsWith('.msi') ? 'msi' as const
    : lower.endsWith('.exe') ? 'exe' as const
    : lower.endsWith('.dmg') ? 'dmg' as const
    : lower.endsWith('.deb') ? 'deb' as const
    : lower.endsWith('.appimage') ? 'AppImage' as const
    : 'msi' as const; // fallback

  return { platform, arch, ext };
}

export async function getLatestRelease(): Promise<LatestRelease> {
  // Build-time fetch. Depo PRIVATE olduğu için GITHUB_TOKEN artık opsiyonel
  // değil, ZORUNLU: kimliksiz istek 404 döner ve sayfa sessizce
  // FALLBACK_RELEASE'e düşer — yani site kalıcı olarak eski sürümü gösterir.
  // Token'ı Vercel ortam değişkeni olarak ver (repo: read izni yeter).
  // Aynı şey release asset indirme URL'leri için de geçerli: private repo'nun
  // asset'leri kimliksiz indirilemez, indirme bağlantıları imzalı bir proxy
  // ya da ayrı bir public dağıtım kovası üzerinden verilmeli.
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'netscope-website/1.0',
  };

  const token = import.meta.env.GITHUB_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${GITHUB_API}/releases/latest`, { headers });

  if (!res.ok) {
    // Rate limit veya GitHub down → fallback statik veri
    console.error(`GitHub API error: ${res.status}`);
    return FALLBACK_RELEASE;
  }

  const release = await res.json();

  const assets: ReleaseAsset[] = release.assets.map((a: any) => ({
    name: a.name,
    browser_download_url: a.browser_download_url,
    size: a.size,
    download_count: a.download_count,
    ...classifyAsset(a.name),
  }));

  return {
    tag: release.tag_name,
    version: release.tag_name.replace(/^v/, ''),
    published_at: release.published_at,
    body: release.body || '',
    assets,
    total_downloads: assets.reduce((sum, a) => sum + a.download_count, 0),
  };
}

/** GitHub API unavailable durumunda kullanılacak statik fallback */
const FALLBACK_RELEASE: LatestRelease = {
  tag: 'v0.2.0',
  version: '0.2.0',
  published_at: '2026-07-25T00:00:00Z',
  body: 'Visit [github.com/azzizefe/netscope/releases](https://github.com/azzizefe/netscope/releases) for downloads.',
  assets: [],
  total_downloads: 0,
};

/**
 * Kullanıcının OS ve mimarisine göre önerilen asset'i bul.
 * Client-side'da çalışır — navigator.platform'dan tespit eder.
 */
export function getRecommendedAsset(
  assets: ReleaseAsset[],
  platformHint?: string
): ReleaseAsset | null {
  const hint = (platformHint || '').toLowerCase();

  if (!hint) return assets[0] || null;

  let targetPlatform: ReleaseAsset['platform'];
  if (hint.includes('win')) targetPlatform = 'windows';
  else if (hint.includes('mac')) targetPlatform = 'macos';
  else targetPlatform = 'linux';

  // Önce platform + x64 eşleştir (en yaygın)
  const match = assets.find(
    a => a.platform === targetPlatform && a.arch === 'x64'
  );
  return match || assets.find(a => a.platform === targetPlatform) || assets[0] || null;
}

/**
 * Sürüm geçmişini (son 10 release) çek.
 * /download sayfasındaki changelog için.
 */
export async function getReleaseHistory(): Promise<Pick<LatestRelease, 'tag' | 'version' | 'published_at'>[]> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'netscope-website/1.0',
  };
  const token = import.meta.env.GITHUB_TOKEN;
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${GITHUB_API}/releases?per_page=10`, { headers });
  if (!res.ok) return [];

  const releases = await res.json();
  return releases.map((r: any) => ({
    tag: r.tag_name,
    version: r.tag_name.replace(/^v/, ''),
    published_at: r.published_at,
  }));
}
```

**`site/src/lib/platform.ts` — Client-side OS Tespiti**

```typescript
export interface PlatformInfo {
  os: 'windows' | 'macos' | 'linux' | 'unknown';
  arch: 'x64' | 'arm64';
  name: string; // 'Windows', 'macOS', 'Linux'
  icon: string; // Lucide icon name
}

export function detectPlatform(): PlatformInfo {
  if (typeof navigator === 'undefined') {
    return { os: 'unknown', arch: 'x64', name: 'Unknown', icon: 'help-circle' };
  }

  const p = navigator.platform?.toLowerCase() || '';
  const ua = navigator.userAgent?.toLowerCase() || '';

  let os: PlatformInfo['os'] = 'unknown';
  if (p.includes('win') || ua.includes('windows')) os = 'windows';
  else if (p.includes('mac') || ua.includes('mac os')) os = 'macos';
  else if (p.includes('linux') || ua.includes('linux')) os = 'linux';

  // ARM detection (Apple Silicon Macs, Windows on ARM)
  // Note: navigator.platform on Apple Silicon returns 'MacIntel' — 
  // we can't reliably detect ARM from JS. Default to x64.
  const arch: PlatformInfo['arch'] = 'x64';

  const names: Record<string, string> = {
    windows: 'Windows',
    macos: 'macOS',
    linux: 'Linux',
    unknown: 'Unknown',
  };

  return { os, arch, name: names[os], icon: 'monitor' };
}
```

---

## 🏗️ Adım 2 — Sayfaların İnşası

### 2.1 Landing Page (`src/pages/index.astro`)

```astro
---
import Base from '../layouts/Base.astro';
import Hero from '../components/Hero.astro';
import FeatureGrid from '../components/FeatureGrid.astro';
import DownloadCTA from '../components/DownloadCTA.astro';

// Build-time: statik sayfa, 0 KB JS
---

<Base
  title="NetScope — Network Analyzer for Humans"
  description="A modern, fast network packet analyzer. 2500+ protocol dissectors, real-time capture, TLS decryption. Free download for personal use."
>
  <Hero />
  <FeatureGrid />
  <DownloadCTA />

  <!-- Trust section -->
  <section class="py-16 border-t border-zinc-800">
    <div class="mx-auto max-w-7xl px-6 text-center">
      <p class="text-zinc-500 text-sm uppercase tracking-widest mb-8">Signed Builds · No Telemetry</p>
      <div class="flex justify-center gap-12 opacity-50">
        <span class="text-zinc-400">Windows · macOS · Linux</span>
        <span class="text-zinc-400">Signed installers</span>
        <span class="text-zinc-400">Captures never leave your machine</span>
      </div>
    </div>
  </section>
</Base>
```

### 2.2 Download Sayfası (`src/pages/download.astro`) — EN KRİTİK SAYFA

```astro
---
import Base from '../layouts/Base.astro';
import { getLatestRelease, getReleaseHistory, type LatestRelease } from '../lib/github';

// Build-time data fetch. GitHub API'sinden en son release'i çek.
// Yeni release çıktığında Vercel re-deploy hook'u tetiklenir → sayfa güncellenir.
const release: LatestRelease = await getLatestRelease();
const history = await getReleaseHistory();

// Platform'a göre gruplanmış asset'ler
const byPlatform = {
  windows: release.assets.filter(a => a.platform === 'windows'),
  macos: release.assets.filter(a => a.platform === 'macos'),
  linux: release.assets.filter(a => a.platform === 'linux'),
};
---

<Base
  title={`Download NetScope v${release.version}`}
  description={`Download the latest NetScope desktop app for Windows, macOS, and Linux. Network analyzer with 2500+ protocol dissectors.`}
>
  <main class="mx-auto max-w-7xl px-6 py-16">
    <h1 class="text-4xl font-bold text-white mb-2">Download NetScope</h1>
    <p class="text-zinc-400 text-lg mb-12">
      Version {release.version} · {new Date(release.published_at).toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      })}
    </p>

    <!-- Auto-detected download card (client-side JS adası) -->
    <div class="mb-16 p-6 rounded-xl bg-emerald-500/10 border border-emerald-500/30" id="auto-download">
      <p class="text-emerald-400 text-sm mb-2">Recommended for your system</p>
      <div class="flex items-center justify-between">
        <div>
          <p class="text-white text-xl font-semibold" id="detected-os">Detecting your OS...</p>
          <p class="text-zinc-400 text-sm mt-1" id="detected-file"></p>
        </div>
        <a href="#" id="download-btn"
           class="px-8 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors">
          Download
        </a>
      </div>
    </div>

    <!-- Manuel platform seçimi -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <!-- Windows -->
      <div class="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
        <h3 class="text-white text-xl font-semibold mb-4">🪟 Windows</h3>
        {byPlatform.windows.length > 0 ? (
          <ul class="space-y-3">
            {byPlatform.windows.map(a => (
              <li>
                <a href={a.browser_download_url}
                   class="flex justify-between items-center p-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 transition-colors group">
                  <span class="text-zinc-300 group-hover:text-white">{a.name}</span>
                  <span class="text-zinc-500 text-sm">
                    {(a.size / 1024 / 1024).toFixed(1)} MB
                  </span>
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p class="text-zinc-500">Check the <a href={`https://github.com/azzizefe/netscope/releases/tag/${release.tag}`}
             class="text-emerald-400 hover:underline">GitHub release</a> for Windows builds.</p>
        )}
        <p class="mt-4 text-zinc-500 text-sm">
          Requires <a href="https://npcap.com/#download" class="text-emerald-400 hover:underline">Npcap</a> · Windows 10+
        </p>
      </div>

      <!-- macOS -->
      <div class="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
        <h3 class="text-white text-xl font-semibold mb-4">🍎 macOS</h3>
        {byPlatform.macos.length > 0 ? (
          <ul class="space-y-3">
            {byPlatform.macos.map(a => (
              <li>
                <a href={a.browser_download_url}
                   class="flex justify-between items-center p-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 transition-colors group">
                  <span class="text-zinc-300 group-hover:text-white">{a.name}</span>
                  <span class="text-zinc-500 text-sm">
                    {(a.size / 1024 / 1024).toFixed(1)} MB
                  </span>
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p class="text-zinc-500">Check the <a href={`https://github.com/azzizefe/netscope/releases/tag/${release.tag}`}
             class="text-emerald-400 hover:underline">GitHub release</a> for macOS builds.</p>
        )}
        <p class="mt-4 text-zinc-500 text-sm">
          macOS 12+ · Intel & Apple Silicon
        </p>
      </div>

      <!-- Linux -->
      <div class="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
        <h3 class="text-white text-xl font-semibold mb-4">🐧 Linux</h3>
        {byPlatform.linux.length > 0 ? (
          <ul class="space-y-3">
            {byPlatform.linux.map(a => (
              <li>
                <a href={a.browser_download_url}
                   class="flex justify-between items-center p-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 transition-colors group">
                  <span class="text-zinc-300 group-hover:text-white">{a.name}</span>
                  <span class="text-zinc-500 text-sm">
                    {(a.size / 1024 / 1024).toFixed(1)} MB
                  </span>
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p class="text-zinc-500">Check the <a href={`https://github.com/azzizefe/netscope/releases/tag/${release.tag}`}
             class="text-emerald-400 hover:underline">GitHub release</a> for Linux builds.</p>
        )}
        <p class="mt-4 text-zinc-500 text-sm">
          Also via package managers:
        </p>
        <div class="mt-2 space-y-2 font-mono text-sm">
          <code class="block p-2 rounded bg-zinc-800 text-emerald-400">
            brew install netscope
          </code>
          <code class="block p-2 rounded bg-zinc-800 text-emerald-400">
            snap install netscope
          </code>
          <code class="block p-2 rounded bg-zinc-800 text-emerald-400">
            winget install netscope
          </code>
        </div>
      </div>
    </div>

    <!-- Sürüm geçmişi -->
    <section class="mt-20">
      <h2 class="text-2xl font-bold text-white mb-6">Release History</h2>
      <div class="space-y-2">
        {history.map(r => (
          <a href={`https://github.com/azzizefe/netscope/releases/tag/${r.tag}`}
             class="flex justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-colors">
            <span class="text-zinc-300">{r.tag}</span>
            <span class="text-zinc-500">{new Date(r.published_at).toLocaleDateString()}</span>
          </a>
        ))}
      </div>
    </section>
  </main>
</Base>

<!-- Sadece bu sayfada çalışacak küçük JS: platform detection -->
<script>
  import { detectPlatform } from '../lib/platform';
  import { getRecommendedAsset } from '../lib/github';

  const platform = detectPlatform();
  const assets = JSON.parse(document.getElementById('release-data')?.textContent || '[]');
  const recommended = getRecommendedAsset(assets, platform.os);

  document.getElementById('detected-os')!.textContent = platform.name;
  if (recommended) {
    document.getElementById('detected-file')!.textContent = `${recommended.name} (${(recommended.size / 1024 / 1024).toFixed(1)} MB)`;
    (document.getElementById('download-btn') as HTMLAnchorElement).href = recommended.browser_download_url;
  } else {
    document.getElementById('detected-file')!.textContent = 'Scroll down for manual download';
    document.getElementById('download-btn')!.textContent = 'See below';
    (document.getElementById('download-btn') as HTMLAnchorElement).href = '#manual';
  }
</script>
```

### 2.3 WASM Demo Sayfası (`src/pages/demo.astro`)

```astro
---
import Base from '../layouts/Base.astro';
// Bu sayfa bir React island içerecek → hydration sadece bu rotada
// Diğer tüm sayfalar 0 KB JS kalır.
---

<Base title="Live Demo — NetScope" description="Try NetScope in your browser. Upload a .pcap file and analyze packets instantly.">
  <main class="mx-auto max-w-7xl px-6 py-16">
    <h1 class="text-4xl font-bold text-white mb-4">Try NetScope Online</h1>
    <p class="text-zinc-400 text-lg mb-8">
      Upload a <code class="text-emerald-400">.pcap</code> or <code class="text-emerald-400">.pcapng</code>
      file and analyze it right in your browser — no installation required.
      Powered by WebAssembly.
    </p>

    <!-- Drop zone + WASM widget — client:load React island -->
    <div id="wasm-demo" class="min-h-[600px] rounded-xl bg-zinc-900 border border-zinc-800 p-6">
      <!-- React component mounts here -->
    </div>

    <!-- Örnek PCAP dosyaları -->
    <section class="mt-12">
      <h2 class="text-xl font-bold text-white mb-4">Sample Captures</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <a href="/samples/http.pcap" download
           class="p-4 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-emerald-500/50 transition-colors">
          <p class="text-white font-medium">HTTP Traffic</p>
          <p class="text-zinc-500 text-sm mt-1">Basic web browsing capture</p>
        </a>
        <a href="/samples/dns.pcap" download
           class="p-4 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-emerald-500/50 transition-colors">
          <p class="text-white font-medium">DNS Queries</p>
          <p class="text-zinc-500 text-sm mt-1">Name resolution traffic</p>
        </a>
        <a href="/samples/tls-handshake.pcap" download
           class="p-4 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-emerald-500/50 transition-colors">
          <p class="text-white font-medium">TLS Handshake</p>
          <p class="text-zinc-500 text-sm mt-1">HTTPS connection setup</p>
        </a>
      </div>
    </section>

    <!-- CTA: Desktop app -->
    <div class="mt-16 text-center p-8 rounded-xl bg-gradient-to-r from-emerald-500/10 to-teal-500/10 border border-emerald-500/20">
      <h2 class="text-2xl font-bold text-white mb-3">Want the full power?</h2>
      <p class="text-zinc-400 mb-6">
        The desktop app supports live capture, TLS decryption, threat detection, and 2500+ protocols.
      </p>
      <a href="/download"
         class="inline-block px-8 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors">
        Download NetScope Desktop →
      </a>
    </div>
  </main>
</Base>
```

### 2.4 Base Layout (`src/layouts/Base.astro`)

```astro
---
import Nav from '../components/Nav.astro';
import Footer from '../components/Footer.astro';
import SEO from '../components/SEO.astro';

export interface Props {
  title: string;
  description: string;
  image?: string;
  noindex?: boolean;
}

const { title, description, image, noindex } = Astro.props;
---

<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />

    <!-- Font: Inter (en yaygın, en hızlı, variable) -->
    <link rel="preconnect" href="https://fonts.bunny.net" />
    <link href="https://fonts.bunny.net/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />

    <SEO {title} {description} {image} {noindex} />

    <!-- Analytics (privacy-first, self-host alternatif: Plausible) -->
    <script defer data-domain="netscope.vercel.app" src="https://plausible.io/js/script.js"></script>
  </head>
  <body class="bg-zinc-950 text-zinc-100 font-sans antialiased">
    <Nav />
    <slot />
    <Footer />
  </body>
</html>

<style is:global>
  /* Tailwind directives */
  @tailwind base;
  @tailwind components;
  @tailwind utilities;

  /* Base layer overrides */
  @layer base {
    html {
      scroll-behavior: smooth;
    }
    body {
      font-family: 'Inter', system-ui, sans-serif;
    }
  }
</style>
```

---

## 🏗️ Adım 3 — Vercel Deploy

### 3.1 İlk Deploy (Vercel CLI ile)

```bash
# site/ dizininde
cd site

# Vercel CLI'yi yükle (tek seferlik)
npm i -g vercel

# İnteraktif kurulum — repo ile bağla
vercel
# ? Set up and deploy: Yes
# ? Which scope: (kişisel hesabın)
# ? Link to existing project: No
# ? Project name: netscope
# ? In which directory: ./
# ? Override settings: No

# İlk deploy tamam. Prod URL: https://netscope.vercel.app
```

### 3.2 GitHub'a Push → Otomatik Deploy

```bash
# site/ dizinindeki değişiklikleri commit et
git add site/
git commit -m "feat: add Astro landing page with download portal"
git push origin main

# Vercel otomatik olarak yeni commit'i algılar ve deploy eder.
# Preview deployment: her PR için ayrı URL
# Production deployment: main branch her push
```

### 3.3 Domain Bağlama (Opsiyonel)

Vercel Dashboard → Project → Settings → Domains:
```
netscope.app    → https://netscope.vercel.app (301 redirect)
www.netscope.app → https://netscope.app
```

DNS kayıtları (domain sağlayıcında):
```
CNAME  @      cname.vercel-dns.com
CNAME  www    cname.vercel-dns.com
```

---

## 🏗️ Adım 4 — CI/CD Entegrasyonu

### 4.1 GitHub Actions: Release → Vercel Re-Deploy

Yeni bir GitHub Release oluşturulduğunda download sayfasının güncellenmesi için Vercel'e deploy hook gönder. Mevcut `.github/workflows/release.yml` sonuna ekle:

```yaml
# .github/workflows/release.yml mevcut sonuna EKLE:

  # ⬇️ YENİ: Release sonrası Vercel sitesini güncelle
  trigger-vercel-deploy:
    name: Trigger Vercel Site Rebuild
    runs-on: ubuntu-latest
    needs: [create-release]   # release oluştuktan sonra çalış
    steps:
      - name: Trigger Vercel deploy hook
        run: |
          curl -X POST "${{ secrets.VERCEL_DEPLOY_HOOK_URL }}"
```

**Vercel Deploy Hook nasıl alınır:**
1. Vercel Dashboard → netscope projesi → Settings → Git → Deploy Hooks
2. "Create Hook" → isim: `release-update`, branch: `main`
3. Oluşan URL'yi kopyala → GitHub repo Settings → Secrets → `VERCEL_DEPLOY_HOOK_URL`

### 4.2 GitHub Token (Build-time API Rate Limit için)

```bash
# GitHub'da: Settings → Developer settings → Personal access tokens → Fine-grained tokens
# Permission: Read-only, sadece "Contents" (releases okumak için)
# Repo: sadece azzizefe/netscope

# Vercel Dashboard → Project → Settings → Environment Variables
# GITHUB_TOKEN = github_pat_...
```

Bu token olmadan da çalışır (60 req/saat/IP), ama Vercel build IP'si shared olduğu için güvenli tarafta olmak için kullan.

---

## 🏗️ Adım 5 — Auto-Update Mimarisi

### 5.1 Tauri Tarafı (`desktop/src-tauri/`)

```rust
// desktop/src-tauri/Cargo.toml'a ekle:
// tauri-plugin-updater = "2"

// desktop/src-tauri/src/lib.rs'de:
use tauri_plugin_updater::UpdaterExt;

// Builder'a plugin ekle:
// .plugin(tauri_plugin_updater::Builder::new().build())

// Check update (app başlangıcında veya manuel):
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = app.updater_builder()
        .endpoint("https://netscope.vercel.app/api/update")
        .build()
        .map_err(|e| e.to_string())?;

    match updater.check().await {
        Ok(Some(update)) => Ok(Some(UpdateInfo {
            version: update.version,
            body: update.body.unwrap_or_default(),
            date: update.date,
        })),
        Ok(None) => Ok(None), // up-to-date
        Err(e) => Err(e.to_string()),
    }
}
```

### 5.2 Vercel Serverless Function (`site/api/update.ts`)

```typescript
// Vercel serverless function: /api/update
// Tauri updater bu endpoint'e GET atar → güncelleme varsa JSON döner.
// Eğer yoksa 204 No Content döner (Tauri "up-to-date" olarak yorumlar).

import type { VercelRequest, VercelResponse } from '@vercel/node';

const REPO_OWNER = 'azzizefe';
const REPO_NAME = 'netscope';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Tauri updater'dan gelen version header'ı
  const currentVersion = req.headers['tauri-updater-current-version'] as string;
  const targetPlatform = req.headers['tauri-updater-target'] as string; // 'windows-msi-x64', 'darwin-dmg-x64', etc.

  const release = await fetch(
    `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest`,
    {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'netscope-updater/1.0',
        ...(process.env.GITHUB_TOKEN && {
          'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`,
        }),
      },
    }
  ).then(r => r.json());

  const latestVersion = release.tag_name?.replace(/^v/, '');

  if (!latestVersion || latestVersion === currentVersion) {
    return res.status(204).end(); // No update available
  }

  // Tauri'nin beklediği JSON formatı:
  // https://v2.tauri.app/plugin/updater/#update-server-json
  res.json({
    version: `v${latestVersion}`,
    notes: release.body || '',
    pub_date: release.published_at,
    platforms: {
      'windows-x86_64': {
        signature: '', // Authenticode imzası (opsiyonel)
        url: release.assets.find((a: any) =>
          a.name.includes('windows') && !a.name.includes('arm64')
        )?.browser_download_url || '',
      },
      'darwin-x86_64': {
        signature: '',
        url: release.assets.find((a: any) =>
          a.name.includes('darwin') && a.name.includes('x64')
        )?.browser_download_url || '',
      },
      'darwin-aarch64': {
        signature: '',
        url: release.assets.find((a: any) =>
          a.name.includes('darwin') && a.name.includes('aarch64')
        )?.browser_download_url || '',
      },
      'linux-x86_64': {
        signature: '',
        url: release.assets.find((a: any) =>
          a.name.includes('linux') && !a.name.includes('arm')
        )?.browser_download_url || '',
      },
    },
  });
}

// Vercel konfigürasyonu için vercel.json'a ekle:
// {
//   "functions": {
//     "api/update.ts": {
//       "memory": 256,
//       "maxDuration": 10
//     }
//   }
// }
```

---

## 🔐 Güvenlik Kontrol Listesi

| Katman | Önlem |
|--------|-------|
| **CSP** | Astro'da `Content-Security-Policy` header'ı `vercel.json`'da tanımla |
| **Download integrity** | GitHub Release'te her binary için SHA-256 `.sha256` dosyası oluştur, sayfada göster |
| **HTTPS only** | Vercel varsayılan olarak HTTP'yi HTTPS'e yönlendirir |
| **API rate limiting** | `/api/update` endpoint'ine Vercel WAF veya `arcjet` ile rate limit |
| **Dependency audit** | `npm audit` CI'a ekle (zaten `ci.yml` var, oraya eklenebilir) |
| **Environment variables** | Sadece `GITHUB_TOKEN` (read-only, minimal scope) |

---

## 📦 Özet: Tüm Akış

```
DEVELOPER                      CI/CD                           USER
────────                       ─────                           ────
git tag v0.3.0 ──► release.yml çalışır
  push                         │
                               ├─► cargo tauri build (.msi/.dmg/.deb)
                               ├─► GitHub Release oluştur
                               └─► Vercel Deploy Hook tetikle ──► Site rebuild
                                                                   │
                                                                   ├─► /download güncellenir
                                                                   │   (yeni versiyon, yeni linkler)
                                                                   │
  KULLANICI ◄──────────────────────────────────────────────────────┘
    │
    ├─► netscope.app → Download → .msi indir
    │                              │
    │                              └─► Kurulum → App açılır
    │                                            │
    │   (sonraki sürüm)                          │
    │   App "Update available" ◄─────────────────┘
    │   → /api/update → GitHub Release URL
    │   → Download & install update
```

---

## ⚡ Quick Start (Bugün Başla)

```bash
# 1. Astro site scaffold
cd netscope
npm create astro@latest site -- --template basics --typescript strict
cd site
npx astro add tailwind
npx astro add mdx

# 2. GitHub API client'ı oluştur
mkdir -p src/lib
# Yukarıdaki github.ts ve platform.ts'yi buraya yaz

# 3. İlk deploy
vercel

# 4. Git commit
cd ..
git add site/ ROADMAP.md IMPLEMENTATION.md
git commit -m "feat: add Astro landing site + download portal for Vercel deploy"
git push origin main
```

> **Son güncelleme:** 25 Temmuz 2026
> **Sıradaki:** `npm create astro@latest site` ile başla. 🚀
