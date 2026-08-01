# Netscope — Windows .exe Dağıtımı & Next.js Web Sitesi Rehberi

Bu doküman iki ana bölümden oluşmaktadır:

1. **Bölüm A** — Netscope'u Windows `.exe` / `.msi` olarak paketlemeden önce yapılması gereken ön hazırlıklar ve derleme adımları.
2. **Bölüm B** — Ayrı bir klasörde Next.js ile tanıtım web sitesi oluşturma ve Vercel'e yayınlama tavsiyeleri.

---

# Bölüm A: Windows .exe Paketleme

## A.1 — Ön Gereksinimler (Bu Adımları Atlamayın!)

### A.1.1 — Npcap Sürücüsü (Çalışma Zamanı)
Netscope canlı ağ yakalama için **Npcap** sürücüsüne ihtiyaç duyar. Bu sürücü `.exe` içine gömülemez; son kullanıcının kendi bilgisayarına ayrıca kurması gerekir.

> [!IMPORTANT]
> Npcap ticari bir lisansa sahiptir ve yeniden dağıtılamaz. Bu nedenle `.exe`'ye gömülmesi veya installer ile birlikte dağıtılması **yasaktır**. Kullanıcılar https://npcap.com adresinden indirmelidir.

**Geliştirici makinenizde kontrol edin:**
```powershell
# Npcap yüklü mü?
Get-Service npcap -ErrorAction SilentlyContinue

# Yoksa yükleyin (WinPcap uyumlu modu işaretleyin)
# https://npcap.com/#download adresinden indirin
```

### A.1.2 — Npcap SDK (Derleme Zamanı)
Derleme zamanında Rust linker'ın `Packet.lib` ve `wpcap.lib`'e ihtiyacı vardır. Bu dosyalar depoda tutulmamalıdır; bunun yerine mevcut script kullanılır:

```powershell
.\tools\ensure-npcap-sdk.ps1
```

Bu script SDK'yı `npcap-sdk/` klasörüne indirir. `.cargo/config.toml` zaten `LIBPCAP_LIBDIR` değişkenini bu dizine yönlendirir.

### A.1.3 — Rust Toolchain
```powershell
# Stable Rust (minimum 1.88) yüklü olmalı
rustup show

# Yoksa yükleyin
rustup toolchain install stable

# WASM target'ı ekleyin (frontend filtreleme motoru için gerekli)
rustup target add wasm32-unknown-unknown
```

### A.1.4 — wasm-bindgen-cli
Frontend WASM modülünü oluşturmak için `wasm-bindgen-cli` gereklidir. **Versiyonu Cargo.lock ile aynı olmalıdır**, aksi halde CLI çalışmayı reddeder:

```powershell
cargo install wasm-bindgen-cli --version 0.2.126
```

### A.1.5 — Tauri CLI v2
```powershell
cargo install tauri-cli --version "^2"
```

---

## A.2 — .exe Öncesi Zorunlu Kontroller

> [!CAUTION]
> Bu kontrolleri geçmeden `.exe` üretmeye çalışmayın. Hatalı bir `.exe` dağıtmak geri alınamaz hasar yaratır.

### A.2.1 — Tüm Testlerin Geçtiğini Doğrulayın
```powershell
# Core, TUI, Server ve Agent testleri
cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent

# Desktop testleri (ayrı çalıştırılmalı — comctl32 manifest sorunu)
cargo test -p netscope-desktop
```

### A.2.2 — Clippy ve Format Kontrolü
```powershell
cargo clippy --workspace --exclude netscope-desktop -- -D warnings
cargo fmt --check
```

### A.2.3 — WASM Modülünü Derleyin ve Bağlayın
Bu adım **kritiktir** — atlandığında masaüstü uygulaması açılırken beyaz ekran görüntülenir çünkü frontend'in ilk import'u 404 döner.

```powershell
# 1. WASM modülünü derleyin
cargo build -p netscope-wasm --release --target wasm32-unknown-unknown

# 2. JavaScript bindings oluşturun
wasm-bindgen --target web --out-dir desktop/frontend/wasm target/wasm32-unknown-unknown/release/netscope_wasm.wasm
```

### A.2.4 — Frontend Test Paketi (Vitest)
```powershell
cd desktop/frontend-tests
npm ci
npm test
cd ../..
```

---

## A.3 — .exe / .msi Üretimi (Build)

### A.3.1 — Geliştirme Testi (Debug Build)
İlk önce debug modda çalıştırarak her şeyin yerli yerinde olduğunu doğrulayın:

```powershell
cd desktop/src-tauri
cargo tauri dev
```

> [!NOTE]
> Debug build'de UAC yükseltme (Administrator istemi) **devre dışıdır** — bu tasarım gereğidir. `build.rs` içinde debug profili elevation bloğunu çıkarır, aksi halde yükseltilmemiş bir terminalden `cargo run` çalıştırılamaz (OS error 740).

### A.3.2 — Release Build (Üretim .exe + .msi)
```powershell
cd desktop/src-tauri
cargo tauri build --bundles nsis,msi
```

Bu komut şunları üretir:
| Çıktı | Konum |
|---|---|
| `netscope.exe` (standalone) | `target/release/netscope.exe` |
| `.msi` kurulum paketi | `target/release/bundle/msi/netscope_0.2.0_x64_en-US.msi` |
| NSIS `.exe` installer | `target/release/bundle/nsis/netscope_0.2.0_x64-setup.exe` |

> [!WARNING]
> Release build'de `requireAdministrator` manifest gömülüdür — uygulama her açılışta UAC istemi gösterir. Bu, IP engelleme özelliğinin (`netsh` firewall kuralları) çalışması için zorunludur. Eğer bu davranışı istemiyorsanız `build.rs` satır 26-37'deki elevation bloğunu düzenleyin.

### A.3.3 — Kod İmzalama (Code Signing) — İsteğe Bağlı ama Önerilen
İmzasız `.exe` dosyaları Windows SmartScreen tarafından engellenir ve kullanıcıya kötü amaçlı yazılım uyarısı gösterilir.

**Seçenek 1 — Kendi Sertifikanızla İmzalama:**
```powershell
# PFX sertifikanızı import edin
$pfx = "C:\path\to\your-certificate.pfx"
$password = "your-password"

# signtool.exe'yi bulun (Windows SDK ile gelir)
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
  Where-Object { $_.FullName -match '\\x64\\' } |
  Sort-Object FullName -Descending |
  Select-Object -First 1

# İmzalayın
& $signtool.FullName sign /f $pfx /p $password /tr http://timestamp.digicert.com /td sha256 /fd sha256 target\release\netscope.exe
```

**Seçenek 2 — GitHub Actions ile Otomatik İmzalama:**
Mevcut `release.yml` dosyası zaten `WINDOWS_CERTIFICATE` ve `WINDOWS_CERTIFICATE_PASSWORD` secret'larıyla Authenticode imzalamayı destekliyor. Repo secret'larını ayarlayarak aktifleştirin:
```
Settings → Secrets → Actions → New repository secret
  WINDOWS_CERTIFICATE = <PFX dosyasının base64 kodlanmış hali>
  WINDOWS_CERTIFICATE_PASSWORD = <PFX şifresi>
```

---

## A.4 — Dağıtım Öncesi Son Kontrol Listesi

- [ ] `cargo tauri build` sıfır hata ile tamamlandı
- [ ] Üretilen `.exe` çift tıklama ile açılıyor
- [ ] UAC istemi göründü (release build)
- [ ] Ana ekran yüklendi (beyaz ekran YOK)
- [ ] Canlı paket yakalama başlatılabiliyor (Npcap yüklüyse)
- [ ] Bir `.pcap` dosyası açılarak offline analiz çalışıyor
- [ ] Filtre çubuğu çalışıyor (WASM modülü aktif)
- [ ] i18n — dil değişimi çalışıyor (Türkçe / İngilizce)
- [ ] IP engelleme özelliği çalışıyor (yönetici modunda)
- [ ] `.msi` installer'ı temiz bir makinede test edildi

---

# Bölüm B: Next.js Tanıtım Web Sitesi & Vercel Yayınlama

## B.1 — Proje Yapısı Önerisi

Web sitesini Netscope repo'sunun **dışında**, ayrı bir klasörde oluşturun. Böylece:
- Git geçmişleri karışmaz
- Vercel otomatik deploy sadece web sitesini tetikler
- Rust derleme süreleri web sitesi CI'ını etkilemez

```
C:\Users\efe\Desktop\
├── netscope\              ← Ana Rust projesi (mevcut)
└── netscope-web\          ← Yeni Next.js web sitesi
```

## B.2 — Next.js Proje Kurulumu

```powershell
cd C:\Users\efe\Desktop
npx -y create-next-app@latest netscope-web --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm
cd netscope-web
```

## B.3 — Önerilen Sayfa Yapısı

```
src/
├── app/
│   ├── layout.tsx          # Root layout (dark mode, Inter font, meta tags)
│   ├── page.tsx            # Landing/Hero page
│   ├── features/
│   │   └── page.tsx        # Özellikler sayfası
│   ├── docs/
│   │   └── page.tsx        # Dokümantasyon
│   ├── demo/
│   │   └── page.tsx        # WASM Demo (tarayıcıda pcap analizi)
│   └── download/
│       └── page.tsx        # İndirme sayfası (GitHub Releases API'den çekilen linkler)
├── components/
│   ├── Hero.tsx            # Ana görsel bölüm
│   ├── FeatureGrid.tsx     # Özellik kartları (grid)
│   ├── Terminal.tsx         # TUI ekran görüntüsü animasyonu
│   ├── DownloadButton.tsx  # Platform algılayan indirme butonu
│   ├── Navbar.tsx          # Navigasyon çubuğu
│   └── Footer.tsx          # Alt bilgi
└── lib/
    ├── github.ts           # GitHub Releases API entegrasyonu
    └── constants.ts        # Sabit değerler
```

## B.4 — Sayfa İçeriği Tavsiyeleri

### B.4.1 — Landing Page (Hero)
- **Başlık:** "Ağ trafiğinizi gerçek zamanlı analiz edin"
- **Alt başlık:** Kısa, vurucu bir açıklama
- **CTA butonları:** "İndir (Windows)" + "Demoyu Dene"
- **Arka plan:** Koyu gradient + ağ düğümleri animasyonu (Canvas veya Framer Motion)
- **TUI/Desktop ekran görüntüleri:** Gerçek uygulama screenshot'ları veya animasyonlu GIF

### B.4.2 — Özellikler Sayfası
Aşağıdaki özellik gruplarını kart grid formatında gösterin:
| Kategori | Özellikler |
|---|---|
| 🔬 Protokol Analizi | 850+ protokol çözümleyici, PQC analizi, TLS/QUIC derinlemesine inceleme |
| 🛡️ Güvenlik | IP engelleme, tehdit istihbaratı, anomali tespiti, risk puanlama |
| 📊 İstatistikler | Bant genişliği, protokol dağılımı, coğrafi analiz (GeoIP) |
| 🖥️ Arayüzler | Terminal (TUI), Masaüstü (Tauri), Web Demo (WASM) |
| 🤖 AI Trafik Analizi | LLM/AI servis trafiği tanıma (OpenAI, Anthropic, Gemini vb.) |

### B.4.3 — Demo Sayfası (WASM)
- Kullanıcı `.pcap` dosyasını sürükleyip bırakır
- `netscope-wasm` modülü tarayıcıda dosyayı parse eder (sunucuya veri gönderilmez)
- Sonuçlar tablo + grafik olarak görselleştirilir
- **Gizlilik vurgusu:** "Verileriniz tarayıcınızdan çıkmaz" mesajı

### B.4.4 — İndirme Sayfası
- `navigator.userAgent` ile platform algılama (Windows/macOS/Linux)
- GitHub Releases API'den (`https://api.github.com/repos/azzizefe/netscope/releases/latest`) en güncel release linklerini dinamik çekme
- Her platform için ön koşulları gösterme (Windows → Npcap, Linux → libpcap, macOS → Homebrew/Xcode CLT)

## B.5 — Tasarım Tavsiyeleri

### Renk Paleti (Koyu Tema)
```css
:root {
  --bg-primary:    #0a0a0f;    /* Derin koyu arka plan */
  --bg-secondary:  #12121a;    /* Kart arka planı */
  --bg-tertiary:   #1a1a2e;    /* Hover/aktif durumlar */
  --accent-cyan:   #00d4ff;    /* Ana vurgu rengi — ağ/siber teması */
  --accent-purple: #7c3aed;    /* İkincil vurgu */
  --accent-green:  #10b981;    /* Başarı/durum göstergesi */
  --text-primary:  #e2e8f0;    /* Ana metin */
  --text-muted:    #64748b;    /* Soluk metin */
  --border:        #1e293b;    /* Kenarlıklar */
}
```

### Font
```tsx
// layout.tsx
import { Inter, JetBrains_Mono } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })
const jetbrains = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' })
```

### Animasyonlar
- **Framer Motion** — Sayfa geçişleri ve kart animasyonları
- **React Particles** veya **tsParticles** — Arka planda ağ düğümleri efekti
- **CSS `backdrop-filter: blur()`** — Glassmorphism kartlar

## B.6 — Vercel'e Yayınlama

### B.6.1 — GitHub Deposu Oluşturun
```powershell
cd C:\Users\efe\Desktop\netscope-web
git init
git add .
git commit -m "chore: initial Next.js setup"
git remote add origin https://github.com/azzizefe/netscope-web.git
git push -u origin main
```

### B.6.2 — Vercel Bağlantısı
1. https://vercel.com adresine gidin ve GitHub hesabınızla oturum açın
2. **"Add New Project"** → `azzizefe/netscope-web` deposunu seçin
3. Framework: **Next.js** (otomatik algılanır)
4. Build komutu: `npm run build` (varsayılan)
5. Çıktı dizini: `.next` (varsayılan)
6. **Deploy** butonuna basın

### B.6.3 — Özel Alan Adı (İsteğe Bağlı)
```
Vercel Dashboard → Settings → Domains → netscope.app (veya tercih ettiğiniz alan adı)
```

### B.6.4 — Ortam Değişkenleri (Gerekirse)
```
NEXT_PUBLIC_GITHUB_REPO=azzizefe/netscope
NEXT_PUBLIC_SITE_URL=https://netscope.vercel.app
```

## B.7 — WASM Demo Entegrasyonu (İleri Düzey)

Web sitesinde tarayıcı içi PCAP analiz demosunu sunmak için:

1. **Ana projede WASM paketini oluşturun:**
   ```powershell
   cd C:\Users\efe\Desktop\netscope
   cargo build -p netscope-wasm --release --target wasm32-unknown-unknown
   wasm-bindgen --target web --out-dir ../netscope-web/public/wasm target/wasm32-unknown-unknown/release/netscope_wasm.wasm
   ```

2. **Next.js'de WASM yükleme:**
   ```typescript
   // src/lib/wasm.ts
   export async function initNetscope() {
     const wasm = await import('/wasm/netscope_wasm.js')
     await wasm.default()
     return wasm
   }
   ```

3. **Demo bileşeninde kullanım:**
   ```tsx
   'use client'
   import { useCallback, useState } from 'react'
   import { initNetscope } from '@/lib/wasm'
   
   export default function DemoPage() {
     const [results, setResults] = useState(null)
     
     const handleDrop = useCallback(async (file: File) => {
       const wasm = await initNetscope()
       const buffer = await file.arrayBuffer()
       const packets = wasm.parse_pcap(new Uint8Array(buffer))
       setResults(packets)
     }, [])
     
     // ... drag-and-drop UI
   }
   ```

## B.8 — SEO & Meta Tag'ler

```tsx
// src/app/layout.tsx
export const metadata = {
  title: 'Netscope — Gerçek Zamanlı Ağ Trafik Analizörü',
  description: 'Açık kaynaklı, 850+ protokol destekli ağ paket analizörü. TUI, masaüstü ve web arayüzleri ile profesyonel ağ izleme.',
  keywords: ['network analyzer', 'packet capture', 'wireshark alternative', 'rust', 'tui'],
  openGraph: {
    title: 'Netscope — Network Traffic Analyzer',
    description: 'Open-source network packet analyzer with 850+ protocol dissectors',
    url: 'https://netscope.vercel.app',
    siteName: 'Netscope',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Netscope',
    description: 'Real-time network traffic analyzer',
  },
}
```

---

# Özet Akış Şeması

```
┌─────────────────────────────────────────────┐
│           .EXE ÜRETİM ADIMLARI              │
├─────────────────────────────────────────────┤
│  1. Npcap SDK indir (ensure-npcap-sdk.ps1)  │
│  2. cargo test (tüm crate'ler)              │
│  3. cargo clippy + cargo fmt --check        │
│  4. WASM build + wasm-bindgen               │
│  5. Frontend tests (vitest)                 │
│  6. cargo tauri dev    (debug test)         │
│  7. cargo tauri build  (release .exe/.msi)  │
│  8. Kod imzalama (opsiyonel)                │
│  9. Temiz makinede test                     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│        WEB SİTESİ YAYINLAMA ADIMLARI        │
├─────────────────────────────────────────────┤
│  1. Ayrı klasörde Next.js proje oluştur     │
│  2. Sayfa yapısını kur (Hero, Features...)  │
│  3. Koyu tema + animasyonlar ekle           │
│  4. WASM demo entegrasyonu (opsiyonel)      │
│  5. GitHub'a push et                        │
│  6. Vercel'e bağla → otomatik deploy        │
│  7. Özel alan adı ekle (opsiyonel)          │
└─────────────────────────────────────────────┘
```
