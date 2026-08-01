# Netscope Windows Derleme ve Paketleme Kılavuzu (Windows Build & Packaging Guide)

Netscope masaüstü uygulaması ([`netscope-desktop`](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri)), **Tauri v2** mimarisi üzerine kurulmuştur. Windows işletim sisteminde dağıtılabilir bir `.exe` (veya NSIS/MSI yükleyicisi) üretebilmek için hem ön gereksinimlerin kurulması hem de çekirdeğin ([`netscope-core`](file:///c:/Users/efe/Desktop/netscope/crates/core)) bağımlı olduğu **Npcap SDK** kütüphanelerinin doğru şekilde bağlanması (linking) gerekir.

Bu kılavuz, senior seviyesinde sıfırdan Windows build ortamının kurulumunu, derleme adımlarını, kod imzalamayı (Authenticode) ve karşılaşılabilecek olası sorunların çözümlerini detaylandırmaktadır.

---

## 1. Windows Derleme Ön Gereksinimleri

Windows üzerinde derleme yapabilmek için sisteminizde aşağıdaki araçların kurulu olması zorunludur:

### 1.1. C++ Build Tools (MSVC Toolchain)
Rust ve Tauri, Windows üzerinde C++ derleyicisine ihtiyaç duyar.
1. [Visual Studio Installer](https://visualstudio.microsoft.com/downloads/) uygulamasını indirin.
2. Kurulumda **"C++ ile masaüstü geliştirme"** (Desktop development with C++) iş yükünü seçin.
3. MSVC v143 veya üzeri derleyici ile birlikte **Windows 10 SDK** (veya Windows 11 SDK) bileşenlerinin seçili olduğunu doğrulayın.

### 1.2. Npcap SDK Kurulumu (Linker Bağımlılığı)
Netscope'un paket yakalama çekirdeği `libpcap` wrapper'ı kullanır. Windows üzerinde derleme yaparken bağlayıcının (linker) `wpcap.lib` ve `Packet.lib` dosyalarını bulabilmesi gerekir.
1. Projedeki hazır script'i PowerShell üzerinden çalıştırarak SDK'yı edinin:
   ```powershell
   .\tools\ensure-npcap-sdk.ps1
   ```
2. Bu script, Npcap SDK'sını indirir ve `npcap-sdk/` dizinine yerleştirir.
3. `.cargo/config.toml` dosyası içerisindeki `LIBPCAP_LIBDIR` ortam değişkeninin bu dizini işaret ettiğinden emin olun (yerelde otomatik ayarlanır).

### 1.3. Node.js ve WASM Derleme
Arayüz tarafındaki filtreleme ve PII maskeleme modülleri WebAssembly ile çalışır.
1. **Node.js** v18+ sürümünün kurulu olduğundan emin olun.
2. WebAssembly modülünü derlemek için:
   ```powershell
   .\tools\build-wasm.ps1
   ```

---

## 2. Derleme Süreci (Build Execution)

Tauri uygulamasını derlemek için iki temel yöntem mevcuttur: **Doğrudan Cargo** ve **Tauri CLI Yöneticisi**.

### Yöntem A: Sadece Bağımsız `.exe` Üretimi (Doğrudan Cargo)
Kurulum paketi (Installer) olmadan sadece doğrudan çalıştırılabilir tek bir `.exe` dosyası üretmek istiyorsanız bu yöntemi kullanın.
1. Terminalde proje kök dizinindeyken release profilinde derleme yapın:
   ```bash
   cargo build -p netscope-desktop --release
   ```
2. **Çıktı Konumu:** Derlenen `.exe` dosyası `target/release/netscope-desktop.exe` yolunda oluşacaktır.
3. > [!NOTE]
   > `[build.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/build.rs)` dosyası, `PROFILE` ortam değişkeni `release` olduğunda uygulamanın manifest dosyasına otomatik olarak `requireAdministrator` yetki isteğini ekler. Bu sayede üretilen `.exe` çift tıklandığında doğrudan Windows UAC (Kullanıcı Hesabı Denetimi) penceresini açacak ve yönetici olarak çalışacaktır (Güvenlik duvarı kurallarını yönetebilmesi için gereklidir).

### Yöntem B: Dağıtılabilir Kurulum Paketleri Üretimi (Tauri CLI)
Kullanıcılara sunulmak üzere `.msi` (WiX Toolset) veya `.exe` (NSIS) biçiminde yükleme sihirbazı oluşturmak için bu adımı izleyin.
1. Tauri CLI aracını yükleyin:
   ```bash
   cargo install tauri-cli --version ^2.0.0
   ```
2. Derleme komutunu çalıştırın:
   ```bash
   cargo tauri build
   ```
3. **Çıktı Konumları:**
   *   **NSIS Kurulum Sihirbazı:** `target/release/bundle/nsis/netscope_0.2.0_x64-setup.exe`
   *   **MSI Paketi:** `target/release/bundle/msi/netscope_0.2.0_x64_en-US.msi`

---

## 3. Kod İmzalama (Authenticode Code Signing)
> [!CAUTION]
> Windows SmartScreen koruması, imzalanmamış veya güvenilmeyen sertifikalarla imzalanmış uygulamaların çalıştırılmasını varsayılan olarak engeller ve kullanıcıya kırmızı bir uyarı gösterir. Production çıkışından önce imzalama zorunludur.

Tauri, derleme aşamasında otomatik imzalama (signing) yapabilmektedir. Bunun için `tauri.conf.json` veya ortam değişkenlerine sertifika bilgilerini tanımlamak gerekir.

### 3.1. Gerekli Ortam Değişkenleri
Sertifikanızı derleme sunucusuna veya yerel bilgisayarınıza kurduktan sonra aşağıdaki ortam değişkenlerini ayarlayarak `cargo tauri build` çalıştırırsanız, Tauri çıktıyı otomatik imzalar:

```powershell
# Sertifikanın bulunduğu PFX dosyasının yolu
$env:TAURI_SIGNING_PRIVATE_KEY = "C:\Path\To\Sertifika.pfx"

# Sertifika şifresi
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "SertifikaSifresi"
```

### 3.2. Manuel İmzalama (Signtool)
Eğer Tauri paketleme bittikten sonra manuel imzalama yapmak isterseniz Windows SDK ile birlikte gelen `signtool.exe` aracını kullanabilirsiniz:

```powershell
signtool sign /f "C:\Path\To\Sertifika.pfx" /p "SertifikaSifresi" /tr http://timestamp.digicert.com /td sha256 /fd sha256 "target\release\bundle\nsis\netscope_0.2.0_x64-setup.exe"
```

---

## 4. Tauri Konfigürasyonunun İncelenmesi

`[tauri.conf.json](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/tauri.conf.json)` dosyasındaki önemli paketleme ayarları şunlardır:

*   **`frontendDist`:** `"../frontend"` — Ekstra bir web bundler derlemesi (Webpack/Vite build) olmadığı için doğrudan statik HTML/JS klasörünü kaynak gösterir.
*   **`bundle -> targets`:** `"all"` — Windows üzerinde hem MSI hem de NSIS installer'larının üretilmesini sağlar.
*   **`security -> csp`:** Content Security Policy tanımları yer alır. WASM modülünün WebView içerisinde sorunsuz çalışabilmesi için `script-src 'self' 'unsafe-eval'` parametresi eklenmiştir.

---

## 5. Senior Sorun Giderme (Troubleshooting & Debugging)

### 5.1. Bağlama Hatası: `link.exe failed: LNK1181: cannot open input file 'wpcap.lib'`
*   **Nedeni:** Bağlayıcı (linker), derleme sırasında libpcap Windows kütüphanelerini bulamıyor.
*   **Çözümü:**
    1. `npcap-sdk/` dizininin proje kökünde mevcut olduğunu teyit edin.
    2. `.cargo/config.toml` dosyasında `rustflags` altında `-L native=npcap-sdk/Lib/x64` (veya ARM64 kullanılıyorsa ilgili yol) parametresinin ekli olduğundan emin olun.
    3. PowerShell ortamında geçici olarak kütüphane yolunu tanımlayın:
       ```powershell
       $env:LIBPCAP_LIBDIR = "C:\Users\efe\Desktop\netscope\npcap-sdk\Lib\x64"
       cargo build -p netscope-desktop --release
       ```

### 5.2. Hata: `TaskDialogIndirect` Sembolü Bulunamadı (`0xc0000139`)
*   **Nedeni:** Tauri dialog eklentisi (`tauri-plugin-dialog`), comctl32 kütüphanesinin v6 versiyonunu gerektirir. Eğer uygulamanın Windows Manifest dosyası bu bağımlılığı beyan etmiyorsa uygulama açılışta çöker.
*   **Çözümü:** `[build.rs](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/build.rs)` dosyasındaki manifest yönetimini kontrol edin. Testler ve binary derlemeleri için comctl32.manifest entegrasyonu otomatik olarak eklenmektedir. El ile manifest override yapmaktan kaçının.

### 5.3. Çalışma Zamanı Hatası: `Npcap is not installed`
*   **Nedeni:** Windows üzerinde Npcap sürücüsü kuruludur ancak uygulama arayüzü paket yakalamaya çalıştığında kütüphane yüklenemez.
*   **Çözümü:** Kullanıcıların sisteminde Npcap kurulurken "WinPcap API-compatible Mode" seçeneğinin aktif edildiğinden emin olun. Aksi halde `wpcap.dll` sistem yollarında bulunamaz. Alternatif olarak, Npcap kurulum paketini uygulamanızın yanında yan-yükleme (sidecar) olarak dağıtabilir ve ilk açılışta kurdurabilirsiniz.
