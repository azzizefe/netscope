# netscope — Release Süreci

## Genel Bakış

Release pipeline'ı `.github/workflows/release.yml` tarafından yönetilir. `v*` tag'i push'landığında otomatik tetiklenir.

**Çıktılar:**
- TUI binary: 5 hedef (x86_64 Linux, aarch64 Linux, aarch64 macOS, x86_64 Windows, aarch64 Windows)
- Desktop installer: NSIS + MSI (Windows), DMG (macOS), DEB + AppImage (Linux)
- GitHub Release (changelog ile)

## Adım Adım

### 1. Versiyon Belirle

```
v<major>.<minor>.<patch>
```

Semver takip edilir. `CHANGELOG.md`'ye bakarak son değişikliklere göre karar ver:

| Değişiklik | Örnek |
|---|---|
| Geriye uyumsuz API değişikliği | `v0.3.0` → `v1.0.0` |
| Yeni özellik | `v0.2.0` → `v0.3.0` |
| Hata düzeltmesi | `v0.2.0` → `v0.2.1` |

### 2. CHANGELOG Güncelle

`CHANGELOG.md`'ye yeni sürümü ekle. Format:

```markdown
## [v0.3.0] - 2026-08-01

### Added
- USB packet capture support
- TLS 1.3 key log visualization

### Fixed
- DNS dissector buffer overflow on malformed queries

### Changed
- Upgrade to ratatui 0.28
```

### 3. Versiyon Numaralarını Güncelle

```bash
# Cargo.toml workspace versiyonu
# (desktop için: desktop/src-tauri/Cargo.toml)

# desktop/src-tauri/tauri.conf.json içindeki "version" alanı
#   release.yml build sırasında tag'den otomatik alır -> elle güncelleme gerekmez
```

### 4. Tag Oluştur ve Push'la

```bash
git add CHANGELOG.md
git commit -m "chore: bump version to v0.3.0"
git tag -a v0.3.0 -m "v0.3.0"
git push origin main --tags
```

### 5. CI'ı İzle

GitHub Actions → `Release` workflow'u:
- **TUI job**: 5 hedefte binary build + Authenticode sign (Windows)
- **Desktop job**: 3 platformda installer build + code sign
- **Release job**: artifact'leri topla, GitHub Release oluştur

İşlem ~30-60 dakika sürer.

### 6. Release'i Doğrula

- [ ] TUI binary'leri GitHub Release sayfasında görünüyor
- [ ] Desktop installer'lar (.msi, .dmg, .deb, .AppImage) mevcut
- [ ] Windows installer imzalı (sağ tık → Özellikler → Dijital İmzalar)
- [ ] Release notları doğru

### 7. Vercel Webhook (Otomatik)

Release oluşturulunca Vercel deploy hook'u tetiklenir → `/download` sayfası güncellenir.

## Elle Yapılması Gerekenler

| Adım | Otomasyon |
|---|---|
| Versiyon bump | Elle (`Cargo.toml`) |
| CHANGELOG güncelleme | Elle |
| Tag oluşturma | Elle (`git tag`) |
| Binary build | CI (release.yml) |
| Installer build | CI (release.yml) |
| Code signing | CI (opt-in secrets) |
| GitHub Release | CI (softprops/action-gh-release) |
| Vercel rebuild | CI (deploy hook) |
| macOS notarization | **Henüz otomatik değil** (manuel) |

## Ön Koşullar

- **Npcap SDK**: CI Windows runner'ına otomatik indirilir
- **libpcap-dev**: CI Linux runner'ında `apt-get` ile kurulur
- **Code signing sertifikası**: `WINDOWS_CERTIFICATE` + `WINDOWS_CERTIFICATE_PASSWORD` repo secret'larında
- **wasm-bindgen-cli**: CI'da `cargo install` ile kurulur (sürüm: Cargo.lock ile sabitlenmiş)
