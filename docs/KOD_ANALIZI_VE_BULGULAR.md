# Netscope — Kıdemli Kod Analizi ve Bulgu Raporu

**Tarih:** 2026-08-01
**Kapsam:** `crates/core`, `crates/server`, `crates/agent`, `crates/tui`, `desktop/`
**Analiz edilen kod:** ~163.000 satır Rust + frontend
**Yöntem:** Statik okuma, dispatch/guard izleme, derleme + test + clippy + fmt kapılarının çalıştırılması, hedefli kod okuma
**Doğrulama durumu:** Aşağıdaki her bulgu kaynak kodda `dosya:satır` ile işaretlenmiştir. "Doğrulandı" etiketi, ilgili kodun bu oturumda okunduğu veya çalıştırıldığı anlamına gelir.

---

## 0. Yönetici Özeti

Netscope'un **protokol motoru olgun ve disiplinli** — 501 dissector, panik/ağ erişimi/kontrol karakteri sızıntısı gibi sınıfları mekanik olarak engelleyen güçlü bir `robustness` test paketi var. Kriptografik primitifler doğru seçilmiş (Argon2, minisign/Ed25519, TLS 1.3). Bu, kod tabanının güçlü tarafı.

**Ancak sunucu (`crates/server`) kimlik doğrulama katmanında sistemik bir yapılandırma hatası var.** Yönetimsel uç noktaların tamamı, kimlik doğrulama middleware'i uygulanmayan `public` router'a bağlanmış. Bunun sonucu tek bir HTTP isteğiyle tam yönetici yetkisi elde edilebilmesi.

Bu, kod kalitesi sorunu değil — **tek satırlık bir montaj hatasının** (routing) sağlam yazılmış güvenlik bileşenlerini tamamen devre dışı bırakmasıdır. Argon2 doğru, JWT doğru, hesap kilitleme doğru yazılmış; hepsi kimlik doğrulaması olmayan bir kapının arkasında duruyor.

### Bulgu dağılımı

| Seviye | Adet | Özet |
|---|---|---|
| 🔴 Kritik | 3 | Kimlik doğrulamasız yetki yükseltme, korumasız yönetim API'si, brute-force korumasının etkisizleştirilmesi |
| 🟠 Yüksek | 5 | IP kilitleme mantığı, IDOR, korumasız WebSocket, CORS, işlemez self-upgrade |
| 🟡 Orta | 5 | mTLS eksikliği, mutex poisoning DoS, erişilemez dissector'lar, kuralın mekanik zorlanmaması |
| 🔵 Düşük | 4 | Artık dosya, CI clippy kapsamı, bayat dokümantasyon, platform stub'ları |
| ⚪ Süreç | 2 | Eşzamanlı ajan, registry bozulma olayı |

### En kritik tek cümle

> `POST /api/v1/auth/register` gövdesine `"role": "admin"` yazan **kimliği doğrulanmamış** herhangi bir istemci, anında geçerli bir yönetici JWT'si alır.

---

## 1. 🔴 KRİTİK BULGULAR

### C-1 — Kimlik doğrulamasız yönetici hesabı oluşturma (yetki yükseltme)

**Konum:** `crates/server/src/api/auth_routes.rs:188-263`, montaj: `crates/server/src/api/mod.rs:46-52`
**Durum:** Doğrulandı (kod okundu, router montajı izlendi)

`register` uç noktası `public` router'a bağlı — yani `auth_middleware` uygulanmıyor. Rolü **istek gövdesinden** alıyor:

```rust
// auth_routes.rs:208-215
let role = if create.role.is_empty() { "viewer".into() } else { create.role.clone() };
if !["admin", "operator", "analyst", "viewer"].contains(&role.as_str()) {
    return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid role"}))).into_response();
}
```

Doğrulama listesi `"admin"` içeriyor. Kullanıcı oluşturulduktan sonra `auth_routes.rs:246` hemen o rol için JWT üretiyor ve `201 CREATED` ile döndürüyor.

**Sömürü:**
```bash
curl -X POST https://<sunucu>/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"x","email":"x@x","password":"x","role":"admin"}'
```
Yanıt: yönetici yetkili `token`.

**Etki:** Tam sistem devralma. Saldırgan bu token'la `protected` router'daki tüm uç noktalara (sensörler, kurallar, SOAR, raporlar, SIEM) yönetici olarak erişir.

**Neden gözden kaçmış:** Rol doğrulaması *var* ve doğru görünüyor — ama doğrulama "geçerli bir rol mü" sorusunu yanıtlıyor, "çağıran bu rolü vermeye yetkili mi" sorusunu değil.

**Düzeltme:**
1. `register`'ı `protected` router'a taşıyın ve `admin` izni isteyin; **veya** açık kayıt isteniyorsa rolü gövdeden almayı tamamen bırakıp sunucu tarafında sabit `"viewer"` atayın.
2. `create.role` alanını `CreateUser` DTO'sundan kaldırın — mevcut olmayan alan kötüye kullanılamaz.

---

### C-2 — Yönetim API'sinin tamamı kimlik doğrulamasız

**Konum:** `crates/server/src/api/mod.rs:46-52` (montaj), `crates/server/src/api/auth_routes.rs:36-55` (router)
**Durum:** Doğrulandı (`main.rs:161-180` dahil üst katmanlarda ek auth katmanı olmadığı teyit edildi)

`auth_routes::routes(...)` `public` router'a bağlanmış. `auth_middleware` yalnızca `protected` router'a uygulanıyor (`mod.rs:76`). `auth_routes` kendi içinde `jwt`'yi yalnızca **Extension** olarak ekliyor (`auth_routes.rs:54`) — bu `login`'in token üretebilmesi için; kimlik doğrulama katmanı değil.

Sonuç olarak aşağıdaki uç noktaların **hepsi** kimlik doğrulamasız:

| Uç nokta | Yetenek | Etki |
|---|---|---|
| `POST /auth/api-keys` | Rastgele izinlerle API anahtarı üretme | **Kalıcı yetkili erişim** |
| `GET /auth/api-keys` | Anahtar listeleme | Bilgi ifşası |
| `DELETE /auth/api-keys/{id}` | Herhangi bir anahtarı iptal | DoS |
| `GET /auth/sessions` | Oturum listeleme | Bilgi ifşası |
| `DELETE /auth/sessions/{id}` | Herhangi bir oturumu sonlandırma | DoS |
| `DELETE /auth/sessions/all/{user_id}` | Bir kullanıcının tüm oturumları | DoS |
| `POST /auth/force-reset/{user_id}` | **Herhangi bir kullanıcının şifresini sıfırlama** | Hesap devralma |
| `POST /auth/unlock/account/{username}` | Hesap kilidini açma | Brute-force koruması bypass |
| `POST /auth/unlock/ip/{ip}` | IP yasağını kaldırma | Brute-force koruması bypass |
| `GET /auth/lockout-events` | Kilitleme olayları | Bilgi ifşası |
| `POST /roles`, `DELETE /roles/{name}` | **RBAC rolü oluşturma/silme** | Yetkilendirme modelini yeniden yazma |
| `GET /permissions` | İzin şeması | Keşif |
| `GET /audit/chain`, `/audit/verify` | Denetim zinciri | Denetim kaydı ifşası |

API anahtarı üretiminde izinler doğrudan gövdeden geliyor (`auth_routes.rs:346`: `req.permissions`), yani saldırgan istediği izin kümesini kendisi seçiyor.

**Özellikle dikkat:** `unlock/account` ve `unlock/ip` uç noktaları, `login` içinde titizlikle uygulanmış hesap kilitleme mekanizmasını (`auth_routes.rs:64-87`) tamamen anlamsız kılıyor. Saldırgan brute-force yapar, kilitlenince kendi kilidini açar, devam eder.

**Düzeltme:**
`public` router'da yalnızca `login` ve (C-1 düzeltilirse) `register` kalmalı. Diğer 14 route `protected`'a taşınmalı ve her biri uygun izinle işaretlenmeli:

```rust
let public = Router::new()
    .nest("/api/v1", auth_routes::public_routes(api_state.clone(), jwt.clone()));

let protected = Router::new()
    .nest("/api/v1", auth_routes::admin_routes(api_state.clone()))
    // ... mevcut protected route'lar
    .layer(axum::middleware::from_fn(crate::auth::auth_middleware));
```

`mod.rs:54-61`'deki yorum, izinlerin route bazında verilmesi gerektiğini zaten doğru şekilde açıklıyor — bu route grubu o kurala hiç dahil edilmemiş.

**Regresyon testi önerisi:** Her route için kimlik doğrulamasız isteğin `401` döndüğünü iddia eden bir tablo testi. Bu sınıf hatanın tek mekanik savunması budur:

```rust
#[tokio::test]
async fn every_non_login_route_rejects_an_anonymous_request() {
    for (method, path) in ADMIN_ROUTES {
        let res = app.clone().oneshot(Request::builder()
            .method(method).uri(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{method} {path} anonim erişime açık");
    }
}
```

---

### C-3 — Brute-force korumasının iki yönlü etkisizliği

**Konum:** `crates/server/src/api/auth_routes.rs:62`
**Durum:** Doğrulandı

```rust
let client_ip = "127.0.0.1";
```

Gerçek istemci IP'si hiç okunmuyor (`ConnectInfo` veya `X-Forwarded-For` yok). Bu sabit değer `check_allowed`, `record_failure`, `record_success` ve `create_session`'a aktarılıyor (satır 65, 92, 119, 172).

Bu, C-2'deki korumasız `unlock` uç noktalarından **bağımsız** ikinci bir kırılma:

1. **IP bazlı kilitleme küresel hale geliyor.** Tüm başarısız denemeler tek bir "IP"ye yazılıyor. Eşik aşıldığında `check_allowed` **her istemci için** `IpBanned` döndürür → tek bir saldırgan, birkaç başarısız denemeyle **tüm kullanıcıları sisteme sokmayabilir**. Bu, kimlik doğrulamasız bir tam hizmet reddidir.
2. **Gerçek IP bazlı savunma hiç çalışmıyor.** Saldırganın adresi hiçbir zaman yasaklanmıyor.

Ayrıca oturum kayıtlarındaki kaynak IP alanı da sabit `127.0.0.1` — adli analiz değeri sıfır.

**Düzeltme:** `axum::extract::ConnectInfo<SocketAddr>` ile gerçek adresi alın; ters proxy arkasındaysa `X-Forwarded-For`'un yalnızca **güvenilen** proxy'den gelenini kabul edin (aksi halde saldırgan başlığı uydurup yasağı atlar).

---

## 2. 🟠 YÜKSEK ÖNCELİKLİ BULGULAR

### H-1 — IDOR: sahiplik kontrolü olmadan iptal

**Konum:** `auth_routes.rs:271, 281, 342, 363, 373`
**Durum:** Doğrulandı

Tüm oturum/anahtar işlemleri sahibi olarak `Uuid::nil()` kullanıyor:

```rust
let dummy_user_id = Uuid::nil();
let sessions = state.session_mgr.list_user_sessions(dummy_user_id);
```

İki ayrı sorun:

1. **Kiracı izolasyonu yok.** Tüm API anahtarları aynı nil kullanıcıya ait. Kod tabanında `multi_tenancy.rs` bulunmasına rağmen bu yol kiracı ayrımı yapmıyor.
2. **`revoke_session` ve `revoke_api_key` sahiplik doğrulaması yapmıyor** — ID'yi path'ten alıp doğrudan iptal ediyorlar. C-2 düzeltilip kimlik doğrulama eklense bile, herhangi bir kimliği doğrulanmış kullanıcı başkasının oturumunu/anahtarını iptal edebilir (yatay yetki yükseltme).

**Düzeltme:** Kullanıcı kimliğini `auth_middleware`'in eklediği `Claims` extension'ından alın (`auth.rs:236`'da zaten ekleniyor); iptal işlemlerinde kaydın sahibinin çağıranla eşleştiğini doğrulayın.

---

### H-2 — Kimlik doğrulamasız canlı olay akışı (WebSocket)

**Konum:** `crates/server/src/main.rs:163, 303-308`
**Durum:** Doğrulandı

```rust
.route("/ws/events", get(ws_handler))
```

`build_router` **dışında**, üst seviye router'a bağlı — dolayısıyla `auth_middleware` uygulanmıyor. Handler token okumuyor:

```rust
async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(ws_state): Extension<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws::handle_socket(socket, ws_state))
}
```

Bağlanabilen herkes canlı güvenlik olay akışını dinler. Bir NDR/SOC ürününde bu, tespit kabiliyetinin tamamının ifşasıdır (hangi tespitlerin ürediği, hangilerinin üremediği).

**Not:** `/` (dashboard) ve `/health` de aynı seviyede; dashboard'un statik HTML olması nedeniyle etkisi düşük, ancak `/health` bilgi ifşası açısından gözden geçirilmeli.

---

### H-3 — Tamamen serbest CORS politikası

**Konum:** `crates/server/src/main.rs:175-180`
**Durum:** Doğrulandı

```rust
CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(Any)
```

Kimlik doğrulama cookie değil Bearer token olduğu için klasik CSRF riski sınırlı; ancak **C-2 ile birleştiğinde ciddileşiyor**: kurbanın tarayıcısını ziyaret ettiği herhangi bir site, kurumsal ağdaki netscope sunucusuna kimlik doğrulamasız `POST /auth/api-keys` isteği atıp yanıtı okuyabilir (`allow_origin(Any)` yanıtın okunmasına izin verir). Bu, dış ağdan iç ağdaki sunucuya karşı sürücüsüz (drive-by) saldırı yolu açar.

**Düzeltme:** İzin verilen origin'leri yapılandırmadan alın; `Any` yerine açık liste kullanın.

---

### H-4 — Ajan self-upgrade yolu pratikte işlemez

**Konum:** `crates/agent/src/upgrade.rs:200-231`, `.github/workflows/release.yml`
**Durum:** Doğrulandı (workflow'da minisign imzalama adımı aranıp bulunamadı)

Doğrulama kodu **örnek gösterilecek kalitede** — her başarısızlık yolu reddediyor, anahtar derleme zamanında gömülü, gerekçesi yorumda açıklanmış. Sorun kodda değil, çevresinde:

1. **Release pipeline'ında minisign imzalama adımı yok.** `release.yml` yalnızca Authenticode (satır 96) ve Apple imzalama içeriyor. Sunucu imzasız binary sunacağı için `upgrade.rs:219` her zaman reddedecek → **self-upgrade hiçbir zaman tamamlanamaz.**
2. **Pozitif test yok.** Mevcut 4 test (satır 276, 289, 304, 310) yalnızca *reddetme* yollarını kapsıyor. `verify` çağrısı bozulsa ve her şeyi reddetse test paketi yine yeşil kalır. Geçerli imzanın doğrulandığını kanıtlayan bir test yok.

**Not:** `docs/TODO.md` §5.1 "Ed25519 altyapısını kurun" diyor — minisign zaten Ed25519 kullanıyor, yani bu madde kısmen bayat. Gerçek eksik: **CI imzalama adımı + pozitif fixture**.

**Düzeltme:** Release'de `minisign -S` adımı ekleyin, `.sig` dosyasını artifact olarak yayınlayın; testlere sabit bir test anahtar çiftiyle üretilmiş geçerli imza fixture'ı ekleyin.

---

### H-5 — mTLS ajan tarafında hiç yok

**Konum:** `crates/agent/src/ws_client.rs:138`, `crates/server/src/tls.rs:26-36`
**Durum:** Doğrulandı

Sunucu mTLS'i destekliyor (`WebPkiClientVerifier`, `tls.rs:26`) ama `with_no_client_auth()` yedeği var (satır 36). Ajan tarafında ise:

```rust
// ws_client.rs:138
.with_no_client_auth();
```

Ajan istemci sertifikası **hiç sunmuyor**. Dolayısıyla sunucu mTLS'i zorunlu kılarsa ajanlar bağlanamaz; zorunlu kılmazsa ajan kimliği yalnızca uygulama katmanı token'ına dayanır. `docs/TODO.md` §5.2 bu boşluğu doğru tespit etmiş.

---

## 3. 🟡 ORTA ÖNCELİKLİ BULGULAR

### M-1 — Mutex poisoning ile kalıcı DoS

**Konum:** `crates/server/src/api/assets.rs:42, 49, 62, 73, 87`

```rust
let registry = global_asset_registry().lock().unwrap();
```

Global bir mutex istek işleyicilerinde `unwrap()` ile kilitleniyor. Kilidi tutan bir iş parçacığı herhangi bir nedenle panic ederse mutex **zehirlenir** ve sonraki her `lock().unwrap()` panic eder — yani `/api/v1/assets` uç noktaları **sunucu yeniden başlatılana kadar kalıcı olarak** çöker. Axum panic'i o isteğe hapseder, ancak zehirlenme kalıcıdır.

**Düzeltme:** `lock().unwrap_or_else(|e| e.into_inner())` ile zehirlenmeden kurtulun veya `parking_lot::Mutex` kullanın (zehirlenme kavramı yoktur).

### M-2 — 140 dissector modülü hiçbir dispatch yolundan erişilemiyor

**Konum:** `crates/core/src/dissectors.rs` — `every_dissector_module_is_reachable`
**Durum:** Bu oturumda ölçüldü ve dürüst hale getirildi (commit `9ddab16`)

Bu modüller derleniyor, kendi testleri geçiyor, ama hiçbir paket onlara ulaşamıyor. Çoğu **tanıma imzasına sahip değil** — sabit offset okuyup doğrulama yapmıyorlar (`nccl_allreduce` herhangi bir 32 baytlık payload'ı kabul ediyor). Bu yüzden port uydurarak bağlanamazlar; bağlanırlarsa alakasız trafiği etiketlerler.

Bu oturumda ilgili 128 registry satırı `Declared`'a çekildi, böylece kullanıcı arayüzü artık bunları reklam etmiyor (Dissected 589 → 461). Kalan iş: capture/spec temini.

### M-3 — Ephemeral port kuralı mekanik olarak zorlanmıyor

**Konum:** `crates/core/src/dissectors/tcp.rs:577-586`

`bindings.rs` başlığında net bir kural var: ephemeral aralıktaki (32768–60999) bir port yalnızca içerik guard'ı ile birlikte bir akışı sahiplenebilir. Ancak bunu koruyan test yalnızca **üç sabit portu** deniyor:

```rust
for port in [51000u16, 51001, 51002] {
```

Bunlar geçmişteki olayın portları — yani test bir **regresyon testi**, bir **değişmez (invariant) kontrolü** değil. Yeni bir ephemeral binding eklense yakalanmaz.

Mevcut tablo temiz (44818, 47808, 51820, 64738 — hepsi kayıtlı atama), yani şu an aktif bir hata yok; risk gelecekteki eklemelerde.

**Düzeltme:** Tabloyu tarayıp ≥32768 olan her portun ya kayıtlı beyaz listede ya da içerik guard'lı olduğunu iddia eden bir test.

### M-4 — Kapsamlı panik taraması CI'da çalışmıyor

**Konum:** `dissectors.rs:4741-4751`

`every_port_never_panics_on_malformed_input` (65.536 port × bozuk payload) `#[ignore]` — gerekçesi meşru (~5 dakika) ve talep üzerine çalıştırma komutu belgelenmiş. Ancak CI'da hiç çalışmadığı için, dar kapsamlı sürümün kaçırdığı bir panik regresyonu fark edilmez. Nightly bir işte çalıştırılması önerilir.

### M-5 — Unix güvenlik duvarı backend'leri stub

**Konum:** `crates/core/src/firewall.rs:130-155`

IP engelleme yalnızca Windows'ta (`netsh`) çalışıyor; `#[cfg(not(windows))]` bloğu stub. Linux/macOS'ta "engelle" eylemi sessizce hiçbir şey yapmıyor olabilir — bir SOC ürününde tehlikeli bir yanlış güven kaynağı. `docs/TODO.md` §3.1 doğru tespit etmiş (nftables/pfctl).

**Kontrol edilmeli:** `is_supported()` bu platformlarda `false` dönüyor mu; arayüz "engellendi" demeden önce bunu kontrol ediyor mu.

---

## 4. 🔵 DÜŞÜK / KOD SAĞLIĞI

| # | Bulgu | Konum | Not |
|---|---|---|---|
| L-1 | Artık yedek dosya | `crates/core/src/dissectors.rs.bak` | `.gitignore`'da (`*.bak`), depoya girmiyor; yine de kafa karıştırıcı — eski `looks_like_modbus_ascii` stub'ını içeriyor |
| L-2 | CI clippy `--all-targets` kullanmıyor | `.github/workflows/ci.yml:64` | Test kodundaki uyarılar (ör. `multi_tenancy.rs:147,167`) CI'da görünmüyor |
| L-3 | `docs/TODO.md` kısmen bayat | §5.1 | "Ed25519 kurun" diyor; minisign zaten Ed25519. Gerçek eksik CI imzalama adımı (bkz. H-4) |
| L-4 | `// RPC — dissector module unavailable.` | `dissectors.rs:4725` | Robustness taramasında atlanan bir yol |

**Olumlu not:** Kod tabanında **sıfır** `TODO`/`FIXME`/`HACK`/`unimplemented!` işareti var ve SQL sorguları `sqlx` ile parametrelendirilmiş (enjeksiyon riski görülmedi). Bu, ortalamanın belirgin üzerinde bir disiplin.

---

## 5. ⚪ SÜREÇ RİSKLERİ

### P-1 — Depoda eşzamanlı çalışan ikinci bir ajan

Bu analiz sırasında gözlendi: zamanlanmış bir ajan aynı çalışma ağacında dosya düzenliyor, commit'liyor ve `origin/main`'e push'luyor. Bu oturumda `crates/core/src/registry.rs`'i **commit edilmemiş haldeyken HEAD'e geri aldı** (devam eden bir onarım kayboldu) ve `dissectors.rs`'i eşzamanlı düzenledi.

**Risk:** İnsan veya ajan kaynaklı commit edilmemiş çalışma habersiz kaybolabilir ya da başkasının commit'ine karışıp push edilebilir.
**Öneri:** Uzun süren düzenlemeleri sık commit'leyin; commit öncesi `git log -1` + `git status` tekrar okuyun; `git add -A` yerine açık pathspec kullanın.

### P-2 — `registry.rs` bozulma olayı (bu oturumda onarıldı, sonra dışarıdan geri alındı)

1.893 `Declared` protokolü silen toplu bir düzenleme, hayatta kalan **171 satırı** `\u{2014}` kaçış dizisinde kesmişti — kapanış tırnağı, virgül ve bloğun `}`'i kaybolmuştu (349 derleme hatası). Ayrıca 14 artık `u {2019}` satırı bırakmıştı.

**Ders:** Registry gibi makine üretimi büyük tabloları düzenleyen betikler, Unicode kaçış dizilerini metin sınırı sanabiliyor. Böyle bir toplu düzenlemeden sonra **mutlaka** derleme çalıştırılmalı; testler değil, derleyici bu sınıfı ilk yakalayan araçtır.

---

## 6. Doğru Yapılmış Olanlar

Dengeli bir değerlendirme için — bu kod tabanının güçlü yanları gerçek ve dikkat çekici:

- **`robustness` test modülü** (`dissectors.rs:2792+`) örnek niteliğinde. Yalnızca davranış değil, **kod özelliklerini** test ediyor: hiçbir dissector paylaşılan satır okuyucusunu yeniden yazamaz, hiçbir özet kontrol karakteri sızdıramaz, **hiçbir dissector ağa çıkamaz** (`no_dissector_reaches_out_to_the_network`). Bu son test, bu ölçekte nadiren görülür.
- **Şifre saklama:** Argon2, rastgele tuz (`auth.rs:93-102`).
- **JWT:** `saturating_add`/`saturating_mul` ile taşma korunmuş, gerekçesi yorumda yazılmış (`auth.rs:67-72`).
- **Güncelleme doğrulama:** Her yol reddediyor, anahtar derleme zamanında gömülü, tehdit modeli yorumda açıklanmış (`upgrade.rs:22-31`). Anahtarın neden dosyadan okunmadığı gerekçesi özellikle iyi.
- **Registry tek kaynak:** Filtre, renk, akış sınıfı ve eğitim içeriği tek tablo satırından türetiliyor; sürüklenmeyi testler engelliyor.
- **Dispatch önceliği** belgelenmiş ve sıralı tablolarla binary search — 600 satırlık `if` zincirinden anlamlı bir iyileştirme.
- **Yorum kalitesi:** Kod "ne" yaptığını değil **"neden"** yaptığını anlatıyor; birçok yorum geçmiş bir hatayı ve alınan dersi kaydediyor.

---

## 7. Önerilen Aksiyon Sırası

| Sıra | Bulgu | İş | Gerekçe |
|---|---|---|---|
| 1 | C-1, C-2 | `auth_routes`'u ikiye bölüp yönetim route'larını `protected`'a taşı; `register`'dan rol alanını kaldır | Tek değişiklik, en büyük risk azalması |
| 2 | — | Anonim isteğin `401` aldığını iddia eden tablo testi | Bu sınıfın tekrarını mekanik olarak engeller |
| 3 | C-3 | `ConnectInfo` ile gerçek istemci IP'si | Kilitleme mantığını çalışır hale getirir, DoS'u kapatır |
| 4 | H-1 | `Claims`'ten kullanıcı kimliği + sahiplik kontrolü | IDOR'u kapatır |
| 5 | H-2, H-3 | WS kimlik doğrulaması + CORS origin listesi | Kalan anonim yüzeyi kapatır |
| 6 | H-4 | Release'e minisign adımı + pozitif test | Self-upgrade'i çalışır hale getirir |
| 7 | M-1 | Mutex zehirlenmesinden kurtarma | Kalıcı DoS'u kapatır |
| 8 | M-3, M-4 | Ephemeral kural değişmez testi; nightly panik taraması | Regresyon savunması |

**1–5 arası maddeler aynı gün içinde kapatılabilir.** Hepsi routing ve bağlam aktarımı düzeyinde; kriptografi veya veri modeli değişikliği gerektirmiyor.

---

## 8. Kapsam ve Sınırlar (dürüstlük notu)

Bu raporun sınırlarını açıkça belirtmek gerekir:

- **Çalıştırılarak sömürü denenmedi.** Sunucu ayağa kaldırılıp gerçek istek atılmadı; bulgular kaynak kodun okunması ve router montajının izlenmesiyle çıkarıldı. C-1 ve C-2 için kod yolu baştan sona takip edildi (route tanımı → router montajı → `main.rs` üst katman), ancak **çalışan bir örnekte doğrulanması önerilir.**
- **Dağıtım katmanı değerlendirilmedi.** Sunucu bir API gateway veya ters proxy arkasında, kimlik doğrulaması dışarıda yapılacak şekilde konumlandırılıyorsa C-1/C-2'nin pratik etkisi azalır. Kodun kendisi böyle bir varsayım belgelemiyor; savunma derinliği açısından yine de düzeltilmeli.
- **`crates/tui` ve `crates/wasm`** yüzeysel tarandı; derinlemesine incelenmedi.
- **Bağımlılık güvenlik taraması yapılmadı** (`cargo audit` çalıştırılmadı) — ayrı bir tur olarak önerilir.
- **Linux/macOS yolları bu makinede doğrulanamadı**; cross-compile mevcut değil, yalnızca CI'da test edilebilir.

---

## Ek: Bu Oturumda Zaten Düzeltilenler

| Commit | İş |
|---|---|
| `35dba4b` | Masaüstü yönetici yetkisiyle yeniden başlatma: temiz kapanış (`app.exit`), UAC reddi doğru algılanıyor (`-ErrorAction Stop`), her açılışta soran davranış kaldırıldı |
| `5f22f44` | Erişilebilirlik guard'ının susturulması geri alındı; NVMe/TCP dürüstçe bağlandı (kayıtlı port 4420) ve header ayrıştırması düzeltildi (PLEN little-endian) |
| `9ddab16` | Registry dürüstlüğü: erişilemez modüller artık "üretiyor" sayılmıyor; 128 satır `Declared`'a çekildi |
