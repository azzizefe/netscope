# 👥 netscope — Ekip Kullanımı / Çok Kullanıcılı Sistem / RBAC / Audit Log

> **Mevcut durum:** `api_server.rs` + `db.rs` ile temel 3 rollü (Admin/Analyst/Viewer)
> RBAC, Bearer token auth, ve SQLite audit log zaten var. Ancak bunlar **tek
> makinede local kullanım** için tasarlanmış — enterprise ekip kullanımı için
> değil.
>
> Bu spesifikasyon, mevcut altyapıyı **sıfırdan yazmadan** enterprise seviyeye
> çıkarmak için gereken her şeyi listeler. Her checkbox mevcut kodun üzerine
> inşa eder, var olanı bozmaz.

---

## 📐 Mevcut Durum Analizi

```
✅ VAR olanlar:
  - User model (username, password_hash, role)
  - Argon2id password hashing
  - Bearer token auth (random 32-char hex)
  - 3 rol: Admin, Analyst, Viewer
  - RBAC middleware (method + path bazlı kaba kontrol)
  - SQLite audit_log tablosu (username, action, capture_file, timestamp)
  - In-memory session HashMap
  - İlk çalıştırmada random password seed

❌ EKSİK olanlar (bu dokümanda ele alınacak):
  - Kullanıcı yönetimi (CRUD) API'si
  - Granüler permission sistemi (rol başına 50+ permission)
  - Custom rol tanımlama
  - Session persistence + expiry + revocation
  - MFA (TOTP, WebAuthn)
  - SSO (SAML, OIDC)
  - API key (servis hesabı için)
  - Ekip/group kavramı
  - Paylaşımlı workspace
  - Gerçek zamanlı collaboration
  - Audit log zenginleştirme (IP, user-agent, old/new values)
  - Audit log tamper-proof (hash chain)
  - Hesap kilitleme (brute-force koruması)
  - Password policy
  - Rate limiting
  - Remote access (mTLS ile)
```

---

## 🔐 Faz 1 — Kimlik Doğrulama (Authentication)

> Mevcut: Bearer token + Argon2id. Sağlam ama minimalist.

### 1.1 — Token & Session Yönetimi

- [ ] **1.1.1** **Session persistence** — session'ları SQLite yerine server PostgreSQL/Redis'te tut, restart'ta kaybolmasın
  ```sql
  CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY,  -- SHA-256(token) — raw token asla DB'ye yazılmaz
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN DEFAULT FALSE,
      ip_address TEXT,
      user_agent TEXT,
      last_activity TIMESTAMPTZ DEFAULT NOW()
  );
  ```
- [ ] **1.1.2** **Token expiry** — access token 24 saat, opsiyonel refresh token 7 gün
- [ ] **1.1.3** **Sliding expiration** — her API call'da `last_activity` yenilensin, idle timeout 30 dk sonra expire
- [ ] **1.1.4** **Concurrent session limit** — aynı kullanıcı max 5 aktif session (Admin ayarlayabilsin)
- [ ] **1.1.5** **Session revocation** — Admin tüm session'ları veya tek bir session'ı sonlandırabilsin (`DELETE /api/v1/sessions/:id`)
- [ ] **1.1.6** **Force password reset** — Admin bir kullanıcının tüm session'larını sonlandırıp "sonraki login'de şifre değiştir" flag'i koyabilsin
- [ ] **1.1.7** **"Remember me"** — tarayıcı kapansa da 30 gün geçerli persistent token (HttpOnly, Secure, SameSite=Strict cookie)
- [ ] **1.1.8** **Token rotation** — refresh token her kullanıldığında yenisiyle değiştirilsin (refresh token reuse detection → tüm session'ları revoke et)
- [ ] **1.1.9** **JWT formatına geçiş** — mevcut random hex token yerine RS256/Ed25519 signed JWT:
  ```json
  {
    "sub": "user_abc123",
    "role": "soc_analyst_l2",
    "perms": ["alert:read", "alert:ack", "pcap:read", "report:read"],
    "tenant": "tenant_01",
    "iat": 1700000000,
    "exp": 1700086400,
    "iss": "netscope-server",
    "jti": "unique-token-id-for-revocation"
  }
  ```
- [ ] **1.1.10** **Token introspection endpoint** — `GET /api/v1/auth/introspect` → token geçerli mi, hangi kullanıcı, permission'ları ne (RFC 7662 uyumlu)

### 1.2 — Brute-Force Koruması

- [ ] **1.2.1** **Account lockout** — 5 başarısız deneme → 15 dakika kilit (configurable: Admin panelden)
- [ ] **1.2.2** **IP-based rate limit** — aynı IP'den 10 başarısız deneme → 30 dakika IP ban
- [ ] **1.2.3** **Progressive delay** — her başarısız denemede `2^n * 100ms` delay (1. deneme 200ms, 5. deneme 3.2sn)
- [ ] **1.2.4** **Global rate limit** — `/api/v1/auth/login` endpoint'i max 30 istek/dakika/IP
- [ ] **1.2.5** **Audit log for lockouts** — her hesap kilitleme ve IP ban audit'e kaydedilsin
- [ ] **1.2.6** **Unlock flow** — Admin manuel unlock yapabilsin (`POST /api/v1/users/:id/unlock`), veya süre dolunca otomatik açılsın

### 1.3 — Multi-Factor Authentication (MFA)

- [ ] **1.3.1** **TOTP (Time-based One-Time Password)** — RFC 6238, Google Authenticator / Authy / 1Password uyumlu
  - [ ] Setup: `POST /api/v1/auth/mfa/setup` → QR code URL (otpauth://)
  - [ ] Verify: `POST /api/v1/auth/mfa/verify` → setup tamamla
  - [ ] Login: normal login'den sonra TOTP kodu sor (2-step)
- [ ] **1.3.2** **Recovery codes** — MFA setup sırasında 8 adet tek kullanımlık recovery code üret
- [ ] **1.3.3** **WebAuthn (FIDO2)** — YubiKey, Windows Hello, Apple Touch ID desteği
  - [ ] Registration: `POST /api/v1/auth/webauthn/register/begin` → challenge → `.../complete`
  - [ ] Authentication: `POST /api/v1/auth/webauthn/auth/begin` → challenge → `.../complete`
- [ ] **1.3.4** **MFA enforcement policy** — rol başına MFA zorunlu/opsiyonel:
  - Admin: zorunlu (TOTP veya WebAuthn)
  - SOC Manager: zorunlu
  - SOC Analyst L2: zorunlu
  - SOC Analyst L1: opsiyonel (ama önerilen)
  - Viewer: opsiyonel
- [ ] **1.3.5** **Remember MFA device** — güvenilir cihazda 30 gün MFA sorma (cookie tabanlı)
- [ ] **1.3.6** **MFA bypass audit** — her MFA bypass (recovery code kullanımı) kritik audit event'i olarak log'lansın

### 1.4 — Single Sign-On (SSO)

- [ ] **1.4.1** **OIDC (OpenID Connect)** — Azure AD / Entra ID, Okta, Keycloak, Google Workspace
  - [ ] Discovery: `.well-known/openid-configuration` auto-fetch
  - [ ] Authorization Code Flow + PKCE (S256)
  - [ ] ID token validation (iss, aud, exp, nonce)
  - [ ] UserInfo endpoint'ten grup/rol mapping
  - [ ] Claim mapping config: `"groups": "netscope_soc_l2"` → `role: soc_analyst_l2`
- [ ] **1.4.2** **SAML 2.0** — ADFS, PingFederate, Shibboleth
  - [ ] SP metadata endpoint: `/api/v1/auth/saml/metadata.xml`
  - [ ] IdP metadata upload (XML) veya URL'den fetch
  - [ ] Attribute mapping: `MemberOf` → rol
  - [ ] Signed AuthnRequest, encrypted assertion desteği
- [ ] **1.4.3** **Just-in-Time (JIT) provisioning** — SSO ile ilk kez gelen kullanıcı otomatik oluşturulsun, default role atansın
- [ ] **1.4.4** **Mixed auth mode** — aynı server'da hem local kullanıcı (admin hesabı) hem SSO kullanıcıları çalışabilsin
- [ ] **1.4.5** **IdP fail-open / fail-closed policy** — IdP'ye ulaşılamazsa local fallback veya tamamen reddet (configurable)

### 1.5 — API Key (Servis Hesapları)

- [ ] **1.5.1** **API key generation** — `POST /api/v1/apikeys` → `nsk_` prefix'li, 32-byte random, SHA-256 hash'i DB'de
  ```json
  {
    "name": "SIEM Forwarder - Elasticsearch",
    "permissions": ["event:push", "stats:read"],
    "expires_at": "2027-01-01T00:00:00Z",
    "allowed_ips": ["10.0.1.0/24", "172.16.0.5/32"]
  }
  ```
- [ ] **1.5.2** **API key auth** — `Authorization: ApiKey nsk_abc123...` header'ı
- [ ] **1.5.3** **Scoped API keys** — sensör agent için sadece `events:push` + `heartbeat:write`, SIEM connector için `events:read`, dashboard için `stats:read`
- [ ] **1.5.4** **API key rotation** — eski key 24 saat grace period ile çalışmaya devam etsin, sonra otomatik expire
- [ ] **1.5.5** **API key usage log** — her API key kullanımı audit log'a `apikey_id` ile kaydedilsin
- [ ] **1.5.6** **Last used tracking** — her API key'in son kullanım tarihi ve IP'si görüntülensin

---

## 🎭 Faz 2 — Rol Tabanlı Erişim Kontrolü (RBAC)

> Mevcut: 3 sabit rol (Admin/Analyst/Viewer), method+path bazlı kaba kontrol.
> Hedef: Granüler permission seti, custom roller, resource-level erişim.

### 2.1 — Permission Sistemi

- [ ] **2.1.1** Her bir aksiyon için atomik permission string'i:
  ```
  Format: <resource>:<action>
  Örnekler:
    users:read, users:create, users:update, users:delete
    roles:read, roles:create, roles:update, roles:delete
    alerts:read, alerts:ack, alerts:close, alerts:escalate
    events:read, events:push, events:export
    sensors:read, sensors:command, sensors:config_write
    capture:start, capture:stop, capture:filter_write
    pcap:read, pcap:download, pcap:delete
    rules:read, rules:create, rules:update, rules:delete, rules:enable
    reports:read, reports:create, reports:schedule, reports:export_pdf
    audit:read, audit:export
    dashboard:read, dashboard:configure
    playbooks:read, playbooks:create, playbooks:execute
    threat_intel:read, threat_intel:manage
    api_keys:read, api_keys:create, api_keys:revoke
    system:health, system:config, system:backup, system:restore
    notifications:read, notifications:configure
    annotations:read, annotations:create, annotations:delete
    bookmarks:read, bookmarks:create, bookmarks:delete
    comments:read, comments:create, comments:delete
    cases:read, cases:create, cases:update, cases:close
  ```
- [ ] **2.1.2** Permission set'leri (**role template** olarak):
  ```yaml
  # Toplam 50+ atomik permission, 7 hazır rol

  soc_viewer:
    - dashboard:read
    - alerts:read
    - events:read
    - pcap:read
    - annotations:read
    - bookmarks:read
    - comments:read
    - reports:read

  soc_analyst_l1:
    inherits: [soc_viewer]
    adds:
      - alerts:ack
      - cases:create
      - annotations:create
      - bookmarks:create
      - comments:create
      - events:export
      - pcap:download

  soc_analyst_l2:
    inherits: [soc_analyst_l1]
    adds:
      - alerts:close
      - alerts:escalate
      - cases:update
      - cases:close
      - rules:read
      - rules:create
      - playbooks:read
      - playbooks:execute
      - threat_intel:read
      - annotations:delete
      - reports:create

  soc_manager:
    inherits: [soc_analyst_l2]
    adds:
      - users:read
      - roles:read
      - rules:update
      - rules:delete
      - rules:enable
      - reports:schedule
      - reports:export_pdf
      - notifications:configure
      - dashboard:configure
      - sensors:read

  admin:
    inherits: [soc_manager]
    adds:
      - users:create
      - users:update
      - users:delete
      - roles:create
      - roles:update
      - roles:delete
      - sensors:command
      - sensors:config_write
      - capture:start
      - capture:stop
      - capture:filter_write
      - playbooks:create
      - threat_intel:manage
      - system:health
      - system:config
      - system:backup
      - system:restore
      - audit:read
      - audit:export

  auditor:
    - audit:read
    - audit:export
    - reports:read
    - reports:export_pdf
    - users:read
    - alerts:read
    - events:read

  api_sensor_agent:
    - events:push
    - heartbeat:write
    - sensors:read  # sadece kendi sensor_id'si için
  ```

  > Built-in roller **silinemez** ama permission'ları Admin tarafından
  > değiştirilebilir. Her değişiklik audit log'a yazılır.

- [ ] **2.1.3** **Custom rol oluşturma** — Admin yeni rol tanımlayabilsin:
  - [ ] `POST /api/v1/roles` — `{name, description, permissions: [...], inherits: [...]}`
  - [ ] `PUT /api/v1/roles/:id` — permission set'ini güncelle
  - [ ] `DELETE /api/v1/roles/:id` — built-in olmayan rolü sil (kullanıcı atanmışsa uyar)
- [ ] **2.1.4** **Permission inheritance** — rol A, rol B'den inherit edebilsin, zincirleme (max 3 seviye)
- [ ] **2.1.5** **Permission conflict resolution** — aynı kullanıcıya birden fazla rol atanmışsa **union** (en geniş izin seti)
- [ ] **2.1.6** **Permission deny override** — Admin spesifik bir permission'ı `-alerts:delete` olarak kaldırabilsin (allow list'ten çıkarma)

### 2.2 — Resource-Level Erişim (Row-Level Security)

- [ ] **2.2.1** **Sensor scope** — bir kullanıcı sadece belirli sensörleri görebilsin:
  ```
  Kullanıcı → Rol → Permission "sensors:read"
  ama scope: sensor_group = ["DC-Istanbul", "DC-Ankara"]
  → Sadece bu group'taki sensörler görünür
  ```
- [ ] **2.2.2** **Alert severity scope** — L1 analist sadece `high` ve altı alert'leri görsün, `critical` sadece L2+
- [ ] **2.2.3** **Tenant isolation** — multi-tenant deployment'da her tenant'ın verisi tamamen izole (tenant_id her tabloda)
- [ ] **2.2.4** **Data classification tag** — event/pcap üzerinde `classification: public | internal | confidential | restricted`, role'un maksimum görebileceği seviye tanımlı

### 2.3 — Permission Kontrol Noktaları

- [ ] **2.3.1** **API middleware** — her endpoint `#[require(perms = ["alerts:read"])]` attribute/macro'su ile korunsun
- [ ] **2.3.2** **WebSocket permission check** — WS bağlantısı açılırken token validation + permission kontrolü
- [ ] **2.3.3** **Frontend permission gating** — UI'da yetkisiz butonlar gri/gizli (ama backend asıl yetkili — frontend sadece UX)
- [ ] **2.3.4** **Export permission check** — rapor/pcap/event export ederken permission + scope kontrolü
- [ ] **2.3.5** **Permission cache** — Redis'te 5 dakika TTL ile permission cache (her istekte DB sorgulama)
- [ ] **2.3.6** **Permission change propagation** — rol değişince Redis cache invalidate + aktif session'lara JWT'ye yeni permission'ları claim olarak ekle (veya session expire ettir)

---

## 🏢 Faz 3 — Kullanıcı & Ekip Yönetimi

### 3.1 — Kullanıcı Yönetimi (CRUD)

- [ ] **3.1.1** **Kullanıcı listesi** — `GET /api/v1/users?role=&status=&search=&page=&per_page=`
  ```json
  {
    "users": [
      {
        "id": "u_abc123",
        "username": "efe.akkaya",
        "display_name": "Efe Akkaya",
        "email": "efe@company.com",
        "role": "soc_analyst_l2",
        "roles": ["soc_analyst_l2", "incident_responder"],
        "status": "active",
        "mfa_enabled": true,
        "last_login": "2026-07-27T09:15:00Z",
        "created_at": "2026-01-15T00:00:00Z"
      }
    ]
  }
  ```
- [ ] **3.1.2** **Kullanıcı oluşturma** — `POST /api/v1/users` → email'e "hoş geldin + şifre belirle" linki gönder
- [ ] **3.1.3** **Kullanıcı güncelleme** — `PUT /api/v1/users/:id` → rol, display_name, email, status
- [ ] **3.1.4** **Kullanıcı deaktivasyon** — soft delete, `status: disabled` — audit log'lar korunur, session'lar sonlandırılır
- [ ] **3.1.5** **Kullanıcı silme (GDPR)** — `DELETE /api/v1/users/:id` → tüm PII silinir, audit log'lar anonimleştirilir (`user_deleted_20260727_001`)
- [ ] **3.1.6** **Self-servis profil** — `GET/PUT /api/v1/users/me` → kendi profilini görüntüle, display_name ve email güncelle
- [ ] **3.1.7** **Şifre değiştirme** — `POST /api/v1/users/me/change-password` → eski şifre + yeni şifre
- [ ] **3.1.8** **Şifre sıfırlama akışı** — `POST /api/v1/auth/forgot-password` → email'e token linki → `POST /api/v1/auth/reset-password`
- [ ] **3.1.9** **Email verification** — yeni kullanıcı email verify etmeden login olamasın (opsiyonel, configurable)

### 3.2 — Şifre Politikası (Password Policy)

- [ ] **3.2.1** **Minimum gereksinimler** (configurable):
  - Min 12 karakter (NIST 2024 önerisi)
  - Max 128 karakter
  - En az 1 büyük harf, 1 küçük harf, 1 rakam, 1 özel karakter (opsiyonel — NIST artık önermiyor)
  - Have I Been Pwned API check (opsiyonel, k-Anonymity model ile)
- [ ] **3.2.2** **Şifre geçmişi** — son 5 şifre tekrar kullanılamasın
- [ ] **3.2.3** **Şifre yaşlandırma** — 90 günde bir şifre değişimi zorunlu (opsiyonel, NIST artık önermiyor — configurable)
- [ ] **3.2.4** **Geçici şifre** — ilk oluşturmada geçici şifre, ilk login'de değiştirme zorunlu

### 3.3 — Ekip / Grup Yönetimi

- [ ] **3.3.1** **Group (ekip) oluşturma** — `POST /api/v1/groups` → `{name: "SOC Istanbul Team", description: "..."}`
- [ ] **3.3.2** **Group'a kullanıcı ekleme/çıkarma** — `POST/DELETE /api/v1/groups/:id/members`
- [ ] **3.3.3** **Group-level rol atama** — gruba rol atanınca tüm üyeler inherit etsin
- [ ] **3.3.4** **Group scope** — bir grubu belirli sensör grubuna veya tenant'a bağla
- [ ] **3.3.5** **Shift rotation (nöbet çizelgesi)** — haftalık nöbet takvimi, gruba atanan şema
- [ ] **3.3.6** **Mention sistemi** — alert yorumunda `@efekakaya` veya `@soc-istanbul` yazınca bildirim gitsin

### 3.4 — Dizin Entegrasyonu

- [ ] **3.4.1** **LDAP / Active Directory** — kullanıcı ve grup senkronizasyonu
  - [ ] LDAPS (LDAP over TLS) desteği
  - [ ] Bind DN + password veya Kerberos keytab
  - [ ] User filter: `(&(objectClass=user)(memberOf=CN=SOC-Analysts,...))`
  - [ ] Group filter, periyodik sync (her 15 dk)
- [ ] **3.4.2** **SCIM v2** — Okta / Azure AD'den otomatik provisioning/deprovisioning
  - [ ] `GET /scim/v2/Users`, `POST /scim/v2/Users`, `PUT`, `PATCH`, `DELETE`
  - [ ] `GET /scim/v2/Groups`, `POST`, `PATCH`, `DELETE`
  - [ ] Service provider config endpoint: `GET /scim/v2/ServiceProviderConfig`

---

## 📝 Faz 4 — Audit Log (Denetim Kaydı)

> Mevcut: SQLite `audit_log` tablosu — `username, action, capture_file, timestamp`.
> Çok basit, zenginleştirilmesi lazım.

### 4.1 — Audit Log Yapısı

- [ ] **4.1.1** Yeni audit log schema (PostgreSQL):
  ```sql
  CREATE TABLE audit_log (
      id BIGSERIAL PRIMARY KEY,
      event_id UUID NOT NULL UNIQUE,           -- her event'in unique ID'si
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      
      -- Actor
      user_id INTEGER REFERENCES users(id),    -- NULL = system action
      username TEXT,                            -- denormalize, silinse bile kalsın
      api_key_id INTEGER REFERENCES api_keys(id),
      actor_ip INET,                           -- istek yapan IP
      actor_user_agent TEXT,                   -- User-Agent header
      
      -- Action
      category TEXT NOT NULL,                   -- auth, user_mgmt, alert, capture, config, system
      action TEXT NOT NULL,                     -- user.login, user.created, alert.acknowledged, ...
      severity TEXT DEFAULT 'info',             -- info, warning, critical
      status TEXT DEFAULT 'success',            -- success, failure, blocked
      
      -- Target
      resource_type TEXT,                       -- user, alert, sensor, rule, pcap, report, ...
      resource_id TEXT,                         -- hangi kaynak etkilendi
      resource_name TEXT,                       -- insan-okunur adı
      
      -- Details (JSONB — esnek, sorgulanabilir)
      details JSONB,                            -- {old: {...}, new: {...}, reason: "..."}
      
      -- Integrity
      prev_hash TEXT,                           -- hash chain için önceki entry'nin hash'i
      hash TEXT NOT NULL,                       -- bu entry'nin hash'i (tüm alanlar + prev_hash)
      
      -- Multi-tenant
      tenant_id TEXT
  );
  
  CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
  CREATE INDEX idx_audit_user ON audit_log(user_id, timestamp DESC);
  CREATE INDEX idx_audit_category ON audit_log(category, timestamp DESC);
  CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
  ```
- [ ] **4.1.2** **Audit kategorileri ve aksiyonları:**
  ```
  auth:
    login.success, login.failure, login.locked_out, login.mfa_failure
    logout, session.expired, session.revoked
    password.changed, password.reset_requested, password.reset_completed
    mfa.enrolled, mfa.removed, mfa.recovery_code_used
    api_key.created, api_key.revoked, api_key.rotated
    sso.login, sso.link, sso.unlink

  user_mgmt:
    user.created, user.updated, user.deactivated, user.deleted
    user.role_changed, user.permission_changed
    user.password_reset_by_admin
    group.created, group.updated, group.deleted
    group.member_added, group.member_removed

  rbac:
    role.created, role.updated, role.deleted
    permission.granted, permission.revoked

  alert:
    alert.triggered, alert.acknowledged, alert.assigned
    alert.escalated, alert.closed, alert.marked_false_positive
    alert.suppressed, alert.unsuppressed

  capture:
    capture.started, capture.stopped, capture.filter_changed
    capture.interface_changed, capture.pcap_saved

  sensor:
    sensor.registered, sensor.deregistered, sensor.command_sent
    sensor.config_changed, sensor.heartbeat_lost, sensor.heartbeat_restored
    sensor.software_updated

  rule:
    rule.created, rule.updated, rule.deleted, rule.enabled, rule.disabled

  incident:
    case.created, case.updated, case.closed
    playbook.triggered, playbook.step_executed
    evidence.uploaded, evidence.deleted

  system:
    system.started, system.shutdown, system.config_changed
    backup.created, backup.restored
    retention.purge_executed

  report:
    report.generated, report.scheduled, report.shared, report.exported

  data:
    data.exported, data.deleted_by_retention, data.anonymized
    pcap.downloaded, pcap.deleted
  ```

### 4.2 — Audit Log Özellikleri

- [ ] **4.2.1** **Tamper-proof hash chain** — her audit entry, önceki entry'nin SHA-256 hash'ini içerir. Zincir kırılırsa alarm.
- [ ] **4.2.2** **Hash verification endpoint** — `POST /api/v1/audit/verify` → tüm chain doğrulansın, sonuç raporlansın
- [ ] **4.2.3** **Immutable storage** — audit log'lar append-only, UPDATE/DELETE yok (DB seviyesinde REVOKE)
- [ ] **4.2.4** **Dual-write audit** — kritik event'ler (user delete, config change) hem DB'ye hem de ayrı bir append-only dosyaya yazılsın
- [ ] **4.2.5** **Audit retention** — configurable: varsayılan 3 yıl, compliance modunda 7 yıl
- [ ] **4.2.6** **Audit export** — CSV, JSON Lines, CEF (SIEM'e beslemek için)
- [ ] **4.2.7** **Audit search** — `GET /api/v1/audit?category=&action=&user=&resource=&from=&to=&severity=&page=`
- [ ] **4.2.8** **Audit dashboard widget** — son 24 saatte en çok yapılan aksiyonlar, başarısız login grafiği, admin aksiyonları

### 4.3 — Audit Log Yeni Kayıt Noktaları

Mevcut `log_action` çağrılarına **ek olarak** şuralara audit log eklenmeli:

- [ ] **4.3.1** Başarısız login denemeleri (şu an sadece başarılı login log'lanıyor)
- [ ] **4.3.2** Permission denied (403) cevapları — kim, neye erişmeye çalıştı?
- [ ] **4.3.3** Rate limit tetiklenmeleri
- [ ] **4.3.4** Hesap kilitlemeleri ve açılmaları
- [ ] **4.3.5** Session oluşturma, yenileme, sonlandırma
- [ ] **4.3.6** Tüm yazma (POST/PUT/DELETE) operasyonlarında **before/after** değerler (JSONB `details` alanında)
- [ ] **4.3.7** Config değişiklikleri (her `PUT /api/v1/system/config`)
- [ ] **4.3.8** Sensör iletişim kopukluğu ve geri gelmesi

---

## 🛡️ Faz 5 — Genel API Güvenliği

### 5.1 — Rate Limiting

- [ ] **5.1.1** **Per-endpoint rate limit** (token bucket algorithm, Redis-backed):
  ```
  /api/v1/auth/login         → 30 req/dk/IP
  /api/v1/auth/*             → 60 req/dk/IP
  /api/v1/users/*            → 120 req/dk/kullanıcı
  /api/v1/events (push)      → 10.000 req/dk/sensör
  /api/v1/* (genel)          → 300 req/dk/kullanıcı
  ```
- [ ] **5.1.2** **Rate limit header'ları** — `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`
- [ ] **5.1.3** **Rate limit bypass listesi** — belirli IP'ler whitelist (iç monitoring sistemleri)
- [ ] **5.1.4** **Burst allowance** — kısa süreli burst'lere izin ver (token bucket ile)

### 5.2 — Input Validation

- [ ] **5.2.1** **Request body size limit** — max 10 MB (pcap upload hariç)
- [ ] **5.2.2** **JSON schema validation** — tüm endpoint'ler için request body şeması
- [ ] **5.2.3** **SQL injection koruması** — zaten parametrize query kullanılıyor, code review ile doğrula
- [ ] **5.2.4** **XSS koruması** — API JSON döndüğü için düşük risk, ama audit log'da HTML escape yap
- [ ] **5.2.5** **Path traversal koruması** — dosya yolu içeren endpoint'lerde `../` filtresi

### 5.3 — Transport Security

- [ ] **5.3.1** **TLS 1.3 (zorunlu)** — TLS 1.2 fallback, TLS 1.0/1.1 reddet
- [ ] **5.3.2** **HSTS header** — `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- [ ] **5.3.3** **mTLS (mutual TLS)** — sensör ↔ server arası client certificate zorunlu
- [ ] **5.3.4** **Certificate pinning** — sensör tarafında server sertifikası pin'lensin
- [ ] **5.3.5** **Security headers** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `CSP`

### 5.4 — CORS

- [ ] **5.4.1** **CORS policy** — sadece allow list'teki origin'lere izin ver (varsayılan: sadece server'ın kendi domain'i)
- [ ] **5.4.2** **CORS preflight cache** — `Access-Control-Max-Age: 3600`

---

## 🧪 Faz 6 — Test Stratejisi

- [ ] **6.1** **RBAC unit test** — her rol için tüm endpoint'lere erişim test matrisi (otomatik, ~100 test)
- [ ] **6.2** **Permission matrix test** — her permission'ın doğru çalıştığını doğrula
- [ ] **6.3** **Auth flow integration test** — login → MFA → token → refresh → revoke zinciri
- [ ] **6.4** **Brute-force test** — 10 başarısız deneme → lockout, unlock flow
- [ ] **6.5** **SSO integration test** — mock OIDC provider (Dex veya Keycloak test container)
- [ ] **6.6** **Audit completeness test** — her endpoint'in audit log ürettiğini doğrula
- [ ] **6.7** **Audit chain integrity test** — hash zincirini kırmaya çalış, tespit edilsin
- [ ] **6.8** **Rate limit test** — limit aşımı → 429 dönüyor mu?
- [ ] **6.9** **Concurrent session test** — aynı anda 5+ session → reddedilsin
- [ ] **6.10** **SQL injection fuzzing** — tüm endpoint'lere SQLi payload'ları gönder
- [ ] **6.11** **Penetration test checklist** — OWASP Top 10 + API Security Top 10 kapsamı

---

## 📋 Mevcut Kodun İyileştirme Yol Haritası

> Mevcut `api_server.rs` ve `db.rs`'i enterprise seviyeye çıkarmak için
> yapılması gereken refactor adımları:

### Adım 1 — `api_server.rs` → `axum` / `actix-web` geçişi
- [ ] Raw TCP parser'ı bırak, `axum` framework'üne geç
- [ ] Extractors (State, Path, Query, Json), middleware katmanı, error handling
- [ ] Bu geçiş **tüm diğer özelliklerin ön koşulu** — şu anki raw parser ile devam etmek teknik borç

### Adım 2 — `db.rs` → `sqlx` + PostgreSQL
- [ ] SQLite → PostgreSQL geçişi (veya en azından PostgreSQL opsiyonu, SQLite test/development için)
- [ ] Migration sistemi (`sqlx migrate` veya `refinery`)
- [ ] Connection pool (`sqlx::PgPool`)

### Adım 3 — RBAC yeniden tasarım
- [ ] `UserRole` enum'ını kaldır, `permissions: Vec<String>` + `roles: Vec<String>` yap
- [ ] Permission check middleware'i yaz
- [ ] Mevcut hardcoded rol kontrollerini permission check ile değiştir

### Adım 4 — Session yönetimi
- [ ] `HashMap<String, User>` → Redis/JWT
- [ ] Token expiry, refresh, revocation ekle

### Adım 5 — Audit log zenginleştirme
- [ ] Yeni audit_log schema'sı
- [ ] Before/after diff
- [ ] Hash chain
- [ ] IP ve User-Agent kaydı

---

## 🗓 Önerilen MVP Yol Haritası (İlk 6 Hafta)

| Hafta | İş |
|-------|-----|
| **1** | `axum`'a geçiş + PostgreSQL schema migration |
| **2** | Yeni RBAC motoru: permission set'leri + 7 built-in rol + middleware |
| **3** | Kullanıcı yönetimi API'si (CRUD) + şifre politikası + hesap kilitleme |
| **4** | Session yönetimi (JWT + Redis) + token refresh/revoke |
| **5** | MFA (TOTP) + audit log zenginleştirme (yeni schema, hash chain) |
| **6** | API key yönetimi + rate limiting + test suite |

**6 hafta sonunda:** 3 rollü local API → enterprise-grade 7 rollü, MFA'lı, JWT'li, tam audit log'lu sistem.

---

> **Her checkbox, üretim kalitesinde bir ekip kullanımı için gereken somut
> iş kalemidir. Mevcut kodu koruyarak, üzerine inşa ederek ilerlenir.**
