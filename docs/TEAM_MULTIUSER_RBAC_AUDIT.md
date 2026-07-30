# 👥 netscope — Ekip Kullanımı / Çok Kullanıcılı Sistem / RBAC / Audit Log

> **Açık Kaynak & Çift Modlu Mimari Stratejisi (Dual-Mode Open-Source Architecture):**
> 
> netscope, hem **Bireysel Masaüstü Kullanıcıları** (Standalone Desktop Mode) hem de **Kurumsal SOC Ekipleri** (Team/Server Mode) düşünülerek tasarlanmıştır:
> 
> - **🟢 Mod A: Standalone Desktop Mode (Varsayılan):** Masaüstü uygulamasını indiren bireysel geliştirici veya güvenlik uzmanın önüne hiçbir şifre/login barikatı çıkarmaz (`zero-config`). Tüm veriler yerel gömülü **SQLite** veritabanında tutulur, hiçbir VPS veya dış veritabanı gerektirmez.
> - **🔵 Mod B: Team / SOC Server Mode (Opsiyonel):** Bir şirket sunucusuna (Linux/Docker/VPS) kurulduğunda veya `multi_user_mode = true` yapıldığında bu dokümandaki **RBAC, Audit Log, Session Yönetimi ve Webhook** yetenekleri aktif olur.

---

## 🎯 Önceliklendirme ve Yol Haritası (Roadmap)

| Öncelik Seviyesi | Kapsam | Altyapı | Amaç |
|---|---|---|---|
| **🔥 Öncelik 1 (MVP)** | SQLite Tabanlı RBAC, SHA-256 Audit Log, Slack/Discord Webhooks | **Gömülü SQLite (Sıfır Sunucu)** | Projeyi Wireshark'tan ayıran temel ekip ve audit yetenekleri. |
| **⭐ Öncelik 2 (İlerlemiş)** | Session Persistence (SQLite), Scoped API Keys, Case Management | **Gömülü SQLite** | Çok kullanıcılı sunucu kurulumlarında oturum ve vaka yönetimi. |
| **🚀 Öncelik 3 (Enterprise)** | PostgreSQL/Redis Migration, 2FA/TOTP, mTLS Remote Access | **PostgreSQL / Redis (Opsiyonel)** | Binlerce sensörlü ve yüzlerce analistli dev kurumsal yapılar. |

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
  - Session persistence + expiry + revocation (SQLite öncelikli)
  - MFA (TOTP, WebAuthn - Opsiyonel)
  - API key (servis hesabı için)
  - Ekip/group kavramı
  - Paylaşımlı workspace
  - Audit log tamper-proof (SHA-256 hash chain)
  - Hesap kilitleme (brute-force koruması)
  - Rate limiting
  - Slack/Discord Webhook entegrasyonları
```

---

## 🔐 Faz 1 — Kimlik Doğrulama (Authentication)

> **Mimarî Not:** Tüm oturum yönetimi varsayılan olarak **SQLite** veritabanında tutulur (`sessions` tablosu). Kullanıcıları PostgreSQL veya Redis kurmaya zorlamaz.

### 1.1 — Token & Session Yönetimi (SQLite Uyumlu)

- [x] **1.1.1** **Session persistence (SQLite)** — session'ları bellekte değil SQLite `sessions` tablosunda tut, sunucu restart ettiğinde oturumlar düşmesin
  ```sql
  CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,  -- SHA-256(token) — ham token DB'ye yazılmaz
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      revoked BOOLEAN DEFAULT FALSE,
      ip_address TEXT,
      user_agent TEXT,
      last_activity DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  ```
- [x] **1.1.2** **Token expiry** — access token 24 saat, opsiyonel refresh token 7 gün
- [x] **1.1.3** **Sliding expiration** — her API çağrısında `last_activity` yenilensin, idle timeout 30 dk sonra expire
- [x] **1.1.4** **Concurrent session limit** — aynı kullanıcı max 5 aktif session (Admin ayarları)
- [x] **1.1.5** **Session revocation** — Admin tüm session'ları veya tek bir session'ı sonlandırabilsin (`DELETE /api/v1/sessions/:id`)
- [x] **1.1.6** **Force password reset** — Admin bir kullanıcının oturumunu kapatıp "sonraki girişinde şifre değiştir" bayrağı koyabilsin
- [x] **1.1.7** **Scoped API Keys** — Sensör ve bot hesapları için zaman kısıtlamalı ve belirli yetkilere sahip API key yönetimi (`netscope_api_...`)

### 1.2 — Brute-Force Koruması

- [x] **1.2.1** **Account lockout** — 5 başarısız deneme → 15 dakika kilit (configurable)
- [x] **1.2.2** **IP-based rate limit** — aynı IP'den 10 başarısız deneme → 30 dakika geçici kısıtlama
- [x] **1.2.3** **Audit log for lockouts** — her hesap kilitleme işlemi audit log'a kaydedilsin
- [x] **1.2.4** **Unlock flow** — Admin manuel unlock yapabilsin (`POST /api/v1/auth/unlock/account/:username`), veya süre dolunca otomatik açılsın

---

## 🛡️ Faz 2 — Rol Tabanlı Erişim Kontrolü (RBAC)

> **Mimarî Not:** SQLite tabanlı esnek rol yetkilendirmesi. Bireysel masaüstü kullanımında Admin rolü ile otomatik başlar.

### 2.1 — Granüler İzin Matrisi (Granular Permissions)

- [ ] **2.1.1** **Permission tanımları** — 50+ granüler yetki dizesi (örn: `pcap:read`, `pcap:export`, `rules:write`, `alert:ack`, `user:manage`, `audit:read`)
- [ ] **2.1.2** **Ön tanımlı roller:**
  - `Admin`: Tüm yetkilere sahip sistem yöneticisi
  - `Analyst`: Paket inceleme, filtreleme, kural yazma ve uyarı onaylama
  - `Auditor`: Sadece read-only rapor ve denetim loglarını görme yetkisi
  - `Operator`: Sensör durumu izleme ve canlı yakalama başlatma/durdurma
- [ ] **2.1.3** **Custom Role Builder** — Kullanıcının istediği yetkileri seçerek kendi özel rolünü oluşturabilmesi

---

## 📜 Faz 3 — Değiştirilemez Denetim İzleri (Tamper-Proof Audit Logging)

> **Mimarî Not:** Güvenlik denetçileri için hayati özelliktir. SQLite üzerinde blokzincir benzeri SHA-256 zinciri ile çalışır.

### 3.1 — Cryptographic Audit Hash Chain

- [ ] **3.1.1** **Audit log tablosu & Hash Chain:**
  ```sql
  CREATE TABLE IF NOT EXISTS audit_chain (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      prev_hash TEXT NOT NULL,       -- Bir önceki kaydın SHA-256 hash'i
      entry_hash TEXT NOT NULL,      -- Bu kaydın SHA-256(prev_hash + user_id + action + timestamp)
      user_id INTEGER NOT NULL,
      action TEXT NOT NULL,          -- örn: "PCAP_EXPORT", "RULE_DELETE", "IP_BLOCK"
      resource TEXT,                 -- örn: "10.0.1.47" veya "rules/malware.json"
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  ```
- [ ] **3.1.2** **Audit Verification Tool** — Logların dışarıdan değiştirilip değiştirilmediğini doğrulayan `netscope-cli audit verify` komutu.

---

## 🔔 Faz 4 — Ekip Bildirimleri & Entegrasyonlar

> **Mimarî Not:** Harici sunucu gerektirmeyen webhook yapılandırması.

### 4.1 — Webhook & Notification Engine

- [ ] **4.1.1** **Telegram Bot Notifications** — Yüksek önem seviyeli bir saldırı veya tehdit tespit edildiğinde kullanıcının kendi Telegram Bot'u (`https://api.telegram.org/bot<token>/sendMessage`) üzerinden doğrudan telefona/gruba anlık bildirim atma.
- [ ] **4.1.2** **Discord & Slack Webhooks** — Otomatik Discord/Slack kanalına bildirim atma.
- [ ] **4.1.3** **Custom JSON Webhook** — Herhangi bir SOAR veya 3. parti servise HTTP POST bildirimi yollama.
- [ ] **4.1.4** **Email Notification (SMTP)** — Kritik sistem uyarıları için e-posta gönderimi.
