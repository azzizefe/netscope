# netscope-server API Referansı

> REST: `http://<host>:<port>/api/v1/*`
> gRPC: `SensorService` @ `<host>:<grpc_port>`

---

## Kimlik Doğrulama

| Yöntem | Rol |
|---|---|
| **admin** | Tüm izinler |
| **operator** | sensors RW, events RW, alerts RW, rules R, dashboard R |
| **analyst** | events R, alerts RW, dashboard R |
| **viewer** | sensors R, events R, alerts R, dashboard R |

JWT (HS256) ile doğrulama: `Authorization: Bearer <token>` header'ı.

---

## REST API

### Auth (public — JWT gerekmez)

| Yöntem | Path | Açıklama |
|---|---|---|
| POST | `/api/v1/auth/login` | Giriş — `{ username, password }` → `{ token, user_id, username, role }` |
| POST | `/api/v1/auth/register` | Kayıt — `{ username, email, password, role? }` → 201 |

### Upgrade (public — JWT gerekmez)

| Yöntem | Path | Açıklama |
|---|---|---|
| GET | `/api/v1/upgrade/check` | Sürüm kontrolü — `?version=&channel=` → `{ upgrade_available, url, sha256 }` |
| GET | `/api/v1/upgrade/download/{version}` | Sensör binary indirme — **her zaman 404** (placeholder) |

### Health

| Yöntem | Path | Açıklama |
|---|---|---|
| GET | `/api/v1/health` | Health check → `{ status, service, version, websocket_sessions }` |

### Dashboard

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | `dashboard:read` | Özet istatistikler (15s Redis cache) |

### Sensors

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/sensors` | `sensors:read` | Tüm sensörleri listele |
| POST | `/api/v1/sensors` | `sensors:write` | Yeni sensör kaydet — 201 |
| POST | `/api/v1/sensors/register` | `sensors:write` | Alternatif kayıt endpoint'i |
| POST | `/api/v1/sensors/bulk/command` | `sensors:command` | Toplu komut gönder — 202 |
| GET | `/api/v1/sensors/{id}` | `sensors:read` | Sensör detayı |
| PUT | `/api/v1/sensors/{id}/heartbeat` | `sensors:write` | Heartbeat bildir (cache TTL=60s) |
| POST | `/api/v1/sensors/{id}/command` | `sensors:command` | Komut kuyruğa al — 202 |
| GET | `/api/v1/sensors/{id}/commands` | `sensors:read` | Bekleyen komutları çek (drain) |
| PUT | `/api/v1/sensors/{id}/commands/{cmd_id}/result` | `sensors:write` | Komut sonucunu bildir |
| GET | `/api/v1/sensors/{id}/config` | `sensors:read` | Sensör konfigürasyonu getir |
| PUT | `/api/v1/sensors/{id}/config` | `sensors:write` | Konfigürasyon güncelle (TOML → WS push) |
| GET | `/api/v1/sensors/{id}/config/history` | `sensors:read` | Konfigürasyon geçmişi |
| POST | `/api/v1/sensors/{id}/config/rollback` | `sensors:write` | Konfigürasyon geri al |
| GET | `/api/v1/sensors/{id}/throughput` | `sensors:read` | Throughput grafik verisi |
| GET | `/api/v1/sensors/{id}/logs` | `sensors:read` | Sensör logları (son 1s, max 1000) |
| GET | `/api/v1/sensors/{id}/topology` | `sensors:read` | Ağ topolojisi grafı |
| GET | `/api/v1/sensors/{id}/ws` | JWT (any) | WebSocket upgrade (gerçek zamanlı) |

### Events

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/events` | `events:read` | Olayları listele (`?severity=&sensor_id=&timerange_start=&timerange_end=&event_type=&page=&per_page=`) |
| POST | `/api/v1/events/batch` | `events:write` | Toplu olay gönder (JSON veya zstd; rate limit 60/dk/IP) |

### Alerts

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/alerts` | `alerts:read` | Alarmları listele (`?status=&severity=&sensor_id=&timerange_start=&timerange_end=&page=&per_page=`) |
| POST | `/api/v1/alerts/bulk/status` | `alerts:write` | Toplu durum güncelleme |
| GET | `/api/v1/alerts/{id}` | `alerts:read` | Alarm detayı (kural adı, olay detayı, atanan kullanıcı) |
| PATCH | `/api/v1/alerts/{id}/status` | `alerts:write` | Alarm durumu güncelle (`{ status, assigned_to? }`) |
| GET | `/api/v1/alerts/{id}/notes` | `alerts:read` | Alarm notlarını getir |
| POST | `/api/v1/alerts/{id}/notes` | `alerts:write` | Alarm notu ekle |
| GET | `/api/v1/alerts/{id}/pcap` | `alerts:read` | Alarm PCAP'ini indir (mock) |
| POST | `/api/v1/alerts/{id}/soar/trigger` | `alerts:write` | SOAR playbook tetikle |

### Rules

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/rules` | `rules:read` | Tüm kuralları listele |
| POST | `/api/v1/rules` | `rules:write` | Kural oluştur — 201 |
| GET | `/api/v1/rules/{id}` | `rules:read` | Kural detayı |
| PUT | `/api/v1/rules/{id}` | `rules:write` | Kural güncelle |
| DELETE | `/api/v1/rules/{id}` | `rules:write` | Kural sil — 204 |

### Hunt (Tehdit Avı)

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| POST | `/api/v1/hunt/events` | `events:read` | Rekürsif HuntRule filtresi ile olay ara |
| POST | `/api/v1/hunt/histogram` | `events:read` | Zaman bazlı histogram |
| GET | `/api/v1/hunt/saved-searches` | `events:read` | Kayıtlı aramaları listele |
| POST | `/api/v1/hunt/saved-searches` | `events:write` | Arama kaydet |
| POST | `/api/v1/hunt/saved-searches/{id}/convert-to-rule` | `events:write` | Aramayı alert rule'a çevir — 201 |

### Reports

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/reports/daily` | `dashboard:read` | Günlük SOC raporu |
| GET | `/api/v1/reports/compliance` | `dashboard:read` | Uyumluluk raporu (ISO27001, GDPR, KVKK, PCI-DSS, NIS2) |
| POST | `/api/v1/reports/custom` | `dashboard:read` | Özel rapor oluştur |
| GET | `/api/v1/reports/executive` | `dashboard:read` | Executive HTML rapor |
| GET | `/api/v1/reports/executive/download` | `dashboard:read` | Executive PDF indir |
| GET | `/api/v1/reports/schedule` | `dashboard:read` | Zamanlanmış raporları listele |
| POST | `/api/v1/reports/schedule` | `dashboard:write` | Rapor zamanlaması oluştur — 201 |
| DELETE | `/api/v1/reports/schedule/{id}` | `dashboard:write` | Zamanlamayı sil — 204 |

### SOAR

| Yöntem | Path | Yetki | Açıklama |
|---|---|---|---|
| GET | `/api/v1/soar/playbooks` | `alerts:read` | Playbook'ları listele |
| POST | `/api/v1/soar/playbooks` | `alerts:read` | Playbook kaydet — 201 |
| POST | `/api/v1/soar/playbooks/debug` | `alerts:read` | Playbook debug (dry-run) |
| POST | `/api/v1/soar/playbooks/execute` | `alerts:write` | Playbook çalıştır |
| GET | `/api/v1/soar/playbooks/marketplace` | `alerts:read` | Topluluk playbook'ları (mock) |
| GET | `/api/v1/soar/cases` | `alerts:read` | Vaka listesi |
| POST | `/api/v1/soar/cases` | `alerts:read` | Vaka oluştur — 201 |
| GET | `/api/v1/soar/cases/{id}` | `alerts:read` | Vaka detayı (alerts, timeline, evidence, custody) |
| POST | `/api/v1/soar/cases/{id}/status` | `alerts:write` | Vaka durumu güncelle |
| POST | `/api/v1/soar/cases/{id}/evidence` | `alerts:write` | Delil yükle — 201 |
| GET | `/api/v1/soar/cases/{id}/post-mortem` | `alerts:read` | Post-mortem raporu (Markdown) |
| GET | `/api/v1/soar/ticketing` | `alerts:read` | Ticketing entegrasyonlarını listele |
| POST | `/api/v1/soar/ticketing` | `alerts:read` | Ticketing entegrasyonu ekle — 201 |
| POST | `/api/v1/soar/ticketing/webhook` | `alerts:write` | Ticketing webhook (çift yönlü senkron) |

---

## gRPC API

**Servis:** `SensorService`
**Port:** varsayılan `9444`

| RPC | Tür | İstek | Yanıt | Açıklama |
|---|---|---|---|---|
| `Register` | Unary | `{ hostname, ip_address, os, version }` | `{ sensor_id, status }` | Sensör kaydı |
| `SendHeartbeat` | Unary | `{ sensor_id, cpu_load_pct, ram_used_mb, capture_throughput_bps, uptime_secs, disk_free_mb }` | `{ acknowledged }` | Heartbeat (Redis cache 60s) |
| `StreamEvents` | Client-streaming | `stream { sensor_id, event_type, severity, title, description, protocol, source_ip, dest_ip, port, raw_data }` | `{ accepted, status }` | Toplu olay gönderimi (rate limit 10 bağlantı/dk/IP) |
| `SendCommand` | Unary | `{ sensor_id, command, parameters }` | `{ status, message }` | Sensöre komut gönder |

---

## HTTP Durum Kodları

| Kod | Anlamı |
|---|---|
| 200 | Başarılı |
| 201 | Oluşturuldu |
| 202 | Kuyruğa alındı |
| 204 | Başarılı (içerik yok) |
| 400 | Geçersiz istek |
| 401 | Yetkisiz (JWT yok/geçersiz) |
| 403 | Yetersiz yetki (role izin vermiyor) |
| 404 | Bulunamadı |
| 409 | Çakışma (duplicate) |
| 429 | Rate limit aşıldı |

---

## Toplam

| Kategori | Adet |
|---|---|
| REST endpoint | 64 (2 public, 1 WS, 61 protected) |
| gRPC RPC | 4 |
| Veritabanı modeli | ~20 |
