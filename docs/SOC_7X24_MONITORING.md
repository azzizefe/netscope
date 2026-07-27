# 🛡️ netscope SOC / 7×24 İzleme Sistemi — Uygulama Yol Haritası

> **Senior-level implementation spec.** Her bir checkbox, üretime hazır bir SOC
> dağıtımı için tamamlanması gereken somut bir iş kalemidir. Checkbox'lar
> bağımlılık sırasına göre (yukarıdan aşağıya) dizilmiştir — önce altyapı,
> sonra entegrasyon, en son otomasyon.

---

## ✅ Durum — 2026-07-27 denetimi

**23 / 267 kutu işaretli.** Tamamı Faz 0 (Mimari Temel) içinde.

Bir kutu ancak şu iki şart sağlanınca işaretlendi: ilgili kod var **ve** iddia
ettiği davranışı gerçekten yapıyor. "Dosya mevcut" yeterli sayılmadı — denetim
sırasında yazılmış ama hiçbir yere bağlanmamış üç şey çıktı:

| Bulgu | Durum |
|---|---|
| RBAC hiç çalışmıyordu — `require_permission` axum'ın `from_fn`'ine sığmayan bir imzaya sahipti, bu yüzden hiçbir router'a takılamamıştı. API kimlik doğruluyor ama **yetki denetlemiyordu**: geçerli herhangi bir token her endpoint'e ulaşıyordu, bir `viewer` alert kurallarını silebiliyordu. | Düzeltildi, test edildi |
| WebSocket `/ws/events` bağlantı kabul ediyor ama **hiç event basmıyordu** — `broadcast_event` hiçbir yerden çağrılmıyordu. | Event ingest'e bağlandı, test edildi |
| `JwtState::create_token`, negatif/uçuk `expiry_hours` değerinde **panikliyordu** (`(hours * 3600) as usize` taşması). Bozuk bir config sunucuyu düşürürdü. | i64 + saturating aritmetiğe çevrildi |

İşaretlenmeyen ama kısmen yazılmış olanlar:

- **0.1.5 Redis** — `CacheLayer` kuruluyor ve `ApiState`'e konuyor, ama tek bir
  metodu bile çağrılmıyor. Heartbeat cache, rate-limit ve alert dedup'ın hiçbiri
  çalışmıyor. Kod var, işlev yok.
- **0.3 Merkezi Config** — sunucu tarafında sensör başına config store/push/
  versioning/validation yok; ajan yalnızca yerel dosyadan okuyor.
- **Faz 1 SIEM** — `siem.rs` 175 satırlık temel bir exporter (NDJSON + ES/Splunk
  URL). Kutuların istediği CEF/LEEF/OCSF, bulk indexing, ILM, retry, enrichment
  ve 10 connector'ın hiçbiri yok. Kutular zaten "mevcut kodu iyileştir" diyor.

Kalan 244 kutu için belgenin kendi tahmini geçerli: **~20-30 adam-ay**.

---

## 📐 Faz 0 — Mimari Temel (Foundation)

> Bu faz olmadan diğer hiçbir şey çalışmaz.

### 0.1 — Merkezi Yönetim Sunucusu (Central Management Server)

- [x] **0.1.1** `netscope-server` binary'si oluştur (`crates/server/`) — capture engine'dan bağımsız, sadece yönetim & telemetri toplama
- [x] **0.1.2** REST API (axum/actix-web) — tüm endpoint'ler JWT auth + RBAC ile korunmuş
  - [x] `POST /api/v1/sensors/register` — sensör kaydı (hostname, IP, OS, netscope versiyonu, desteklenen interface'ler)
  - [x] `GET /api/v1/sensors` — tüm sensörlerin listesi + heartbeat durumu
  - [x] `GET /api/v1/sensors/:id` — tek sensör detayı (CPU, RAM, capture throughput, uptime, son görülme)
  - [x] `POST /api/v1/sensors/:id/command` — sensöre uzaktan komut (capture başlat/durdur, filter değiştir, pcap kaydet)
  - [x] `GET /api/v1/events?severity=&timerange=&sensor=` — merkezi event akışı (sayfalı, filtrelenebilir)
  - [x] `GET /api/v1/alerts?status=&severity=&timerange=` — alert geçmişi (sayfalı)
  - [x] `POST /api/v1/rules` / `PUT /api/v1/rules/:id` / `DELETE /api/v1/rules/:id` — kural CRUD
  - [x] `GET /api/v1/dashboard/summary` — SOC dashboard özet verisi (aktif alert, event/sn, top talker, top threat)
  - [x] `GET /api/v1/health` — health check (DB bağlantısı, Redis, disk)
- [x] **0.1.3** WebSocket endpoint'i `ws://server/ws/events` — sensörlerden real-time event push
- [x] **0.1.4** PostgreSQL schema — migration dosyaları (`sqlx` veya `refinery` ile)
  ```sql
  sensors, sensor_heartbeats, events, alerts, alert_rules,
  threat_indicators, audit_log, users, roles, api_keys
  ```
- [ ] **0.1.5** Redis cache katmanı — sensor heartbeat'leri, rate-limit, alert dedup için
- [x] **0.1.6** TLS 1.3 (mTLS) — sensör ↔ server arası tüm trafik şifreli, client certificate ile mutual auth
- [x] **0.1.7** gRPC streaming — yüksek throughput'lu sensör → server telemetri kanalı (REST + WS alternatifi)

### 0.2 — Sensör Ajanı (Sensor Agent)

- [x] **0.2.1** `netscope-agent` binary'si — capture engine'ın yanında çalışan yan süreç / embedded mod
- [x] **0.2.2** Server'a register olma — ilk başlatmada `POST /sensors/register`, server'dan `sensor_id` + mTLS cert al
- [x] **0.2.3** Heartbeat — her 15 saniyede `PUT /sensors/:id/heartbeat` (CPU %, RAM MB, capture pkt/s, disk MB free, uptime)
- [x] **0.2.4** Komut poll / WebSocket — server'dan gelen komutları al (capture başlat/durdur, filter değiştir), sonucu raporla
- [x] **0.2.5** Event batch push — her 500 ms veya 100 event'te bir, sıkıştırılmış (zstd) batch olarak server'a gönder
- [x] **0.2.6** Offline buffer — server'a ulaşılamazsa event'leri SQLite'da biriktir, bağlantı dönünce flush et (max 4 GB disk)
- [x] **0.2.7** Auto-upgrade — server'dan yeni binary çekip kendini güncelleme (checksum doğrulamalı, rollback'li)
- [x] **0.2.8** Windows Service / Linux systemd unit — agent'ı servis olarak çalıştırma, auto-restart

### 0.3 — Merkezi Yapılandırma (Central Config)

- [ ] **0.3.1** Server-side config store — her sensör için ayrı ayrı override edilebilir YAML/TOML config
- [ ] **0.3.2** Config push — server'da config değişince sensöre otomatik push (WebSocket üzerinden)
- [ ] **0.3.3** Config versioning — her değişiklik audit log'a kaydedilsin, rollback yapılabilsin
- [ ] **0.3.4** Config validation — sensör config'i kabul etmeden önce server tarafında validate et (schema-based)

---

## 🔗 Faz 1 — SIEM Entegrasyonu (SIEM Integration)

> Mevcut `siem.rs` temel alınacak, enterprise-grade hale getirilecek.

### 1.1 — SIEM Format Desteği

- [ ] **1.1.1** **Syslog (RFC 5424)** çıktı formatı — structured data + severity mapping
- [ ] **1.1.2** **CEF (Common Event Format)** — ArcSight, McAfee ESM, Sumo Logic için
  ```
  CEF:0|netscope|netscope-agent|2.0|100|Suspicious Beaconing|5|src=10.0.0.5 dst=203.0.113.42 ...
  ```
- [ ] **1.1.3** **LEEF (Log Event Extended Format)** — QRadar için
- [ ] **1.1.4** **JSON Lines (NDJSON)** — Elasticsearch, Splunk HEC, Loki için (mevcut kod iyileştirilecek)
- [ ] **1.1.5** **Raw PCAP export** — alert tetiklendiğinde ilgili .pcap parçasını otomatik dışa aktar

### 1.2 — SIEM Connector'lar

- [ ] **1.2.1** **Elasticsearch connector** — mevcut `siem.rs` iyileştir: bulk indexing, index template, ILM policy, index rotation (`netscope-2026.07.27`)
- [ ] **1.2.2** **Splunk HEC connector** — mevcut kod iyileştir: batching, retry, sourcetype mapping
- [ ] **1.2.3** **Splunk TCP/UDP connector** — direkt Splunk Universal Forwarder'a syslog/CEF gönder
- [ ] **1.2.4** **Graylog GELF connector** — GELF TCP/UDP çıktısı
- [ ] **1.2.5** **Azure Sentinel connector** — Log Analytics Workspace API (DCR-based ingestion)
- [ ] **1.2.6** **AWS Security Lake connector** — OCSF (Open Cybersecurity Schema Framework) formatında S3'e yaz
- [ ] **1.2.7** **Wazuh connector** — Wazuh agent'a syslog/JSON event forward
- [ ] **1.2.8** **Google Chronicle / SecOps** — Ingestion API (UDM format)
- [ ] **1.2.9** **Kafka sink** — tüm event'leri Kafka topic'e yaz (Confluent/SaaS + self-hosted), SASL/SSL destekli
- [ ] **1.2.10** **Loki sink** — Grafana Loki'ye direkt push (logQL ile alerting zinciri)

### 1.3 — SIEM Event Schema

- [ ] **1.3.1** **OCSF uyumlu event modeli** — `SiemEvent` struct'ını OCSF 1.3.0 `security_finding` + `network_activity` class'larına uygun hale getir
- [ ] **1.3.2** Event zenginleştirme (enrichment):
  - [ ] GeoIP (MaxMind GeoLite2 — zaten mevcut)
  - [ ] ASN / ISP bilgisi (MaxMind GeoLite2 ASN)
  - [ ] Threat intel lookup (VirusTotal, AbuseIPDB — zaten mevcut)
  - [ ] JA3/JA4 fingerprint (zaten mevcut)
  - [ ] MAC vendor (OUI lookup — zaten mevcut)
  - [ ] DNS passive resolution (zaten mevcut)
- [ ] **1.3.3** Severity mapping standardizasyonu:
  ```
  netscope ExpertSeverity → SIEM severity (0-10)
    Chat    → 0 (Informational)
    Note    → 2-3 (Low)
    Warning → 5-6 (Medium)
    Error   → 8-9 (High)
  ```
- [ ] **1.3.4** MITRE ATT&CK taktik/teknik mapping'i her event tipi için
- [ ] **1.3.5** Cyber Kill Chain faz mapping'i her event tipi için

---

## 🚨 Faz 2 — Alerting Motoru (Alerting Engine)

> Merkezi, kural tabanlı, threshold + anomaly + correlation destekli.

### 2.1 — Alert Rule Engine

- [ ] **2.1.1** Rule DSL (domain-specific language) — YAML tabanlı, mevcut display-filter syntax'ını genişlet:
  ```yaml
  name: "Port scan detection"
  severity: high
  mitre_attack: "T1046"
  trigger:
    type: threshold
    filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0"
    group_by: [src, dst]
    threshold: 50
    window: 30s
  actions:
    - alert
    - block_src  # otomatik firewall block
    - pcap_dump   # ilgili paketleri kaydet
  ```
- [ ] **2.1.2** Kural tipleri:
  - [ ] **Threshold** — X olay Y sürede Z kere olursa tetikle
  - [ ] **Anomaly** — baseline'dan sapma (ör: normalde 100 pkt/sn → şu an 5000 pkt/sn)
  - [ ] **Signature** — belirli pattern/IOC match olursa (mevcut YARA-lite + Suricata kural motoru)
  - [ ] **Correlation** — birden fazla event'in ardışık/ilişkili gelmesi (ör: port scan → brute force → lateral movement)
  - [ ] **Absence** — beklenen trafik Y süredir gelmiyorsa (ör: heartbeat kaybı)
  - [ ] **Compound** — (A && B) || (C && !D) tipi boolean logic ile birden fazla kuralı birleştir
  - [ ] **Time-based** — belirli saat/gün aralığında farklı threshold (mesai dışı = daha hassas)

- [ ] **2.1.3** Alert deduplication — aynı (kural, src, dst) tuple'ı için N saniyede sadece 1 alert üret
- [ ] **2.1.4** Alert suppression — belirli IP/subnet/vlan'dan gelen alert'leri sustur (maintenance window)
- [ ] **2.1.5** Alert enrichment — alert oluştuğunda otomatik:
  - WHOIS sorgusu
  - Pasif DNS geçmişi (kendi DNS log'undan)
  - Bağlı olduğu diğer connection'lar
  - Aynı src IP'nin son 24 saatteki diğer alert'leri
- [ ] **2.1.6** Alert correlation engine — farklı sensörlerden gelen alert'leri birleştir (ör: 3 farklı sensörde aynı dst IP'ye tarama)

### 2.2 — Smart Alert Triggers (Mevcut kodun iyileştirilmesi)

- [ ] **2.2.1** **Traffic spike alert** — baseline'dan 3σ sapma (mevcut "smart alerts" kodunu kural motoruna taşı)
- [ ] **2.2.2** **Error burst alert** — 1 dakikada 4xx/5xx sayısı normalin 5 katına çıkarsa
- [ ] **2.2.3** **New host alert** — daha önce hiç görülmemiş bir IP ağda belirirse
- [ ] **2.2.4** **New protocol alert** — daha önce bu network'te görülmemiş bir protokol tespit edilirse
- [ ] **2.2.5** **Beaconing alert** — düzenli aralıklarla C2 benzeri check-in (mevcut heuristics iyileştir)
- [ ] **2.2.6** **Data exfiltration alert** — outbound traffic > baseline + 100 MB (mevcut DLP iyileştir)
- [ ] **2.2.7** **Privilege escalation alert** — düşük porttan yüksek porta SMB/RDP/SSH bağlantısı
- [ ] **2.2.8** **Lateral movement alert** — bir host'un kısa sürede çok sayıda internal host'a bağlanması
- [ ] **2.2.9** **DNS tunneling alert** — anormal uzunlukta/frekansda DNS sorguları
- [ ] **2.2.10** **DGA domain alert** — entropy tabanlı domain generation algorithm tespiti (mevcut "suspicious domains" iyileştir)
- [ ] **2.2.11** **Encrypted traffic anomaly** — normalde plaintext olması beklenen portta TLS (veya tersi)
- [ ] **2.2.12** **Expired certificate alert** — TLS sertifikası expire olmuş bağlantı
- [ ] **2.2.13** **Weak cipher alert** — TLS 1.0/1.1, RC4, 3DES, MD5 kullanan bağlantı
- [ ] **2.2.14** **PQC migration gap alert** — PQC'ye geçmemiş kritik servis (mevcut `pqc_analytics` kullanarak)

### 2.3 — Alert Eskalasyon (Escalation)

- [ ] **2.3.1** Eskalasyon seviyeleri (zaman bazlı):
  ```
  L1 (SOC Analyst) → 15 dk → L2 (Senior Analyst) → 30 dk → L3 (IR Lead) → 1 saat → CISO
  ```
- [ ] **2.3.2** Eskalasyon policy — her kural için ayrı ayrı override edilebilir eskalasyon zinciri
- [ ] **2.3.3** On-call schedule entegrasyonu — PagerDuty, Opsgenie, VictorOps API
- [ ] **2.3.4** Shift rotation — haftalık nöbet çizelgesi, otomatik atama

### 2.4 — Bildirim Kanalları (Notification Channels)

- [ ] **2.4.1** **E-posta** — SMTP/SMTPS, HTML + plaintext template, rate limit (max 1/dk)
- [ ] **2.4.2** **Slack** — incoming webhook, formatted message + attachment (pcap snippet, event detail)
- [ ] **2.4.3** **Microsoft Teams** — incoming webhook / Power Automate connector
- [ ] **2.4.4** **Discord** — webhook
- [ ] **2.4.5** **Telegram** — bot API
- [ ] **2.4.6** **PagerDuty** — Events API v2 (dedup key, severity, component)
- [ ] **2.4.7** **Opsgenie** — Alert API
- [ ] **2.4.8** **Webhook (generic)** — custom URL'ye JSON POST (HMAC-SHA256 imzalı)
- [ ] **2.4.9** **SMS** — Twilio API (sadece critical alert'ler için)
- [ ] **2.4.10** **Sesli arama** — Twilio Voice API (sadece emergency — sunucu down, DDoS tespiti)
- [ ] **2.4.11** **Syslog alert** — alert'leri de syslog olarak SIEM'e geri besleme (kapalı döngü)
- [ ] **2.4.12** **Windows Event Log** — alert'leri yerel Event Viewer'a yaz (Windows sensörler için)
- [ ] **2.4.13** **SNMP trap** — kritik alert'leri SNMP trap olarak NMS'e gönder

---

## 📊 Faz 3 — SOC Dashboard (Web UI)

> Tauri masaüstü uygulamasına ek olarak, **browser-tabanlı** bir SOC operatör
> paneli. Bu panel netscope-server'ın içinde gömülü gelir.

### 3.1 — Ana Dashboard

- [ ] **3.1.1** **7×24 Overview** — tek ekranda tüm sensörlerin durumu:
  - [ ] Aktif sensör sayısı + online/offline badge
  - [ ] Son 24 saatte toplam event sayısı
  - [ ] Açık (acknowledge edilmemiş) alert sayısı (L1/L2/L3 kırılımlı)
  - [ ] Son 1 saatte alert trend sparkline'ı
  - [ ] Top 5 attacker src IP (iç + dış)
  - [ ] Top 5 targeted dst IP
  - [ ] Protocol distribution pie chart
  - [ ] Network throughput (aggregate, tüm sensörler)
  - [ ] MTTR (Mean Time to Resolve) son 7 gün
  - [ ] False positive oranı son 7 gün
- [ ] **3.1.2** **Dark theme** default — SOC operatörleri karanlık odada çalışır (mevcut Midnight/Dracula/Nord tema'larını Web UI'a portla)
- [ ] **3.1.3** **Auto-refresh** — 5 saniyede bir WebSocket üzerinden canlı güncelleme
- [ ] **3.1.4** **Responsive** — 1080p, 1440p, 4K ve ultrawide (21:9, 32:9) monitörler için fluid layout

### 3.2 — Sensör Yönetimi

- [ ] **3.2.1** Sensör listesi grid view — hostname, IP, OS, versiyon, uptime, CPU, RAM, pkt/s, durum, son görülme
- [ ] **3.2.2** Tek sensör detay sayfası:
  - [ ] Canlı capture throughput grafiği (son 1 saat, 1 dk resolution)
  - [ ] Aktif filter, yazılan pcap dosyası
  - [ ] Son N event (sayfalı, filtrelenebilir)
  - [ ] Sensöre komut gönder (capture restart, filter değiştir, pcap rotate)
  - [ ] Sensör log'ları (son 1000 satır, canlı tail)
  - [ ] Ağ topolojisi (o sensörün gördüğü host'ların force-directed graph'i)
- [ ] **3.2.3** Toplu sensör operasyonu — N sensörü aynı anda güncelle, restart et, config push'la

### 3.3 — Alert Yönetimi

- [ ] **3.3.1** Alert queue — triage board (TODO / Investigating / Resolved / False Positive)
- [ ] **3.3.2** Alert detay sayfası:
  - [ ] Hangi kural tetiklendi + kuralın YAML tanımı
  - [ ] İlgili event'ler (timeline, packet detail)
  - [ ] Kaynak ve hedef hakkında zenginleştirilmiş bilgi (GeoIP, ASN, threat intel)
  - [ ] Acknowledge / Assign / Escalate / Close butonları
  - [ ] Alert notları (analistler arası iletişim, Markdown destekli)
  - [ ] İlgili pcap parçasını indir
  - [ ] "Bunu araştıran diğer analistler" (collaboration)
  - [ ] SOAR playbook tetikleme butonu
- [ ] **3.3.3** Alert timeline — kronolojik sırada tüm alert + event akışı, görsel correlation çizgileriyle
- [ ] **3.3.4** Alert bulk operations — N alert'i aynı anda kapat, FP işaretle, assign et

### 3.4 — Threat Hunting

- [ ] **3.4.1** **Interactive query builder** — görsel display-filter builder (AND/OR/NOT blokları, drag & drop)
- [ ] **3.4.2** **Histogram view** — seçilen filter için event frekansının zaman çizelgesi
- [ ] **3.4.3** **Pivot** — bir event'ten başlayarak tüm ilişkili event'lere atlama:
  - Bu src IP başka nelere bağlanmış?
  - Bu dst IP'ye başka kimler bağlanmış?
  - Bu port'ta başka neler olmuş?
  - Bu JA3 fingerprint başka nerelerde görülmüş?
- [ ] **3.4.4** **Saved searches** — sık kullanılan hunt query'leri kaydet, paylaş, alert'e dönüştür
- [ ] **3.4.5** **Threat intel overlay** — search sonuçlarının üzerine VirusTotal/AbuseIPDB sonuçlarını overlay et

### 3.5 — Raporlama

- [ ] **3.5.1** **Daily SOC report** — otomatik oluşan günlük özet:
  - Toplam event, alert (severity kırılımlı), resolved, FP
  - En aktif sensörler, en çok alert üreten kurallar
  - Yeni görülen IP/protocol/domain'ler
  - MTTR, ortalama acknowledge süresi
- [ ] **3.5.2** **Weekly executive report** — PDF, yönetime sunulacak formatta
- [ ] **3.5.3** **Monthly compliance report** — KVKK, GDPR, ISO 27001, PCI-DSS, NIS2 metrikleri
- [ ] **3.5.4** **Custom report builder** — drag & drop ile özel rapor şablonu oluşturma
- [ ] **3.5.5** **Scheduled report delivery** — e-posta ile otomatik gönderim (günlük/haftalık/aylık)
- [ ] **3.5.6** **Executive KPI dashboard** — yönetim için sadeleştirilmiş, büyük rakamlı, yeşil/sarı/kırmızı renkli özet ekran

---

## 🤖 Faz 4 — SOAR / Otomasyon (Security Orchestration, Automation & Response)

### 4.1 — Playbook Engine

- [ ] **4.1.1** **Playbook formatı** — YAML tabanlı, step-by-step:
  ```yaml
  name: "Ransomware suspicion response"
  trigger:
    rule_ids: [105, 203, 442]
  steps:
    - action: enrich_ip
      target: "{{.SrcIP}}"
    - action: block_host
      target: "{{.SrcIP}}"
      condition: "{{.EnrichResult.AbuseIPDB.confidence}} > 80"
    - action: snapshot_sensor
      target: "{{.SensorID}}"
    - action: notify_slack
      channel: "#incident-response"
      template: "ransomware-alert"
  ```
- [ ] **4.1.2** Built-in action'lar:
  - [ ] `block_host` — Windows Firewall / iptables rule (mevcut `firewall.rs` üzerinden)
  - [ ] `block_subnet` — /24 veya /16 block
  - [ ] `quarantine_host` — 802.1X / NAC API ile port kapatma
  - [ ] `snapshot_sensor` — o anki pcap buffer'ı diske yaz
  - [ ] `start_full_capture` — sensörde full packet capture başlat
  - [ ] `enrich_ip` / `enrich_domain` / `enrich_hash` — threat intel lookup
  - [ ] `notify_slack` / `notify_teams` / `notify_email`
  - [ ] `create_ticket` — Jira / ServiceNow / TheHive
  - [ ] `run_script` — sensörde custom script çalıştır
  - [ ] `send_syslog` / `send_snmp_trap`
  - [ ] `isolate_host_via_edr` — CrowdStrike / SentinelOne API
  - [ ] `dns_sinkhole` — Pi-hole / DNS server API ile domain block
- [ ] **4.1.3** Condition engine — `{{.Field}} > X`, `contains`, `regex`, `in_list`
- [ ] **4.1.4** Playbook debugger — kuru çalıştırma (dry run), step-by-step execution trace
- [ ] **4.1.5** Playbook marketplace — topluluktan paylaşılan playbook'ları import et

### 4.2 — Incident Response

- [ ] **4.2.1** **Case management** — alert → incident dönüştürme, case ID atama
- [ ] **4.2.2** **Evidence locker** — incident'a bağlı tüm pcap, log, screenshot, not'ları bir arada tutma
- [ ] **4.2.3** **Chain of custody** — her evidence parçası için timestamp + user damgası (adli bilişim uyumlu)
- [ ] **4.2.4** **Incident timeline** — olayın başlangıcından kapanışına kadar tüm aksiyonların kronolojisi
- [ ] **4.2.5** **Post-mortem template** — incident kapandığında otomatik post-mortem raporu oluştur
- [ ] **4.2.6** **Lessons learned** — incident'tan öğrenilenleri kaydet, yeni kural öner

### 4.3 — Ticketing Entegrasyonu

- [ ] **4.3.1** **Jira** — REST API (create issue, transition, comment, close)
- [ ] **4.3.2** **ServiceNow** — Table API
- [ ] **4.3.3** **TheHive** — open-source case management API
- [ ] **4.3.4** **Linear** — GraphQL API
- [ ] **4.3.5** **GitHub Issues** — repo'ya issue aç (iç takım için)
- [ ] **4.3.6** İki yönlü sync — ticket kapandığında alert de kapanır, alert kapandığında ticket da kapanır

---

## 📡 Faz 5 — Ağ Sensörleri & Veri Toplama (Data Acquisition)

### 5.1 — Sensör Deployment Modelleri

- [ ] **5.1.1** **Inline sensör** — köprü modunda (bridge), L2 seviyesinde tüm trafiği görür, block yapabilir
- [ ] **5.1.2** **SPAN/Mirror sensör** — switch mirror port'una bağlı, passive-only
- [ ] **5.1.3** **TAP sensör** — network TAP cihazı arkasında, tam duplex görünürlük
- [ ] **5.1.4** **Endpoint sensör** — her sunucu/PC'ye kurulu lightweight agent (sadece o host'un trafiği)
- [ ] **5.1.5** **Cloud sensör** — AWS VPC Traffic Mirror / Azure vTap / GCP Packet Mirroring
- [ ] **5.1.6** **Container sensör** — Kubernetes DaemonSet, her node'da bir pod
- [ ] **5.1.7** **Virtual sensör** — VMware/Hyper-V virtual switch port mirror

### 5.2 — Yüksek Performanslı Capture

- [ ] **5.2.1** **AF_PACKET / AF_XDP** (Linux) — kernel-bypass capture, 10Gbps+ line rate
- [ ] **5.2.2** **PF_RING / DPDK** desteği — 40/100Gbps network'ler için
- [ ] **5.2.3** **Zero-copy pipeline** — packet buffer'ları copy'lemeden dissect → event → SIEM pipeline'ı
- [ ] **5.2.4** **Hardware timestamp** — NIC donanım timestamp'i ile nanosecond doğruluk
- [ ] **5.2.5** **Multi-core dissect** — her interface ayrı CPU core'unda (mevcut kod bunu yapıyor — iyileştir)
- [ ] **5.2.6** **Adaptive sampling** — CPU %90 üstüne çıkarsa 1/N paket örnekle, düşünce full capture'a dön

### 5.3 — Protokol Kapsamı (SOC için kritik olanlar)

- [ ] **5.3.1** Tam IDS/IPS kural seti uyumluluğu — Suricata/Emerging Threats kural formatı desteği
- [ ] **5.3.2** ICS/SCADA protokol derinliği — Modbus function code, S7comm job/ack, DNP3 object group detayı
- [ ] **5.3.3** Healthcare protokolleri — DICOM, HL7 v2/v3, FHIR derinlemesine
- [ ] **5.3.4** Finansal protokoller — FIX engine, SWIFT, ISO 8583
- [ ] **5.3.5** Bulut native protokoller — Kubernetes API, gRPC, GraphQL, Kafka wire protocol
- [ ] **5.3.6** VPN/Zero Trust protokolleri — WireGuard, Tailscale, ZeroTier, OpenZiti
- [ ] **5.3.7** PQC (Post-Quantum Crypto) trafik tespiti — mevcut `pqc_*` modüllerini SOC'a entegre et

---

## 🧠 Faz 6 — Anormallik Tespiti & AI/ML (Advanced Detection)

### 6.1 — Baseline & Anomaly

- [ ] **6.1.1** **Adaptive baseline** — her sensör için 7 günlük rolling baseline:
  - pkt/s, bytes/s, connection/s
  - unique src IP, unique dst IP, unique dst port
  - protocol distribution (%TCP, %UDP, %TLS, %DNS, ...)
- [ ] **6.1.2** **Seasonal decomposition** — haftanın günü + saate göre normal pattern (Pazartesi 09:00 spike'ı normal)
- [ ] **6.1.3** **Z-score / Modified Z-score** anormallik skorlaması
- [ ] **6.1.4** **Isolation Forest** — çok boyutlu anormallik (src IP entropy + dst port entropy + packet size variance)
- [ ] **6.1.5** **DBSCAN clustering** — normal trafik kümeleri dışında kalan outlier'lar
- [ ] **6.1.6** **Holt-Winters forecasting** — mevcut least-squares prediction'ı mevsimsellik destekli hale getir

### 6.2 — AI/ML Pipeline

- [ ] **6.2.1** **Feature extraction** — her connection için 50+ feature vektörü (süre, byte, pkt, flag'ler, entropy, ...)
- [ ] **6.2.2** **XGBoost / LightGBM classifier** — malicious vs benign connection sınıflandırma
- [ ] **6.2.3** **Autoencoder anomaly detection** — reconstruction error yüksekse anormal
- [ ] **6.2.4** **LLM-based triage** — alert detayını LLM'e özetletip ilk triage'ı otomatik yap (mevcut `llm_analytics` modülü üzerine inşa et)
- [ ] **6.2.5** **Model serving** — ONNX runtime ile cross-platform inference
- [ ] **6.2.6** **Model retraining pipeline** — ayda bir yeni veriyle retrain, A/B test, canary deploy
- [ ] **6.2.7** **Feedback loop** — analistin "FP" işaretlediği alert'ler eğitim verisine negatif örnek olarak eklenir

---

## 🔐 Faz 7 — Güvenlik & Uyumluluk (Security & Compliance)

### 7.1 — Platform Güvenliği

- [ ] **7.1.1** **RBAC** — role-based access control:
  - `admin` — her şey
  - `soc_manager` — alert yönetimi, raporlar, kullanıcı yönetimi
  - `soc_analyst_l2` — alert acknowledge, incident oluşturma, kural önerme
  - `soc_analyst_l1` — sadece alert görüntüleme, triage
  - `readonly` — dashboard görüntüleme
  - `auditor` — sadece rapor ve audit log
- [ ] **7.1.2** **MFA** — TOTP, WebAuthn (YubiKey) desteği
- [ ] **7.1.3** **SSO** — SAML 2.0, OIDC (Azure AD, Okta, Keycloak)
- [ ] **7.1.4** **API key** — servis hesabı için scoped API key (sadece event push, sadece alert read, ...)
- [ ] **7.1.5** **Audit log** — her kullanıcı aksiyonu kayıt altında (kim, ne zaman, ne yaptı, hangi IP'den)
- [ ] **7.1.6** **Tamper-proof log** — audit log'lar append-only, hash chain ile bütünlük doğrulamalı
- [ ] **7.1.7** **Secret management** — API key, token, password'ler için HashiCorp Vault / AWS Secrets Manager entegrasyonu
- [ ] **7.1.8** **Vulnerability scanning** — kendi ürününün bağımlılıklarını `cargo audit` + `npm audit` + Trivy ile tara, CI'da zorunlu

### 7.2 — Veri Gizliliği

- [ ] **7.2.1** **Payload maskeleme** — PCI-DSS (kredi kartı), PII (e-posta, telefon), HIPAA verilerini otomatik maskele
- [ ] **7.2.2** **IP anonymization** — raporlarda ve paylaşılan verilerde IP maskeleme (mevcut `IP anonymisation` özelliğini SOC'a entegre et)
- [ ] **7.2.3** **Veri saklama (retention)** — event ve alert'ler için configurable retention policy:
  - Raw events: 30 gün (varsayılan)
  - Alert'ler: 1 yıl
  - Audit log: 3 yıl
  - PCAP snapshot: 7 gün
- [ ] **7.2.4** **Auto-purge** — retention süresi dolan verileri otomatik sil (background job, throttled)
- [ ] **7.2.5** **Encryption at rest** — tüm veritabanı ve dosya depolama AES-256-GCM ile şifreli
- [ ] **7.2.6** **Right to erasure** — GDPR/KVKK "silme hakkı" için belirli bir IP'ye ait tüm verileri silme butonu

### 7.3 — Uyumluluk Raporları

- [ ] **7.3.1** **ISO 27001** — Annex A kontrol listesi mapping'i, uyum skoru
- [ ] **7.3.2** **PCI-DSS v4.0** — requirement mapping, ağ segmentasyonu görünürlüğü
- [ ] **7.3.3** **GDPR / KVKK** — kişisel veri içeren trafik raporu, data flow map
- [ ] **7.3.4** **NIS2** — kritik altyapı ağ izleme kanıtı raporu
- [ ] **7.3.5** **SOC 2 Type II** — ağ güvenliği kontrol kanıtı
- [ ] **7.3.6** **MITRE ATT&CK coverage** — hangi teknikleri tespit edebiliyoruz, hangilerini edemiyoruz matrisi
- [ ] **7.3.7** **Cyber Kill Chain coverage** — her faz için tespit kabiliyetimizin görsel haritası

---

## 📦 Faz 8 — Kurumsal Özellikler (Enterprise Features)

### 8.1 — Yüksek Erişilebilirlik (HA)

- [ ] **8.1.1** **Active-Passive failover** — 2 server, floating IP / keepalived
- [ ] **8.1.2** **Active-Active cluster** — N server, PostgreSQL streaming replication, Redis Sentinel
- [ ] **8.1.3** **Load balancer** — sensörler HAProxy/Nginx upstream'a bağlanır, sticky session
- [ ] **8.1.4** **Disaster recovery** — günlük off-site backup, 1 saat RTO, 5 dakika RPO
- [ ] **8.1.5** **Multi-site federation** — farklı DC'lerdeki server'lar arası alert/event paylaşımı

### 8.2 — Ölçeklenebilirlik

- [ ] **8.2.1** **Horizontal scaling** — sensör sayısı arttıkça server otomatik scale-out (K8s HPA)
- [ ] **8.2.2** **Event throughput benchmark** — tek server'da 100.000 event/saniye işleme hedefi
- [ ] **8.2.3** **ClickHouse / TimescaleDB** — yüksek hacimli event depolama için PostgreSQL alternatifi
- [ ] **8.2.4** **Data tiering** — sıcak veri (son 7 gün) SSD'de, soğuk veri S3/Blob'da
- [ ] **8.2.5** **Sharding** — tenant veya sensör başına ayrı DB shard (multi-tenant SaaS için)

### 8.3 — Multi-Tenancy

- [ ] **8.3.1** Tenant isolation — her tenant'ın sensörleri, alert'leri, kullanıcıları tamamen izole
- [ ] **8.3.2** Custom branding — tenant başına logo, renk, e-posta template
- [ ] **8.3.3** Usage metering — tenant başına event/saniye, sensör sayısı, storage limit
- [ ] **8.3.4** Tenant backup/restore — tek tenant'ın tüm verilerini export/import

### 8.4 — Deployment

- [ ] **8.4.1** **Docker Compose** — tek komutla server + DB + Redis + UI ayağa kaldırma
- [ ] **8.4.2** **Kubernetes Helm chart** — production-grade, tüm bileşenler
- [ ] **8.4.3** **Air-gapped deployment** — internet olmayan ortamda çalışabilme (offline MaxMind, offline NTP)
- [ ] **8.4.4** **Ansible playbook** — sensörlerin toplu kurulumu için
- [ ] **8.4.5** **Terraform module** — bulut altyapısını (VM, VPC, subnet, mirror) otomatik kurma

---

## 🧪 Faz 9 — Test & QA

### 9.1 — Test Stratejisi

- [ ] **9.1.1** **Unit test coverage ≥ 80%** — tüm yeni SOC modülleri için
- [ ] **9.1.2** **Integration test suite** — server + agent + SIEM connector uçtan uca test
- [ ] **9.1.3** **PCAP replay test** — bilinen kötü amaçlı pcap'leri replay edip alert'lerin tetiklendiğini doğrula
- [ ] **9.1.4** **Chaos engineering** — sensör kesintisi, ağ kopması, disk dolması senaryoları
- [ ] **9.1.5** **Soak test** — 7 gün boyunca 100 sensör simülasyonu, memory leak yok
- [ ] **9.1.6** **Performance regression** — her PR'da benchmark çalıştır (`criteria` veya `cargo bench`)
- [ ] **9.1.7** **Fuzzing** — SIEM event parser, kural motoru, API endpoint'leri `cargo fuzz` ile

### 9.2 — Test Verisi

- [ ] **9.2.1** **Synthetic traffic generator** — normal + şüpheli trafik üreten araç (mevcut `gen-fixtures` iyileştir)
- [ ] **9.2.2** **Malicious pcap library** — C2 beaconing, DGA DNS, SQLi, port scan, SMB exploit içeren pcap koleksiyonu
- [ ] **9.2.3** **Benchmark dataset** — 100 GB'lık gerçek enterprise network capture (anonimleştirilmiş)

---

## 📚 Faz 10 — Dokümantasyon & Eğitim

### 10.1 — Operasyonel Dokümanlar

- [ ] **10.1.1** **SOC Admin Guide** — kurulum, yapılandırma, HA, backup/restore, troubleshooting
- [ ] **10.1.2** **SOC Analyst Playbook** — alert triage, incident response, threat hunting adımları
- [ ] **10.1.3** **Rule Writing Guide** — etkili alert kuralı yazma rehberi, false positive azaltma
- [ ] **10.1.4** **API Reference** — OpenAPI 3.1 spec, tüm endpoint'ler dokümante
- [ ] **10.1.5** **Runbook library** — her alert tipi için adım adım müdahale runbook'u
- [ ] **10.1.6** **Architecture Decision Records (ADR)** — mimari kararların nedenleri
- [ ] **10.1.7** **Hardware sizing guide** — sensör/server için CPU/RAM/disk/network gereksinimleri

### 10.2 — Eğitim

- [ ] **10.2.1** **Interactive SOC onboarding** — netscope'un kendi Learn modunda SOC modu (mevcut `education` modülüne ek)
- [ ] **10.2.2** **CTF-style training lab** — içinde flag'ler olan zararlı pcap'ler
- [ ] **10.2.3** **Video tutorial series** — kurulum, alert triage, threat hunting, playbook yazma
- [ ] **10.2.4** **Certification program** — "netscope Certified SOC Analyst" (NCSA)

---

## 🗓 Uygulama Takvimi (Önerilen)

| Faz | Konu | Süre (Adam-Ay) | Öncelik |
|-----|------|-----------------|---------|
| **Faz 0** | Mimari Temel | 3-4 ay | 🔴 Critical — her şeyin temeli |
| **Faz 1** | SIEM Entegrasyonu | 2-3 ay | 🔴 Critical — mevcut `siem.rs` üzerine inşa |
| **Faz 2** | Alerting Motoru | 2-3 ay | 🔴 Critical — SOC'un kalbi |
| **Faz 3** | SOC Dashboard | 3-4 ay | 🟡 High — operatörlerin arayüzü |
| **Faz 4** | SOAR / Otomasyon | 3-4 ay | 🟡 High — analist yükünü azaltır |
| **Faz 5** | Ağ Sensörleri | 2-3 ay | 🟡 High — veri kalitesi |
| **Faz 6** | AI/ML Anormallik | 3-4 ay | 🟢 Medium — fark yaratır |
| **Faz 7** | Güvenlik & Uyumluluk | 2 ay | 🟢 Medium — enterprise satış için şart |
| **Faz 8** | Kurumsal Özellikler | 3 ay | 🟢 Medium — büyük müşteri için |
| **Faz 9** | Test & QA | Sürekli | 🔴 Her fazla paralel |
| **Faz 10** | Dokümantasyon | Sürekli | 🔴 Her fazla paralel |

> **Toplam:** ~20-30 adam-ay (3 senior developer × 8-10 ay)

---

## 🏁 Başlangıç İçin MVP (İlk 3 Ay)

Eğer tüm bunları birden yapmak mümkün değilse, **SOC MVP** olarak şunları öneririm:

1. [ ] `netscope-server` binary — REST API + PostgreSQL + Redis
2. [ ] `netscope-agent` — register, heartbeat, event push (mevcut capture engine + `siem.rs` event'lerini kullanarak)
3. [ ] Kural motoru — threshold ve signature tabanlı alert (mevcut `threat.rs` Suricata kural motoru üzerine)
4. [ ] 5 kritik alert kuralı (port scan, beaconing, data exfil, DGA DNS, lateral movement)
5. [ ] Slack + e-posta bildirimi
6. [ ] Basit Web UI — sensör durumu + alert listesi + acknowledge
7. [ ] Elasticsearch + Splunk HEC connector (mevcut `siem.rs` iyileştirilerek)

Bu MVP, 1 senior developer ile ~3 ayda tamamlanabilir ve hemen değer üretmeye başlar.

---

> **Legend:** 🔴 Critical Path · 🟡 High Priority · 🟢 Medium Priority
>
> Her checkbox, üretim kalitesinde bir SOC dağıtımı için gereken somut iş
> kalemidir. Sırayla işaretleyerek ilerleyin — her işaretlenen kutu, sistemi
> bir adım daha "muazzam" yapar.
