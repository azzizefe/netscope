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
- [x] **0.1.5** Redis cache katmanı — sensor heartbeat'leri, rate-limit, alert dedup için
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

- [x] **0.3.1** Server-side config store — her sensör için ayrı ayrı override edilebilir YAML/TOML config
- [x] **0.3.2** Config push — server'da config değişince sensöre otomatik push (WebSocket üzerinden)
- [x] **0.3.3** Config versioning — her değişiklik audit log'a kaydedilsin, rollback yapılabilsin
- [x] **0.3.4** Config validation — sensör config'i kabul etmeden önce server tarafında validate et (schema-based)

---

## 🔗 Faz 1 — SIEM Entegrasyonu (SIEM Integration)

> Mevcut `siem.rs` temel alınacak, enterprise-grade hale getirilecek.

### 1.1 — SIEM Format Desteği

- [x] **1.1.1** **Syslog (RFC 5424)** çıktı formatı — structured data + severity mapping
- [x] **1.1.2** **CEF (Common Event Format)** — ArcSight, McAfee ESM, Sumo Logic için
  ```
  CEF:0|netscope|netscope-agent|2.0|100|Suspicious Beaconing|5|src=10.0.0.5 dst=203.0.113.42 ...
  ```
- [x] **1.1.3** **LEEF (Log Event Extended Format)** — QRadar için
- [x] **1.1.4** **JSON Lines (NDJSON)** — Elasticsearch, Splunk HEC, Loki için (mevcut kod iyileştirilecek)
- [x] **1.1.5** **Raw PCAP export** — alert tetiklendiğinde ilgili .pcap parçasını otomatik dışa aktar

### 1.2 — SIEM Connector'lar

- [x] **1.2.1** **Elasticsearch connector** — mevcut `siem.rs` iyileştir: bulk indexing, index template, ILM policy, index rotation (`netscope-2026.07.27`)
- [x] **1.2.2** **Splunk HEC connector** — mevcut kod iyileştir: batching, retry, sourcetype mapping
- [x] **1.2.3** **Splunk TCP/UDP connector** — direkt Splunk Universal Forwarder'a syslog/CEF gönder
- [x] **1.2.4** **Graylog GELF connector** — GELF TCP/UDP çıktısı
- [x] **1.2.5** **Azure Sentinel connector** — Log Analytics Workspace API (DCR-based ingestion)
- [x] **1.2.6** **AWS Security Lake connector** — OCSF (Open Cybersecurity Schema Framework) formatında S3'e yaz
- [x] **1.2.7** **Wazuh connector** — Wazuh agent'a syslog/JSON event forward
- [x] **1.2.8** **Google Chronicle / SecOps** — Ingestion API (UDM format)
- [x] **1.2.9** **Kafka sink** — tüm event'leri Kafka topic'e yaz (Confluent/SaaS + self-hosted), SASL/SSL destekli
- [x] **1.2.10** **Loki sink** — Grafana Loki'ye direkt push (logQL ile alerting zinciri)

### 1.3 — SIEM Event Schema

- [x] **1.3.1** **OCSF uyumlu event modeli** — `SiemEvent` struct'ını OCSF 1.3.0 `security_finding` + `network_activity` class'larına uygun hale getir
- [x] **1.3.2** Event zenginleştirme (enrichment):
  - [x] GeoIP (MaxMind GeoLite2 — zaten mevcut)
  - [x] ASN / ISP bilgisi (MaxMind GeoLite2 ASN)
  - [x] Threat intel lookup (VirusTotal, AbuseIPDB — zaten mevcut)
  - [x] JA3/JA4 fingerprint (zaten mevcut)
  - [x] MAC vendor (OUI lookup — zaten mevcut)
  - [x] DNS passive resolution (zaten mevcut)
- [x] **1.3.3** Severity mapping standardizasyonu:
  ```
  netscope ExpertSeverity → SIEM severity (0-10)
    Chat    → 0 (Informational)
    Note    → 2-3 (Low)
    Warning → 5-6 (Medium)
    Error   → 8-9 (High)
  ```
- [x] **1.3.4** MITRE ATT&CK taktik/teknik mapping'i her event tipi için
- [x] **1.3.5** Cyber Kill Chain faz mapping'i her event tipi için

---

## 🚨 Faz 2 — Alerting Motoru (Alerting Engine)

> Merkezi, kural tabanlı, threshold + anomaly + correlation destekli.

### 2.1 — Alert Rule Engine

- [x] **2.1.1** Rule DSL (domain-specific language) — YAML tabanlı, mevcut display-filter syntax'ını genişlet:
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
- [x] **2.1.2** Kural tipleri:
  - [x] **Threshold** — X olay Y sürede Z kere olursa tetikle
  - [x] **Anomaly** — baseline'dan sapma (ör: normalde 100 pkt/sn → şu an 5000 pkt/sn)
  - [x] **Signature** — belirli pattern/IOC match olursa (mevcut YARA-lite + Suricata kural motoru)
  - [x] **Correlation** — birden fazla event'in ardışık/ilişkili gelmesi (ör: port scan → brute force → lateral movement)
  - [x] **Absence** — beklenen trafik Y süredir gelmiyorsa (ör: heartbeat kaybı)
  - [x] **Compound** — (A && B) || (C && !D) tipi boolean logic ile birden fazla kuralı birleştir
  - [x] **Time-based** — belirli saat/gün aralığında farklı threshold (mesai dışı = daha hassas)

- [x] **2.1.3** Alert deduplication — aynı (kural, src, dst) tuple'ı için N saniyede sadece 1 alert üret
- [x] **2.1.4** Alert suppression — belirli IP/subnet/vlan'dan gelen alert'leri sustur (maintenance window)
- [x] **2.1.5** Alert enrichment — alert oluştuğunda otomatik:
  - WHOIS sorgusu
  - Pasif DNS geçmişi (kendi DNS log'undan)
  - Bağlı olduğu diğer connection'lar
  - Aynı src IP'nin son 24 saatteki diğer alert'leri
- [x] **2.1.6** Alert correlation engine — farklı sensörlerden gelen alert'leri birleştir (ör: 3 farklı sensörde aynı dst IP'ye tarama)

### 2.2 — Smart Alert Triggers (Mevcut kodun iyileştirilmesi)

- [x] **2.2.1** **Traffic spike alert** — baseline'dan 3σ sapma (mevcut "smart alerts" kodunu kural motoruna taşı)
- [x] **2.2.2** **Error burst alert** — 1 dakikada 4xx/5xx sayısı normalin 5 katına çıkarsa
- [x] **2.2.3** **New host alert** — daha önce hiç görülmemiş bir IP ağda belirirse
- [x] **2.2.4** **New protocol alert** — daha önce bu network'te görülmemiş bir protokol tespit edilirse
- [x] **2.2.5** **Beaconing alert** — düzenli aralıklarla C2 benzeri check-in (mevcut heuristics iyileştir)
- [x] **2.2.6** **Data exfiltration alert** — outbound traffic > baseline + 100 MB (mevcut DLP iyileştir)
- [x] **2.2.7** **Privilege escalation alert** — düşük porttan yüksek porta SMB/RDP/SSH bağlantısı
- [x] **2.2.8** **Lateral movement alert** — bir host'un kısa sürede çok sayıda internal host'a bağlanması
- [x] **2.2.9** **DNS tunneling alert** — anormal uzunlukta/frekansda DNS sorguları
- [x] **2.2.10** **DGA domain alert** — entropy tabanlı domain generation algorithm tespiti (mevcut "suspicious domains" iyileştir)
- [x] **2.2.11** **Encrypted traffic anomaly** — normalde plaintext olması beklenen portta TLS (veya tersi)
- [x] **2.2.12** **Expired certificate alert** — TLS sertifikası expire olmuş bağlantı
- [x] **2.2.13** **Weak cipher alert** — TLS 1.0/1.1, RC4, 3DES, MD5 kullanan bağlantı
- [x] **2.2.14** **PQC migration gap alert** — PQC'ye geçmemiş kritik servis (mevcut `pqc_analytics` kullanarak)

### 2.3 — Alert Eskalasyon (Escalation)

- [x] **2.3.1** Eskalasyon seviyeleri (zaman bazlı):
  ```
  L1 (SOC Analyst) → 15 dk → L2 (Senior Analyst) → 30 dk → L3 (IR Lead) → 1 saat → CISO
  ```
- [x] **2.3.2** Eskalasyon policy — her kural için ayrı ayrı override edilebilir eskalasyon zinciri
- [x] **2.3.3** On-call schedule entegrasyonu — PagerDuty, Opsgenie, VictorOps API
- [x] **2.3.4** Shift rotation — haftalık nöbet çizelgesi, otomatik atama

### 2.4 — Bildirim Kanalları (Notification Channels)

- [x] **2.4.1** **E-posta** — SMTP/SMTPS, HTML + plaintext template, rate limit (max 1/dk)
- [x] **2.4.2** **Slack** — incoming webhook, formatted message + attachment (pcap snippet, event detail)
- [x] **2.4.5** **Telegram** — bot API
- [x] **2.4.11** **Syslog alert** — alert'leri de syslog olarak SIEM'e geri besleme (kapalı döngü)
- [x] **2.4.12** **Windows Event Log** — alert'leri yerel Event Viewer'a yaz (Windows sensörler için)
- [x] **2.4.13** **işletim sisteminde sekme açıp bilgilendirme**

---

## 📊 Faz 3 — SOC Dashboard (Web UI)

> Tauri masaüstü uygulamasına ek olarak, **browser-tabanlı** bir SOC operatör
> paneli. Bu panel netscope-server'ın içinde gömülü gelir.

### 3.1 — Ana Dashboard

- [x] **3.1.1** **7×24 Overview** — tek ekranda tüm sensörlerin durumu:
  - [x] Aktif sensör sayısı + online/offline badge
  - [x] Son 24 saatte toplam event sayısı
  - [x] Açık (acknowledge edilmemiş) alert sayısı (L1/L2/L3 kırılımlı)
  - [x] Son 1 saatte alert trend sparkline'ı
  - [x] Top 5 attacker src IP (iç + dış)
  - [x] Top 5 targeted dst IP
  - [x] Protocol distribution pie chart
  - [x] Network throughput (aggregate, tüm sensörler)
  - [x] MTTR (Mean Time to Resolve) son 7 gün
  - [x] False positive oranı son 7 gün
- [x] **3.1.2** **Dark theme** default — SOC operatörleri karanlık odada çalışır (mevcut Midnight/Dracula/Nord tema'larını Web UI'a portla)
- [x] **3.1.3** **Auto-refresh** — 5 saniyede bir WebSocket üzerinden canlı güncelleme
- [x] **3.1.4** **Responsive** — 1080p, 1440p, 4K ve ultrawide (21:9, 32:9) monitörler için fluid layout

### 3.2 — Sensör Yönetimi

- [x] **3.2.1** Sensör listesi grid view — hostname, IP, OS, versiyon, uptime, CPU, RAM, pkt/s, durum, son görülme
- [x] **3.2.2** Tek sensör detay sayfası:
  - [x] Canlı capture throughput grafiği (son 1 saat, 1 dk resolution)
  - [x] Aktif filter, yazılan pcap dosyası
  - [x] Son N event (sayfalı, filtrelenebilir)
  - [x] Sensöre komut gönder (capture restart, filter değiştir, pcap rotate)
  - [x] Sensör log'ları (son 1000 satır, canlı tail)
  - [x] Ağ topolojisi (o sensörün gördüğü host'ların force-directed graph'i)
- [x] **3.2.3** Toplu sensör operasyonu — N sensörü aynı anda güncelle, restart et, config push'la

### 3.3 — Alert Yönetimi

- [x] **3.3.1** Alert queue — triage board (TODO / Investigating / Resolved / False Positive)
- [x] **3.3.2** Alert detay sayfası:
  - [x] Hangi kural tetiklendi + kuralın YAML tanımı
  - [x] İlgili event'ler (timeline, packet detail)
  - [x] Kaynak ve hedef hakkında zenginleştirilmiş bilgi (GeoIP, ASN, threat intel)
  - [x] Acknowledge / Assign / Escalate / Close butonları
  - [x] Alert notları (analistler arası iletişim, Markdown destekli)
  - [x] İlgili pcap parçasını indir
  - [x] "Bunu araştıran diğer analistler" (collaboration)
  - [x] SOAR playbook tetikleme butonu
- [x] **3.3.3** Alert timeline — kronolojik sırada tüm alert + event akışı, görsel correlation çizgileriyle
- [x] **3.3.4** Alert bulk operations — N alert'i aynı anda kapat, FP işaretle, assign et

### 3.4 — Threat Hunting

- [x] **3.4.1** **Interactive query builder** — görsel display-filter builder (AND/OR/NOT blokları, drag & drop)
- [x] **3.4.2** **Histogram view** — seçilen filter için event frekansının zaman çizelgesi
- [x] **3.4.3** **Pivot** — bir event'ten başlayarak tüm ilişkili event'lere atlama:
  - Bu src IP başka nelere bağlanmış?
  - Bu dst IP'ye başka kimler bağlanmış?
  - Bu port'ta başka neler olmuş?
  - Bu JA3 fingerprint başka nerelerde görülmüş?
- [x] **3.4.4** **Saved searches** — sık kullanılan hunt query'leri kaydet, paylaş, alert'e dönüştür
- [x] **3.4.5** **Threat intel overlay** — search sonuçlarının üzerine VirusTotal/AbuseIPDB sonuçlarını overlay et

### 3.5 — Raporlama

- [x] **3.5.1** **Daily SOC report** — otomatik oluşan günlük özet:
  - Toplam event, alert (severity kırılımlı), resolved, FP
  - En aktif sensörler, en çok alert üreten kurallar
  - Yeni görülen IP/protocol/domain'ler
  - MTTR, ortalama acknowledge süresi
- [x] **3.5.2** **Weekly executive report** — PDF, yönetime sunulacak formatta
- [x] **3.5.3** **Monthly compliance report** — KVKK, GDPR, ISO 27001, PCI-DSS, NIS2 metrikleri
- [x] **3.5.4** **Custom report builder** — drag & drop ile özel rapor şablonu oluşturma
- [x] **3.5.5** **Scheduled report delivery** — e-posta ile otomatik gönderim (günlük/haftalık/aylık)
- [x] **3.5.6** **Executive KPI dashboard** — yönetim için sadeleştirilmiş, büyük rakamlı, yeşil/sarı/kırmızı renkli özet ekran

---

## 🤖 Faz 4 — SOAR / Otomasyon (Security Orchestration, Automation & Response)

### 4.1 — Playbook Engine

- [x] **4.1.1** **Playbook formatı** — YAML tabanlı, step-by-step:
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
- [x] **4.1.2** Built-in action'lar:
  - [x] `block_host` — Windows Firewall / iptables rule (mevcut `firewall.rs` üzerinden)
  - [x] `block_subnet` — /24 veya /16 block
  - [x] `quarantine_host` — 802.1X / NAC API ile port kapatma
  - [x] `snapshot_sensor` — o anki pcap buffer'ı diske yaz
  - [x] `start_full_capture` — sensörde full packet capture başlat
  - [x] `enrich_ip` / `enrich_domain` / `enrich_hash` — threat intel lookup
  - [x] `notify_slack` / `notify_teams` / `notify_email`
  - [x] `create_ticket` — Jira / ServiceNow / TheHive
  - [x] `run_script` — sensörde custom script çalıştır
  - [x] `send_syslog` / `send_snmp_trap`
  - [x] `isolate_host_via_edr` — CrowdStrike / SentinelOne API
  - [x] `dns_sinkhole` — Pi-hole / DNS server API ile domain block
- [x] **4.1.3** Condition engine — `{{.Field}} > X`, `contains`, `regex`, `in_list`
- [x] **4.1.4** Playbook debugger — kuru çalıştırma (dry run), step-by-step execution trace
- [x] **4.1.5** Playbook marketplace — topluluktan paylaşılan playbook'ları import et

### 4.2 — Incident Response

- [x] **4.2.1** **Case management** — alert → incident dönüştürme, case ID atama
- [x] **4.2.2** **Evidence locker** — incident'a bağlı tüm pcap, log, screenshot, not'ları bir arada tutma
- [x] **4.2.3** **Chain of custody** — her evidence parçası için timestamp + user damgası (adli bilişim uyumlu)
- [x] **4.2.4** **Incident timeline** — olayın başlangıcından kapanışına kadar tüm aksiyonların kronolojisi
- [x] **4.2.5** **Post-mortem template** — incident kapandığında otomatik post-mortem raporu oluştur
- [x] **4.2.6** **Lessons learned** — incident'tan öğrenilenleri kaydet, yeni kural öner

### 4.3 — Ticketing Entegrasyonu

- [x] **4.3.1** **Jira** — REST API (create issue, transition, comment, close)
- [x] **4.3.2** **ServiceNow** — Table API
- [x] **4.3.3** **TheHive** — open-source case management API
- [x] **4.3.4** **Linear** — GraphQL API
- [x] **4.3.5** **GitHub Issues** — repo'ya issue aç (iç takım için)
- [x] **4.3.6** İki yönlü sync — ticket kapandığında alert de kapanır, alert kapandığında ticket da kapanır

---

## 📡 Faz 5 — Ağ Sensörleri & Veri Toplama (Data Acquisition)

### 5.1 — Sensör Deployment Modelleri

- [x] **5.1.1** **Inline sensör** — köprü modunda (bridge), L2 seviyesinde tüm trafiği görür, block yapabilir
- [x] **5.1.2** **SPAN/Mirror sensör** — switch mirror port'una bağlı, passive-only
- [x] **5.1.3** **TAP sensör** — network TAP cihazı arkasında, tam duplex görünürlük
- [x] **5.1.4** **Endpoint sensör** — her sunucu/PC'ye kurulu lightweight agent (sadece o host'un trafiği)
- [x] **5.1.5** **Cloud sensör** — AWS VPC Traffic Mirror / Azure vTap / GCP Packet Mirroring
- [x] **5.1.6** **Container sensör** — Kubernetes DaemonSet, her node'da bir pod
- [x] **5.1.7** **Virtual sensör** — VMware/Hyper-V virtual switch port mirror

### 5.2 — Yüksek Performanslı Capture

- [x] **5.2.1** **AF_PACKET / AF_XDP** (Linux) — kernel-bypass capture, 10Gbps+ line rate
- [x] **5.2.2** **PF_RING / DPDK** desteği — 40/100Gbps network'ler için
- [x] **5.2.3** **Zero-copy pipeline** — packet buffer'ları copy'lemeden dissect → event → SIEM pipeline'ı
- [x] **5.2.4** **Hardware timestamp** — NIC donanım timestamp'i ile nanosecond doğruluk
- [x] **5.2.5** **Multi-core dissect** — her interface ayrı CPU core'unda (mevcut kod bunu yapıyor — iyileştir)
- [x] **5.2.6** **Adaptive sampling** — CPU %90 üstüne çıkarsa 1/N paket örnekle, düşünce full capture'a dön

### 5.3 — Protokol Kapsamı (SOC için kritik olanlar)

- [x] **5.3.1** Tam IDS/IPS kural seti uyumluluğu — Suricata/Emerging Threats kural formatı desteği
- [x] **5.3.2** ICS/SCADA protokol derinliği — Modbus function code, S7comm job/ack, DNP3 object group detayı
- [x] **5.3.3** Healthcare protokolleri — DICOM, HL7 v2/v3, FHIR derinlemesine
- [x] **5.3.4** Finansal protokoller — FIX engine, SWIFT, ISO 8583
- [x] **5.3.5** Bulut native protokoller — Kubernetes API, gRPC, GraphQL, Kafka wire protocol
- [x] **5.3.6** VPN/Zero Trust protokolleri — WireGuard, Tailscale, ZeroTier, OpenZiti
- [x] **5.3.7** PQC (Post-Quantum Crypto) trafik tespiti — mevcut `pqc_*` modüllerini SOC'a entegre et

---

## 📊 Faz 6 — İstatistiksel & Deterministik Anormallik Tespiti (Zero-Token / 100% Yerel)

### 6.1 — Yerel İstatistiksel Baseline & Anormallik Skorlaması

- [x] **6.1.1** **Hareketli Taban Çizgisi (Rolling Baseline)** — Her sensör için 100% yerel EWMA (Exponentially Weighted Moving Average) & Welford algoritması ile:
  - pkt/s, bytes/s, connection/s
  - Benzersiz kaynak IP, hedef IP, hedef port sayıları
  - Protokol dağılım oranları (%TCP, %UDP, %TLS, %DNS)
- [x] **6.1.2** **Mevsimsel Saat/Gün Matrisi** — Haftanın günü ve saate göre lokal geçmiş matrisi (Pazartesi 09:00 normal trafik profili)
- [x] **6.1.3** **Z-Score & IQR Outlier Tespiti** — Yerel standart sapma ve Interquartile Range (IQR) ile anormallik skorlaması
- [x] **6.1.4** **Shannon Entropi Hesaplama Motoru** — IP/Port dağılımı ve paket yükü entropisi üzerinden şüpheli tünelleme tespiti (Zero-token)
- [x] **6.1.5** **Pencere Tabanlı Frekans Analizi** — Son N saniyedeki kayan pencere (sliding window) bağlantı ve burst oranları

### 6.2 — Deterministik Triage & Kural Tabanlı Önceliklendirme

- [x] **6.2.1** **Lokal Öz Nitelik Çıkarımı (Feature Extraction)** — Her bağlantı için süre, bayt, paket, TCP bayrakları ve entropi değerlerinin yerel hesaplanması
- [x] **6.2.2** **Deterministik Risk Skorlama Motoru** — Kural ve istatistik tabanlı ağırlıklı tehdit puanlaması (0-100 Risk Score)
- [x] **6.2.3** **Otomatik Yerel Triage Engine** — LLM/Token kullanmadan, kural matrisi ve alarm korelasyonu ile anlık yerel triage (Zero-Token)
- [x] **6.2.4** **Yanlış Pozitif (FP) Bastırma & Beyaz Liste** — Statik/Dinamik beyaz liste ve analist onay mekanizması ile alarm gürültüsünü engelleme
- [x] **6.2.5** **Sıfır Dış Bağımlılık (100% Native Rust Engine)** — Harici API, LLM veya token maliyeti olmadan nano-saniye seviyesinde yerel analiz

---

## 🔐 Faz 7 — Güvenlik & Uyumluluk (Security & Compliance)

### 7.1 — Platform Güvenliği

- [x] **7.1.1** **RBAC** — role-based access control:
  - `admin` — her şey
  - `soc_manager` — alert yönetimi, raporlar, kullanıcı yönetimi
  - `soc_analyst_l2` — alert acknowledge, incident oluşturma, kural önerme
  - `soc_analyst_l1` — sadece alert görüntüleme, triage
  - `readonly` — dashboard görüntüleme
  - `auditor` — sadece rapor ve audit log
- [x] **7.1.2** **MFA** — TOTP, WebAuthn (YubiKey) desteği
- [x] **7.1.3** **SSO** — SAML 2.0, OIDC (Azure AD, Okta, Keycloak)
- [x] **7.1.4** **API key** — servis hesabı için scoped API key (sadece event push, sadece alert read, ...)
- [x] **7.1.5** **Audit log** — her kullanıcı aksiyonu kayıt altında (kim, ne zaman, ne yaptı, hangi IP'den)
- [x] **7.1.6** **Tamper-proof log** — audit log'lar append-only, hash chain ile bütünlük doğrulamalı
- [x] **7.1.7** **Secret management** — API key, token, password'ler için HashiCorp Vault / AWS Secrets Manager entegrasyonu
- [x] **7.1.8** **Vulnerability scanning** — kendi ürününün bağımlılıklarını `cargo audit` + `npm audit` + Trivy ile tara, CI'da zorunlu

### 7.2 — Veri Gizliliği

- [x] **7.2.1** **Payload maskeleme** — PCI-DSS (kredi kartı), PII (e-posta, telefon), HIPAA verilerini otomatik maskele
- [x] **7.2.2** **IP anonymization** — raporlarda ve paylaşılan verilerde IP maskeleme (mevcut `IP anonymisation` özelliğini SOC'a entegre et)
- [x] **7.2.3** **Veri saklama (retention)** — event ve alert'ler için configurable retention policy:
  - Raw events: 30 gün (varsayılan)
  - Alert'ler: 1 yıl
  - Audit log: 3 yıl
  - PCAP snapshot: 7 gün
- [x] **7.2.4** **Auto-purge** — retention süresi dolan verileri otomatik sil (background job, throttled)
- [x] **7.2.5** **Encryption at rest** — tüm veritabanı ve dosya depolama AES-256-GCM ile şifreli
- [x] **7.2.6** **Right to erasure** — GDPR/KVKK "silme hakkı" için belirli bir IP'ye ait tüm verileri silme butonu

### 7.3 — Uyumluluk Raporları

- [x] **7.3.1** **ISO 27001** — Annex A kontrol listesi mapping'i, uyum skoru
- [x] **7.3.2** **PCI-DSS v4.0** — requirement mapping, ağ segmentasyonu görünürlüğü
- [x] **7.3.3** **GDPR / KVKK** — kişisel veri içeren trafik raporu, data flow map
- [x] **7.3.4** **NIS2** — kritik altyapı ağ izleme kanıtı raporu
- [x] **7.3.5** **SOC 2 Type II** — ağ güvenliği kontrol kanıtı
- [x] **7.3.6** **MITRE ATT&CK coverage** — hangi teknikleri tespit edebiliyoruz, hangilerini edemiyoruz matrisi
- [x] **7.3.7** **Cyber Kill Chain coverage** — her faz için tespit kabiliyetimizin görsel haritası

---

## 📦 Faz 8 — Kurumsal Özellikler (Enterprise Features)

### 8.1 — Yüksek Erişilebilirlik (HA)

- [x] **8.1.1** **Active-Passive failover** — 2 server, floating IP / keepalived
- [x] **8.1.2** **Active-Active cluster** — N server, PostgreSQL streaming replication, Redis Sentinel
- [x] **8.1.3** **Load balancer** — sensörler HAProxy/Nginx upstream'a bağlanır, sticky session
- [x] **8.1.4** **Disaster recovery** — günlük off-site backup, 1 saat RTO, 5 dakika RPO
- [x] **8.1.5** **Multi-site federation** — farklı DC'lerdeki server'lar arası alert/event paylaşımı

### 8.2 — Ölçeklenebilirlik

- [x] **8.2.1** **Horizontal scaling** — sensör sayısı arttıkça server otomatik scale-out (K8s HPA)
- [x] **8.2.2** **Event throughput benchmark** — tek server'da 100.000 event/saniye işleme hedefi
- [x] **8.2.3** **ClickHouse / TimescaleDB** — yüksek hacimli event depolama için PostgreSQL alternatifi
- [x] **8.2.4** **Data tiering** — sıcak veri (son 7 gün) SSD'de, soğuk veri S3/Blob'da
- [x] **8.2.5** **Sharding** — tenant veya sensör başına ayrı DB shard (multi-tenant SaaS için)

### 8.3 — Multi-Tenancy

- [x] **8.3.1** Tenant isolation — her tenant'ın sensörleri, alert'leri, kullanıcıları tamamen izole
- [x] **8.3.2** Custom branding — tenant başına logo, renk, e-posta template
- [x] **8.3.3** Usage metering — tenant başına event/saniye, sensör sayısı, storage limit
- [x] **8.3.4** Tenant backup/restore — tek tenant'ın tüm verilerini export/import

### 8.4 — Deployment

- [x] **8.4.1** **Docker Compose** — tek komutla server + DB + Redis + UI ayağa kaldırma
- [x] **8.4.2** **Kubernetes Helm chart** — production-grade, tüm bileşenler
- [x] **8.4.3** **Air-gapped deployment** — internet olmayan ortamda çalışabilme (offline MaxMind, offline NTP)
- [x] **8.4.4** **Ansible playbook** — sensörlerin toplu kurulumu için
- [x] **8.4.5** **Terraform module** — bulut altyapısını (VM, VPC, subnet, mirror) otomatik kurma

---

## 🧪 Faz 9 — Test & QA

### 9.1 — Test Stratejisi

- [x] **9.1.1** **Unit test coverage ≥ 80%** — tüm yeni SOC modülleri için
- [x] **9.1.2** **Integration test suite** — server + agent + SIEM connector uçtan uca test
- [x] **9.1.3** **PCAP replay test** — bilinen kötü amaçlı pcap'leri replay edip alert'lerin tetiklendiğini doğrula
- [x] **9.1.4** **Chaos engineering** — sensör kesintisi, ağ kopması, disk dolması senaryoları
- [x] **9.1.5** **Soak test** — 7 gün boyunca 100 sensör simülasyonu, memory leak yok
- [x] **9.1.6** **Performance regression** — her PR'da benchmark çalıştır (`criteria` veya `cargo bench`)
- [x] **9.1.7** **Fuzzing** — SIEM event parser, kural motoru, API endpoint'leri `cargo fuzz` ile

### 9.2 — Test Verisi

- [x] **9.2.1** **Synthetic traffic generator** — normal + şüpheli trafik üreten araç (mevcut `gen-fixtures` iyileştir)
- [x] **9.2.2** **Malicious pcap library** — C2 beaconing, DGA DNS, SQLi, port scan, SMB exploit içeren pcap koleksiyonu
- [x] **9.2.3** **Benchmark dataset** — 100 GB'lık gerçek enterprise network capture (anonimleştirilmiş)

---

## 📚 Faz 10 — Dokümantasyon & Eğitim

### 10.1 — Operasyonel Dokümanlar

- [x] **10.1.1** **SOC Admin Guide** — kurulum, yapılandırma, HA, backup/restore, troubleshooting
- [x] **10.1.2** **SOC Analyst Playbook** — alert triage, incident response, threat hunting adımları
- [x] **10.1.3** **Rule Writing Guide** — etkili alert kuralı yazma rehberi, false positive azaltma
- [x] **10.1.4** **API Reference** — OpenAPI 3.1 spec, tüm endpoint'ler dokümante
- [x] **10.1.5** **Runbook library** — her alert tipi için adım adım müdahale runbook'u
- [x] **10.1.6** **Architecture Decision Records (ADR)** — mimari kararların nedenleri
- [x] **10.1.7** **Hardware sizing guide** — sensör/server için CPU/RAM/disk/network gereksinimleri

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
