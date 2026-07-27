# 📋 netscope — Uyumluluk Denetimi / KVKK · GDPR · PCI-DSS · ISO 27001 · NIS2 · MITRE ATT&CK

> **Mevcut durum:** `app.js` içinde rapor scrub (`scrubText()`), IP anonimleştirme
> (`anonymizeIps()`), Privacy X-ray (`analyzePrivacy()`), Insights otomatik
> güvenlik bulguları, ve `api_server.rs`'te forensic HTML raporu var. PQC
> tarafında `pqc_compliance_checker.rs` ile NIST/BSI/ANSSI/NSA CNSA/ETSI
> framework'lerine karşı denetim yapılabiliyor.
>
> **Ancak bunların hiçbiri formel bir uyumluluk raporu değil.** KVKK, GDPR,
> PCI-DSS, ISO 27001, NIS2, MITRE ATT&CK için **sıfır şablon, sıfır kontrol
> listesi, sıfır otomatik puanlama** var.
>
> Bu spesifikasyon, mevcut analiz verisini formel uyumluluk çerçevelerine
> otomatik olarak eşleyen bir sistemi adım adım tanımlar.

---

## 📐 Mevcut Durum Analizi

```
✅ VAR olan veri kaynakları (uyumluluk raporuna beslenebilecek):
  - Insights: cleartext passwords, unencrypted HTTP, port scans, beaconing,
    DGA domains, DNS exposure, encryption ratio, data exfiltration
  - Privacy X-ray: tracker categorization, cookie security flags, WAF
    detection, HTTP error rates, per-site risk score (0-100)
  - PQC compliance checker: NIST/BSI/ANSSI/CNSA/ETSI framework scoring
  - Report module: 📄 Export with 🛡 scrub + 🕶 anon toggles
  - Forensic HTML report: GET /api/v1/report
  - Per-site: Server header, CVE flags, busiest period, data volume
  - Protocol stats: distribution, encryption vs cleartext ratio
  - TLS: version, cipher, JA3/JA4 fingerprint, certificate status

❌ EKSİK olanlar (bu dokümanda ele alınacak):
  - KVKK uyumluluk raporu şablonu ve otomatik kontrol listesi
  - GDPR uyumluluk raporu şablonu ve otomatik kontrol listesi
  - PCI-DSS v4.0 ağ gereksinimleri denetim şablonu
  - ISO 27001:2022 Annex A kontrol eşleştirme
  - NIS2 kritik altyapı denetim kanıtı
  - MITRE ATT&CK taktik/teknik kapsama haritası
  - Cyber Kill Chain faz mapping'i
  - Uyumluluk skoru (pass/fail/warning her kontrol için)
  - Otomatik kanıt toplama (evidence collection)
  - Compliance drift detection (zaman içinde uyumluluk değişimi)
  - Politika-trafik karşılaştırması (gap analysis)
  - Zamanlanmış uyumluluk taramaları
  - PCI-DSS ağ segmentasyonu doğrulama
  - GDPR Article 30 veri akış haritası
  - DPIA (Veri Koruma Etki Değerlendirmesi) şablonu
```

---

## 🏛️ Faz 1 — Uyumluluk Çerçeve Motoru (Compliance Framework Engine)

> Her framework için ortak bir soyutlama katmanı. Yeni bir framework eklemek
> sadece YAML/JSON tanım dosyası yazmak kadar basit olmalı.

### 1.1 — Compliance Framework Tanım Formatı

- [ ] **1.1.1** Framework tanım şeması (YAML):
  ```yaml
  # compliance/frameworks/gdpr.yaml
  id: gdpr_2024
  name: "GDPR (EU 2016/679)"
  version: "2024"
  category: privacy
  jurisdiction: EU/EEA
  description: "General Data Protection Regulation — EU personal data protection"
  
  controls:
    - id: gdpr_art5_1f
      article: "Art. 5(1)(f)"
      title: "Integrity and confidentiality"
      description: "Personal data must be processed in a manner that ensures 
                    appropriate security, including protection against 
                    unauthorised or unlawful processing and against accidental 
                    loss, destruction or damage."
      severity: critical
      
      checks:
        - id: gdpr_art5_1f_encryption_transit
          name: "Encryption in transit"
          question: "Is all personal data traffic encrypted in transit?"
          type: ratio_threshold
          metric: tls_ratio
          operator: gte
          threshold: 0.95
          fail_message: "Less than 95% of web traffic is encrypted"
          evidence_query:
            type: protocol_ratio
            params:
              numerator: [Tls, Quic, Ssh]
              denominator: [Http, Tls, Quic, Smtp, Ftp, Telnet]
          
        - id: gdpr_art5_1f_weak_ciphers
          name: "No weak ciphers"
          question: "Are deprecated TLS versions and ciphers absent?"
          type: count_threshold
          metric: weak_tls_count
          operator: eq
          threshold: 0
          fail_message: "Detected TLS < 1.2 or weak cipher connections"
          evidence_query:
            type: event_count
            params:
              filter: "tls.version < 1.2 || tls.cipher in [RC4, 3DES, EXPORT]"
              
        - id: gdpr_art5_1f_cleartext_secrets
          name: "No cleartext credentials"
          question: "Are any passwords, tokens, or API keys sent in cleartext?"
          type: count_threshold
          metric: cleartext_secrets_count
          operator: eq
          threshold: 0
          fail_message: "Detected cleartext credentials in network traffic"
          evidence_query:
            type: insight_count
            params:
              finding: "cleartext passwords"
              
      # ... her GDPR article'ı için benzer kontroller
  ```
- [ ] **1.1.2** Framework tanım formatı — desteklenen check tipleri:
  - [ ] `ratio_threshold` — metrik oranı eşik değerle karşılaştır (örn: TLS oranı ≥ %95)
  - [ ] `count_threshold` — olay sayısı eşikle karşılaştır (örn: 0 weak cipher bağlantısı)
  - [ ] `boolean` — var/yok kontrolü (örn: WAF mevcut mu?)
  - [ ] `list_contains` — listede belirli bir değer var mı? (örn: kullanılan cipher'lar arasında AES-256-GCM var mı?)
  - [ ] `list_excludes` — listede belirli bir değer olmamalı (örn: kullanılan protokoller arasında Telnet olmamalı)
  - [ ] `range` — değer belirli aralıkta mı? (örn: ortalama oturum süresi 5-60 dk)
  - [ ] `trend` — zaman içinde iyileşiyor mu? (örn: encryption ratio artıyor mu?)
  - [ ] `composite` — birden fazla check'i AND/OR ile birleştir

### 1.2 — Compliance Engine (Rust)

- [ ] **1.2.1** `compliance` modülü (`crates/core/src/compliance.rs`):
  ```rust
  pub struct ComplianceFramework {
      pub id: String,            // "gdpr_2024"
      pub name: String,          // "GDPR (EU 2016/679)"
      pub version: String,
      pub category: ComplianceCategory,  // Privacy, Security, Financial, CriticalInfra
      pub controls: Vec<Control>,
  }
  
  pub struct Control {
      pub id: String,            // "gdpr_art5_1f"
      pub article: String,       // "Art. 5(1)(f)"
      pub title: String,
      pub description: String,
      pub severity: Severity,
      pub checks: Vec<Check>,
  }
  
  pub enum CheckType {
      RatioThreshold { metric: String, operator: CmpOp, threshold: f64 },
      CountThreshold { metric: String, operator: CmpOp, threshold: u64 },
      Boolean { metric: String },
      ListContains { metric: String, value: String },
      ListExcludes { metric: String, value: String },
      Range { metric: String, min: f64, max: f64 },
      Trend { metric: String, direction: TrendDir, window: Duration },
      Composite { logic: LogicOp, children: Vec<Check> },
  }
  
  pub struct ComplianceReport {
      pub framework: ComplianceFramework,
      pub generated_at: DateTime<Utc>,
      pub capture_duration: Duration,
      pub total_packets: u64,
      pub overall_score: f64,              // 0.0 - 100.0
      pub overall_verdict: Verdict,        // Compliant, PartiallyCompliant, NonCompliant
      pub controls: Vec<ControlResult>,
      pub evidence_summary: EvidenceSummary,
  }
  
  pub struct ControlResult {
      pub control_id: String,
      pub status: ControlStatus,           // Pass, Fail, Warning, NotApplicable, InsufficientData
      pub score: f64,                      // 0.0 - 100.0
      pub check_results: Vec<CheckResult>,
      pub evidence: Vec<EvidenceItem>,     // otomatik toplanan kanıtlar
      pub recommendation: Option<String>,  // başarısızsa düzeltme önerisi
  }
  ```
- [ ] **1.2.2** Framework YAML loader — `compliance/frameworks/*.yaml` dosyalarını oku, validate et, `ComplianceFramework` struct'ına parse et
- [ ] **1.2.3** Metric extractor — capture verisinden compliance metriklerini çıkar:
  - `tls_ratio`, `tls_version_distribution`, `cipher_suite_list`
  - `cleartext_secrets_count`, `unencrypted_http_hosts`
  - `weak_cookie_count`, `missing_security_headers_count`
  - `external_data_transfer_bytes`, `cross_border_transfer_count`
  - `port_scan_count`, `beaconing_host_count`
  - `waf_detected`, `ids_events_count`
  - `protocol_diversity`, `unknown_protocol_ratio`
  - `auth_protocol_usage` (Kerberos, LDAP, NTLM, RADIUS vs)
- [ ] **1.2.4** Scoring engine — her kontrol için 0-100 skor:
  - `Pass` = 100, `Fail` = 0
  - `Warning` = 50 (kısmi uyumluluk)
  - `NotApplicable` = ignore (ortalamaya katılmaz)
  - Genel skor = tüm applicable kontrollerin ağırlıklı ortalaması
  - Severity ağırlığı: critical ×3, high ×2, medium ×1, low ×0.5
- [ ] **1.2.5** Otomatik kanıt toplama — her check için `evidence_query` çalıştır, sonucu `EvidenceItem` olarak rapora ekle
- [ ] **1.2.6** Delta (drift) hesaplama — iki compliance raporu arasındaki fark:
  - Hangi kontroller `Pass → Fail` (compliance drift)?
  - Hangi kontroller `Fail → Pass` (iyileşme)?
  - Genel skor değişimi (trend sparkline)
- [ ] **1.2.7** Politika-trafik gap analysis — kullanıcı bir politika tanımlar ("Tüm trafik TLS 1.3 olmalı"), compliance engine bu politikayı gerçek trafiğe karşı kontrol eder

---

## 🔐 Faz 2 — KVKK Uyumluluk Denetimi

> **KVKK (Kişisel Verileri Koruma Kanunu, 6698 sayılı)** — Türkiye'nin veri
> koruma kanunu. GDPR ile %80 örtüşür ama kendine özgü maddeleri vardır.

### 2.1 — KVKK Kontrol Listesi

- [ ] **2.1.1** KVKK Madde 12 — Veri Güvenliği Yükümlülükleri:
  - [ ] **KVKK-12.1.a** "Kişisel verilerin hukuka aykırı işlenmesini önlemek" — Ağda tespit edilen anormal veri transferleri (DLP alert'leri, büyük outbound transfer)
  - [ ] **KVKK-12.1.b** "Kişisel verilere hukuka aykırı erişilmesini önlemek" — Yetkisiz erişim göstergeleri (port scan, brute force, lateral movement alert'leri)
  - [ ] **KVKK-12.1.c** "Kişisel verilerin muhafazasını sağlamak" — Şifreleme durumu: TLS kullanım oranı, weak cipher varlığı, plaintext protokol kullanımı
  - [ ] **KVKK-12.2** "Veri güvenliği ihlali bildirimi" — Tespit edilebilir ihlal göstergelerinin varlığı, alert'lerin süresi içinde fark edilme durumu
  - [ ] **KVKK-12.3** "Teknik tedbirlerin periyodik denetimi" — Bu raporun kendisi kanıt olarak kullanılabilir mi? (zaman damgalı, değiştirilemez)

- [ ] **2.1.2** KVKK Madde 4 — Genel İlkeler:
  - [ ] **KVKK-4.1.c** "İşlendikleri amaçla bağlantılı, sınırlı ve ölçülü olma" — Hangi veri tipleri ağda transfer ediliyor? Gereksiz veri toplama var mı?
  - [ ] **KVKK-4.1.d** "İşlendikleri amaç için gerekli olan süre kadar muhafaza edilme" — Retention policy uygulanıyor mu? PCAP/event/log'lar ne kadar saklanıyor?

- [ ] **2.1.3** KVKK Madde 9 — Yurt Dışına Veri Aktarımı:
  - [ ] **KVKK-9.1** Türkiye dışına giden veri akışlarının tespiti — GeoIP ile dış IP'lere giden bağlantılar
  - [ ] **KVKK-9.2** Yeterli korumanın bulunduğu ülkeler listesi (KVKK beyaz liste) ile karşılaştırma
  - [ ] **KVKK-9.3** Yeterli koruma olmayan ülkelere giden veri akışı uyarısı (örn: veri Çin'e/Rusya'ya gidiyor mu?)

- [ ] **2.1.4** KVKK VERBİS (Veri Sorumluları Sicili) uyumluluğu:
  - [ ] Hangi veri kategorileri işleniyor? (otomatik sınıflandırma: iletişim, lokasyon, finansal, sağlık, ...)
  - [ ] Veri işleme amaçları hangileri? (otomatik haritalama)
  - [ ] Alıcı/alıcı grupları kimler? (IP bazlı kuruluş tespiti)

### 2.2 — KVKK Rapor Şablonu

- [ ] **2.2.1** Şablon çıktı formatları:
  - [ ] **HTML rapor** — Kurum logosu eklenebilir, yazdırılabilir, PDF'e çevrilebilir
  - [ ] **Markdown rapor** — Git repo'da saklanabilir, diff alınabilir
  - [ ] **PDF rapor** — Resmi makamlara sunulabilecek formatta (imza satırı, tarih, denetçi adı)
  - [ ] **JSON rapor** — Otomasyona beslenebilir (SIEM/SOAR entegrasyonu)

- [ ] **2.2.2** Rapor İçeriği:
  ```
  📋 KVKK Uyumluluk Denetim Raporu
  ══════════════════════════════════
  
  Denetim Bilgileri
  ├── Denetim tarihi: 2026-07-27 14:30:00 +03
  ├── Denetim kapsamı: 192.168.1.0/24 ağ segmenti
  ├── İncelenen paket: 1,247,832
  ├── İnceleme süresi: 24 saat (26 Tem 14:30 → 27 Tem 14:30)
  └── netscope versiyonu: 0.2.0
  
  Bölüm 1: Genel Uyumluluk Skoru
  ├── Genel skor: 72/100 ⚠️ Kısmi Uyumlu
  ├── Kritik kontroller: 3/4 ✅
  ├── Yüksek öncelikli: 5/8 ⚠️
  ├── Orta öncelikli: 4/6 ⚠️
  └── Düşük öncelikli: 2/2 ✅
  
  Bölüm 2: Madde 12 — Veri Güvenliği (Detay)
  ├── KVKK-12.1.a Hukuka aykırı işleme önlemi
  │   ├── ✅ Veri sızıntısı tespiti: 0 olay — Başarılı
  │   ├── ⚠️ Büyük veri transferi: 3 olay (toplam 847 MB) — Uyarı
  │   └── Kanıt: [Ek A — DLP alert log'u]
  │
  ├── KVKK-12.1.b Hukuka aykırı erişim önlemi
  │   ├── ❌ Port tarama girişimi: 12 olay — Başarısız
  │   ├── ✅ Brute force: 0 olay — Başarılı
  │   └── Öneri: 185.220.101.x bloğuna firewall rule ekleyin
  │
  └── KVKK-12.1.c Veri muhafazası
      ├── ✅ TLS kullanım oranı: %97.3 — Başarılı (eşik: %95)
      ├── ⚠️ Weak cipher bağlantı: 5 olay (TLS 1.0) — Uyarı
      ├── ❌ Plaintext HTTP: 3 host tespit edildi — Başarısız
      └── Kanıt: [Ek B — TLS versiyon dağılım grafiği]
  
  Bölüm 3: Madde 9 — Yurt Dışı Veri Aktarımı
  ├── Toplam dış bağlantı: 847
  ├── KVKK yeterli koruma listesinde: 823 (%97.2)
  ├── Yeterli koruma OLMAYAN ülkelere: 24 bağlantı ⚠️
  │   ├── 🇨🇳 Çin: 15 bağlantı, 2.3 MB
  │   ├── 🇷🇺 Rusya: 7 bağlantı, 0.8 MB
  │   └── 🇮🇷 İran: 2 bağlantı, 0.1 MB
  └── Kanıt: [Ek C — GeoIP dış bağlantı haritası]
  
  Bölüm 4: Önerilen Düzeltici Aksiyonlar
  ├── 1. [Kritik] 185.220.101.0/24 bloğuna firewall rule ekleyin
  ├── 2. [Yüksek] TLS 1.0/1.1'i sunucularda devre dışı bırakın
  ├── 3. [Yüksek] Plaintext HTTP servisleri HTTPS'e taşıyın
  ├── 4. [Orta]  Yurt dışı veri aktarımı policy'si oluşturun
  └── 5. [Orta]  Aylık otomatik denetim zamanlayın
  
  Ekler
  ├── Ek A: DLP alert log'u (24 saat)
  ├── Ek B: TLS versiyon dağılım grafiği
  ├── Ek C: GeoIP dış bağlantı haritası
  └── Ek D: Denetim hash'i (SHA-256): a1b2c3... (bütünlük doğrulaması)
  ```
- [ ] **2.2.3** Rapor imza/blokzincir — rapor hash'i hesaplansın, opsiyonel olarak Ethereum/zkSync'e yazılsın (denetim kanıtı)
- [ ] **2.2.4** KVKK başvuru formu entegrasyonu — ilgili kişi başvurusu için gerekli veri haritası

---

## 🇪🇺 Faz 3 — GDPR Uyumluluk Denetimi

> KVKK ile %80 aynı altyapı. GDPR'a özgü ek kontroller:

### 3.1 — GDPR'a Özgü Kontroller

- [ ] **3.1.1** Article 5 — Principles relating to processing of personal data:
  - [ ] **GDPR-5.1.f** Integrity & confidentiality (KVKK-12 ile aynı motor, farklı eşikler)
  - [ ] **GDPR-5.1.c** Data minimisation — Gereksiz veri toplama tespiti (User-Agent, Referer, unnecessary headers)
  - [ ] **GDPR-5.1.e** Storage limitation — Retention policy kanıtı

- [ ] **3.1.2** Article 30 — Records of processing activities:
  - [ ] **GDPR-30.1** Otomatik veri akış haritası (hangi IP'den hangi IP'ye, hangi veri kategorisi)
  - [ ] **GDPR-30.1.a** Controller bilgisi (DNS + WHOIS lookup)
  - [ ] **GDPR-30.1.b** Processing amaçları (HTTP path + User-Agent analizi)
  - [ ] **GDPR-30.1.c** Veri kategorileri (DICOM = sağlık, FIX = finansal, HTTP form = kişisel)
  - [ ] **GDPR-30.1.d** Alıcı kategorileri (tracker/ad network sınıflandırması — zaten Privacy tab'de var)
  - [ ] **GDPR-30.1.e** Cross-border transfer (GeoIP — KVKK-9 ile aynı altyapı)
  - [ ] **GDPR-30.1.f** Retention süreleri (sistem config'inden oku)

- [ ] **3.1.3** Article 32 — Security of processing:
  - [ ] **GDPR-32.1.a** Pseudonymisation & encryption (TLS ratio, cipher strength)
  - [ ] **GDPR-32.1.b** Ongoing CIA (mevcut Insights verisi: availability = error rate, integrity = malformed pkts, confidentiality = encryption)
  - [ ] **GDPR-32.1.c** Incident response capability (alert → acknowledge süresi)
  - [ ] **GDPR-32.2** Risk assessment (mevcut risk score 0-100'ü framework'e entegre et)

- [ ] **3.1.4** Article 33-34 — Breach notification:
  - [ ] **GDPR-33.1** 72 saat içinde bildirim — İhlal göstergesi bulundu mu? Ne zaman tespit edildi? Süre hesabı
  - [ ] **GDPR-34.1** Data subject notification — Hangi kişisel veriler etkilendi? (otomatik sınıflandırma)

- [ ] **3.1.5** Article 35 — Data Protection Impact Assessment (DPIA):
  - [ ] Otomatik DPIA ön raporu — hangi veri işleme operasyonları yüksek riskli?
  - [ ] Risk matrisi: olasılık × etki = her veri akışı için skor
  - [ ] Azaltıcı kontrollerin listesi (encryption, access control, monitoring)

### 3.2 — GDPR Rapor Şablonu

- [ ] **3.2.1** KVKK şablonuyla aynı yapı, ek olarak:
  - [ ] Article 30 processing activities tablosu (Excel/CSV export)
  - [ ] DPIA summary section
  - [ ] Supervisory authority (DPC/ICO/CNIL/...) bildirim hazırlığı
  - [ ] DPO (Data Protection Officer) imza satırı
  - [ ] İngilizce + yerel dil opsiyonu (çok uluslu şirket için)

---

## 💳 Faz 4 — PCI-DSS v4.0 Uyumluluk Denetimi

> PCI-DSS (Payment Card Industry Data Security Standard) v4.0 — ağ
> güvenliği gereksinimlerine odaklanan kontroller.

### 4.1 — PCI-DSS Ağ Kontrolleri

- [ ] **4.1.1** Requirement 1 — Install and Maintain Network Security Controls:
  - [ ] **PCI-1.2.1** Inbound/outbound traffic restriction — Hangi port'lar dışarı açık? Baseline'dan sapma var mı?
  - [ ] **PCI-1.2.2** Firewall rule audit — Mevcut firewall rule'ları (netscope + OS) listele, PCI kapsamındaki sistemlere erişimi doğrula
  - [ ] **PCI-1.2.3** Network segmentation (CDE isolation) — Cardholder Data Environment (CDE) ağı, diğer ağlardan izole mi? CDE → non-CDE trafik analizi
  - [ ] **PCI-1.2.4** Configuration review — 6 ayda bir firewall rule review kanıtı
  - [ ] **PCI-1.3.2** DMZ isolation — DMZ'den internal ağa yetkisiz bağlantı var mı?
  - [ ] **PCI-1.4.1** Network security controls (NSC) — IDS/IPS aktif mi? (netscope Suricata kural motoru kanıt olarak)

- [ ] **4.1.2** Requirement 2 — Apply Secure Configurations:
  - [ ] **PCI-2.2.4** Only necessary ports — Dinlenen port'ların listesi, beklenmeyen port uyarısı
  - [ ] **PCI-2.2.5** Service enumeration — Ağda tespit edilen servisler, PCI scope dışı servis uyarısı

- [ ] **4.1.3** Requirement 4 — Protect Cardholder Data with Strong Cryptography:
  - [ ] **PCI-4.1.1** Strong cryptography — TLS 1.2+ zorunlu, weak cipher kontrolü (mevcut TLS analizi)
  - [ ] **PCI-4.2.1** PAN (Primary Account Number) detection — Ağda kredi kartı numarası pattern'i tespiti (Luhn algoritması + regex: `\b[34]\d{15}\b`, `\b[45]\d{15}\b`, `\b5[1-5]\d{14}\b`)
  - [ ] **PCI-4.2.2** PAN over open networks — PAN tespit edildiğinde, şifreli kanalda mı gidiyor?
  - [ ] **PCI-4.2.3** PAN storage detection — PAN'ın log/pcap'te saklanması uyarısı (auto-mask öner)

- [ ] **4.1.4** Requirement 6 — Develop and Maintain Secure Systems:
  - [ ] **PCI-6.3.1** Vulnerability identification — Server header CVE tespiti (mevcut)
  - [ ] **PCI-6.4.3** Payment page script integrity — Ödeme sayfasındaki 3. parti script'ler (analyzePrivacy'deki tracker verisi)

- [ ] **4.1.5** Requirement 10 — Log and Monitor:
  - [ ] **PCI-10.1** Audit log mechanism — netscope audit log'un PCI uyumlu olduğunun kanıtı
  - [ ] **PCI-10.2.1** Audit log content — PCI gereksinimlerini karşılıyor mu kontrolü
  - [ ] **PCI-10.4.1** Time synchronization — NTP kullanımı kontrolü
  - [ ] **PCI-10.7** Retention — 12 ay online + 3 yıl archive kanıtı

- [ ] **4.1.6** Requirement 11 — Test Security of Systems and Networks:
  - [ ] **PCI-11.3.1** External vulnerability scan — ASV (Approved Scanning Vendor) taraması değil ama iç görünürlük
  - [ ] **PCI-11.4.1** IDS/IPS coverage — Suricata kural sayısı, alert trendi
  - [ ] **PCI-11.4.2** IDS/IPS alert response — Alert → acknowledge süresi (SOC metrikleri)
  - [ ] **PCI-11.4.3** IDS/IPS maintenance — Kural güncelleme tarihi
  - [ ] **PCI-11.5.1** Change detection — Ağda yeni host/protokol tespit edildiğinde alert (mevcut "new host alert")

### 4.2 — PCI-DSS Rapor Şablonu

- [ ] **4.2.1** ROC (Report on Compliance) formatına uygun yapı:
  ```
  📋 PCI-DSS v4.0 Ağ Güvenliği Uyumluluk Denetimi
  ═══════════════════════════════════════════════
  
  Denetim Bilgileri
  ├── Denetim tarihi: ...
  ├── CDE segmenti: 10.0.1.0/24 (POS terminaller)
  ├── Denetim tipi: Self-Assessment (SAQ-D)
  └── ...
  
  Her Requirement için:
  ├── Control ID, PCI-4.x.y
  ├── Durum: ✅ In Place / ⚠️ In Place with Remediation / ❌ Not In Place / N/A
  ├── Test Prosedürü: Otomatik uygulanan test
  ├── Bulgu: Otomatik tespit edilen sonuç
  ├── Kanıt: Ek X — otomatik toplanan log/pcap/grafik
  └── Düzeltici aksiyon: Otomatik öneri
  
  Özet:
  ├── Toplam kontrol: 42
  ├── In Place: 33 (%78.6)
  ├── In Place with Remediation: 5 (%11.9)
  ├── Not In Place: 4 (%9.5)
  └── Compliance: ⚠️ PARTIAL — 4 kontrol başarısız
  ```

---

## 🔬 Faz 5 — ISO 27001:2022 Uyumluluk Denetimi

- [ ] **5.1** Annex A kontrol eşleştirmesi (ağ ile ilgili olanlar):

| Annex A Control | netscope Denetimi |
|-----------------|-------------------|
| **A.5.1** Policies for InfoSec | Politika-trafik gap analysis |
| **A.5.15** Access control | RBAC audit, yetkisiz erişim alert'leri |
| **A.5.17** Authentication info | MFA kullanımı, plaintext auth tespiti |
| **A.8.1** User endpoint devices | Endpoint sensör ile cihaz envanteri |
| **A.8.7** Malware protection | Suricata kural hit'leri, IOC tespiti |
| **A.8.8** Technical vulnerability mgmt | Server CVE, weak cipher, TLS version |
| **A.8.12** Data leakage prevention | DLP alert'leri, büyük outbound transfer |
| **A.8.14** Network segregation | Ağ segmentasyonu görünürlüğü, cross-segment trafik |
| **A.8.16** Monitoring activities | 7×24 sensör uptime, alert volume, MTTR |
| **A.8.20** Network security | IDS/IPS kapsamı, firewall rule audit |
| **A.8.21** Security of network services | Servis envanteri, beklenmeyen protokol |
| **A.8.22** Segregation in networks | CDE/PCI benzeri segmentasyon |
| **A.8.24** Cryptographic controls | TLS version/cipher denetimi, PQC readiness |
| **A.5.28** Evidence of compliance | Otomatik rapor + hash chain kanıt |
| **A.5.29** InfoSec in disruption | Incident response metrikleri |
| **A.5.33** Records of processing | GDPR Art.30'a denk — veri akış haritası |
| **A.8.15** Logging | Audit log completeness, PCI-10 benzeri |
| **A.8.17** Clock sync | NTP kullanımı kanıtı |

- [ ] **5.2** ISO 27001 rapor şablonu — Annex A mapping tablosu + SoA (Statement of Applicability) formatı
- [ ] **5.3** ISMS (Information Security Management System) uyumluluk skoru ve trend takibi

---

## 🏭 Faz 6 — NIS2 Kritik Altyapı Denetimi

> NIS2 (EU Directive 2022/2555) — kritik altyapı sektörleri için siber
> güvenlik gereksinimleri.

- [ ] **6.1** NIS2 Article 21 — Risk management measures:
  - [ ] **NIS2-21.2.a** Policies on risk analysis and infoSec — Ağ risk analizi (risk score 0-100, trend)
  - [ ] **NIS2-21.2.b** Incident handling — Incident detection/response metrikleri
  - [ ] **NIS2-21.2.c** Business continuity — Sensör uptime, ağ kesintisi tespiti
  - [ ] **NIS2-21.2.d** Supply chain security — 3. parti servis bağlantıları (tracker/analytics/CDN sınıflandırması)
  - [ ] **NIS2-21.2.e** Security in network acquisition — (out of scope — donanım/yazılım tedariki)
  - [ ] **NIS2-21.2.f** Security effectiveness assessment — Otomatik penetration test değil ama güvenlik metrikleri
  - [ ] **NIS2-21.2.g** Crypto policies — TLS/PQC denetimi
  - [ ] **NIS2-21.2.h** Human resources security — (out of scope)
  - [ ] **NIS2-21.2.i** Access control — RBAC audit
  - [ ] **NIS2-21.2.j** Asset management — Ağ envanteri (host'lar, servisler, protokoller)

- [ ] **6.2** NIS2 Article 23 — Reporting obligations:
  - [ ] **NIS2-23.1** Significant incident — 24 saat içinde erken uyarı
  - [ ] **NIS2-23.4** Final report — 1 ay içinde nihai rapor şablonu

- [ ] **6.3** Sektör-spesifik ek kontroller:
  - [ ] Enerji sektörü (IEC 62443, IEC 62351) — ICS/SCADA protokol güvenliği (Modbus auth, DNP3 SA, OPC UA Secure)
  - [ ] Sağlık sektörü (HIPAA benzeri) — DICOM/HL7 şifreleme kontrolü
  - [ ] Finans sektörü (DORA) — Dijital operasyonel dayanıklılık testi
  - [ ] Ulaşım sektörü — CAN/EtherCAT/Profinet güvenlik denetimi

---

## ⚔️ Faz 7 — MITRE ATT&CK Kapsama Haritası

> Mevcut Insights/Suricata/threat detection'ların hangi MITRE ATT&CK
> tekniklerini kapsadığını otomatik olarak haritalama.

### 7.1 — MITRE ATT&CK Mapping Motoru

- [ ] **7.1.1** Detection → ATT&CK technique mapping tanım dosyası (`compliance/mitre_attack_mapping.yaml`):
  ```yaml
  mappings:
    - detection: "Port scan detected"
      technique: T1046
      name: "Network Service Discovery"
      tactic: "Discovery"
      confidence: high
    
    - detection: "Cleartext password in HTTP"
      technique: T1040
      name: "Network Sniffing"
      tactic: "Credential Access"
      confidence: medium
      
    - detection: "Suspicious beaconing"
      technique: T1071.001
      name: "Web Protocols (C2)"
      tactic: "Command and Control"
      confidence: medium
      
    - detection: "Lateral movement detected"
      technique: T1021
      name: "Remote Services"
      tactic: "Lateral Movement"
      confidence: medium
      
    - detection: "DNS tunneling"
      technique: T1071.004
      name: "DNS (C2)"
      tactic: "Command and Control"
      confidence: medium
      
    - detection: "Data exfiltration (large outbound)"
      technique: T1041
      name: "Exfiltration Over C2 Channel"
      tactic: "Exfiltration"
      confidence: low
      
    - detection: "JA3/JA4 fingerprint — C2 tool"
      technique: T1071
      name: "Application Layer Protocol (C2)"
      tactic: "Command and Control"
      confidence: medium
      
    - detection: "Brute force login"
      technique: T1110
      name: "Brute Force"
      tactic: "Credential Access"
      confidence: high
    
    # ... her detection için bir mapping
  ```
- [ ] **7.1.2** ATT&CK matrix verisi — MITRE ATT&CK STIX verisini (`enterprise-attack.json`) indir, parse et, güncel tut (haftalık cron)
- [ ] **7.1.3** Coverage hesaplama:
  - Toplam ATT&CK teknik sayısı: ~200 (Enterprise matrix v16)
  - netscope'un kapsayabildiği: mapping'deki teknikler
  - Coverage oranı: `kapsanan / toplam * 100`
  - Taktik bazında kapsama: Her taktik için ayrı oran

### 7.2 — ATT&CK Görselleştirmesi

- [ ] **7.2.1** **ATT&CK Navigator katmanı** (heatmap JSON export):
  ```json
  {
    "name": "netscope coverage",
    "versions": {"attack": "16", "navigator": "5.1.0"},
    "domain": "enterprise-attack",
    "techniques": [
      {"techniqueID": "T1046", "score": 100, "comment": "Port scan detection"},
      {"techniqueID": "T1071.001", "score": 75, "comment": "Beaconing detection (interval-based)"},
      {"techniqueID": "T1110", "score": 100, "comment": "Brute force alert"},
      {"techniqueID": "T1566", "score": 0,  "comment": "Not covered — phishing"}
    ],
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100}
  }
  ```
  → Bu JSON, [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)'a doğrudan import edilebilir.

- [ ] **7.2.2** **In-app ATT&CK matrix** — Dashboard'da interaktif heatmap:
  - Yeşil: netscope'un yüksek güvenle tespit edebildiği
  - Sarı: orta güvenle / kısmen tespit edebildiği
  - Kırmızı: tespit edemediği (boşluk — "bilinçli kör nokta")
  - Hücreye tıklayınca: teknik detayı + hangi netscope detection'ı eşleşiyor + hangi veri kaynağı

- [ ] **7.2.3** **Gap analysis raporu** — "Bu ay ATT&CK kapsaman %34 → geçen ay %32, 2 yeni teknik eklendi"
- [ ] **7.2.4** **Öneri motoru** — Hangi eksik teknikler için hangi detection kuralları yazılmalı?

### 7.3 — Cyber Kill Chain Mapping

- [ ] **7.3.1** Her detection → Kill Chain fazı:
  ```
  1. Reconnaissance    — Port scan, DNS enumeration
  2. Weaponization     — (ağda görülmez — out of scope)
  3. Delivery          — Malware download (HTTP .exe/.dll, Suricata hit)
  4. Exploitation      — Log4Shell, Shellshock signature match
  5. Installation      — C2 beaconing (ilk check-in)
  6. Command & Control — C2 beaconing, DNS tunneling, JA3/JA4 C2 fingerprint
  7. Actions on Obj.   — Data exfiltration, lateral movement
  ```
- [ ] **7.3.2** Kill Chain dashboard — 7 fazın her biri için doluluk oranı (progress bar)
- [ ] **7.3.3** Kill Chain gap: "Reconnaissance ve C2 tespit edebiliyoruz ama Exploitation'da körüz"

---

## 📊 Faz 8 — Uyumluluk Dashboard (Web UI)

- [ ] **8.1** **Compliance overview sayfası** (yeni tab: 📋 Compliance):
  ```
  ┌─────────────────────────────────────────────┐
  │ 📋 Compliance Dashboard                      │
  │                                              │
  │ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
  │ │ KVKK     │ │ GDPR     │ │ PCI-DSS  │ ...  │
  │ │ 72/100 ⚠️│ │ 68/100 ⚠️│ │ 78/100 ⚠️│      │
  │ │ 3 ❌     │ │ 2 ❌     │ │ 4 ❌     │      │
  │ └──────────┘ └──────────┘ └──────────┘      │
  │                                              │
  │ ┌──────────────────────────────────────────┐ │
  │ │ Skor Trendi (son 6 ay)                   │ │
  │ │ 📈 58 → 65 → 72 (KVKK)                   │ │
  │ └──────────────────────────────────────────┘ │
  │                                              │
  │ ┌──────────────────────────────────────────┐ │
  │ │ MITRE ATT&CK Coverage: 34% (68/200)      │ │
  │ │ ████████░░░░░░░░░░░░░░░░░░ 34%            │ │
  │ │ Son 1 ayda +2 teknik eklendi              │ │
  │ └──────────────────────────────────────────┘ │
  └─────────────────────────────────────────────┘
  ```
- [ ] **8.2** Framework detay sayfası — her framework için tüm kontroller, filtreleme (pass/fail/warning), drill-down
- [ ] **8.3** Evidence browser — her kontrolün altında otomatik toplanan kanıtlar (log snippet, grafik, event list)
- [ ] **8.4** Rapor zamanlama — haftalık/aylık otomatik compliance raporu (e-posta, Slack)
- [ ] **8.5** Compliance export — PDF (resmi), HTML (interaktif), JSON (API), CSV (Excel)

---

## 🧪 Faz 9 — Test & Doğrulama

- [ ] **9.1** Her framework için YAML şema validasyon testi
- [ ] **9.2** Metrik hesaplama doğruluk testi (bilinen pcap ile beklenen metrik karşılaştırması)
- [ ] **9.3** PCI-DSS Luhn algoritması doğruluk testi (1 milyon rastgele sayı)
- [ ] **9.4** MITRE ATT&CK mapping bütünlük testi (tüm teknik ID'leri geçerli mi?)
- [ ] **9.5** Rapor formatı regression testi (şablon değişince çıktı bozulmadı mı?)
- [ ] **9.6** KVKK/GDPR mevzuat değişikliği algılama — framework YAML'ları güncel mi? (yarı otomatik)
- [ ] **9.7** False positive analizi — compliance raporundaki her "Fail" gerçekten fail mi?

---

## 📦 Faz 10 — Paket & Deployment

- [ ] **10.1** Framework paket yapısı:
  ```
  compliance/
  ├── frameworks/
  │   ├── kvkk_6698.yaml
  │   ├── gdpr_2024.yaml
  │   ├── pci_dss_v4.yaml
  │   ├── iso_27001_2022.yaml
  │   ├── nis2_2022.yaml
  │   └── mitre_attack_v16.yaml
  ├── templates/
  │   ├── report_kvkk.html.hbs    (Handlebars template)
  │   ├── report_gdpr.html.hbs
  │   ├── report_pci.html.hbs
  │   ├── report_iso.html.hbs
  │   └── report_common.css
  ├── scripts/
  │   └── fetch_attack_stix.sh   (ATT&CK verisini güncelle)
  └── evidence/
      └── (run-time generated)
  ```
- [ ] **10.2** Framework güncelleme mekanizması — compliance server'dan yeni YAML/template çekme
- [ ] **10.3** Community framework marketplace — topluluk yeni framework ekleyebilsin (Brezilya LGPD, Hindistan DPDP, ...)
- [ ] **10.4** Compliance-as-Code — framework YAML'ları git reposunda versiyonlu, PR ile güncelleme, review

---

## 🗓 Önerilen MVP Yol Haritası (İlk 8 Hafta)

| Hafta | İş |
|-------|-----|
| **1** | `compliance` modülü: `ComplianceFramework` struct, YAML loader, metric extractor |
| **2** | Scoring engine + evidence collector + delta/drift hesaplama |
| **3** | KVKK framework YAML (12 kontrol) + HTML/MD rapor template'i |
| **4** | GDPR framework YAML (15 kontrol) + rapor template'i |
| **5** | PCI-DSS v4 framework YAML (20 kontrol) + PAN detection (Luhn + regex) + ROC template |
| **6** | ISO 27001 Annex A mapping (18 kontrol) + MITRE ATT&CK mapping motoru + ATT&CK Navigator export |
| **7** | Compliance dashboard UI (yeni tab) + rapor zamanlama |
| **8** | NIS2 framework + test suite + dokümantasyon |

---

> **Her checkbox, resmi bir uyumluluk denetiminde "kanıt" olarak
> sunabileceğiniz somut bir iş kalemidir. Mevcut Insights, Privacy X-ray,
> PQC checker ve Suricata kural motoru verisi doğrudan bu framework'lere
> beslenir.**
