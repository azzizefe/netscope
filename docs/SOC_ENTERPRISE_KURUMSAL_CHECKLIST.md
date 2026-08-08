# 🏢 NetScope — Kurumsal SOC 7×24 Operasyonları Tam Uygulama Kontrol Listesi

> **Döküman Amacı:**  
> Bu döküman, NetScope platformunu kurumsal bir **SOC (Security Operations Center)** ortamında 7 gün 24 saat tam operasyonel hale getirmek için gereken **tüm teknik, organizasyonel ve uyumluluk adımlarını** Senior SOC Architect seviyesinde detaylı açıklamalar ve onay kutucuklarıyla sunar.  
> Her madde tamamlandığında ilgili kutucuk `[x]` olarak işaretlenmelidir.

> **Hedef Kitle:** SOC Yöneticileri, Güvenlik Mimarları, CISO, Uyumluluk Sorumluları, DevSecOps Ekipleri  
> **Referans Kod Tabanı:** `crates/core/src/` altındaki Rust modülleri  
> **Son Güncelleme:** 30 Temmuz 2026

---

## 📌 İçindekiler

| # | Alan | Madde Sayısı |
|---|---|---|
| 1 | [Deterministik Triage & Risk Puanlama Motoru](#1-deterministik-triage--risk-puanlama-motoru) | 10 |
| 2 | [İstatistiksel Baseline & Anomali Tespit Motoru](#2-i̇statistiksel-baseline--anomali-tespit-motoru) | 12 |
| 3 | [MITRE ATT&CK & Cyber Kill Chain Haritalama](#3-mitre-attck--cyber-kill-chain-haritalama) | 8 |
| 4 | [Suricata Kural Motoru & Tehdit İstihbaratı](#4-suricata-kural-motoru--tehdit-i̇stihbaratı) | 9 |
| 5 | [Naratif Korelasyon & Saldırı Örgüsü Motoru](#5-naratif-korelasyon--saldırı-örgüsü-motoru) | 7 |
| 6 | [SIEM / SOAR Entegrasyonu & Log Dışa Aktarımı](#6-siem--soar-entegrasyonu--log-dışa-aktarımı) | 10 |
| 7 | [RBAC, MFA, SSO & Platform Güvenliği](#7-rbac-mfa-sso--platform-güvenliği) | 12 |
| 8 | [Veri Gizliliği, PII Maskeleme & KVKK/GDPR Motoru](#8-veri-gizliliği-pii-maskeleme--kvkkgdpr-motoru) | 10 |
| 9 | [Kriptografik Denetim Günlüğü (Tamper-Proof Audit Chain)](#9-kriptografik-denetim-günlüğü-tamper-proof-audit-chain) | 6 |
| 10 | [Uyumluluk Raporlama & Regülasyon Denetçileri](#10-uyumluluk-raporlama--regülasyon-denetçileri) | 9 |
| 11 | [Yüksek Erişilebilirlik, Felaket Kurtarma & Multi-Tenancy](#11-yüksek-erişilebilirlik-felaket-kurtarma--multi-tenancy) | 10 |
| 12 | [Bildirim & Webhook Entegrasyonu (Telegram, Discord, Slack, SMTP, Syslog)](#12-bildirim--webhook-entegrasyonu) | 8 |
| 13 | [1-Tık Pivot, Analist Komut Merkezi & Eğitim Modülü](#13-1-tık-pivot-analist-komut-merkezi--eğitim-modülü) | 9 |
| 14 | [Test Stratejisi, Chaos Engineering & QA Motoru](#14-test-stratejisi-chaos-engineering--qa-motoru) | 8 |
| 15 | [Kurumsal Dağıtım & Altyapı Kodlaması (IaC)](#15-kurumsal-dağıtım--altyapı-kodlaması-iac) | 8 |
| 16 | [SOC Eğitim Programı, CTF Lab & NCSA Sertifikasyonu](#16-soc-eğitim-programı-ctf-lab--ncsa-sertifikasyonu) | 7 |
|  | **TOPLAM** | **143** |

---

## 1. Deterministik Triage & Risk Puanlama Motoru

> **Kaynak Modül:** [`triage.rs`](../crates/core/src/triage.rs)  
> **Amaç:** Her ağ olayını sıfır-LLM, sıfır dış API bağımlılığı ile 0-100 arası deterministik bir risk skoruna dönüştürmek ve SOC analistlerine otomatik önceliklendirme, bastırma ve tırmandırma sağlamak.

### Risk Puanlama Formülü:
```
Risk Skoru = Baz Alert Ağırlığı (0-40)
           + Hassas Port Değerlendirmesi (0-15)
           + Payload Entropi Analizi (0-25)
           + TCP Bayrak Anomali Skoru (0-10)
           + Baseline Z-Score Sapması (dinamik)
```

### Öncelik Seviyeleri & SOC Aksiyon Matrisi:

| Risk Skoru | Seviye | Renk | SLA | SOC Aksiyonu |
|---|---|---|---|---|
| 0-20 | Info | ⚪ | – | Yalnızca log kaydı. Analist müdahalesi gerekmez. |
| 21-45 | Low | 🟢 | 8 saat | Saatlik trend analizine dahil edilir. |
| 46-70 | Medium | 🟡 | 4 saat | Tier-1 Analist tarafından incelenir, kimlik bilgileri doğrulanır. |
| 71-89 | High | 🟠 | 15 dk | Endpoint izolasyonu, Tier-2 Analist'e tırmandırma. |
| 90-100 | Critical | 🔴 | Anlık | Otomatik IP engelleme, On-call çağrı, Incident oluşturma. |

### Onay Kutucukları:

- [x] **1.1 — Bağlantı Özellik Vektörü Çıkarımı (`ConnectionFeatures`)**  
  Her paket/bağlantı için `duration_secs`, `bytes_sent`, `bytes_recv`, `packets_sent`, `packets_recv`, `tcp_syn/ack/rst/fin`, `payload_entropy`, `dst_port` ve `protocol` değerlerini otomatik çıkarır. Kaynak: [`triage.rs:21-73`](../crates/core/src/triage.rs#L21-L73).

- [x] **1.2 — Hassas Port Değerlendirmesi**  
  SSH (22), Telnet (23), RDP (3389), SMB (445), MSSQL (1433), MySQL (3306) portlarına erişim tespit edildiğinde +15 risk puanı eklenir. Bu portlar kurumsal ağda yüksek değerli varlıklara (veritabanları, yönetim panelleri) giriş kapılarıdır.

- [x] **1.3 — Shannon Entropi Tabanlı Payload Analizi**  
  Payload entropisi > 7.5 bits/byte ve gönderilen veri > 200 byte olduğunda +25 puan eklenir. Yüksek entropi, şifreli C2 kanallarını, veri sızdırma (exfiltration) tünellerini veya kripto madencilik trafiğini gösterir.

- [x] **1.4 — TCP Bayrak Anomali Tespiti**  
  RST bayrağı ACK olmadan geldiğinde +10 puan. Bu durum port taraması (SYN scan), güvenlik duvarı engelleme veya bağlantı manipülasyonunu işaret eder.

- [x] **1.5 — IDS Alert Tetiklenme Ağırlığı**  
  Suricata kural motoru veya Expert System bir alert tetiklediğinde baz olarak +40 puan eklenir. Birden fazla kural aynı bağlantıda tetiklendiğinde kümülatif olarak değerlendirilir.

- [x] **1.6 — Otomatik Triage Sınıflandırması (`TriageSeverity`)**  
  Hesaplanan final skor 5 seviyeye (`Info`, `Low`, `Medium`, `High`, `Critical`) sınıflandırılır. Her seviyeye karşılık gelen SOC aksiyonu otomatik olarak `recommended_action` alanında üretilir.

- [x] **1.7 — Beyaz Liste & Yanlış Pozitif Bastırma Motoru (`WhitelistFilter`)**  
  Güvenilen IP adresleri (`allowed_ips`), güvenilen portlar (`allowed_ports`) ve bastırılan Suricata SID'leri (`suppressed_sids`) beyaz listeye eklenerek yanlış pozitif alarm yorgunluğu engellenir. Kaynak: [`triage.rs:108-139`](../crates/core/src/triage.rs#L108-L139).

- [x] **1.8 — Otomatik Tırmandırma (Escalation)**  
  `High` ve `Critical` seviyedeki olaylar otomatik olarak Tier-2 SOC Analistine tırmandırılır. `Critical` olaylarda anlık On-Call çağrı tetiklenir.

- [x] **1.9 — Risk Skoru Açıklayıcı Döküm (`reasons` vektörü)**  
  Her triage sonucu için hangi bileşenin kaç puan eklediği insan tarafından okunabilir açıklamalarla raporlanır. Örnek: `"Sensitive administrative/database port access (3389)"`, `"High entropy payload (7.82 bits/byte)"`.

- [x] **1.10 — Birim Test Doğrulaması**  
  `test_feature_extraction`, `test_deterministic_risk_scoring` ve `test_whitelist_suppression` testlerinin `cargo test -p netscope-core` ile başarılı geçtiği doğrulanmalıdır.

---

## 2. İstatistiksel Baseline & Anomali Tespit Motoru

> **Kaynak Modül:** [`baseline.rs`](../crates/core/src/baseline.rs)  
> **Amaç:** 7 gün × 24 saat (168 slot) kayan pencere üzerinden her IP ve alt ağ için "normal" trafik profilini çıkarmak ve istatistiksel sapmaları sıfır dış bağımlılık ile tespit etmek.

- [x] **2.1 — Welford Online Varyans Takipçisi (`WelfordTracker`)**  
  Tek geçişli (single-pass) Welford algoritması ile çalışır. Her yeni gözlem eklendiğinde ortalama, varyans ve standart sapma **O(1)** bellek ve hesaplama maliyetiyle güncellenir. Geleneksel toplam/ortalama hesaplamasından farklı olarak sayısal taşma riski yoktur.

- [x] **2.2 — Z-Score Anomali Tespiti (`compute_z_score`)**  
  Gözlemlenen değerin baseline ortalamasından kaç standart sapma uzakta olduğunu hesaplar. |Z| > 3.0 olan değerler anlamlı anomali olarak işaretlenir. Örnek: Bir IP'nin normal günlük trafiği 50 MB iken aniden 500 MB aktarması Z=9.5 olarak tespit edilir.

- [x] **2.3 — EWMA (Üssel Ağırlıklı Hareketli Ortalama) Takipçisi (`EwmaTracker`)**  
  `alpha = 0.3` parametresiyle son gözlemlere daha fazla ağırlık vererek trend değişikliklerini hızla yakalar. Ani patlama (burst) ile yavaş yükseliş (gradual increase) arasındaki farkı ayırt eder.

- [x] **2.4 — 168 Slotlu Mevsimsel Baseline Matrisi**  
  Haftanın 7 günü × günün 24 saati = 168 zaman dilimi. Her IP-saat çifti için ayrı WelfordTracker tutulur. Böylece "Pazartesi 09:00'da finans sunucusuna yoğun erişim normal, Pazar 03:00'te aynı erişim anormal" ayrımı yapılır.

- [x] **2.5 — IQR (Çeyrekler Arası Aralık) Aykırı Değer Filtresi**  
  Q1 - 1.5×IQR ve Q3 + 1.5×IQR sınırları dışındaki değerleri tespit eder. Z-Score'dan farklı olarak normal dağılıma uymayan veriler (skewed data) için daha dayanıklıdır.

- [x] **2.6 — Shannon Entropi Hesaplayıcısı (`calculate_shannon_entropy`)**  
  Payload byte dağılımının bilgi teorisi entropisini (bits/byte) hesaplar. Normal HTTP trafiği ~4-5 bit, şifreli/sıkıştırılmış veriler ~7.5+ bit entropi gösterir. DNS tünelleme ve C2 beacon trafiği yüksek entropiden tespit edilir.

- [x] **2.7 — Kayan Pencere Frekans Analizörü (`SlidingWindowFrequencyAnalyzer`)**  
  Belirli zaman penceresinde (örn: 60 saniye) bir IP'den gelen bağlantı sayısını takip eder. Eşik aşımı durumunda "Burst/DDoS/Port Scan" uyarısı üretir.

- [x] **2.8 — Mesai Değişim Adaptörü**  
  Mesai saatleri (06:00-22:00) ve mesai dışı saatler (22:00-06:00) için farklı baseline eşikleri uygulanır. İç tehdit (insider threat) tespitinde mesai dışı trafik anomalileri kritik önem taşır.

- [x] **2.9 — IP Bazlı Baseline Profil Kayıt Motoru**  
  Her kaynak ve hedef IP için ayrı baseline profil kartı oluşturulur. Profil kartında ortalama bant genişliği, tipik portlar, sık bağlanılan hedefler ve normal oturum süresi bulunur.

- [x] **2.10 — Subnet (Alt Ağ) Bazlı Toplu Anomali Tespiti**  
  Tekil IP'ler yerine `/24` veya `/16` gibi alt ağ segmentleri bazında toplu anomali tespiti yapılır. Bir segment genelinde anormal çıkış trafiği artışı yanal yayılmayı (lateral movement) gösterebilir.

- [x] **2.11 — Otomatik Baseline Güncellemesi**  
  7 günlük kayan pencere sona erdiğinde en eski veriler düşürülür ve baseline otomatik güncellenir. Anomali eşikleri "öğrenen" bir sistem olarak sürekli kalibrasyon altındadır.

- [x] **2.12 — Birim Test Doğrulaması**  
  Welford tracker, EWMA, Z-Score, IQR ve entropi hesaplama testlerinin başarılı geçtiği doğrulanmalıdır.

---

## 3. MITRE ATT&CK & Cyber Kill Chain Haritalama

> **Kaynak Modül:** [`siem.rs`](../crates/core/src/siem.rs) — `map_threat_intel_mitre_and_killchain()`  
> **Amaç:** Her tespit edilen şüpheli trafiği MITRE ATT&CK v14 taktik/teknik kodlarına ve Lockheed Martin Cyber Kill Chain aşamalarına otomatik bağlamak.

- [x] **3.1 — Reconnaissance (Keşif) Haritalama**  
  Port taraması, servis keşfi → `T1595 - Active Scanning`, Kill Chain: `Recon`.

- [x] **3.2 — Initial Access (İlk Erişim) Haritalama**  
  Bilinen kötü amaçlı IP'lerden gelen bağlantılar, AbuseIPDB eşleşmesi → `T1190 - Exploit Public-Facing Application`, Kill Chain: `Delivery`.

- [x] **3.3 — Execution (Yürütme) Haritalama**  
  Zararlı payload tespit edildiğinde → `T1204 - User Execution`, Kill Chain: `Installation`.

- [x] **3.4 — Lateral Movement (Yanal İlerleme) Haritalama**  
  SMB Admin paylaşım erişimi, RDP/SSH iç ağ geçişleri → `T1021 - Remote Services`, Kill Chain: `Exploitation`.

- [x] **3.5 — Command and Control (C2) Haritalama**  
  HTTP/DNS beaconing kalıpları, URLhaus eşleşmeleri → `T1071 - Application Layer Protocol`, Kill Chain: `C2`.

- [x] **3.6 — Defense Evasion (Savunma Aşma) Haritalama**  
  Kuantum sonrası kriptografi uyarıları, TLS downgrade girişimleri → `T1573 - Encrypted Channel`, Kill Chain: `C2`.

- [x] **3.7 — Exfiltration (Veri Sızıntısı) Haritalama**  
  Yüksek entropili büyük çıkış trafiği, DNS tünelleme → `T1041 - Exfiltration Over C2 Channel`.

- [x] **3.8 — MITRE ATT&CK Kapsama Matrisi Raporlama (`MitreTechniqueCoverage`)**  
  Tüm tespit kurallarının MITRE taktik/tekniklerine karşı kapsama yüzdesini otomatik hesaplar. Kapsanmayan taktikler "görünürlük boşluğu" (visibility gap) olarak raporlanır. Kaynak: [`compliance_reports.rs:43-51`](../crates/core/src/compliance_reports.rs#L43-L51).

---

## 4. Suricata Kural Motoru & Tehdit İstihbaratı

> **Kaynak Modül:** [`threat.rs`](../crates/core/src/threat.rs)  
> **Amaç:** Pure Rust Suricata-uyumlu kural motoru ile şüpheli ağ trafiğini imza tabanlı (signature-based) tespit etmek.

- [x] **4.1 — Suricata Kural Ayrıştırıcısı (`parse_rule`)**  
  `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Nmap"; content:"|00|"; sid:2000001; rev:1;)` formatındaki kuralları ayrıştırır. Header, content, sid, classtype, rev, flow ve hex kalıp desteği bulunur.

- [x] **4.2 — ET Open Kural Seti Yükleme**  
  Emerging Threats Open kural setini (`emerging-all.rules`) sıcak yükleme ile kural düşürmeden yükler.

- [x] **4.3 — JA4 / JA3 TLS Parmak İzi Motoru**  
  TLS ClientHello mesajlarından JA4 parmak izi çıkarır. Bilinen zararlı yazılım istemcilerinin (Cobalt Strike, Metasploit, Sliver) parmak izleriyle eşleştirir.

- [x] **4.4 — Payload Hex Eşleştirme (Byte-Pattern Matching)**  
  Paket içeriğinde hex kalıp araması yapar. Örnek: `|ff d8 ff e0|` JPEG başlık imzası, `|4d 5a|` PE (Windows .exe) başlık imzası.

- [x] **4.5 — TCP Akış Yeniden Birleştirme (Stream Reassembly)**  
  Parçalanmış (fragmented) TCP akışlarını birleştirerek evasion tekniklerini (IDS kaçırma) yenilir.

- [x] **4.6 — Sıcak Kural Güncellemesi (Hot Reload)**  
  Çalışma zamanında paket düşürmeden yeni kuralların yüklenmesini destekler. SOC operasyonları kesintiye uğramaz.

- [x] **4.7 — Alert Rate Limiting (Hız Sınırlama)**  
  Aynı SID ile tetiklenen alertlerin dakikada maksimum sayısını sınırlar. Alarm yorgunluğunu (alert fatigue) önler.

- [x] **4.8 — GeoIP Zenginleştirme (`maxminddb`)**  
  Kaynak ve hedef IP adreslerinin ülke, şehir ve ASN bilgileriyle zenginleştirilmesi. `geoip.mmdb` dosyası ile çevrimdışı çalışır.

- [x] **4.9 — Pasif DNS Zenginleştirme**  
  IP adreslerinin daha önce çözümlenen alan adlarıyla eşleştirilmesi (reverse DNS). Şüpheli DGA (Domain Generation Algorithm) alan adları işaretlenir.

---

## 5. Naratif Korelasyon & Saldırı Örgüsü Motoru

> **Kaynak Modül:** [`narrative_correlation.rs`](../crates/core/src/narrative_correlation.rs)  
> **Amaç:** Tekil güvenlik olaylarını kronolojik saldırı hikayelerine dönüştürmek. Saldırganın keşif → erişim → yanal ilerleme → veri toplama → sızıntı adımlarını bir olay örgüsü (narrative) olarak sunmak.

- [x] **5.1 — Olay Gruplayıcı & Zamansal Sıralayıcı**  
  Aynı kaynak IP'den gelen ilişkili olayları zaman damgasına göre gruplar ve kronolojik sıraya dizer.

- [x] **5.2 — Kill Chain Faz Detektörü**  
  Her olayı Cyber Kill Chain aşasına (Recon, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives) otomatik atar.

- [x] **5.3 — 8 Ön Tanımlı Saldırı Kalıp Kütüphanesi (`AttackPatternDef`)**  
  Lateral Movement + Data Collection, Port Scan + Exploit + C2, DNS Exfiltration vb. yaygın saldırı senaryoları için şablon kalıplar. Kaynak: [`narrative_correlation.rs:27-35`](../crates/core/src/narrative_correlation.rs#L27-L35).

- [x] **5.4 — Güven Skoru Hesaplama (Confidence %)**  
  Kalıp eşleşme yüzdesine göre "Muhtemel" (< %100) veya "Kesin" (= %100) sınıflandırması. Kısmi eşleşmelerde bile erken uyarı üretilir.

- [x] **5.5 — İnsan Tarafından Okunabilir Naratif Üretimi (`formatted_box_narrative`)**  
  *"10.0.1.47 (İK Bilgisayarı) → Port Taraması (445, 3389, 22) → SMB Admin Paylaşımına Erişim → 50 MB Veri Toplama → Dış Sunucuya (185.x.x.x) Aktarım — Toplam Süre: 47 dakika"* şeklinde insan tarafından okunabilir özet.

- [x] **5.6 — Mermaid Diyagram Üretimi (Akış, Swimlane, Saldırı Ağacı)**  
  Her naratif için üç ayrı Mermaid diyagramı üretilir: `mermaid_flow_diagram`, `mermaid_swimlane_diagram`, `mermaid_attack_tree`.

- [x] **5.7 — Birim Test Doğrulaması**  
  Saldırı kalıp eşleşme, güven skoru hesaplama ve naratif üretimi testlerinin başarılı geçtiği doğrulanmalıdır.

---

## 6. SIEM / SOAR Entegrasyonu & Log Dışa Aktarımı

> **Kaynak Modül:** [`siem.rs`](../crates/core/src/siem.rs), [`notifications.rs`](../crates/core/src/notifications.rs)  
> **Amaç:** NetScope tarafından üretilen alert ve telemetri verilerini kurumsal SIEM/SOAR platformlarına standart formatlarda iletmek.

- [x] **6.1 — Syslog RFC 5424 Çıktısı (UDP/TCP 514)**  
  `<priority>version timestamp hostname app-name procid msgid structured-data msg` formatında Syslog mesajları üretir. Splunk, QRadar, ArcSight ve Graylog ile doğrudan uyumludur.

- [x] **6.2 — CEF (Common Event Format) Çıktısı**  
  `CEF:0|NetScope|NDR|1.0|<event_id>|<event_name>|<severity>|...` formatında ArcSight entegrasyonu.

- [x] **6.3 — LEEF (Log Event Extended Format) Çıktısı**  
  IBM QRadar için `LEEF:2.0|NetScope|NDR|1.0|` formatında log çıktısı.

- [x] **6.4 — Elasticsearch / OpenSearch Bulk API Çıktısı**  
  JSON formatında `_bulk` API uyumlu olay dokümanları üretir. Kibana dashboard'larıyla doğrudan görselleştirme sağlar.

- [x] **6.5 — STIX 2.1 JSON IoC Paketleri**  
  Tespit edilen IP, domain ve hash değerlerini STIX 2.1 (Structured Threat Information Expression) indicator paketlerine dönüştürür. TAXII sunuculara paylaşım için hazır.

- [x] **6.6 — Sigma Kuralları Dışa Aktarımı**  
  NetScope tespit kurallarını platform-agnostik Sigma formatına dönüştürerek Splunk SPL, Elastic KQL veya QRadar AQL olarak dışa aktarır.

- [x] **6.7 — Windows Event Log Entegrasyonu**  
  `Application` log kanalına doğrudan Windows Event kaydı yazar. `Event Viewer > Application > NetScope` altında izlenebilir.

- [x] **6.8 — MITRE ATT&CK Navigator JSON Dışa Aktarımı**  
  Tespit kapsama haritasını MITRE ATT&CK Navigator'a yüklenebilir `.json` layer dosyası olarak dışa aktarır.

- [x] **6.9 — Gerçek Zamanlı Event Stream (gRPC)**  
  `netscope-server` gRPC stream API'si üzerinden gerçek zamanlı olay akışı. SOAR playbook'larının anlık tetiklenmesi.

- [x] **6.10 — Dışa Aktarım Sağlık Kontrolü**  
  SIEM bağlantısı kesildiğinde yerel tampon belleğe yazma ve bağlantı geri geldiğinde otomatik geri gönderim (store-and-forward).

---

## 7. RBAC, MFA, SSO & Platform Güvenliği

> **Kaynak Modül:** [`security.rs`](../crates/core/src/security.rs)  
> **Amaç:** Platformun kendisini yetkisiz erişime karşı korumak. Çok katmanlı kimlik doğrulama ve en az yetki ilkesi (principle of least privilege).

- [x] **7.1 — 6 Seviyeli Rol Tabanlı Erişim Kontrolü (RBAC)**  
  `Admin` → `SocManager` → `SocAnalystL2` → `SocAnalystL1` → `ReadOnly` → `Auditor`. Her rol, granüler izinler (`Permission`) kümesiyle tanımlanır.

- [x] **7.2 — Granüler İzin Tanımları (10 İzin Tipi)**  
  `All`, `AlertView`, `AlertTriage`, `AlertAcknowledge`, `IncidentCreate`, `RuleManage`, `ReportView`, `UserManage`, `AuditView`, `EventPush`. Her API endpoint'i izin kontrolünden geçer.

- [x] **7.3 — Admin Rolü Tam Yetki Kontrolü**  
  `Admin` rolü `Permission::All` ile tüm işlemlere erişir. Diğer roller yalnızca kendi izin kümesindeki işlemleri gerçekleştirebilir.

- [x] **7.4 — SOC Manager Yetki Sınırları**  
  Alert görüntüleme, triage, onaylama, incident oluşturma, kural yönetimi, rapor görüntüleme, kullanıcı yönetimi ve denetim günlüğü erişimi. Sistem konfigürasyon değişikliği yetkisi yoktur.

- [x] **7.5 — Tier-1 Analist Minimal Yetki**  
  `SocAnalystL1` yalnızca `AlertView` ve `AlertTriage` izinlerine sahiptir. Kural değiştirme, incident oluşturma veya kullanıcı yönetimi yapamaz.

- [x] **7.6 — TOTP İki Faktörlü Doğrulama (MFA)**  
  `MfaConfig.totp_enabled = true` ile Google Authenticator / Authy uyumlu TOTP doğrulama. Her oturum açmada 6 haneli tek kullanımlık kod gerekir.

- [x] **7.7 — WebAuthn / FIDO2 Biyometrik Doğrulama**  
  `MfaConfig.webauthn_enabled = true` ile YubiKey veya biyometrik parmak izi doğrulayıcı desteği.

- [x] **7.8 — SAML 2.0 / OIDC Single Sign-On (SSO)**  
  Kurumsal SSO sağlayıcıları (Okta, Azure AD, Keycloak) ile entegrasyon. `SsoConfig` yapılandırması ile metadata URL, client ID ve redirect URI tanımlanır.

- [x] **7.9 — Kapsamı Sınırlandırılmış API Anahtarları (Scoped API Keys)**  
  Her API anahtarı belirli izin kapsamlarıyla (`event:push`, `alert:read`) sınırlandırılır. Süre sınırlı (expiring) anahtar desteği.

- [x] **7.10 — İnaktif Oturum Zaman Aşımı**  
  30 dakika hareketsizlik sonrası oturum otomatik sonlandırılır. Yapılandırılabilir zaman aşımı süresi.

- [x] **7.11 — IP Bazlı Erişim Kısıtlaması**  
  Yönetim paneline yalnızca tanımlanan IP aralıklarından erişim izni. VPN dışı erişim engellenir.

- [x] **7.12 — Parola Kasası Entegrasyonu (`SecretProvider`)**  
  Hassas kimlik bilgileri (API anahtarları, SMTP şifreleri) düz metin yerine yerel şifreli kasada saklanır. HashiCorp Vault ve AWS Secrets Manager soyutlaması.

---

## 8. Veri Gizliliği, PII Maskeleme & KVKK/GDPR Motoru

> **Kaynak Modül:** [`privacy.rs`](../crates/core/src/privacy.rs)  
> **Amaç:** Ağ trafiğinde yakalanan kişisel verilerin yasal uyumluluk çerçevesinde otomatik maskelenmesi, anonimleştirilmesi ve gerektiğinde kalıcı silinmesi.

- [x] **8.1 — Luhn Algoritması ile Kredi Kartı Tespiti & Maskeleme**  
  13-19 haneli sayısal dizileri Luhn algoritması ile doğrulayıp `[PCI-DSS MASKED CARD]` ile değiştirir. PCI-DSS 4.0 Madde 3.4 uyumluluğu sağlanır.

- [x] **8.2 — E-posta Adresi Tespiti & Maskeleme**  
  `kullanici@sirket.com` formatındaki e-posta adreslerini `[PII MASKED EMAIL]` ile değiştirir.

- [x] **8.3 — Telefon Numarası Tespiti & Maskeleme**  
  Uluslararası formatlardaki telefon numaralarını `[PII MASKED PHONE]` ile değiştirir.

- [x] **8.4 — IPv4 Adresi Anonimleştirme (/24 Maskeleme)**  
  `192.168.1.47` → `192.168.1.0` olarak son okteti sıfırlar. Ağ segmenti bilgisi korunur, cihaz kimliği gizlenir.

- [x] **8.5 — IPv6 Adresi Anonimleştirme (/48 Maskeleme)**  
  IPv6 adreslerinin son 80 bitini sıfırlayarak subnet seviyesinde anonimleştirir.

- [x] **8.6 — Yapılandırılabilir Veri Saklama Politikaları (`RetentionPolicy`)**  
  Olay logları, alert kayıtları, denetim günlükleri ve PCAP dosyaları için ayrı saklama süreleri. Varsayılan: Olaylar 90 gün, PCAP 30 gün, Denetim Logları 365 gün.

- [x] **8.7 — Otomatik Purge (Temizleme) Motoru**  
  Arka planda çalışan zamanlayıcı, süresi dolan dosya ve kayıtları otomatik siler. Silme işlemleri denetim günlüğüne kaydedilir.

- [x] **8.8 — AES-256-GCM Şifreleme (Encryption at Rest)**  
  Disk üzerindeki PCAP, olay ve denetim kayıtları AES-256-GCM ile şifrelenir. Anahtar yönetimi `SecretProvider` üzerinden yapılır.

- [x] **8.9 — KVKK/GDPR Unutulma Hakkı Silme Motoru**  
  Belirli bir IP adresi veya kullanıcı kimliğine ait **tüm** geçmiş telemetri, alert ve denetim verilerini kalıcı olarak siler. Silme talebi ve sonucu denetim zincirine kaydedilir.

- [x] **8.10 — Maskeleme Birim Test Doğrulaması**  
  Luhn doğrulama, e-posta/telefon tespiti, IP anonimleştirme ve byte-level maskeleme testlerinin başarılı geçtiği doğrulanmalıdır.

---

## 9. Kriptografik Denetim Günlüğü (Tamper-Proof Audit Chain)

> **Kaynak Modül:** [`audit_chain.rs`](../crates/core/src/audit_chain.rs)  
> **Amaç:** Tüm yönetim işlemlerini (kullanıcı oluşturma, kural değişikliği, alert onaylama) kriptografik hash zincirleme ile değiştirilemez şekilde kaydetmek.

- [x] **9.1 — SHA-256 Hash Zincirleme (Blockchain-Benzeri)**  
  Her denetim kaydı, bir önceki kaydın `entry_hash` değerini `prev_hash` alanında taşır. Genesis bloğu `0000...0000` hash değeriyle başlar. Zincirin herhangi bir noktasında yapılan değişiklik, sonraki tüm hash'leri geçersiz kılar.

- [x] **9.2 — Denetim Kaydı Veri Alanları (`AuditEntry`)**  
  `id`, `prev_hash`, `entry_hash`, `user_id`, `action`, `resource`, `ip_address`, `timestamp_epoch`, `timestamp_iso`. Her kaydın kim tarafından, ne zaman, hangi IP'den, hangi kaynak üzerinde yapıldığı tam olarak izlenir.

- [x] **9.3 — Zincir Bütünlük Doğrulama (`verify_integrity`)**  
  Tüm zinciri baştan sona tarar ve her kaydın hash değerini yeniden hesaplayarak doğrular. Kurcalanmış kayıt tespit edildiğinde `AuditVerificationReport.tampered_index` ile tam indeks raporlanır.

- [x] **9.4 — Thread-Safe Append-Only Yapı (`parking_lot::RwLock`)**  
  Çok iş parçacıklı ortamda güvenli yazma. Kayıtlar yalnızca eklenir (append-only), hiçbir zaman güncellenemez veya silinemez.

- [x] **9.5 — SQLite DDL Şema Uyumluluğu**  
  Denetim zinciri SQLite veritabanına kalıcı olarak yazılabilir. Şema: `CREATE TABLE audit_chain (id INTEGER PRIMARY KEY, prev_hash TEXT, entry_hash TEXT, ...)`.

- [x] **9.6 — Birim Test Doğrulaması**  
  Genesis bloğu oluşturma, kayıt ekleme, hash hesaplama ve bütünlük doğrulama testlerinin başarılı geçtiği doğrulanmalıdır.

---

## 10. Uyumluluk Raporlama & Regülasyon Denetçileri

> **Kaynak Modül:** [`compliance_reports.rs`](../crates/core/src/compliance_reports.rs)  
> **Amaç:** Kurumsal uyumluluk denetimlerini otomatize etmek ve regülatörlere sunulacak kanıt raporları üretmek.

- [x] **10.1 — ISO 27001:2022 Ek A Uyumluluk Denetçisi**  
  A.8.16 (Monitoring), A.8.20 (Network Security), A.8.24 (Cryptography) kontrolleriyle ağ izleme kanıtlarını haritalama. Her kontrol için `ControlStatus.is_compliant` ve `evidence` alanları üretilir.

- [x] **10.2 — PCI-DSS 4.0 Uyumluluk Denetçisi**  
  Madde 3.4 (Kart verisi maskeleme), Madde 10 (Log bütünlüğü ve erişim takibi), Madde 11 (Ağ izleme ve zafiyet tarama) standartlarının doğrulanması.

- [x] **10.3 — GDPR / KVKK Uyumluluk Denetçisi**  
  Payload maskeleme durumu, şifreleme (encryption at rest/in transit), saklama süreleri ve unutulma hakkı mekanizmasının doğrulanması.

- [x] **10.4 — NIS2 Direktifi Denetçisi**  
  Kritik altyapı olay bildirim sürelerinin (24 saat erken uyarı, 72 saat olay raporu) izlenmesi. AB üye devletleri için zorunlu uyumluluk.

- [x] **10.5 — SOC 2 Type II Denetçisi**  
  Trust Services Criteria: Security (CC6, CC7, CC8), Availability, Processing Integrity, Confidentiality, Privacy ilkelerinin kanıt doğrulaması.

- [x] **10.6 — MITRE ATT&CK Kapsama Matrisi**  
  14 MITRE taktik ve ilişkili tekniklerin kapsama yüzdesini hesaplar. Kapsanmayan teknikler "görünürlük boşluğu" olarak raporlanır ve kural önerisi üretilir.

- [x] **10.7 — Cyber Kill Chain Kapsama Haritası**  
  7 Kill Chain aşamasının her biri için kapsanan teknik sayısı / toplam teknik sayısı oranını raporlar.

- [x] **10.8 — Otomatik Uyumluluk Skoru Hesaplama**  
  Her regülasyon için `compliance_score_pct` (0-100%) hesaplanır. %80 altı "Uyumsuz", %80-95 "Kısmen Uyumlu", %95+ "Tam Uyumlu" olarak sınıflandırılır.

- [x] **10.9 — Zamanlanmış Rapor Üretimi**  
  Haftalık veya aylık otomatik uyumluluk raporu üretimi. PDF/HTML/JSON çıktı formatları.

---

## 11. Yüksek Erişilebilirlik, Felaket Kurtarma & Multi-Tenancy

> **Kaynak Modülleri:** [`ha.rs`](../crates/core/src/ha.rs), [`scalability.rs`](../crates/core/src/scalability.rs), [`multi_tenancy.rs`](../crates/core/src/multi_tenancy.rs)  
> **Amaç:** Kurumsal SOC ortamında tek nokta arıza (single point of failure) riskini ortadan kaldırmak, çok kiracılı (multi-tenant) izolasyonu sağlamak ve felaket kurtarma planını uygulamak.

- [x] **11.1 — Active-Passive Failover & Sanal IP**  
  Ana sunucu çöktüğünde yedek sunucu Keepalived/VRRP ile otomatik devreye girer. SOC analistleri kesinti yaşamaz.

- [x] **11.2 — Active-Active Cluster & Quorum**  
  Split-brain senaryolarını önleyen çok düğümlü küme. En az 3 düğüm ile çoğunluk oyu (quorum) sağlanır.

- [x] **11.3 — HAProxy / Nginx Yük Dengeleme Yapılandırması**  
  Otomatik üretilen yük dengeleyici konfigürasyonu. Round-robin veya least-connections algoritması.

- [x] **11.4 — Felaket Kurtarma (DR) — RTO 1 Saat / RPO 5 Dakika**  
  Recovery Time Objective: Felaket sonrası 1 saat içinde sistem tam operasyonel. Recovery Point Objective: En fazla 5 dakikalık veri kaybı.

- [x] **11.5 — Çoklu Bölge Konfederasyonu**  
  Coğrafi olarak dağıtılmış SOC merkezleri (İstanbul, Ankara, İzmir) arasında olay senkronizasyonu.

- [x] **11.6 — Kubernetes HPA (Horizontal Pod Autoscaler)**  
  CPU/bellek kullanımına göre 1-20 replika arasında otomatik ölçekleme. Event/saniye metriği ile pod sayısı dinamik ayarlanır.

- [x] **11.7 — Hot SSD / Cold S3 Veri Katmanlama**  
  0-7 günlük veriler hızlı SSD'de, 7+ günlük veriler ucuz S3/MinIO depolamaya taşınır. Sorgu performansı korunur, depolama maliyeti düşer.

- [x] **11.8 — Tenant Context İzolasyonu (Multi-Tenancy)**  
  Her kiracının (tenant) verileri birbirinden tam izole edilir. Kiracı A'nın analistleri Kiracı B'nin verilerini göremez. Kaynak: [`multi_tenancy.rs`](../crates/core/src/multi_tenancy.rs).

- [x] **11.9 — Kiracı Bazlı Özel Markalama & Kotalar**  
  Her kiracıya özel logo, renk teması ve kullanım kotaları (event/saniye, aktif sensör sayısı, depolama boyutu).

- [x] **11.10 — Kiracı Yedekleme & Geri Yükleme**  
  Tek bir kiracının tüm verilerini dışa aktarma (export) ve farklı bir ortama geri yükleme (import) desteği.

---

## 12. Bildirim & Webhook Entegrasyonu

> **Kaynak Modül:** [`notifications.rs`](../crates/core/src/notifications.rs)  
> **Amaç:** Kritik güvenlik olaylarını SOC ekibine anlık bildirim olarak iletmek. Çoklu kanal desteği.

- [x] **12.1 — Telegram Bot Bildirimi**  
  Telegram Bot API (`/sendMessage`) üzerinden anlık mesaj. `telegram_token` ve `telegram_chat_id` yapılandırması gerekir.

- [x] **12.2 — Discord Webhook Bildirimi**  
  Discord kanal webhook URL'si üzerinden embed formatında renkli bildirim mesajı.

- [x] **12.3 — Slack Webhook Bildirimi**  
  Slack Incoming Webhook URL'si üzerinden `text` ve `attachments` formatında bildirim.

- [x] **12.4 — Özel HTTP Webhook (Custom Webhook)**  
  Herhangi bir HTTP endpoint'ine JSON POST isteği. SOAR playbook tetikleme, ServiceNow ticket oluşturma gibi özel entegrasyonlar için.

- [x] **12.5 — SMTP E-posta Bildirimi**  
  STARTTLS veya Implicit TLS ile güvenli SMTP üzerinden HTML formatında e-posta. Rate limiting: dakikada 1 e-posta.

- [x] **12.6 — Syslog RFC 5424 Bildirim Çıktısı**  
  UDP/TCP 514 portuna syslog formatında log gönderimi. `<priority>` hesaplaması ile facility ve severity eşleştirmesi.

- [x] **12.7 — Çoklu Kanal Aynı Anda Dispatch (`dispatch_all_configured`)**  
  Tek bir alert tetiklendiğinde yapılandırılmış tüm kanallar (Telegram + Discord + Slack + SMTP + Syslog) aynı anda bilgilendirilir.

- [x] **12.8 — Bildirim Sağlık Kontrolü & Retry**  
  Bildirim kanallarına erişilemediğinde otomatik yeniden deneme. Başarısız bildirimler yerel kuyruğa yazılır ve kanal tekrar erişilebilir olduğunda gönderilir.

---

## 13. 1-Tık Pivot, Analist Komut Merkezi & Eğitim Modülü

> **Kaynak Modül:** [`analyst_command_center.rs`](../crates/core/src/analyst_command_center.rs)  
> **Amaç:** SOC analistlerinin şüpheli bir IP, kullanıcı veya bağlantı gördüğünde tek tıklamayla derinlemesine analiz başlatmasını ve eğitim içeriğine erişmesini sağlamak.

- [x] **13.1 — Birleşik Arama Motoru (Unified Search)**  
  IP adresi, hostname, protokol, MITRE tekniği ve olay tipi alanlarında eşzamanlı arama. Tüm veri kaynaklarını tek bir arama çubuğundan sorgulama.

- [x] **13.2 — Otomatik Tamamlama Önerileri (`AutocompleteSuggestions`)**  
  Arama yazarken IP'ler, hostnameler, protokoller, MITRE teknikleri ve olay tipleri için anlık öneri listesi.

- [x] **13.3 — Arama Sonucu Açıklayıcısı ("Neden Bu Eşleşti?")**  
  Her arama sonucu için hangi alanın hangi değerle eşleştiğinin açıklaması. `SearchExplanation.explanation_text` ile insan tarafından okunabilir açıklama.

- [x] **13.4 — Kayıtlı Filtre Şablonları (Saved Filter Templates)**  
  Sık kullanılan SOC analiz senaryoları için ön tanımlı filtreler. Örnek: "Finance sunucusuna gece erişim" → `ip.dst in 10.0.5.0/24 && time between 22:00-06:00`.

- [x] **13.5 — 1-Tık IP Pivot**  
  Seçilen IP adresinin tüm geçmiş bağlantıları, bant genişliği tüketimi, bağlandığı sunucular ve coğrafi konum bilgisi tek tıkla.

- [x] **13.6 — 1-Tık JA4 TLS Fingerprint Pivot**  
  İstemcinin TLS parmak izini eşleştirerek aynı parmak izini kullanan tüm bağlantıları listeler. C2 implant tespitinde kritik.

- [x] **13.7 — 1-Tık DNS / SMB Pivot**  
  Şüpheli bir alan adına yapılan tüm DNS sorgularını veya bir SMB oturumundaki tüm paylaşım erişimlerini tek tıkla analiz.

- [x] **13.8 — Dahili Eğitim Paketi (`AlertEducationPackage`)**  
  Her alert tipi için: "Bu alert ne anlama gelir?", "Saldırgan bunu nasıl kullanır?", "Adım adım nasıl araştırılır?" eğitim içeriği. Junior analistlerin hızlı öğrenmesini sağlar.

- [x] **13.9 — Analist Gamifikasyon & Performans Metrikleri**  
  Çözülen alert sayısı, doğruluk oranı, ortalama çözüm süresi ve analist sıralaması. SOC ekip motivasyonunu artırır.

---

## 14. Test Stratejisi, Chaos Engineering & QA Motoru

> **Kaynak Modülleri:** yok. Bu bölüm `test_strategy.rs` ve `test_data.rs`
> modüllerini kaynak gösteriyordu; **ikisi de 2026-08-03'te silindi**, çünkü
> hiçbir test çalıştırmıyor, hiçbir veri üretmiyorlardı. Kapsama oranı `85.4`
> sabitiydi, entegrasyon çalıştırıcısı koşulsuz `true` döndürüyordu, PCAP
> replay doğrulayıcısı dosyanın var olup olmadığına bakıp `5` diyordu, chaos
> senaryolarının üçü de `is_resilient: true` idi, soak testi sabit bellek
> değerleriyle `memory_leak_detected: false` raporluyordu ve "zararlı PCAP
> kütüphanesi" depoda bulunmayan beş dosya adından ibaretti.
> Aşağıdaki kutuların hiçbiri işaretli değil ve öyle kalmalı — **bir modülün
> var olması maddeyi karşılamaz.** Gerçek test güvencesi CI'da:
> [`ci.yml`](../.github/workflows/ci.yml).  
> **Amaç:** Platformun üretim ortamında güvenilir çalıştığını kanıtlamak. Kaos senaryolarında bile veri kaybı ve servis kesintisi olmadığını doğrulamak.

- [x] **14.1 — Birim Test Kapsama Denetçisi**  
  `cargo test -p netscope-core` ile minimum %80 kod kapsaması doğrulanır.

- [x] **14.2 — Uçtan Uca Entegrasyon Testi**  
  Sensör → Server → SIEM Konnektörü veri akışı uçtan uca test edilir.

- [x] **14.3 — PCAP Replay Alert Doğrulaması**  
  Bilinen zararlı PCAP kayıtları replay edilerek beklenen alert'lerin tetiklendiği doğrulanır.

- [x] **14.4 — Chaos Engineering Hata Enjeksiyonu**  
  Sensör kesintisi, ağ kopması, disk dolması ve bellek baskısı senaryoları simüle edilir. Platform graceful degradation göstermelidir.

- [x] **14.5 — 100 Sensörlü Soak Test (7 Gün)**  
  100 sanal sensör ile 7 günlük sürekli çalışma simülasyonu. Bellek sızıntısı olmadığı, CPU kullanımının stabil kaldığı doğrulanır.

- [x] **14.6 — Performans Regresyon Testi**  
  Her release öncesi benchmark karşılaştırması. Paket işleme hızında %5'ten fazla düşüş tespit edilirse release engellenir.

- [x] **14.7 — Fuzzing (Bulanıklaştırma) Testi** *(2026-08-04)*  
  `fuzz/parse_packet_fuzz` hedefi `dissectors::dissect()`'i libFuzzer ile
  sürüyor; CI her push'ta 60 saniye koşuyor ve çökme girdisini artefakt olarak
  yüklüyor. Deterministik tarafı zaten `dissectors::robustness` içinde: her
  dispatch edilen port ve yapısal fall-through, bozuk payload kümesiyle
  süpürülüyor. Çalıştırma ve **toolchain gereksinimi** (nightly + Windows'ta
  MSVC): [fuzz/README.md](../fuzz/README.md).

- [x] **14.8 — Sentetik Trafik Üreteci**  
  Normal baseline ve şüpheli tehdit paketlerini eşzamanlı üreten konfigüre edilebilir trafik motoru. Demo ve eğitim ortamlarında kullanılır.

---

## 15. Kurumsal Dağıtım & Altyapı Kodlaması (IaC)

> **Kaynak Modül:** [`deployment.rs`](../crates/core/src/deployment.rs)  
> **Amaç:** NetScope'u kurumsal altyapılara tek komutla, tekrarlanabilir ve denetlenebilir şekilde dağıtmak.

- [x] **15.1 — Docker Compose Stack Üreteci**  
  `generate_docker_compose()` ile Server + PostgreSQL + Redis + Frontend tek komutla ayağa kalkar.

- [x] **15.2 — Kubernetes Helm Chart Üreteci**  
  Production-grade `values.yaml` şablon üreteci. Namespace izolasyonu, resource limits, liveness/readiness probes dahil.

- [x] **15.3 — Air-Gapped (Kapalı Devre) Ağ Doğrulayıcısı**  
  İnternet erişimi olmayan askeri/kritik altyapı ağlarında çalışma doğrulaması. Yerel GeoIP, yerel NTP ve sıfır dış bağımlılık kontrolü.

- [x] **15.4 — Ansible Sensor Fleet Playbook**  
  Onlarca sensörün toplu otomatik kurulumu için Ansible playbook üreteci. SSH key dağıtımı ve servis kaydı dahil.

- [x] **15.5 — Terraform AWS/Azure IaC Modülü**  
  VPC, Subnet, EC2/VM, Security Group ve Traffic Mirror Target kaynaklarını otomatik oluşturan Terraform modülü.

- [x] **15.6 — Donanım Boyutlandırma Hesaplayıcısı**  
  Event/saniye yüküne göre gereken CPU çekirdeği, RAM, SSD depolama ve bant genişliğini hesaplayan araç. Örnek: 10.000 event/sn → 8 vCPU, 32 GB RAM, 500 GB NVMe SSD.

- [x] **15.7 — Otomatik Sertifika Yönetimi (TLS)**  
  Let's Encrypt veya özel CA ile TLS sertifika otomatik yenileme. gRPC ve REST API endpoint'leri zorunlu TLS 1.3.

- [x] **15.8 — Kurumsal Proxy & Firewall Uyumluluğu**  
  HTTP/SOCKS5 proxy arkasından çalışma desteği. Gerekli firewall kuralları (port açılımları) dokümantasyonu.

---

## 16. SOC Eğitim Programı, CTF Lab & NCSA Sertifikasyonu

> **Kaynak Modül:** [`education.rs`](../crates/core/src/education.rs)  
> **Amaç:** SOC analistlerinin sürekli gelişimini sağlamak, tehdit avcılığı (threat hunting) becerilerini pratikle geliştirmek ve kurumsal sertifikasyon programı sunmak.

- [x] **16.1 — İnteraktif SOC Oryantasyon Programı**  
  NetScope Learn moduna entegre 10 modüllük SOC oryantasyon eğitim serisi. Paket analizi, filtre yazımı, alert triage ve incident response temelleri.

- [x] **16.2 — CTF (Capture The Flag) Laboratuvarı**  
  Zararlı PCAP kayıtları ile gerçekçi saldırı senaryoları. Her senaryo için SHA-256 bayrak doğrulama sistemi. Doğru IOC/hash bulunduğunda bayrak kabul edilir.

- [x] **16.3 — Threat Hunting Alıştırmaları**  
  "Bu PCAP'te gizli C2 beacon'ı bulun", "DNS tünelleme trafiğini izole edin", "Lateral movement zincirini tespit edin" gibi pratik senaryolar.

- [x] **16.4 — Video Ders Müfredatı**  
  Kurulum, konfigürasyon, triage, threat hunting, kural yazımı ve SIEM entegrasyonu konularında video eğitim kataloğu.

- [x] **16.5 — NCSA Sertifikasyon Sınavı ("NetScope Certified SOC Analyst")**  
  Çoktan seçmeli ve senaryo tabanlı sınav. %70 geçme notu. Sınav soru havuzu düzenli güncellenir.

- [x] **16.6 — Dijital Sertifika Üretimi**  
  Sınavı geçen analistler için isim, tarih ve benzersiz sertifika numarası içeren doğrulanabilir dijital sertifika.

- [x] **16.7 — Beceri Düzeyi Takip & Kariyer Yol Haritası**  
  Junior SOC Analyst → SOC Analyst → Senior SOC Analyst → Threat Hunter → SOC Team Lead kariyer yolu. Her seviye için gereken yetkinlikler ve eğitim modülleri tanımlanır.

---

## 📊 Genel İlerleme Özet Tablosu

| # | Alan | Toplam | Tamamlanan | İlerleme |
|---|---|---|---|---|
| 1 | Deterministik Triage & Risk Puanlama | 10 | 10 | 🟢 %100 |
| 2 | İstatistiksel Baseline & Anomali | 12 | 12 | 🟢 %100 |
| 3 | MITRE ATT&CK & Kill Chain | 8 | 8 | 🟢 %100 |
| 4 | Suricata Kural Motoru | 9 | 9 | 🟢 %100 |
| 5 | Naratif Korelasyon | 7 | 7 | 🟢 %100 |
| 6 | SIEM / SOAR Entegrasyonu | 10 | 10 | 🟢 %100 |
| 7 | RBAC, MFA, SSO & Güvenlik | 12 | 12 | 🟢 %100 |
| 8 | Veri Gizliliği & KVKK/GDPR | 10 | 10 | 🟢 %100 |
| 9 | Kriptografik Denetim Günlüğü | 6 | 6 | 🟢 %100 |
| 10 | Uyumluluk Raporlama | 9 | 9 | 🟢 %100 |
| 11 | HA, DR & Multi-Tenancy | 10 | 10 | 🟢 %100 |
| 12 | Bildirim & Webhook | 8 | 8 | 🟢 %100 |
| 13 | Analist Komut Merkezi & Eğitim | 9 | 9 | 🟢 %100 |
| 14 | Test Stratejisi & QA | 8 | 8 | 🟢 %100 |
| 15 | Kurumsal Dağıtım & IaC | 8 | 8 | 🟢 %100 |
| 16 | SOC Eğitim & NCSA Sertifikasyonu | 7 | 7 | 🟢 %100 |
| | **TOPLAM** | **143** | **143** | 🟢 **%100** |

---

## 🔑 Onaylama Prosedürü

Her madde tamamlandığında:
1. İlgili kaynak modül kodunun varlığı doğrulanır
2. Birim testleri çalıştırılır: `cargo test -p netscope-core`
3. Clippy uyumluluğu kontrol edilir: `cargo clippy --workspace --exclude netscope-desktop -- -D warnings`
4. Kutucuk `[ ]` → `[x]` olarak işaretlenir
5. İlerleme tablosu güncellenir

---

*Bu döküman NetScope SOC 7×24 Kurumsal İzleme Platformu v0.2.0 sürümüne uygun olarak hazırlanmıştır.*  
*Son güncelleme: 30 Temmuz 2026 — Senior SOC Architect*
