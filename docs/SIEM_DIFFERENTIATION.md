# 🔬 netscope — Rakip SIEM'lere Karşı Fark Yaratan Açıklayıcı SIEM Sistemi

> **"Every SIEM can tell you what happened. netscope tells you why it matters."**
>
> Bu spesifikasyon, netscope'u **piyasadaki en açıklayıcı, en öğretici,
> en "insan gibi konuşan" SIEM** yapmak için gereken her şeyi tanımlar.
>
> Mevcut SIEM çözümleri (Splunk, Elastic, QRadar, Sentinel, Graylog) size
> **raw log satırları** gösterir. Analistin bu log'ları okuyup kendi kafasında
> anlamlandırması, korele etmesi, MITRE'ye eşlemesi, riski değerlendirmesi
> gerekir. netscope bunu **otomatik olarak** yapar — çünkü paketin içini
> görür, sadece IP ve port değil.

---

## 🧬 netscope'un Rakipsiz SIEM Avantajları — Temel Farklar

```
Diğer SIEM'lerin gördüğü:          netscope'un gördüğü:
─────────────────────────          ─────────────────────
"192.168.1.5 → 10.0.0.3:445"      "HR-DESK-023 (Efe Akkaya) → FIN-DB-01 SMB
                                   session, NTLMv2 auth, user: CORP\jsmith, 
                                   accessed \\FIN-DB-01\payroll\Q4_2026.xlsx 
                                   (2.3 MB transferred). TLS not used — 
                                   SMB signing: disabled ⚠️"

"Alert: port scan detected"        "Between 14:32-14:44, 10.0.1.47 scanned 47 
                                   ports on 10.0.5.18. This is 12× the baseline 
                                   for this host (avg 3.8 scan events/day). 
                                   Source is a Windows 11 workstation in HR OU, 
                                   user: efe.akkaya. The target is FIN-DB-01 
                                   (PostgreSQL 16, Finance segment). After the 
                                   scan, 2 SMB connections and 1 RDP attempt 
                                   followed. MITRE: T1046 → T1021.002 → T1021.001.
                                   Risk: HIGH (85/100) — credential access pattern."

"TLS 1.2 connection"               "TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384, 
                                   JA4: t12d..., cert CN=*.saas-app.com 
                                   (expires in 14 days ⚠️), Issuer: DigiCert. 
                                   NOT PQC-ready — recommendation: upgrade 
                                   to TLS 1.3 with Kyber-1024 hybrid."
```

---

## 📐 Faz 1 — Semantic Event Enrichment (Olay Zenginleştirme Motoru)

> Her event, ham haliyle değil, **bağlamla zenginleştirilmiş** olarak SIEM'e
> iletilir. Bu motor, netscope'un 250+ dissector'ından gelen içgörüyü
> kullanır.

### 1.1 — Otomatik Event Bağlam Katmanları

Her event, 7 katmanda zenginleştirilir:

- [x] **1.1.1** **Katman 1 — Ağ Kimliği (Network Identity):**
  ```
  IP:       10.0.1.47 → HR-DESK-023.internal.corp (DNS PTR + DHCP fingerprint)
  MAC:      00:1A:2B:3C:4D:5F → Dell Inc. (OUI)
  VLAN:     HR-Subnet (VLAN 120)
  Segment:  Istanbul Office, Floor 3, HR Department
  Device:   Windows 11 Pro 22H2, Dell Latitude 5540
  User:     efe.akkaya (Kerberos / LDAP correlation)
  ```
  - [x] DNS PTR + Passive DNS lookup (mevcut name cache)
  - [x] DHCP fingerprinting (Option 55, Vendor Class)
  - [x] MAC OUI → üretici (zaten mevcut)
  - [x] Kerberos AS-REQ / LDAP bind → kullanıcı adı eşleştirme
  - [x] NetBIOS / LLMNR / mDNS → hostname
  - [x] HTTP User-Agent → OS/browser tespiti
  - [x] Active Directory OU → departman

- [x] **1.1.2** **Katman 2 — Protokol Semantik (Protocol Semantics):**
  ```
  Ham:  "TCP 10.0.1.47:52134 → 10.0.5.18:445 SYN"
  
  netscope (derin dissector sayesinde):
  "SMB2 SESSION_SETUP request: user=CORP\jsmith, 
   dialect=SMB 3.1.1, signing=disabled ⚠️, encryption=disabled ❌,
   NTLMv2 challenge/response, workstation=HR-DESK-023,
   TreeConnect → \\FIN-DB-01\payroll, 
   Create → Q4_2026.xlsx (open for read),
   Read → 2,359,296 bytes transferred in 47 packets (3.2 sec),
   Close → normal termination"
  ```
  Bu seviyede analiz **sadece netscope'un 250+ protokol dissector'ı ile mümkün**.
  Splunk/ELK bu trafiği sadece "TCP 445" olarak görür.

  - [x] Her dissector, SIEM event'ine **semantic summary** üretsin
  - [x] Protokol seviyesinde risk flag'leri: `signing=disabled`, `encryption=none`, `weak_cipher=TLS_RSA_WITH_RC4_128_MD5`
  - [x] Protokol parametreleri event fields olarak expose edilsin (filtrelenebilir)

- [x] **1.1.3** **Katman 3 — Tehdit İstihbaratı (Threat Intelligence):**
  ```
  IP 185.220.101.34 (dst):
    - Tor Exit Node ✅ (AbuseIPDB: confidence 98%)
    - Last reported: 2026-07-26 (C2 traffic)
    - Country: Germany
    - ASN: AS200052 (Zwiebelfreunde e.V.)
    - VirusTotal: 5/94 engines detected as malicious
    - AlienVault OTX: 12 pulses in last 30 days
    - GreyNoise: "commonly seen scanning the internet"
  ```
  - [x] AbuseIPDB (zaten var — event'e göm)
  - [x] URLhaus (zaten var — domain için)
  - [x] VirusTotal API (opsiyonel — API key ile)
  - [x] AlienVault OTX
  - [x] GreyNoise (özellikle internet background noise tespiti için)
  - [x] Shodan (açık port bilgisi)
  - [x] GeoIP + ASN (zaten var)

- [x] **1.1.4** **Katman 4 — Davranışsal Baseline (Behavioral Baseline):**
  ```
  Bu event'in normalden sapma derecesi:
    - 10.0.1.47'nin 10.0.5.18'e bağlantı sayısı: 47 (7-günlük ortalama: 1.2)
      → Anomali skoru: +39× baseline ⚠️
    - 10.0.1.47'nin saat 02:00-04:00 arası aktivitesi: GENELDE SIFIR
      → Zaman anomalisi: mesai dışı ⚠️
    - 10.0.1.47'nin FIN-DB-01'e erişimi: İLK KEZ (daha önce hiç olmamış)
      → Yeni hedef anomalisi ⚠️
    - SMB veri transferi: 2.3 MB (bu host için 7-gün max: 145 KB)
      → Veri hacmi anomalisi: +15× baseline ❌
  ```
  - [x] 7-günlük rolling baseline her sensör için
  - [x] Z-skor hesaplama (her metrik için)
  - [x] Event'e "anomali skoru" alanı ekle
  - [x] Baseline'dan sapma nedenlerini insan dilinde açıkla

- [x] **1.1.5** **Katman 5 — MITRE ATT&CK & Kill Chain Mapping:**
  ```
  MITRE ATT&CK:
    T1046  Network Service Discovery     (confidence: HIGH)
    T1021.002 SMB/Windows Admin Shares   (confidence: HIGH)
    T1021.001 Remote Desktop Protocol    (confidence: MEDIUM)
    
  Kill Chain Phase: 2 (Weaponization) → 3 (Delivery) → 7 (Actions on Objective)
  
  Detection coverage: Bu event zinciri, 3 ATT&CK tekniğini kapsıyor.
  ```
  - [x] Her event tipi → ATT&CK teknik(ler)i mapping
  - [x] Confidence score (event tipinden gelen)
  - [x] Phase of Kill Chain

- [x] **1.1.6** **Katman 6 — İş Etkisi (Business Impact):**
  ```
  Etkilenen varlık: FIN-DB-01
    Kritiklik: CRITICAL (Production Database, Finance)
    Veri sınıflandırması: CONFIDENTIAL
    Compliance: PCI-DSS (kredi kartı verisi), KVKK (çalışan maaş bilgisi)
    İş etkisi: Bu sunucuya yetkisiz erişim, tüm finans verilerinin 
               sızmasına ve PCI-DSS ihlaline yol açabilir.
    Tahmini maddi etki: YÜKSEK (regülasyon cezası + itibar kaybı)
  ```
  - [x] Asset inventory API'si (müşteri kendi CMDB'sini besleyebilir)
  - [x] Asset kritiklik seviyesi (Tier 1-4)
  - [x] İlgili compliance framework'leri
  - [x] Tahmini iş etkisi (düşük / orta / yüksek / kritik)

- [x] **1.1.7** **Katman 7 — "Bunu Neden Önemsemeliyim?" Açıklaması:**
  ```
  🧠 Neden önemli?
  
  Bu event zinciri, bir iç tehdit (insider threat) veya ele geçirilmiş bir
  workstation'ın finansal verilere erişmeye çalıştığını gösteriyor.
  
  Normalde HR departmanından hiçbir çalışan FIN-DB-01'e erişmez. Bu
  erişim mesai dışı saatte, normalin 39 katı bağlantı ile gerçekleşti.
  SMB imzalama kapalı olduğu için, ağdaki bir saldırgan bu trafiği
  relay edebilir.
  
  Aksiyon: Bu host'u hemen izole edin, kullanıcının şifresini
  sıfırlayın, SMB signing'i tüm domain'de zorunlu hale getirin.
  ```
  - [x] Her alert için otomatik "why this matters" paragrafı
  - [x] Template-based üretim (Handlebars/Tera şablonları ile — LLM kullanmaz, token harcamaz)
  - [x] Her event tipi + severity kombinasyonu için önceden yazılmış şablon kütüphanesi
  - [x] Aksiyon önerisi (1-2-3 adım) — rule-based, önceden tanımlanmış aksiyon kataloğundan

masın

### 1.2 — Zenginleştirilmiş Event Schema (OCSF Uyumlu)

- [x] **1.2.1** Yeni `EnrichedEvent` yapısı (mevcut `Event` + tüm enrichment):
  ```json
  {
    "id": "evt_abc123...",
    "time": "2026-07-27T02:42:17.123Z",
    "severity": "high",
    "confidence": 87,
    "anomaly_score": 92.5,
    
    "actor": {
      "ip": "10.0.1.47",
      "hostname": "HR-DESK-023",
      "mac": "00:1A:2B:3C:4D:5F",
      "mac_vendor": "Dell Inc.",
      "os": "Windows 11 Pro 22H2",
      "department": "Human Resources",
      "user": "efe.akkaya",
      "user_sid": "S-1-5-21-...",
      "privilege_level": "Standard User"
    },
    
    "target": {
      "ip": "10.0.5.18",
      "hostname": "FIN-DB-01",
      "fqdn": "fin-db-01.internal.corp",
      "asset_criticality": "critical",
      "asset_tier": 1,
      "data_classification": "confidential",
      "department": "Finance",
      "service": "PostgreSQL 16.3",
      "port": 5432
    },
    
    "protocol": {
      "transport": "TCP",
      "application": "PostgreSQL",
      "dissector": "pgsql",
      "dissector_version": "0.2.0",
      "encrypted": false,
      "details": {
        "pgsql_message_type": "Query",
        "pgsql_query_preview": "SELECT * FROM employees WHERE salary > ...",
        "pgsql_user": "app_finance_ro"
      }
    },
    
    "tls": {
      "version": null,
      "reason": "PostgreSQL connection is plaintext — no TLS detected ❌"
    },
    
    "threat_intel": {
      "actor_ip": {"abuseipdb": "clean", "greynoise": "benign"},
      "target_ip": {"abuseipdb": "clean"}
    },
    
    "baseline": {
      "actor_to_target_7day_avg": 0.2,
      "current_vs_baseline": "195×",
      "time_of_day_normal": false,
      "protocol_normal_for_host": true,
      "data_volume_7day_avg_mb": 0.05,
      "current_data_volume_mb": 9.8,
      "volume_vs_baseline": "196×"
    },
    
    "mitre_attack": [
      {"technique": "T1046", "tactic": "Discovery", "confidence": "high"},
      {"technique": "T1213", "tactic": "Collection", "confidence": "medium"}
    ],
    "kill_chain_phase": "Actions on Objective",
    
    "business_impact": {
      "level": "critical",
      "data_at_risk": "Employee salary data (KVKK Art. 6 — özel nitelikli)",
      "compliance": ["KVKK", "ISO 27001 A.8.12"],
      "estimated_financial_risk": "YÜKSEK"
    },
    
    "human_readable": {
      "one_line": "HR workstation HR-DESK-023 (efe.akkaya) executed a SELECT query on FIN-DB-01 for salary data — over plaintext PostgreSQL, no encryption, 196× normal data volume at 02:42 AM",
      "why_it_matters": "This is a potential insider threat or compromised workstation accessing confidential payroll data outside business hours with no encryption. The data volume is 196× the 7-day baseline.",
      "recommended_action": [
        "1. Isolate HR-DESK-023 from the network immediately",
        "2. Verify with efe.akkaya if this access was authorized",
        "3. Enable TLS on all PostgreSQL connections to FIN-DB-01",
        "4. Implement time-based access control for HR→Finance segment"
      ]
    },
    
    "raw": {
      "packet_id": 184723,
      "capture_interface": "eth0",
      "sensor_id": "sensor_istanbul_03"
    }
  }
  ```
- [x] **1.2.2** OCSF 1.3.0 `security_finding` + `network_activity` class'larına tam uyum
- [x] **1.2.3** Her event'in `human_readable` alanı **her zaman dolu** olsun — hiçbir event "anlamsız IP-port çifti" olarak kalmasın

## 🧠 Faz 2 — Narrative Correlation (Olay Örgüsü / Hikaye Motoru)

> Sıradan SIEM'ler alert'leri liste olarak gösterir. netscope, alert'leri
> **bir hikaye** olarak anlatır — "önce bu oldu, sonra şu oldu, bu yüzden
> bu tehlikeli."

### 2.1 — Otomatik Hikaye Üretimi

- [x] **2.1.1** **Correlation Engine v2** — mevcut threshold/signature kurallarını aş:
  ```
  Girdi: 47 event (scan → SMB session → file read → RDP attempt)
  
  Çıktı — Otomatik Olay Örgüsü:
  
  ┌─────────────────────────────────────────────────────────┐
  │ 🕐 Attack Narrative: Potential Data Exfiltration        │
  │                                                         │
  │ ⏱ 02:41:12  [Discovery]                               │
  │   HR-DESK-023 started scanning FIN-DB-01:                │
  │   47 ports probed in 32 seconds.                         │
  │   Open: 445/SMB, 3389/RDP, 5432/PostgreSQL               │
  │   → MITRE T1046 (Network Service Discovery)             │
  │                                                         │
  │ ⏱ 02:42:07  [Lateral Movement]                         │
  │   SMB connection established. NTLMv2 auth: CORP\jsmith. │
  │   SMB signing DISABLED. Share: \\FIN-DB-01\payroll.     │
  │   → MITRE T1021.002 (SMB/Windows Admin Shares)          │
  │                                                         │
  │ ⏱ 02:42:17  [Collection]                               │
  │   File accessed: Q4_2026.xlsx (2.3 MB read).            │
  │   PostgreSQL query: SELECT * FROM employees              │
  │   WHERE salary > 100000 (9.8 MB result set).            │
  │   → MITRE T1213 (Data from Information Repositories)    │
  │                                                         │
  │ ⏱ 02:44:51  [Lateral Movement Attempt]                 │
  │   RDP connection attempt to FIN-DB-01:3389.             │
  │   Failed — user jsmith is not in Remote Desktop Users.  │
  │   → MITRE T1021.001 (Remote Desktop Protocol)           │
  │                                                         │
  │ 📊 Toplam süre: 3 dakika 39 saniye                      │
  │ 🎯 Hedef: FIN-DB-01 (Finance Database, KRİTİK)         │
  │ 👤 Aktör: jsmith / HR-DESK-023                          │
  │ 🔴 Risk: 92/100 (Critical)                              │
  │                                                         │
  │ 💡 Karar: Bu bir insider threat veya ele geçirilmiş     │
  │    hesap. Kullanıcı finans verilerine yetkisiz erişmiş. │
  └─────────────────────────────────────────────────────────┘
  ```
- [x] **2.1.2** Narrative engine bileşenleri:
  - [x] **Event grouper** — aynı aktör/hedef/zaman penceresindeki event'leri grupla
  - [x] **Temporal sequencer** — event'leri kronolojik sırala, faz geçişlerini tespit et (Discovery → Lateral → Collection → Exfil)
  - [x] **Kill Chain phase detector** — her event grubunun hangi Kill Chain fazına denk geldiğini belirle
  - [x] **Narrative template engine** — her saldırı pattern'i için önceden tanımlanmış hikaye şablonları
  - [x] **Template finalizer** — şablondaki `{{placeholder}}`'ları gerçek verilerle doldur, Tera/Handlebars template engine ile doğal dilde hikaye üret (LLM kullanmaz, sıfır maliyet)

- [x] **2.1.3** Önceden tanımlanmış saldırı pattern'leri (narrative template library):
  ```
  Pattern:        "Port scan → lateral movement → data access"
  Pattern:        "Brute force → successful login → privilege escalation"
  Pattern:        "Phish click → C2 beaconing → data exfiltration"
  Pattern:        "Recon → exploit (Log4Shell/SQLi) → reverse shell"
  Pattern:        "DGA DNS → encrypted C2 → large outbound transfer"
  Pattern:        "Credential dump → pass-the-hash → lateral spread"
  Pattern:        "Insider: normal hours + unusual target + large data transfer"
  Pattern:        "Ransomware: SMB spread + shadow copy delete + file encrypt"
  ```
  Her pattern için:
  - Hangi event tipleri hangi sırayla gelmeli?
  - Aralarındaki max süre (timeout)
  - Minimum event sayısı
  - Hikaye şablonu metni ({{placeholder}}'lar ile)

- [x] **2.1.4** **Confidence scoring** — her narrative için:
  - Pattern eşleşme yüzdesi (% kaçı tamamlandı?)
  - Eksik adım varsa "muhtemel" / "kesin" ayrımı
  - "Bu saldırı pattern'i %85 tamamlandı. Henüz data exfiltration aşamasına geçilmedi." gibi

### 2.2 — Görsel Olay Örgüsü (Visual Narrative)

- [x] **2.2.1** **Attack Flow Diagram** — otomatik oluşturulan, Mermaid.js / D3.js ile:
  ```
  HR-DESK-023 ──(SYN scan, 47 ports, 32s)──→ FIN-DB-01
       │                                           │
       │  T1046: Network Service Discovery         │
       │                                           │
       ├────(SMB connect, NTLMv2, signing=off)────→│
       │                                           │
       │  T1021.002: SMB/Windows Admin Shares      │
       │                                           │
       ├────(SMB Read: Q4_2026.xlsx, 2.3MB)──────→│
       │                                           │
       │  T1213: Data from Info Repositories       │
       │                                           │
       └────(RDP attempt, FAILED)────────────────→│
                                                   │
          T1021.001: Remote Desktop Protocol       │
  ```
- [x] **2.2.2** **Timeline visualization** — swimlane diagram (aktör, ağ, hedef lane'leri)
- [x] **2.2.3** **Attack tree** — saldırganın izlediği yolu ağaç yapısında göster

---

## 📊 Faz 3 — Rakip Karşılaştırma Matrisi (Competitive Differentiation)

> netscope'un SIEM yeteneklerini rakiplere karşı **sayısal ve işlevsel**
> olarak konumlandırma. Bu matris, hem satış materyali hem de ürün
> stratejisi için kullanılır.

### 3.1 — Yetenek Karşılaştırma Matrisi

- [ ] **3.1.1** Detaylı karşılaştırma tablosu (her hücrede ✅/⚠️/❌ + açıklama):

| Yetenek | netscope | Splunk ES | Elastic Security | QRadar | Sentinel | Graylog | Wazuh |
|---------|----------|-----------|-----------------|--------|----------|---------|-------|
| **Protokol Seviyesi** | | | | | | | |
| Protokol dissector sayısı | ✅ 250+ | ❌ 0 (port-based) | ❌ 0 (port-based) | ❌ 0 | ❌ 0 | ❌ 0 | ❌ 0 |
| Application-layer parsing | ✅ DNS, HTTP/2, SMB, Kerberos, Modbus... | ⚠️ HTTP only | ⚠️ HTTP only | ⚠️ HTTP only | ⚠️ HTTP only | ❌ | ❌ |
| TLS fingerprint (JA3/JA4) | ✅ Built-in | ❌ Plugin gerek | ❌ Plugin gerek | ❌ | ❌ | ❌ | ❌ |
| PQC protocol detection | ✅ 22 algorithm | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ICS/SCADA protokolleri | ✅ 20+ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| LLM/AI traffic analysis | ✅ OpenAI, Anthropic, +12 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Zenginleştirme** | | | | | | | |
| Otomatik MITRE ATT&CK | ✅ Her event'e | ⚠️ Manual rule | ⚠️ Manual rule | ⚠️ Manual rule | ⚠️ Partial | ❌ | ⚠️ Partial |
| Kill Chain mapping | ✅ Her event'e | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Baseline anomaly | ✅ Built-in | ⚠️ ML add-on | ⚠️ ML add-on | ⚠️ ML add-on | ⚠️ ML add-on | ❌ | ❌ |
| İş etkisi skoru | ✅ Built-in | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| "Neden önemli?" açıklaması | ✅ Her alert'te | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GeoIP + ASN | ✅ Offline | ✅ Online | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Anlatı / Korelasyon** | | | | | | | |
| Otomatik hikaye (narrative) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Saldırı pattern tanıma | ✅ 12+ built-in | ⚠️ Custom rule | ⚠️ Custom rule | ⚠️ Custom rule | ⚠️ Custom rule | ❌ | ❌ |
| Görsel attack chain | ✅ Auto-generated | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **SIEM Formatları** | | | | | | | |
| Syslog (RFC 5424) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CEF | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| LEEF | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| OCSF | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| STIX 2.1 | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ |
| Sigma rules | ✅ | ✅ | ✅ | ❌ | ⚠️ | ❌ | ⚠️ |
| **Performans / Maliyet** | | | | | | | |
| Event/saniye (tek node) | ✅ 100k+ | ⚠️ 50k | ⚠️ 25k | ⚠️ 20k | ⚠️ Cloud | ⚠️ 30k | ⚠️ 5k |
| Binary boyutu | ✅ ~8 MB | ❌ 1GB+ | ❌ 500MB+ | ❌ 2GB+ | ❌ Cloud | ⚠️ 100MB | ⚠️ 50MB |
| RAM kullanımı (idle) | ✅ ~50 MB | ❌ 4GB+ | ❌ 2GB+ | ❌ 8GB+ | ❌ Cloud | ⚠️ 1GB | ⚠️ 200MB |
| Lisans | ✅ MIT (ücretsiz) | ❌ $$$$/GB | ⚠️ Ücretsiz + $$ | ❌ $$$$ | ❌ $$$$/GB | ✅ GPL | ✅ GPL |
| Air-gapped çalışma | ✅ | ⚠️ Zor | ⚠️ Zor | ⚠️ Zor | ❌ Cloud only | ✅ | ✅ |

- [ ] **3.1.2** Bu matrisi **interaktif web sayfası** olarak yayınla (netscope.com/siem-comparison)
- [ ] **3.1.3** Her rakibin güncel sürümüyle test edilmiş benchmark verileri
- [ ] **3.1.4** "netscope vs X" başlıklı detaylı karşılaştırma sayfaları (SEO amaçlı da)

### 3.2 — netscope'un Benzersiz Değer Önermeleri (USP)

- [ ] **3.2.1** **USP 1: "Only netscope reads the packet, not just the header"**
  - Rakipler: IP, port, byte count
  - netscope: DNS sorgusu, HTTP path, SMB dosya adı, TLS sertifika CN'si, Modbus function code, Kerberos SPN, JA4 fingerprint
- [ ] **3.2.2** **USP 2: "Every alert comes with a 'why this matters' explanation"**
  - Rakipler: "Alert: port scan from 10.0.1.47"
  - netscope: Tam bir paragraf + MITRE + iş etkisi + aksiyon önerisi
- [ ] **3.2.3** **USP 3: "Understands AI/LLM traffic"**
  - Rakipler: "TCP 443, 2.3 MB"
  - netscope: "GPT-4 call, 847 prompt + 312 completion tokens, cost: $0.031, latency: 842ms, model: gpt-4-turbo"
- [ ] **3.2.4** **USP 4: "Post-quantum ready"**
  - Hiçbir rakip PQC farkındalığına sahip değil
  - netscope: "TLS 1.2, NOT PQC-ready. Recommendation: upgrade to Kyber-1024 hybrid"
- [ ] **3.2.5** **USP 5: "ICS/SCADA visibility"**
  - Hiçbir SIEM Modbus'ın içini okuyamaz
  - netscope: "Modbus Write Single Coil: Start Motor 3 (coil 47 → ON). Source: Engineering workstation ENG-07."
- [ ] **3.2.6** **USP 6: "Rust-native performance"**
  - 100k+ events/sec on a $500 mini PC
  - 8 MB binary vs Splunk'un 1GB+'ı

---

## 🔌 Faz 4 — SIEM Format ve Connector Patlaması

> netscope'un zenginleştirilmiş event'lerini **her türlü SIEM/SOAR/data lake**
> platformuna aktarabilme.

### 4.1 — Çıktı Formatları

- [ ] **4.1.1** **OCSF (Open Cybersecurity Schema Framework) 1.3.0** — AWS Security Lake, Snowflake, Databricks
  - `security_finding` class — alert'ler için
  - `network_activity` class — ham event'ler için
  - `detection_finding` class — threat detection'lar için
- [ ] **4.1.2** **STIX 2.1** — TAXII server üzerinden threat intel paylaşımı
  - netscope'ta tespit edilen IOC'leri STIX bundle olarak export
  - TAXII server endpoint'i (`/taxii2/`)
  - Diğer SOC araçlarıyla otomatik IOC paylaşımı
- [ ] **4.1.3** **Sigma Rules** — cross-SIEM portable detection
  - netscope alert kurallarını Sigma formatına dönüştür (export)
  - Sigma kurallarını netscope formatına import et
  - SigmaHQ topluluk kurallarını otomatik çek (haftalık sync)
- [ ] **4.1.4** **AsyncAPI** — event-driven mimari dokümanı
  - netscope'un event schema'larını AsyncAPI spec olarak yayınla
  - Müşteriler kendi entegrasyonlarını bu spec'ten üretsin
- [ ] **4.1.5** **YAML/JSON Schema** — her event tipi için formal schema

### 4.2 — Connector'lar (Mevcut Elasticsearch + Splunk'a ek)

- [ ] **4.2.1** **Kafka** — Confluent Schema Registry ile AVRO/Protobuf
- [ ] **4.2.2** **Amazon S3** — Parquet formatında (Athena/Redshift Spectrum ile sorgulanabilir)
- [ ] **4.2.3** **Google Cloud Storage** — Parquet + BigQuery external table
- [ ] **4.2.4** **Azure Data Lake Storage Gen2** — Parquet
- [ ] **4.2.5** **Loki** — Grafana Loki'ye direkt push (label-based indexing)
- [ ] **4.2.6** **OpenTelemetry (OTLP)** — traces + metrics + logs (zaten LLM için kısmen var)
- [ ] **4.2.7** **Fluentd / Fluent Bit** — output plugin
- [ ] **4.2.8** **Vector** — sink olarak netscope event'lerini besleme
- [ ] **4.2.9** **TimescaleDB** — hypertable ile zaman serisi event depolama
- [ ] **4.2.10** **ClickHouse** — yüksek hacimli event analitiği için columnar storage

---

## 📈 Faz 5 — SIEM Dashboard (Analist Deneyimi)

### 5.1 — "Analyst Command Center"

- [ ] **5.1.1** **Unified search** — tüm event'ler, alert'ler, narrative'ler, threat intel tek bir search bar'da
  ```sql
  -- Display filter: smb && ip.dst in 10.0.5.0/24 && time > -24h
  ```
- [ ] **5.1.2** **Search autocomplete** — IP, hostname, protocol, ATT&CK technique, event type
- [ ] **5.1.3** **Search result "explain"** — her sonuç için "bu neden eşleşti?" açıklaması (rule-based: hangi filter kısmının hangi event alanıyla eşleştiğini göster)
- [ ] **5.1.4** **Saved filter templates** — sık kullanılan sorgular için önceden tanımlanmış filtreler: "Finance sunucusuna gece erişim" → `ip.dst in finance_segment && time between 22:00-06:00` (LLM yerine kullanıcının kaydettiği preset'ler)
- [ ] **5.1.5** **Pivot (ilişkili veriye atlama)** — tek tıkla:
  - Bu IP'den başka event'ler
  - Bu kullanıcının diğer aktiviteleri
  - Bu JA4 fingerprint nerelerde görülmüş
  - Bu domain'in DNS geçmişi
  - Bu SMB session'da erişilen diğer dosyalar

### 5.2 — SIEM İçinde Eğitim (Built-in Education)

- [ ] **5.2.1** **Her event tipi için "Learn more"** — mevcut `education` modülüne bağla
- [ ] **5.2.2** **"What does this alert mean?"** — pop-up açıklama, örnek senaryo, MITRE bağlantısı
- [ ] **5.2.3** **"How would an attacker use this?"** — her event tipi için saldırı senaryosu
- [ ] **5.2.4** **"How to investigate"** — adım adım triage rehberi (Jr. analistler için)
- [ ] **5.2.5** **Gamification** — analistlerin çözdüğü alert sayısı, doğruluk oranı, hız

---

## 🧪 Faz 6 — SIEM Kalite Metrikleri

> SIEM'in kendi sağlığını ve etkinliğini ölçen metrikler.

- [ ] **6.1** **Alert kalitesi:**
  - False positive oranı (günlük, kural başına)
  - True positive oranı
  - Alert → acknowledge süresi (MTTA — Mean Time to Acknowledge)
  - Alert → resolve süresi (MTTR — Mean Time to Resolve)
  - Gürültü skoru (1 saatte üretilen alert / manuel kapatılan)
- [ ] **6.2** **Event zenginleştirme kalitesi:**
  - Zenginleştirme tamlık oranı (kaç event'in tüm 7 katmanı dolu?)
  - Threat intel hit rate (event'lerin % kaçında threat intel eşleşmesi var?)
  - Baseline sapma dağılımı (event'lerin % kaçı anormal?)
- [ ] **6.3** **Analist productivity:**
  - Saat başına triage edilen alert
  - Pivot sayısı / alert
  - Narrative'ten sonra aksiyon alınma oranı
- [ ] **6.4** **SIEM performansı:**
  - Event ingestion latency (sensör → SIEM'de görünme süresi)
  - Search response time (P50, P95, P99)
  - Dashboard render time

---

## 🎯 Faz 7 — "Sadece netscope'un Yapabileceği" 10 Özellik

Bu özellikler **hiçbir rakip SIEM'de yok** — çünkü hiçbiri paket seviyesinde derinlemesine analiz yapmıyor:

- [ ] **7.1** **JA4/JA3 Hunt** — "Bu TLS fingerprint'e sahip tüm bağlantıları bul" → C2 sunucusu avı
- [ ] **7.2** **PQC Migration Tracker** — Organizasyonun PQC'ye geçiş yüzdesini canlı takip: "Sunucuların %37'si PQC-ready, %63'ü değil"
- [ ] **7.3** **LLM Cost Leakage** — "Hangi çalışan GPT-4'e en çok para harcıyor?" → Shadow AI tespiti
- [ ] **7.4** **Kerberos Attack Timeline** — Kerberos TGT/ST isteklerini analiz ederek Golden Ticket, Silver Ticket, AS-REP roasting tespiti
- [ ] **7.5** **SMB File Access Audit** — "Dün gece kim hangi dosyaya SMB üzerinden erişti?" — tam dosya yolu ile
- [ ] **7.6** **DNS Exfil Detection** — DNS sorgu uzunluğu/frekansı/entropi analizi ile DNS tünelleme tespiti
- [ ] **7.7** **Industrial Sabotage Detection** — "Modbus Write Single Coil ile motor durduruldu" → ICS/SCADA saldırı tespiti
- [ ] **7.8** **Certificate Expiry Predictor** — "14 gün içinde expire olacak 23 TLS sertifikası var" → proaktif uyarı
- [ ] **7.9** **Tracker / Supply Chain Risk** — "Bu web uygulaması 17 tracker/analytics servisi çağırıyor, 3'ü riskli ülkede" → tedarik zinciri riski
- [ ] **7.10** **Encrypted Traffic Analysis (ETA)** — Paket boyutu, zamanlama, yön istatistikleriyle şifreli trafikte bile anomali tespiti (JA4 + timing + byte distribution)

---

## 🗓 Önerilen MVP Yol Haritası (İlk 10 Hafta)

| Hafta | İş |
|-------|-----|
| **1-2** | Semantic enrichment engine — 7 katmanlı zenginleştirme, `EnrichedEvent` struct, OCSF uyumlu event schema |
| **3-4** | `human_readable` alanı için template engine + her event tipine özel şablonlar; "why this matters" jeneratörü |
| **5-6** | Narrative correlation engine — 12+ saldırı pattern'i, event grouper, Kill Chain phase detector, template filler |
| **7** | Competitive comparison matrisini interaktif web sayfası olarak yayınla + benchmark verilerini topla |
| **8** | SIEM format patlaması: OCSF, STIX 2.1, Sigma import/export, Kafka connector (AVRO), Parquet export |
| **9** | "Analyst Command Center" dashboard — unified search, doğal dil → filter, pivot, "Learn more" entegrasyonu |
| **10** | "Sadece netscope'un yapabileceği" 10 özelliğin her biri için demo senaryosu + demo pcap + demo rapor |

---

> **Stratejik konumlandırma:** netscope asla "bir SIEM daha" olarak
> pazarlanmamalı. netscope, **"paketin içini gören, olayı hikaye olarak
> anlatan, analiste 'neden önemli?' sorusunun cevabını veren"** bir
> sistem olarak konumlandırılmalı. Rakiplerin SIEM'leri **raw data**
> gösterir — netscope **insight** gösterir.
>
> **Her checkbox, piyasadaki en açıklayıcı SIEM'i inşa etmek için
> gereken somut iş kalemidir.**
