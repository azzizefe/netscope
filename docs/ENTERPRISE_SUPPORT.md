# 🎯 netscope — Kurumsal Destek / SLA · Öncelikli Destek · Profesyonel Hizmetler

> **Mevcut durum:** netscope açık kaynak (MIT), GitHub Issues + Discussions
> üzerinden topluluk desteği var. Herhangi bir ticari destek paketi, SLA
> taahhüdü, öncelikli destek kanalı veya profesyonel hizmet sunumu yok.
>
> Bu spesifikasyon, **açık kaynak çekirdeği koruyarak** üzerine kurumsal
> destek katmanı inşa etmek için gereken her şeyi tanımlar. Model: **açık
> kaynak (MIT) + ücretli enterprise destek** — Redis, Elasticsearch, GitLab
> ile aynı strateji.
>
> Hedef kitle: **SOC ekipleri, kritik altyapı işleten kurumlar, regülasyona
> tabi sektörler** (finans, sağlık, enerji, telekom, kamu).

---

## 🏗️ Destek Modeli Mimarisi

```
┌──────────────────────────────────────────────────────────────┐
│                    netscope Destek Piramidi                    │
│                                                               │
│                         ┌─────────┐                           │
│                         │  TAM +  │  ← Technical Account      │
│                         │  SLA    │     Manager (Enterprise)  │
│                         ├─────────┤                           │
│                         │ 24×7    │  ← Priority Support       │
│                         │ Support │     (Professional)        │
│                         ├─────────┤                           │
│                         │ İş      │  ← Business Hours         │
│                         │ Saatleri│     (Standard)            │
│                         ├─────────┤                           │
│                         │ Topluluk│  ← Community (herkese     │
│                         │ Desteği │     açık, ücretsiz)       │
│                         └─────────┘                           │
│                                                               │
│  ← ÜCRETSİZ (MIT) → │ ← ÜCRETLİ (Enterprise) →              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 Faz 1 — Destek Paketleri (Support Tiers)

### 1.1 — Community (Ücretsiz)

- [ ] **1.1.1** **GitHub Issues** — bug raporu, feature request (şu an aktif)
- [ ] **1.1.2** **GitHub Discussions** — soru-cevap, topluluk yardımlaşması (şu an aktif)
- [ ] **1.1.3** **Discord / Slack topluluk sunucusu** — "netscope Community" (ücretsiz)
  - `#general` — genel sohbet
  - `#help` — kullanıcı soruları
  - `#showcase` — nasıl kullandığını paylaş
  - `#protocol-dev` — yeni dissector geliştirme
  - `#jobs` — netscope bilen eleman arayanlar
- [ ] **1.1.4** **Stack Overflow** — `[netscope]` etiketi ile soru-cevap
- [ ] **1.1.5** **Belgeler** — docs.netscope.com (zaten `docs/` altında 10+ dosya var, genişletilecek)
- [ ] **1.1.6** **Topluluk çağrısı** — ayda bir 30dk Zoom/Meet, roadmap paylaşımı, Q&A

### 1.2 — Standard (Ücretli — İş Saatleri)

| Özellik | Detay |
|---------|-------|
| **Kanal** | Email ticket + portal |
| **Saat** | İş günleri 09:00-18:00 (yerel saat) |
| **İlk yanıt** | 8 iş saati |
| **Öncelik** | Normal kuyruk |
| **Güncelleme** | Ayda 1 sürüm (stable) |
| **Kapsam** | Kurulum, yapılandırma, hata düzeltme |
| **Max sensör** | 50 |
| **Fiyat** | €X / sensör / yıl |

- [ ] **1.2.1** Email ticket sistemi (help@netscope.com → Zendesk / Freshdesk / Linear)
- [ ] **1.2.2** Support portal (self-servis):
  - Ticket oluşturma ve takip
  - Ticket geçmişi (şirket bazında tüm ticket'lar)
  - Knowledge base (çözüm makaleleri)
  - Sistem durumu sayfası (status.netscope.com)
  - Lisans yönetimi (kaç sensör, ne zaman bitiyor)
- [ ] **1.2.3** Auto-response — ticket açıldığında otomatik "aldık" maili + ticket numarası
- [ ] **1.2.4** SLA dashboard — şirketin kendi ticket metrikleri (ortalama yanıt süresi, çözüm süresi, CSAT)

### 1.3 — Professional (Ücretli — 24×7)

| Özellik | Detay |
|---------|-------|
| **Kanal** | Email + Telefon + WhatsApp/Telegram (ops.) |
| **Saat** | 7×24 (365 gün) |
| **İlk yanıt** | Severity 1: 1 saat · Sev 2: 4 saat · Sev 3: 8 saat · Sev 4: 24 saat |
| **Çözüm süresi** | Sev 1: 4 saat · Sev 2: 12 saat · Sev 3: 48 saat · Sev 4: next release |
| **Öncelik** | Öncelikli kuyruk |
| **Güncelleme** | Ayda 1 sürüm + hotfix (kritik bug'lar için 24 saat içinde) |
| **Kapsam** | Kurulum, yapılandırma, hata, performans, upgrade |
| **On-call** | Telefonla 7×24 erişilebilir mühendis |
| **Max sensör** | 500 |
| **Fiyat** | €X / sensör / yıl |

- [ ] **1.3.1** 7×24 nöbetçi mühendis rotasyonu (follow-the-sun: İstanbul → Londra → New York)
- [ ] **1.3.2** PagerDuty / Opsgenie entegrasyonu — Sev 1 ticket → otomatik on-call ara
- [ ] **1.3.3** Telefon hattı (VoIP, ülke bazlı lokal numaralar: TR, DE, UK, US)
- [ ] **1.3.4** Hotfix SLA'si — kritik güvenlik açığı: 24 saat içinde patch, 72 saat içinde release

### 1.4 — Enterprise (Ücretli — 24×7 + TAM)

| Özellik | Detay |
|---------|-------|
| **Kanal** | Email + Telefon + WhatsApp + Slack Connect + Özel portal |
| **Saat** | 7×24 (365 gün) |
| **İlk yanıt** | Sev 1: 15 dk · Sev 2: 1 saat · Sev 3: 4 saat · Sev 4: 8 saat |
| **Çözüm süresi** | Sev 1: 2 saat · Sev 2: 8 saat · Sev 3: 24 saat · Sev 4: 7 gün |
| **TAM** | Evet — adanmış Technical Account Manager |
| **Onboarding** | Beyaz eldiven kurulum, 3 gün onsite/remote |
| **Quarterly business review** | Evet — TAM liderliğinde |
| **Health check** | Ayda 1 proaktif sistem sağlık kontrolü |
| **Güncelleme** | Stable + hotfix + early access (beta'yı 2 hafta önce test etme) |
| **Custom dev** | Yılda 40 saat özel geliştirme (dissector, kural, entegrasyon) |
| **Eğitim** | Yılda 2 gün (8'er saat) ekip eğitimi |
| **Max sensör** | Sınırsız |
| **Fiyat** | €X / sensör / yıl (hacim indirimi: 1.000+ sensör) |

- [ ] **1.4.1** **Dedicated Slack Connect channel** — müşteri ↔ netscope destek ekibi arasında özel kanal
- [ ] **1.4.2** **TAM (Technical Account Manager)** ataması:
  - Tek bir kişi, müşterinin tüm teknik ihtiyaçlarının sahibi
  - Ayda 1 check-in call (30 dk)
  - Çeyrekte 1 QBR (Quarterly Business Review) — "son 3 ayın metrikleri, roadmap, öneriler"
  - Yılda 1 onsite ziyaret (isteğe bağlı)
- [ ] **1.4.3** **Custom development** havuzu (40 saat/yıl):
  - Yeni dissector yazımı (müşterinin özel protokolü)
  - Özel alert kuralı
  - Özel SIEM connector
  - Özel rapor şablonu
- [ ] **1.4.4** **Early access program** — yeni sürümleri GA'dan 2 hafta önce test etme hakkı
- [ ] **1.4.5** **Named support engineers** — aynı ekip sizi tanır, context kaybı olmaz

---

## ⏱️ Faz 2 — SLA (Service Level Agreement) Tanımı

### 2.1 — Severity (Önem Derecesi) Tanımları

- [ ] **2.1.1** Severity sınıflandırma matrisi:

| Sev | Tanım | Örnek | İlk Yanıt (Ent) | Çözüm (Ent) |
|-----|-------|-------|-----------------|-------------|
| **1 — Critical** | Üretim durdu, veri kaybı var, tüm sensörler offline | Server çöktü, hiçbir sensör event gönderemiyor | 15 dk (telefon) | 2 saat |
| **2 — High** | Kritik fonksiyon çalışmıyor ama sistem kısmen çalışıyor | Alert motoru alert üretmiyor, 10 sensör offline | 1 saat | 8 saat |
| **3 — Medium** | Non-kritik fonksiyon bozuk, workaround var | Bir dissector yanlış parse ediyor, UI hatası | 4 saat | 24 saat |
| **4 — Low** | Kozmetik, dokümantasyon, feature request | Yazım hatası, renk uyumsuzluğu | 8 saat | Next release |

- [ ] **2.1.2** Sev 1 eskalasyon akışı:
  ```
  Dakika 0:     Ticket açılır → PagerDuty alert → On-call mühendis
  Dakika 5:     Mühendis acknowledge eder, Slack kanalına "#sev1 aktif" mesajı
  Dakika 15:    İlk analiz müşteriye iletilir (durum güncellemesi)
  Dakika 30:    Çözüm yoksa → L3 Engineering Lead eskalasyon
  Dakika 60:    Çözüm yoksa → CTO eskalasyon
  Dakika 120:   SLA penceresi kapanır — çözülmüş olmalı
  Çözüm sonrası: Otomatik RCA (Root Cause Analysis) draft'ı oluşturulur
  ```
- [ ] **2.1.3** Sev 1 RCA (Root Cause Analysis) şablonu:
  - Olay özeti
  - Zaman çizelgesi (timeline)
  - Kök neden (5 Why analizi)
  - Etkilenen müşteriler/sensörler
  - Çözüm adımları
  - Kalıcı düzeltici aksiyon (PDCA)
  - Önleyici aksiyon (bir daha olmaması için)

### 2.2 — SLA Metrikleri ve Raporlama

- [ ] **2.2.1** SLA KPI'ları (aylık rapor):
  ```
  📊 SLA Raporu — Ağustos 2026
  ┌─────────────────────────────────────┬──────────┬──────────┐
  │ Metrik                              │ Hedef    │ Gerçekleş│
  ├─────────────────────────────────────┼──────────┼──────────┤
  │ İlk yanıt süresi (Sev 1)           │ ≤ 15 dk  │ 8 dk  ✅ │
  │ İlk yanıt süresi (Sev 2)           │ ≤ 1 saat │ 42 dk ✅ │
  │ İlk yanıt süresi (Sev 3)           │ ≤ 4 saat │ 3.2 sa ✅│
  │ Çözüm süresi (Sev 1)               │ ≤ 2 saat │ 1.5 sa ✅│
  │ Çözüm süresi (Sev 2)               │ ≤ 8 saat │ 6.2 sa ✅│
  │ Uptime SLA (server)                │ %99.95   │ %99.97 ✅│
  │ CSAT (Customer Satisfaction)       │ ≥ 4.5/5  │ 4.7   ✅│
  │ Ticket volume                      │ -        │ 47     │
  │ RCA tamamlanma oranı (Sev 1-2)     │ %100     │ %100  ✅│
  │ Knowledge base makale (yeni/ay)    │ ≥ 5      │ 7     ✅│
  └─────────────────────────────────────┴──────────┴──────────┘
  ```
- [ ] **2.2.2** CSAT (Customer Satisfaction) anketi — her kapanan ticket'tan sonra otomatik 3 soru:
  1. "Sorununuz çözüldü mü?" (Evet/Hayır/Kısmen)
  2. "Destek deneyiminizi 1-5 arası puanlayın" (⭐⭐⭐⭐⭐)
  3. "Eklemek istediğiniz bir şey var mı?" (serbest metin)
- [ ] **2.2.3** SLA breach alert — SLA aşımında otomatik e-posta → Support Manager + TAM
- [ ] **2.2.4** SLA credit — SLA aşımı durumunda müşteriye otomatik kredi (sözleşmede tanımlı)
- [ ] **2.2.5** **Quarterly SLA Review** — TAM müşteriye son 3 ayın SLA metriklerini sunar

---

## 🎓 Faz 3 — Profesyonel Hizmetler (Professional Services)

### 3.1 — Danışmanlık Hizmetleri

- [ ] **3.1.1** **SOC Mimarisi Danışmanlığı** (2-5 gün):
  - Mevcut ağ topolojisi analizi
  - Sensör yerleşim planı (nerelere sensör konmalı)
  - Server boyutlandırma (CPU/RAM/disk/network)
  - SIEM entegrasyon mimarisi
  - Alert stratejisi (hangi kurallar, hangi eşikler)
  - Çıktı: Netscope Deployment Architecture Document
- [ ] **3.1.2** **Ağ Görünürlük Değerlendirmesi** (1-3 gün):
  - 1 haftalık pilot capture
  - "Şu an ağınızda neler oluyor?" raporu
  - Kör noktalar (encrypted traffic, east-west, IoT)
  - Önerilen filtre ve kural seti
- [ ] **3.1.3** **Regülasyon Uyumluluk Danışmanlığı** (1-2 gün):
  - KVKK/GDPR/PCI-DSS/ISO 27001 kapsamında ağ izleme gereksinimleri
  - netscope ile hangi kontroller otomatik denetlenebilir?
  - Eksik kontroller için tamamlayıcı çözüm önerileri
- [ ] **3.1.4** **Tehdit Modelleme** (2-3 gün):
  - Kuruma özel threat model (STRIDE)
  - netscope bu tehditlerin hangilerini tespit edebilir?
  - Tespit edilemeyen tehditler için öneriler
- [ ] **3.1.5** **PQC (Post-Quantum Crypto) Geçiş Değerlendirmesi** (1-2 gün):
  - Mevcut kriptografik durum (TLS version, cipher, sertifika)
  - PQC'ye geçiş yol haritası
  - Risk skoru ve zaman çizelgesi

### 3.2 — Kurulum & Onboarding

- [ ] **3.2.1** **Remote onboarding** (1 gün — Professional pakete dahil):
  - Video call ile kurulum rehberliği
  - Server kurulumu (Docker / bare metal)
  - İlk 10 sensörün deployment'ı ve validasyonu
  - İlk alert'in tetiklenmesi ve ack'lenmesi (uçtan uca test)
  - Ekip eğitimi (2 saat — temel kullanım)
- [ ] **3.2.2** **Onsite onboarding** (3 gün — Enterprise pakete dahil):
  - Gün 1: Mimari workshop, server kurulumu
  - Gün 2: Sensör deployment (50+ sensör), GPO/MSI/MDM setup
  - Gün 3: Ekip eğitimi (tam gün), SOC dashboard özelleştirme, playbook yazma
  - Çıktı: As-Built dokümantasyonu
- [ ] **3.2.3** **Migration hizmeti** (Wireshark / tcpdump / Zeek'ten netscope'a geçiş):
  - Mevcut capture altyapısının analizi
  - Paralel çalışma dönemi (eski sistem + netscope, 2 hafta)
  - Eski sistemin devre dışı bırakılması
- [ ] **3.2.4** **Health check** (aylık — Enterprise pakete dahil):
  - Server performans analizi (CPU, RAM, disk, DB query latency)
  - Sensör health (offline sensörler, config drift, versiyon dağılımı)
  - Alert kalitesi (false positive oranı, alert/ack süresi)
  - Öneriler raporu

### 3.3 — Eğitim Hizmetleri

- [ ] **3.3.1** **netscope 101 — Temel Kullanım** (4 saat):
  - Arayüz turu (Desktop + TUI)
  - Paket yakalama ve analiz
  - Display filter yazma
  - Insights ve Privacy tab'leri
  - Rapor oluşturma
  - Malzeme: Eğitim kitapçığı (PDF) + lab ortamı (önceden hazırlanmış pcap)
- [ ] **3.3.2** **netscope 201 — SOC Operatörlüğü** (8 saat):
  - SOC dashboard kullanımı
  - Alert triage ve incident response
  - Threat hunting (pivot, histogram, query builder)
  - Playbook yazma
  - SIEM entegrasyonu
  - Malzeme: CTF-style lab (içinde flag'ler olan zararlı pcap)
- [ ] **3.3.3** **netscope 301 — Admin & Deployment** (8 saat):
  - Server kurulumu ve yapılandırma
  - PostgreSQL/Redis optimizasyonu
  - Fleet deployment (GPO, MDM, Ansible)
  - mTLS/PKI setup
  - Yedekleme ve disaster recovery
  - RBAC ve audit yapılandırması
  - Custom dissector yazma (Rust)
- [ ] **3.3.4** **netscope 401 — Train the Trainer** (16 saat, 2 gün):
  - Yukarıdaki tüm eğitimleri verebilecek iç eğitmen yetiştirme
  - Sertifika: "netscope Certified Instructor" (NCI)
- [ ] **3.3.5** **Sertifikasyon programı:**
  - **NCSA** — netscope Certified SOC Analyst (sınav: 60 soru, 90 dk, pratik lab)
  - **NCSA-S** — NCSA Senior (2 yıl deneyim + vaka çalışması savunması)
  - **NCSE** — netscope Certified Support Engineer (derinlemesine teknik)
  - **NCI** — netscope Certified Instructor (eğitmen)

### 3.4 — Özel Geliştirme (Custom Development)

- [ ] **3.4.1** **Custom dissector** — müşterinin özel protokolü için parser (Rust)
- [ ] **3.4.2** **Custom SIEM connector** — müşterinin kullandığı spesifik SIEM/SOAR
- [ ] **3.4.3** **Custom alert rule pack** — müşterinin threat modeline özel 20+ kural
- [ ] **3.4.4** **Custom compliance framework** — müşterinin tabi olduğu sektörel regülasyon
- [ ] **3.4.5** **Custom dashboard/report** — müşteri yönetimine özel rapor formatı
- [ ] **3.4.6** **Integration development** — müşterinin mevcut sistemleriyle entegrasyon (Jira, ServiceNow, TheHive)
- [ ] **3.4.7** Teslimat paketi:
  - Kaynak kod (müşteriye ait — telif hakkı müşteride)
  - Test suite (unit + integration)
  - Dokümantasyon (teknik + kullanıcı)
  - 90 gün warranty (bug fix)
  - Opsiyonel: mainline'a merge (müşteri izin verirse)

---

## 🛠️ Faz 4 — Destek Operasyon Altyapısı

### 4.1 — Ticketing Sistemi (Zendesk / Freshdesk / Linear)

- [ ] **4.1.1** Ticket oluşturma kanalları:
  - Email → otomatik ticket (help@netscope.com)
  - Web portal → form (support.netscope.com)
  - API → programatik ticket (müşteri kendi sisteminden)
  - Slack Connect → `/netscope-ticket` slash komutu
- [ ] **4.1.2** Ticket form alanları:
  - Şirket (otomatik — login'den)
  - Destek paketi (otomatik — lisans key'den)
  - Başlık
  - Açıklama (Markdown)
  - Severity (Sev 1-4, açıklamalı radio button)
  - Etkilenen sensör sayısı
  - netscope versiyonu
  - OS/Platform
  - Ek dosyası (log, screenshot, pcap — max 100 MB)
  - "Diagnostics bundle" — otomatik sistem bilgisi ekleme
- [ ] **4.1.3** Ticket SLA tracking — her ticket'ın SLA saati (due date), yaklaşan/geçen SLA'ler için alarm
- [ ] **4.1.4** Ticket otomasyonu:
  - Auto-assign (müşterinin TAM'ı varsa → direkt ona ata)
  - Auto-tag (başlık/içerik analizi ile otomatik etiket: `dissector-bug`, `performance`, `install`)
  - Auto-escalation (SLA yaklaşıyorsa → Support Lead'e bildirim)
  - Auto-close (7 gün müşteriden yanıt yoksa → "kapatılıyor, gerekirse reopen" maili)
- [ ] **4.1.5** Knowledge base entegrasyonu:
  - Ticket kapanırken "bu çözümü KB makalesine dönüştür" butonu
  - Ticket oluştururken benzer KB makalelerini öner ("belki bu sorunuzu cevaplar?")
  - Müşteriye özel KB (şirket içi çözümler)

### 4.2 — Destek Ekibi Yapısı

- [ ] **4.2.1** Ekip rolleri:
  ```
  L1 — Support Engineer (ilk temas, bilinen sorunlar, KB'den çözüm)
       Yetkinlik: netscope kullanımı, temel networking, display filter yazma
       
  L2 — Senior Support Engineer (derinlemesine troubleshooting, bug doğrulama)
       Yetkinlik: Rust debugging, packet analysis, sistem yönetimi
  
  L3 — Engineering (kod düzeltme, hotfix, yeni özellik)
       Yetkinlik: netscope core geliştirici, protocol expert
  
  TAM — Technical Account Manager (müşteri ilişkisi, QBR, proaktif sağlık)
       Yetkinlik: Enterprise IT, SOC operasyonları, proje yönetimi
       
  Support Manager — (SLA yönetimi, ekip koordinasyonu, süreç iyileştirme)
  ```
- [ ] **4.2.2** Follow-the-sun nöbet modeli:
  - İstanbul (GMT+3): 09:00-18:00
  - Londra (GMT+1): 10:00-19:00 (İstanbul ile 2 saat overlap)
  - New York (GMT-4): 08:00-17:00 (Londra ile 4 saat overlap)
  - → 7×24 coverage
- [ ] **4.2.3** Nöbetçi mühendis onboarding:
  - İlk 2 hafta: shadow (deneyimli mühendisi izle)
  - 3-4 hafta: reverse shadow (yeni mühendis yapar, deneyimli izler)
  - 5. hafta: solo (ama escalation desteği hazır)
  - Checklist: 50 maddelik "hazır mısın?" testi
- [ ] **4.2.4** Haftalık support retrospective (30 dk):
  - Geçen haftanın Sev 1-2 ticket'ları
  - SLA aşımı oldu mu?
  - Hangi ticket'larda zorlandık?
  - KB'ye yeni ne eklendi?
  - Müşteri memnuniyetsizliği var mı?

### 4.3 — Diagnostics & Uzaktan Destek Araçları

- [ ] **4.3.1** **Diagnostics bundle** (tek tıkla):
  ```bash
  netscope-agent diagnostics --output diag-20260727-143000.tar.zst
  # İçerik:
  # - config.toml (secrets masked)
  # - agent.log (son 100 MB)
  # - system info (OS, CPU, RAM, disk, NIC list)
  # - agent stats (uptime, pkt/s, event/s, error count)
  # - server connectivity test (ping, TLS handshake, latency)
  # - son 1000 event (anonymize opsiyonu)
  ```
- [ ] **4.3.2** **Remote session** (müşteri onayı ile):
  - SSH ters tünel (müşteri başlatır, destek ekibi bağlanır)
  - Ekran paylaşımı (Zoom/TeamViewer — opsiyonel)
  - Sadece read-only, kayıt altında
  - Session sonunda otomatik kayıt silme
- [ ] **4.3.3** **Health check betiği** (proaktif — haftalık cron):
  ```bash
  netscope-agent health-check
  # Çıktı:
  # ✅ Server bağlantısı: OK (12ms)
  # ✅ mTLS sertifikası: 45 gün kaldı
  # ✅ Capture: eth0, 847 pkt/s
  # ⚠️ Disk: %82 dolu (487 GB / 600 GB)
  # ❌ CPU throttling: %95 (limit: %90)
  # ✅ Versiyon: 0.2.0 (güncel)
  # → Öneri: Disk temizliği yapın veya retention süresini kısaltın
  ```

---

## 📊 Faz 5 — Müşteri Başarı (Customer Success)

### 5.1 — Onboarding Journey

- [ ] **5.1.1** Müşteri yolculuğu zaman çizelgesi:
  ```
  Hafta -2:  Sözleşme imzalanır
  Hafta -1:  TAM atanır, hoş geldin maili, Slack Connect kanalı açılır
  Gün 0:     Kick-off call (30 dk) — beklentiler, zaman çizelgesi, ekip tanışması
  Gün 1-5:   Teknik onboarding (remote/onsite)
  Gün 7:     1 hafta check-in (TAM) — "her şey yolunda mı?"
  Gün 30:    İlk ay sağlık kontrolü — deployment stabil mi?
  Gün 90:    İlk QBR (Quarterly Business Review)
  ```
- [ ] **5.1.2** Welcome kit (Enterprise müşteri):
  - Dijital: Welcome packet PDF (ekip, iletişim bilgileri, kaynak linkleri)
  - Fiziksel (opsiyonel): netscope sticker, hoodie, "netscope Certified" sertifika çerçevesi
- [ ] **5.1.3** Başarı metrikleri (müşteri ile birlikte belirlenir):
  - "İlk 30 günde 100 sensör online"
  - "İlk ay sonunda false positive oranı < %5"
  - "MTTR (Mean Time to Resolve) < 15 dk"

### 5.2 — Health Score & Churn Prevention

- [ ] **5.2.1** Müşteri sağlık skoru (0-100, otomatik hesaplanır):
  ```
  Skor = 
    Sensör online oranı × 25 +
    Ticket CSAT ortalaması × 25 +
    Son 30 günde login var mı? × 15 +
    Versiyon güncelliği × 15 +
    Son QBR yapıldı mı? × 10 +
    Açık Sev 1/2 ticket yok × 10
  ```
- [ ] **5.2.2** Risk flag'leri (TAM dashboard'unda):
  - Skor < 60 → "Kırmızı hesap — müdahale gerek"
  - Son 30 günde hiç login yok → "Kullanmıyorlar — neden?"
  - Sürekli aynı tip ticket → "Eğitim verelim mi?"
  - Lisans yenilemeye 30 gün kaldı → "Renewal yaklaşıyor"

---

## 📜 Faz 6 — Sözleşme & Lisans Yönetimi

- [ ] **6.1.1** **Lisanslama modeli**:
  - Community: MIT (ücretsiz, limitsiz)
  - Standard: €X / sensör / yıl (max 50 sensör)
  - Professional: €X / sensör / yıl (max 500 sensör, hacim indirimi)
  - Enterprise: €X / sensör / yıl (limitsiz, TAM, özel geliştirme)
  - Akademik/Kamu: %50 indirimli
  - Startup (< 20 çalışan, < 5M funding): ilk yıl ücretsiz Professional
- [ ] **6.1.2** **Lisans key yapısı**:
  ```
  nsl_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ├── prefix: nsl_ (netscope license)
  ├── encoded: base58(version + tier + sensor_limit + expiry + hmac)
  └── HMAC-SHA256 ile imzalı, offline doğrulanabilir
  ```
- [ ] **6.1.3** **Lisans yönetim portalı** (müşteri tarafı):
  - Lisans key'ini gir
  - Aktif sensör sayısı / Lisans limiti
  - Lisans bitiş tarihi
  - Yenileme (stripe/ fatura)
- [ ] **6.1.4** **Lisans yönetim paneli** (netscope tarafı):
  - Müşteri başına lisans
  - Kullanım metrikleri (aktif sensör, event/sn, storage)
  - Faturalandırma geçmişi
  - Otomatik fatura (Stripe / offline invoice)
- [ ] **6.1.5** **SLA sözleşmesi** (yasal metin, şablon):
  - Taraflar, süre, kapsam
  - SLA metrikleri ve taahhütler
  - SLA ihlalinde telafi mekanizması (credit)
  - Fesih koşulları
  - Gizlilik ve veri işleme (DPA — Data Processing Agreement)
  - Uyuşmazlık çözümü (tahkim / mahkeme)
- [ ] **6.1.6** **DPA (Data Processing Agreement)** — GDPR/KVKK uyumlu:
  - netscope, müşteri verisini işlemez (on-premise deployment)
  - Destek sırasında paylaşılan diagnostik verilerin kapsamı
  - Veri saklama ve silme politikası
  - Alt işleyenler (sub-processors) listesi (AWS/hosting, Zendesk, Slack, ...)

---

## 🧪 Faz 7 — Kalite Güvencesi (Support QA)

- [ ] **7.1** **Her ay 3 rastgele kapanmış ticket'ın QA review'u** (Support Manager):
  - Doğru severity atanmış mı?
  - SLA karşılanmış mı?
  - Çözüm kalıcı mı, yoksa geçici workaround mu?
  - Müşteri ile iletişim kalitesi (profesyonel, empatik, net)
  - KB makalesi yazılmış mı?
- [ ] **7.2** **Mystery shopper testi** (3 ayda bir):
  - Sahte müşteri olarak ticket aç
  - İlk yanıt süresi, çözüm kalitesi, iletişim ölç
  - Sonuçları Support retrospective'te paylaş
- [ ] **7.3** **Yıllık destek anketi** (tüm müşterilere):
  - Genel memnuniyet (1-10)
  - Destek ekibi değerlendirmesi
  - Ürün değerlendirmesi
  - "netscope'u başkasına önerir misiniz?" (NPS — Net Promoter Score)
  - Açık uçlu: "Neyi daha iyi yapabiliriz?"
- [ ] **7.4** **Support OKR'ları** (çeyreklik):
  - CSAT ≥ 4.5/5
  - Sev 1 SLA ≥ %99
  - Sev 2 SLA ≥ %95
  - Ortalama ilk yanıt < 2 saat
  - KB makalesi ≥ 10 yeni/çeyrek

---

## 🗓 Önerilen MVP Yol Haritası (İlk 8 Hafta)

| Hafta | İş |
|-------|-----|
| **1** | Destek paketleri tanımı (Community/Standard/Professional/Enterprise), fiyatlandırma |
| **2** | Zendesk/Freshdesk kurulumu, support@netscope.com, ticket form, SLA tracking |
| **3** | Support portal (self-servis) + Knowledge base (en az 20 başlangıç makalesi) |
| **4** | PagerDuty entegrasyonu, Sev 1 eskalasyon akışı, on-call rotasyonu |
| **5** | Diagnostics bundle tool (`netscope-agent diagnostics`) |
| **6** | Health check betiği + otomatik weekly report |
| **7** | Lisans key sistemi (generate, validate, revoke) + lisans portalı |
| **8** | NCSA sertifika sınavı (60 soru) + eğitim kitapçığı (netscope 101) |

---

> **Strateji:** Açık kaynak çekirdek (MIT) herkese açık ve ücretsiz kalır.
> Ücretli katman, **SLA, öncelikli destek, TAM, profesyonel hizmetler ve
> sertifikasyon** gibi kurumsal ihtiyaçları karşılar. Bu model Redis,
> Elasticsearch ve GitLab tarafından kanıtlanmıştır.
>
> **Her checkbox, enterprise müşteriye taahhüt edilebilir bir destek
> organizasyonu kurmak için gereken somut iş kalemidir.**
