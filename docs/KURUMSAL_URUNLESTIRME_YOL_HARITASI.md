# Netscope Kurumsal Ürünleştirme & SOC Mimari Yol Haritası (Enterprise Blueprint)

Bu yol haritası, Netscope'un tekil bir masaüstü/TUI arayüzünden, kurumsal ölçekte binlerce sunucu ve iş istasyonunu izleyebilen, SIEM/SOAR entegrasyonuna sahip merkezi bir **Dağıtık Ağ Tehdit Algılama ve Müdahale Platformuna (Distributed Network Detection & Response - NDR)** dönüştürülmesi için yapılması gereken mimari ve teknik adımları içerir.

---

## 1. Merkezi Ajan Yönetimi & Sensör Orkestrasyonu (Fleet Management)
Uygulamanın kurumsal ağlardaki binlerce makinede sensör olarak çalışması ve tek bir merkezden yönetilmesi adımları.

- [x] **1.1. Merkezi Konfigürasyon Dağıtımı (Centralized Config Push):**
  *   Ajanların ([`netscope-agent`](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/main.rs)) yerel `config.toml` dosyalarını manuel düzenlemek yerine, sunucudan ([`netscope-server`](file:///c:/Users/efe/Desktop/netscope/crates/server/src/main.rs)) gRPC/WebSocket aracılığıyla anlık kural (`rules/`), PII maskeleme kuralları ve paket yakalama filtreleri çekmesini sağlayın.
- [x] **1.2. Ajan Durum ve Sağlık Paneli (Sensors Dashboard):**
  *   Tauri arayüzündeki **SOC** sekmesine, sunucuya bağlı tüm aktif ajanları (IP, Hostname, CPU/RAM kullanımı, anlık PPS ve Packet Drop oranları) listeleyen bir grid görünümü ekleyin.
- [x] **1.3. Otomatik Yaygınlaştırma (Mass Deployment & IaC):**
  *   Windows Active Directory ortamları için MSI paketini sessiz kurulum (`msiexec /i netscope.msi /qn`) parametreleriyle yapılandırın.
  *   Linux sunucu parkları için ajanın Docker, Systemd ve Ansible playbook entegrasyonlarını tamamlayın.

---

## 2. SIEM, SOAR & Log Yönetimi Entegrasyonları
SOC ekiplerinin tehditleri merkezi log havuzlarında analiz edebilmesi ve otomatik aksiyon alabilmesi için gereken entegrasyonlar.

- [x] **2.1. Syslog / CEF / LEEF Doğrudan İletim (Log Forwarder):**
  *   Uygulamanın ürettiği akıllı uyarıları ve anomali loglarını doğrudan Splunk, IBM QRadar veya Elastic Stack'e iletmek üzere RFC 5424 uyumlu şifreli (TLS üzerinden TCP) Syslog aktarıcısı geliştirin.
- [x] **2.2. Otomatik Müdahale (SOAR Entegrasyonu & Playbook tetikleyiciler):**
  *   Bir C2 (Command & Control) beacon trafiği algılandığında veya kritik bir anomali tespit edildiğinde, platformun güvenlik duvarı bloklama modülünü ([`firewall.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs)) SOAR sistemlerine (örn: Cortex XSOAR, Shuffle) API üzerinden maruz bırakın.
- [x] **2.3. Windows Event Log ve Linux Journald Derin Entegrasyonu:**
  *   Tehdit alarmlarını Windows Event Log altında özel bir *Event Source (Netscope)* olarak Event ID'leri ile kaydedin.

---

## 3. Kurumsal Kimlik ve Erişim Güvenliği (Enterprise IAM & RBAC)
SOC ekiplerinin farklı yetki seviyelerindeki analistler tarafından güvenli bir şekilde kullanılabilmesi için gereken kimlik altyapısı.

- [x] **3.1. SSO & Kurumsal Kimlik Doğrulama (SAML 2.0 / OIDC):**
  *   Masaüstü ve Web konsoluna giriş için Azure AD, Okta veya Keycloak entegrasyonlarını (OpenID Connect / OAuth2) ekleyin.
- [x] **3.2. Rol Tabanlı Erişim Kontrolü (RBAC):**
  *   **Tier 1 Analyst:** Sadece alarmları görebilir, ham paket içeriğini (payload) göremez.
  *   **Tier 2/3 Incident Responder:** Alarmları görebilir, şüpheli paketlerin içeriğini (PCAP) indirebilir, IP bloklayabilir.
  *   **Auditor / Compliance Officer:** Sadece kurumsal uyumluluk (KVKK, ISO 27001) raporlarını alabilir.
  *   **Admin:** Tüm konfigürasyonu ve sensör ayarlarını değiştirebilir.

---

## 4. Veri Güvenliği ve KVKK / GDPR Uyum Paketleri
Ağ trafiğinde uçuşan kredi kartı, şifre ve kişisel verilerin yasalara uygun olarak işlenmesi adımları.

- [x] **4.1. Uçta (Sensör Seviyesinde) PII Temizliği (Scrubbing at the Edge):**
  *   Paket içeriği sensör tarafından yakalandığı an, daha sunucuya veya log veritabanına gönderilmeden önce e-posta, kredi kartı ve kimlik numaraları gibi kişisel verileri maskeleyin ([`privacy.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/privacy.rs) mimarisini sensör seviyesinde çalıştırın).
- [x] **4.2. Kriptografik Denetim Günlüğü (Immutable Audit Trail):**
  *   Analistlerin aldığı tüm aksiyonları (kim hangi paketi inceledi, hangi IP'yi blokladı, ne zaman oturum açtı), SHA-256 zinciriyle birbirine bağlı, kurcalanamaz (tamper-proof) bir veritabanı tablosunda saklayın.

---

## 5. Dağıtık Paket Yakalama & Adli Bilişim (Distributed Forensics)
Merkezi SOC analistinin uzak bir sensörden canlı veya geçmişe dönük paket çekebilmesi.

- [x] **5.1. Akıllı Ön-Tamponlama (Smart Packet Pre-buffering):**
  *   Sensörler üzerinde sürekli olarak son 10 saniyelik ham paket verisini RAM'de ring-buffer olarak tutun. Bir tehdit algılandığında (tetikleyici çalıştığında), alarm anından 5 saniye öncesini ve 5 saniye sonrasını içeren PCAP dosyasını otomatik olarak oluşturup sunucuya yükleyin (Sıfır veri kaybıyla tehdit analizi).
- [x] **5.2. İsteğe Bağlı Uzak PCAP İndirme (On-Demand Remote PCAP):**
  *   Analistin, Tauri arayüzü üzerinden belirli bir ajanı seçip filtre yazarak (örn: `tcp.port == 80`) o makinenin ağ kartından canlı paket akışını gRPC Stream üzerinden kendi ekranına yansıtmasını sağlayın.

---

## 6. Yüksek Performanslı Kernel-Bypass Yakalama
1 Gbps ve üzeri kurumsal omurga trafiklerinde paket kaçırmadan (zero packet loss) analiz yapabilmek için çekirdeğin donanım hızlandırma entegrasyonları.

- [x] **6.1. eBPF / XDP Arka Ucu (Linux):**
  *   Linux sunucularda ağ kartına gelen paketleri daha kernel ağ yığınına (network stack) girmeden eBPF / XDP filtreleri ile yakalayıp doğrudan netscope ring buffer'ına yazın.
- [x] **6.2. DPDK (Data Plane Development Kit) Entegrasyonu:**
  *   Veri merkezlerindeki 10G/40G switch ayna (SPAN) portlarından gelen yoğun trafiği kernel bypass yöntemiyle doğrudan donanım seviyesinde işleyin.

---

## 7. Gelişmiş Tehdit Avcılığı & Yapay Zeka Anomali Analizi (Threat Hunting & AI Analytics)
SOC analistlerinin karmaşık ve gizli tehditleri yapay zeka ve davranışsal analiz modelleriyle tespit edebilmesi.

- [x] **7.1. Makine Öğrenmesi Tabanlı Ağ Davranış Analizi (UEBA & Baseline Anomaly):**
  *   Ağdaki cihazların varsayılan bant genişliği kullanımı, aktif çalışma saatleri ve iletişim kurduğu IP/port profillerini öğrenip, alışılagelmişin dışına çıkan şüpheli veri sızıntılarını (Data Exfiltration) anomali skoru ile derecelendirin.
- [x] **7.2. Otomatik MITRE ATT&CK® Haritalama ve Saldırı Zinciri Görselleştirme:**
  *   Algılanan tüm alarmları ve olay dizilerini MITRE ATT&CK Taktik ve Tekniklerine (T1071 Application Layer Protocol, T1041 Exfiltration, T1095 Non-Application Layer Protocol) otomatik eşleyerek görsel siber saldırı matrisi sunun.

---

## 8. Kurumsal Dayanıklılık & Yüksek Erişilebilirlik (HA & Disaster Recovery)
Kesintisiz izleme ve yüksek erişilebilirliğe sahip kurumsal düğüm mimarileri.

- [x] **8.1. Çoklu Sunucu Kümeleme & Yük Dengeleme (Active-Active HA Clustering):**
  *   `netscope-server` örneklerini birden fazla düğümde (node) çalıştırıp gRPC ve ortak veritabanı/mesaj kuyruğu entegrasyonuyla binlerce sensörden gelen trafiği yük dengelemeli ve kesintisiz işleyin.
- [x] **8.2. Sensör Otomatik İyileştirme & Dayanıklılık (Sensor Watchdog & Fail-Safe):**
  *   Ajanların bellek veya CPU sınırına ulaştığı durumlarda otomatik olarak dinamik paket örnekleme (adaptive sampling) moduna geçmesini ve olası servis aksamalarında veri kaybetmeden kendiliğinden kurtarılmasını sağlayın.

---

## 9. OT / IoT ve Endüstriyel Ağ Güvenliği (ICS / SCADA Security)
Kritik altyapı ve endüstriyel üretim tesislerinin (OT) ağ güvenliği denetimi.

- [ ] **9.1. Endüstriyel Ağ Protokolleri Derin Paket İncelemesi (ICS/SCADA DPI):**
  *   Modbus TCP, DNP3, IEC 60870-5-104 ve BACnet gibi SCADA/ICS ağ protokollerinin komut setlerini ve kayıt değerlerini inceleyerek yetkisiz PLC müdahalelerini ve anormal endüstriyel trafiği tespit edin.
