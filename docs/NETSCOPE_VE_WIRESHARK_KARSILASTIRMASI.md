# Netscope ve Wireshark Karşılaştırma Analizi (Netscope vs. Wireshark)

Bu doküman, Netscope projesi ile endüstri standardı paket analizörü Wireshark arasındaki mimari, operasyonel ve kullanıcı deneyimi (UX) farklarını ortaya koyar. Ayrıca "Kullanıcılar neden Netscope'u tercih etmeli?" sorusuna yanıt verir.

---

## 1. Mimari ve Temel Odak Noktaları

| Özellik | Wireshark | Netscope |
| :--- | :--- | :--- |
| **Ana Odak** | Derin Paket İncelemesi (DPI), Protokol Hata Ayıklama (Debugging) | Ağ Tehdidi Tespit/Yanıt (NDR) ve Güvenlik Operasyonları (SOC) |
| **Güvenlik Duruşu** | Pasif Analiz (Pasif dinleme yapar, trafiğe müdahale etmez) | Aktif Analiz & Yanıt (IP Bloklama, Canlı Uyarılar) |
| **Dil & Güvenlik** | Büyük oranda C (Bellek güvenliği açıkları ve dissector CVE'leri yaygındır) | %100 Güvenli Rust (Bellek güvenli, yüksek paralel işlem gücü) |
| **Dağıtım Modeli** | Yerel Masaüstü Uygulaması (Tekil makine analizi) | Dağıtık Ajan-Sunucu Mimarisi (Merkezi yönetim ve izleme) |

---

## 2. Derinlemesine Karşılaştırma (Neden Farklıyız?)

### 2.1. Güvenlik Operasyonları (SOC/SIEM) ve Otomasyon
*   **Wireshark:** Ağdaki bir anomaliden dolayı alarm üretemez, otomatik e-posta gönderemez, Slack veya Telegram botuyla entegre olamaz. Tamamen reaktiftir (olay gerçekleştikten sonra PCAP dosyası incelenir).
*   **Netscope:** Gerçek zamanlı uyarı motoruna sahiptir ([`notifications.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/notifications.rs)). Anormal trafik hacmi veya şüpheli port taramaları tespit edildiğinde anında Slack, Telegram, E-posta veya Windows Event Log kanalları üzerinden SOC ekiplerine bildirim gönderir.

### 2.2. Aktif Tehdit Önleme (Firewall/Blocking)
*   **Wireshark:** Şüpheli veya zararlı bir IP'nin (örn: C2 Sunucusu) ağ bağlantısını kesemez.
*   **Netscope:** Entegre güvenlik duvarı arayüzü ([`firewall.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/firewall.rs)) sayesinde, analist tek bir tıklama ile zararlı trafiği üreten IP adresini OS düzeyinde (Windows Filtering Platform / iptables) bloklayabilir.

### 2.3. Baseline ve Yapay Zeka Tabanlı Anomali Tespiti
*   **Wireshark:** Ağın normal (baseline) durumunun ne olduğunu bilmez. İki PCAP dosyası arasındaki anomaliyi bulmak için analistin el yapımı filtreler yazması gerekir.
*   **Netscope:** Otomatik baseline analizörü ([`baseline.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/baseline.rs)) sayesinde, ağdaki sıradışı trafik artışlarını ve yeni eklenen yabancı hostları (makineleri) otomatik tespit eder.

### 2.4. Kullanıcı Deneyimi (UX) ve Eğitim Odaklılık
*   **Wireshark:** Arayüzü oldukça yoğundur. Ağ mühendisliği geçmişi olmayan birinin protokol detaylarını (örn: TCP Handshake bayrakları) anlaması günler sürer.
*   **Netscope:** Bünyesinde barındırdığı interaktif eğitim modülü ([`education.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/education.rs)) sayesinde, yakalanan her bir protokolün ne işe yaradığını, neden önemli olduğunu ve pakette neyi aramamız gerektiğini plain-language (sade dil) ile açıklar.

### 2.5. Dahili Derin Paket İnceleme (DPI Engine)
*   **Wireshark:** Karmaşık C kütüphaneleri ve dissector yapısıyla analiz yapar (C bellek açıkları ve CVE riski taşır).
*   **Netscope:** %100 Güvenli Rust ile geliştirilmiş yerleşik `DpiEngine` ([`dpi.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dpi.rs)) sayesinde Shannon entropi hesabı, otomatik payload sınıflandırması (JSON, SSE Stream, Executable Header, High-Entropy Encrypted), adres offsetli Hex/ASCII dökümü ve canlı zararlı payload (SQLi, XSS, Path Traversal, Unencrypted Credentials) tespiti yapar.

---

## 3. Kullanıcılar Netscope'u Kullanır mı? (Hedef Kitle ve Kullanım Senaryoları)

**Evet, Netscope'un Wireshark'ın yerini almaya çalışmak yerine hedeflediği benzersiz kullanım senaryoları (use cases) kullanıcıları çekmektedir:**

### Scenario A: SOC ve Güvenlik Analistleri (Hızlı TriaJ)
*   Analistler binlerce paket satırı arasında kaybolmak istemezler. Netscope'un **SOC Paneli** onlara kritik alarmları ve aktif tetikleyicileri doğrudan sunar. Analistlerin öncelikli tercihidir çünkü reaktif analiz yerine proaktif koruma sağlar.

### Scenario B: Sistem ve Ağ Yöneticileri (Hafif Sunucu İzleme)
*   Wireshark, sunucularda 7/24 arka planda çalıştırmak için ağır ve güvensizdir. Netscope ise hafif Rust ajan yapısıyla ([`netscope-agent`](file:///c:/Users/efe/Desktop/netscope/crates/agent/src/main.rs)) sunucularda minimum CPU/RAM tüketerek çalışır ve anomalileri merkeze raporlar.

### Scenario C: Siber Güvenlik Öğrencileri ve Junior Analistler (Öğrenim)
*   Wireshark sadece ham veri gösterirken, Netscope **"Öğren" (Learn)** sekmesiyle ağ analizini pratik yaparak öğrenmek isteyenler için harika bir interaktif eğitim platformudur.

---

## 4. Özet Sonuç

*   **Wireshark**, bir ağ paketinin her bir bitini (bit-level) incelemek isteyen **Protokol Uzmanları** için en iyi araçtır.
*   **Netscope**, ağ trafiğini sürekli izlemek, tehditleri anında yakalamak, takımı uyarmak ve zararlı bağlantıları hemen kesmek isteyen **Güvenlik Operasyonları (SOC) ve Sistem Yöneticileri** için kurumsal seviyede modern bir platformdur.
