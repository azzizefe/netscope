# Netscope SOC Modülü Ayıklama ve Test Rehberi (SOC Debugging & Testing Guide)

Bu rehber, arayüzdeki **SOC (Güvenlik Operasyon Merkezi)** sekmesinde yer alan butonların, bildirim kanallarının, nöbetçi/alarm takip sistemlerinin çalışma mekanizmasını ve bunları nasıl test edip hataları ayıklayacağınızı (debugging) açıklamaktadır.

---

## 1. SOC Panelindeki Elemanların Durumu (Hangileri Çalışıyor?)

Arayüzde gördüğünüz tüm temel bileşenler Rust arka ucuna ([`lib.rs`](file:///c:/Users/efe/Desktop/netscope/desktop/src-tauri/src/lib.rs)) ve [`app.js`](file:///c:/Users/efe/Desktop/netscope/desktop/frontend/app.js) üzerindeki arayüz mantığına bağlıdır:

1.  **SOC Sunucusu "Bağlan" Butonu:**
    *   **Çalışma Mantığı:** Girilen URL'yi (varsayılan `http://localhost:8080`) doğrular ve arayüzde gizli duran bir `iframe` içine yükler. 
    *   **Doğrulama:** Eğer arka planda çalışan bir `netscope-server` gRPC/REST sunucunuz varsa, "Bağlan" dediğinizde yerel SOC paneli gizlenir ve sunucu arayüzü iframe içinde yüklenir. "Bağlantıyı Kes" dediğinizde yerel arayüze geri döner.
2.  **Windows Event Log "Test" Butonu:**
    *   **Çalışma Mantığı:** **Doğrudan çalışır.** Windows üzerinde ek bir şifre/adres gerekmediği için varsayılan olarak *"Yapılandırıldı"* (Configured) görünür. "Test" butonuna bastığınızda Rust arka ucu Windows Application Log (Uygulama Günlüğü) alanına bir test girdisi yazar.
3.  **Bildirim Kanalları (Syslog, SMTP, Slack, Telegram):**
    *   **Çalışma Mantığı:** Bu servisler varsayılan olarak *"Yapılandırılmadı"* görünür ve test butonları gizlidir. Aktif olabilmeleri için işletim sistemindeki kullanıcı ana dizininizde bulunan `config.toml` dosyasında yapılandırılmaları gerekir.
4.  **Oturum İstatistikleri (Session Stats):**
    *   **Çalışma Mantığı:** **Doğrudan çalışır.** Canlı yakalama başlattığınızda veya bir dosya analiz ettiğinizde toplam paket, alarm ve aktif tetikleyici sayıları çekirdekten gelen gerçek verilerle güncellenir.
5.  **Yükseltme ve Nöbet (Escalation & On-Call):**
    *   **Çalışma Mantığı:** `config.toml` içerisinde `[escalation]` bloğu aktif edildiğinde nöbetçi analistler, haftalık rotasyon ve bekleyen alarmlar otomatik listelenir.

---

## 2. Kanalları Aktif Etmek: `config.toml` Nasıl Yapılandırılır?

Netscope, konfigürasyonu Windows üzerinde `C:\Users\<Kullanıcı_Adı>\.netscope\config.toml` (kısaca `~/.netscope/config.toml`) dosyasından okur (Bkz: `[config.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/config.rs)`).

Aşağıdaki şablonu kopyalayıp kendi `~/.netscope/config.toml` dosyanıza yapıştırarak kanalları aktif edebilirsiniz:

```toml
[general]
profile = "HTTP Analysis"

[notifications]
# Windows Event Log (Varsayılan olarak açıktır)
# Syslog Yapılandırması
syslog_host = "127.0.0.1"
syslog_port = 514

# Slack Webhook Entegrasyonu
slack_webhook_url = "https://hooks.slack.com/services/T00/B00/X00"

# Telegram Bot Entegrasyonu
telegram_token = "123456:ABC-DEF1234ghIkl-zyx"
telegram_chat_id = "987654321"

# Email (SMTP) Yapılandırması
email_smtp_host = "smtp.gmail.com"
email_smtp_port = 587
email_from = "netscope-alerts@domain.com"
email_to = "soc-team@domain.com"
email_username = "smtp_user"
email_password = "smtp_password"
email_tls = "starttls" # "starttls", "implicit" veya "none"

[escalation]
enabled = true
primary_user = "Ahmet Yilmaz"
primary_email = "ahmet@netscope.io"
backup_user = "Mehmet Demir"
backup_email = "mehmet@netscope.io"
```

> [!NOTE]
> Bu dosyayı kaydedip uygulamayı yeniden başlattığınızda (veya SOC ekranındayken Araçlar -> Yeniden Yükle yaptığınızda) tüm kanalların yanında yeşil renkli **"Yapılandırıldı"** uyarısı çıkacak ve her biri için **"Test"** butonları aktif olacaktır.

---

## 3. Hata Ayıklama (Debugging & Tracing) Nasıl Yapılır?

Test butonlarına bastığınızda arka planda ne olduğunu görmek ve olası hataları yakalamak için şu yolları izleyin:

### 3.1. Windows Event Log Testinin Doğrulanması (Windows Olay Görüntüleyicisi)
Windows Event Log için **Test** butonuna bastıktan sonra logun gerçekten yazıldığını doğrulamak için:
1.  Klavyeden `Win + R` tuşlarına basın, `eventvwr.msc` yazıp Enter'a basarak **Olay Görüntüleyicisi**'ni açın.
2.  Sol menüden **Windows Günlükleri -> Uygulama** (Windows Logs -> Application) yolunu seçin.
3.  Sağ menüden **Bul** (Find) seçeneğine tıklayın ve "netscope" kelimesini aratın.
4.  **Doğrulama:** Bilgi (Information) seviyesinde *"netscope test notification — the SOC view sent this to check the channel."* açıklamasını taşıyan olay kaydını görmelisiniz.

### 3.2. Arayüz Konsolunu Açmak (WebView2 Developer Tools)
Tauri uygulamasının arayüz (JavaScript/CSS) loglarını incelemek için:
1.  Uygulama penceresi açıkken ekranın boş bir yerine **sağ tıklayın**.
2.  **"İncele" (Inspect)** seçeneğine tıklayarak Geliştirici Araçları'nı açın (veya `Ctrl + Shift + I` kısayolunu kullanın).
3.  **Console** sekmesine geçin. Herhangi bir kanala test gönderdiğinizde oluşan hata kodları, giden API çağrıları ve Tauri IPC (Invoke) detayları burada anlık olarak listelenecektir.

### 3.3. Arka Uç Rust Logları (Terminal Çıktısı)
Eğer uygulamayı `cargo tauri dev` ile başlattıysanız:
*   Ajan-sunucu bağlantı kopmaları, gRPC hataları veya TCP/UDP soket oluşturma sorunları (örneğin Syslog sunucusuna erişilemediğinde oluşan zaman aşımı) doğrudan **komutu çalıştırdığınız terminal penceresine** kırmızı/sarı log satırları olarak yazdırılır.
*   Bir hata durumunda terminal çıktısını kontrol ederek hatanın Rust tarafındaki kök nedenini (örn. `AddrInUse`, `TimedOut`, `ConnectionRefused`) saniyeler içinde görebilirsiniz.
