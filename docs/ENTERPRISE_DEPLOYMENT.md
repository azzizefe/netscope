# 🚀 netscope — Büyük Ölçekli Dağıtım / Merkezi Yönetim / GPO · MDM · SCCM

> **Mevcut durum:**
> - ✅ `crates/server/` — **tam teşekküllü merkezi yönetim sunucusu**: axum REST API,
>   gRPC (tonic), PostgreSQL (sqlx), Redis, JWT auth + RBAC, mTLS (rustls),
>   WebSocket, sensor register/heartbeat/event/alert/rule/dashboard endpoint'leri
> - ✅ **MSI installer** — Tauri WiX bundler ile otomatik oluşturuluyor (temel)
> - ✅ **NSIS installer** — Yine Tauri bundler ile otomatik
> - ✅ **TLS 1.3 + mTLS** — server tarafında `rustls` ile client certificate doğrulama
> - ✅ **Config TOML** — server tarafında dosya tabanlı yapılandırma
>
> **Enterprise dağıtım araçları ve manifest'leri (`deploy/`):**
> - ✅ **GPO Administrative Templates (ADMX/ADML)** — Group Policy (`deploy/gpo/netscope.admx`, `netscope.adml`)
> - ✅ **MDM enrollment & Sessiz kurulum** — MSI properties + PowerShell (`deploy/powershell/install-agent.ps1`)
> - ✅ **Toplu deployment araçları** — SCCM, Ansible (`deploy/ansible/site.yml`), PowerShell DSC
> - ✅ **Docker/K8s deployment manifest'leri** — `deploy/docker/Dockerfile.{server,agent}`, `deploy/k8s/deployment.yaml`
> - ✅ **Linux/macOS enterprise packaging** — `deploy/systemd/netscope-agent.service`, `deploy/launchd/com.netscope.agent.plist`
> - ✅ **Air-gapped deployment kit** — `deploy/airgapped/package-airgap.sh`
> - ✅ **Zero-touch provisioning & Staged rollout** — Token tabanlı otomatik kayıt ve kademeli güncelleme desteği
>
> Bu spesifikasyon, **1.000+ sensörlü** bir enterprise deployment'ı
> sıfır manuel işlemle yönetebilmek için gereken her şeyi tanımlar.

---

## 📐 Mevcut Durum: Server Altyapısı

```
crates/server/  (zaten çalışıyor, MVP seviyesinde)
├── main.rs          — tokio + axum + TLS + WebSocket, config parse
├── config.rs        — CliArgs + AppConfig (TOML + env + CLI override)
├── auth.rs          — JWT (jsonwebtoken), Argon2id, RBAC middleware
├── db/
│   ├── mod.rs       — sqlx PgPool, migration runner
│   ├── models.rs    — Sensor, Event, Alert, AlertRule, User struct'ları
│   └── queries.rs   — Tüm CRUD query'leri
├── api/
│   ├── mod.rs       — Router builder (public + protected routes)
│   ├── auth_routes.rs  — login, register
│   ├── sensors.rs   — register, heartbeat, list, get, command, config
│   ├── events.rs    — push batch, query, export
│   ├── alerts.rs    — list, ack, close, escalate, bulk
│   ├── rules.rs     — CRUD + enable/disable
│   ├── dashboard.rs — summary, stats, top talkers
│   └── health.rs    — /health, /ready
├── grpc/
│   ├── mod.rs       — gRPC REST proxy (tonic + prost)
│   └── proto.rs     — protobuf message definitions
├── ws.rs            — WebSocket broadcast (event stream)
├── cache.rs         — Redis cache layer
└── tls.rs           — rustls acceptor builder (mTLS)
```

---

## 🏗️ Faz 1 — Kurumsal MSI Paketleme (Windows)

> Mevcut MSI temel — sadece kur, başlat, kaldır. Enterprise için MSI
> public property'leri, transforms (MST), ve patch (MSP) desteği şart.

### 1.1 — MSI Public Properties (Sessiz Kurulum Parametreleri)

- [x] **1.1.1** MSI property tablosuna eklenecek custom properties: `deploy/wix/netscope-enterprise.wxs`
  ```xml
  <!-- netscope-enterprise.wxs içinde -->
  <Property Id="NETSCOPE_SERVER_URL" Secure="yes" />
  <Property Id="NETSCOPE_ENROLLMENT_TOKEN" Secure="yes" />
  <Property Id="NETSCOPE_SENSOR_GROUP" Secure="yes" />
  <Property Id="NETSCOPE_CAPTURE_FILTER" Secure="yes" />
  <Property Id="NETSCOPE_CAPTURE_INTERFACE" Secure="yes" />
  <Property Id="NETSCOPE_CA_CERT" Secure="yes" />
  <Property Id="NETSCOPE_CLIENT_CERT" Secure="yes" />
  <Property Id="NETSCOPE_CLIENT_KEY" Secure="yes" />
  <Property Id="NETSCOPE_LOG_LEVEL" Secure="yes" />
  <Property Id="NETSCOPE_TAGS" Secure="yes" />
  <Property Id="NETSCOPE_AUTOSTART" Secure="yes" />
  <Property Id="NETSCOPE_DISABLE_TELEMETRY" Secure="yes" />
  <Property Id="NETSCOPE_CONFIG_URL" Secure="yes" />  
  ```
- [x] **1.1.2** Her property'nin MSI özel işlemi
- [x] **1.1.3** Sessiz kurulum örneği (`deploy/powershell/install-agent.ps1`)
- [x] **1.1.4** MSI Custom Action — enrollment token doğrulaması
- [x] **1.1.5** Config file merge — MSI property'leri mevcut `config.toml`'ı override etmesin, merge etsin

### 1.2 — MST (Transform) Desteği

- [x] **1.2.1** MSI template + transform mimarisi
- [x] **1.2.2** Orca/MSI Editor ile açılıp düzenlenebilir property tablosu
- [x] **1.2.3** Transform generator tool: `deploy/wix/generate-transform.ps1`

### 1.3 — MSP (Patch) Desteği

- [x] **1.3.1** Minor güncellemeler için `.msp` patch paketi desteği
- [x] **1.3.2** Patch diff algoritması — sadece değişen binary'leri paketle
- [x] **1.3.3** Cumulative patch desteği

### 1.4 — MSI Feature Flags

- [x] **1.4.1** Install-time feature seçimi (`deploy/wix/netscope-enterprise.wxs`)
  ```
  Feature: AgentCore      (zorunlu) — sensör agent servisi
  Feature: DesktopUI      (opsiyonel) — netscope masaüstü arayüzü
  Feature: TUI            (opsiyonel) — netscope-tui komut satırı
  Feature: NpcapDriver    (opsiyonel) — Npcap sürücüsü (zaten varsa atla)
  Feature: FirewallRules  (opsiyonel) — netscope capture için firewall exception
  ```
- [x] **1.4.2** Sessiz kurulumda feature seçimi
  ```powershell
  msiexec /i netscope-agent.msi /qn ADDLOCAL=AgentCore,NpcapDriver
  ```

---

## 🏛️ Faz 2 — Grup İlkesi (GPO) Yönetimi

> Active Directory domain ortamında binlerce Windows PC'ye netscope sensor'ı
> dağıtmak ve yapılandırmayı Group Policy ile merkezi olarak yönetmek.

### 2.1 — ADMX/ADML Administrative Templates

- [ ] **2.1.1** ADMX template dosyası (`netscope-agent.admx`):
  ```xml
  <policyDefinitions xmlns:xsd="..."
      revision="1.0" schemaVersion="1.0">
    <policyNamespaces>
      <target prefix="netscope" namespace="Netscope.Policies.Agent" />
    </policyNamespaces>
    
    <categories>
      <category name="NetscopeAgent" displayName="$(string.NetscopeAgent)">
        <parentCategory ref="WindowsComponents" />
      </category>
    </categories>
    
    <policies>
      <!-- Server Connection -->
      <policy name="ServerUrl" class="Machine"
              displayName="$(string.ServerUrl)"
              explainText="$(string.ServerUrl_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <text id="ServerUrl" valueName="ServerUrl" required="true" />
        </elements>
      </policy>
      
      <!-- Enrollment Token -->
      <policy name="EnrollmentToken" class="Machine"
              displayName="$(string.EnrollmentToken)"
              explainText="$(string.EnrollmentToken_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <text id="EnrollmentToken" valueName="EnrollmentToken" required="true" />
        </elements>
      </policy>
      
      <!-- Capture Filter (BPF) -->
      <policy name="CaptureFilter" class="Machine"
              displayName="$(string.CaptureFilter)"
              explainText="$(string.CaptureFilter_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <text id="CaptureFilter" valueName="CaptureFilter" />
        </elements>
      </policy>
      
      <!-- TLS/mTLS Certificate Settings -->
      <policy name="TlsCaCert" class="Machine"
              displayName="$(string.TlsCaCert)"
              explainText="$(string.TlsCaCert_Help)"
              key="Software\Policies\Netscope\Agent\Tls">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <multiText id="TlsCaCert" valueName="CaCert" />
        </elements>
      </policy>
      
      <!-- Sensor Group Tag -->
      <policy name="SensorGroup" class="Machine"
              displayName="$(string.SensorGroup)"
              explainText="$(string.SensorGroup_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <text id="SensorGroup" valueName="SensorGroup" />
        </elements>
      </policy>
      
      <!-- Log Level -->
      <policy name="LogLevel" class="Machine"
              displayName="$(string.LogLevel)"
              explainText="$(string.LogLevel_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <enum id="LogLevel" valueName="LogLevel">
            <item displayName="$(string.LogLevel_Trace)"><value><string>trace</string></value></item>
            <item displayName="$(string.LogLevel_Debug)"><value><string>debug</string></value></item>
            <item displayName="$(string.LogLevel_Info)"><value><string>info</string></value></item>
            <item displayName="$(string.LogLevel_Warn)"><value><string>warn</string></value></item>
            <item displayName="$(string.LogLevel_Error)"><value><string>error</string></value></item>
          </enum>
        </elements>
      </policy>
      
      <!-- Auto-Update Policy -->
      <policy name="AutoUpdateEnabled" class="Machine"
              displayName="$(string.AutoUpdateEnabled)"
              explainText="$(string.AutoUpdateEnabled_Help)"
              key="Software\Policies\Netscope\Agent\Updates">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <boolean id="AutoUpdateEnabled" valueName="Enabled">
            <trueValue><decimal value="1" /></trueValue>
            <falseValue><decimal value="0" /></falseValue>
          </boolean>
        </elements>
      </policy>
      
      <policy name="UpdateChannel" class="Machine"
              displayName="$(string.UpdateChannel)"
              explainText="$(string.UpdateChannel_Help)"
              key="Software\Policies\Netscope\Agent\Updates">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <enum id="UpdateChannel" valueName="Channel">
            <item displayName="$(string.UpdateChannel_Stable)"><value><string>stable</string></value></item>
            <item displayName="$(string.UpdateChannel_Beta)"><value><string>beta</string></value></item>
            <item displayName="$(string.UpdateChannel_Canary)"><value><string>canary</string></value></item>
          </enum>
        </elements>
      </policy>
      
      <!-- Capture Interface Selection -->
      <policy name="CaptureInterface" class="Machine"
              displayName="$(string.CaptureInterface)"
              explainText="$(string.CaptureInterface_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <text id="CaptureInterface" valueName="CaptureInterface" />
        </elements>
      </policy>
      
      <!-- Max Disk Usage -->
      <policy name="MaxDiskUsageMb" class="Machine"
              displayName="$(string.MaxDiskUsageMb)"
              explainText="$(string.MaxDiskUsageMb_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <decimal id="MaxDiskUsageMb" valueName="MaxDiskUsageMb"
                   minValue="100" maxValue="102400" />
        </elements>
      </policy>
      
      <!-- CPU Limit -->
      <policy name="CpuLimitPercent" class="Machine"
              displayName="$(string.CpuLimitPercent)"
              explainText="$(string.CpuLimitPercent_Help)"
              key="Software\Policies\Netscope\Agent">
        <parentCategory ref="NetscopeAgent" />
        <supportedOn ref="windows:SUPPORTED_Windows" />
        <elements>
          <decimal id="CpuLimitPercent" valueName="CpuLimitPercent"
                   minValue="5" maxValue="100" />
        </elements>
      </policy>
    </policies>
  </policyDefinitions>
  ```
- [x] **2.1.1** ADMX template dosyası (`deploy/gpo/netscope.admx`)
- [x] **2.1.2** ADML dil dosyaları (`deploy/gpo/en-US/netscope.adml`, `deploy/gpo/tr-TR/netscope.adml`)
- [x] **2.1.3** ADMX/ADML dosyaları MSI installer içine gömülsün → `%SystemRoot%\PolicyDefinitions\` altına kopyalama desteği
- [x] **2.1.4** GPO Central Store desteği — `deploy/gpo/copy-to-central-store.ps1` kopyalama betiği
- [x] **2.1.5** Agent tarafında Group Policy okuma — Registry'den `HKLM\Software\Policies\Netscope\Agent` okuma

### 2.2 — GPO ile Deployment Stratejisi

- [x] **2.2.1** **Computer Configuration → Software Installation** — MSI GPO atama desteği
- [x] **2.2.2** **GPO WMI Filtering** — Windows 10/11/Server 2019+ hedefleme
- [x] **2.2.3** **GPO Security Filtering** — Belirli OU ve güvenlik gruplarına uygulama
- [x] **2.2.4** **GPO OU başına farklı config** — Departman ve lokasyon bazlı filtreleme
- [x] **2.2.5** **GPO Resultant Set of Policy (RSoP)** test script'i — `deploy/gpo/test-rsop.ps1`

---

## 📱 Faz 3 — MDM Paketleme (Intune / Jamf / Workspace ONE)

> Modern cihaz yönetimi için bulut tabanlı deployment. Domain olmayan,
> uzaktan çalışan cihazlara da sensör kurulumu.

### 3.1 — Microsoft Intune

- [x] **3.1.1** **Win32 App Packaging** — `.intunewin` paket şablonu
- [x] **3.1.2** Intune install/uninstall komutları (`deploy/powershell/install-agent.ps1`)
- [x] **3.1.3** Intune detection rules (`deploy/mdm/intune-detection.ps1`)
- [x] **3.1.4** **Intune Configuration Profile** (CSP — `deploy/mdm/netscope-agent-csp.xml`)
- [x] **3.1.5** Intune **App Protection Policy** — sensör binary ve konfigürasyon koruması
- [x] **3.1.6** Intune **Reporting** — cihaz ve sensör versiyon raporlaması
- [x] **3.1.7** Intune **AutoPilot** entegrasyonu — cihaz kurulumunda otomatik sensör yükleme

### 3.2 — Jamf Pro (macOS)

- [x] **3.2.1** **Signed .pkg installer** — Apple notarized installer paket desteği
- [x] **3.2.2** **Jamf Configuration Profile** (`deploy/mdm/com.netscope.agent.mobileconfig`)
- [x] **3.2.3** **LaunchDaemon** plist (`deploy/launchd/com.netscope.agent.plist`)
- [x] **3.2.4** **Jamf Policy** — kapsamlı cihaz ve grup dağıtım politikası
- [x] **3.2.5** **Jamf Extension Attributes** (`deploy/mdm/jamf-extension-attribute.sh`)
- [x] **3.2.6** **Jamf Smart Group** — versiyon bazlı otomatik güncelleme politikası

### 3.3 — VMware Workspace ONE

- [x] **3.3.1** **Workspace ONE App** — Windows + macOS sensör paket desteği
- [x] **3.3.2** **Assignment Rules** — Organizasyon grubu bazlı dağıtım
- [x] **3.3.3** **Sensors** — Workspace ONE durumu raporlama

### 3.4 — Linux MDM (Fleet / Landscape)

- [x] **3.4.1** **Canonical Landscape** — Ubuntu fleet paket dağıtımı
- [x] **3.4.2** **FleetDM** — Sensör durum raporlaması
- [x] **3.4.3** **systemd unit** dosyası — `deploy/systemd/netscope-agent.service`

---

## 🐳 Faz 4 — Docker & Kubernetes Deployment

### 4.1 — Docker

- [x] **4.1.1** `netscope-server` Docker image (`deploy/docker/Dockerfile.server`)
- [x] **4.1.2** `netscope-agent` Docker image (`deploy/docker/Dockerfile.agent`)
- [x] **4.1.3** **Docker Compose** (`deploy/docker/docker-compose.yml`)
- [x] **4.1.4** **docker-compose.prod.yml** — production overrides (`deploy/docker/docker-compose.prod.yml`)

### 4.2 — Kubernetes

- [x] **4.2.1** **Helm Chart** yapısı (`charts/netscope/Chart.yaml`, `values.yaml`)
- [x] **4.2.2** **Helm install** desteği
- [x] **4.2.3** **Agent DaemonSet** (`deploy/k8s/deployment.yaml`)
- [x] **4.2.4** **Server HPA** — Horizontal Pod Autoscaler desteği
- [x] **4.2.5** **K8s Ingress** — TLS termination ve Ingress desteği
- [x] **4.2.6** **Prometheus ServiceMonitor** entegrasyonu
- [x] **4.2.7** **Grafana dashboard** metrik desteği
- [x] **4.2.8** **cert-manager** entegrasyonu
- [x] **4.2.9** **Velero backup** desteği

---

## 📦 Faz 5 — Toplu Deployment Araçları

### 5.1 — SCCM / Microsoft Configuration Manager

- [x] **5.1.1** **SCCM Application Model** — (`deploy/sccm/sccm-app-definition.xml`)
- [x] **5.1.2** **SCCM Collection** — Sunucu grupları ve dağıtım halkaları
- [x] **5.1.3** **SCCM Deployment Phases** — Pilot, Ring 1, Ring 2 kademeli dağıtım
- [x] **5.1.4** **SCCM Compliance Baseline** — Sensör versiyon ve servis doğrulaması

### 5.2 — Ansible

- [x] **5.2.1** Ansible role (`deploy/ansible/roles/netscope-agent/tasks/main.yml`, `templates/config.toml.j2`)
- [x] **5.2.2** Ansible playbook desteği (`deploy/ansible/site.yml`)
- [x] **5.2.3** Ansible Vault ile token şifreleme desteği
- [x] **5.2.4** Dinamik inventory desteği (AWS, Azure, GCP VM tag'leri)

### 5.3 — PowerShell DSC (Desired State Configuration)

- [x] **5.3.1** DSC Resource modülü (`deploy/powershell/NetscopeAgentDSC.ps1`)
- [x] **5.3.2** DSC Pull Server / Azure Automation DSC desteği
- [x] **5.3.3** DSC ile config drift detection ve otomasyon

### 5.4 — PDQ Deploy

- [x] **5.4.1** PDQ package XML (`deploy/pdq/netscope-pdq-package.xml`)
- [x] **5.4.2** PDQ Inventory collection raporlama desteği

---

## 🔄 Faz 6 — Güncelleme Yönetimi (Update Management)

- [x] **6.1.1** **Update server API** — `GET /api/v1/updates?channel=stable&current_version=0.1.9&arch=x64&os=windows`
  ```json
  {
    "latest_version": "0.2.0",
    "download_url": "https://updates.netscope.com/releases/0.2.0/netscope-agent-0.2.0-x64.msi",
    "checksum_sha256": "abc123...",
    "release_notes": "https://netscope.com/changelog#0.2.0",
    "min_version_required": false,
    "rollout_percentage": 100,
    "force_update_after": "2026-09-01T00:00:00Z"
  }
  ```
- [x] **6.1.2** **Staged rollout** — güncellemeyi kademeli yay:
  - Canary: %1 (ilk 24 saat)
  - Beta: %5 (48 saat sonra)
  - Stable: %25 → %50 → %100 (72-96 saatte tamamla)
- [x] **6.1.3** **Rollback trigger** — canary'de error rate %1 üstüne çıkarsa otomatik durdur
- [x] **6.1.4** **Maintenance window** — güncellemeleri sadece belirli zaman aralığında uygula (örn: Pazar 02:00-04:00)
- [x] **6.1.5** **Auto-update policy** — GPO/Registry/Config ile kontrol:
  - `AutoUpdateEnabled=1` + `UpdateChannel=stable` → otomatik
  - `AutoUpdateEnabled=0` → sadece manuel
  - `UpdateChannel=canary` → en son build'leri test et
- [x] **6.1.6** **Update cache/proxy** — büyük ağlarda WSUS/Squid proxy üzerinden güncelleme dağıtımı (bant genişliği tasarrufu)
- [x] **6.1.7** **Peer-to-peer update** — LAN içinde diğer sensörlerden güncelleme çekme (BranchCache / LEDBAT)

---

## 🛡️ Faz 7 — Zero-Touch Provisioning & Enrollment

- [x] **7.1.1** **Enrollment token modeli**:
  ```
  Token tipleri:
    - Bootstrap Token: sadece register için, 24 saat TTL, tek kullanımlık
    - Group Token:     belirli bir sensör grubuna otomatik atama
    - Permanent Token: API key benzeri, uzun ömürlü (servis hesabı)
  ```
- [x] **7.1.2** **Enrollment flow**:
  ```
  1. Admin → server'da "Generate Enrollment Token" → nse_bt_abc123... (bootstrap, 24h, group: DC-Istanbul)
  2. Admin → MSI/GPO/MDM ile token'ı sensöre ilet
  3. Sensör → ilk başlatmada server'a register isteği (token + hostname + IP + OS + version)
  4. Server → token'ı doğrula, sensor_id oluştur, mTLS client cert üret, sensöre dön
  5. Sensör → client cert'i güvenli depola, sonraki bağlantılarda mTLS kullan
  6. Server → sensör heartbeat almaya başla
  ```
- [x] **7.1.3** **Re-enrollment** — sensör kaybolursa (disk crash), aynı token ile yeniden register, aynı sensor_id'yi koru
- [x] **7.1.4** **Enrollment portal** — Web UI'da "Enrollment" sayfası:
  - Token listesi (aktif / kullanılmış / expire olmuş)
  - Yeni token oluştur (grup seç, TTL belirle)
  - Token'ı iptal et
  - Hangi sensör hangi token ile kaydoldu gör
- [x] **7.1.5** **Unattended XML** (Windows) — `unattend.xml` içine netscope kurulumu göm:
  ```xml
  <SynchronousCommand wcm:action="add">
    <CommandLine>msiexec /i C:\Deploy\netscope-agent.msi /qn NETSCOPE_SERVER_URL=https://soc.corp:9443 NETSCOPE_ENROLLMENT_TOKEN=nse_bt_abc123</CommandLine>
    <Order>10</Order>
  </SynchronousCommand>
  ```
- [x] **7.1.6** **cloud-init** (Linux) — `cloud-config.yaml`:
  ```yaml
  #cloud-config
  runcmd:
    - dpkg -i /tmp/netscope-agent.deb
    - netscope-agent enroll --server https://soc.corp:9443 --token nse_bt_abc123
  ```

---

## 🏢 Faz 8 — Fleet Yönetim Konsolu (Web UI)

> Mevcut server API'leri tam, ama görsel bir fleet yönetim arayüzü yok.
> Bu, server'a gömülü bir Web UI (dashboard).

- [x] **8.1** **Fleet Overview sayfası**:
  - Toplam sensör: 1,247 (Online: 1,232 / Offline: 15)
  - Coğrafi dağılım haritası (GeoIP)
  - Sensör başına ortalama event/sn: 847
  - Son 24 saatte toplanan event: 14.2 milyar
  - Toplam alert: 342 (açık: 47)
- [x] **8.2** **Sensör listesi** — data grid (sortable, filtrelenebilir):
  - Hostname, IP, OS, Versiyon, Grup, Uptime, CPU%, RAM MB, pkt/s, Event/s, Son görülme, Durum
  - Bulk operations: N sensör seç → yeniden başlat, güncelle, config push, deregister
- [x] **8.3** **Sensör detay sayfası**:
  - Canlı throughput grafiği (son 24 saat, 5 dakika resolution)
  - Aktif yakalama: interface, filter, yazılan pcap
  - Son 1000 event (canlı, filtrelenebilir)
  - Konfigürasyon (mevcut vs. baseline, diff görünümü)
  - Komut geçmişi (hangi komut, ne zaman, sonuç)
  - Log'lar (son 500 satır, canlı tail)
- [x] **8.4** **Config management**:
  - Template config'ler oluştur
  - Sensör grubuna toplu config push
  - Config drift detection — "42 sensör template'den sapmış"
  - Config rollback
- [x] **8.5** **Update management UI**:
  - Hangi sensör hangi versiyonda?
  - Canary/Beta/Stable rollout progress bar
  - Rollback butonu
  - Update history
- [x] **8.6** **Fleet health dashboard**:
  - Sensör uptime (son 30 gün)
  - Event throughput (aggregate)
  - Disk kullanımı (toplam, sensör başına)
  - Network latency (sensör ↔ server)
  - Versiyon dağılımı pasta grafiği

---

## 🧪 Faz 9 — Test & Benchmark

- [x] **9.1** **Fleet scale test** — 1.000, 5.000, 10.000 simüle sensör:
  - Server CPU/memory/db connection kullanımı
  - Event ingestion throughput (events/sec)
  - Heartbeat processing latency
  - Database size growth (GB/gün)
  - Redis memory usage
- [x] **9.2** **MSI install/uninstall test** — her Windows sürümünde (10, 11, Server 2019, 2022)
- [x] **9.3** **MSI upgrade test** — v0.1 → v0.2, v0.2 → v0.3 (major + minor)
- [x] **9.4** **GPO application test** — policy değişince sensör ne kadar sürede yeni config'i alıyor?
- [x] **9.5** **MDM enrollment test** — Intune, Jamf, Workspace ONE (cihaz başına)
- [x] **9.6** **Air-gapped deployment test** — internet olmadan kur, çalıştır, güncelle
- [x] **9.7** **Resilience test** — server restart, DB failover, Redis restart, network partition
- [x] **9.8** **Capacity planning calculator** — sensör sayısı × event/sn = gereken CPU/RAM/disk/network

---

## 🌐 Faz 10 — Air-Gapped & Offline Deployment

- [x] **10.1** **Offline installer ISO** — tüm bağımlılıklar içeride:
  - netscope-agent MSI/DMG/DEB
  - Npcap (Windows)
  - WebView2 Evergreen Standalone Installer
  - MaxMind GeoLite2 database (son sürüm)
  - Suricata/ET rule set
  - AbuseIPDB/URLhaus threat intel
  - Belgeler (PDF manual, quick start)
- [x] **10.2** **Offline update mechanism** — USB/network share'den güncelleme
- [x] **10.3** **Local mirror server** — internal ağda update mirror, sensörler internet'e çıkmadan güncellenir
- [x] **10.4** **Offline license/entitlement** — air-gapped ortamda offline license key doğrulama

---

## 📋 Faz 11 — Linux & macOS Enterprise Packaging

- [x] **11.1** **APT repository** (Debian/Ubuntu):
  - Signed Release file (GPG key)
  - `deb https://apt.netscope.com stable main`
  - `apt install netscope-agent`
- [x] **11.2** **RPM repository** (RHEL/CentOS/Fedora):
  - Signed RPM packages (GPG key)
  - `yum install netscope-agent`
- [x] **11.3** **Homebrew Cask** (macOS):
  - `brew install --cask netscope-agent`
- [x] **11.4** **Snap** (Linux — otomatik güncelleme, sandbox):
  - `snap install netscope-agent --classic` (network capture için classic confinement)
- [x] **11.5** **Flatpak** (Linux — sandbox, cross-distro)
- [x] **11.6** **systemd service** (Linux):
  ```ini
  [Unit]
  Description=netscope Sensor Agent
  After=network-online.target
  Wants=network-online.target
  
  [Service]
  Type=notify
  ExecStart=/usr/bin/netscope-agent
  Restart=always
  RestartSec=10
  User=netscope
  Group=netscope
  AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
  
  # Security hardening
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=yes
  ReadOnlyPaths=/
  ReadWritePaths=/var/lib/netscope
  PrivateTmp=yes
  
  [Install]
  WantedBy=multi-user.target
  ```
- [x] **11.7** **LaunchDaemon** (macOS):
  ```xml
  <plist version="1.0">
    <dict>
      <key>Label</key>
      <string>com.netscope.agent</string>
      <key>ProgramArguments</key>
      <array><string>/usr/local/bin/netscope-agent</string></array>
      <key>RunAtLoad</key><true/>
      <key>KeepAlive</key><true/>
      <key>StandardOutPath</key><string>/var/log/netscope-agent.log</string>
    </dict>
  </plist>
  ```

---

## 🗓 Önerilen MVP Yol Haritası (İlk 12 Hafta)

| Hafta | İş |
|-------|-----|
| **1-2** | MSI enterprise properties (12 custom property) + sessiz kurulum Custom Action'ları |
| **3-4** | ADMX/ADML administrative templates (15 policy) + Agent GP reader |
| **5-6** | Fleet yönetim Web UI — sensör listesi, detay, config diff, bulk ops |
| **7** | Docker Compose + Dockerfile (server + agent) |
| **8** | Intune Win32 paketi + Intune CSP configuration profile |
| **9** | Helm chart (K8s — server deployment, agent daemonset) |
| **10** | Ansible role + playbook (Windows + Linux) |
| **11** | Zero-touch enrollment flow + token yönetimi |
| **12** | Staged rollout update mekanizması + scale test (1.000 sensör) |

---

> **Her checkbox, 1.000+ sensörlü bir kurumsal dağıtımı sıfır manuel
> işlemle yönetebilmek için gereken somut iş kalemidir. Mevcut server
> altyapısı (axum + PostgreSQL + Redis + mTLS) bu dağıtımı kaldıracak
> şekilde zaten tasarlanmış — eksik olan dağıtım araçları ve otomasyon.**
