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
> **Ancak enterprise dağıtım için gereken asıl araçlar eksik:**
> - ❌ GPO Administrative Templates (ADMX/ADML) — Group Policy ile sensör yapılandırma
> - ❌ MDM enrollment paketi — Intune, Jamf, Workspace ONE
> - ❌ Sessiz kurulum parametreleri — MSI public properties (`SERVER_URL`, `ENROLLMENT_TOKEN` vs)
> - ❌ Fleet yönetim konsolu Web UI — yüzlerce sensörü görsel yönetme
> - ❌ Toplu deployment araçları — SCCM, Ansible, PowerShell DSC, PDQ Deploy
> - ❌ Zero-touch provisioning — sensörün sıfır manuel müdahale ile kurulumu
> - ❌ Docker/K8s deployment manifest'leri — server + agent container
> - ❌ Linux/macOS enterprise packaging — systemd, launchd, DEB/RPM repo
> - ❌ Air-gapped deployment kit — internet olmayan ortamda kurulum
> - ❌ Staged rollout / canary deployment — aşamalı güncelleme
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

- [ ] **1.1.1** MSI property tablosuna eklenecek custom properties:
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
- [ ] **1.1.2** Her property'nin MSI özel işlemi:
  - `NETSCOPE_SERVER_URL` → `C:\ProgramData\netscope\agent\config.toml` içine `server_url` yaz
  - `NETSCOPE_ENROLLMENT_TOKEN` → `config.toml` içine `enrollment_token` yaz (encrypted)
  - `NETSCOPE_CA_CERT` → dosya yolundan oku, `C:\ProgramData\netscope\agent\certs\ca.pem`'e kopyala
  - `NETSCOPE_AUTOSTART` → Windows Service'i `Automatic` olarak başlat
- [ ] **1.1.3** Sessiz kurulum örneği:
  ```powershell
  msiexec /i netscope-agent-0.2.0-x64.msi /qn /norestart `
    NETSCOPE_SERVER_URL="https://soc-server.internal.corp:9443" `
    NETSCOPE_ENROLLMENT_TOKEN="nse_token_abc123..." `
    NETSCOPE_SENSOR_GROUP="DC-Istanbul-Floor3" `
    NETSCOPE_CAPTURE_FILTER="not host 10.0.0.1" `
    NETSCOPE_AUTOSTART="1" `
    NETSCOPE_LOG_LEVEL="info" `
    /L*V "C:\Logs\netscope-install.log"
  ```
- [ ] **1.1.4** MSI Custom Action — enrollment token doğrulaması (kurulum sırasında server'a ping at, token geçerli mi?)
- [ ] **1.1.5** Config file merge — MSI property'leri mevcut `config.toml`'ı override etmesin, merge etsin (sonra gelen kazansın)

### 1.2 — MST (Transform) Desteği

- [ ] **1.2.1** MSI template + transform mimarisi:
  - Base MSI: tüm özellikler (feature flags ile)
  - Transform (MST): kurumsal ayarları override eden `.mst` dosyası
  - Örnek: `netscope-finance-dept.mst` → Finance departmanı için özel filter'lar
- [ ] **1.2.2** Orca/MSI Editor ile açılıp düzenlenebilir property tablosu
- [ ] **1.2.3** Transform generator tool: `netscope-admin mst create --template finance`

### 1.3 — MSP (Patch) Desteği

- [ ] **1.3.1** Minor güncellemeler için `.msp` patch paketi (tam MSI indirmeden)
- [ ] **1.3.2** Patch diff algoritması — sadece değişen binary'leri paketle
- [ ] **1.3.3** Cumulative patch desteği (her patch öncekileri içerir)

### 1.4 — MSI Feature Flags

- [ ] **1.4.1** Install-time feature seçimi:
  ```
  Feature: AgentCore      (zorunlu) — sensör agent servisi
  Feature: DesktopUI      (opsiyonel) — netscope masaüstü arayüzü
  Feature: TUI            (opsiyonel) — netscope-tui komut satırı
  Feature: NpcapDriver    (opsiyonel) — Npcap sürücüsü (zaten varsa atla)
  Feature: FirewallRules  (opsiyonel) — netscope capture için firewall exception
  ```
- [ ] **1.4.2** Sessiz kurulumda feature seçimi:
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
- [ ] **2.1.2** ADML dil dosyası (`netscope-agent.adml`):
  - İngilizce (en-US) — default
  - Türkçe (tr-TR)
  - Almanca (de-DE)
  - Fransızca (fr-FR)
  - İspanyolca (es-ES)
  - Japonca (ja-JP)
- [ ] **2.1.3** ADMX/ADML dosyaları MSI installer içine gömülsün → `%SystemRoot%\PolicyDefinitions\` altına otomatik kopyalansın (opsiyonel feature)
- [ ] **2.1.4** GPO Central Store desteği — `\\domain.local\SYSVOL\domain.local\Policies\PolicyDefinitions\` altına kopyalama script'i
- [ ] **2.1.5** Agent tarafında Group Policy okuma — Windows Registry'den `HKLM\Software\Policies\Netscope\Agent` key'lerini oku, `config.toml` ile merge et (GP her zaman kazansın)

### 2.2 — GPO ile Deployment Stratejisi

- [ ] **2.2.1** **Computer Configuration → Software Installation** — MSI'ı GPO ile atama (assign):
  - Bilgisayar açılışında otomatik kurulum
  - Domain Controller'a yük bindirmeden staggered start (random delay 0-10 dk)
- [ ] **2.2.2** **GPO WMI Filtering** — sadece Windows 10 22H2+ / Windows 11 / Server 2019+ makinelere deploy et
- [ ] **2.2.3** **GPO Security Filtering** — sadece belirli OU'lardaki bilgisayarlara uygula (örn: `OU=Servers,DC=corp,DC=local`)
- [ ] **2.2.4** **GPO OU başına farklı config** — DC/İstanbul sensörleri DC/Ankara'dan farklı filter ile:
  ```
  OU=Istanbul-Servers → GPO "netscope-agent-istanbul" (filter: "net 10.0.1.0/24")
  OU=Ankara-Servers  → GPO "netscope-agent-ankara"  (filter: "net 10.0.2.0/24")
  OU=DMZ             → GPO "netscope-agent-dmz"     (filter: "net 192.168.100.0/24")
  ```
- [ ] **2.2.5** **GPO Resultant Set of Policy (RSoP)** test script'i — hedef makinede hangi netscope GP ayarları uygulanmış?

---

## 📱 Faz 3 — MDM Paketleme (Intune / Jamf / Workspace ONE)

> Modern cihaz yönetimi için bulut tabanlı deployment. Domain olmayan,
> uzaktan çalışan cihazlara da sensör kurulumu.

### 3.1 — Microsoft Intune

- [ ] **3.1.1** **Win32 App Packaging** — `.intunewin` formatında paket:
  ```powershell
  # IntuneWinAppUtil.exe ile paketleme
  .\IntuneWinAppUtil.exe -c C:\build\netscope-agent -s netscope-agent-installer.exe `
    -o C:\build\output -q
  ```
- [ ] **3.1.2** Intune install/uninstall komutları:
  ```
  Install:   netscope-agent-installer.exe /S /SERVER_URL=https://soc.corp.com:9443 /TOKEN={{enrollment_token}}
  Uninstall: "C:\Program Files\netscope\uninstall.exe" /S
  ```
- [ ] **3.1.3** Intune detection rules:
  - Registry: `HKLM\SOFTWARE\Netscope\Agent` → `Version` >= `0.2.0`
  - File: `C:\Program Files\netscope\netscope-agent.exe` exists + version check
- [ ] **3.1.4** **Intune Configuration Profile** (CSP — Configuration Service Provider):
  ```xml
  <!-- netscope-agent-csp.xml -->
  <SyncML>
    <SyncBody>
      <Replace>
        <CmdID>1</CmdID>
        <Item>
          <Target>
            <LocURI>./Device/Vendor/MSFT/Policy/Config/Netscope/ServerUrl</LocURI>
          </Target>
          <Data>https://soc-server.internal.corp:9443</Data>
        </Item>
      </Replace>
      <Replace>
        <CmdID>2</CmdID>
        <Item>
          <Target>
            <LocURI>./Device/Vendor/MSFT/Policy/Config/Netscope/EnrollmentToken</LocURI>
          </Target>
          <Data>nse_token_abc123...</Data>
        </Item>
      </Replace>
      <!-- ... tüm yapılandırma CSP'leri -->
    </SyncBody>
  </SyncML>
  ```
- [ ] **3.1.5** Intune **App Protection Policy** — sensör binary'sini ve config'i koruma
- [ ] **3.1.6** Intune **Reporting** — hangi cihazlarda yüklü, hangi versiyon, son heartbeat
- [ ] **3.1.7** Intune **AutoPilot** entegrasyonu — sıfır dokunuşla cihaz setup'ı sırasında otomatik netscope kurulumu

### 3.2 — Jamf Pro (macOS)

- [ ] **3.2.1** **Signed .pkg installer** — Apple notarized, MDM'e yüklenebilir
- [ ] **3.2.2** **Jamf Configuration Profile** (`.mobileconfig`):
  ```xml
  <plist version="1.0">
    <dict>
      <key>PayloadContent</key>
      <array>
        <dict>
          <key>PayloadType</key>
          <string>com.netscope.agent</string>
          <key>ServerUrl</key>
          <string>https://soc.internal.corp:9443</string>
          <key>EnrollmentToken</key>
          <string>nse_token_abc123...</string>
          <key>SensorGroup</key>
          <string>macOS-Fleet</string>
          <key>CaptureInterface</key>
          <string>en0</string>
        </dict>
      </array>
    </dict>
  </plist>
  ```
- [ ] **3.2.3** **LaunchDaemon** plist — `com.netscope.agent.plist` (KeepAlive, RunAtLoad)
- [ ] **3.2.4** **Jamf Policy** — scoped deployment (department/group/network segment)
- [ ] **3.2.5** **Jamf Extension Attributes** — sensor status, version, connected server
- [ ] **3.2.6** **Jamf Smart Group** — "sensors with version < 0.2.0" → auto-update policy

### 3.3 — VMware Workspace ONE

- [ ] **3.3.1** **Workspace ONE App** — Windows + macOS sensor paketi
- [ ] **3.3.2** **Assignment Rules** — Organization Group / Smart Group bazlı deployment
- [ ] **3.3.3** **Sensors** (Workspace ONE Sensors) — netscope agent status'ünü raporlama

### 3.4 — Linux MDM (Fleet / Landscape)

- [ ] **3.4.1** **Canonical Landscape** — Ubuntu fleet için package deployment
- [ ] **3.4.2** **FleetDM** — osquery benzeri, sensör durumunu Fleet'e raporla
- [ ] **3.4.3** **systemd unit** dosyası — `netscope-agent.service` (enable, start, restart, status)

---

## 🐳 Faz 4 — Docker & Kubernetes Deployment

### 4.1 — Docker

- [ ] **4.1.1** `netscope-server` Docker image:
  ```dockerfile
  FROM debian:bookworm-slim
  COPY target/release/netscope-server /usr/local/bin/
  COPY config/server.docker.toml /etc/netscope/server.toml
  EXPOSE 9443 9444
  ENTRYPOINT ["netscope-server", "-c", "/etc/netscope/server.toml"]
  ```
- [ ] **4.1.2** `netscope-agent` Docker image (container monitoring için):
  ```dockerfile
  # Host network modunda çalışır, container'ların trafiğini izler
  FROM debian:bookworm-slim
  RUN apt-get update && apt-get install -y libpcap0.8
  COPY target/release/netscope-agent /usr/local/bin/
  ENV NETSCOPE_SERVER_URL="https://netscope-server:9443"
  ENTRYPOINT ["netscope-agent"]
  ```
- [ ] **4.1.3** **Docker Compose** — tek komutla tüm stack:
  ```yaml
  # docker-compose.yml
  services:
    postgres:
      image: postgres:16-alpine
      volumes: [pgdata:/var/lib/postgresql/data]
      environment: {POSTGRES_DB: netscope, POSTGRES_USER: netscope, POSTGRES_PASSWORD: ...}
    
    redis:
      image: redis:7-alpine
    
    netscope-server:
      image: netscope-server:latest
      ports: ["9443:9443"]
      depends_on: [postgres, redis]
      environment:
        DATABASE_URL: "postgres://netscope:...@postgres:5432/netscope"
        REDIS_URL: "redis://redis:6379"
      volumes: [./certs:/etc/netscope/certs:ro]
    
    netscope-agent:
      image: netscope-agent:latest
      network_mode: host
      environment:
        NETSCOPE_SERVER_URL: "https://netscope-server:9443"
        NETSCOPE_ENROLLMENT_TOKEN: "..."
      cap_add: [NET_RAW, NET_ADMIN]
  ```
- [ ] **4.1.4** **docker-compose.prod.yml** — production overrides (resource limits, logging driver, restart policy)

### 4.2 — Kubernetes

- [ ] **4.2.1** **Helm Chart** yapısı:
  ```
  charts/netscope/
  ├── Chart.yaml
  ├── values.yaml
  ├── values-prod.yaml
  ├── templates/
  │   ├── server-deployment.yaml
  │   ├── server-service.yaml
  │   ├── server-ingress.yaml
  │   ├── server-hpa.yaml           # Horizontal Pod Autoscaler
  │   ├── server-pdb.yaml           # Pod Disruption Budget
  │   ├── agent-daemonset.yaml      # Her node'da bir agent pod
  │   ├── postgres-statefulset.yaml
  │   ├── redis-deployment.yaml
  │   ├── secrets.yaml
  │   ├── configmap.yaml
  │   ├── serviceaccount.yaml
  │   ├── servicemonitor.yaml       # Prometheus ServiceMonitor
  │   └── _helpers.tpl
  └── README.md
  ```
- [ ] **4.2.2** **Helm install** (tek komut):
  ```bash
  helm upgrade --install netscope ./charts/netscope \
    --namespace netscope --create-namespace \
    -f values-prod.yaml \
    --set server.config.jwt.secret="$(openssl rand -hex 32)" \
    --set agent.config.serverUrl="https://netscope.internal.corp:9443" \
    --set agent.config.enrollmentToken="nse_token_..."
  ```
- [ ] **4.2.3** **Agent DaemonSet** — `hostNetwork: true`, `hostPID: true`, her node'da tek pod, tüm container'ların trafiğini görür
- [ ] **4.2.4** **Server HPA** — CPU > %70 veya memory > %80 ise scale-out (max 10 replica)
- [ ] **4.2.5** **K8s Ingress** — TLS termination, external-dns ile auto DNS
- [ ] **4.2.6** **Prometheus ServiceMonitor** — server ve agent metriklerini Prometheus'a expose et
- [ ] **4.2.7** **Grafana dashboard** — K8s cluster + netscope metrics kombine dashboard
- [ ] **4.2.8** **cert-manager** entegrasyonu — TLS sertifikalarını otomatik yenileme
- [ ] **4.2.9** **Velero backup** — PostgreSQL ve config'in otomatik yedeği

---

## 📦 Faz 5 — Toplu Deployment Araçları

### 5.1 — SCCM / Microsoft Configuration Manager

- [ ] **5.1.1** **SCCM Application Model** — detection method + deployment type:
  - Detection: Registry `HKLM\SOFTWARE\Netscope\Agent\Version`
  - Install: `msiexec /i netscope-agent.msi /qn SERVER_URL=... TOKEN=...`
  - Uninstall: `msiexec /x {ProductCode} /qn`
- [ ] **5.1.2** **SCCM Collection** — "All Windows Servers", "Domain Controllers", "DMZ Servers"
- [ ] **5.1.3** **SCCM Deployment Phases**:
  - Phase 1: Pilot (10 makine, 1 hafta izle)
  - Phase 2: Ring 1 (100 makine)
  - Phase 3: Ring 2 (500 makine)
  - Phase 4: Full production
- [ ] **5.1.4** **SCCM Compliance Baseline** — sensör versiyonu, config doğruluğu, servis çalışıyor mu?

### 5.2 — Ansible

- [ ] **5.2.1** Ansible role: `ansible/roles/netscope-agent/`
  ```
  roles/netscope-agent/
  ├── tasks/
  │   ├── main.yml          # OS detection → include install-{windows,linux,macos}.yml
  │   ├── install-windows.yml
  │   ├── install-linux.yml
  │   ├── install-macos.yml
  │   ├── configure.yml     # config.toml template deployment
  │   ├── enroll.yml        # enrollment token doğrulama
  │   └── validate.yml      # health check
  ├── templates/
  │   ├── config.toml.j2
  │   ├── netscope-agent.service.j2   # systemd unit
  │   └── com.netscope.agent.plist.j2 # launchd
  ├── defaults/main.yml
  └── handlers/main.yml
  ```
- [ ] **5.2.2** Ansible playbook örneği:
  ```yaml
  # deploy-netscope.yml
  - name: Deploy netscope agent to all servers
    hosts: all
    become: yes
    roles:
      - netscope-agent
    vars:
      netscope_server_url: "https://soc-server.internal.corp:9443"
      netscope_enrollment_token: "{{ vault_netscope_token }}"
      netscope_sensor_group: "{{ ansible_environment }}"
      netscope_log_level: "info"
  ```
- [ ] **5.2.3** Ansible Vault ile token şifreleme
- [ ] **5.2.4** Dinamik inventory — AWS EC2, Azure VM, GCP Compute Engine tag'leri ile otomatik grup

### 5.3 — PowerShell DSC (Desired State Configuration)

- [ ] **5.3.1** DSC Resource modülü: `NetscopeAgentDSC`
  ```powershell
  Configuration NetscopeAgentConfig {
      Import-DscResource -ModuleName NetscopeAgentDSC
      
      Node "DC-Istanbul-*" {
          NetscopeAgent InstallAgent {
              Ensure = "Present"
              Version = "0.2.0"
              ServerUrl = "https://soc.istanbul.corp:9443"
              EnrollmentToken = "nse_token_istanbul..."
              SensorGroup = "DC-Istanbul"
              CaptureFilter = "not host 192.168.255.1"
          }
      }
      
      Node "DC-Ankara-*" {
          NetscopeAgent InstallAgent {
              Ensure = "Present"
              Version = "0.2.0"
              ServerUrl = "https://soc.ankara.corp:9443"
              EnrollmentToken = "nse_token_ankara..."
              SensorGroup = "DC-Ankara"
          }
      }
  }
  ```
- [ ] **5.3.2** DSC Pull Server / Azure Automation DSC desteği
- [ ] **5.3.3** DSC ile config drift detection ve auto-remediation

### 5.4 — PDQ Deploy

- [ ] **5.4.1** PDQ package XML — netscope-agent için hazır import dosyası
- [ ] **5.4.2** PDQ Inventory collection — netscope yüklü/yüksüz/outdated raporu

---

## 🔄 Faz 6 — Güncelleme Yönetimi (Update Management)

- [ ] **6.1.1** **Update server API** — `GET /api/v1/updates?channel=stable&current_version=0.1.9&arch=x64&os=windows`
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
- [ ] **6.1.2** **Staged rollout** — güncellemeyi kademeli yay:
  - Canary: %1 (ilk 24 saat)
  - Beta: %5 (48 saat sonra)
  - Stable: %25 → %50 → %100 (72-96 saatte tamamla)
- [ ] **6.1.3** **Rollback trigger** — canary'de error rate %1 üstüne çıkarsa otomatik durdur
- [ ] **6.1.4** **Maintenance window** — güncellemeleri sadece belirli zaman aralığında uygula (örn: Pazar 02:00-04:00)
- [ ] **6.1.5** **Auto-update policy** — GPO/Registry/Config ile kontrol:
  - `AutoUpdateEnabled=1` + `UpdateChannel=stable` → otomatik
  - `AutoUpdateEnabled=0` → sadece manuel
  - `UpdateChannel=canary` → en son build'leri test et
- [ ] **6.1.6** **Update cache/proxy** — büyük ağlarda WSUS/Squid proxy üzerinden güncelleme dağıtımı (bant genişliği tasarrufu)
- [ ] **6.1.7** **Peer-to-peer update** — LAN içinde diğer sensörlerden güncelleme çekme (BranchCache / LEDBAT)

---

## 🛡️ Faz 7 — Zero-Touch Provisioning & Enrollment

- [ ] **7.1.1** **Enrollment token modeli**:
  ```
  Token tipleri:
    - Bootstrap Token: sadece register için, 24 saat TTL, tek kullanımlık
    - Group Token:     belirli bir sensör grubuna otomatik atama
    - Permanent Token: API key benzeri, uzun ömürlü (servis hesabı)
  ```
- [ ] **7.1.2** **Enrollment flow**:
  ```
  1. Admin → server'da "Generate Enrollment Token" → nse_bt_abc123... (bootstrap, 24h, group: DC-Istanbul)
  2. Admin → MSI/GPO/MDM ile token'ı sensöre ilet
  3. Sensör → ilk başlatmada server'a register isteği (token + hostname + IP + OS + version)
  4. Server → token'ı doğrula, sensor_id oluştur, mTLS client cert üret, sensöre dön
  5. Sensör → client cert'i güvenli depola, sonraki bağlantılarda mTLS kullan
  6. Server → sensör heartbeat almaya başla
  ```
- [ ] **7.1.3** **Re-enrollment** — sensör kaybolursa (disk crash), aynı token ile yeniden register, aynı sensor_id'yi koru
- [ ] **7.1.4** **Enrollment portal** — Web UI'da "Enrollment" sayfası:
  - Token listesi (aktif / kullanılmış / expire olmuş)
  - Yeni token oluştur (grup seç, TTL belirle)
  - Token'ı iptal et
  - Hangi sensör hangi token ile kaydoldu gör
- [ ] **7.1.5** **Unattended XML** (Windows) — `unattend.xml` içine netscope kurulumu göm:
  ```xml
  <SynchronousCommand wcm:action="add">
    <CommandLine>msiexec /i C:\Deploy\netscope-agent.msi /qn NETSCOPE_SERVER_URL=https://soc.corp:9443 NETSCOPE_ENROLLMENT_TOKEN=nse_bt_abc123</CommandLine>
    <Order>10</Order>
  </SynchronousCommand>
  ```
- [ ] **7.1.6** **cloud-init** (Linux) — `cloud-config.yaml`:
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

- [ ] **8.1** **Fleet Overview sayfası**:
  - Toplam sensör: 1,247 (Online: 1,232 / Offline: 15)
  - Coğrafi dağılım haritası (GeoIP)
  - Sensör başına ortalama event/sn: 847
  - Son 24 saatte toplanan event: 14.2 milyar
  - Toplam alert: 342 (açık: 47)
- [ ] **8.2** **Sensör listesi** — data grid (sortable, filtrelenebilir):
  - Hostname, IP, OS, Versiyon, Grup, Uptime, CPU%, RAM MB, pkt/s, Event/s, Son görülme, Durum
  - Bulk operations: N sensör seç → yeniden başlat, güncelle, config push, deregister
- [ ] **8.3** **Sensör detay sayfası**:
  - Canlı throughput grafiği (son 24 saat, 5 dakika resolution)
  - Aktif yakalama: interface, filter, yazılan pcap
  - Son 1000 event (canlı, filtrelenebilir)
  - Konfigürasyon (mevcut vs. baseline, diff görünümü)
  - Komut geçmişi (hangi komut, ne zaman, sonuç)
  - Log'lar (son 500 satır, canlı tail)
- [ ] **8.4** **Config management**:
  - Template config'ler oluştur
  - Sensör grubuna toplu config push
  - Config drift detection — "42 sensör template'den sapmış"
  - Config rollback
- [ ] **8.5** **Update management UI**:
  - Hangi sensör hangi versiyonda?
  - Canary/Beta/Stable rollout progress bar
  - Rollback butonu
  - Update history
- [ ] **8.6** **Fleet health dashboard**:
  - Sensör uptime (son 30 gün)
  - Event throughput (aggregate)
  - Disk kullanımı (toplam, sensör başına)
  - Network latency (sensör ↔ server)
  - Versiyon dağılımı pasta grafiği

---

## 🧪 Faz 9 — Test & Benchmark

- [ ] **9.1** **Fleet scale test** — 1.000, 5.000, 10.000 simüle sensör:
  - Server CPU/memory/db connection kullanımı
  - Event ingestion throughput (events/sec)
  - Heartbeat processing latency
  - Database size growth (GB/gün)
  - Redis memory usage
- [ ] **9.2** **MSI install/uninstall test** — her Windows sürümünde (10, 11, Server 2019, 2022)
- [ ] **9.3** **MSI upgrade test** — v0.1 → v0.2, v0.2 → v0.3 (major + minor)
- [ ] **9.4** **GPO application test** — policy değişince sensör ne kadar sürede yeni config'i alıyor?
- [ ] **9.5** **MDM enrollment test** — Intune, Jamf, Workspace ONE (cihaz başına)
- [ ] **9.6** **Air-gapped deployment test** — internet olmadan kur, çalıştır, güncelle
- [ ] **9.7** **Resilience test** — server restart, DB failover, Redis restart, network partition
- [ ] **9.8** **Capacity planning calculator** — sensör sayısı × event/sn = gereken CPU/RAM/disk/network

---

## 🌐 Faz 10 — Air-Gapped & Offline Deployment

- [ ] **10.1** **Offline installer ISO** — tüm bağımlılıklar içeride:
  - netscope-agent MSI/DMG/DEB
  - Npcap (Windows)
  - WebView2 Evergreen Standalone Installer
  - MaxMind GeoLite2 database (son sürüm)
  - Suricata/ET rule set
  - AbuseIPDB/URLhaus threat intel
  - Belgeler (PDF manual, quick start)
- [ ] **10.2** **Offline update mechanism** — USB/network share'den güncelleme
- [ ] **10.3** **Local mirror server** — internal ağda update mirror, sensörler internet'e çıkmadan güncellenir
- [ ] **10.4** **Offline license/entitlement** — air-gapped ortamda offline license key doğrulama

---

## 📋 Faz 11 — Linux & macOS Enterprise Packaging

- [ ] **11.1** **APT repository** (Debian/Ubuntu):
  - Signed Release file (GPG key)
  - `deb https://apt.netscope.com stable main`
  - `apt install netscope-agent`
- [ ] **11.2** **RPM repository** (RHEL/CentOS/Fedora):
  - Signed RPM packages (GPG key)
  - `yum install netscope-agent`
- [ ] **11.3** **Homebrew Cask** (macOS):
  - `brew install --cask netscope-agent`
- [ ] **11.4** **Snap** (Linux — otomatik güncelleme, sandbox):
  - `snap install netscope-agent --classic` (network capture için classic confinement)
- [ ] **11.5** **Flatpak** (Linux — sandbox, cross-distro)
- [ ] **11.6** **systemd service** (Linux):
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
- [ ] **11.7** **LaunchDaemon** (macOS):
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
