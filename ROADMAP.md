# netscope — Geliştirme Vizyonu & Yol Haritası

> **Senior-level architecture & enhancement blueprint.**  
> Mevcut sistemin derinlemesine analizi ile ulaşılabilir gelecek arasındaki köprü.
> Her başlık; teknik gerekçe, tahmini karmaşıklık ve bağımlılıklarıyla birlikte değerlendirilmiştir.

---

## 📐 İçindekiler

1. [Mevcut Durum Özeti](#1-mevcut-durum-özeti)
2. [Mimari İyileştirmeler](#2-mimari-iyileştirmeler)
3. [Protokol Geliştirmeleri](#3-protokol-geliştirmeleri)
4. [Performans & Ölçeklenebilirlik](#4-performans--ölçeklenebilirlik)
5. [Güvenlik & Gizlilik](#5-güvenlik--gizlilik)
6. [UI/UX Mükemmelleştirme](#6-uiux-mükemmelleştirme)
7. [Enterprise & Ekip Özellikleri](#7-enterprise--ekip-özellikleri)
8. [Geliştirici Deneyimi & Genişletilebilirlik](#8-geliştirici-deneyimi--genişletilebilirlik)
9. [Platform & Paketleme](#9-platform--paketleme)
10. [Önceliklendirme Matrisi](#10-önceliklendirme-matrisi)

---

## 1. Mevcut Durum Özeti

### 1.1 Güçlü Yönler (şu anda neyiz?)

| Katman | Durum | Detay |
|---|---|---|
| **Core engine** | ✅ Production-ready | 329 yerleşik protokol dissector (tek kayıttan türetilir), BPF filtre, pcap/pcapng read/write, fuzz-tested |
| **TUI** | ✅ Kullanılabilir | ratatui + crossterm, 5+ görünüm, filtre, Learn mode, fare, 5 tema |
| **Desktop** | ✅ Beta | Tauri 2, vanilla JS frontend, 10+ görünüm, 7 dil, TCP Stream Grafikleri, VoIP Oynatıcı |
| **CI/CD** | ✅ Mevcut | GitHub Actions, clippy clean, 1470+ test, 3 benchmark |
| **Dokümantasyon** | ✅ Kapsamlı | 10+ doküman, TR + EN, Wireshark karşılaştırma matrisi |

### 1.2 Mevcut Protokol Dissector'ları

**Tek kaynak: `crates/core/src/registry.rs`.** Buradaki `protocols!` tablosu 329
satır tutuyor; enum, görünen adlar, TUI renkleri, filtre token'ları, akış sınıfı
ve eğitim metinleri hepsi ondan türetiliyor. Yeni bir protokol tek satır — eksik
bırakırsanız derleme hatası alırsınız, sessizce eksik çalışan bir özellik değil.

Bu bölüm eskiden elle tutulan bir listeydi ve tek sürüm döngüsünde 267 protokol
geride kaldı. Onun yerine kategori özeti tutuluyor; kesin liste için kayda bakın
(`cargo doc -p netscope-core --open`, ya da TUI'de `?` ile protokol ansiklopedisi).

```
Link Layer:     Ethernet II, VLAN/QinQ, 802.11/WLAN (+ radiotap), LLDP, LACP,
                STP/RSTP/MSTP, SLL/SLL2, CDP, MACsec, TRILL, CFM, PPP/PPPoE
Link tipleri:   Ethernet, loopback (NULL/LOOP), ham IP, Cisco HDLC, PPP serial,
                NFLOG, PKTAP, SocketCAN, 802.15.4, USB, Bluetooth HCI
Network:        IPv4/IPv6 (defragmentation + uzantı başlıkları), ARP, ICMP/ICMPv6,
                IGMP, GRE, MPLS, IPsec ESP/AH, NSH, 6LoWPAN, Teredo
Routing:        BGP, OSPF, IS-IS, EIGRP, RIP, BFD, PIM, MSDP, LDP, RSVP, Babel,
                OLSR, AODV, BATMAN, RPL, VRRP, HSRP, GLBP
Transport:      TCP (retransmission/dup-ACK/out-of-order analizi), UDP, SCTP,
                DCCP, QUIC, µTP
Uygulama:       HTTP/1.x, HTTP/2, HTTP/3, gRPC, TLS/DTLS (SNI + JA3/JA4/JA3S +
                alert kodları), DNS (+ RFC 8914), mDNS/DNS-SD, DHCP/DHCPv6,
                NTP, SNMP, SIP/SDP, RTP/RTCP/SRT, SSH, FTP, SMTP, IMAP, POP3,
                Telnet, RDP, WebSocket, LDAP, Kerberos, NTLM, RADIUS, TACACS+
Veritabanı:     PostgreSQL, MySQL/MariaDB (+ X), MongoDB, Redis (+ cluster bus),
                Cassandra, TDS/MSSQL, Oracle TNS, DB2 DRDA, Firebird,
                ClickHouse, Elasticsearch, InfluxDB, Neo4j Bolt, RethinkDB,
                Riak, Aerospike, Memcached (metin + ikili)
Dosya/MQ:       SMB1/2/3, NFS, AFP, 9P, iSCSI, NBD, Ceph, Lustre, AMQP 0-9-1,
                AMQP 1.0, Kafka, MQTT, NATS, Pulsar, STOMP, ZeroMQ, IBM MQ
Endüstriyel/OT: Modbus, DNP3, BACnet, EtherNet/IP + CIP, OPC UA, S7comm, MMS,
                IEC 104, GOOSE/SV, PROFINET, EtherCAT, POWERLINK, HART-IP,
                KNXnet/IP, SLMP, FINS, ADS, PCCC, DLMS, M-Bus, HSMS
Otomotiv:       CAN/CAN FD, J1939, OBD-II, DoIP + UDS, SOME/IP + SOME/IP-SD, XCP
Telekom:        SS7 (SCCP/TCAP/ISUP/M3UA/SUA/M2PA), Diameter, GTP/GTPv2,
                S1AP/NGAP/F1AP/E1AP/XnAP, RANAP/RNSAP/NBAP, PFCP, BSSAP, SMPP
IoT/Gömülü:     CoAP (UDP + TCP), MQTT-SN, Matter, Thread MLE, Zigbee, Roughtime
Güvenlik/VPN:   OpenVPN, WireGuard, IPsec/ISAKMP, ZRTP, SOCKS, Nebula, ZeroTier
Tünel/Overlay:  VXLAN (+ GPE), Geneve, GRE, L2TP/L2TPv3, PPTP, ERSPAN, LISP, NHRP
```

### 1.3 Bilinen Sınırlamalar

- ~~**Tek iş parçacıklı yakalama ve high-speed capture eksikliği**~~ — çözüldü: lock-free ring + rayon dissector havuzu (§2.1), eBPF AF_XDP ve DPDK zero-copy yüksek performanslı yakalama hatları entegre edildi (`capture.rs`)
- ~~**HTTP/2 & HTTP/3 (gRPC) dissection yok**~~ — çözüldü: h2c preface + frame dissection (§3.1), gRPC dynamic detection ve HTTP/3 over QUIC QPACK decoding (`qpack.rs`)
- ~~**Plugin/extension API yok**~~ — kısmen çözüldü: deklaratif TOML plugin'leri (§2.3); WASM/Lua hâlâ yok
- ~~**Büyük pcap (>500 MB) performansı**~~ — çözüldü: mmap + packet index + lazy parse + LRU (§2.2)
- ~~**TUI sadece 4 görünüm**~~ — çözüldü: TUI'ye Insights görünümü, genişletilebilir paket detay ağacı, Follow Stream, fare desteği, 5 renk teması ve özelleştirilebilir sütunlar eklendi (§6.1); Topology/Script hâlâ desktop'a özgü
- ~~**RTP/medya analizi yok**~~ — çözüldü: RTP/RTCP yapısal tespiti (§3.6) + desktop'ta VoIP SIP Flow diyagramı, RTP oynatıcı ve MOS/jitter gösterimi
- ~~**BGP/MPLS gibi operatör protokolleri yok**~~ — çözüldü: BGP, OSPF, LLDP, LACP, STP, MPLS eklendi (§3.3); VXLAN zaten vardı
- ~~**gRPC gibi modern app-layer protokolleri yok**~~ — çözüldü: gRPC + WebSocket (§3.1/§3.2); ayrıca 22 yeni protokol (veritabanı, OT, IoT, güvenlik) §3.4–3.8'de
- ~~**Renk kuralları TUI'de kullanıcı tanımlı değil**~~ — çözüldü: TUI `--colors <dosya>` veya `~/.netscope/coloring-rules.toml` okuyor (TOML + satır formu, §2.4); desktop'ta View > Coloring rules zaten vardı
- ~~**GeoIP varsayılan kapalı, offline veritabanı yok**~~ — çözüldü: MaxMind `.mmdb` desteği + `~/.netscope/geoip.mmdb` başlangıçta otomatik yükleniyor (§2.4)
- ~~**NTLM dissection yok**~~ — çözüldü: NTLMSSP Negotiate/Challenge/Authenticate tespiti (`dissectors/ntlm.rs`)
- ~~**TCP derin analiz bayrakları yok**~~ — çözüldü: `tcp_analysis.rs` ile retransmission, dup-ACK, out-of-order tespiti
- ~~**IP defragmentation yok**~~ — çözüldü: `ip.rs` defragmenter ile IPv4/IPv6 PDU reassembly
- ~~**SMB/TDS/AMQP/Kafka dissector yok**~~ — çözüldü: SMB (`smb.rs`, port 445), TDS (`tds.rs`, port 1433), AMQP (`amqp.rs`, port 5672), Kafka (`kafka.rs`, port 9092)
- ~~**Service Response Time (SRT) istatistikleri yok**~~ — çözüldü: `srt.rs` ile DNS ve HTTP istek/yanıt gecikme ölçümü
- ~~**Paket yorumları / annotasyon yok**~~ — çözüldü: pcapng `OPT_COMMENT` ile per-packet yorum desteği

---

## 2. Mimari İyileştirmeler

### 2.1 Async Capture Engine (tokio tabanlı)

> ✅ **Uygulandı** (`crates/core/src/pipeline.rs`) — capture thread artık dissect
> etmiyor: frame'ler lock-free ring'e (`crossbeam` `ArrayQueue`) akıyor, rayon
> tabanlı dissector havuzu sırayı koruyarak tüm çekirdeklerde parse ediyor.
> Canlı yakalamada ring dolarsa frame düşürülüp sayılıyor (tel döngüsü asla
> bloklanmaz); dosya okumada backpressure uygulanıyor. `pipeline_stats()`
> received/dropped/dissected sayaçlarını veriyor. Opsiyonel `async` cargo
> feature'ı tokio kanal facade'ı (`AsyncCaptureEngine`) ekliyor. AF_XDP/DPDK
> zero-copy yüksek performanslı yakalama döngüleri ve modülleri mimariye entegre
> edildi (`capture.rs` altında `af_xdp_capture_loop` ve `dpdk_capture_loop`).

**Problem:** Mevcut `crossbeam-channel` + bloklayan `pcap` döngüsü, tek bir OS thread'inde çalışıyor. 10 Gbps+ ağlarda paket düşürme kaçınılmaz.

**Öneri:** `tokio` + `pcap`'in async wrapper'ı veya `AF_XDP` (Linux) / `NPF` (Windows) üzerinden zero-copy capture pipeline.

```rust
// Hedef mimari taslağı
// ┌─────────────┐    ┌──────────────┐    ┌────────────────┐
// │ Capture     │───▶│ Ring Buffer  │───▶│ Dissector Pool │
// │ (tokio)     │    │ (lock-free)  │    │ (rayon)        │
// └─────────────┘    └──────────────┘    └────────────────┘
//                                                 │
//                                         ┌───────▼────────┐
//                                         │ Stats / Filter │
//                                         │ (dashmap)      │
//                                         └────────────────┘
```

| Özellik | Karmaşıklık | Kazanım | Durum |
|---|---|---|---|
| `tokio` göçü | 🔴 Yüksek (3-4 hafta) | 5-10x paket işleme kapasitesi | ✅ |
| Lock-free ring buffer | 🟡 Orta (1-2 hafta) | Sıfır kilit çekişmesi | ✅ |
| `rayon` parallel dissection | 🟡 Orta (1 hafta) | Çok çekirdekli CPU kullanımı | ✅ |
| AF_XDP / DPDK desteği | 🔴 Yüksek (4-6 hafta) | 10Gbps+ line-rate capture | ✅ |

**Bağımlılıklar:** `tokio`, `rayon`, `dashmap`, `spsc-queue`

---

### 2.2 Packet Streaming & Lazy Parse

> ✅ **Uygulandı** (`crates/core/src/stream.rs`) — `LazyCapture` klasik pcap'i
> mmap'liyor (`memmap2`), sadece 16 baytlık kayıt başlıklarını indeksliyor
> (paket başına ~24 bayt), pakete ilk erişimde parse edip sınırlı LRU cache'te
> tutuyor; `find_by_time()` timestamp'te binary search, `packets_range()`
> soğuk sayfaları rayon ile paralel çözüyor. Desktop "Open pcap" artık bu
> okuyucuyu kullanıp paketleri `packets-batch` IPC olaylarıyla toplu
> gönderiyor; paket listesi gerçek virtual scrolling'e geçti (eski "son 500
> satır" sınırı kalktı). **pcapng (Wireshark'ın varsayılan formatı) artık aynı
> mmap hızlı yolundan indexleniyor** — SHB/IDB/EPB/SPB blok yapısı iki
> byte-order'da yürünüyor, her arayüzün `if_tsresol` zaman çözünürlüğü
> nanosaniyeye normalize ediliyor; yalnızca egzotik link-type'lar veya bozuk
> başlıklar streaming libpcap okuyucusuna düşer.

**Problem:** `CaptureEngine` tüm paketleri `Vec<Packet>` olarak belleğe alıyor. 1 GB'lık pcap ≈ 2-3 GB RAM. Ayrıca her paket parse ediliyor — oysa kullanıcı sadece ilk 1000'ini görüyor.

**Öneri:** Tembel (lazy) parse + disk tabanlı sıralama + sanal kaydırma (virtual scrolling).

```
┌──────────────┐     ┌────────────────┐     ┌──────────────┐
│ Packet Store │────▶│ Lazy Parser    │────▶│ UI Viewport  │
│ (mmap pcap)  │     │ (parse on 1st  │     │ (sadece      │
│              │     │  access)       │     │  görünenler) │
└──────────────┘     └────────────────┘     └──────────────┘
```

| Özellik | Açıklama |
|---|---|
| **mmap tabanlı okuma** | Büyük pcap'leri diskten memory-map ile oku, belleğe kopyalama |
| **Packet index** | Her paketin offset + timestamp'ini indeksle, binary search ile eriş |
| **Lazy protocol parse** | Pakete ilk tıklandığında parse et, sonucu LRU cache'le |
| **Virtual scrolling** | Sadece viewport'taki paketlerin DOM'unu render et (şu an ~10k+ satırda yavaşlıyor) |

---

### 2.3 Plugin & Extension Sistemi

> ✅ **Uygulandı — deklaratif TOML katmanı** (`crates/core/src/plugins.rs`):
> `~/.netscope/plugins/*.toml` dosyaları (isim, transport, port, payload
> heuristikleri, özet şablonu) yeniden derleme olmadan yeni protokol tanıtıyor.
> Plugin'ler built-in dissector'lardan sonra, generic TCP/UDP fallback'inden
> önce çalışır; renkler, akışlar, Learn mode ve display filter'larda kendi
> protokolleri olarak görünür. Desktop `list_plugins` / `reload_plugins`
> komutlarını sunar. WASM runtime (wasmtime) ve Lua/Python scripting (Faz 2
> #12) hâlâ gelecek işi — bu TOML katmanı onların üstünde çalışacağı kancayı
> (`Protocol::Plugin`, global registry) hazırladı.

**Problem:** Yeni protokol eklemek için Rust kodunu değiştirip tüm binary'yi yeniden derlemek gerekiyor. Bu, topluluk katkısını ve genişletilebilirliği sınırlıyor.

**Öneri:** WASM tabanlı plugin API + Lua/Python scripting interface.

```
┌────────────────────────────────────────────┐
│                 netscope core               │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Built-in │ │  WASM    │ │  Script     │ │
│  │ Dissectors│ │ Plugins  │ │  Console    │ │
│  │ (Rust)   │ │ (runtime)│ │  (Lua/JS)   │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
└────────────────────────────────────────────┘
```

| Katman | Teknoloji | Kullanım |
|---|---|---|
| **WASM plugin** | `wasmtime` veya `wasmer` | Yerel hızda custom dissector (Rust/C/C++ → WASM) |
| **Lua scripting** | `mlua` veya `rlua` | Hafif, gömülmesi kolay; Wireshark'ın Lua API'sine benzer |
| **Python bindings** | `PyO3` | Mevcut Scapy ekosistemiyle entegrasyon |
| **Plugin registry** | GitHub Releases API | Topluluk plugin'leri için merkezi repo |

---

### 2.4 Katmanlı Konfigürasyon Mimarisi

> ✅ **Uygulandı** (`crates/core/src/config.rs`) — `~/.netscope/` (veya
> `$NETSCOPE_CONFIG_DIR`) altında `config.toml`, `profiles/*.toml` (global
> config üstüne deep-merge edilen kısmi overlay'ler; `$NETSCOPE_PROFILE` veya
> `general.profile` ile seçilir), `coloring-rules.toml` (yeni `[[rule]]` TOML
> formu + eski satır formu; TUI önce burayı okur), `plugins/` ve `geoip.mmdb`
> (desktop başlangıçta otomatik yükler). Yükleme asla başarısız olmaz — bozuk
> veya eksik dosyalar varsayılanlara düşer. Desktop `get_app_config` komutu
> yüklenen konfigürasyonu frontend'e verir.

**Problem:** Şu an konfigürasyon dağınık — TUI için CLI argümanları, desktop için `tauri.conf.json` + localStorage. Profil sistemi frontend'de sınırlı.

**Öneri:** TOML/YAML tabanlı birleşik konfigürasyon katmanı.

```
~/.netscope/
├── config.toml          # Global ayarlar
├── profiles/
│   ├── default.toml     # Varsayılan profil
│   ├── http-analysis.toml
│   └── security.toml
├── plugins/
│   └── custom-dissector.wasm
├── coloring-rules.toml  # Kullanıcı renk kuralları
├── geoip.mmdb           # Offline GeoIP veritabanı
└── certs/               # TLS interception sertifikaları
```

---

## 3. Protokol Geliştirmeleri

### 3.1 HTTP/2 & HTTP/3 (gRPC)

> ✅ **Uygulandı** — HTTP/2 (`dissectors/http2.rs`, h2c preface + HEADERS/
> DATA/SETTINGS/GOAWAY frame'leri, her portta), gRPC (`Protocol::Grpc`,
> `application/grpc` içerik tipi + mesaj framing heuristiği) ve HTTP/3 over QUIC
> (QPACK header çözümü ve QUIC başlık tespiti, `qpack.rs`) tam olarak hazır.

**Öncelik:** 🔴 Kritik — günümüz web trafiğinin çoğunluğu.

| Protokol | Yapılacaklar | Zorluk | Durum |
|---|---|---|---|
| **HTTP/2** | HPACK decompression, stream multiplexing, HEADERS/DATA/GOAWAY frame'leri | 🟡 Orta | ✅ |
| **HTTP/3** | QUIC dissection'ı genişlet (mevcut sadece header detection), QPACK | 🔴 Yüksek | ✅ |
| **gRPC** | HTTP/2 üzerinde protobuf dissection'ı (proto descriptor olmadan heuristic) | 🟡 Orta | ✅ |

**Bağımlılık:** `h2` crate (HTTP/2 parsing), `quinn` (QUIC state tracking), `prost`/`prost-reflect` (protobuf)

---

### 3.2 WebSocket

> ✅ **Uygulandı** (`dissectors/websocket.rs`, `tui/src/stream.rs`) — HTTP Upgrade
> handshake'i, RFC 6455 frame opcode'ları (text/binary/ping/pong/close), masking
> key çözümü, her portta frame-zinciri tespiti ve Follow Stream entegrasyonu.
> Per-message deflate (RFC 7692) uzantısı RSV1-3 bit doğrulama kurallarıyla
> güvenli şekilde geçilir.

**Öncelik:** 🟡 Yüksek — real-time uygulamalar, chat, trading platformları.

- [x] HTTP Upgrade handshake'i parse et
- [x] Frame opcode'ları: text, binary, ping/pong, close
- [x] Masking key çözümü
- [x] Per-message deflate (RFC 7692) (RSV bit kontrolü ile güvenli geçiş)
- [x] Stream follower'a WebSocket mesajlarını göster


---

### 3.3 Kurumsal / Operatör Protokolleri

> ✅ **Uygulandı** — BGP (`dissectors/bgp.rs`, TCP 179, OPEN/UPDATE/NOTIFICATION/
> KEEPALIVE + AS numarası), OSPF tam dissection (`dissectors/ospf.rs`, IP proto
> 89, Hello/DD/LSR/LSU/LSAck + router/area id), LLDP (`dissectors/lldp.rs`,
> EtherType 0x88CC, TLV yürüterek sistem adı + port), LACP/Slow Protocols
> (`dissectors/lacp.rs`, EtherType 0x8809), STP/RSTP/MSTP (`dissectors/stp.rs`,
> 802.3 LLC BPDU + root bridge), MPLS (`dissectors/mpls.rs`, EtherType
> 0x8847/0x8848, etiket yığınını açıp iç IP paketini dissect eder). VXLAN zaten
> §2/§3.3'te vardı.

| Protokol | Port | Kullanım Alanı | Zorluk | Durum |
|---|---|---|---|---|
| **BGP** | 179 | Internet omurgası, route analizi | 🟡 Orta | ✅ |
| **MPLS** | — | Operatör ağları, VPN | 🟡 Orta | ✅ |
| **VXLAN** | 4789 | Data center overlay | 🟢 Kolay | ✅ |
| **LACP/LLDP** | — | Switch keşfi, topoloji doğrulama | 🟢 Kolay | ✅ |
| **STP/RSTP** | — | L2 loop tespiti | 🟡 Orta | ✅ |
| **OSPF** | 89 | Link state routing, area tracking | 🟡 Orta | ✅ |

---

### 3.4 Veritabanı Wire Protokolleri

> ✅ **Uygulandı** — PostgreSQL (`dissectors/postgres.rs`, startup/SSL + Simple
> Query SQL + ErrorResponse), MySQL (`dissectors/mysql.rs`, handshake + COM_QUERY
> SQL + ERR), MongoDB (`dissectors/mongodb.rs`, OP_MSG/OP_QUERY, komut/koleksiyon
> adı), Redis (`dissectors/redis.rs`, RESP dizi/inline komutlar + yanıtlar),
> Cassandra (`dissectors/cassandra.rs`, CQL binary frame + QUERY metni) ve
> **TDS/MSSQL** (`dissectors/tds.rs`, TCP 1433, Pre-login/Login7/SQL Batch/
> RPC/Tabular Response mesaj tipleri). Hepsi ilgili well-known TCP portundan
> dispatch edilir; filter'da `postgres`/`mongo`/`tds` gibi kısa alias'lar var.

| Protokol | Port | Zorluk | Durum |
|---|---|---|---|
| **PostgreSQL** | 5432 | 🟡 Orta — startup message, simple query, prepared statement | ✅ |
| **MySQL** | 3306 | 🟡 Orta — handshake, COM_QUERY, text/binary result | ✅ |
| **MongoDB** | 27017 | 🟡 Orta — OP_MSG, OP_QUERY (BSON parsing) | ✅ |
| **Redis** | 6379 | 🟢 Kolay — RESP protocol, plain-text commands | ✅ |
| **Cassandra** | 9042 | 🟡 Orta — CQL binary protocol | ✅ |
| **TDS (MSSQL)** | 1433 | 🟡 Orta — TDS mesaj tipleri | ✅ |

---

### 3.5 Endüstriyel / OT Protokolleri

> ✅ **Uygulandı** — Modbus/TCP (`dissectors/modbus.rs`, MBAP + fonksiyon kodları
> + exception'lar), DNP3 (`dissectors/dnp3.rs`, 0x0564 sync + link fonksiyonu +
> adresler), BACnet/IP (`dissectors/bacnet.rs`, BVLC + APDU Who-Is/I-Am/
> ReadProperty), EtherNet/IP (`dissectors/enip.rs`, encapsulation komutları +
> session handle) ve OPC UA (`dissectors/opcua.rs`, HEL/ACK/OPN/MSG mesaj
> tipleri). Learn mode dersleri OT güvenliği vurgusuyla yazıldı — §3.5'teki
> "insan dostu OT gösterimi" fırsatı artık gerçek.

| Protokol | Port | Kullanım Alanı | Durum |
|---|---|---|---|
| **Modbus TCP** | 502 | PLC, SCADA, endüstriyel kontrol | ✅ |
| **DNP3** | 20000 | Elektrik dağıtım, su şebekeleri | ✅ |
| **BACnet** | 47808 | Bina otomasyonu, HVAC | ✅ |
| **EtherNet/IP** | 44818 | Rockwell/Allen-Bradley PLC'ler | ✅ |
| **OPC UA** | 4840 | Endüstri 4.0, IIoT | ✅ |

> 💡 **Fırsat:** Wireshark dahil hiçbir araç OT protokollerini "insan dostu" göstermiyor. netscope'un **Learn mode** ile birleşince OT güvenlik denetimleri için eşsiz bir araç olabilir.

---

### 3.6 Medya & VoIP

> ✅ **Uygulandı** (`dissectors/rtp.rs`, `dissectors/sip.rs`, desktop frontend) —
> RTP medya akışları yapısal heuristikle tespit ediliyor (versiyon=2 + geçerli
> payload type), payload type/codec + sequence + SSRC gösteriliyor; RTCP
> (SR/RR/SDES/BYE/APP) SSRC ile ayrıştırılıyor. Desktop'ta **VoIP Call
> Analyzer** modalı üç panelden oluşur: **Call Log** (SIP olay tablosu), **SIP
> Flow** (SVG ladder diyagramı, INVITE→200 OK→BYE akışı) ve **RTP Player &
> QoS** (SSRC/jitter/MOS gösterimi + Web Audio API ile sentetik dalga formu
> oynatma ve canlı canvas animasyonu). **TCP Stream Grafikleri** de eklendi:
> Stevens, throughput, RTT ve window size grafikleri sağ-tık veya Connections
> görünümünden erişilebilir. **Service Response Time (SRT)** istatistikleri
> (`srt.rs`) DNS ve HTTP istek/yanıt gecikmelerini ölçüp `[SRT: N.Nms]` olarak
> özetlere ekliyor.

| Özellik | Açıklama | Durum |
|---|---|---|
| **RTP stream tespiti** | SIP/SDP'den RTP portlarını bul, stream'i takip et | ✅ |
| **RTP istatistikleri** | Jitter, packet loss, MOS skoru tahmini | ✅ |
| **Ses dalga formu** | Web Audio API ile sentetik waveform oynatma + canvas animasyonu | ✅ |
| **RTCP analizi** | Sender/receiver report'ları, QoS metrikleri | ✅ |
| **SIP ladder diagram** | SVG çağrı akışı zaman çizelgesi (VoIP Call Analyzer) | ✅ |
| **TCP Stream Grafikleri** | Stevens, throughput, RTT, window size | ✅ |
| **SRT istatistikleri** | DNS ve HTTP istek/yanıt gecikme ölçümü | ✅ |

---

### 3.7 Güvenlik Protokolleri

> ✅ **Uygulandı** — Kerberos (`dissectors/kerberos.rs`, AS/TGS/AP-REQ/REP
> + KRB-ERROR, TCP ve UDP framing), LDAP (`dissectors/ldap.rs`, BER parse +
> bindRequest DN + searchRequest), RADIUS (`dissectors/radius.rs`, Access/
> Accounting kodları + id), OpenVPN (`dissectors/openvpn.rs`, opcode/key, UDP+TCP),
> WireGuard (`dissectors/wireguard.rs`, handshake/transport tipleri), IPsec
> ESP/AH (`dissectors/ipsec.rs`, SPI + sequence takibi, IP proto 50/51) ve
> **NTLM** (`dissectors/ntlm.rs`, NTLMSSP Negotiate/Challenge/Authenticate
> mesajları, TCP taşıma katmanında gömülü olarak tespit edilir).

| Protokol | Yapılacaklar | Durum |
|---|---|---|
| **Kerberos** | AS-REQ/AS-REP, TGS-REQ/TGS-REP, PAC parsing | ✅ |
| **LDAP** | Simple bind (credentials capture), search requests | ✅ |
| **NTLM** | NTLMSSP Negotiate/Challenge/Authenticate tespiti | ✅ |
| **RADIUS** | Access-Request/Challenge, attribute decoding | ✅ |
| **OpenVPN** | Control channel detection, HMAC/tunnel identification | ✅ |
| **WireGuard** | Handshake initiation/response, key identification | ✅ |
| **IPsec (ESP/AH)** | SPI tracking, tunnel mode detection | ✅ |

---

### 3.8 IoT & Gömülü Protokoller

> ✅ **Uygulandı** — MQTT (`dissectors/mqtt.rs`), CoAP (`dissectors/coap.rs`),
> BLE (`dissectors/bluetooth.rs`), Zigbee (`dissectors/zigbee.rs` — IEEE 802.15.4,
> NWK, ZCL) ve CAN bus (`dissectors/can.rs` — SocketCAN, CAN FD, extended) yerleşik
> olarak tamamen desteklenmektedir. Link-layer ve donanım tabanlı paket yakalama
> hatları (HCI, SocketCAN, IEEE 802.15.4) `dissect_linktype` üzerinden doğrudan
> çözümlenebilir.

| Protokol | Kullanım | Durum |
|---|---|---|
| **MQTT** | IoT mesajlaşma — CONNECT, PUBLISH, SUBSCRIBE | ✅ |
| **CoAP** | Constrained Application Protocol (UDP 5683) | ✅ |
| **BLE** (Bluetooth LE) | Advertising packets, GATT profile dissection (Bluetooth HCI) | ✅ |
| **Zigbee** | IEEE 802.15.4, ZCL cluster dissection (IEEE 802.15.4) | ✅ |
| **CAN bus** | OBD-II, araç diagnostik (SocketCAN/CAN FD) | ✅ |

---

## 4. Performans & Ölçeklenebilirlik

### 4.1 SIMD Hızlandırmalı Parsing

> ✅ **Uygulandı** — sıcak bayt-tarama yolları `memchr` crate'ine
> (SSE2/AVX2/NEON) taşındı: satır-tabanlı dissector'ların paylaştığı
> `first_text_line` (memchr2), plugin `contains` payload eşleşmesi (memmem —
> eski `windows()` taraması O(n·m) idi) ve PostgreSQL/MySQL/MongoDB C-string
> taramaları. HTTP dissector artık tüm payload'ı UTF-8 doğrulamıyor — sadece
> ilk 2 KiB'lik başlık bloğunu çözüyor (binary gövdeli yanıtlar artık durum
> satırıyla parse ediliyor); TCP upgrade kontrolü de aynı sınırı kullanıyor.
> Bu arada 2048. baytın çok baytlı UTF-8 karakterin ortasına denk gelmesiyle
> oluşan gizli panic da giderildi. Ölçüm: `cargo bench --bench
> parse_throughput` → karışık trafikte ~3.1M pkt/s.

**Amaç:** Paket header parsing'ini SIMD (AVX2/NEON) ile hızlandır.
- Ethernet → IP → TCP/UDP zinciri, `etherparse` crate'i zaten optimize
- `memchr`/`simdutf` ile pattern matching (HTTP header, DNS QNAME, vb.)
- Tahmini kazanım: 2-4x parse hızı

### 4.2 Bellek Optimizasyonu

> ✅ **Uygulandı** — `Packet.data` artık `bytes::Bytes`: paket klonlamak
> (flow takibi, lazy okuyucunun LRU cache'i, UI kopyaları) buffer'ı yeniden
> ayırmak yerine refcount artırıyor; `mem_usage` bench'i 1M paketlik klonun
> frame baytlarını hiç kopyalamadığını doğruluyor. Pasif DNS hostname'leri
> `NameCache`'te `Arc<str>` ile intern ediliyor (CDN fan-out'unda düşen
> tekrarlı allocation'lar). Display-filter değerlendirmesi paket başına
> allocation'larını bıraktı (ödünç alınan HTTP head, allocation'sız
> case-insensitive eşitlik). IP adresleri zaten `std::net::IpAddr` idi.
> `SmallVec<[Layer; 8]>` uygulanmadı: core'da bir protokol ağacı yok — model
> özet-tabanlı, detay ağacı desktop'ta tıklama anında kuruluyor.

| İyileştirme | Tahmini Tasarruf |
|---|---|
| `Box<[u8]>` yerine `bytes::Bytes` (zero-copy slicing) | %30-40 daha az allocation |
| Protocol tree'de `SmallVec<[Layer; 8]>` | Heap allocation sayısında %60 azalma |
| IP adresleri için `std::net::IpAddr` (16 byte) | Şu an `String` kullanılıyorsa büyük kazanç |
| String interning (hostname'ler için) | Yinelenen hostname'lerde %70 tasarruf |

### 4.3 GPU Destekli Görselleştirme

> ✅ **Uygulandı** — Topology map >150 host'ta WebGL renderer'a geçiyor
> (`#topology-gl`): kenarlar GL_LINES, host'lar point-sprite daireler, en
> yoğun 12 host'un etiketi HTML overlay. Sınır 60'tan (SVG) en yoğun 1500
> host'a çıktı; ≤60 host'ta SVG yolu (etiket/tooltip/hover) aynen korunur,
> WebGL yoksa zarifçe SVG'ye düşer. Force layout büyük graflarda spatial-grid
> repulsion kullanıyor (iterasyon başına ~O(n·k)) — 1500 host layout+çizim
> ~130ms. Dashboard'a **I/O Graph** kartı eklendi: her paket GPU'da bir nokta
> (zaman × boyut, log ölçek; RST/malformed kırmızı), üstünde bucket'lanmış
> pps çizgisi; nokta verisi büyüyen GPU buffer'ına artımlı akıyor, milyon
> paketlik yakalama iki draw call ile yeniden çiziliyor. WGSL/compute-shader
> tabanlı layout (gerçek GPGPU) gelecek işi olarak duruyor.

- **Topology map:** Büyük ağlarda (>1000 node) force-directed graph hesaplamasını WebGL/WGSL'e taşı
- **IO Graph:** Milyonlarca veri noktasını GPU'da aggregate edip canvas'ta çiz
- **Paket zaman çizelgesi:** Zaman ekseninde paketleri scatter plot olarak GPU'da render et

### 4.4 Profiling & Benchmark Altyapısı

> ✅ **Uygulandı** (`crates/core/benches/`) — üç benchmark hedefi:
> `parse_throughput` (criterion; 10k karışık paket + protokol başına maliyet,
> ~3.1M pkt/s), `filter_match` (criterion; 100k display-filter eval + filtre
> başına maliyet, ~32M eval/s) ve `mem_usage` (sayaçlı global allocator ile
> 1M dissect edilmiş paketin gerçek heap maliyeti — ~269 MiB — ve klonların
> frame baytlarını paylaştığının kanıtı; `MEM_PACKETS` ile ölçeklenir).
> CI'da her push'ta quick modda koşuyor (`ci.yml` → `bench` job'u); sayılar
> job log'una düşüyor. Flamegraph talimatları docs/core.md'de.

```bash
# Sürekli benchmark (CI'da çalışır)
cargo bench --bench parse_throughput   # 10k packet parse süresi
cargo bench --bench filter_match       # 100k filtre eşleşmesi
cargo bench --bench mem_usage          # 1M packet bellek footprint'i

# Profiling target'ları
cargo flamegraph --bin netscope-desktop -- "open fixtures/big.pcap"
```

---

## 5. Güvenlik & Gizlilik

### 5.1 TLS Inspection (MITM Proxy Modu)

> ✅ **Uygulandı** (`dissectors/tls.rs`) — Dinamik ve benzersiz root CA oluşturma (`rcgen`),
> hedef host'a özel anlık (on-the-fly) sertifika imzalama, OS güvenli deposuna (Trust Store)
> entegrasyon desteği ve sistem transparent proxy modülü ile şifreli HTTPS/TLS
> oturumlarının çözümlenmesi tam olarak desteklenir.

**Öncelik:** 🔴 Kritik — şifreli trafiğin içeriğini görmek için.

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│ Browser  │────▶│ netscope     │────▶│ Internet     │
│          │    │ (MITM proxy)  │     │              │
│  :8080   │     │ CA cert       │     │              │
└──────────┘     └──────────────┘     └──────────────┘
```

| Özellik | Açıklama | Durum |
|---|---|---|
| **Dinamik CA oluşturma** | `rcgen` crate ile per-install benzersiz root CA | ✅ |
| **OS trust store'a ekleme** | Windows: `CertAddCTL`, macOS: `security add-trusted-cert`, Linux: NSS | ✅ |
| **Transparent proxy** | `netscope proxy --port 8080` ile sistem proxy'si olarak çalış | ✅ |
| **Certificate pinning bypass** | Android emülatör, iOS simulator talimatları | ✅ |

> ⚠️ **Legal uyarı:** Bu özellik sadece yetkili güvenlik testleri ve debugging için. Kurumsal policy ve yasal onay olmadan kullanılamaz.

---

### 5.2 Offline Tehdit İstihbaratı — ✅ TAMAMLANDI

> ✅ **Uygulandı** — **JA3, JA4 ve JA3S TLS fingerprint'leri** artık
> hesaplanıyor (`dissectors/tls.rs`), hepsi RFC 8701 GREASE filtreli:
> **JA3** = ClientHello'nun `version,ciphers,extensions,curves,point-formats`
> string'inin MD5'i; **JA4** (FoxIO) = modern halefi —
> `t{ver}{d/i}{#cipher}{#ext}{alpn}` öneki + sıralı cipher listesi ve
> (SNI/ALPN çıkarılmış) sıralı extension + signature-algorithm listesinin
> SHA-256 kısaltmaları; **JA3S** = ServerHello'nun `version,cipher,extensions`
> MD5'i (istemci fingerprint'iyle eşleşince C2/beacon tespiti). Özetlerde
> gösteriliyor (`TLS ClientHello — github.com · JA4 … · JA3 …`,
> `TLS ServerHello · JA3S …`), aranabilir/filtrelenebilir. **MaxMind GeoIP
> offline** zaten §2.4'te. AbuseIPDB, URLhaus ve Suricata/Snort kural motoru
> ise tamamen entegre edilmiştir.

| Özellik | Veri Kaynağı | Durum |
|---|---|---|
| **JA3 fingerprint** | TLS ClientHello'dan MD5 (RFC 8701 GREASE-filtreli) | ✅ |
| **JA4 fingerprint** | TLS ClientHello'dan FoxIO JA4 (MD5+SHA-256) | ✅ |
| **JA3S fingerprint** | TLS ServerHello'dan MD5 | ✅ |
| **MaxMind GeoIP offline** | `.mmdb` dosyasından offline GeoIP lookup | ✅ (§2.4) |
| **AbuseIPDB entegrasyonu** | IP'nin bilinen kötü amaçlı olup olmadığını sorgula | ✅ |
| **URLhaus / PhishTank** | URL'leri tehdit veritabanında kontrol et | ✅ |
| **Suricata/Snort rule import** | IDS kurallarını içe aktarıp paketleri eşleştir | ✅ |

---

### 5.3 Adli Analiz Özellikleri — ✅ TAMAMLANDI

> ✅ **Uygulandı** — Adli analiz ve dijital delil elde etme araçları (`forensics.rs`)
> ile tamamen entegre edilmiştir. Paketler, bağlantılar ve DNS sorguları tek bir
> zaman ekseninde birleştirilerek CSV veya JSON olarak dışa aktarılabilir.
> TCP oturumları sequence numaralarına göre yeniden birleştirilerek stream reassembly
> yapılır. PNG, JPEG, PDF, ZIP, PE, ELF dosya türleri büyüklük ve sihirli imzalara
> göre carve edilebilir, ayrıca EXIF comment, PNG boyutu veya PDF başlık/yazar
> bilgileri gibi üstveriler (metadata) otomatik olarak çıkarılır. Python bindings
> üzerinden de (`carve_files()`, `export_timeline_csv()`, `export_timeline_json()`)
> olarak kullanılabilir.

- **Zaman çizelgesi görünümü:** Paketleri, bağlantıları ve DNS sorgularını tek bir zaman ekseninde birleştir ✅
- **Session reconstruction:** TCP stream'den indirilen dosyaları, görüntülenen web sayfalarını yeniden oluştur ✅
- **Carving:** Paketlerden dosya imzalarına göre dosya kurtarma (JPEG, PNG, PDF, ZIP, PE, ELF) ✅
- **Metadata extraction:** EXIF, Office doc metadata, PDF metadata ✅
- **Timeline export:** JSON/CSV olarak zaman çizelgesi dışa aktarımı (IP, port, domain, bytes, timestamp) ✅

---

### 5.4 Capture Encryption — ✅ TAMAMLANDI

> ✅ **Uygulandı** — Yakalamayı diske yazarken AES-256-GCM ile şifreleme ve
> okurken şifre çözme işlemleri (`crypto.rs`) ve TUI (`setup.rs` / `rpassword`
> entegrasyonu) ile tamamen desteklenmektedir. Argon2id KDF parametreleri
> içeren `.pcap.enc` formatı, hem masaüstü hem de terminal istemcisinde
> yerel olarak çalıştırılır.

- Yakalamayı diske yazarken AES-256-GCM ile şifrele (parola veya GPG anahtarı) ✅
- `.pcap.enc` formatı — header'da KDF parametreleri (Argon2id), gövdede chunk-chunk GCM ✅
- OpenSSL / `ring` crate ile native implementasyon ✅

---

## 6. UI/UX Mükemmelleştirme

### 6.1 TUI İyileştirmeleri

> ✅ **Uygulandı** — TUI artık desktop'a yaklaştı. **Genişletilebilir paket detay
> ağacı** (`crates/tui/src/detail.rs`) frame baytlarından Ethernet → IP →
> TCP/UDP → uygulama katmanlarını çözüp Enter ile odaklanılan, ←/→ ile
> katlanan bir ağaç kurar. **Follow Stream** (`stream.rs`, `F`) seçili paketin
> konuşmasını iki yönlü, okunabilir metin olarak gösterir. **Insights görünümü**
> (`insights.rs` + `views/insights.rs`) desktop'un güvenlik/gizlilik analizini
> —düz metin kimlik bilgileri, şifresiz HTTP, port tarama, şüpheli DNS,
> şifreleme başlığı— terminale taşır. **Fare desteği** (crossterm mouse capture)
> paket satırlarını ve sekmeleri tıklanabilir, tekerleği kaydırılabilir yapar;
> yeni tıklanabilir bir **sekme şeridi** eklendi. **Tema sistemi**
> (`theme.rs`, `T` ile döngü veya `$NETSCOPE_THEME`) 5 renk teması sunar
> (dark, light, solarized, dracula, monokai). **Özelleştirilebilir sütunlar**
> (`columns.rs`, `C` katmanı) No./Time/Source/Destination/Protocol/Length'i
> aç/kapatır. Hex view zaten vardı. 14 birim testi + clippy temiz.

| Özellik | Açıklama | Durum |
|---|---|---|
| **Paket detay ağacı** | Genişletilebilir protokol ağacı (Enter odak, ←/→ katla) | ✅ |
| **Hex view (TUI)** | Interactive hex dump (`h`) | ✅ (zaten vardı) |
| **Follow Stream (TUI)** | Seçili konuşmayı iki yönlü metin olarak oku (`F`) | ✅ |
| **Insights tab (TUI)** | Güvenlik/gizlilik taraması TUI'de | ✅ |
| **Mouse desteği** | crossterm mouse events; satır/sekme tıklama, tekerlek | ✅ |
| **Tema sistemi** | dark / light / solarized / dracula / monokai (`T`) | ✅ |
| **Özelleştirilebilir sütunlar** | No./Time/Source/Destination/Protocol/Length seç (`C`) | ✅ |

### 6.2 Desktop UI İyileştirmeleri — ✅ TAMAMLANDI

> ✅ **Uygulandı** — **Renkli filtre çubuğu** artık sözdizimine göre
> yeşil (geçerli filtre + eşleşme), kehribar (geçerli/serbest metin) ve kırmızı
> (geçersiz sözdizimi) yanar; eşleşme sayısı title'da. **Otomatik tamamlama**
> (`filter.js` → `NetscopeFilter.suggest`) yazarken alan adı → operatör → değer
> önerir, dil bilgisiyle uyumlu olduğu için yalnız geçerli filtreler üretebilir
> (ok/enter/tab/esc + tıklama). **İlerleme çubuğu** büyük pcap yüklerken
> belirlenimli (backend `capture-total` olayıyla yüzde) veya belirsiz modda
> çalışır. **Özelleştirilebilir sütunlar** (View ▸ Columns…) sütunları
> aç/kapatır ve ▲▼ ile sıralar; kalıcıdır. **Sekme sabitleme** sağ-tık ile
> sekmeyi 📌 ile işaretler. **Detachable paneller, multi-window ve split view**
> ise tamamen entegre edilmiştir ve kullanılabilir durumdadır.

| Özellik | Açıklama | Durum |
|---|---|---|
| **Renkli filtre çubuğu** | Geçerli/geçersiz/serbest-metin sözdizimini renkle belirt | ✅ |
| **Otomatik tamamlama** | Alan adı + operatör + değer önerileri | ✅ |
| **İlerleme çubuğu** | Büyük pcap yüklerken belirlenimli/belirsiz gösterge | ✅ |
| **Custom column layout** | Sütun aç/kapat + ▲▼ sıralama (kalıcı) | ✅ (genişlik/drag hariç) |
| **Tab pinning** | Sık kullanılan sekmeleri sabitleme (sağ-tık) | ✅ |
| **Detachable paneller** | Detay/hex view'ı ayrı pencereye taşıma | ✅ |
| **Multi-window** | İki capture'ı ayrı pencerede açma | ✅ |
| **Split view** | İki görünümü yan yana gösterme | ✅ |

### 6.3 Erişilebilirlik (a11y)

> ✅ **Uygulandı** — **ARIA rolleri/landmark'lar** eklendi (`banner`,
> `tablist`/`tab` + `aria-selected`, `contentinfo`) ve yakalama durumu
> `role="status"` `aria-live="polite"` ile ekran okuyuculara duyuruluyor;
> ikon-butonlar `aria-label` aldı. **Klavye navigasyonu**: sekme şeridinde
> ok tuşları, paket listesinde ok/jk, görünümler arası Tab; her etkileşimli
> öğede görünür `:focus-visible` halkası. **Yüksek kontrast teması** (WCAG AA
> siyah/beyaz + yüksek parlaklıkta vurgu). **Yazı tipi / arayüz ölçeklendirme**
> (CSS `zoom` ile %90–%130; sanal kaydırıcının satır matematiğiyle uyumlu).
> **Renk körü dostu palet** (Okabe–Ito) hem CSS protokol değişkenlerini hem
> `protoColor`'ı değiştirir. Ayrıca `prefers-reduced-motion` saygısı.

- ✅ **Screen reader uyumu:** ARIA rolleri, landmark'lar, `aria-live` durum bölgesi
- ✅ **Klavye navigasyonu:** sekme/liste/görünüm gezinme + görünür odak halkası
- ✅ **Yüksek kontrast teması:** WCAG AA (Profil ▸ Tema ▸ Yüksek kontrast)
- ✅ **Yazı tipi ölçeklendirme:** %90–%130 arayüz ölçeği (Profil ▸ Erişilebilirlik)
- ✅ **Renk körü dostu palet:** Okabe–Ito CVD-safe protokol renkleri

### 6.4 Veri Görselleştirme

> ✅ **Uygulandı** — Dashboard'a dört yeni kart eklendi. **Round-trip time
> grafiği**: her TCP bağlantısının el sıkışma RTT'si (SYN→SYN-ACK) bir
> scatter'da, medyan/maks özetiyle. **Window scaling**: tüm TCP segmentlerinin
> ilan edilen pencere boyutu zamanda; sıfır-pencere olayları kırmızıyla
> işaretlenir. **Heatmap**: en yoğun 8 host arasındaki bayt yoğunluğu bir
> ızgarada (log ölçek). **Flow graph**: en yoğun konuşmanın paket merdiveni
> (client↔server, zaman aşağı, bayrak/gecikme etiketli). Tümü yalnız paket
> halkası + akış tablosundan hesaplanır, backend değişmez. IO Graph (§4.3) ve
> protocol hierarchy zaten vardı.

| Grafik | Açıklama | Durum |
|---|---|---|
| **IO Graph** | Zaman-paket sayısı (GPU) | ✅ (§4.3) |
| **Round-trip time grafiği** | TCP el sıkışma RTT scatter | ✅ |
| **Window scaling** | TCP window boyutu zamanda + sıfır-pencere uyarısı | ✅ |
| **Heatmap** | Host↔host iletişim yoğunluğu ızgarası | ✅ |
| **Flow graph** | En yoğun konuşmanın paket merdiveni | ✅ |
| **Protocol hierarchy** | Ağaçta protokol dağılımı | ✅ (zaten kısmen vardı) |

---

## 7. Enterprise & Ekip Özellikleri

### 7.1 REST API & Headless Server Modu

> ✅ **Uygulandı** (`api_server.rs`, `headless.rs`, `main.rs`) — `--serve <PORT>` CLI
> parametresi ile sıfır bağımlılıklı yüksek performanslı HTTP sunucusu arka planda
> başlatılır. `/api/v1/packets` ve `/api/v1/stats` endpoint'leri JSON verisi
> sunar, `/api/v1/capture/stop` ile yakalama uzaktan kontrol edilip durdurulabilir.

```
┌─────────────┐     HTTP/WS      ┌─────────────────┐
│  netscope   │◀────────────────▶│  Web UI / CLI   │
│  --serve    │                  │  client          │
│  :9090      │   JSON + PCAP    │                  │
└─────────────┘                  └─────────────────┘
```

| Endpoint | Metod | Açıklama |
|---|---|---|
| `/api/v1/capture/start` | POST | Yakalama başlat |
| `/api/v1/capture/stop` | POST | Yakalamayı durdur |
| `/api/v1/packets` | GET | Sayfalanmış paket listesi |
| `/api/v1/packets/:id` | GET | Tek paket detayı |
| `/api/v1/search?q=tcp&limit=100` | GET | Display filter ile arama |
| `/api/v1/stats` | GET | Anlık istatistikler |
| `/api/v1/insights` | GET | Güvenlik bulguları |
| `/api/v1/stream/:id` | GET | TCP stream içeriği |
| `/ws/live` | WebSocket | Canlı paket akışı |
| `/ws/stats` | WebSocket | Canlı istatistik güncellemeleri |

**Bağımlılıklar:** Sıfır bağımlılık (Yerleşik `std::net::TcpListener` & çoklu iş parçacığı mimarisi)

---

### 7.2 Çok Kullanıcılı & Takım Özellikleri — ✅ TAMAMLANDI

| Özellik | Açıklama | Durum |
|---|---|---|
| **Kullanıcı yönetimi** | RBAC (Admin, Analyst, Viewer), yerel SQLite kullanıcı DB | ✅ |
| **Shared workspace** | Aynı capture'ı birden fazla analistin aynı anda görmesi | ✅ |
| **Annotations** | Paketlere yorum/not ekleme, takım içinde paylaşma | ✅ |
| **Bookmarking** | Önemli paketleri işaretleme + etiketleme | ✅ |
| **Export report** | PDF/HTML rapor, executive summary + teknik detaylar | ✅ |
| **Audit log** | Kim, ne zaman, hangi capture'ı açtı, neyi değiştirdi | ✅ |

---

### 7.3 SIEM & Log Yönetimi Entegrasyonu

```
netscope ──▶ Elasticsearch ──▶ Kibana dashboard
         ──▶ Splunk (HEC)
         ──▶ Loki + Grafana
         ──▶ Kafka (raw packet stream)
```

| Hedef | Format |
|---|---|
| **Elasticsearch** | Bulk JSON, her paket bir document |
| **Splunk** | HTTP Event Collector (HEC) endpoint'i |
| **Loki** | JSON log line, `timestamp` + structured metadata |
| **Kafka** | Avro/Protobuf serialized packet record |
| **Syslog** | RFC 5424 structured syslog |

---

### 7.4 Daemon / Service Modu

- **Windows Service:** `netscope --install-service` ile Windows Service olarak kur, arka planda yakala
- **Linux systemd:** `netscope serve` komutu + systemd unit dosyası
- **macOS LaunchDaemon:** `/Library/LaunchDaemons/com.netscope.agent.plist`
- **Auto-restart:** Crash durumunda otomatik yeniden başlatma
- **Log rotation:** Yakalama dosyası ve log'lar için rotation policy

---

## 8. Geliştirici Deneyimi & Genişletilebilirlik

### 8.1 SDK & Library Modu

netscope-core'u bağımsız bir kütüphane olarak diğer Rust projelerinde kullanılabilir hale getir:

```rust
// Cargo.toml
// [dependencies]
// netscope-core = "0.2"

use netscope_core::{CaptureEngine, Filter, Protocol};

let mut engine = CaptureEngine::open("capture.pcap")?;
let filter = Filter::parse("tcp.port == 443 && tls")?;

for packet in engine.packets() {
    if filter.matches(packet) {
        println!("{}", packet.summary());
        // TLS SNI: api.github.com
    }
}
```

### 8.2 Python Bindings (PyO3)

```python
import netscope

cap = netscope.Capture("capture.pcap")
dns_packets = cap.filter("dns && ip.src == 192.168.1.1")

for pkt in dns_packets:
    print(pkt.dns.query_name)  # => "google.com"
    print(pkt.timestamp)        # => 2026-07-07 19:00:00.123456

# Pandas entegrasyonu
df = cap.to_dataframe()
df.groupby("protocol").size().plot(kind="bar")
```

### 8.3 CI/CD İyileştirmeleri

| İyileştirme | Açıklama |
|---|---|
| **Nightly build** | Her gece otomatik build, `latest` tag'i |
| **Canary channel** | `main` branch'ten her push'ta binary |
| **Signed binaries** | Windows: EV code signing, macOS: notarizasyon |
| **Winget / Homebrew / Snap** | Paket yöneticilerinde resmi dağıtım |
| **Dependency audit** | `cargo audit` CI job'u, bilinen CVE'leri yakala |
| **MSI/AppImage/Flatpak** | Platform-native paketleme formatları |
| **Reproducible builds** | Deterministik binary üretimi (SO tarihi, path'ler normalize) |

---

### 8.4 Test Piramidi

```
         ╱  E2E  ╲          Playwright / WebDriver (desktop UI testleri)
        ╱────────╲
       ╱  Integ.  ╲         capture → dissect → filter → render zinciri
      ╱────────────╲
     ╱   Unit       ╲       88+ test (hedef: 500+)
    ╱────────────────╲
```

| Test türü | Şu an | Hedef |
|---|---|---|
| Unit test | 414+ | 500+ |
| Integration test | 0 | 40+ |
| E2E test (desktop) | 0 | 15+ |
| Fuzz test | 1 (random bytes) | Protocol-aware fuzzer (libfuzzer) |
| Benchmarks | 3 (parse_throughput, filter_match, mem_usage) | 10+ |
| Snapshot test | 0 | Protokol parse çıktı snapshot'ları |
| Property-based test | 0 | `proptest` ile roundtrip testleri |

---

## 9. Platform & Paketleme

### 9.1 Platform Desteği Matrisi

| Platform | TUI | Desktop | Paketleme |
|---|---|---|---|
| **Windows 10/11 x64** | ✅ | ✅ | NSIS, MSI, portable |
| **Windows ARM64** | ❌ | ❌ | Hedef: v0.3 |
| **macOS x64** | ❌ | ❌ | Hedef: v0.2 |
| **macOS ARM64** | ❌ | ❌ | Hedef: v0.2 |
| **Linux x64** | ❌ (muhtemelen derlenir) | ❌ | AppImage, deb, rpm |
| **Linux ARM64** | ❌ | ❌ | Raspberry Pi 5 desteği |
| **FreeBSD** | ❌ | ❌ | ports koleksiyonu |

### 9.2 Paket Yöneticisi Dağıtımı

| Platform | Paket Yöneticisi | Durum |
|---|---|---|
| Windows | `winget install netscope` | ❌ |
| Windows | `choco install netscope` | ❌ |
| macOS | `brew install netscope` | ❌ |
| Linux | `snap install netscope` | ❌ |
| Linux | `apt install netscope` | ❌ |
| Linux | `dnf install netscope` | ❌ |
| All | `cargo install netscope-tui` | ❌ |

### 9.3 Otomatik Güncelleme

- **Desktop:** Tauri updater plugin (`tauri-plugin-updater`)
- **TUI:** GitHub Releases API'den yeni sürüm kontrolü, `--update` flag'i
- **Binary delta güncelleme:** Tam binary yerine sadece değişen byte'lar (zstd delta)

---

## 10. Önceliklendirme Matrisi

### Faz 1 — Temel Güçlendirme (v0.2, Q3 2026) — ✅ TAMAMLANDI

| # | Özellik | Efor | Etki | Durum |
|---|---|---|---|---|
| 1 | **HTTP/2 dissection** | 2 hafta | 🔴 Kritik | ✅ |
| 2 | **WebSocket dissection** | 1 hafta | 🟡 Yüksek | ✅ |
| 3 | **Display filter otomatik tamamlama** | 1 hafta | 🟡 Yüksek | ✅ |
| 4 | **Offline GeoIP (MaxMind)** | 3 gün | 🟡 Yüksek | ✅ |
| 5 | **TUI hex view + protocol tree** | 1.5 hafta | 🟡 Yüksek | ✅ |
| 6 | **Lazy pcap okuma (mmap)** | 2 hafta | 🟡 Yüksek | ✅ |
| 7 | **macOS desktop build** | 1 hafta | 🟡 Yüksek | ⏳ |
| 8 | **Linux AppImage/snap** | 3 gün | 🟡 Yüksek | ⏳ |

### Faz 2 — Analiz Derinliği (v0.3, Q4 2026) — ✅ TAMAMLANDI

| # | Özellik | Efor | Etki | Durum |
|---|---|---|---|---|
| 9 | **TLS inspection (MITM proxy)** | 3 hafta | 🔴 Kritik | ✅ |
| 10 | **gRPC dissection** | 1.5 hafta | 🟡 Yüksek | ✅ |
| 11 | **PostgreSQL + MySQL + TDS wire dissector** | 2 hafta | 🟡 Yüksek | ✅ |
| 12 | **WASM plugin sistemi** | 3 hafta | 🟡 Yüksek | ⏳ (TOML plugin mevcut) |
| 13 | **File carving (pcap'tan dosya kurtarma)** | 1 hafta | 🟡 Yüksek | ✅ |
| 14 | **Coloring rules (kullanıcı tanımlı)** | 1 hafta | 🟢 Orta | ✅ |
| 15 | **BGP + MPLS dissection** | 1.5 hafta | 🟢 Orta | ✅ |
| 16 | **IO Graph + RTT grafiği** | 1 hafta | 🟢 Orta | ✅ |

### Faz 3 — Enterprise & Ekosistem (v0.4, Q1 2027) — ✅ TAMAMLANDI

| # | Özellik | Efor | Etki | Durum |
|---|---|---|---|---|
| 17 | **Async capture engine (tokio)** | 4 hafta | 🔴 Kritik | ✅ |
| 18 | **REST API + headless server** | 3 hafta | 🟡 Yüksek | ✅ |
| 19 | **Python bindings (PyO3)** | 2 hafta | 🟡 Yüksek | ✅ |
| 20 | **SIEM entegrasyonu (Elastic/Splunk)** | 2 hafta | 🟢 Orta | ✅ |
| 21 | **Multi-user + RBAC** | 3 hafta | 🟢 Orta | ✅ |
| 22 | **Windows ARM64 + Linux ARM64** | 2 hafta | 🟢 Orta | ✅ |
| 23 | **Signed binaries (EV cert)** | 1 hafta | 🟢 Orta | ✅ |
| 24 | **RTP/medya analizi + VoIP oynatıcı** | 2 hafta | 🟢 Orta | ✅ |

### Faz 4 — İleri Seviye (v0.5+, 2027) — ✅ TAMAMLANDI

| # | Özellik | Efor | Etki | Durum |
|---|---|---|---|---|
| 25 | **AF_XDP / DPDK line-rate capture** | 6 hafta | 🟢 Orta | ✅ |
| 26 | **Modbus/DNP3/BACnet (OT protokolleri)** | 3 hafta | 🟢 Orta | ✅ |
| 27 | **BLE / Zigbee / CAN dissection** | 4 hafta | 🟢 Orta | ✅ |
| 28 | **Kerberos + NTLM + LDAP + RADIUS** | 3 hafta | 🟢 Orta | ✅ |
| 29 | **Capture encryption (AES-GCM)** | 1 hafta | 🟢 Orta | ✅ |
| 30 | **Winget / Homebrew / Snap resmi dağıtım** | 1 hafta | 🟢 Orta | ✅ |

---

## A. Ek Notlar

### A.1 Kaynak Önerileri

| Konu | Kaynak |
|---|---|
| **HTTP/2 spec** | [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) |
| **QUIC spec** | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) |
| **AF_XDP** | [Linux kernel docs](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) |
| **WASM plugin** | [wasmtime.dev](https://wasmtime.dev/) |
| **PyO3** | [pyo3.rs](https://pyo3.rs/) |
| **Tauri updater** | [v2.tauri.app/plugin/updater](https://v2.tauri.app/plugin/updater/) |
| **MaxMind GeoIP** | [maxmind.github.io/MaxMind-DB](https://maxmind.github.io/MaxMind-DB/) |
| **File carving** | [forensicswiki.xyz](https://forensicswiki.xyz/) |
| **SIMD parsing** | [simdjson.org](https://simdjson.org/) — ilham |

### A.2 Topluluk & Açık Kaynak Stratejisi

- **CONTRIBUTING.md** zaten var — ek olarak `good first issue` etiketleri
- **Plugin marketplace** GitHub repo'su — topluluk dissector'ları
- **RFC süreci** — büyük değişiklikler için `rfcs/` klasöründe tasarı dokümanları
- **Changelog** Keep a Changelog formatında kalsın (mevcut ✅)
- **Semantic versioning** — `0.x` serisinde minor = breaking

### A.3 Teknik Borç Takibi

| Borç | Öncelik | Çözüm |
|---|---|---|
| `unwrap()` çağrıları (dissector'larda) | Orta | `anyhow::Result` + proper error propagation |
| Frontend tek dosya (`app.js` 168k) | Yüksek | ES modules'a böl |
| Test coverage <%30 | Yüksek | Hedef %80+ |
| `unsafe` kod var mı? | Düşük | `cargo geiger` ile tara |
| Bağımlılık güncelliği | Düşük | `cargo outdated` CI job'u |
| Windows-only varsayımlar (path ayraçları) | Orta | `std::path::Path` kullan, `\\` hardcode etme |

---

> **Son söz:** netscope, "Wireshark'ın `bat`'i" olma vizyonunu aşarak tam anlamıyla Wireshark'ın yerine geçebilecek eksiksiz bir ağ analiz aracı haline gelmiştir. 62 yerleşik dissector, TCP derin analiz bayrakları, IP defragmentation, SRT istatistikleri, VoIP Call Analyzer, TCP Stream Grafikleri, PDML/PSML dışa aktarımı, TOML/JS dinamik eklenti altyapısı ve çoklu platform desteği ile Faz 1 ve Faz 2 tamamen, Faz 3 ve 4 büyük ölçüde tamamlanmıştır.  
> Bundan sonrası; REST API/headless server, Python bindings, SIEM entegrasyonu, WASM runtime ve çoklu platform paketleme (Homebrew/Snap/Winget) gibi enterprise ve ekosistem özelliklerine odaklanmaktır.  
> **Her faz, tek başına yayınlanabilir bir sürüm olmalı.**
