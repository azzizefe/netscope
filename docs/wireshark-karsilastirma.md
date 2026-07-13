# netscope vs Wireshark — Kapsamlı Karşılaştırma

> **Amaç:** netscope'un Wireshark karşısında nerede *tam*, nerede *kısmi*, nerede *eksik* olduğunu dürüstçe ortaya koymak; neyin eklenmesi *gerektiğini* ve neyin eklenmesinin *güzel* olacağını önceliklendirmek.
> **Tarih:** 2026-07-13 · **Kapsam:** netscope 0.1.0 (core + TUI + Tauri desktop) vs Wireshark 4.x

---

## 0. Bir cümlede konumlandırma

| | netscope | Wireshark |
|---|---|---|
| **Kimlik** | "İnsanlar için Wireshark" — odaklı, okunabilir, güvenlik-öncelikli, çevrimdışı, tek küçük binary | Ağ analizinin **referans aracı** — 25+ yıl, devasa protokol kapsamı, her şeyi gösterir ama hiçbir şeyi yorumlamaz |
| **Felsefe** | Sinyal, gürültü değil. Az ama derin. Yorumlar. | Eksiksizlik. Her protokol, her alan, her platform. |
| **En güçlü yanı** | UX, güvenlik içgörüsü, gizlilik, öğrenme, JA3/JA4 kutudan | Protokol genişliği (~3000 dissector), TLS deşifre, olgunluk |

**netscope Wireshark'ı "geçmek" için onun her şeyini yapmak zorunda değil** — farklı bir kitleye (analiste değil, geliştiriciye/öğrenciye/güvenlikçiye) hitap ediyor. Ama "ciddi bir alternatif" olması için aşağıdaki kritik boşlukların kapatılması gerekir.

**Gösterge:** ✅ tam · 🟡 kısmi/temel · ❌ yok

---

## 1. Yakalama (Capture)

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Canlı yakalama (tek arayüz) | ✅ | ✅ | libpcap/Npcap üzerinden |
| BPF yakalama filtresi (`-f`) | ✅ | ✅ | Aynı sözdizimi |
| Lock-free ring + paralel dissect | ✅ | 🟡 | netscope çok çekirdekli; Wireshark tek-thread dissect |
| Monitor mode (Wi-Fi rfmon) | ✅ | ✅ | |
| Dropped-packet sayacı | ✅ | ✅ | |
| **Aynı anda birden çok arayüz** | ✅ | ✅ | Her arayüz kendi capture-thread + dissector-pipeline'ında; tek akışa birleşir. TUI: `-i "Wi-Fi,Ethernet"`; desktop: "🌐 Tüm arayüzler" |
| **Uzaktan yakalama** (sshdump, ciscodump, extcap)| ❌ | ✅ | Wireshark uzak host/cihazdan çeker |
| **Ring buffer / dosyaya dönüşümlü yakalama** | ❌ | ✅ | Uzun süreli yakalamada dosya rotasyonu |
| **USB / Bluetooth / CAN yakalama** | ❌ | ✅ | Özel link-type + donanım gerektirir |
| Yakalama sırasında durdur-koşulları (süre/boyut/paket) | ❌ | ✅ | |

---

## 2. Dosya Formatları (I/O)

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| pcap oku (klasik) | ✅ | ✅ | mmap + lazy parse, dev dosyalar için hızlı |
| **pcapng oku** | ✅ | ✅ | Wireshark'ın varsayılan formatı; netscope artık aynı hızlı yoldan indeksliyor |
| pcap yaz | ✅ | ✅ | |
| **pcapng yaz** (yorumlar, çoklu arayüz, meta) | ✅ | ✅ | netscope artık `.pcapng` uzantılı dosya kaydetme desteğine sahip |
| Şifreli yakalama (`.pcap.enc`, AES-GCM) | ✅ | ❌ | netscope'a özgü |
| **Diğer format import** (snoop, pcap variants, k12, erf…) | ✅ | ✅ | netscope snoop, modified pcap, ERF ve K12 formatlarını otomatik algılayıp açar |
| **Birleştir/böl** (mergecap/editcap muadili) | ✅ | ✅ | CLI sub-command'leri (`merge`, `split`, `info`) ile entegre |

---

## 3. Protokol Dissection (Genişlik)

| | netscope | Wireshark |
|---|:---:|:---:|
| **Dissector sayısı** | **~50** | **~3000** |
| Kapsam | Ethernet/IP/TCP/UDP, DNS, HTTP/1-2-3 (QPACK), TLS, QUIC, DHCP, DoH/DoT değil, DB (PG/MySQL/Mongo/Redis/Cassandra), OT (Modbus/DNP3/BACnet/EtherNet-IP/OPC-UA), VoIP (SIP/RTP/RTCP Jitter/MOS), güvenlik (Kerberos/LDAP/RADIUS/OpenVPN/WireGuard/IPsec/NTLM), IoT (MQTT/CoAP), operatör (BGP/OSPF/MPLS/LLDP/LACP/STP), overlay (VXLAN) | Neredeyse her şey |

> **Bu, en büyük ve kapatılması en zor boşluk.** Wireshark'ın protokol genişliği onun *varlık sebebi*. netscope stratejisi bunu 1:1 kovalamak **olmamalı** — bunun yerine (a) en yaygın 50-100 protokolü *insan-okunur* biçimde yapmak, (b) **eklenti/scripting** ile uzun kuyruğu topluluğa bırakmak (§10). Yine de SMB/SMB2, NFS, TDS(MSSQL), AMQP, Kafka, gRPC-web, gibi popüler eksikler öncelikli.

**Tamamlananlar (✅):** HTTP/3 (QPACK statik tablo kod çözümü dahil), gRPC (protobuf descriptor'suz heuristik kod çözümü dahil), RTP (jitter/MOS kalitesi dahil), NTLM (SSP çözücü dahil).

---

## 4. Görüntüleme Filtresi & Paket Listesi

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Wireshark-tarzı display filter dili | ✅ | ✅ | `ip.addr==`, `tcp.port==`, `&&/\|\|/!`, `contains` |
| Filtre otomatik tamamlama | ✅ | ✅ | Desktop: alan→operatör→değer |
| Serbest-metin arama (fallback) | ✅ | 🟡 | netscope tek kutuda ikisini birleştirir |
| Renklendirme kuralları (kullanıcı) | ✅ | ✅ | TUI + desktop |
| **JA3/JA4/JA3S filtre alanları** | ✅ | 🟡 | Wireshark eklenti/lua ister; netscope yerleşik |
| Özelleştirilebilir sütunlar | ✅ | ✅ | Genişlik/sürükle sınırlı |
| **"Apply as Column" / "Apply as Filter" / "Prepare a Filter"** | ❌ | ✅ | Sağ-tık ile alandan sütun/filtre üretme |
| **Filtre yer imleri / makrolar** | ❌ | ✅ | Kayıtlı filtre kütüphanesi |
| **Alan sayısı (filtrelenebilir)** | ~15 alan | ~300.000 alan | Wireshark her dissector alanını filtrelenebilir yapar |
| **Zaman referansı / zaman kaydırma / delta** | 🟡 | ✅ | netscope delta gösterir, "set time reference" yok |

> **Önemli mimari fark:** Wireshark'ta *her* dissector alanı otomatik filtrelenebilir (`http.host`, `dns.a`, `tcp.analysis.retransmission`…). netscope'ta filtre alanları elle eklenir. Bu, "az ama seçili" felsefesiyle uyumlu ama güçlü kullanıcıyı sınırlar.

---

## 5. Analiz & İstatistik

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Protokol dağılımı | ✅ | ✅ | |
| Top talkers / endpoints | ✅ | ✅ | |
| Conversations tablosu | ✅ | ✅ | netscope: Connections görünümü |
| **Protocol Hierarchy (ağaç)** | 🟡 | ✅ | netscope kısmi |
| Bant genişliği / IO Graph | ✅ | ✅ | GPU hızlandırmalı |
| RTT / pencere boyutu / heatmap / flow graph | ✅ | 🟡 | netscope modern kartlar; Wireshark TCP stream graph'ları (Stevens/tcptrace) |
| **Expert Info sistemi** | 🟡 | ✅ | netscope: reset/malformed rozetleri; Wireshark: tam hata/uyarı/not/chat taksonomisi + `tcp.analysis.*` |
| **Service Response Time** (SMB/RPC/…) | ❌ | ✅ | |
| **Packet Lengths / IO istatistik penceresi** | 🟡 | ✅ | |
| **TCP retransmission / dup-ACK / out-of-order tespiti** | ❌ | ✅ | Wireshark'ın en çok kullanılan analizi; netscope'ta yok |
| Güvenlik/gizlilik otomatik taraması (Insights) | ✅ | ❌ | netscope'a özgü |

> **En kritik analiz boşluğu: TCP akış sağlığı analizi** (`tcp.analysis.retransmission`, `.duplicate_ack`, `.zero_window`, `.out_of_order`). Ağ sorunu teşhisinin bel kemiği. netscope pencere/RTT görselleştiriyor ama bu bayrakları paket bazında üretmiyor.

---

## 6. Akış / Stream Analizi

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Follow Stream (TCP/UDP) | ✅ | ✅ | İki yönlü metin |
| **TCP reassembly (segment birleştirme)** | 🟡 | ✅ | netscope özet-tabanlı; Wireshark tam PDU yeniden montajı |
| **IP defragmentation** | ❌ | ✅ | |
| Follow — HTTP/2, TLS, QUIC stream | 🟡 | ✅ | |
| **Export Objects** (HTTP/SMB/FTP'den dosya çıkarma) | ❌ | ✅ | Yakalamadan indirilen dosyaları kurtarma |
| **File carving** (imzadan dosya kurtarma) | ❌ | ✅(kısmen) | ROADMAP'te planlı |

---

## 7. Şifre Çözme (Decryption)

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| **TLS deşifre (SSLKEYLOGFILE / keylog)** | ❌ | ✅ | **Wireshark'ın en güçlü kozlarından. netscope'ta yok.** |
| TLS deşifre (RSA private key) | ❌ | ✅ | |
| **WPA/WPA2/WEP (Wi-Fi) deşifre** | ❌ | ✅ | |
| Kerberos / IPsec (anahtarla) deşifre | ❌ | ✅ | |
| TLS MITM CA altyapısı | 🟡 | ❌ | netscope'ta `rcgen` temeli var, proxy modu henüz yok (ROADMAP §5.1) |
| JA3/JA4/JA3S fingerprint | ✅ | 🟡 | netscope yerleşik; Wireshark eklenti |

> **`SSLKEYLOGFILE` ile TLS deşifresi netscope için en yüksek getirili tek özellik olabilir.** Chrome/Firefox/curl bu dosyayı üretebiliyor; Wireshark bununla HTTPS içeriğini açıyor. netscope bunu eklerse "şifreli trafiği de okuyabilen" sınıfa girer — MITM proxy'den çok daha basit ve yasal olarak temiz.

---

## 8. Görselleştirme

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Topology / host grafiği | ✅ | ❌ | GPU/WebGL, 1500 host |
| IO Graph | ✅ | ✅ | |
| Flow graph (ladder) | ✅ | ✅ | |
| Heatmap / RTT / window scatter | ✅ | 🟡 | Modern kartlar |
| **TCP Stream Graphs** (time-sequence, throughput, RTT, window) | 🟡 | ✅ | Wireshark'ın Stevens/tcptrace grafikleri |
| **VoIP: SIP flow + RTP oynatıcı** | ❌ | ✅ | RTP sesini oynatma, jitter/MOS |

---

## 9. Dışa Aktarım (Export)

| Format | netscope | Wireshark |
|---|:---:|:---:|
| pcap kaydet | ✅ | ✅ |
| CSV | ✅ | ✅ |
| JSON | ✅ | ✅ |
| Markdown rapor (scrubbing + IP anonimleştirme) | ✅ | ❌ |
| **PDML / PSML (XML)** | ❌ | ✅ |
| **C arrays / hex dump / plain text** | 🟡 | ✅ |
| **Export Objects (dosya)** | ❌ | ✅ |
| **Export Packet Bytes** | 🟡 | ✅ |

---

## 10. Genişletilebilirlik (Extensibility)

| Özellik | netscope | Wireshark | Not |
|---|:---:|:---:|---|
| Deklaratif eklenti (yeni protokol, yeniden derlemesiz) | ✅ (TOML) | 🟡 | netscope TOML; Wireshark Lua/C |
| **Script konsolu (paket üstünde kod)** | ✅ (JS) | 🟡 | netscope kutuda JS; Wireshark Lua |
| **Lua dissector API** | ❌ | ✅ | Wireshark ekosisteminin belkemiği |
| **C plugin API** | ❌ | ✅ | |
| **WASM eklenti** | ❌ | ❌ | netscope ROADMAP'te (§2.3) |
| **extcap arayüzü** | ❌ | ✅ | Harici yakalama kaynakları |
| SDK / kütüphane olarak kullanım | 🟡 | 🟡 | netscope-core Rust crate; ROADMAP'te Python binding |

---

## 11. Platform & Paketleme

| | netscope | Wireshark |
|---|:---:|:---:|
| Windows | ✅ (yayınlı) | ✅ |
| macOS | 🟡 (derlenir, yayın yok) | ✅ |
| Linux | 🟡 (derlenir, yayın yok) | ✅ |
| BSD | ❌ | ✅ |
| Paket yöneticileri (brew/apt/winget…) | ❌ | ✅ |
| Tek binary / kurulumsuz | ✅ | ❌ (~200 MB) |
| İmzalı binary (code signing) | ❌ | ✅ |

---

## 12. netscope'un Wireshark'ta OLMAYAN artıları (farklılaştırıcılar)

Bunlar netscope'un "geçme" iddiasının dayanağı — Wireshark bunları *tasarımı gereği* yapmaz:

- 🎓 **Learn mode** — her protokolü ve paketi düz dille açıklama
- 🛡 **Insights** — otomatik güvenlik/gizlilik taraması (açık şifre, şifresiz HTTP, port tarama, şüpheli DNS, şifreleme oranı)
- 🔎 **Privacy X-ray** — "bu site benden ne alıyor, arka planda kim çalışıyor"
- 🧠 **İnsan-okunur özetler** — `google.com → 142.250...`, SNI/DNS/HTTP çözümlü
- ⚡ **Script konsolu** — paket akışı üstünde doğrudan JavaScript
- 🧩 **Semantic parsing** — paketi iş mantığına çevirme
- 🔮 **Protocol guesser** — entropi/port/magic ile bilinmeyen protokol tahmini
- ↻ **Replay/Repeater** — paketi düzenleyip yeniden gönderme (yerleşik)
- 🛡 **WAF tespiti**, 🌐 **threat-intel pivot linkleri**, 🔀 **Traffic diff**
- 🔑 **JA3/JA4/JA3S kutudan** (Wireshark eklenti ister)
- 🔒 **Tamamen çevrimdışı, telemetrisiz, tek küçük binary**
- 🌍 **7 dil + erişilebilirlik (WCAG-AA, ekran okuyucu)**

---

## 13. Öncelikli Eylem Planı

### 🔴 Kritik — "ciddi alternatif" için gerekenler
1. **TCP analiz bayrakları** (`retransmission`, `dup-ACK`, `zero-window`, `out-of-order`) — ağ teşhisinin bel kemiği, şu an tamamen yok.
2. **TLS deşifre (`SSLKEYLOGFILE`)** — en yüksek getirili tek özellik; HTTPS içeriğini açar.
3. **Tam TCP reassembly + IP defragmentation** — çok-segmentli PDU'lar (büyük HTTP gövdesi, TLS kayıtları) doğru çözülsün.
4. **"Apply as Filter / Column" sağ-tık** + daha fazla filtrelenebilir alan — güç kullanıcı akışı.

### 🟡 Yüksek — kapsamı ciddi büyütür
5. **pcapng yazma** (yorumlar dahil) — kaydedilen dosya Wireshark'la tam uyumlu olsun.
6. **Export Objects** (HTTP/SMB'den dosya çıkarma) + **file carving**.
7. **Popüler eksik dissector'lar**: SMB/SMB2, TDS (MSSQL), gRPC-tam, HTTP/3 QPACK, AMQP, Kafka.
8. **Lua veya WASM dissector API** — protokol uzun kuyruğunu topluluğa aç.
9. **macOS + Linux yayın** (şu an yalnız Windows yayınlı) + paket yöneticileri.

### 🟢 Güzel olur — cila / niş
10. **VoIP RTP analizi** (jitter/loss/MOS) + basit oynatıcı.
11. **Wi-Fi (WPA) deşifre**.
12. **TCP Stream Graphs** (time-sequence/Stevens) — Wireshark tarzı.
13. **Paket yorumları/annotasyon** (pcapng comment) + yer imleri.
14. **Uzaktan (extcap) yakalama** — çoklu arayüz artık var (✅), uzak/SSH kaynakları kaldı.
15. **PDML/PSML export** — başka araçlarla entegrasyon.
16. **Service Response Time** istatistikleri.

---

## 14. Özet tablo — nerede durum ne?

| Kategori | Durum |
|---|---|
| **Tam / rekabetçi** | Display filter, renklendirme, temel istatistik, IO/topology görselleştirme, Follow Stream, BPF yakalama, pcap/pcapng okuma, JA3/JA4/JA3S, güvenlik içgörüsü, UX/öğrenme |
| **Kısmi** | Protocol hierarchy, expert info, TCP reassembly, gRPC/HTTP-3, RTP, export (temel), platform (Win yayınlı), TLS MITM temeli |
| **Eksik (kritik)** | TCP analiz bayrakları, TLS keylog deşifre, IP defrag, Export Objects, Lua/C plugin API, uzak (extcap) yakalama, pcapng yazma |
| **Eksik (niş)** | VoIP oynatıcı, Wi-Fi deşifre, USB/BT/CAN, PDML, service response time, paket yorumları |

> **Sonuç:** netscope, "insan-dostu + güvenlik-öncelikli + çevrimdışı" nişinde Wireshark'ı **zaten geçiyor**. Ama "genel amaçlı derin ağ analizi" alanında Wireshark hâlâ önde — aradaki farkı en çok kapatacak dört şey: **TCP analiz bayrakları, TLS keylog deşifre, tam reassembly/defrag, ve bir gerçek eklenti API'si (Lua/WASM).** Bu dördü olmadan netscope "harika bir tamamlayıcı"; bunlarla birlikte "gerçek bir yerine geçen" olur.
