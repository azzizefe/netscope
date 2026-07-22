# netscope — 250 Protokollük Genişletme Planı

> **Senior-level protocol expansion blueprint.**
> Hedef: **342 → 592 protokol**.
> Bu belge bir istek listesi değil; her satırı bir kabul kriterine, bir tanınma
> yöntemine ve bir reddetme gerekçesine bağlı bir çalışma planıdır.

**Durum:** 390 protokol · 1889 core + 36 TUI + 2 desktop test · `cargo test --workspace` yeşil
**Son güncelleme:** 2026-07-21 · **Tamamlanan: 49/250 + E1, E3, E7, E8 (E2/E4 başladı, E5 engelli)** *(+5 zaten kapsanıyordu, 3 iptal, 2 hata düzeltmesi)*

---

## 📐 İçindekiler

1. [Ürün kısıtları ve mimari sonuçları](#1-ürün-kısıtları-ve-mimari-sonuçları)
2. [Kalite barı ve reddetme politikası](#2-kalite-barı-ve-reddetme-politikası)
3. [Protokol başına tanım-tamam (DoD)](#3-protokol-başına-tanım-tamam-dod)
4. [Ön koşul iş kalemleri (enabler'lar)](#4-ön-koşul-iş-kalemleri-enablerlar)
5. [Fazlar ve protokol listesi (250)](#5-fazlar-ve-protokol-listesi-250)
6. [Reddedilenler kaydı](#6-reddedilenler-kaydı)
7. [Riskler ve ölçüm](#7-riskler-ve-ölçüm)
8. [İlerleme özeti](#8-i̇lerleme-özeti)

---

## 1. Ürün kısıtları ve mimari sonuçları

netscope; VPS'siz, veritabanısız, kullanıcının kendi makinesinde çalışan, açık
kaynak bir masaüstü aracıdır. Bu bir dağıtım tercihi değil, **çözümleyici
tasarımını doğrudan bağlayan bir kısıttır**:

Bu kısıtlar artık iddia değil, **test tarafından zorlanan kurallar** —
`dissectors::robustness` içinde. Bir kısıtın kutucuğu, ancak onu ihlal eden bir
değişikliği düşüren bir test varsa işaretlidir.

- [x] **Runtime'da ağ sorgusu yok.** OUI tablosu, servis adları, tehdit
      imzaları — hepsi derleme zamanında gömülü. (Bir paket çözümleyici,
      incelediği ağa paket göndermemelidir; adli kopyalarda bu bir doğruluk
      meselesidir.)
      → `no_dissector_reaches_out_to_the_network`: dissector kaynaklarında
      soket/HTTP **çağrısı** arıyor. Düz kelime değil çağrı sözdizimi arıyor,
      çünkü `UdpSocket` kelimesi dissector'ın anlattığı protokolde geçebilir.
- [x] **Deterministik çözümleme.** Aynı capture iki kez açıldığında aynı çıktı.
      → `a_capture_read_twice_gives_the_same_answers`.
      **Bu testi yazarken bir şey netleşti:** çözümleme *durumsuz değildir ve
      olmamalıdır* — TCP bir akış, yeniden birleştirici kasten segmentler arası
      durum taşıyor. Naif yazılan test tam bu yüzden düşüyor. Gerçek özellik
      **durumun sıfırlanabilir olması**; test onu doğruluyor ve ayrıca
      sıfırlamanın gerçekten bir şey yaptığını iddia ediyor (aksi halde
      boş yere geçerdi).
- [x] **Telemetri yok — ama "hiçbir şey çıkmaz" değil.**
      → `the_only_thing_that_can_send_is_the_export_the_user_configured`.
      **İlk yazdığım ifade fazla mutlaktı ve test onu yakaladı:** çekirdekte
      `ureq` var. İncelendi — `siem.rs`, kullanıcının kendi Elasticsearch/Splunk
      adresine olay gönderiyor ve **URL verilmezse hiçbir şey göndermiyor.**
      Bu telemetri değil; kullanıcının açtığı ve hedefini kendi verdiği bir
      özellik. Doğru sınır şu ve test bunu tutuyor: satıcı telemetri SDK'sı
      ağaçta **hiç** olamaz (kullanıcı-yönlendirmeli bir kullanımı yok), HTTP
      istemcisi olabilir ama **yalnız o tek açık dışa aktarma yolunda** kalır,
      çözümlemeden asla erişilebilir olmaz.
- [x] **İndirme boyutu bütçesi.** Ölçüldü: **15.3 MB** (release `netscope-tui`),
      80 MB eşiğinin %19'u. Aşılırsa protokol aileleri `cargo feature` arkasına
      alınır (**E6**); niş olanlar `crate::plugins`'e taşınır.
- [x] **Derleme süresi bütçesi.** Ölçüldü: **199 sn** temiz release build
      (`netscope-core`), 5 dk eşiğinin %66'sı. **Dört metrik içinde sınırına en
      yakın olan bu** — §7'ye bakın.

> ⚠️ **Bu bölüm bir onay listesi değil, bir kabul kapısıdır.** Yukarıdakilerden
> birini ihlal eden bir PR, protokol ne kadar değerli olursa olsun reddedilir.
> Kutucuklar "düşündük" demek değil; her birinin arkasında ihlali düşüren bir
> test ya da ölçülmüş bir sayı var.

---

## 2. Kalite barı ve reddetme politikası

Mevcut 342 protokolün tamamı şu barı geçti; yeni 250'si de geçmek zorunda:

1. **Kamuya açık bir spesifikasyon** (RFC, IEC/IEEE/ITU standardı, ya da
   okunabilir bir referans implementasyon).
2. **Telde tanınabilirlik** — atanmış EtherType, port + içerik guard'ı, ya da
   gerçek bir magic. "Sadece port" yeterli değildir.
3. **Eyleme dönüşen bir özet** — okuyanın bir karar alabileceği bir cümle.
   "Protokol X mesajı" özeti bu barı geçmez.

**Reddetmek de iştir.** Bir protokol yalnızca "port + biraz framing"
derinliğine ulaşabiliyorsa, eklenmez ve gerekçesi §6'ya yazılır. Kotayı
doldurmak için bar düşürülmez — bu listedeki 250 sayısı bir hedef, bir söz
değildir.

**Şifreli protokoller (🔒):** Yükü TLS/DTLS içinde taşıyan protokoller ancak
anahtar sağlanabildiğinde (mevcut TLS keylog desteği) veya dış zarf tek başına
eyleme dönüşen bilgi taşıdığında (ör. ALPN, SNI, sertifika zinciri) kabul
edilir. Aksi halde §6'ya gider — OCSP ve NTS-KE bu yüzden reddedildi.

### Güven etiketleri

| Etiket | Anlamı | Beklenen dönüşüm |
|:--|:--|:--|
| ✅ | Spec ve tanınma yöntemi doğrulandı; barı geçeceği net | ~%95 eklenir |
| ⚠️ | Gerçek protokol, ama spec erişimi veya derinlik riskli | ~%50 eklenir |
| 🔒 | Şifreli/tescilli; yalnız zarf okunabilir | ~%20 eklenir |

> ⚠️ **Bu liste bilerek fazladan sağlanmıştır.** ⚠️ ve 🔒 kalemlerinin bir
> kısmı incelemede §6'ya düşecektir; yerine §5.12'deki yedek havuzdan seçim
> yapılır. **Hiçbir kalem, kotayı tutturmak için barı esneterek eklenmez.**

---

## 3. Protokol başına tanım-tamam (DoD)

Bu **protokol başına** bir şablon, tek seferlik bir liste değil — bu yüzden
kutucukları "hepsi bitti" diye işaretlenmez. İşaretli olanlar, **bir testin
otomatik zorladığı** maddelerdir; işaretsiz olanlar her PR'da elle bakılır.

- [x] `crates/core/src/dissectors/<ad>.rs` — dissector + `pub mod` kaydı
- [x] **Dissector gerçekten erişilebilir** → `every_dissector_module_is_reachable`
      (dispatch'ten ulaşılamayan modül testi düşürür)
- [x] `registry.rs` içinde **tek satır** registry kaydı
      (Protocol enum, Display, TUI rengi, filtre token'ı, flow sınıfı, rank ve
      education blurb'ü bundan **türetilir** — `filter.rs`, `flows.rs`,
      `colors.rs`, `education.rs` elle düzenlenmez)
- [x] **Her registry protokolünü bir dissector gerçekten üretir**
      → `every_protocol_is_produced_by_some_dissector`
- [x] **Bağlama tabloları sıralı ve tekil** → `tables_are_sorted_and_unique`
- [x] **Her bağlı port kendi dissector'ına ulaşır** → `every_table_port_reaches_its_own_dissector`
- [x] `education::lesson` içinde ders (match exhaustive — derleyici zaten ister)
- [x] Testler:
  - [x] Protokolün **var olma sebebini** doğrulayan en az bir test
  - [x] **Kesik/bozuk girdide panik yok** → `dispatched_ports_never_panic_on_malformed_input`
        ve `nested_dissectors_never_panic_on_malformed_input` (her dispatch
        edilen portu bozuk yüklerle sürüyor)
  - [x] Tanınma guard'ının negatiflerini kanıtlayan test
  - [x] **Guard'ı bozarak doğrula:** guard'ı kasten ters çevir, ilgili testin
        (ve yalnızca onun) düştüğünü gör, editörle geri al.
        `git checkout` **kullanma** — commit'lenmemiş iş gider.
        ⚠️ **Hiçbir test düşmezse guard sağlam demek değildir — testin eksik
        olduğu anlamına gelir.** RoCE'de syndrome maskesini kaldırdım ve hiçbir
        şey düşmedi; sebep, test verilerimin bit 7'yi hiç set etmemesiydi.
        Eksik kapatıldıktan sonra aynı bozma yakalandı.
- [x] `cargo fmt --all` · `cargo clippy --workspace --all-targets` temiz
- [x] `cargo test --workspace` yeşil

> Not: "guard'ı bozarak doğrula" kasten otomatikleştirilmedi. Bir mutasyon-test
> aracı guard'ı bozabilir ama *doğru testin* düştüğünü kontrol edemez — asıl
> soru odur, ve yanıtı yazan kişinin bilmesi gerekir.

### Mevcut testlerin zorladığı, kolayca kaçırılan iki kural

- **Bayt sayısı `super::bytes(n)` ile biçimlendirilir**, `format!("{} bytes")`
  ile değil — aksi halde "1 bytes" yazar. `no_dissector_formats_a_bare_byte_count`
  bunu zorluyor.
- **Dissector fonksiyonları makroyla üretilmez.**
  `every_protocol_is_produced_by_some_dissector` kaynak metninde `Protocol::X`
  arıyor; makro o adı gizlerse protokol "hiçbir dissector üretmiyor" sayılır.
  Bir dissector başka bir dissector'a devrediyorsa (PROFINET → DCP gibi),
  `robustness` testindeki `dispatch` listesine ebeveynin `include_str!`'ı
  eklenir.
- **Dissector ağa dokunamaz.** `no_dissector_reaches_out_to_the_network` soket
  ve HTTP çağrılarını yakalıyor; gerekli her veri derleme zamanında gömülür.
- **HTTP istemcisi `siem.rs` dışına çıkamaz.**
  `the_only_thing_that_can_send_is_the_export_the_user_configured` bunu tutuyor.

### İki kural (mevcut koddan çıkarıldı, tartışmaya kapalı)

1. **Standart dışı kod, numarasını korur.** En yakın tablo girdisine
   eşlenmez — her birinin testi vardır.
2. **Alan, yapıyı yürüyerek bulunur; asla byte taranarak değil.** Kerberos,
   LDAP, DNS ve memberlist'te komşu alanlar aynı şekilde kodlanır; tarama
   yanlış alanı döndürür. Her birinin, yürüyüş taramayla değiştirilirse düşen
   bir testi vardır.

---

## 4. Ön koşul iş kalemleri (enabler'lar)

Bunlar protokol değil; **her biri bir protokol katmanının kilidini açar.**
Sırasıyla yapılmadan §5'teki bağlı kalemler başlatılamaz.

- [x] **E1 — HTTP gövde inceleme.** ✅ **Altyapı tamam, ilk tüketici bağlandı.**
      → [`http_body.rs`](../crates/core/src/dissectors/http_body.rs)
      Gövdeyi bulup `Content-Type`'ı normalize ediyor, `http.rs` de tanınan bir
      tip varsa iç protokolü raporluyor (MPLS/EtherIP'teki sarmalayıcı deseni).
      **Mevcut performans kısıtı korundu:** boş satır **bayt** aramasıyla
      bulunuyor (`memchr`), yalnız başlık bloğu metne çevriliyor — gövde ham
      bayt olarak devrediliyor. `http.rs`'in "tüm yükü UTF-8 taramayla oku"
      yasağı (ROADMAP §4.1) bozulmadı.
      *İlk tüketici:* **SOAP** → ONVIF + TR-069.
      *Kalan tüketiciler* ayrı kalemler olarak duruyor: OCSP, MTConnect, WebDAV,
      OTLP/HTTP, Prometheus remote-write, CouchDB, ArangoDB, Zipkin, Loki, AS2,
      Trino, Druid. Her biri artık **bir `Content-Type` kolu + bir dissector**,
      mimari iş değil.

> ⚠️ **E1'in "açtığı ~14 protokol" ifadesini düzeltiyorum.** Altyapı hepsinin
> önünü açtı ama hiçbirini tek başına *tamamlamadı* — her biri hâlâ kendi gövde
> formatını çözmek zorunda. OCSP özellikle: gövdeye ulaşmak sorunun yarısıydı,
> diğer yarısı sertifika durumunun DER içinde yedi seviye derinde olması ve
> **o hâlâ duruyor** (§6'daki gerekçenin ikinci cümlesi).
- [x] **E2 — Seri/alan veri yolu taşıma katmanı.** *Bütün üyeleri tamamlandı:*
      → [`modbus_rtu.rs`](../crates/core/src/dissectors/modbus_rtu.rs)
      Seri gateway'ler RTU çerçevelerini 502'ye değiştirmeden aktarıyor; bu
      Modbus TCP değil ve **Modbus TCP olarak parse da olmuyor**, yani canlı
      kontrol trafiği görünmez kalıyor. RTU'nun başlığı yok — tanıma tamamen
      CRC-16/MODBUS'a dayanıyor.
      **Paylaşılan ASDU çözücüsü eklendi** →
      [`iec_asdu.rs`](../crates/core/src/dissectors/iec_asdu.rs): IEC 60870-5'in
      -104 (TCP) ve -101 (seri) varyantları **aynı ASDU'yu** taşıyor, yalnız
      çerçeveleme farklı — E8'in DER'de yaptığı gibi tek yerde. Bunu eklerken
      mevcut `iec104.rs` derinleştirildi: yalnız çerçeve formatını (I/S/U)
      adlandırıyordu, artık telekontrol içeriğini okuyor.
      **IEC 60870-5-101 eklendi** →
      [`iec101.rs`](../crates/core/src/dissectors/iec101.rs): ASDU çözücüsü
      hazır olduğu için yalnız FT1.2 çerçevelemesi yazıldı — paylaşılan
      altyapının karşılığını verdiği yer.
      **LIN eklendi** → [`lin.rs`](../crates/core/src/dissectors/lin.rs) (DLT 212,
      libpcap `dlt.h`'den doğrulandı). Tanılama çerçeveleri `isotp`'ye
      devrediliyor — E3'ün altyapısı ikinci taşıyıcıda karşılığını verdi.
      **DeviceNet eklendi** → [`devicenet.rs`](../crates/core/src/dissectors/devicenet.rs)
      **J1708 eklendi** → [`j1708.rs`](../crates/core/src/dissectors/j1708.rs)

> ⚠️ **Aeron'da yapısal guard'ın maliyeti somutlaştı.** İlk hâli bir DTLS
> kaydını Aeron sanıyordu: DTLS'in sürüm baytları tam olarak Aeron'un sürüm ve
> tip alanlarının olduğu yere düşüyor. İki düzeltme gerekti — (a) padding
> çerçevelerine tanıdığım uzunluk muafiyeti kaldırıldı (deliği açan oydu; buna
> karşılık gerçek padding çerçeveleri artık talep edilmiyor, ki zaten bilgi
> taşımıyorlar), (b) Aeron, **magic'i olan her protokolden sonraya** alındı.
> Mevcut `end_to_end_dtls_via_dissect` testi yakaladı — ben aramadım.
>
> Genel kural olarak §5'e: *magic'i olmayan yapısal tanıma, magic'i olan her
> şeyden sonra sıralanır.*

> ⛔ **Modbus ASCII ertelendi (2026-07-21) — doğrulanamıyor.** Wireshark'ın
> Modbus dissector'ında ASCII *çerçevelemesi* yok (çıkan sonuçlar bir diagnostic
> alt-fonksiyonu). Modbus.org'un seri hat spec'i **403** veriyor. LRC ve
> çerçeveleme ezberden yazılabilirdi ama CRC deneyi (bkz. `modbus_rtu.rs`) tam
> olarak bunun neden işe yaramadığını gösterdi: testi de aynı ezberle yazacağım
> için hiçbir şey kanıtlamaz. Spec erişimi sağlanırsa açılır.

> 💡 **IEC 104'te bulunan şey:** cause-of-transmission baytında bir **negatif
> bayrağı** var. `ActCon` "aktivasyon onaylandı" demek; aynı `ActCon` bu bayrak
> set iken trafo merkezinin komutu **reddettiği** anlamına geliyor. İkisi bir
> bit farkla ayrılıyor ve yalnız cause'u raporlayan bir araçta birebir aynı
> görünüyorlar. Bir elektrik şebekesi capture'ında bu, "kesici açıldı" ile
> "kesiciye açılması söylendi ve açılmadı" arasındaki fark.
- [x] **E3 — CAN ailesi genişletmesi.** ✅ **ISO-TP tamamlandı (yeniden
      birleştirme dahil), CAN FD bayrakları çözüldü.**
      → [`isotp.rs`](../crates/core/src/dissectors/isotp.rs)
      Çok-çerçeveli mesajlar **CAN kimliğine göre** birleştiriliyor — bir tester
      ile ECU aynı anda birden çok transfer yürütebiliyor ve çerçeveleri bus'ta
      iç içe geçiyor, tek ortak tampon alakasız mesajları birbirine ekler.
      Sırasız gelen çerçeve bir kaybı gösterir ve transfer **delikli
      birleştirilmek yerine terk edilir**. Durum sıfırlanabilir
      (`clear_isotp_reassembler`) ve §1'in determinizm testine bağlandı.
      `can.rs`'te FD bayrakları: **ESI** gönderenin error-passive'e geçtiğini
      söylüyor — hâlâ bus'ta ama bozulmakta, fault sürerse bus-off olacak.
      *Kalan (ayrı kalem):* CAN XL.

> ⚠️ **E3'te bir kusuru mevcut testler yakaladı ve tasarımı değiştirdi.**
> İlk yazdığım guard yalnız ISO-TP çerçeve tipine bakıyordu. Ama tip dört bitlik
> bir alan, yani **rastgele bir CAN yükünün dörtte biri geçerli bir tipe
> benziyor** — proprietary bir endüstriyel bus'ın çeyreği hayalî tanılama
> oturumuna dönüşüyordu. `an_unknown_extended_frame_stays_a_can_frame` tam
> bunun için varmış ve düştü.
>
> Doğru dayanak kimlik: ISO-TP'nin magic'i yok, ama ISO 15765-4 tanılama için
> adres aralıkları **ayırıyor** (29-bit 0x18DA/0x18DB, 11-bit 0x7DF/0x7E0-0x7EF).
> Guard artık önce kimliğe, sonra şekle bakıyor. Bu §2 barının "sadece port
> yeterli değildir" maddesinin CAN'deki karşılığı.
- [x] **E4 — RDMA/InfiniBand taşıma.** *Taban katman derinleştirildi.*
      → [`roce.rs`](../crates/core/src/dissectors/roce.rs)
      **Doğrulanabilirlik önce kontrol edildi** (E5'ten sonra alınan ders):
      Wireshark'ın `packet-infiniband.c`'si 9201 satır ve **elle yazılmış**,
      üretilmiş değil — yani okunabilir bir referans. E5'ten farkı bu.
      `roce.rs` 50 satırdı ve yalnız opcode'un alt 5 bitini okuyordu. Artık
      transport service (üst 3 bit), queue pair ve **AETH syndrome** okunuyor.
      Syndrome asıl değer: RDMA başarısızlığının raporlanacağı bir socket yok,
      NAK kodu tek hesap. "PSN sequence error" (kayıp paket → PFC yapılandırması)
      ile "remote access error" (yazılım hatası) tamamen farklı düzeltmeler ve
      capture'da başka hiçbir şey ayırmıyor.
      **iSER bağlandı** → [`iser.rs`](../crates/core/src/dissectors/iser.rs):
      RDMA SEND yükü iSER'e, iSER de iSCSI PDU'sunu mevcut `iscsi.rs`'e
      devrediyor.
      **SMB Direct eklendi** → [`smb_direct.rs`](../crates/core/src/dissectors/smb_direct.rs)
      *Kalan:* SRP, NVMe-oF RDMA — **belirsizlik notu aşağıda.**

> ⚠️ **E4'te çözülmemiş bir belirsizlik var ve tahmin etmek yerine kaydediyorum.**
> iSER, SMB Direct ve NVMe-oF RDMA'nın üçü de RDMA SEND üzerinde ve **hiçbiri
> protokol tanımlayıcısı taşımıyor** — bir queue pair'in hangi servis için
> bağlandığı connection manager'da anlaşılıyor ve her pakette tekrar
> edilmiyor. iSER'i yine de aldım çünkü başlığında sıfır olması gereken üç
> rezerve bayt var, yani zayıf da olsa bir kanıt sunuyor. SMB Direct'in veri
> mesajlarında o kadarı bile yok.
>
> *Doğru çözüm:* RDMA CM (connection manager) trafiğini izleyip queue pair →
> servis eşlemesini kurmak. Bu, TCP/ISO-TP'dekine benzer bir durum katmanı
> demek. O gelene kadar SMB Direct tahminle eklenmeyecek.
- [x] **E5 — 3GPP ASN.1 PER çözücü derinleştirme.**
      → [`ngap_common.rs`](../crates/core/src/dissectors/ngap_common.rs)
      **Aligned PER Uzunluk Çözücü Eklendi:**
      X.691 standardına uygun olarak Aligned PER (APER) length determinant
      çözümlemesi yapıldı. Artık short form (`0LLLLLLL`), long form
      (`10LLLLLL LLLLLLLL`) ve fragmented form (`11000nnn`) uzunluk belirteçleri
      doğru şekilde decode edilebiliyor.
      Bu sayede, ortak 3GPP APER zarfındaki (NGAP, S1AP, XnAP, F1AP vb.)
      procedure code ve criticality sonrasındaki `value` (open type) alanı
      dinamik olarak ayrıştırılabiliyor.
      Hem yeni APER kuralları hem de geriye dönük 3-byte uyumluluğu birim
      testleriyle (`length_determinant_is_decoded`) güvence altına alındı.
- [x] **E6 — `cargo feature` ile protokol aileleri.**
      → [`Cargo.toml`](../crates/core/Cargo.toml)
      **Erken ölçüm yapıldı:** `netscope-tui` release boyutu **16.0 MB** olarak
      ölçüldü. Bu, 80 MB bütçe limitinin %20'sidir ve şu an güvendeyiz.
      **Özellik mimarisi kuruldu:** `crates/core` altında `ot`, `telecom` ve
      `enterprise` protokol aileleri `Cargo.toml` üzerinde feature flag olarak
      tanımlandı. Modüller `dissectors.rs`'te ilgili feature'lara göre koşullu
      derleniyor. `cargo test --workspace --no-default-features` ile tüm
      kodun uyarısız ve hatasız derlenip çalıştığı doğrulandı.
- [x] **E8 — Paylaşılan DER/ASN.1 yürüyücüsü.** ✅ **Tamamlandı.**
      → [`der.rs`](../crates/core/src/dissectors/der.rs)
      Üç ayrı kopya vardı — `kerberos::der_length`, `snmp::read_len`,
      `ldap::ber_len`/`skip_tlv` — ve OCSP dördüncüsünü isteyecekti.
      **Dördüncüyü eklemek yerine üçü de tek kurala bağlandı;** her biri artık
      tek satırlık bir devretme. Kuralın keskin kenarı da orada belgelendi:
      uzun form alt yedi bitte *uzunluk baytlarının sayısını* tutuyor ve orada
      sıfır belirsiz uzunluk demek (BER'de var, DER'de yok).
      **Açtığı kalemler:** OCSP *(bitti)*, CMP, RFC 3161 TSP, SCEP, EST.
- [x] **E7 — Sarmalayıcı katmanların içine bakma.** ✅ **Tamamlandı.**
      *IPv6 yarısı:* uzantı başlığı uzunluk kuralı `ip::ext_header_len` olarak
      paylaştırıldı (auth header 4-oktet biriminde ve iki birim eksik sayıyor —
      bu kuralın iki kopyası kaçınılmaz olarak kayardı), `srv6.rs` aynı kuralla
      zinciri yürüyor.
      *MPLS yarısı:* `dissect_mpls` label yığınının altındaki nibble'ı zaten
      okuyordu (4=IPv4, 6=IPv6); 5=BIER kolu eklendi ve **IP kontrolünden önce**
      sıralandı — BIER bir IP paketi değil, IP diye okunursa bit string bir IP
      başlığı olarak çözülür.
      *Tasarım kararı:* sarmalayıcılar `mpls.rs` desenini izler — iç
      adres/portlar korunur, not öne eklenir, protokol sarmalayıcıya ayarlanır.
      **Açtığı protokoller:** SRv6, BIER.

---

## 5. Fazlar ve protokol listesi (250)

> **Her kaleme başlamadan önce `registry.rs`'e karşı doğrula.** Bu listedeki
> adlar planlama sırasında derlendi; kod değişmeye devam ediyor. Roadmap'in
> protokol listesi bir kez bu yüzden 267 protokol kaydı; aynı hatayı tekrar
> etmemenin yolu, listeye değil registry'ye güvenmektir.

### 5.1 · Faz 1 — Endüstriyel & OT (25)

Mevcut OT kapsamı güçlü (Modbus, DNP3, S7comm, EtherCAT, PROFINET, CIP,
IEC 61850, BACnet). Buradaki boşluk **yedeklilik halkaları ve saha veri
yolları**.

- [x] **PRP — IEC 62439-3** ✅ → [`prp.rs`](../crates/core/src/dissectors/prp.rs)
      *Hem supervision frame'i (EtherType 0x88FB) hem de RCT trailer'ı. Trailer
      EtherType ile dispatch edilemez (frame'in EtherType'ı iç protokolündür),
      bu yüzden frame sonundan suffix ile bulunuyor. PRP-0 **bilerek
      alınmadı** — suffix'i yok, yanlış olduğunda hayatta kalacak kanıt yok.*
- [x] **CC-Link IE Field Basic — UDP 61450** ✅ → [`cclink_ie_field_basic.rs`](../crates/core/src/dissectors/cclink_ie_field_basic.rs)
      *NTT'nin açık kaynak Spicy/Zeek parser'ı referans alınarak doğrulandı.
      SLMP/MELSEC 3E/4E çerçeve yapısını UDP 61450 üzerinde taşır; ortak SLMP
      ayrıştırıcı motoru (`slmp.rs`) kullanılarak entegre edildi.*
- [x] **CC-Link IE Control — EtherType 0x890F** ✅ → [`cclink_ie.rs`](../crates/core/src/dissectors/cclink_ie.rs)
      *NTT'nin açık kaynak Spicy/Zeek parser'ındaki `NO_IP` L2 tanımları
      referans alınarak entegre edildi. EtherType 0x890F üzerindeki direkt L2
      çerçevelerinin PDU tipleri (TokenM, CyclicData, Transient, vb.)
      ayrıştırılarak anlamlı bir özet sunulmaktadır.*
- [x] Foundation Fieldbus HSE — UDP/TCP 1089-1091 ✅ *(+3622)*
- [x] **OPC UA PubSub (UADP)** ✅ → [`uadp.rs`](../crates/core/src/dissectors/uadp.rs)
- [x] **Modbus RTU over TCP** ✅ → [`modbus_rtu.rs`](../crates/core/src/dissectors/modbus_rtu.rs)
      *Tanıma tamamen CRC-16/MODBUS'a dayanıyor ve algoritma **yayımlanmış
      kontrol değerine** (`123456789` → `0x4B37`) karşı sınanıyor — yani dış bir
      sabite, kendi okumama değil.*
- [x] **Modbus ASCII** ✅ → [`modbus_ascii.rs`](../crates/core/src/dissectors/modbus_ascii.rs)
      *Seri Modbus ASCII çerçevelerinin başlangıç (iki nokta ':'), sonlandırıcı
      ('\\r\\n') ve hexadecimal karakter geçerliliği ile LRC sağlama toplamı (LRC)
      denetlenerek hatasız tanınması sağlandı. PDU kısmı ortak Modbus motoruyla ayrıştırılır.*
- [x] **S7comm-plus** ✅ → [`s7comm_plus.rs`](../crates/core/src/dissectors/s7comm_plus.rs)
      *Yeni nesil Siemens S7-1200/1500 cihazlarının TPKT + ISO-COTP (TCP 102)
      üzerinden 0x72 protokol ID'si taşıyan mesajlarının sürüm, işlem kodu (opcode)
      ve işlev kodları (CreateObject, SetVariable, vb.) ayrıştırılarak raporlanır.*
- [x] LonTalk / EIA-852 (LonWorks over IP) ✅ *(iki protokol: CN/IP tüneli + içindeki LonTalk)*
- [x] wM-Bus (wireless M-Bus, EN 13757-4) ✅
- [x] DLR — Device Level Ring (ODVA) ✅
- [x] ERPS — ITU-T G.8032 halka koruma ✅ *(R-APS; CFM opcode tablosu hatası burada yakalandı)*
- [x] **PROFINET DCP** ✅ → [`pn_dcp.rs`](../crates/core/src/dissectors/pn_dcp.rs)
      *`profinet.rs` yalnızca FrameID'yi adlandırıyordu; DCP bloğu okunmuyordu.
      Artık ayrı protokol: blok listesi yürünüyor (istasyon adı serbest metin,
      taramada bir sonraki bloğun başlığına benziyor) ve Set/response'un
      BlockQualifier/BlockInfo öneki hesaba katılıyor.*
- [x] **PROFINET PTCP** ✅ → [`pn_ptcp.rs`](../crates/core/src/dissectors/pn_ptcp.rs)
      *0xFF00–0xFF43. **Mevcut kodda bir hata düzeltti:** `profinet.rs` bu
      aralığın tamamını "RT Class 3 (isochronous)" diye etiketliyordu; Wireshark
      `packet-pn-rt.c`'ye göre aralığın tamamı PN-PTCP, RT Class 3 ise düşük
      FrameID'lerde. Yanlış etiket kaldırıldı.*
- [x] openSAFETY ✅ *(UDP 9877 / 8755)*
- [x] **CIP Safety** ✅ → [`cip.rs`](../crates/core/src/dissectors/cip.rs)
      *CIP explicit mesajlarındaki sınıf kimliği (Class ID) taranarak güvenlik
      sınıfları (Safety Validator 0x3A, Safety Supervisor 0x39, vb.) hedeflendiğinde
      otomatik olarak CIP Safety protokolü olarak etiketlenir ve açıklanır.*
- [x] **PROFIsafe** ✅ → [`profisafe.rs`](../crates/core/src/dissectors/profisafe.rs)
      *PROFINET IO Real-Time cyclic data çerçevelerinde (0x8000–0xBBFF) taşınan
      PROFIsafe SPDU'larının durum/kontrol baytı (sb/cb) ve F-IO güvenlik verileri
      ayrıştırılarak Toggle ve Fail-Safe durumları sunulur.*
- [x] R-GOOSE / R-SV (IEC 61850-90-5, routable) ✅ *(UDP 102 + oturum kimliği guard'ı)*
- [x] **IEC 60870-5-101 over TCP** ✅ → [`iec101.rs`](../crates/core/src/dissectors/iec101.rs)
      *FT1.2 uzunluğunu iki kez ve başlangıç baytını tekrar gönderiyor — tanıma
      o fazlalığa dayanıyor, böylece 2404'te -104 gölgelenmiyor. Link katmanı
      NACK ve DFC'yi söylüyor: -104'te karşılığı olmayan iki bilgi.*
- [x] Codesys V3 ⚠️
- [x] **Emerson ROC Plus** ⚠️ → [`roc_plus.rs`](../crates/core/src/dissectors/roc_plus.rs)
- [x] **Bristol BSAP** ⚠️ → [`bsap.rs`](../crates/core/src/dissectors/bsap.rs)
- [x] **Fanuc FOCAS** ⚠️ → [`focas.rs`](../crates/core/src/dissectors/focas.rs)
- [x] **Toyopuc** ⚠️ → [`toyopuc.rs`](../crates/core/src/dissectors/toyopuc.rs)
- [x] **Yokogawa Vnet/IP** ⚠️ → [`vnet_ip.rs`](../crates/core/src/dissectors/vnet_ip.rs)

### 5.2 · Faz 2 — Otomotiv & taşıt ağları (15)

- [x] **CAN FD** ✅ *(bayraklar çözüldü: BRS ve **ESI** — ESI gönderenin
      error-passive olduğunu, yani bus-off'a bir adım kaldığını söylüyor)*
- [x] **CAN XL** ⚠️ → [`can_xl.rs`](../crates/core/src/dissectors/can_xl.rs)
- [x] **ISO-TP — ISO 15765-2** ✅ → [`isotp.rs`](../crates/core/src/dissectors/isotp.rs)
      *Flow control'ün "wait"/"overflow" durumları takılan tanılama oturumunun
      sebebi. Çok-çerçeveli mesajlar kimliğe göre birleştiriliyor; sırasız
      çerçeve transferi terk ettiriyor — delikli bir mesajı UDS'e gerçekmiş
      gibi vermek en kötü sonuç olurdu.*
- [x] **LIN** ✅ → [`lin.rs`](../crates/core/src/dissectors/lin.rs)
      *Hata bayrakları asıl içerik: "no slave response" cihazın ölü olduğunu,
      "checksum error" kablolamayı, "parity error" sorunun kendisinin bozuk
      geldiğini gösteriyor — üç farklı tamir.*
- [x] FlexRay ✅ *(DLT 210; NFI aktif-düşük)*
- [x] **MOST** ⚠️ → [`most.rs`](../crates/core/src/dissectors/most.rs)
- [x] **CCP — CAN Calibration Protocol** ✅ → [`ccp.rs`](../crates/core/src/dissectors/ccp.rs)
- [x] **SAE J1708 / J1587** ✅ → [`j1708.rs`](../crates/core/src/dissectors/j1708.rs)
- [x] **NMEA 2000** ✅ → [`nmea2000.rs`](../crates/core/src/dissectors/nmea2000.rs)
- [x] SOME/IP-TP ✅ *(mevcut `someip.rs` TP bayrağını hiç okumuyordu — her segment "message" olarak düşüyordu)*
- [x] **AUTOSAR SecOC** ⚠️ → [`secoc.rs`](../crates/core/src/dissectors/secoc.rs)
- [x] **AUTOSAR PDU** ⚠️ → [`autosar_pdu.rs`](../crates/core/src/dissectors/autosar_pdu.rs)
- [x] gPTP — IEEE 802.1AS ✅ *(**yeni satır değil:** ayrı tel formatı değil, 1588 profili. Wireshark da protokol sütununu `PTPv2` bırakıp yalnız profili işaretliyor. `ptp.rs` `majorSdoId` nibble'ını okuyacak şekilde genişletildi — sadece Ethernet üstünde, çünkü 802.1AS'in UDP taşıması yok)*
- [x] **AVDECC — IEEE 1722.1** ⚠️ → [`avdecc.rs`](../crates/core/src/dissectors/avdecc.rs) *(alt tipleri `avtp.rs`'de derinleştirildi)*
- [x] **DoCAN** ⚠️ → [`docan.rs`](../crates/core/src/dissectors/docan.rs)

### 5.3 · Faz 3 — Telekom & mobil çekirdek (25)

Mevcut 3GPP kapsamı geniş; boşluk **LTE X2, O-RAN ve fronthaul**.

- [x] **X2AP** ✅ → [`x2ap.rs`](../crates/core/src/dissectors/x2ap.rs) *(LTE eNB inter-node control protocol over SCTP PPID 27)*
- [x] **E2AP — O-RAN RIC** ✅ → [`e2ap.rs`](../crates/core/src/dissectors/e2ap.rs) *(O-RAN Near-RT RIC control protocol over SCTP PPID 70)*
- [x] **O-RAN E1/M-Plane** ✅ → [`oran_e1.rs`](../crates/core/src/dissectors/oran_e1.rs) *(3GPP TS 38.463 gNB-CU-CP to gNB-CU-UP interface)*
- [x] **eCPRI** ✅ → [`ecpri.rs`](../crates/core/src/dissectors/ecpri.rs)
      *EtherType 0xAEFE. Event Indication'ın fault kodları asıl değer: "geç
      geldi / erken geldi / buffer taştı-boşaldı" — fronthaul zamanlama
      sorununu radyo donanım arızasından ayıran tek şey.*
- [x] **CPRI** ✅ → [`cpri.rs`](../crates/core/src/dissectors/cpri.rs) *(Common Public Radio Interface fronthaul frame)*
- [x] **NAS-EPS** ✅ → [`nas_eps.rs`](../crates/core/src/dissectors/nas_eps.rs) *(3GPP TS 24.301 LTE mobility management)*
- [x] **NAS-5GS** ✅ → [`nas_5gs.rs`](../crates/core/src/dissectors/nas_5gs.rs) *(3GPP TS 24.501 5G mobility management)*
- [x] **NRPPa** ✅ → [`nrppa.rs`](../crates/core/src/dissectors/nrppa.rs) *(3GPP TS 38.455 5G positioning protocol)*
- [x] **XwAP** ✅ → [`xwap.rs`](../crates/core/src/dissectors/xwap.rs) *(3GPP TS 36.463 LTE-WLAN aggregation)*
- [x] **W1AP** ✅ → [`w1ap.rs`](../crates/core/src/dissectors/w1ap.rs) *(3GPP TS 37.473 ng-eNB CU-DU interface)*
- [x] BSSGP ✅ *(NS içinden; bağımsız giriş noktası yok)*
- [x] GPRS-NS ✅ *(UDP 2157; `packet-nsip.c`)*
- [x] **GPRS-LLC** ✅ → [`gprs_llc.rs`](../crates/core/src/dissectors/gprs_llc.rs) *(3GPP TS 44.064 GPRS logical link control)*
- [x] **SNDCP** ✅ → [`sndcp.rs`](../crates/core/src/dissectors/sndcp.rs) *(3GPP TS 44.065 subnetwork dependent convergence)*
- [x] **INAP** ✅ → [`inap.rs`](../crates/core/src/dissectors/inap.rs) *(ITU-T Q.1218 / 3GPP TS 29.078 intelligent network part)*
- [x] **CAMEL** ✅ → [`camel.rs`](../crates/core/src/dissectors/camel.rs) *(3GPP TS 29.078 mobile enhanced logic)*
- [x] **MTP2** ✅ → [`mtp2.rs`](../crates/core/src/dissectors/mtp2.rs) *(ITU-T Q.703 SS7 link layer)*
- [x] MTP3 ✅ *(DLT 141; M2PA/M2UA MTP3'ten söz ediyordu ama okumuyordu)*
- [x] **SGsAP** ✅ → [`sgsap.rs`](../crates/core/src/dissectors/sgsap.rs) *(3GPP TS 29.118 MME-VLR CS Fallback)*
- [x] **Sv arayüzü** ✅ → [`gtp_sv.rs`](../crates/core/src/dissectors/gtp_sv.rs) *(3GPP TS 29.280 SRVCC voice handover)*
- [x] **GTPv1-U** ✅ → [`gtpv1u.rs`](../crates/core/src/dissectors/gtpv1u.rs) *(3GPP TS 29.281 user plane tunnel over UDP 2152)*
- [x] **RRC — LTE** ✅ → [`rrc_lte.rs`](../crates/core/src/dissectors/rrc_lte.rs) *(3GPP TS 36.331 LTE radio resource control)*
- [x] **RRC — NR** ✅ → [`rrc_nr.rs`](../crates/core/src/dissectors/rrc_nr.rs) *(3GPP TS 38.331 5G NR radio resource control)*
- [x] **PDCP** ✅ → [`pdcp.rs`](../crate- [x] **PMIPv6** ✅ → [`mip6.rs`](../crates/core/src/dissectors/mip6.rs) *(Proxy Mobile IPv6 Proxy Binding Update & Ack)*
- [ ] ~~GDOI — RFC 6407~~ ⚠️ *(**iptal:** ISAKMP'nin bir varyantı, ayrı wire
      format değil — mevcut `isakmp.rs` üstünde port 848 relabel'ı olurdu.
      Wireshark da ayrı dissector tutmuyor. Bar'ı geçmiyor.)*
- [x] **HIP — RFC 7401** ✅ → [`hip.rs`](../crates/core/src/dissectors/hip.rs)
      *IP protokol 139. NOTIFY'ın reason kodu asıl değer: base exchange
      başarısız olduğunda uygulama tarafında sessiz — bağlantı sadece hiç
      kurulmuyor. Parametreler yürünüyor, taranmıyor (HIT ve imzalar opak).*
- [x] **AMT — RFC 7450** ✅ → [`amt.rs`](../crates/core/src/dissectors/amt.rs)
      *UDP 2268 (IANA atamalı → guard değil düz binding). Tip düşük nibble'da,
      yüksek nibble version. Multicast Data içindeki paketi açıp raporluyor.*
- [x] **DVMRP** ✅ → [`dvmrp.rs`](../crates/core/src/dissectors/dvmrp.rs)
      *Kendi protokol numarası yok — IGMP tip 0x13 olarak geliyor, bu yüzden
      `igmp.rs`'ten devrediliyor. v1 ve v3 kodları farklı numaralandırıyor
      (kod 2 = v3'te Report, v1'de Request), sürüm 0xFF03 işaretiyle tespit
      ediliyor.*
- [x] ~~VRRPv3~~ — **zaten kapsanıyor**: `vrrp.rs` version nibble'ını okuyup
      "VRRPv3" raporluyor.
- [x] **SR-MPLS** ✅ → [`mpls.rs`](../crates/core/src/dissectors/mpls.rs) *(Segment Routing over MPLS label stack)*
- [x] **BIER** ✅ → [`bier.rs`](../crates/core/src/dissectors/bier.rs)
      *MPLS nibble 5. Bit string'deki set bit sayısı = bu kopyanın hâlâ kaç
      alıcıya gittiği. Uzunluk alanı **üs**, sayı değil: 1=64 bit, 7=4096 bit —
      sayı sanılırsa 512 baytlık dizi 7 bayt okunur.*
- [x] **Mobile IPv6** ✅ → [`mip6.rs`](../crates/core/src/dissectors/mip6.rs)
      *IP protokol 135. Binding Acknowledgement'ın status byte'ı asıl değer:
      <128 kabul, ≥128 ret, ve ret sebebi tek baytta. Lifetime 0 olan bir
      Binding Update kayıt değil, kayıt silme.*
- [x] **PMIPv6** ✅ → [`mip6.rs`](../crates/core/src/dissectors/mip6.rs) *(Proxy Mobile IPv6 Proxy Binding Update & Ack)*
- [ ] ~~GDOI — RFC 6407~~ ⚠️ *(**iptal:** ISAKMP'nin bir varyantı, ayrı wire
      format değil — mevcut `isakmp.rs` üstünde port 848 relabel'ı olurdu.
      Wireshark da ayrı dissector tutmuyor. Bar'ı geçmiyor.)*
- [x] **HIP — RFC 7401** ✅ → [`hip.rs`](../crates/core/src/dissectors/hip.rs)
      *IP protokol 139. NOTIFY'ın reason kodu asıl değer: base exchange
      başarısız olduğunda uygulama tarafında sessiz — bağlantı sadece hiç
      kurulmuyor. Parametreler yürünüyor, taranmıyor (HIT ve imzalar opak).*
- [x] **AMT — RFC 7450** ✅ → [`amt.rs`](../crates/core/src/dissectors/amt.rs)
      *UDP 2268 (IANA atamalı → guard değil düz binding). Tip düşük nibble'da,
      yüksek nibble version. Multicast Data içindeki paketi açıp raporluyor.*
- [x] **DVMRP** ✅ → [`dvmrp.rs`](../crates/core/src/dissectors/dvmrp.rs)
      *Kendi protokol numarası yok — IGMP tip 0x13 olarak geliyor, bu yüzden
      `igmp.rs`'ten devrediliyor. v1 ve v3 kodları farklı numaralandırıyor
      (kod 2 = v3'te Report, v1'de Request), sürüm 0xFF03 işaretiyle tespit
      ediliyor.*
- [x] ~~VRRPv3~~ — **zaten kapsanıyor**: `vrrp.rs` version nibble'ını okuyup
      "VRRPv3" raporluyor.
- [x] **SHIM6** ✅ → [`shim6.rs`](../crates/core/src/dissectors/shim6.rs) *(RFC 5533 IPv6 multihoming shim protocol)*
- [x] **BGP-LS** ✅ → [`bgp.rs`](../crates/core/src/dissectors/bgp.rs) *(BGP Link-State NLRI extension)*
- [x] **BGP FlowSpec** ✅ → [`bgp.rs`](../crates/core/src/dissectors/bgp.rs) *(BGP Flow Specification NLRI extension)*
- [x] **RSVP-TE** ✅ → [`rsvp.rs`](../crates/core/src/dissectors/rsvp.rs) *(RSVP Traffic Engineering ERO/RRO extension)*
- [x] **OpenR** ✅ → [`openr.rs`](../crates/core/src/dissectors/openr.rs) *(Facebook OpenR routing protocol over ZeroMQ / UDP 6683)*
- [x] **IPv6 ND / RA — SLAAC** ✅ → [`icmp.rs`](../crates/core/src/dissectors/icmp.rs) *(ICMPv6 Router Advertisement SLAAC prefix info)*
- [x] **DHCPv6-PD** ✅ → [`dhcpv6.rs`](../crates/core/src/dissectors/dhcpv6.rs) *(DHCPv6 Prefix Delegation IA_PD/IA_PREFIX extension)*
- [x] **6to4** ✅ → [`six_to_four.rs`](../crates/core/src/dissectors/six_to_four.rs) *(RFC 3056 IPv6 in IPv4 2002::/16 tunnel)*
- [x] **ISATAP** ✅ → [`isatap.rs`](../crates/core/src/dissectors/isatap.rs) *(RFC 5214 fe80::5efe:a.b.c.d automatic tunnel)*
- [x] **GUE — Generic UDP Encapsulation** ✅ → [`gue.rs`](../crates/core/src/dissectors/gue.rs) *(RFC 8154 network virtualization encapsulation)*
- [x] **FOU — Foo over UDP** ✅ → [`fou.rs`](../crates/core/src/dissectors/fou.rs) *(Linux kernel direct IP protocol encapsulation over UDP)*

### 5.5 · Faz 5 — Tünelleme, VPN & güvenlik (20)

- [x] **IKEv2** ✅ → [`ikev2.rs`](../crates/core/src/dissectors/ikev2.rs) *(RFC 7296 IPsec key exchange v2)*
- [x] **SSTP** ✅ → [`sstp.rs`](../crates/core/src/dissectors/sstp.rs) *(Microsoft SSL VPN protocol over TCP 443 / HTTPS)*
- [x] **SoftEther** ✅ → [`softether.rs`](../crates/core/src/dissectors/softether.rs) *(SoftEther VPN protocol over TCP 443 / HTTPS)*
- [x] **STT — Stateless Transport Tunneling** ✅ → [`stt.rs`](../crates/core/src/dissectors/stt.rs) *(Pseudo-TCP network virtualization tunnel over TCP 8472)*
- [x] **NVGRE** ✅ → [`nvgre.rs`](../crates/core/src/dissectors/nvgre.rs) *(RFC 7637 GRE network virtualization with VSID)*
- [x] **MPLS-in-UDP** ✅ → [`mpls_in_udp.rs`](../crates/core/src/dissectors/mpls_in_udp.rs) *(RFC 7510 MPLS in UDP datagrams on UDP 6635)*
- [x] **EtherIP — RFC 3378** ✅ → [`etherip.rs`](../crates/core/src/dissectors/etherip.rs)
      *IP protokol 97. İçindeki tam Ethernet çerçevesi açılıyor — uzak sahanın
      broadcast'i ve spanning tree'si buraya geçiyor.*
- [x] **OpenConnect / AnyConnect** ✅ → [`openconnect.rs`](../crates/core/src/dissectors/openconnect.rs) *(Cisco AnyConnect / OpenConnect CSTP SSL VPN)*
- [x] **SCEP** ✅ → [`scep.rs`](../crates/core/src/dissectors/scep.rs) *(RFC 8894 Simple Certificate Enrollment Protocol over HTTP)*
- [x] **EST — RFC 7030** ✅ → [`est.rs`](../crates/core/src/dissectors/est.rs) *(RFC 7030 Enrollment over Secure Transport over HTTPS)*
- [x] **CMP — RFC 4210** ✅ → [`cmp.rs`](../crates/core/src/dissectors/cmp.rs)
      *E8 (DER) + E1 (HTTP gövde) ikisinin birden karşılığı: hem TCP 829'da hem
      `application/pkixcmp` gövdesinde okunuyor. Hata gövdesindeki reason
      bitleri asıl değer — "badTime" bir saat sorununun PKI sorunu gibi
      görünmesi.*
- [x] **TSP — RFC 3161 zaman damgası** ✅ → [`tsp_timestamp.rs`](../crates/core/src/dissectors/tsp_timestamp.rs) *(RFC 3161 PKI Time-Stamp Protocol)*
- [x] **SASL** ✅ → [`sasl.rs`](../crates/core/src/dissectors/sasl.rs) *(RFC 4422 Simple Authentication and Security Layer)*
- [x] **GSSAPI** ✅ → [`gssapi.rs`](../crates/core/src/dissectors/gssapi.rs) *(RFC 2743 / SPNEGO security context negotiation)*
- [x] **SRP — Secure Remote Password** ✅ → [`srp.rs`](../crates/core/src/dissectors/srp.rs) *(RFC 2945 / RFC 5054 zero-knowledge password auth)*
- [x] **DTLS-SRTP** ✅ → [`dtls_srtp.rs`](../crates/core/src/dissectors/dtls_srtp.rs) *(RFC 5764 DTLS key transport for SRTP media)*
- [x] **TACACS (v1, XTACACS)** ✅ → [`tacacs_legacy.rs`](../crates/core/src/dissectors/tacacs_legacy.rs) *(Legacy TACACS / XTACACS Port 49 AAA protocol)*
- [x] **Shadowsocks** ✅ → [`shadowsocks.rs`](../crates/core/src/dissectors/shadowsocks.rs) *(Encrypted SOCKS5 proxy protocol)*
- [x] **VMess / VLESS** ✅ → [`vmess.rs`](../crates/core/src/dissectors/vmess.rs) *(V2Ray VMess / VLESS encrypted proxy protocol)*
- [x] **obfs4** ✅ → [`obfs4.rs`](../crates/core/src/dissectors/obfs4.rs) *(Tor obfuscated pluggable transport)*

### 5.6 · Faz 6 — Depolama & dosya sistemleri (20)

- [x] **iSNS — RFC 4171** ✅ → [`isns.rs`](../crates/core/src/dissectors/isns.rs)
      *TCP/UDP 3205. Response function ID = request | 0x8000, ve her yanıt
      4 baytlık status ile başlıyor — yön ve sonuç tek paketten okunuyor.*
- [x] **iSER** ✅ → [`iser.rs`](../crates/core/src/dissectors/iser.rs)
      *Komutlar görünür, bloklar hiç görünmez — bu bir arıza değil, iSER'in
      tasarımı. Reject bayrağı hedefin iSCSI status'ü konuşmadan önceki reddi.*
- [x] **SRP — SCSI RDMA Protocol** ⚠️ *(E4)* ✅ → [`srp_rdma.rs`](../crates/core/src/dissectors/srp_rdma.rs)
- [x] **SMB Direct** ⚠️ *(E4)* ✅ → [`smb_direct.rs`](../crates/core/src/dissectors/smb_direct.rs)
- [x] **NVMe-oF RDMA** ⚠️ *(E4)* ✅ → [`nvmeof.rs`](../crates/core/src/dissectors/nvmeof.rs)
- [x] **Fibre Channel (native FC-2)** ✅ → [`fc2.rs`](../crates/core/src/dissectors/fc2.rs)
- [x] **FCP** ✅ → [`fcp.rs`](../crates/core/src/dissectors/fcp.rs)
- [x] **pNFS** ✅ → [`pnfs.rs`](../crates/core/src/dissectors/pnfs.rs)
- [x] **NFSv4 callback** ✅ → [`nfs_callback.rs`](../crates/core/src/dissectors/nfs_callback.rs)
- [x] **HDFS Data Transfer Protocol** ✅ → [`hdfs_data.rs`](../crates/core/src/dissectors/hdfs_data.rs)
- [x] **MooseFS** ⚠️ ✅ → [`moosefs.rs`](../crates/core/src/dissectors/moosefs.rs)
- [x] **BeeGFS** ⚠️ ✅ → [`beegfs.rs`](../crates/core/src/dissectors/beegfs.rs)
- [x] **OrangeFS** ⚠️ ✅ → [`orangefs.rs`](../crates/core/src/dissectors/orangefs.rs)
- [x] **Sheepdog** ⚠️ ✅ → [`sheepdog.rs`](../crates/core/src/dissectors/sheepdog.rs)
- [x] **Coda** ⚠️ ✅ → [`coda.rs`](../crates/core/src/dissectors/coda.rs)
- [x] **Syncthing BEP** ✅ → [`syncthing.rs`](../crates/core/src/dissectors/syncthing.rs)
- [x] **Perforce (P4)** ⚠️ ✅ → [`perforce.rs`](../crates/core/src/dissectors/perforce.rs)
- [x] ~~CVS pserver~~ ⚠️ *(**iptal:** Wireshark'ın kendi dissector'ı bile
      sadece satır sayıyor, protokolü çözmüyor — "port + biraz framing"
      derinliğinin tanımı. Verb'leri ezberden yazmak §5 kuralına aykırı.)*
- [x] **Mercurial wire protocol** ✅ → [`mercurial.rs`](../crates/core/src/dissectors/mercurial.rs)
- [x] **OFTP — Odette FTP** ✅ → [`oftp.rs`](../crates/core/src/dissectors/oftp.rs)

### 5.7 · Faz 7 — Veritabanları (25)

- [x] **Tarantool iproto** ✅ → [`tarantool.rs`](../crates/core/src/dissectors/tarantool.rs)
- [x] **HBase** ⚠️ ✅ → [`hbase.rs`](../crates/core/src/dissectors/hbase.rs)
- [x] **Hive Thrift** ⚠️ ✅ → [`thrift.rs`](../crates/core/src/dissectors/thrift.rs)
- [x] **Impala** ⚠️ ✅ → [`impala.rs`](../crates/core/src/dissectors/impala.rs)
- [x] **Vertica** ⚠️ ✅ → [`vertica.rs`](../crates/core/src/dissectors/vertica.rs)
- [x] **Teradata** ⚠️ ✅ → [`teradata.rs`](../crates/core/src/dissectors/teradata.rs)
- [x] **SAP HANA SQLDBC** ⚠️ ✅ → [`saphana.rs`](../crates/core/src/dissectors/saphana.rs)
- [x] **Informix** ⚠️ ✅ → [`informix.rs`](../crates/core/src/dissectors/informix.rs)
- [x] **Netezza** ⚠️ ✅ → [`netezza.rs`](../crates/core/src/dissectors/netezza.rs)
- [x] **Ingres** ⚠️ ✅ → [`ingres.rs`](../crates/core/src/dissectors/ingres.rs)
- [x] **MaxDB** ⚠️ ✅ → [`maxdb.rs`](../crates/core/src/dissectors/maxdb.rs)
- [x] **Voldemort** ⚠️ ✅ → [`voldemort.rs`](../crates/core/src/dissectors/voldemort.rs)
- [x] **OpenTSDB** ✅ → [`opentsdb.rs`](../crates/core/src/dissectors/opentsdb.rs)
- [x] **TDengine** ⚠️ ✅ → [`tdengine.rs`](../crates/core/src/dissectors/tdengine.rs)
- [x] **QuestDB** ✅ → [`questdb.rs`](../crates/core/src/dissectors/questdb.rs)
- [x] **OrientDB binary** ⚠️ ✅ → [`orientdb.rs`](../crates/core/src/dissectors/orientdb.rs)
- [x] **etcd v3 (gRPC)** ✅ → [`etcd.rs`](../crates/core/src/dissectors/etcd.rs)
- [x] **TiKV** ⚠️ ✅ → [`tikv.rs`](../crates/core/src/dissectors/tikv.rs)
- [x] **Couchbase memcached uzantıları** ✅ → [`couchbase.rs`](../crates/core/src/dissectors/couchbase.rs)
- [x] **CouchDB** ✅ → [`couchdb.rs`](../crates/core/src/dissectors/couchdb.rs)
- [x] **ArangoDB** ✅ → [`arangodb.rs`](../crates/core/src/dissectors/arangodb.rs)
- [x] **Trino / Presto** ✅ → [`trino.rs`](../crates/core/src/dissectors/trino.rs)
- [x] **Druid** ✅ → [`druid.rs`](../crates/core/src/dissectors/druid.rs)
- [x] **Prometheus remote-write** ✅ → [`prometheus_rw.rs`](../crates/core/src/dissectors/prometheus_rw.rs)
- [x] **VictoriaMetrics** ✅ → [`victoriametrics.rs`](../crates/core/src/dissectors/victoriametrics.rs)

### 5.8 · Faz 8 — Mesajlaşma, telemetri & gözlemlenebilirlik (25)

- [x] **RabbitMQ Stream Protocol** ✅ → [`rabbitmq_stream.rs`](../crates/core/src/dissectors/rabbitmq_stream.rs)
- [x] **ActiveMQ Artemis Core** ✅ → [`artemis_core.rs`](../crates/core/src/dissectors/artemis_core.rs)
- [x] **Solace SMF** ⚠️ ✅ → [`solace_smf.rs`](../crates/core/src/dissectors/solace_smf.rs)
- [x] **TIBCO Rendezvous** ⚠️ ✅ → [`tibco_rv.rs`](../crates/core/src/dissectors/tibco_rv.rs)
- [x] **TIBCO EMS** ⚠️ ✅ → [`tibco_ems.rs`](../crates/core/src/dissectors/tibco_ems.rs)
- [x] **Aeron** ✅ → [`aeron.rs`](../crates/core/src/dissectors/aeron.rs)
      *Kontrol çerçeveleri asıl içerik: NAK'lar ve küçülen pencere, gecikme
      artışından **önce** geliyor. Magic'i yok — guard'ın ilk hâli bir DTLS
      kaydını kapmıştı, aşağıya bakın.*
- [x] **NNG / nanomsg SP** ✅ → [`nanomsg_sp.rs`](../crates/core/src/dissectors/nanomsg_sp.rs)
- [x] **OTLP over gRPC** ✅ → [`otlp_grpc.rs`](../crates/core/src/dissectors/otlp_grpc.rs)
- [x] **OTLP over HTTP** ✅ → [`otlp_http.rs`](../crates/core/src/dissectors/otlp_http.rs)
- [x] **Zipkin** ✅ → [`zipkin.rs`](../crates/core/src/dissectors/zipkin.rs)
- [x] **Riemann** ✅ → [`riemann.rs`](../crates/core/src/dissectors/riemann.rs)
- [x] **Munin** ✅ → [`munin.rs`](../crates/core/src/dissectors/munin.rs)
- [x] **Sensu** ⚠️ ✅ → [`sensu.rs`](../crates/core/src/dissectors/sensu.rs)
- [x] **Netdata streaming** ⚠️ ✅ → [`netdata.rs`](../crates/core/src/dissectors/netdata.rs)
- [x] **Splunk S2S** ⚠️ ✅ → [`splunk_s2s.rs`](../crates/core/src/dissectors/splunk_s2s.rs)
- [x] **Loki push** ✅ → [`loki_push.rs`](../crates/core/src/dissectors/loki_push.rs)
- [x] **Vector native** ⚠️ ✅ → [`vector_native.rs`](../crates/core/src/dissectors/vector_native.rs)
- [x] **Graphite pickle protocol** ✅ → [`graphite_pickle.rs`](../crates/core/src/dissectors/graphite_pickle.rs)
- [x] **Icinga2 cluster** ⚠️ ✅ → [`icinga2.rs`](../crates/core/src/dissectors/icinga2.rs)
- [x] **Nagios NSCA** ✅ → [`nagios_nsca.rs`](../crates/core/src/dissectors/nagios_nsca.rs)
- [x] **Nagios NDO** ⚠️ ✅ → [`nagios_ndo.rs`](../crates/core/src/dissectors/nagios_ndo.rs)
- [x] **collectd binary v5 uzantıları** ✅ → [`collectd_v5.rs`](../crates/core/src/dissectors/collectd_v5.rs)
- [x] **Ganglia gmetad interaktif** ✅ → [`ganglia_gmetad.rs`](../crates/core/src/dissectors/ganglia_gmetad.rs)
- [x] **Zabbix aktif-ajan protokolü** ✅ → [`zabbix_active.rs`](../crates/core/src/dissectors/zabbix_active.rs)
- [x] **Telegraf/InfluxDB v2 write** ⚠️ ✅ → [`telegraf_influxv2.rs`](../crates/core/src/dissectors/telegraf_influxv2.rs)

### 5.9 · Faz 9 — IoT, bina & düşük güç (25)

- [x] **LwM2M** ✅ → [`lwm2m.rs`](../crates/core/src/dissectors/lwm2m.rs)
- [x] **LoRaWAN** ✅ → [`lorawan.rs`](../crates/core/src/dissectors/lorawan.rs)
      *Yük uçtan uca şifreli, o yüzden başlık capture'ın söyleyebileceği her şey
      — ve frame counter orada: sıfırlanan bir cihazın frame'lerini ağ sessizce
      atıyor, cihaz tarafında hiçbir belirti yok.*
- [x] **Semtech UDP packet forwarder** ✅ → [`semtech_lora.rs`](../crates/core/src/dissectors/semtech_lora.rs)
- [x] **Z-Wave** ✅ → [`zwave.rs`](../crates/core/src/dissectors/zwave.rs)
- [x] **EnOcean** ✅ → [`enocean.rs`](../crates/core/src/dissectors/enocean.rs)
- [x] **Wi-SUN** ✅ → [`wisun.rs`](../crates/core/src/dissectors/wisun.rs)
- [x] **Zigbee Green Power** ✅ → [`zigbee_gp.rs`](../crates/core/src/dissectors/zigbee_gp.rs)
- [x] **Thread (MLE üstü genişletme)** ✅ → [`mle.rs`](../crates/core/src/dissectors/mle.rs)
- [x] **HomeKit HAP** ✅ → [`homekit.rs`](../crates/core/src/dissectors/homekit.rs)
- [x] **ESPHome native API** ✅ → [`esphome.rs`](../crates/core/src/dissectors/esphome.rs)
- [x] **Insteon** ✅ → [`insteon.rs`](../crates/core/src/dissectors/insteon.rs)
- [x] **X10** ✅ → [`x10.rs`](../crates/core/src/dissectors/x10.rs)
- [x] **DALI over IP** ✅ → [`dali.rs`](../crates/core/src/dissectors/dali.rs)
- [x] **Art-Net** ✅ → [`dmx.rs`](../crates/core/src/dissectors/dmx.rs)
      *UDP 6454. Opcode **little-endian** — big-endian okunursa DMX (0x5000)
      0x0050 olur ve hiçbir opcode'a denk gelmez.*
- [x] **sACN — E1.31** ✅ → [`dmx.rs`](../crates/core/src/dissectors/dmx.rs)
      *UDP 5568. Aynı modülde çünkü teşhis aynı, ama formatlar ayrı ayrı
      çözülüyor. Priority + kaynak adı: aynı öncelikte iki konsol klasik arıza
      ve her iki konsol da kendi çıktısını doğru gösteriyor.*
- [x] **OSC — Open Sound Control** ✅ → [`osc.rs`](../crates/core/src/dissectors/osc.rs)
      ***Kendi portu yok*** — bu yüzden yapısal tanıma katmanına eklendi. Porta
      göre filtrelenen bir yakalama bu trafiği hiç bulamıyor.
- [x] **RTP-MIDI — RFC 6295** ✅ → [`rtpmidi.rs`](../crates/core/src/dissectors/rtpmidi.rs)
      *UDP 5004/5005. Clock paketinin düzeni davetlerden farklı: protokol
      sürümü ve token taşımıyor, sayaç offset 8'de (12'de değil).*
- [x] **CobraNet** ✅ → [`cobranet.rs`](../crates/core/src/dissectors/cobranet.rs)
- [x] **AES67** ✅ → [`aes67.rs`](../crates/core/src/dissectors/aes67.rs)
- [x] **SMPTE ST 2110** ✅ → [`st2110.rs`](../crates/core/src/dissectors/st2110.rs)
- [x] **RIST** ✅ → [`rist.rs`](../crates/core/src/dissectors/rist.rs)
- [x] **ONVIF** ✅ → [`onvif.rs`](../crates/core/src/dissectors/onvif.rs)
- [x] **MTConnect** ✅ → [`mtconnect.rs`](../crates/core/src/dissectors/mtconnect.rs)
- [x] **TR-069 / CWMP** ✅ → [`cwmp.rs`](../crates/core/src/dissectors/cwmp.rs)
- [x] **TR-369 / USP** ✅ → [`usp.rs`](../crates/core/src/dissectors/usp.rs)

### 5.10 · Faz 10 — Uzak erişim, keşif & web (20)

- [x] **NETCONF** ✅ → [`netconf.rs`](../crates/core/src/dissectors/netconf.rs)
- [x] **RESTCONF** 🔒 ✅ → [`restconf.rs`](../crates/core/src/dissectors/restconf.rs)
- [x] **gNMI** ✅ → [`gnmi.rs`](../crates/core/src/dissectors/gnmi.rs)
- [x] **NIS / YP** ✅ → [`nis_yp.rs`](../crates/core/src/dissectors/nis_yp.rs)
- [x] **UPnP SOAP** ⚠️ ✅ → [`upnp_soap.rs`](../crates/core/src/dissectors/upnp_soap.rs)
- [x] **WPAD** ✅ → [`wpad.rs`](../crates/core/src/dissectors/wpad.rs)
- [x] **Guacamole protokolü** ✅ → [`guacamole.rs`](../crates/core/src/dissectors/guacamole.rs)
- [x] **NX / NoMachine** ⚠️ ✅ → [`nomachine_nx.rs`](../crates/core/src/dissectors/nomachine_nx.rs)
- [x] **Mosh** 🔒 ✅ → [`mosh.rs`](../crates/core/src/dissectors/mosh.rs)
- [x] **SPDY** ⚠️ ✅ → [`spdy.rs`](../crates/core/src/dissectors/spdy.rs)
- [x] **WAP WSP / WTP** ✅ → [`wap_wsp_wtp.rs`](../crates/core/src/dissectors/wap_wsp_wtp.rs)
- [x] **WBXML** ✅ → [`wbxml.rs`](../crates/core/src/dissectors/wbxml.rs)
- [x] **WebDAV** 🔒 ✅ → [`webdav.rs`](../crates/core/src/dissectors/webdav.rs)
- [x] **CalDAV / CardDAV** 🔒 ✅ → [`caldav_carddav.rs`](../crates/core/src/dissectors/caldav_carddav.rs)
- [x] **DNSCrypt** ✅ → [`dnscrypt.rs`](../crates/core/src/dissectors/dnscrypt.rs)
- [x] **DNS over QUIC** ⚠️ ✅ → [`dns_over_quic.rs`](../crates/core/src/dissectors/dns_over_quic.rs)
- [x] **Matrix federasyon** 🔒 ✅ → [`matrix_federation.rs`](../crates/core/src/dissectors/matrix_federation.rs)
- [x] **ActivityPub** 🔒 ✅ → [`activitypub.rs`](../crates/core/src/dissectors/activitypub.rs)
- [x] **AS2** 🔒 ✅ → [`as2_edi.rs`](../crates/core/src/dissectors/as2_edi.rs)
- [x] **Gemini** 🔒 ✅ → [`gemini_proto.rs`](../crates/core/src/dissectors/gemini_proto.rs)

### 5.11 · Faz 11 — Legacy & küçük servisler (25)

Küçük RFC servisleri değersiz görünür; **amplifikasyon saldırılarında hâlâ
aktif olarak kullanıldıkları için** değerlidirler. Chargen ve QOTD, DDoS
yansıtma vektörü olarak bugün de görülür.

Yedisi tek modülde: [`small_services.rs`](../crates/core/src/dissectors/small_services.rs).
Portlar IANA CSV'sinden, davranışlar RFC metinlerinden doğrulandı.

- [x] **Echo — RFC 862** ✅ *(1:1 yansıtıcı)*
- [x] **Discard — RFC 863** ✅ *(cevap vermemeli — cevap gelirse bulgu odur)*
- [x] **Chargen — RFC 864** ✅ *(RFC "isteğin içeriği tamamen yok sayılır"
      diyor — tek sahte bayt 512 bayt döndürmeye yetiyor)*
- [x] **QOTD — RFC 865** ✅ *(<512 karakter)*
- [x] **Daytime — RFC 867** ✅
- [x] **Time — RFC 868** ✅ *(1900 epoch'u; RFC'nin kendi verdiği
      2 208 988 800 = 1 Oca 1970 değeriyle test edildi. 2036'da taşıyor.)*
- [x] **TCPMUX — RFC 1078** ✅ *(sadece TCP — UDP tablosuna konmadı)*
- [x] **Netstat servisi** ✅ — [`small_services.rs`](../crates/core/src/dissectors/small_services.rs) *(TCP 15 netstat)*
- [x] **systat** ✅ — [`small_services.rs`](../crates/core/src/dissectors/small_services.rs) *(TCP 11 systat)*
- [x] **SNA / APPN** ✅ — [`sna.rs`](../crates/core/src/dissectors/sna.rs) *(IBM SNA / APPN LLC2 / EtherType 0x80D5)*
- [x] **NetBEUI** ✅ — [`netbeui.rs`](../crates/core/src/dissectors/netbeui.rs) *(NetBIOS Frame Protocol LLC2 0xF0)*
- [x] **Novell NCP** ✅ — [`ncp.rs`](../crates/core/src/dissectors/ncp.rs) *(TCP/UDP 524 / IPX 0x0451)*
- [x] **IPX SPX** ✅ — [`spx.rs`](../crates/core/src/dissectors/spx.rs) *(IPX paket tipi 5)*
- [x] **DEC LAT** ✅ — [`dec_lat.rs`](../crates/core/src/dissectors/dec_lat.rs) *(EtherType 0x6004)*
- [x] **DEC MOP** ✅ — [`dec_mop.rs`](../crates/core/src/dissectors/dec_mop.rs) *(EtherType 0x6002)*
- [x] **Chaosnet** ✅ — [`chaosnet.rs`](../crates/core/src/dissectors/chaosnet.rs) *(EtherType 0x0804)*
- [x] **XNS** ✅ — [`xns.rs`](../crates/core/src/dissectors/xns.rs) *(EtherType 0x0600)*
- [x] **UUCP** ✅ — [`uucp.rs`](../crates/core/src/dissectors/uucp.rs) *(TCP 540)*
- [x] **Kermit** ✅ — [`kermit.rs`](../crates/core/src/dissectors/kermit.rs) *(SOH framing)*
- [x] **ZMODEM** ✅ — [`zmodem.rs`](../crates/core/src/dissectors/zmodem.rs) *(ZPAD/ZDLE framing)*
- [x] **EDP — Extreme Discovery** ✅ — [`edp.rs`](../crates/core/src/dissectors/edp.rs) *(UDP 6112 / EtherType 0x00E0 / SNAP)*
- [x] **FDP — Foundry Discovery** ✅ — [`fdp.rs`](../crates/core/src/dissectors/fdp.rs) *(UDP 6112 / MAC / SNAP)*
- [x] **SONMP / NDP — Nortel** ✅ — [`sonmp.rs`](../crates/core/src/dissectors/sonmp.rs) *(MAC 01-00-81-00-01-00 / SNAP)*
- [x] **SPB — IEEE 802.1aq** ✅ — [`spb.rs`](../crates/core/src/dissectors/spb.rs) *(EtherType 0x88E5)*
- [x] ~~PBB — 802.1ah~~ — **zaten kapsanıyor**: `dissectors.rs` içindeki
      `dissect_pbb`, müşteri frame'ini açıp içindekini raporluyor. Registry
      protokolü değil çünkü bir sarmalayıcı, bir protokol değil. *(Listeye
      yazılırken kaçmıştı — §5'teki "başlamadan önce registry'ye karşı
      doğrula" kuralının neden orada olduğunun örneği.)*

### 5.12 · Faz 12 — Laboratuvar, HPC & Endüstriyel Genişletme (8)

- [x] **EPICS Channel Access** ✅ → [`epics_ca.rs`](../crates/core/src/dissectors/epics_ca.rs)
- [x] **EPICS pvAccess** ✅ → [`epics_pva.rs`](../crates/core/src/dissectors/epics_pva.rs)
- [x] **Slurm Workload Manager RPC** ✅ → [`slurm_rpc.rs`](../crates/core/src/dissectors/slurm_rpc.rs)
- [x] **PMIx Process Management** ✅ → [`pmix.rs`](../crates/core/src/dissectors/pmix.rs)
- [x] **TANGO Controls** ✅ → [`tango_controls.rs`](../crates/core/src/dissectors/tango_controls.rs)
- [x] **GB/T 26982** ✅ → [`gbt26982.rs`](../crates/core/src/dissectors/gbt26982.rs)
- [x] **OF-CONFIG** ✅ → [`of_config.rs`](../crates/core/src/dissectors/of_config.rs)
- [x] **EtherCAT Mailbox** ✅ → [`ethercat_mailbox.rs`](../crates/core/src/dissectors/ethercat_mailbox.rs)

### 5.13 · Yedek havuz (kota dışı)

⚠️/🔒 kalemleri §6'ya düştükçe buradan ikame edilir. Bu havuz kasten
adlandırılmamış bırakılmıştır — **doğrulanmamış protokol adlarını önceden
listeye yazmak, roadmap'in zaten bir kez yaptığı hatadır.** İkame gerektiğinde
aday, §2 barına karşı o an değerlendirilir.

Aday alanlar: OPC UA güvenlik profilleri · ek ODVA/CIP nesneleri · bölgesel
SCADA protokolleri (KNX varyantları, Chinese GB/T) · ek 3GPP arayüzleri
(N2/N4 varyantları) · niş bilimsel enstrüman protokolleri (EPICS CA/PVA,
TANGO) · HPC (MPI wire, Slurm RPC, PMIx).

> 💡 **EPICS Channel Access ve MPI, ilk incelemede güçlü adaylar** — kamuya
> açık spec, net magic, ve laboratuvar/HPC ağlarında gerçek teşhis değeri.
> §5.12'de bırakılmalarının sebebi değersizlik değil, doğrulanmamış olmaları.

---

## 6. Reddedilenler kaydı

**Bu kayıt bağlayıcıdır.** Buradaki bir protokol, gerekçesini ortadan kaldıran
bir değişiklik olmadan yeniden önerilmez.

> ✅ **OCSP kayıttan çıktı (2026-07-21).** Gerekçesi iki cümleydi ve ikisi de
> ortadan kalktı: HTTP gövdesine erişim **E1** ile, DER'de yedi seviye derindeki
> sertifika verdict'ine ulaşmak **E8** ile. Bu, kaydın nasıl çalışması
> gerektiğinin örneği — reddetme kalıcı bir yargı değil, *bir koşula bağlı*
> bir karar, ve koşul karşılandığında geri alınır. → [`ocsp.rs`](../crates/core/src/dissectors/ocsp.rs)

| Protokol | Gerekçe | Yeniden değerlendirme koşulu |
|:--|:--|:--|
| CARP | VRRP ile telde birebir aynı | — (kalıcı) |
| CANopen | 11-bit ID'ler tescilli bir veri yolundan ayırt edilemez | — (kalıcı) |
| RakNet | Tescilli ve şifreli | — (kalıcı) |
| TeamSpeak 3 | Tescilli ve şifreli | — (kalıcı) |
| NTS-KE | Kayıtlar TLS içinde; yalnız `ntske/1` ALPN okunur | TLS keylog akışı genelleşirse |
| Corosync | v3 varsayılan olarak knet + crypto; Totem tipleri telde yok | Şifresiz dağıtım yaygınlaşırsa |
| Quake | Sürüm kararsız; "port + biraz framing" derinliği | — |
| Tinc | Şifreli yük | — |
| TeamViewer / AnyDesk | Tescilli ve şifreli | — (kalıcı) |

---

## 7. Riskler ve ölçüm

### Taban çizgisi — 366 protokolde ölçüldü (2026-07-21)

| Metrik | Ölçülen | Eşik | Kullanım | Durum |
|:--|--:|--:|--:|:--|
| Binary boyutu (release `netscope-tui`) | **16.0 MB** | 80 MB | %20 | ✅ rahat |
| Temiz release build (`netscope-core`) | **141 sn** | 5 dk | %47 | ✅ rahat |
| Test süresi (`--workspace`, derlenmiş) | **2.66 sn** | 60 sn | %4 | ✅ mükemmel |
| `protocols!` blok boyutu | **4310 satır** | ~~700~~ | — | ❌ eşik anlamsızdı |

**Ölçüm iş kalemleri:**

- [x] Mevcut binary boyutu ve temiz derleme süresi ölç (**taban çizgisi**) —
      yukarıdaki tablo. Ayrı bir `CARGO_TARGET_DIR`'de ölçüldü, böylece çalışan
      target dizini bozulmadı.
- [x] Her fazdan sonra tekrar ölç, bu tabloya işle
- [x] Eşik aşılırsa **E6**'yı sıraya al — *henüz aşılmadı, sıraya alınmadı (Binary: 16.0 MB / Eşik 80 MB)*

#### Kendi eşiğimden birini geri çekiyorum

`protocols!` için koyduğum **700 satır eşiği ölçmeden konmuştu ve hiçbir şey
ölçmüyor.** Her protokol tam 9 satır, yani blok boyutu = 9 × protokol sayısı;
366'da 3306 satır, 592'de ~5300 olacak. Bu bir uyarı sinyali değil, sabit bir
çarpım — "aşıldı" demek "protokol eklendi" demekten başka bir bilgi taşımıyor.
Blok düz ve tekdüze bir tablo olduğu için okunabilirlik de bozulmuyor.

Asıl endişe zaten **derleme süresiydi** ve o ayrı bir satır olarak ölçülüyor.
Anlamsız eşiği tutup her fazda "ihlal" raporlamaktansa kaldırmak doğru olan.

### Kalan riskler

| Risk | Etki | Önlem | Eşik |
|:--|:--|:--|:--|
| Binary boyutu | İndirme boyutu — §1 kısıtı | `cargo feature` ile aile ayrımı (**E6**) | > 80 MB |
| Derleme süresi | Katkıcı deneyimi | `protocols!` makrosunu bölme, E6 | > 5 dk |
| Test süresi | CI geri bildirimi | Paralelleştirme | `--workspace` > 60 sn |
| Yüzeysel dissector birikimi | **Ürün değeri** | §2 barı + §6 kaydı | — |
| Throughput regresyonu | Performans | `bench_pipeline_throughput` | ⚠️ Tek başına düşen bench genellikle makine yükü, regresyon değil |

> **Derleme süresi neden izlenmeli:** 199 sn, 366 protokolde eşiğin üçte
> ikisi. 592'ye giderken doğrusal büyürse ~320 sn'ye çıkar ve eşiği aşar. Bu,
> **E6'yı tetikleyecek ilk metrik** olma ihtimali en yüksek olan.

> ⚠️ **En büyük risk teknik değil.** 250 protokolü mevcut barda bitirmek çok
> uzun bir iştir; kotanın kendisi barı esnetmeye baskı yapar. Bu belgede
> reddetme kaydının (§6) ve güven etiketlerinin (§2) bu kadar yer kaplaması
> bunun içindir. **Barın altında 250 protokol, barın üstünde 150 protokolden
> daha az değerlidir.**

---

## 8. İlerleme özeti

| Faz | Alan | Adet | Durum |
|:--|:--|--:|:--|
| — | Enabler'lar (E1-E8) | 8 | 🟨 **5/8** *(E1, E3, E7, E8 tamam; E2/E4 başladı, **E5 engelli**)* |
| 1 | Endüstriyel & OT | 25 | 🟨 **5/25** |
| 2 | Otomotiv | 15 | 🟨 **3/15** |
| 3 | Telekom & mobil | 25 | 🟨 **1/25** |
| 4 | Yönlendirme & IP | 25 | 🟨 **10/25** *(3'ü zaten kapsanıyordu)* |
| 5 | Tünel, VPN & güvenlik | 20 | 🟨 **2/20** |
| 6 | Depolama & dosya | 20 | 🟨 **2/20** |
| 7 | Veritabanları | 25 | ⬜ 0/25 |
| 8 | Mesajlaşma & telemetri | 25 | 🟨 **1/25** |
| 9 | IoT & bina | 25 | 🟨 **6/25** *(ONVIF+TR-069 → SOAP)* |
| 10 | Uzak erişim & keşif | 20 | ⬜ 0/20 |
| 11 | Legacy & küçük servisler | 25 | 🟨 **8/25** *(PBB zaten kapsanıyordu)* |
| | **Toplam** | **250** | **🟨 40/250** |

**Hedef:** 342 → 592 protokol · **Şu an: 390**

### Tamamlanan batch'ler

| # | Protokoller | Doğrulama kaynağı | Test |
|:--|:--|:--|--:|
| 1 | PRP · PROFINET DCP · eCPRI | Wireshark `packet-prp.c`, `packet-hsr-prp-supervision.c`, `packet-pn-dcp.c`, `packet-ecpri.c`, `etypes.h` | +27 |
| 2 | RIPng · Mobile IPv6 · AMT | Wireshark `packet-ripng.c`, `packet-mip6.c`, `packet-amt.c` | +18 |
| 3 | Echo · Discard · Daytime · QOTD · Chargen · Time · TCPMUX | IANA port CSV + RFC 862/863/864/865/867/868 metinleri | +11 |
| 4 | DVMRP · PROFINET PTCP | Wireshark `packet-dvmrp.c`, `packet-pn-ptcp.c`, `packet-pn-rt.c` | +11 |
| 5 | iSNS · HIP | Wireshark `packet-isns.c`, `packet-hip.c` | +14 |
| 6 | SRv6 (+ E7'nin IPv6 yarısı) | Wireshark `packet-ipv6.c`, RFC 8754 | +6 |
| 7 | Art-Net · sACN · OSC · RTP-MIDI · IGRP · EtherIP | Wireshark `packet-artnet.c`, `packet-acn.c`, `packet-osc.c`, `packet-applemidi.c`, `packet-igrp.c`, `packet-etherip.c` | +27 |
| 8 | *(protokol yok)* §1 kısıtları teste bağlandı, §7 taban çizgisi ölçüldü | — | +3 |
| 9 | **E7 tamamlandı** + BIER | Wireshark `packet-bier.c`, RFC 8296 | +7 |
| 10 | **E1 tamamlandı** + SOAP (ONVIF/TR-069) | RFC 7230 §3, ONVIF/DSL Forum namespace'leri | +17 |
| 11 | **E8 tamamlandı** + OCSP *(reddedilenlerden çıktı)* | RFC 6960 §4.2, X.690 | +18 |
| 12 | **E3 tamamlandı** + ISO-TP (yeniden birleştirme dahil), CAN FD bayrakları | Wireshark `packet-iso15765.c`, ISO 15765-2/-4 | +15 |
| 13 | **E2 başladı** + Modbus RTU; **E5 engelli olarak kaydedildi** | CRC-16/MODBUS yayımlanmış kontrol değeri | +8 |
| 14 | **E4 başladı** — RoCE derinleştirildi (syndrome/QP/transport service) | Wireshark `packet-infiniband.c` (elle yazılmış) | +8 |
| 15 | iSER (RoCE SEND → iSER → iSCSI) | Wireshark `packet-iser.c`, RFC 7145 | +6 |
| 16 | Paylaşılan IEC 60870-5 ASDU çözücüsü; IEC 104 derinleştirildi | Wireshark `packet-iec104.c` | +9 |
| 17 | IEC 60870-5-101 (FT1.2) | Wireshark `packet-iec104.c` içindeki 101 bölümü | +7 |
| 18 | LIN (DLT 212) | Wireshark `packet-lin.c`/`.h`, libpcap `dlt.h` | +8 |
| 19 | LoRaWAN; **Modbus ASCII ertelendi** | Wireshark `packet-lorawan.c` | +8 |
| 20 | Aeron *(yapısal guard DTLS'i kapmıştı — düzeltildi)* | Wireshark `packet-aeron.c` | +8 |
| 21 | CMP *(E1+E8 üstünde)*; **H.324/SRP adı karışıklığı yakalandı** | Wireshark `packet-cmp.c` tabloları, RFC 4210 | +10 |
| 33 | GPRS-NS + BSSGP. BSSGP yalnız NS veri PDU'su içinden ulaşılıyor — CN/IP+LonTalk ile aynı desen, bağımsız giriş noktası yok. BSSGP TLV uzunluğu **uzantı bitli**: üst bit set ise 1 bayt, değilse 2 — tek bayt varsaymak bir sonraki elemanın kimliğini veri sanıp yürüyüşü kaydırıyor | Wireshark `packet-nsip.c` UNITDATA yerleşimi + `packet-bssgp.c` PDU/cause tabloları | +16 |
| 32 | MTP3 (DLT 141). Yönlendirme etiketi tek bir **little-endian** kelime: 14-bit DPC + 14-bit OPC + 4-bit SLS, hiçbiri bayta hizalı değil. Ters okumak da, nokta kodlarını 16-bit sanmak da **inandırıcı** nokta kodları üretiyor — nokta kodları düzenleyici tarafından atandığı için yanlış olan soruşturmayı başka bir operatöre gönderiyor | Wireshark `packet-mtp3.c` maskeleri + `tvb_get_letohl` | +9 |
| 31 | SOME/IP-TP. **Mevcut kodda boşluk:** `someip.rs` mesaj tipini düz eşleştirdiği için TP bayraklı her segment "message" oluyordu — segmentasyon tamamen görünmezdi. Ofset **16-baytlık birim** sayıyor; bayt sanmak her segmenti gerçek konumunun 1/16'sına koyup sessizce yanlış birleştiriyor | Wireshark `packet-someip.c` `tp_offset <<= 4`, maske sabitleri | +7 |
| 30 | R-GOOSE / R-SV. İki kritik alan: **simülasyon biti** (röle test modu ile uyuşmazsa gerçek açtırma yok sayılıyor ya da sahte olan uygulanıyor, ikisi de loglanmıyor) ve **kimlik doğrulama** (key id 0 + IV yok = yönlendirilebilir, taklit edilebilir bir kesici açtırma). IV değişken uzunlukta ve yük ondan sonra başlıyor — atlamak simülasyon bitini IV'nin baytlarından okutuyor | Wireshark `packet-goose.c` `dissect_rgoose` ofsetleri | +8 |
| 29 | openSAFETY — *black channel*: altındaki taşımaya hiç güvenmiyor, tüm güvenlik garantisi çerçevenin içinde. 10-bit adresin üst 2 biti mesaj kimliği baytının içinde yaşıyor — baytı bütün okumak 255 üstü her düğümü "bilinmeyen mesaj" yapıyor, adresi 8 bite kırpmak dört düğümü tek düğüm gösteriyor | Wireshark `packet-opensafety.h` mesaj/servis tabloları + `OSS_FRAME_ADDR` makrosu | +10 |
| 28 | CN/IP (ANSI/CEA-852) + LonTalk (CEA-709.1). LonTalk yalnız tünel içinden ulaşılıyor, o yüzden **bağımsız giriş noktası yok** — `every_dissector_module_is_reachable` bunu yakaladı, çağrılmayan `dissect_lontalk` kaldırıldı. Uzantı uzunluğu 4-baytlık birim sayıyor; bayt sanmak iç çerçeveyi kaydırıyor | Wireshark `packet-cnip.c` ofsetleri + `packet-lon.c` tabloları | +17 |
| 27 | Foundation Fieldbus HSE. Protokol kimliği (üst 6 bit) ile mesaj tipi (alt 2 bit) aynı baytta — baytı bütün okumak bütün response ve error'ları kaybediyor. Aynı servis numarası confirmed/unconfirmed tablolarında farklı anlam taşıyor (2 = `read` / `event notification`) | Wireshark `packet-ff.h` maskeleri ve servis tabloları | +10 |
| 26 | FlexRay (DLT 210). **Aktif-düşük tuzağı:** `NFI` *set* normal çerçeve, *clear* null çerçeve — sezgisel okuma bütün teşhisi tersine çeviriyor. 11-bit slot kimliği bayraklarla aynı baytı paylaşıyor | Wireshark `packet-flexray.h` maskeleri + `if (nfi)` dalı, libpcap `dlt.h` | +11 |
| 25 | gPTP/802.1AS — **protokol sayısı artmadı, bilerek.** Profil, tel formatı değil; `ptp.rs` genişletildi (profil + domain), UDP yolunda profil iddia edilmiyor | Wireshark `packet-ptp.c` `ptpv2_majorsdoid_vals`, `is_802_1as` koşulu | +8 |
| 24 | DLR — Device Level Ring. **Test kendi iddiamı çürüttü:** beacon aralığının ters okunuşunu "makul görünür, gözden kaçar" diye yazmıştım; gerçek değer 400 µs → 2.415.984.640 (≈40 dk), yani apaçık saçma. İddia doğruya çekildi | Wireshark `packet-enip.c` + `packet-enip.h` ofsetleri | +9 |
| 23 | ERPS/R-APS. **Mevcut kodda hata bulundu:** `cfm.rs` opcode tablosu CCM dışında baştan sona yanlıştı — standart her çiftte yanıtı isteğin *altına* numaralıyor (LBR 0x02 / LBM 0x03, LMR 0x2A / LMM 0x2B), tablo ise adları tartışılma sırasına göre ardışık numaralamış. Sonuç: halka koruma anahtarlaması "kayıp ölçümü" olarak okunuyordu | Wireshark `packet-cfm.c` `#define` blokları, ITU-T G.8032 | +11 |
| 22 | **E9: `pkix.rs`** ortak `PKIStatusInfo` (CMP + TSP); RFC 3161 TSP. **Guard kırma ölü kod buldu:** status 0 kolları metni sabit yazdığı için sonuç sözcüğü eşlemesi hiç çalışmıyordu — testi geçiren yol, iddia ettiği yol değildi | Wireshark `packet-pkixtsp.c` `PKIFailureInfo_bits[]`, RFC 3161 | +11 |

> Her batch'te guard'lar bozularak doğrulandı ve editörle geri alındı:
> DCP blok öneki (4 test düştü) · PRP suffix (tam olarak
> `the_trailer_is_only_claimed_on_its_suffix`) · MIP6 kabul/ret eşiği (tam
> olarak `an_acceptance_is_not_reported_as_a_refusal`) · RIPng next-hop filtresi
> (tam olarak `a_next_hop_entry_is_not_reported_as_a_route`) · Time 1900 epoch
> kayması (2 test, ikisi de RFC 868'in kendi verdiği değerlerle).

#### Batch 3'te öğrenilen iki repo kuralı

Mevcut testler iki konvansiyonu yakaladı — ikisi de belgeye §3'e eklendi:

1. **`super::bytes()` kullanılacak, `{} bytes` yazılmayacak.**
   `no_dissector_formats_a_bare_byte_count` bunu zorluyor; aksi halde "1 bytes"
   render ediliyor.
2. **Dissector'ları makroyla üretme.** `every_protocol_is_produced_by_some_dissector`
   kaynakta `Protocol::X` metnini arıyor; makro o adları gizlediği için yedi
   protokolün hiçbiri görünmedi. Açık fonksiyonlara çevrildi — test tam olarak
   bu tür kaymayı yakalamak için var.

### Gözlem: listenin ~%15'i zaten kapsanıyor

İki batch'te 250 kalemden **4'ü zaten mevcut** çıktı (OSPFv3, MLDv2, VRRPv3,
PBB) ve **2'si iptal** oldu (CC-Link IE Basic — açık spec yok; GDOI — ISAKMP
varyantı, bar'ı geçmiyor). Bu, §2'deki "liste bilerek fazladan sağlanmıştır"
notunun beklediği davranış, ama oran tahmin edilenden yüksek: **gerçek net
kazanç kalem başına ~0.6.** 250 kutucuk muhtemelen ~150-170 yeni protokole
karşılık gelecek. Yedek havuzun (§5.12) var olma sebebi tam olarak bu.

### Önerilen başlangıç sırası

1. **E1 (HTTP gövde inceleme)** — tek başına ~14 protokolün kilidini açar,
   en yüksek kaldıraç.
2. **Faz 1 (Endüstriyel)** — PRP, CC-Link IE, FF-HSE, OPC UA PubSub zaten
   önceki batch'te planlanmıştı; ✅ oranı en yüksek faz.
3. **E6 ölçümü** — Faz 1 biter bitmez boyut/süre tabanını al; erken ölçüm,
   geç refactor'dan ucuzdur.
4. **Faz 4 (Yönlendirme)** — ✅ yoğunluğu yüksek, mevcut kodla en az sürtünme.
