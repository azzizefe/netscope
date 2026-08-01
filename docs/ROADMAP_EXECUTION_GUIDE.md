# netscope — Yol Haritası Uygulama ve Geliştirme Kılavuzu

Bu doküman, **Netscope** projesinde önümüzdeki fazların adım adım nasıl uygulanacağını, kullanılacak kod kalıplarını, komutları ve dikkat edilmesi gereken mimari kuralları açıklamaktadır.

---

## 📌 İçindekiler
1. [Faz 1: 145 Dissector Modülünün Dispatch Katmanına Bağlanması](#faz-1-145-dissector-modülünün-dispatch-katmanına-bağlanması)
2. [Faz 2: Sentetik PCAP Fixture Üretimi ve Çevrimdışı Testler](#faz-2-sentetik-pcap-fixture-üretimi-ve-çevrimdışı-testler)
3. [Faz 3: Desktop App Test Coverage (Tauri & Vitest)](#faz-3-desktop-app-test-coverage-tauri--vitest)
4. [Faz 4: Sensör (Agent) Simülasyonu ve Auto-Update](#faz-4-sensör-agent-simülasyonu-ve-auto-update)
5. [🛠️ Hızlı Komutlar Çizelgesi (Cheat Sheet)](#-hızlı-komutlar-çizelgesi-cheat-sheet)

---

## Faz 1: 145 Dissector Modülünün Dispatch Katmanına Bağlanması

Erişilemeyen dissector'lar `crates/core/src/dissectors/` klasöründedir ve `dissectors::robustness::unreachable_modules()` tarafından listelenir.

### 1.1. Port Bazlı Bağlama (Fixed Port)
Eğer dissector sabit bir IANA/well-known port kullanıyorsa:

1. **[bindings.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/bindings.rs)** dosyasını açın.
2. Modülü `use super::{...}` bloğuna ekleyin.
3. `TCP_PORTS` veya `UDP_PORTS` dizisine port numarasına göre **sıralı (sorted)** olarak ekleyin:
   ```rust
   // Örnek: TCP Port 9092 - Kafka Custom Stream
   (9092, my_protocol::dissect_my_protocol),
   ```
   > ⚠️ **Önemli**: `TCP_PORTS` ve `UDP_PORTS` dizileri port numarasına göre **artan sırada** olmak zorundadır. Sırasız eklenirse `tables_are_sorted_and_unique` testi hata verir.

### 1.2. İçerik / İmza Bazlı Bağlama (Magic Bytes / Heuristic)
Portu değişken olan veya dinamik çalışan protokoller için:

1. Modül içinde imza kontrol fonksiyonu yazın:
   ```rust
   pub fn matches_signature(data: &[u8]) -> bool {
       data.len() >= 4 && &data[0..4] == b"NETS"
   }
   ```
2. **[tcp.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/tcp.rs)** veya **[udp.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/dissectors/udp.rs)** içerisindeki heuristic dispatch zincirine ekleyin:
   ```rust
   if my_protocol::matches_signature(payload) {
       return my_protocol::dissect_my_protocol(src_ip, dst_ip, src_port, dst_port, payload);
   }
   ```

### 1.3. Registry Statüsünü Güncelleme
Dissector bağlandıktan sonra:
1. **[registry.rs](file:///c:/Users/efe/Desktop/netscope/crates/core/src/registry.rs)** dosyasındaki `protocols!` tablosunda ilgili protokolün statüsünü değiştirin:
   ```rust
   // Eski: status: Declared,
   // Yeni:
   status: Dissected,
   ```
2. Testi çalıştırarak doğrulayın:
   ```bash
   cargo test -p netscope-core --lib registry
   ```

---

## Faz 2: Sentetik PCAP Fixture Üretimi ve Çevrimdışı Testler

Yeni dissector'lar için test pcap dosyaları üretmek ve bunları offline ayrıştırma testlerine dahil etmek.

### 2.1. Generator Tool Kullanımı
Projedeki sentetik pcap üretici aracı kullanın:
```bash
# Generator tool'u derleyip çalıştırın
cargo run -p netscope-tools-gen-fixtures
```

### 2.2. Yeni Fixture Ekleme
1. `tools/gen-fixtures/src/main.rs` içinde hedef protokole ait ham baytları (raw bytes) oluşturun.
2. `fixtures/` dizinine yeni `.pcap` dosyasını kaydedin (ör: `fixtures/custom_proto.pcap`).
3. Offline TUI veya Core testi yazın:
   ```rust
   #[test]
   fn test_parse_custom_pcap() {
       let pcap_bytes = include_bytes!("../../../fixtures/custom_proto.pcap");
       let packets = netscope_core::parse_pcap(pcap_bytes).unwrap();
       assert!(!packets.is_empty());
   }
   ```

---

## Faz 3: Desktop App Test Coverage (Tauri & Vitest)

Tauri v2 masaüstü uygulamasının backend (Rust) ve frontend (Vitest/Svelte) test kapsamını artırmak.

### 3.1. Tauri Command Handler Testi (Rust)
`desktop/src-tauri/src/commands/` klasöründeki Tauri komutlarına unit test ekleme:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_export_pcap_command() {
        let result = export_pcap_handler("test.pcap").await;
        assert!(result.is_ok());
    }
}
```

### 3.2. Frontend Tests (Vitest)
```bash
# Frontend test dizinine gidin
cd desktop/frontend-tests

# Bağımlılıkları kurun ve testleri çalıştırın
npm ci
npm test
```

---

## Faz 4: Sensör (Agent) Simülasyonu ve Auto-Update

### 4.1. Canlı Sensör & Sunucu Test Simülasyonu
1. **gRPC Sunucusunu Başlatın**:
   ```bash
   cargo run -p netscope-server
   ```
2. **Sensör Agent'ı Başlatın**:
   ```bash
   cargo run -p netscope-agent
   ```
3. Sensörün sunucuya attığı Heartbeat ve Event streaming loglarını kontrol edin.

### 4.2. Auto-Update Konfigürasyonu
Tauri Updater plugin'i yapılandırması:
1. `desktop/src-tauri/tauri.conf.json` içinde updater uç noktasını belirtin:
   ```json
   "plugins": {
     "updater": {
       "endpoints": ["https://netscope-update.vercel.app/api/update/{{target}}/{{current_version}}"],
       "pubkey": "YOUR_TAURI_PUBLIC_KEY"
     }
   }
   ```

---

## 🛠️ Hızlı Komutlar Çizelgesi (Cheat Sheet)

| Amaç | Komut |
|---|---|
| **Tüm Çalışma Alanını Derle** | `cargo build` |
| **Spesifik Crate Derle** | `cargo build -p netscope-core -p netscope-server` |
| **Tüm Testleri Çalıştır** | `cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent` |
| **Registry Testlerini Çalıştır** | `cargo test -p netscope-core --lib registry` |
| **Clippy Control (Hata Toleranssız)** | `cargo clippy --workspace --exclude netscope-desktop -- -D warnings` |
| **Kod Biçimlendirme Kontrolü** | `cargo fmt --check` |
| **Frontend Testleri (Vitest)** | `cd desktop/frontend-tests && npm test` |
| **TUI Offline Pcap Testi** | `cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless` |
