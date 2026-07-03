# Dissector Protocol Guide

## Summary Convention

netscope aims for human-readable one-line summaries rather than raw hex or
field-by-field output. The goal: tell the user what happened, not what bits
were on the wire.

| Protocol | Summary Pattern | Example |
|----------|----------------|---------|
| TCP (handshake) | `"TCP Connection opened (3-way handshake)"` | SYN |
| TCP (handshake) | `"TCP SYN-ACK — handshake in progress"` | SYN-ACK |
| TCP (data) | `"TCP — N bytes of payload"` | established connection |
| TCP (close) | `"TCP Connection closing (FIN)"` | FIN |
| TCP (reset) | `"TCP Connection reset (RST)"` | RST |
| TCP (no payload) | `"TCP — no payload (keep-alive or ACK)"` | pure ACK |
| UDP | `"UDP — N bytes of payload"` | generic UDP |
| DNS Query | `"DNS Query — example.com (1)"` | outgoing lookup |
| DNS Response | `"DNS Response — example.com → 93.184.216.34 (2 answers)"` | incoming reply |
| DNS Response (AAAA) | `"DNS Response — example.com → 2607:f8b0::1 (AAAA)"` | IPv6 answer |
| HTTP Request | `"HTTP GET /api/users (HTTP/1.1)"` | method + path |
| HTTP Request | `"HTTP POST /login (HTTP/1.1)"` | POST method |
| HTTP Response | `"HTTP 200 OK (1234 bytes)"` | status code + reason |
| TLS | `"TLS — github.com (HTTPS)"` | SNI hostname |
| TLS (no SNI) | `"TLS Handshake (no SNI)"` | handshake without SNI |
| TLS (encrypted) | `"TLS — N bytes of encrypted data"` | post-handshake |
| ARP Request | `"ARP Request — Who has 192.168.1.1? Tell 192.168.1.2 (aa:bb:cc:dd:ee:ff)"` | MAC + IP |
| ARP Reply | `"ARP Reply — 192.168.1.1 is at aa:bb:cc:dd:ee:ff"` | MAC + IP |
| ICMP | `"ICMP message"` | generic (no type/code yet) |
| Unknown | `"Unknown protocol (N bytes)"` | graceful fallback |

## Dispatch Logic

```
dissect(data)
  ├─ ethernet::dissect_ethernet(data)
  │   ├─ EtherType 0x0800 → ip::dissect_ipv4(payload)
  │   ├─ EtherType 0x86DD → ip::dissect_ipv6(payload)
  │   └─ EtherType 0x0806 → arp::dissect_arp(payload)
  │
  ├─ ip::dissect_ipv4(payload)
  │   └─ Protocol 6 → tcp::dissect_tcp(payload, addrs)
  │       ├─ port 80 → http::dissect_http(payload)
  │       └─ port 443 → tls::dissect_tls(payload)
  │   └─ Protocol 17 → udp::dissect_udp(payload, addrs)
  │       └─ port 53 → dns::dissect_dns(payload)
  │   └─ Protocol 1 → icmp::dissect_icmp(addrs)
  │
  └─ ip::dissect_ipv6(payload) — same dispatch as IPv4
```

## Adding a New Dissector

1. Create `crates/core/src/dissectors/<protocol>.rs`
2. Implement a public function returning `DissectedResult`
3. Register in `crates/core/src/dissectors.rs`:
   - Add `pub mod <protocol>;`
   - Add dispatch logic in `dispatch_transport()` or match a new EtherType in `dissect()`
4. Add tests in the same file (within `#[cfg(test)] mod tests { ... }`)
5. Add test helpers in `crates/core/src/dissectors.rs` under `mod test_helpers`
6. Generate a fixture pcap in `tools/gen-fixtures/src/main.rs`
7. Verify with: `cargo test -p netscope-core && cargo clippy -p netscope-core -- -D warnings`

## Error Handling

Every dissector follows the same rule: **never panic**. If input is malformed:

- Return `Protocol::Unknown(reason)` with a descriptive string
- Provide a summary like `"Malformed TCP header"` or `"DNS — malformed packet"`
- Always return a valid `DissectedResult`, never use `unwrap()` on packet data
- The fuzz test (`dispatch_random_garbage_never_panics`) validates this with 1000 random garbage inputs

## Port-Based Dispatch

netscope uses port-based protocol detection for L7 (no payload inspection fallback):

| Transport | Port | Protocol |
|-----------|------|----------|
| TCP | 80 | HTTP |
| TCP | 443 | TLS |
| UDP | 53 | DNS |

Future work: add payload-signature-based detection for non-standard ports.
