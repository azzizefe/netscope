# Filter Cookbook

netscope has two layers of filtering. Use them together.

| | Capture filter (`-f`) | Live search (type in TUI) |
|---|---|---|
| **When it runs** | Before packets reach netscope | On packets already captured |
| **Syntax** | BPF (same as Wireshark/tcpdump) | Free text — no syntax at all |
| **Can be changed live** | No — restart required | Yes — updates as you type |
| **Use it for** | Reducing noise at the source | Finding things interactively |

## Live search (the easy one)

Just start typing in the TUI. The packet list narrows instantly. It matches
against protocol names, IPs, **hostnames**, and packet summaries:

```
google        → everything to/from *google* domains
dns           → all DNS traffic
192.168.1.5   → packets involving that IP
handshake     → TCP handshakes
```

Press `Esc` to clear. That's the whole syntax — for free-text search.

## Display filters (the Wireshark-style one)

The same box also understands a **Wireshark-style display-filter language**. If
what you type parses as a filter expression, it's evaluated field-by-field; if
it doesn't, it falls back to the free-text search above. So both styles live in
one box — no mode switch.

```
tcp.port == 443 && tls          → TLS on 443
ip.addr == 8.8.8.8              → to or from that IP
http.request.method == POST     → HTTP POST requests
http.response.code >= 400       → HTTP errors
dns.qry.name contains "cdn"     → DNS lookups for *cdn* names
frame.len > 1000 and !tls       → big, non-TLS packets
```

**Fields:** `ip.addr` / `ip.src` / `ip.dst`, `port` / `tcp.port` / `udp.port`,
`frame.len` (`len`), `tcp.flags.syn` / `.ack` / `.fin` / `.rst` / `.psh`,
`http.request.method` / `.uri` / `http.host` / `http.response.code`,
`dns.qry.name`, and `info` (the summary column).
**Operators:** `==` `!=` `>` `<` `>=` `<=` and `contains`.
**Logic:** `&&`/`and`, `||`/`or`, `!`/`not`, and parentheses.

### TLS fingerprints (JA3 / JA4 / JA3S)

netscope computes TLS client and server fingerprints from the handshake and
exposes them as filter fields — so you can hunt encrypted traffic by *how* the
client or server speaks TLS, even though you can't read the content. This is
threat-hunting territory Wireshark needs a plugin for.

```
ja3 == 6169fabc98e3e6c9690301eaf306d632     → a known JA3 (e.g. from a feed)
ja4 contains "t13d"                          → TLS 1.3 clients with SNI
ja3s == <hash>                               → a specific server fingerprint
```

Aliases: `tls.ja3` / `ja3`, `tls.ja4` / `ja4`, `tls.ja3s` / `ja3s`. The
fingerprints also appear in each TLS handshake's summary line, so free-text
search finds them too.

## BPF capture filters (`-f`)

Pass with `-f` at startup. These run in the kernel — packets that don't
match are never captured, which keeps CPU and memory low on busy networks.

### By protocol

```bash
netscope-tui -f "tcp"              # TCP only
netscope-tui -f "udp"              # UDP only
netscope-tui -f "icmp or icmp6"    # pings and errors
netscope-tui -f "arp"              # who-has chatter
```

### By port

```bash
netscope-tui -f "port 53"                  # DNS (queries and responses)
netscope-tui -f "tcp port 443"             # HTTPS
netscope-tui -f "tcp port 80 or tcp port 8080"   # HTTP
netscope-tui -f "portrange 8000-9000"      # dev servers
```

### By host

```bash
netscope-tui -f "host 192.168.1.10"        # to or from one machine
netscope-tui -f "src host 192.168.1.10"    # only packets it sends
netscope-tui -f "net 192.168.1.0/24"       # the whole subnet
```

### Combining

BPF supports `and`, `or`, `not`, and parentheses:

```bash
# HTTPS to one server
netscope-tui -f "tcp port 443 and host 140.82.121.4"

# Everything except SSH and DNS noise
netscope-tui -f "not port 22 and not port 53"

# DNS or any traffic with a specific host
netscope-tui -f "port 53 or host 10.0.0.5"
```

### Recipes

| Task | Filter |
|------|--------|
| "What is this device talking to?" | `host <device-ip>` |
| "Who is hammering my DNS?" | `port 53` |
| "Is anything unencrypted?" | `tcp port 80 or tcp port 21 or tcp port 23` |
| "Watch a single download" | `tcp port 443 and host <cdn-ip>` |
| "Local network gossip only" | `net 192.168.0.0/16 and not port 443` |
| "Pings only" | `icmp or icmp6` |

### Common mistakes

- **`-f "https"` doesn't work.** BPF knows ports, not application protocols.
  Use `tcp port 443`. (The TUI's live search *does* understand `tls` — it
  matches the dissected protocol name.)
- **Quotes matter.** Filters with spaces must be quoted: `-f "tcp port 443"`.
- **An invalid filter fails at startup** with the error from libpcap —
  netscope won't silently capture everything.

Full BPF reference: [biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)
or `man pcap-filter`.
