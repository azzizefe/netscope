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

Press `Esc` to clear. That's the whole syntax.

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
