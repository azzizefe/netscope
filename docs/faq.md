# FAQ & Troubleshooting

## Capture problems

### "Failed to open interface" on Windows

Install [Npcap](https://npcap.com) with **"WinPcap API-compatible mode"**
checked during setup. Reboot if capture still fails after installing.

To verify Npcap is present:

```powershell
Test-Path "C:\Windows\System32\Npcap\wpcap.dll"   # should print True
```

### "Permission denied" on Linux

Either run with `sudo`, or grant the binary capture capabilities once:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which netscope-tui)
```

### "Permission denied" on macOS

Your user needs read access to the BPF devices:

```bash
sudo chmod +r /dev/bpf*        # until reboot
```

or run with `sudo`. Installing Wireshark's ChmodBPF package makes this
permanent.

### I see no packets at all

1. **Wrong interface.** Run `netscope-tui -D` and look for the one with your
   LAN IP (e.g. `192.168.x.x`). Pass it with `-i`. Without `-i`, netscope
   picks the connected interface with a routable address automatically —
   but VPNs can confuse the heuristic.
2. **A capture filter is eating everything.** An overly narrow `-f` filter
   silently matches nothing. Start without `-f`.
3. **VPN is active.** Traffic may flow through a TUN adapter instead of your
   Wi-Fi. Capture on the VPN adapter, or disconnect the VPN.

### I only see my own traffic, not other devices'

That's how modern networks work — switches and Wi-Fi access points only
deliver frames addressed to you. Promiscuous mode can't change what never
reaches your NIC. Seeing other devices requires a mirror port, an old hub,
or capturing on the router itself. netscope deliberately does not include
ARP-spoofing / MITM features.

## Display questions

### Why do some packets show a domain and others an IP?

netscope learns names **passively** from DNS responses it captures. If the
lookup happened before you started capturing (or the OS answered from its
cache), there's no DNS response to learn from, so you see the raw IP.
Start netscope first, then open the site — the name appears.

### What does "TLS — N bytes of encrypted data" mean?

Everything after the TLS handshake is encrypted; nobody on the wire (netscope
and Wireshark alike) can see inside. The useful part is the **SNI hostname**
in the ClientHello — netscope shows it as `TLS — github.com (HTTPS)`.

### Why does a "75B" packet say "1 byte of encrypted data"?

75 bytes is the whole frame (Ethernet + IP + TCP headers). The payload the
application actually sent is 1 byte — usually a TLS keep-alive.

### What is "WAN Miniport" / "Wi-Fi Direct Virtual Adapter"?

Windows creates virtual adapters for internal plumbing. They rarely carry
your traffic. netscope's auto-selection skips them; if you pass `-i`
manually, prefer your physical Wi-Fi or Ethernet adapter.

## Usage questions

### How do I save a capture and open it later?

```bash
netscope-tui -w session.pcap          # capture and save
netscope-tui -r session.pcap          # re-open later
```

Files are standard pcap — they open in Wireshark too, and netscope opens
files Wireshark saved.

### How do I use netscope in scripts?

```bash
netscope-tui --headless --json | jq 'select(.protocol == "DNS")'
```

One JSON object per line (JSON Lines). Fields: `timestamp`, `src`, `dst`,
`src_port`, `dst_port`, `protocol`, `length`, `summary`.

### How do I block a connection?

Switch to the **Connections** view (`Tab`), select a row with `j`/`k`, and
press `b`. netscope adds a Windows Firewall rule blocking all traffic to/from
that host; press `u` to remove it. This needs Administrator — launch netscope
elevated, or you'll see `⚠ not admin` in the status bar.

From the command line: `netscope-tui --list-blocked` shows what's blocked and
`netscope-tui --unblock-all` clears every netscope rule.

### Does blocking drop the packets I'm watching?

No. netscope captures passively, so it can't drop a packet already on the
wire. Blocking installs an OS firewall rule that stops **new** traffic to/from
that IP — the current connection dies on its next packet, and nothing new
reaches the host. The rules are named `netscope-block-<ip>` and persist until
you remove them (so they keep working after netscope closes).

### I blocked something by accident — how do I undo it?

Any of: press `u` on it in the Connections view, run
`netscope-tui --unblock-all`, or open **Windows Defender Firewall → Advanced
→ Outbound/Inbound Rules** and delete the `netscope-block-*` rules.

### Can netscope decrypt HTTPS?

Yes — if *you* supply the keys. netscope never breaks encryption; it only uses
key material you already have:

- **Key log — TLS 1.3 and 1.2** — set `SSLKEYLOGFILE` to the file your browser
  or `curl` writes, then run netscope with that variable set:
  ```bash
  export SSLKEYLOGFILE=~/tls-keys.log   # your browser writes this
  netscope-tui -i eth0
  ```
- **RSA private key — classic TLS 1.2 RSA handshakes** — point
  `TLS_RSA_PRIVATE_KEY` at a PEM file (PKCS#1 or PKCS#8):
  ```bash
  export TLS_RSA_PRIVATE_KEY=/path/to/server.key
  ```

This is the same mechanism Wireshark uses. Keys are read locally and never
leave your machine, and without them nothing is decrypted.

Key-log decryption covers TLS 1.3 (`CLIENT_TRAFFIC_SECRET_0`) and TLS 1.2
(`CLIENT_RANDOM`), including forward-secret **ECDHE** suites — which a server
private key can never recover.

**Supported TLS 1.2 suites:** AES-128/256-GCM (`0x009c`, `0x009d`, `0xc02b`,
`0xc02c`, `0xc02f`, `0xc030`) and ChaCha20-Poly1305 (`0xcca8`, `0xcca9`,
`0xccaa`) — covering the AEAD suites browsers actually negotiate. Legacy CBC
suites aren't decrypted, and QUIC decryption isn't supported; Wireshark covers
both.

If you have no keys, the SNI hostname, JA3/JA4 fingerprints and traffic
patterns still answer most "what is this app talking to?" questions.

### Does netscope work over SSH?

Yes — it's a terminal app. `ssh` into the machine and run it. This is the
main reason the TUI exists.

## Performance

### How many packets can it handle?

The dissector benchmarks at >100k packets/sec (`cargo test bench_dissect_throughput -- --nocapture`).
The TUI keeps the most recent 10,000 packets in memory and drops the oldest
beyond that — stats and flow counters keep counting everything.

### Memory keeps growing on long captures

Packet history is capped at 10k packets and hostname cache at 50k entries.
If you're writing to a file with `-w`, the file grows unbounded by design —
that's your capture.

## Still stuck?

[Open an issue](https://github.com/azzizefe/netscope/issues) with your OS,
netscope version, and the exact command you ran.
