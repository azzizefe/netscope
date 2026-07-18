<h1 align="center">netscope ⚡</h1>

<p align="center">
  <b>Network analysis for humans.</b> A modern, lightning-fast alternative to Wireshark.
  <br>
  One binary. Zero config. Beautiful by default.
</p>

<p align="center">
  <a href="#install"><img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-blue" alt="Platforms"></a>
  <img src="https://img.shields.io/badge/rust-1.95+-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <a href="https://github.com/azzizefe/netscope/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/azzizefe/netscope/ci.yml?branch=main&label=ci" alt="CI"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#why-netscope">Why netscope?</a> •
  <a href="#install">Install</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#keyboard-shortcuts">Keys</a> •
  <a href="#docs">Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

<br>

---

## Why netscope?

| | netscope | Wireshark |
|---|---|---|
| **Readability** | ✅ Plain-language summaries by default — `google.com → 142.250.74.46` | ⚪ Full protocol tree, but you decode the meaning yourself |
| **Setup** | ✅ One binary, sensible defaults, no profile to configure | ⚪ Powerful but heavy — lots of dialogs before you're productive |
| **Size** | ✅ ~8 MB TUI binary · ~7-10 MB desktop installer | ⚪ ~85 MB installer (Windows) |
| **Interprets your capture** | ✅ Automatic security & privacy findings, JA3/JA4, per-site X-ray | ❌ Shows everything, interprets nothing |
| **Acts on traffic** | ✅ Block a host live via a real OS firewall rule | ❌ Passive only, by design |
| **Protocol coverage** | ⚪ **178 protocols** — the common ones, plus industrial/automotive/telecom | ✅ **~3000** — unmatched breadth and decode depth |
| **TLS decryption** | ✅ TLS 1.3 + 1.2 AEAD (ECDHE, GCM & ChaCha20) via `SSLKEYLOGFILE` | ✅ Broader — also legacy CBC suites and QUIC |
| **Deep analysis** | ⚪ Summaries, Follow Stream, protocol tree | ✅ Decode-as, VoIP playback, IO graphs, Lua/C plugins |
| **Speed** | ✅ 100k+ pkt/s dissect throughput | ⚪ Can slow down on very large captures |

**netscope is to Wireshark what `bat` is to `cat`.** Not a replacement for Wireshark's
depth — the tool you open *first*, that answers 90% of questions in seconds and
tells you what the traffic actually means. For exotic protocol internals, full
decryption or forensic depth, Wireshark is still the reference.

---

## Features

- **🗂 178 protocols out of the box** — from everyday (DNS, HTTP/2, TLS, QUIC, SMB) to
  industrial (Modbus, S7comm, PROFINET, EtherCAT, IEC 61850 GOOSE/SV, KNX, HART-IP),
  automotive (SOME/IP, DoIP, XCP, AVTP), telecom (PFCP, GTP, Diameter, Megaco, Skinny),
  healthcare/finance (DICOM, HL7, FIX) and cloud infra (Kafka, NATS, gRPC, ZeroMQ,
  Elasticsearch). Protocols on dynamic ports — DTLS, DDS/RTPS, FIX, SPICE, BitTorrent
  DHT — are recognised by their wire signature, not just a port number.
- **🧠 Human-readable summaries** — DNS domains, TLS SNI hostnames, HTTP paths. Not hex.
- **🌐 Passive hostname resolution** — Watches DNS responses and shows `github.com:443` instead of a bare IP. No lookups of its own, zero added traffic.
- **⛔ Block traffic, live** — See a connection you don't like? Select it and press `b`. netscope installs a real OS firewall rule to cut it off. Wireshark can't do that.
- **🎓 Built-in Learn mode** — Never used a packet analyzer? A dedicated view explains every protocol in plain language, and each selected packet gets a one-line "what is this?". No prior networking knowledge needed.
- **🎯 Zero-config interface pick** — Skips loopback and virtual adapters (WAN Miniport, Hyper-V) and lands on your real Wi-Fi/Ethernet automatically.
- **🌐 Multi-interface capture** — Capture on several interfaces at once, merged into one stream (Wireshark-style). Pick **🌐 All interfaces** in the desktop, or pass a comma-separated list to the TUI (`-i "Wi-Fi,Ethernet"`). Each interface is dissected on its own core, so mixed link types (Ethernet + Wi-Fi) just work.
- **🖧 Remote capture over SSH** — Capture from another machine without installing anything on it: netscope runs `tcpdump` on the remote host over SSH and streams the packets back live (Wireshark's *sshdump*). Desktop: **Capture ▸ Remote capture (SSH)…**; TUI: `--remote-host 192.168.1.1 --remote-user root`. Key/agent auth only — no passwords typed into the app.
- **🧩 External & piped sources (extcap-style)** — Any tool that writes pcap/pcapng to stdout is a capture source. The TUI reads a live stream from stdin (`ssh host "tcpdump -U -w -" | netscope-tui -i -`), and both classic pcap and pcapng streams are parsed incrementally.
- **🔌 USB · Bluetooth · CAN capture** — Beyond the network stack: dissects USB traffic (Linux *usbmon*, Windows **USBPcap** — auto-listed as `\\.\USBPcap1`), Bluetooth **HCI** (commands/events, LE advertising & connects) and **CAN bus** (SocketCAN, classic + CAN FD). Hardware-bus interfaces are badged `[USB]`/`[BT]`/`[CAN]` in the picker, and `usb`/`bluetooth`/`can` are display-filter predicates.
- **⏱ Autostop conditions** — Stop a capture automatically at a limit: duration, packet count, or captured size. Desktop: **Capture ▸ Options**; TUI: `-a duration:60 -a packets:10000` (repeatable, Wireshark's `-a`). Works across every interface of a multi-interface capture.
- **♻️ Ring-buffer capture files** — Long-running capture without filling the disk: rotate the save file by size or time and keep only the last *N* files (Wireshark's `-b`). Desktop: **Capture ▸ Options**; TUI: `-b filesize:2048 -b files:10`. Files are timestamp-named so a set sorts chronologically.
- **🔬 Wireshark-style inspector** — The desktop app has the classic three-pane layout: colorized packet list, an expandable protocol tree (Frame → IP → TCP → app layer), and a live hex/ASCII byte view — plus a plain-language "What is this?" for every packet.
- **🌍 Where is it going?** — Click a packet and the inspector shows the remote host's **country (with flag), city, and owning organisation** (e.g. `🇺🇸 United States · Google LLC`). Point it at an **offline MaxMind database** (free GeoLite2 `.mmdb`) and lookups resolve **entirely on your machine** — private, offline, no network calls. Looked up on demand only for the packet you open, and cached per IP.
- **💬 Follow Stream** — In the Connections view, press **Follow** on any TCP/UDP conversation to read it reassembled as plain text, color-coded by direction (client vs. server) — Wireshark's most-used feature, one click away.
- **⚠ Expert Info** — Packets the dissector flags as a reset or malformed connection get a small warning badge in the packet list and detail view, in plain language (no "duplicate ACK" jargon).
- **🛡 Insights — automatic security & privacy scan** — The thing Wireshark won't do: it shows you everything but interprets nothing. The **🛡 Insights** tab reads your capture and surfaces plain-language findings — cleartext passwords, unencrypted HTTP, possible port scans, connection-reset bursts, suspicious/DGA-looking domains, plaintext DNS exposure, and an encrypted-vs-cleartext ratio — each rated high / warning / info. No rules to write, no columns to configure.
- **🔑 TLS fingerprinting (JA3 / JA4 / JA3S)** — Every TLS handshake is fingerprinted: **JA3** and the modern **JA4** for the client, **JA3S** for the server. They show up in the packet summary and are first-class filter fields (`ja3 == …`, `ja4 contains "t13d"`, `ja3s == …`), so you can hunt a malicious client or C2 server by *how* it speaks TLS — even though the payload is encrypted. Wireshark needs a plugin for this; netscope does it out of the box, offline.
- **🔓 TLS decryption (opt-in, local)** — Supply the keys and netscope reads the plaintext:
  set `SSLKEYLOGFILE` to the key log your browser or `curl` already writes — covering
  **TLS 1.3 and TLS 1.2, including forward-secret ECDHE** — or `TLS_RSA_PRIVATE_KEY` to a
  PEM private key for classic TLS 1.2 RSA handshakes. Same approach Wireshark uses: keys
  are read locally, never leave your machine, and nothing is decrypted without them.
- **↻ Replay (Repeater)** — Open a packet and press **↻ Replay** to reload its payload into an editor, tweak it, point it at a host/port, and resend it over a fresh socket — the response comes back in the same window. No exporting to Packet Sender or Burp Repeater. *Sends real traffic — for authorised testing only.*
- **⚡ Script console** — An in-app **⚡ Script** tab runs JavaScript directly over the captured packet stream. Instead of exporting a `.pcap` and re-reading it with Python/Scapy, every packet is already a `packets` array you can filter, aggregate, and flag anomalies on — with `Ctrl+Enter` to run and built-in examples (connection-reset anomalies, top talkers, unencrypted-secret scanning, suspicious DNS domains).
- **🗂 Profiles** — The **🗂 Profile** button (top right) saves task presets — a filter, a starting view, and display settings — the way Wireshark's Configuration Profiles do. Ships with **HTTP Analysis**, **VoIP**, and **Security Review** presets, plus "Save current as…" for your own. Persists across restarts.
- **🕐 Time Display Format** — Same menu: switch between `Time of Day`, full `Date and Time of Day`, or `Seconds Since Beginning of Capture` (relative to the first packet) — matches Wireshark's View > Time Display Format.
- **🏷 Name Resolution toggle** — Turn passive hostname resolution off to see raw IPs everywhere (and shave a little rendering work on very large captures), or back on for `github.com` instead of `140.82.112.3`.
- **🎨 Beautiful TUI** — Protocol-colored rows, dark theme, smooth layout. Ships with taste.
- **📊 Live dashboard** — Bandwidth, top talkers, protocol distribution. Updated in real time.
- **📋 DNS log view** — See every queried domain at a glance.
- **🔍 Smart filter** — Type anything — IP, protocol, domain — results update instantly.
- **🖥️ Headless mode** — Pipe-friendly `--json` output for scripts and integrations.
- **📂 Read/write pcap** — Analyze saved captures, save live ones for later.
- **⚡ Blazing fast** — Rust-native. 10k+ packets/sec without breaking a sweat.
- **🖥️ Desktop app** — Same engine, native GUI via Tauri. Bundles for Windows/macOS/Linux.

### 🖥️ Desktop analysis suite

The desktop app layers a full analysis workbench on top of the capture engine — all of it running locally over the packets you already captured, no cloud, no extra traffic:

**Visualise & monitor**
- **🕸 Topology map** — A live force-directed graph of who talks to whom. Node size = traffic, green = local, blue = remote; Fit / Freeze controls.
- **📊 Live "Grafana-style" dashboard** — Per-second tiles with 60-second sparklines: throughput, packets/sec, error rate, active hosts, plus top-10 talkers.
- **📈 Predictive traffic modeling** — Projects bandwidth ~5 minutes ahead from the recent trend (least-squares), with a rising/steady/falling read.
- **🔀 Traffic diff** — Snapshot A (baseline) vs. Snapshot B (later) and see the delta — which protocols and hosts appeared, grew, or vanished (`NEW`/`GONE`).

**Understand a packet**
- **🧩 Semantic parsing** — Translates a packet into business logic: *"Client asked example.com to GET /login"*, *"Request requires authentication (401)"*, *"Starting an encrypted session (TLS ClientHello)"*.
- **✨ Payload beautifier** — JSON and XML bodies rendered as a syntax-coloured, collapsible tree.
- **🔮 Protocol guesser** — For traffic the dissector can't name, guesses the protocol from port hints, byte magic, printable ratio and Shannon entropy — and shows its reasoning and a confidence score.
- **🌐 Threat-intel pivots** — One-click reputation links (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan) for any public IP. No silent calls to paid feeds.
- **🧬 Hex → code** — Copy a payload's bytes as a C, Rust, or Python literal.

**Privacy & site health**
- **🔎 Privacy X-ray** — Groups traffic by site and answers *"what is this site taking from me, and what runs in the background?"* — what you send it (cookies, User-Agent, Referer, form data, email, location), the trackers/ad networks it calls behind your back (classified: Advertising / Analytics / Social / CDN), the cookies it sets on you (tracking cookies and weak `Secure`/`HttpOnly`/`SameSite` flags flagged), and how much of your data — up and down — it cost, with a meter for the share that went to trackers. HTTPS hides content, not this metadata.
- **🛡 WAF detection** — Fingerprints the Web Application Firewall in front of a site (Cloudflare, Akamai, Imperva Incapsula, AWS, F5 BIG-IP, Sucuri, ModSecurity…) from response headers/cookies, with a labelled "likely" guess when only the fronting CDN is visible.
- **🚫 HTTP error explainer** — Groups 4xx/5xx responses per site and says *why* in plain words (403 = permissions/geo/WAF block, 429 = rate limit, 502 = backend down…).
- **⏰ Busiest period** — A Dashboard card showing when traffic peaked (and, for long captures, the busiest hour-of-day).
- **🎯 Contextual risk score** — A transparent 0–100 exposure score per site (cleartext, credentials, trackers, weak cookies, errors).
- **🐛 Service-CVE flags** — Matches cleartext `Server:` headers against a small set of known-vulnerable versions.
- **📋 Quick summary** — A short plain-language TL;DR of the whole capture (top sites, trackers, WAF, errors, busiest time, top findings), separate from the full Markdown report.

**Detect & hunt**
- **🧷 Signature scan (YARA-lite)** — Payloads matched against readable IOC/attack signatures: Log4Shell, Shellshock, reverse shells, SQLi, directory traversal, scanner User-Agents, EICAR.
- **📤 Data-exfiltration (DLP)** — Flags unusually large outbound transfers from a local host to a single external destination.
- **📶 Threat-actor heuristics** — Beaconing (regular check-in intervals) and suspect-port detection — honest "worth a look" flags, not attribution.
- **💡 One-click exploit demo** — Each exploitable finding gets a plain-language attack scenario **and** the fix. Educational.
- **🔔 Smart alerts & triggers** — Proactive alerts on traffic spikes and error bursts, plus your own IFTTT-style rules (*host contains X → alert*), persisted.

**Workflow & sharing**
- **🧭 Workspace modes** — Self-configuring presets (Web Dev, Kernel / Driver Dev, IoT, Malware Analysis) that set filter + view + timestamps + noise filter in one click.
- **🧹 Zero-touch noise filter** — Hide OS-update, telemetry and discovery chatter so the list shows what your app is actually doing.
- **📄 Shareable report** — One-click Markdown summary (findings, protocol breakdown, talkers, domains, dependency map) with **🛡 secret scrubbing** and **🕶 IP anonymisation** for GDPR/KVKK-safe sharing.
- **🗺 Dependency map** — Automatically groups the external services a host reaches (Google, AWS/CloudFront, Cloudflare, …).
- **↻ Replay (Repeater)** — Resend a packet's payload to a target and read the response. *Sends real traffic — authorised testing only.*
- **🎨 Themes** — Midnight, VS Code Dark+, Dracula, Nord, and a Daylight light mode.

---

## Install

netscope ships in two flavors: a **desktop app** (native window, no terminal)
and a **terminal UI** (TUI). Both share the same engine.

> [!WARNING]
> **Windows users:** You **must** install **[Npcap](https://npcap.com)** before
> running netscope (both desktop and TUI). During installation, tick
> **☑ "Install Npcap in WinPcap API-compatible mode"**. Without it, netscope
> cannot see any network interfaces and capture will fail silently.
>
> 👉 **Download:** [npcap.com](https://npcap.com) (free for personal use)

> [!NOTE]
> **Linux users:** Install `libpcap` via your package manager
> (`sudo apt install libpcap-dev` on Debian/Ubuntu, `sudo dnf install libpcap-devel` on Fedora).
> **macOS** ships libpcap by default — no extra install needed.

### 🖥️ Desktop app — what you need to run it

1. **Npcap** (Windows) — the driver that lets any app read packets. Install from
   [npcap.com](https://npcap.com) with **"WinPcap API-compatible mode"** ticked. *(macOS/Linux don't need this.)*
2. **WebView2** (Windows) — pre-installed on Windows 10/11; renders the window.
3. **Run as Administrator** — capturing packets and installing block rules both
   need it. Right-click → *Run as administrator*. Without it you'll see a `⚠ not admin` badge.

Then download the installer for your OS from [Releases](https://github.com/azzizefe/netscope/releases):

| OS | File |
|----|------|
| **Windows** | `netscope_x.y.z_x64-setup.exe` |
| **macOS** | `netscope_x.y.z_universal.dmg` |
| **Linux** | `.AppImage` or `.deb` |

Full details in the [Desktop Guide](docs/desktop.md).

### ⌨️ Terminal UI

Grab the prebuilt `netscope-tui` binary for your OS from
[Releases](https://github.com/azzizefe/netscope/releases), or build from source (below).

| Platform | Requirement |
|----------|-------------|
| **Windows** | [Npcap](https://npcap.com) (WinPcap-compatible mode) |
| **macOS** | No setup needed |
| **Linux** | `sudo setcap cap_net_raw,cap_net_admin+eip $(which netscope-tui)` (capture without root) |

### Build from source

Building from source requires **Rust 1.75+** and the platform-specific packet
capture library headers.

#### Prerequisites

<details>
<summary><b>🪟 Windows</b></summary>

1. **Npcap** — Install from [npcap.com](https://npcap.com) with both
   **"WinPcap API-compatible mode"** and **"Install Npcap SDK"** ticked.
2. **Npcap SDK** — If the SDK wasn't installed alongside the driver, download
   it separately from [npcap.com/dist](https://npcap.com/dist/npcap-sdk-1.13.zip)
   and extract it. Then set the environment variable so the `pcap` crate can
   find it:
   ```powershell
   # PowerShell — adjust the path to where you extracted the SDK
   $env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
   ```
3. **WebView2** — Pre-installed on Windows 10/11 (needed for the desktop app).
4. **Visual Studio Build Tools** — `rustup` on Windows needs the MSVC toolchain.
   Install "Desktop development with C++" from
   [visualstudio.microsoft.com](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

</details>

<details>
<summary><b>🐧 Linux (Debian / Ubuntu)</b></summary>

```bash
# Packet capture library + Tauri desktop dependencies
sudo apt update
sudo apt install -y \
  libpcap-dev \
  build-essential \
  pkg-config \
  libssl-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

> **Note:** `libwebkit2gtk-4.1-dev` and the GTK packages are only needed if you
> want to build the **desktop app**. For the TUI alone, `libpcap-dev` and
> `build-essential` are sufficient.

</details>

<details>
<summary><b>🐧 Linux (Fedora / RHEL)</b></summary>

```bash
sudo dnf install -y \
  libpcap-devel \
  gcc \
  openssl-devel \
  gtk3-devel \
  webkit2gtk4.1-devel \
  libappindicator-gtk3-devel \
  librsvg2-devel
```

</details>

<details>
<summary><b>🐧 Linux (Arch)</b></summary>

```bash
sudo pacman -S --needed \
  libpcap \
  base-devel \
  openssl \
  gtk3 \
  webkit2gtk-4.1 \
  libappindicator-gtk3 \
  librsvg
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

macOS ships `libpcap` out of the box — no extra packages needed.

If you want to build the desktop app, install Xcode Command Line Tools:

```bash
xcode-select --install
```

</details>

#### Build & Run

```bash
git clone https://github.com/azzizefe/netscope.git
cd netscope

# TUI only
cargo build --release -p netscope-tui
./target/release/netscope-tui

# Desktop app (run as admin on Windows for packet capture)
cargo tauri dev                       # development mode
cargo tauri build                     # production bundle
```

#### Post-install (Linux) — capture without root

```bash
# Grant raw-socket capability so you don't need sudo every time
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/netscope-tui
```

#### Verify your build

```bash
cargo test -p netscope-core -p netscope-tui   # run the engine + TUI tests (~630)
cd desktop/frontend-tests && npm test  # run frontend tests (74 tests)
```

---

## Quick Start

```bash
# Launch TUI (auto-selects interface)
netscope-tui

# Capture on specific interface with a BPF filter
netscope-tui -i eth0 -f "tcp port 443"

# Analyze a saved pcap file
netscope-tui -r capture.pcap

# Pipe JSON output to jq
netscope-tui -i eth0 --headless --json | jq '.summary'
```

---

## Usage

### CLI Options

```
Usage: netscope-tui [OPTIONS]

  -i, --interface <IFACE>    Interface(s) to capture on — comma-separated for
                             several; "-" reads a pcap stream from stdin;
                             "\\.\USBPcap1" captures USB (Windows)
  -r, --read <FILE>          Read from a pcap file
  -w, --write <FILE>         Save capture to pcap file
  -f, --filter <BPF>         BPF filter (e.g. "tcp port 443")
      --monitor              Capture raw 802.11 Wi-Fi in monitor mode
                             (needs a monitor-capable adapter; not on Windows)
  -a, --autostop <COND>      Stop automatically (repeatable): duration:SECONDS,
                             packets:COUNT or filesize:kB
  -b, --ring <COND>          Ring-buffer the -w file (repeatable): filesize:kB,
                             duration:SECONDS, files:COUNT
      --remote-host <HOST>   Capture on a remote host over SSH (runs tcpdump
                             there, streams the pcap back — sshdump-style)
      --remote-user <USER>   SSH user for --remote-host
      --remote-port <PORT>   SSH port for --remote-host
      --remote-identity <F>  SSH private-key file for --remote-host
      --remote-interface <I> Remote interface to capture on (default: any)
      --remote-command <CMD> Remote command override (must write pcap to stdout)
      --remote-sudo          Run the remote capture command with sudo
      --colors <FILE>        Coloring rules file (see below)
  -D, --list-interfaces      List available interfaces
      --headless             Plain text output to stdout
      --json                 JSON Lines output (implies --headless)
      --list-blocked         List IPs blocked by netscope firewall rules
      --unblock-all          Remove all netscope block rules and exit
  -h, --help                 Print help
```

**Examples**

```bash
# Stop after 60 seconds OR 10k packets, whichever comes first
netscope-tui -i eth0 -a duration:60 -a packets:10000

# Long capture, rotating: 2 MB files, keep the last 10
netscope-tui -i eth0 -w rolling.pcap -b filesize:2048 -b files:10

# Capture from a remote host over SSH (needs key/agent auth + tcpdump there)
netscope-tui --remote-host 192.168.1.1 --remote-user root -f "not port 22"

# Pipe any extcap-style source in via stdin
ssh gw "tcpdump -U -w -" | netscope-tui -i - --headless
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate packet list |
| `Enter` | Expand/collapse packet details |
| `Tab` / `Shift+Tab` | Switch views |
| *(any character)* | Filter packets — display-filter syntax or free text (type directly) |
| `b` / `u` | *(Connections view)* Block / unblock the selected remote host |
| `Space` | Pause / resume capture |
| `h` | Toggle hex dump |
| `?` | Help overlay |
| `Esc` | Clear filter / close help |
| `q` | Quit |

### Display Filters

The filter box speaks a **Wireshark-style display-filter language** — and falls
back to plain substring search when what you type isn't a filter expression, so
you can always just type a keyword.

```
ip.addr == 1.2.3.4            # either endpoint is this IP
ip.src == 10.0.0.5            # source only (also ip.dst)
tcp.port == 443              # TCP on port 443 (also udp.port, port)
frame.len > 1000             # packets larger than 1000 bytes (also len)
dns                          # bare protocol name — any of the 178 supported protocols
                             # (tcp, udp, http, tls, quic, dns, ssh, smb, rdp, sip, rtp,
                             #  modbus, s7comm, profinet, ethercat, goose, knx, dicom, hl7,
                             #  fix, someip, doip, pfcp, gtp, diameter, kafka, nats, dds…)
http && ip.dst == 8.8.8.8    # combine with &&, ||, !  (and / or / not)
tcp && (tls || dns)          # parentheses group
ip.dst contains "142.250"    # substring match on a field
```

`tcp` matches TCP transport (so it also catches HTTP and TLS), just like
Wireshark; `http` matches the HTTP application protocol specifically.

### Coloring Rules

Both UIs tint packet rows with **display-filter driven coloring rules**
(Wireshark's View > Coloring Rules), checked top-down — the first match wins:

- **Desktop** — View > 🎨 Coloring rules…: add/edit/reorder rules in place;
  they persist across sessions.
- **TUI** — rules load from `~/.config/netscope/colors` (Linux/macOS) or
  `%APPDATA%\netscope\colors` (Windows), or from `--colors <file>`. One rule
  per line — a hex colour followed by any display filter:

  ```
  # first match wins; '#' starts a comment
  ef4444 tcp.flags.rst == 1 || info contains "Malformed"
  f97316 http.response.code >= 400
  22d3ee ip.addr == 192.168.1.42
  ```

Without a file, both UIs ship the same defaults: bad TCP red, HTTP errors
orange, handshakes grey, DNS purple, ICMP amber, ARP grey.

### Views

| View | Description |
|------|-------------|
| **Packets** | Live packet stream with human-readable summaries. Selecting a packet opens the inspector: protocol tree, semantic "what happened", JSON/XML beautifier, protocol guess, threat-intel pivots, and hex→code |
| **Dashboard** | *(desktop)* Live "Grafana-style" tiles (throughput, packets/sec, error rate, active hosts) with sparklines, bandwidth projection, protocol distribution, and top-10 talkers |
| **Connections** | Conversations grouped by flow — packets, bytes, direction, duration per connection. Press **💬 Follow** to read the conversation as plain text, or `b` to **block** the remote host via an OS firewall rule (`u` to unblock). |
| **Topology** | *(desktop)* Live node/edge map of who talks to whom — traffic-sized nodes, local vs. remote colouring |
| **DNS Log** | All DNS queries and responses in one place |
| **Insights** | *(desktop)* Automatic security & privacy analysis — cleartext secrets, scans, signature matches, data-exfiltration, beaconing, encryption ratio — each rated by severity with a "how could this be exploited?" teaching expander |
| **Privacy** | *(desktop)* Per-site X-ray — what each site collects from you, the trackers it calls in the background, the cookies it sets, and how much of your data it costs |
| **Diff** | *(desktop)* Compare two capture snapshots and highlight the delta (what appeared, grew, or vanished) |
| **Script** | *(desktop)* Write JavaScript over the captured packets — filter, aggregate, and flag anomalies without exporting to a file |
| **Learn** | Plain-language guide to every protocol netscope shows, plus a glossary and how-to cards for every feature — for people new to networking |

---

## Docs

Full index: [docs/README.md](docs/README.md)

| Document | What it covers |
|----------|---------------|
| [Setup Guide](docs/setup.md) | Prerequisites, build instructions, troubleshooting |
| [TUI Guide](docs/tui.md) | CLI flags, views, colors, keyboard shortcuts, headless mode |
| [Filter Cookbook](docs/filters.md) | Ready-to-paste BPF filters for common tasks |
| [FAQ & Troubleshooting](docs/faq.md) | Common problems and their fixes |
| [Kullanım Kılavuzu (Türkçe)](docs/KULLANIM.md) | Kurulum, gereksinimler (Npcap vb.), tüm özellikler, sorun giderme |
| [Architecture](docs/architecture.md) | Crate layout, data flow, dispatch chain, CI/CD |
| [Core API](docs/core.md) | Packet, Protocol, CaptureEngine, StatsEngine, NameCache, dissectors |
| [Dissector Guide](docs/dissectors.md) | Summary conventions, dispatch logic, how to add |
| [Desktop Guide](docs/desktop.md) | Tauri commands, frontend, build instructions, icons |
| [CI/CD Guide](docs/ci-cd.md) | Pipeline details, release process, adding platforms |

---

## Project Structure

```
netscope/
├── crates/
│   ├── core/           Capture engine, protocol dissectors, models, stats
│   ├── tui/            Terminal UI (ratatui + crossterm + clap)
│   ├── wasm/           WASM bindings (display filter engine for frontend)
│   └── python/         Python bindings (PyO3)
├── desktop/
│   ├── frontend/       Desktop frontend (HTML/CSS/JS + ES modules)
│   ├── frontend-tests/ Vitest unit tests for the frontend
│   └── src-tauri/      Tauri 2 backend (Rust)
├── fixtures/           8 sample .pcap files for testing
├── docs/               Architecture, API, guides (10+ files)
├── tools/gen-fixtures/ pcap generator (etherparse)
└── .github/workflows/  CI + Release pipelines
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Capture** | `pcap` crate (libpcap / Npcap) |
| **Packet parsing** | `etherparse` + custom dissectors |
| **DNS parsing** | `dns-parser` |
| **TUI** | `ratatui` + `crossterm` |
| **CLI** | `clap` |
| **Concurrency** | `crossbeam-channel` |
| **Desktop** | Tauri (vanilla HTML/CSS/JS) |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Bug reports](.github/ISSUE_TEMPLATE/bug_report.md)
- [Feature requests](.github/ISSUE_TEMPLATE/feature_request.md)

---

<p align="center">
  Built with ❤️ and 🦀
  <br>
  <a href="https://github.com/azzizefe/netscope">GitHub</a> •
  <a href="https://github.com/azzizefe/netscope/releases">Releases</a> •
  <a href="#netscope-">Back to top</a>
</p>
