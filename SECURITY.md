# Security Policy

## Supported versions

netscope is pre-1.0 software. Security fixes are applied to the latest
released version and `main`. Older tags are not maintained.

| Version | Supported |
|---|---|
| latest release / `main` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/azzizefe/netscope/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). This keeps
the details confidential until a fix is available.

Please include:

- affected component (core dissector, TUI, desktop, capture, etc.)
- a description of the impact and, where possible, a minimal reproduction
  (a small `.pcap`/`.pcapng` or crafted input is ideal)
- the version or commit you tested

You can expect an initial acknowledgement within a few days. Once a fix is
ready, a coordinated disclosure will be arranged and reporters will be
credited unless they prefer to remain anonymous.

## Scope and threat model

netscope parses **untrusted network data** — packet captures and live
traffic that an attacker may fully control. The following are in scope:

- memory-safety or panic-based denial of service in any dissector or parser
  when fed malformed input
- crashes, hangs, or unbounded resource use while reading capture files
- issues in the decryption paths (WEP / WPA-CCMP, TLS key material handling)

Out of scope: vulnerabilities in third-party capture drivers (e.g. Npcap),
the operating system, or the elevated privileges required for live capture.
Running a live capture requires administrative/root privileges by design.
