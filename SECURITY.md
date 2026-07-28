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

## Fleet deployment (`netscope-server`, `netscope-agent`)

Two things fail closed rather than degrading quietly. Both will stop a
deployment that has not been configured, which is deliberate.

### The server will not start without a JWT secret

Set `[server.jwt] secret` in the config file, or pass `--jwt-secret`. There is
no default. A generated secret would appear to work and then not: sessions end
at every restart, and two instances behind a load balancer reject each other's
tokens, which surfaces to users as intermittent "invalid or expired token" with
nothing in the logs to explain it.

`--dev-insecure-jwt` generates a throwaway secret for local development. It logs
a warning on every start and must not be used anywhere else.

### The agent will not install an unsigned binary

The agent can replace its own executable and restart into it, which is code
execution as whatever account runs the sensor. The SHA-256 in the upgrade
response does not protect that: it arrives in the same response as the download
URL, so anything that can serve the binary can serve a matching digest. Only the
signature decides.

The public key is compiled in, not read from disk — a key in a config file is
swappable by anyone who can write that file, which on an already-compromised
host is the attacker, and it would then verify their own signature.

Generate a key pair once and keep the secret half offline or in the release
pipeline's secret store:

```bash
minisign -G -p netscope-agent.pub -s netscope-agent.key
```

Build agents with the public half:

```bash
NETSCOPE_AGENT_UPDATE_PUBKEY="$(tail -n1 netscope-agent.pub)" cargo build -p netscope-agent --release
```

Sign each released binary and serve the signature as the `signature` field of
`/api/v1/upgrade/check`:

```bash
minisign -S -s netscope-agent.key -m netscope-agent
```

An agent built without `NETSCOPE_AGENT_UPDATE_PUBKEY` logs that automatic
upgrades are off and never checks again; upgrade those sensors out of band.
Rotating the key means rebuilding and redeploying the agents — that is the cost
of the key not being swappable at runtime.
