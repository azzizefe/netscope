// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Documented security risks of individual protocols.
//!
//! This is deliberately **not** derived from the registry. Risk is a property
//! of a protocol, not of its category: HTTP and HTTPS sit in the same category
//! and have opposite risk profiles, as do Modbus and OPC UA. A note generated
//! from a category would be wrong for at least one member of every pair, and a
//! wrong security claim costs more than a missing one — it teaches the reader
//! to distrust the findings that *are* right.
//!
//! So [`risk`] returns [`Option`], and the answer for most protocols is
//! `None`. Callers show nothing in that case. There is no generic filler entry
//! and there should never be one: a panel that always has something to say is
//! a panel nobody reads.
//!
//! Every entry names what is actually wrong, when it applies, what to do
//! instead, and the document that says so.

use crate::models::Protocol;

/// How much the risk matters, for ordering and colouring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    /// Credentials or payload are readable by anyone on the path, or the
    /// protocol grants control with no authentication at all.
    Critical,
    /// Broken or withdrawn cryptography, or an abusable amplification vector.
    High,
    /// Exploitable in the right position on the network — spoofing, poisoning,
    /// downgrade.
    Medium,
    /// Worth knowing, not itself a vulnerability.
    Info,
}

impl RiskSeverity {
    pub fn label(self) -> &'static str {
        match self {
            RiskSeverity::Critical => "Critical",
            RiskSeverity::High => "High",
            RiskSeverity::Medium => "Medium",
            RiskSeverity::Info => "Info",
        }
    }
}

/// A documented weakness of one protocol.
#[derive(Debug, Clone, Copy)]
pub struct Risk {
    pub severity: RiskSeverity,
    /// One line, the finding itself.
    pub headline: &'static str,
    /// Why it is true and when it applies.
    pub detail: &'static str,
    /// What to do instead.
    pub mitigation: &'static str,
    /// The document that says so — an RFC, a CVE, or a vendor advisory.
    pub reference: &'static str,
}

/// The documented risk of `proto`, if it has one.
///
/// `None` means "nothing specific to say", which is the correct answer for the
/// overwhelming majority of the registry. It is not a gap to be filled.
pub fn risk(proto: &Protocol) -> Option<Risk> {
    use Protocol as P;
    Some(match proto {
        // ── Credentials in the clear ────────────────────────────────────────
        P::Telnet => Risk {
            severity: RiskSeverity::Critical,
            headline: "Passwords travel in plain text",
            detail: "Telnet has no encryption at all. The login name and password \
are sent as readable characters, one keystroke per packet, so anyone who can \
see the traffic — a switch span port, a compromised router, shared Wi-Fi — \
reads them directly out of the capture.",
            mitigation: "Replace with SSH. If a device offers only Telnet, reach it \
over an out-of-band management network that no user traffic touches.",
            reference: "RFC 854; NIST SP 800-42 recommends against Telnet on any network",
        },
        P::Ftp => Risk {
            severity: RiskSeverity::Critical,
            headline: "Credentials and files are unencrypted",
            detail: "The USER and PASS commands carry the login in plain text, and \
the data channel is unencrypted too. FTP also opens a second connection on a \
negotiated port, which is why it needs firewall helpers that have their own \
history of being abused.",
            mitigation: "Use SFTP (over SSH) or FTPS. Plain FTP is acceptable only for \
genuinely public, anonymous downloads.",
            reference: "RFC 959; RFC 2577 'FTP Security Considerations'",
        },
        P::Pop3 => Risk {
            severity: RiskSeverity::Critical,
            headline: "Mailbox password sent in the clear without TLS",
            detail: "On port 110 without STARTTLS, the USER/PASS exchange and every \
retrieved message are readable on the wire.",
            mitigation: "Use POP3S (port 995) or require STARTTLS before authenticating.",
            reference: "RFC 1939; RFC 2595 for the TLS variant",
        },
        P::Imap => Risk {
            severity: RiskSeverity::Critical,
            headline: "Mailbox password sent in the clear without TLS",
            detail: "On port 143 without STARTTLS, LOGIN carries the password as \
readable text and message bodies are unencrypted. IMAP keeps the connection \
open far longer than POP3, so there is more to capture.",
            mitigation: "Use IMAPS (port 993), or refuse LOGIN until STARTTLS has \
succeeded.",
            reference: "RFC 3501; RFC 2595",
        },
        P::Smtp => Risk {
            severity: RiskSeverity::High,
            headline: "Mail and AUTH credentials are readable without STARTTLS",
            detail: "SMTP begins unencrypted and only upgrades if both sides offer \
STARTTLS. An attacker in the path can strip the STARTTLS capability from the \
server's greeting, and the client will silently continue in plain text.",
            mitigation: "Require STARTTLS and refuse to send if it is unavailable. \
MTA-STS and DANE stop the downgrade.",
            reference: "RFC 5321; RFC 3207; RFC 8461 (MTA-STS)",
        },
        P::Http => Risk {
            severity: RiskSeverity::High,
            headline: "Everything is readable and modifiable in transit",
            detail: "URLs, headers, cookies, form posts and responses are all plain \
text. Anyone on the path can read session cookies and reuse them, or alter the \
response — injecting content into an unencrypted page needs no key.",
            mitigation: "Serve over HTTPS and send HSTS so browsers refuse the plain \
version afterwards.",
            reference: "RFC 9110; RFC 6797 (HSTS)",
        },
        P::Snmp => Risk {
            severity: RiskSeverity::Critical,
            headline: "v1 and v2c authenticate with a plain-text community string",
            detail: "The community string is the entire authentication, it is sent \
unencrypted in every packet, and the defaults ('public' for read, 'private' for \
write) are still common. A write community grants configuration changes on the \
device.",
            mitigation: "Use SNMPv3 with authPriv. If v2c cannot be avoided, make it \
read-only, restrict it by source address, and never leave the defaults.",
            reference: "RFC 3410; CISA ICS advisories on default community strings",
        },
        P::Ldap => Risk {
            severity: RiskSeverity::High,
            headline: "Simple bind sends the password in the clear",
            detail: "An LDAP simple bind on port 389 without TLS carries the \
distinguished name and password unencrypted. In a directory this is very often \
a domain account.",
            mitigation: "Use LDAPS, or StartTLS before binding. Prefer SASL binds \
over simple binds.",
            reference: "RFC 4511; RFC 4513 'Authentication Methods and Security Mechanisms'",
        },
        P::Tftp => Risk {
            severity: RiskSeverity::Critical,
            headline: "No authentication whatsoever",
            detail: "TFTP has no concept of a user. Anyone who can reach the server \
can read any file it serves and, if writes are enabled, replace them. It is \
routinely used to distribute switch and phone configurations, which contain \
credentials.",
            mitigation: "Confine it to an isolated provisioning VLAN, make it \
read-only, and remove it when provisioning is done.",
            reference: "RFC 1350 — the specification itself notes the absence of access control",
        },
        P::Rsh | P::Rlogin => Risk {
            severity: RiskSeverity::Critical,
            headline: "Unencrypted, and trusts the client's word for who you are",
            detail: "The r-services send everything in plain text and authenticate \
with .rhosts host trust, which an attacker who can spoof an address satisfies \
without a password.",
            mitigation: "Remove them. SSH replaced these in the 1990s.",
            reference: "RFC 1282; CERT advisories CA-1994-01 and later",
        },
        P::Vnc => Risk {
            severity: RiskSeverity::High,
            headline: "Screen contents and keystrokes are unencrypted",
            detail: "The classic RFB authentication is a DES challenge-response \
limited to an 8-character password, and everything after it — the framebuffer \
and every keystroke, including passwords typed into the remote session — is \
unencrypted.",
            mitigation: "Tunnel VNC over SSH or a VPN, or use a build with TLS \
support. Never expose it directly.",
            reference: "RFC 6143 §7 'Security Considerations'",
        },
        P::Finger | P::Ident => Risk {
            severity: RiskSeverity::Medium,
            headline: "Hands out user account names to anyone who asks",
            detail: "Both answer questions about who exists on a host and who is \
logged in. That is reconnaissance: it converts a password-guessing attack from \
'guess the username too' into 'guess only the password'.",
            mitigation: "Disable. Neither has a use on a modern network.",
            reference: "RFC 1288 §3 (finger's own security section); RFC 1413 §6",
        },

        P::Rdp => Risk {
            severity: RiskSeverity::High,
            headline: "Without Network Level Authentication the login screen is the attack surface",
            detail: "With NLA off, a client reaches the Windows logon session before \
authenticating — which is the pre-auth surface BlueKeep exploited for wormable \
remote code execution. Exposed RDP is also the most common initial access \
vector in ransomware incident reports, through credential stuffing rather than \
any protocol flaw.",
            mitigation: "Require NLA, never publish 3389 to the internet — put it \
behind a VPN or an RD Gateway — and enforce account lockout and MFA.",
            reference: "CVE-2019-0708 (BlueKeep); CVE-2019-1181/1182 (DejaBlue)",
        },
        P::Ipmi => Risk {
            severity: RiskSeverity::Critical,
            headline: "The BMC hands a password hash to anyone who asks",
            detail: "IPMI 2.0's RAKP exchange returns a HMAC of the user's password \
to an unauthenticated requester, which can then be cracked offline. Cipher \
suite 0, still enabled on some boards, skips authentication altogether. A BMC \
controls power and console for the host, and it survives an OS reinstall.",
            mitigation: "Keep BMCs on a physically separate management network with no \
route to anything else. Disable cipher suite 0, and use long random passwords \
because the hash will leak.",
            reference: "CVE-2013-4786; CERT VU#843044",
        },

        // ── Services that ship with no authentication ───────────────────────
        P::Redis => Risk {
            severity: RiskSeverity::Critical,
            headline: "No password by default, and CONFIG SET turns that into code execution",
            detail: "An unprotected Redis accepts every command, including `CONFIG \
SET dir` and `SAVE` — which writes the database wherever the attacker chooses. \
Pointed at an SSH authorized_keys file or a cron directory, that is remote code \
execution as the Redis user, not merely data disclosure.",
            mitigation: "Bind to localhost, set `requirepass`, and rename or disable \
CONFIG. Never expose 6379.",
            reference: "Redis security documentation; CVE-2022-0543 (Lua sandbox escape)",
        },
        P::Mongodb => Risk {
            severity: RiskSeverity::Critical,
            headline: "Older builds listen on every interface with authentication off",
            detail: "MongoDB before 3.6 defaulted to binding all interfaces with no \
authentication. Tens of thousands of databases were found, wiped and held to \
ransom in the 2017 sweeps. Any exposed instance is a full read and write of the \
data.",
            mitigation: "Set `bindIp` to the addresses that need it, enable \
authorization, and require TLS between application and database.",
            reference:
                "MongoDB security checklist; the 2017 ransom sweeps (BleepingComputer/Shodan)",
        },
        P::Elasticsearch => Risk {
            severity: RiskSeverity::Critical,
            headline: "Open builds had no authentication — an exposed index is a full data dump",
            detail: "Security features were a paid add-on until 6.8/7.1, so open-source \
deployments commonly ran with no authentication at all. A reachable node means \
every index can be read, modified or deleted with plain HTTP requests.",
            mitigation: "Enable the built-in security (free since 6.8), bind to a \
private interface, and put TLS on both the HTTP and transport ports.",
            reference: "Elastic security announcement, May 2019; CVE-2015-1427 (Groovy RCE)",
        },
        P::Etcd => Risk {
            severity: RiskSeverity::Critical,
            headline: "Holds the cluster's secrets and historically served them unauthenticated",
            detail: "etcd is where Kubernetes keeps every Secret, ServiceAccount token \
and cluster configuration. Older versions served the v2 API with no \
authentication, so reaching port 2379 meant reading — and writing — the entire \
control plane state.",
            mitigation: "Require client certificates on both the client and peer ports, \
enable encryption at rest, and keep etcd off any network a workload can reach.",
            reference: "CVE-2018-1099; Kubernetes hardening guidance (NSA/CISA)",
        },
        P::Mqtt => Risk {
            severity: RiskSeverity::High,
            headline: "Unencrypted and usually unauthenticated, on a bus that commands devices",
            detail: "MQTT has no transport security of its own and brokers commonly \
allow anonymous connections. Because subscribers receive whatever is published, \
an open broker leaks all telemetry — and lets anyone publish, which on an \
actuator topic means operating the device.",
            mitigation: "Use MQTT over TLS (8883), require per-client credentials or \
certificates, and restrict publish rights by topic ACL.",
            reference: "OASIS MQTT 3.1.1 §5 'Security'; OWASP IoT Top 10",
        },
        P::Nfs => Risk {
            severity: RiskSeverity::High,
            headline: "AUTH_SYS believes whatever user ID the client claims",
            detail: "With the default AUTH_SYS flavour the client asserts its own uid \
and gid and the server trusts it. Anyone with root on a machine that can mount \
the export can become any user on the files it contains, root_squash \
notwithstanding.",
            mitigation: "Restrict exports by address, use root_squash and read-only \
where possible, and move to NFSv4 with Kerberos (sec=krb5p) for real identity.",
            reference: "RFC 5531 §8; RFC 7530 §3 for the Kerberos flavours",
        },
        P::Syslog => Risk {
            severity: RiskSeverity::Medium,
            headline: "Unauthenticated and unencrypted — logs can be read and forged",
            detail: "Classic syslog over UDP has no authentication, so entries can be \
spoofed by anyone who can reach the collector, and no encryption, so the log \
contents — often including usernames and internal addresses — are readable in \
transit. Forged entries undermine the record an investigation depends on.",
            mitigation: "Use syslog over TLS (RFC 5425) on TCP, and restrict the \
collector to known senders.",
            reference: "RFC 5424 §8 'Security Considerations'; RFC 5425",
        },

        // ── Broken or withdrawn cryptography ────────────────────────────────
        P::Ntlm | P::Ntlmssp => Risk {
            severity: RiskSeverity::High,
            headline: "Relayable, and the hash is as good as the password",
            detail: "NTLM authentication can be relayed to another service by an \
attacker in the middle unless signing is enforced, and it is a challenge-response \
over the password hash — so stealing the hash is enough to authenticate without \
ever cracking it.",
            mitigation: "Prefer Kerberos. Where NTLM remains, require SMB signing and \
LDAP channel binding, and disable NTLMv1 entirely.",
            reference: "Microsoft ADV170014; CVE-2019-1040 (NTLM tampering)",
        },
        P::Smb => Risk {
            severity: RiskSeverity::High,
            headline: "SMBv1 is the EternalBlue protocol and should not be present",
            detail: "SMB itself is fine at version 3 with signing and encryption. \
Version 1 is not: it carries the flaws exploited by EternalBlue and the WannaCry \
and NotPetya outbreaks, and it cannot be made safe by configuration.",
            mitigation: "Disable SMBv1 on clients and servers. Require SMB 3.x with \
signing; enable encryption for shares that leave the local segment.",
            reference: "MS17-010; CVE-2017-0144",
        },
        P::Wlan | P::Eapol => Risk {
            severity: RiskSeverity::High,
            headline: "WEP is broken outright and WPA/TKIP is deprecated",
            detail: "WEP keys can be recovered from captured traffic in minutes. \
TKIP was a transitional fix for hardware that could not do AES and has been \
withdrawn. The WPA2 four-way handshake is also what an offline dictionary \
attack needs, so a weak passphrase is a weak network however modern the cipher.",
            mitigation: "WPA3, or WPA2 with AES-CCMP and a long random passphrase. \
Use 802.1X where there are many users.",
            reference: "IEEE 802.11-2020 deprecates WEP and TKIP; CVE-2017-13077 (KRACK)",
        },
        P::Tls => Risk {
            severity: RiskSeverity::Info,
            headline: "Only the modern versions are safe — check which one this is",
            detail: "TLS 1.3 and 1.2 are current. SSLv3, TLS 1.0 and TLS 1.1 are \
formally deprecated and carry POODLE, BEAST and downgrade weaknesses. netscope \
reports the negotiated version in the handshake, which is the field to read \
here.",
            mitigation: "Serve TLS 1.2 as a floor and prefer 1.3. Disable renegotiation \
and export-grade ciphers.",
            reference: "RFC 8996 deprecates TLS 1.0/1.1; RFC 7568 deprecates SSLv3",
        },

        // ── Amplification vectors ───────────────────────────────────────────
        P::Dns => Risk {
            severity: RiskSeverity::Medium,
            headline: "Queries are readable, and open resolvers amplify attacks",
            detail: "Plain DNS reveals every name a host looks up, which is a \
detailed record of what someone is doing. A resolver that answers anyone also \
turns a small spoofed query into a large reply aimed at a victim — an \
amplification factor of roughly 50×.",
            mitigation: "DoT or DoH for privacy; DNSSEC for integrity. Never leave a \
resolver open to the internet, and rate-limit responses.",
            reference: "RFC 9076 (DNS privacy); US-CERT TA13-088A",
        },
        P::Ntp => Risk {
            severity: RiskSeverity::High,
            headline: "Mode 6 and 7 queries amplify by several hundred times",
            detail: "The monlist command in mode 7 returns the last 600 clients from \
a tiny request — an amplification factor near 500×. Mode 6 control queries are \
smaller but still abusable. Both were used in the largest reflection attacks on \
record.",
            mitigation: "Upgrade past ntpd 4.2.7, disable monlist, and restrict mode 6 \
and 7 to localhost.",
            reference: "CVE-2013-5211; US-CERT TA14-013A",
        },
        P::Ssdp => Risk {
            severity: RiskSeverity::High,
            headline: "Amplifies about 30× and should never face the internet",
            detail: "An M-SEARCH discovery request produces a much larger reply, and \
consumer devices answer it by default. SSDP reflection is a standing source of \
large DDoS traffic. Seeing SSDP arrive from outside the local network means a \
device is exposed.",
            mitigation: "Block UDP 1900 at the perimeter in both directions and turn \
UPnP off on the router.",
            reference: "US-CERT UDP-based amplification advisory (TA14-017A)",
        },
        P::Memcached => Risk {
            severity: RiskSeverity::Critical,
            headline: "No authentication, and the worst amplification factor known",
            detail: "Memcached on UDP has no authentication and amplifies by up to \
51,000×, which produced the 1.35 Tbps GitHub attack in 2018. Anything reachable \
also means the cache contents — often session data — can be read and written by \
anyone.",
            mitigation: "Bind to localhost, disable UDP entirely, and never expose \
port 11211.",
            reference: "CVE-2018-1000115; US-CERT TA18-054A",
        },
        P::Cldap => Risk {
            severity: RiskSeverity::High,
            headline: "Connectionless LDAP amplifies about 60×",
            detail: "CLDAP answers over UDP with no handshake, so the source address \
can be spoofed and the reply aimed at a victim. Exposed domain controllers are \
the usual reflectors.",
            mitigation: "Block UDP 389 at the perimeter. Domain controllers have no \
reason to answer it from the internet.",
            reference: "Akamai CLDAP reflection advisory, 2017",
        },
        P::Chargen => Risk {
            severity: RiskSeverity::High,
            headline: "A 1983 debugging toy that is now purely a DDoS reflector",
            detail: "Chargen replies to any packet with a stream of characters. It \
has no legitimate modern use and exists only as an amplification source.",
            mitigation: "Disable it. There is no configuration that makes it useful.",
            reference: "RFC 864; US-CERT TA14-017A",
        },

        // ── Industrial control: designed without authentication ─────────────
        P::Modbus => Risk {
            severity: RiskSeverity::Critical,
            headline: "No authentication, no encryption — any client can command",
            detail: "Modbus/TCP was designed for an isolated serial bus and carries \
that design onto Ethernet. There is no identity and no integrity check, so \
anyone who can reach port 502 can read and write coils and registers — that is, \
operate the equipment.",
            mitigation: "Segment the OT network, allow Modbus only from named \
engineering hosts, and put a protocol-aware firewall in front of it. Modbus \
Security (TLS, port 802) where devices support it.",
            reference: "Modbus/TCP spec; CISA ICS-TIP-12-146-01B",
        },
        P::Dnp3 => Risk {
            severity: RiskSeverity::High,
            headline: "No authentication unless Secure Authentication is enabled",
            detail: "Base DNP3 has no identity check, so a reachable outstation \
accepts control commands from anyone. Secure Authentication (IEEE 1815-2012) \
adds it, but is off by default and often unimplemented on older RTUs.",
            mitigation: "Enable Secure Authentication where the equipment supports it; \
otherwise isolate and monitor. Alert on unexpected function codes.",
            reference: "IEEE 1815-2012; CISA ICS advisories on DNP3 implementations",
        },
        P::S7comm | P::S7commPlus => Risk {
            severity: RiskSeverity::Critical,
            headline: "PLC start, stop and program download with weak or no auth",
            detail: "S7comm has no authentication. S7comm+ added obfuscation and a \
session key, but versions have been replayed and the protection is not a \
security boundary. Reaching a PLC on port 102 can mean stopping it or \
downloading new logic.",
            mitigation: "Keep PLCs off routable networks, restrict port 102 to the \
engineering workstation, and use the CPU's own protection level.",
            reference: "Siemens SSA advisories; CISA ICSA-16-348-05",
        },
        P::Enip => Risk {
            severity: RiskSeverity::High,
            headline: "CIP carries control commands with no authentication",
            detail: "EtherNet/IP encapsulates CIP, which has no identity check. \
Reaching port 44818 allows reading and writing tags and, on many controllers, \
changing the processor mode.",
            mitigation: "Segment, and use the controller's key switch or trusted-slot \
feature. CIP Security where the hardware supports it.",
            reference: "ODVA CIP Security specification; CISA ICSA-20-051-02",
        },
        P::Bacnet => Risk {
            severity: RiskSeverity::High,
            headline: "Building controls answer anyone who asks",
            detail: "BACnet/IP has no authentication in normal deployments. \
Who-Is/I-Am discovery maps every device on the network, and writing a present \
value changes what the building actually does — setpoints, dampers, access \
control.",
            mitigation: "Keep the BMS on its own VLAN with no internet path, and \
restrict UDP 47808 to the controllers that need it.",
            reference: "ASHRAE 135; CISA ICS advisories on exposed BACnet",
        },
        P::PNet => Risk {
            severity: RiskSeverity::High,
            headline: "Real-time frames have no authentication and DCP can reset devices",
            detail: "PROFINET real-time traffic runs directly on Ethernet with no \
authentication. The DCP discovery protocol can rename a station, change its IP, \
or issue a factory reset — from any host on the same layer 2 segment.",
            mitigation: "Treat the PROFINET segment as a trust boundary: no user \
traffic, no wireless bridges, managed switches with port security.",
            reference: "IEC 61158; CISA ICSA-19-134-08",
        },

        // ── Network infrastructure: spoofable by design ─────────────────────
        P::Arp => Risk {
            severity: RiskSeverity::Medium,
            headline: "Unauthenticated by design — the basis of most local MITM",
            detail: "ARP replies are believed without verification, so a host can \
claim to own the gateway's address and receive traffic meant for it. Every \
local man-in-the-middle tool starts here.",
            mitigation: "Dynamic ARP Inspection with DHCP snooping on managed \
switches; static entries for critical hosts.",
            reference: "RFC 826; the protocol has no authentication mechanism at all",
        },
        P::Dhcp => Risk {
            severity: RiskSeverity::Medium,
            headline: "A rogue server can hand out its own gateway and DNS",
            detail: "Clients accept the first answer. A rogue DHCP server can make \
itself the default gateway and the DNS resolver for every host that boots, \
which is a complete man-in-the-middle position obtained without touching a \
single client.",
            mitigation: "DHCP snooping on access switches, with the real server's port \
marked trusted.",
            reference: "RFC 2131; RFC 3118 (authentication, almost never deployed)",
        },
        P::Stp => Risk {
            severity: RiskSeverity::Medium,
            headline: "A forged BPDU can make an attacker the root bridge",
            detail: "Spanning Tree elects the lowest bridge ID as root and accepts \
BPDUs from any port. A host claiming priority 0 becomes root, and traffic \
between switches is rerouted through it.",
            mitigation: "BPDU Guard and Root Guard on every access port.",
            reference: "IEEE 802.1D; Cisco BPDU Guard guidance",
        },
        P::Llmnr | P::Nbns | P::Netbios => Risk {
            severity: RiskSeverity::High,
            headline: "Name-resolution fallback that hands over credential hashes",
            detail: "When DNS fails, Windows broadcasts the name on LLMNR and \
NBT-NS and trusts whoever answers. An attacker answers every query, the client \
authenticates to them, and their NTLM hash is captured — this is what Responder \
does, and it needs no exploit.",
            mitigation: "Disable LLMNR and NBT-NS by Group Policy. They have no \
function on a network with working DNS.",
            reference: "Microsoft security guidance on LLMNR/NBT-NS; CISA advisory on Responder",
        },
        P::Mdns => Risk {
            severity: RiskSeverity::Info,
            headline: "Broadcasts device and user names across the local network",
            detail: "mDNS and DNS-SD announce hostnames, service types and often the \
owner's name ('Efe's MacBook') to every device on the segment. Not a \
vulnerability, but it is a free inventory of the network for anyone on it.",
            mitigation: "Fine on a trusted LAN. Block it between guest and corporate \
VLANs so the two cannot enumerate each other.",
            reference: "RFC 6762; RFC 6763",
        },

        // ── Remaining protocols have nothing specific to say. ───────────────
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of returning `Option`: a protocol with no documented weakness
    /// must produce silence, not filler. These are the modern replacements the
    /// entries above recommend — if any of them grew a risk note, the advice
    /// would be contradicting itself.
    #[test]
    fn a_protocol_with_no_documented_weakness_says_nothing() {
        for p in [
            Protocol::Ssh,
            Protocol::Quic,
            Protocol::Kerberos,
            Protocol::Http2,
            Protocol::WireGuard,
        ] {
            assert!(risk(&p).is_none(), "{p:?} should have no risk note");
        }
    }

    /// The plain-text protocols are the reason this module exists.
    #[test]
    fn cleartext_credential_protocols_are_flagged_critical() {
        for p in [
            Protocol::Telnet,
            Protocol::Ftp,
            Protocol::Pop3,
            Protocol::Imap,
            Protocol::Snmp,
            Protocol::Tftp,
        ] {
            let r = risk(&p).unwrap_or_else(|| panic!("{p:?} has no risk note"));
            assert_eq!(r.severity, RiskSeverity::Critical, "{p:?}");
        }
    }

    /// Industrial control protocols command physical equipment, so an
    /// unauthenticated one is never merely informational.
    #[test]
    fn unauthenticated_control_protocols_are_at_least_high() {
        for p in [
            Protocol::Modbus,
            Protocol::Dnp3,
            Protocol::S7comm,
            Protocol::Enip,
            Protocol::Bacnet,
            Protocol::PNet,
        ] {
            let r = risk(&p).unwrap_or_else(|| panic!("{p:?} has no risk note"));
            assert!(
                r.severity <= RiskSeverity::High,
                "{p:?} is only {}",
                r.severity.label(),
            );
        }
    }

    /// Every field is load-bearing: a note without a mitigation leaves the
    /// reader stuck, and one without a reference is an assertion they cannot
    /// check. An empty string in any of them is a half-written entry.
    #[test]
    fn every_entry_is_complete() {
        for p in Protocol::ALL {
            let Some(r) = risk(p) else { continue };
            for (field, value) in [
                ("headline", r.headline),
                ("detail", r.detail),
                ("mitigation", r.mitigation),
                ("reference", r.reference),
            ] {
                assert!(!value.trim().is_empty(), "{p:?} has an empty {field}");
            }
            assert!(
                r.detail.len() > r.headline.len(),
                "{p:?}: the detail should say more than the headline",
            );
        }
    }

    /// Data stores that historically shipped listening on every interface with
    /// authentication off. Each of these has had a mass-compromise event, so
    /// none of them is a mild note.
    #[test]
    fn data_stores_that_ship_open_are_flagged_critical() {
        for p in [
            Protocol::Redis,
            Protocol::Mongodb,
            Protocol::Elasticsearch,
            Protocol::Etcd,
        ] {
            let r = risk(&p).unwrap_or_else(|| panic!("{p:?} has no risk note"));
            assert_eq!(r.severity, RiskSeverity::Critical, "{p:?}");
        }
    }

    /// The desktop sends a packet's protocol as `Protocol::to_string()` and
    /// looks the risk up by `display_name()`. Those are the same string today
    /// because `Display` delegates to it — but nothing in the type system says
    /// so, and if they ever diverge the risk panel does not break loudly, it
    /// just silently never appears. This is that seam.
    #[test]
    fn a_protocol_is_findable_by_the_name_the_ui_sends() {
        for p in Protocol::ALL.iter().filter(|p| risk(p).is_some()) {
            let sent = p.to_string();
            let found = Protocol::ALL.iter().find(|c| c.display_name() == sent);
            assert!(
                found.is_some_and(|c| risk(c).is_some()),
                "{p:?} serialises as {sent:?}, which no lookup finds",
            );
        }
    }

    /// A count, so that deleting the table by accident fails loudly rather
    /// than turning the panel silently empty.
    #[test]
    fn the_table_covers_a_meaningful_set_without_covering_everything() {
        let with_risk = Protocol::ALL.iter().filter(|p| risk(p).is_some()).count();
        assert!(
            with_risk >= 30,
            "only {with_risk} protocols carry a risk note"
        );
        assert!(
            with_risk < Protocol::ALL.len() / 10,
            "{with_risk} is too many — this table is meant to be selective",
        );
    }
}
