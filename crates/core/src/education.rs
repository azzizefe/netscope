// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Plain-language explanations of what netscope shows.
//!
//! The goal: someone who has never opened Wireshark and doesn't know what a
//! "packet" is should be able to look at a row, read a sentence, and
//! understand what their computer just did. Every string here is written for
//! that person — accurate, but no jargon without a definition.

use crate::models::{Packet, Protocol};

/// A beginner-friendly lesson about one protocol.
pub struct Lesson {
    /// Short headline, e.g. "DNS — the internet's phone book".
    pub title: &'static str,
    /// One-sentence gist.
    pub summary: &'static str,
    /// A couple of sentences of real explanation.
    pub body: &'static str,
    /// What the reader will actually see in netscope for this protocol.
    pub look_for: &'static str,
}

/// The lesson for a given protocol.
pub fn lesson(proto: &Protocol) -> Lesson {
    match proto {
        Protocol::Dns => Lesson {
            title: "DNS — the internet's phone book",
            summary: "Turns names like google.com into numeric IP addresses.",
            body: "Computers talk using numbers (IP addresses), not names. Before \
your browser can reach google.com it asks a DNS server \"what's the number \
for this name?\". The answer comes back as an IP address, and the real \
connection starts. DNS is unencrypted, so anyone on the path can see which \
sites you look up.",
            look_for: "\"DNS Query — google.com\" (asking) then \"DNS Response — google.com → 142.250.74.46\" (the answer).",
        },
        Protocol::Tls => Lesson {
            title: "TLS / HTTPS — the encrypted web",
            summary: "The lock icon in your browser. Encrypts web traffic.",
            body: "TLS is the 'S' in HTTPS. It wraps the connection in encryption so \
nobody in between can read or change it. netscope can't see inside encrypted \
traffic (neither can Wireshark) — but at the very start, the browser announces \
which site it wants in clear text (the 'SNI'), so you can still see WHERE the \
traffic goes, just not WHAT is sent.",
            look_for: "\"TLS ClientHello — github.com\" reveals the site (plus JA4/JA3 fingerprints of the client); \"TLS — 1360 bytes of encrypted data\" is content you can't read.",
        },
        Protocol::Http => Lesson {
            title: "HTTP — the (unencrypted) web",
            summary: "Web requests in plain text — everyone can read them.",
            body: "HTTP is how browsers fetch web pages: the browser sends a request \
(GET a page, POST a form) and the server replies with a status code (200 OK, \
404 Not Found). Unlike HTTPS it is NOT encrypted, so passwords or data sent \
over plain HTTP are visible to anyone capturing — which is exactly why the web \
moved to HTTPS.",
            look_for: "\"HTTP GET /login (HTTP/1.1)\" is a request; \"HTTP 200 OK\" is the reply.",
        },
        Protocol::Tcp => Lesson {
            title: "TCP — the reliable delivery service",
            summary: "Carries most traffic; guarantees nothing is lost or out of order.",
            body: "TCP is the workhorse under HTTPS, HTTP, email and more. It's like \
a phone call: both sides first agree to talk (the 'handshake'), then data \
flows reliably — if a piece is lost it's re-sent. When you see a connection \
open and close, that's TCP managing the conversation.",
            look_for: "\"TCP Connection opened (3-way handshake)\" = starting; \"...closing (FIN)\" = ending; \"...reset (RST)\" = refused/aborted.",
        },
        Protocol::Udp => Lesson {
            title: "UDP — fire and forget",
            summary: "Fast, lightweight, no guarantees. Used by DNS, video, games.",
            body: "UDP is like shouting a message without checking if it arrived. \
There's no handshake and no re-sending, which makes it fast and cheap. That's \
perfect for things where speed beats perfection: DNS lookups, live video, voice \
calls and online games all ride on UDP.",
            look_for: "\"UDP — 40 bytes of payload\". Most DNS you see is UDP underneath.",
        },
        Protocol::Icmp => Lesson {
            title: "ICMP — the network's status messages",
            summary: "Used by 'ping' and for error reports like 'host unreachable'.",
            body: "ICMP is how devices report network conditions. The classic use is \
'ping': send an echo request, get an echo reply, and you know the other side is \
reachable and how long the round trip took. Routers also use ICMP to say things \
like 'that destination is unreachable' or 'the packet lived too long'.",
            look_for: "\"Ping request (echo request)\" and \"Ping reply (echo reply)\" — a reachability test in action.",
        },
        Protocol::Arp => Lesson {
            title: "ARP — who's who on the local network",
            summary: "Matches an IP address to a device's hardware (MAC) address.",
            body: "Inside your home or office network, devices are found by their \
hardware address (MAC), not their IP. ARP is the little broadcast that asks \
'who has 192.168.1.1?' and gets back 'that's me, at this MAC address'. It only \
happens on your local network — you'll never see ARP for internet servers.",
            look_for: "\"ARP Request — Who has 192.168.1.1? Tell 192.168.1.5\" then a reply with the MAC address.",
        },
        Protocol::Dhcp => Lesson {
            title: "DHCP — how your device gets an IP address",
            summary: "Hands out IP addresses automatically when a device joins the network.",
            body: "When your phone or laptop joins a network it doesn't yet have an IP \
address. DHCP is the automatic negotiation that gives it one: the device shouts \
'Discover', a server 'Offers' an address, the device 'Requests' it, and the \
server confirms with an 'ACK'. That's why you almost never have to type in \
network settings by hand.",
            look_for: "\"DHCP Discover\" → \"DHCP Offer — 192.168.1.50\" → \"DHCP Request\" → \"DHCP ACK\".",
        },
        Protocol::Ntp => Lesson {
            title: "NTP — keeping the clock correct",
            summary: "How devices sync their clocks with time servers, to the millisecond.",
            body: "Computer clocks drift. NTP is the quiet background protocol that \
corrects them by asking time servers 'what time is it?' and measuring the round \
trip so the answer stays accurate. Correct time matters more than it sounds — \
security certificates, logs and encryption all depend on it.",
            look_for: "\"NTP v4 client\" (your device asking) and \"NTP v4 server (stratum 2)\" (the answer).",
        },
        Protocol::Mdns => Lesson {
            title: "mDNS — finding devices on the local network",
            summary: "How your laptop discovers the printer, speaker or TV nearby.",
            body: "mDNS (also called Bonjour or 'Zeroconf') is DNS without a server: \
devices announce themselves on the local network so others can find them by \
name. It's how AirPrint finds printers and how a Chromecast shows up in your \
cast menu — no configuration required.",
            look_for: "\"mDNS — Query — _airplay._tcp.local\" and similar `.local` service names.",
        },
        Protocol::Snmp => Lesson {
            title: "SNMP — monitoring network gear",
            summary: "How admins read status and stats from routers, switches and printers.",
            body: "SNMP is the language network equipment speaks to management tools: \
'how much traffic have you handled?', 'is this port up?', 'how much toner is \
left?'. Older versions (v1/v2c) send a plaintext 'community' string as a \
password — worth noticing if you see it on the wire.",
            look_for: "\"SNMPv2c — community 'public'\" — note the community string is not encrypted.",
        },
        Protocol::Quic => Lesson {
            title: "QUIC — the modern, faster HTTPS",
            summary: "Google-designed transport behind HTTP/3; encrypted, over UDP.",
            body: "QUIC is what a lot of 'HTTPS' traffic actually uses now. It rolls \
the connection setup and encryption into one and runs over UDP instead of TCP, \
so pages start loading faster — especially on flaky mobile networks. Like TLS, \
the content is encrypted; you can see the connection but not what's inside.",
            look_for: "\"QUIC — Initial\" (starting a connection) and \"QUIC — 1-RTT\" (encrypted data).",
        },
        Protocol::Sip => Lesson {
            title: "SIP — setting up voice and video calls",
            summary: "The signalling behind VoIP: ringing, answering and hanging up.",
            body: "SIP is how internet phone calls are arranged. It doesn't carry the \
audio itself — it's the 'ringing' layer that invites the other party, negotiates \
the call, and tears it down at the end. The actual voice usually flows in a \
separate media stream once SIP has set things up.",
            look_for: "\"SIP INVITE — sip:bob@example.com\" (calling) and \"SIP 200 OK\" (answered).",
        },
        Protocol::Ssh => Lesson {
            title: "SSH — the encrypted remote shell",
            summary: "How admins log into servers securely; encrypted end to end.",
            body: "SSH is the standard way to get a command line on a remote machine \
safely. After a brief plaintext banner exchange (which is why you can see the \
software version), everything is encrypted — commands, output and passwords. \
netscope can tell an SSH session is happening but not what's inside it.",
            look_for: "\"SSH — SSH-2.0-OpenSSH_8.9\" (the banner) then \"SSH — encrypted\".",
        },
        Protocol::Ftp => Lesson {
            title: "FTP — old-school file transfer",
            summary: "Moves files, but sends commands and passwords in the clear.",
            body: "FTP predates encryption on the web. The control channel carries \
plain-text commands like USER and PASS, so anyone capturing can read the login. \
That's why it's largely replaced by SFTP/FTPS today — but you'll still meet it on \
legacy gear, and it's a classic thing to spot in a capture.",
            look_for: "\"FTP USER alice\", \"FTP PASS …\", and numbered replies like \"FTP 230 login OK\".",
        },
        Protocol::Smtp => Lesson {
            title: "SMTP — sending email between servers",
            summary: "The protocol that carries mail from one server to the next.",
            body: "SMTP is the delivery half of email: a sender announces who the mail \
is from and who it's to, then hands over the message. Plain SMTP is unencrypted \
(modern setups wrap it in TLS via STARTTLS), so on older links you can watch the \
envelope of a message go by.",
            look_for: "\"SMTP MAIL FROM:<a@b.com>\", \"SMTP RCPT TO:<c@d.com>\", and \"SMTP 250 OK\".",
        },
        Protocol::Imap => Lesson {
            title: "IMAP — reading mail on the server",
            summary: "How a mail app browses a mailbox that stays on the server.",
            body: "IMAP lets your mail client read and organise messages that live on \
the mail server, so the same mailbox looks the same on your phone and laptop. \
Commands are tagged (a1, a2…) so replies can be matched to requests. Plain IMAP \
is unencrypted; most clients use it over TLS.",
            look_for: "\"IMAP LOGIN\", \"IMAP SELECT INBOX\", and \"* OK\" server replies.",
        },
        Protocol::Pop3 => Lesson {
            title: "POP3 — downloading your mail",
            summary: "An older mail protocol that pulls messages down and removes them.",
            body: "POP3 is the simple, older way to fetch email: connect, download the \
messages, and (classically) delete them from the server. It's mostly given way to \
IMAP, which keeps mail on the server. Like the others, plain POP3 is unencrypted \
and usually run over TLS today.",
            look_for: "\"POP3 USER alice\", \"POP3 PASS …\", and \"+OK\" / \"-ERR\" replies.",
        },
        Protocol::Telnet => Lesson {
            title: "Telnet — the unencrypted remote terminal",
            summary: "A remote shell with no encryption — everything is in the clear.",
            body: "Telnet was the original way to log into a remote machine, before \
SSH. It has no encryption at all, so the username, password and every keystroke \
are visible to anyone on the path. Seeing Telnet on a network today is usually a \
red flag (or old lab/router gear) — it's a textbook example of why SSH exists.",
            look_for: "\"Telnet — data\" carrying readable text, including logins.",
        },
        Protocol::Rdp => Lesson {
            title: "RDP — Windows Remote Desktop",
            summary: "The protocol behind 'Remote Desktop' to a Windows machine.",
            body: "RDP is how you control a Windows desktop over the network — the \
screen, keyboard and mouse of a remote PC. The session is encrypted, so netscope \
can see that an RDP connection exists (and to where) but not the screen contents. \
RDP exposed to the internet is a common attack target worth noticing.",
            look_for: "\"RDP (Remote Desktop)\" to or from TCP port 3389.",
        },
        Protocol::WebSocket => Lesson {
            title: "WebSocket — the browser's two-way channel",
            summary: "A persistent connection where server and browser both push messages.",
            body: "Normal HTTP is request-then-reply. WebSocket upgrades that \
connection into a permanent two-way pipe: chat apps, live dashboards, games \
and dev-server hot-reload all use it to push updates instantly. It starts as \
an ordinary HTTP request with an 'Upgrade: websocket' header; after the \
server's '101 Switching Protocols' answer, the same connection carries \
WebSocket frames instead of HTTP.",
            look_for: "An \"HTTP GET … — WebSocket handshake\" pair, then \"WebSocket Text\" / \"WebSocket Binary\" frames flowing both ways.",
        },
        Protocol::Http2 => Lesson {
            title: "HTTP/2 — the multiplexed web",
            summary: "A binary, faster HTTP where many requests share one connection.",
            body: "HTTP/2 replaces HTTP/1.1's one-request-at-a-time text protocol \
with binary 'frames': many requests and responses are interleaved on a single \
connection (multiplexing), so pages with dozens of resources load faster. On \
the open internet it's almost always wrapped in TLS, where netscope sees only \
the encryption — what you can watch here is its cleartext form (h2c), common \
between services inside data centres.",
            look_for: "\"HTTP/2 connection preface\" starting a connection, then \"HTTP/2 HEADERS\" (a request or response) and \"HTTP/2 DATA\" frames on numbered streams.",
        },
        Protocol::Grpc => Lesson {
            title: "gRPC — services calling each other",
            summary: "A remote-procedure-call protocol microservices use, built on HTTP/2.",
            body: "gRPC is how modern backend services talk to each other: instead \
of hand-written REST endpoints, one service calls a function on another, and \
gRPC ships the call as compact binary (protobuf) messages inside HTTP/2 \
frames. Seeing gRPC in a capture usually means microservices, Kubernetes or \
mobile apps talking to their backends. Like HTTP/2 it's normally TLS-wrapped; \
netscope spots the cleartext form by its content-type and message framing.",
            look_for: "\"gRPC headers (application/grpc)\" starting a call, then \"gRPC message — 42 bytes\" frames carrying the protobuf payload.",
        },
        Protocol::Vxlan => Lesson {
            title: "VXLAN — networks inside networks",
            summary: "A tunnel that carries one network's traffic inside another's.",
            body: "Cloud platforms and Kubernetes clusters run many virtual \
networks on the same physical one. VXLAN wraps a complete Ethernet frame \
inside a UDP packet and labels it with a VNI (network number), so traffic for \
virtual network 5000 stays separate from 5001 even on shared cables. netscope \
unwraps the tunnel and shows you what's really travelling inside.",
            look_for: "\"VXLAN VNI 5000 → DNS Query — …\" — the part after the arrow is the inner, real conversation.",
        },
        Protocol::Postgres => Lesson {
            title: "PostgreSQL — talking to the database",
            summary: "The wire protocol a PostgreSQL client uses to run SQL queries.",
            body: "When an app stores or reads data in PostgreSQL, it opens a TCP \
connection (port 5432) and speaks Postgres' own message protocol: a startup \
handshake, then messages like 'Query' carrying SQL text and 'DataRow' carrying \
results. Plain connections send the SQL — and sometimes the password — in clear \
text, which is why production databases are usually behind TLS.",
            look_for: "\"PostgreSQL Query — SELECT …\" (a query going out) and \"PostgreSQL DataRow\" / \"PostgreSQL ReadyForQuery\" (results coming back).",
        },
        Protocol::Mysql => Lesson {
            title: "MySQL — the other popular database",
            summary: "How MySQL/MariaDB clients send queries and get results.",
            body: "MySQL (and its fork MariaDB) runs on TCP 3306. The server opens \
with a handshake that reveals its version, the client logs in, then sends \
commands — most commonly COM_QUERY carrying the SQL text. As with any \
unencrypted database link, the queries and login are visible on the wire unless \
the connection is wrapped in TLS.",
            look_for: "\"MySQL Server handshake — 8.0.32\" at the start, then \"MySQL Query — SELECT …\".",
        },
        Protocol::Mongodb => Lesson {
            title: "MongoDB — the document database",
            summary: "The binary protocol behind MongoDB reads and writes.",
            body: "MongoDB stores JSON-like documents and talks a compact binary \
protocol on TCP 27017. Modern drivers send everything as 'OP_MSG' messages that \
wrap a BSON command — 'find', 'insert', 'update' and so on. netscope reads the \
message header and the command name without decoding the whole document.",
            look_for: "\"MongoDB OP_MSG — find\" or \"MongoDB OP_MSG — insert\" — the word after the dash is the command.",
        },
        Protocol::Redis => Lesson {
            title: "Redis — the in-memory data store",
            summary: "A fast key-value store with a simple, almost human-readable protocol.",
            body: "Redis keeps data in memory for speed and is used as a cache, queue \
or session store. Its protocol (RESP, on TCP 6379) is refreshingly simple: a \
command is just an array of strings like GET, SET or PUBLISH, and replies are \
prefixed by a single character (+ ok, - error, : number). You can almost read it \
straight off the wire.",
            look_for: "\"Redis command — GET foo\" / \"Redis command — SET key value\" and \"Redis reply — +OK\".",
        },
        Protocol::Cassandra => Lesson {
            title: "Cassandra — the distributed database",
            summary: "The CQL binary protocol used by Apache Cassandra clusters.",
            body: "Cassandra spreads data across many nodes for scale and resilience. \
Clients speak the CQL native protocol on TCP 9042: a STARTUP handshake, then \
QUERY frames carrying CQL (a SQL-like language) and RESULT frames coming back. \
Each frame is tagged with a stream id so many requests can share the connection.",
            look_for: "\"CQL STARTUP\" opening a session, then \"CQL QUERY — SELECT …\" and \"CQL RESULT\".",
        },
        Protocol::Modbus => Lesson {
            title: "Modbus — talking to industrial machines",
            summary: "The simple, decades-old protocol that controls PLCs and factory gear.",
            body: "Modbus is how control systems read sensors and flip switches on \
industrial equipment — 'read these registers', 'write this coil'. It was designed \
in 1979 with no authentication or encryption, so anyone who can reach TCP 502 can \
issue commands. That's why spotting Modbus on a network — especially crossing into \
IT segments — matters for OT security.",
            look_for: "\"Modbus Read Holding Registers (fn 3)\" (a read) and \"Modbus Write Single Coil (fn 5)\" (a command); \"Modbus Exception\" when the device refuses.",
        },
        Protocol::Dnp3 => Lesson {
            title: "DNP3 — the grid's control protocol",
            summary: "Used by electric utilities and water systems to run remote equipment.",
            body: "DNP3 connects a control-room 'master' to remote 'outstations' across \
power and water infrastructure. Frames start with a fixed 0x0564 sync and address \
a specific station. Like Modbus it grew up without security; a modern secure \
variant exists, but plenty of legacy DNP3 still runs in the clear — worth flagging \
in any utility capture.",
            look_for: "\"DNP3 UNCONFIRMED_USER_DATA — 1 → 1024\" (master to outstation) and \"DNP3 LINK_STATUS\" replies; the numbers are station addresses.",
        },
        Protocol::Bacnet => Lesson {
            title: "BACnet — the building's nervous system",
            summary: "Runs HVAC, lighting and access control in commercial buildings.",
            body: "BACnet is how the thermostats, air handlers and door controllers in \
a building talk to their management system. Devices announce themselves with a \
'Who-Is' broadcast and answer with 'I-Am', then read and write properties on each \
other. It usually lives on UDP 47808 — and, like other building/OT protocols, \
assumes the network itself is trusted.",
            look_for: "\"BACnet Who-Is\" / \"BACnet I-Am\" discovery, then \"BACnet ReadProperty\" and \"BACnet WriteProperty\".",
        },
        Protocol::Enip => Lesson {
            title: "EtherNet/IP — Rockwell PLC networking",
            summary: "Carries CIP commands to Allen-Bradley and other industrial controllers.",
            body: "EtherNet/IP (the 'IP' is Industrial Protocol, not Internet Protocol) \
is the CIP object model over Ethernet, common on Rockwell/Allen-Bradley plants. A \
client registers a session, then sends explicit-messaging requests to read and \
write tags on a controller. Seeing it reach a PLC from an unexpected host is a \
classic OT red flag.",
            look_for: "\"EtherNet/IP RegisterSession\" opening a session, then \"EtherNet/IP SendRRData\" carrying the CIP request.",
        },
        Protocol::OpcUa => Lesson {
            title: "OPC UA — the Industry 4.0 data bus",
            summary: "The modern, secure-capable protocol linking factory equipment to IT.",
            body: "OPC UA is the standard that finally brought security and structure to \
industrial data — it can authenticate and encrypt, and it models equipment as \
browsable objects. Connections open with a Hello/Acknowledge handshake, then a \
secure channel, then service messages. It's the bridge between the plant floor \
and the cloud in most new IIoT deployments.",
            look_for: "\"OPC UA Hello\" / \"OPC UA Acknowledge\" to start, \"OPC UA OpenSecureChannel\", then \"OPC UA Message\" service calls.",
        },
        Protocol::Rtp => Lesson {
            title: "RTP — the voice and video itself",
            summary: "The actual audio/video stream of a call, once SIP has set it up.",
            body: "If SIP is the ringing, RTP is the conversation. Once a call is \
agreed, each side sends a steady stream of small UDP packets carrying encoded \
audio or video — dozens per second, each stamped with a sequence number and \
timestamp so the receiver can reorder them and measure jitter. There's no fixed \
port; it's negotiated per call, which is why netscope recognises RTP by its shape \
rather than a port number.",
            look_for: "\"RTP PCMU/8000 — seq 1234\" streaming steadily one way, with a matching stream coming back — that's a live call's audio.",
        },
        Protocol::Rtcp => Lesson {
            title: "RTCP — how a call reports its own quality",
            summary: "Control messages that ride alongside RTP to track loss and jitter.",
            body: "RTCP is RTP's companion: every few seconds each participant sends a \
report saying how many packets it sent or received, how much was lost, and how \
much the timing jittered. Phones and conferencing apps use these to adapt — \
switching codecs or bitrate when a call degrades. It's where the 'call quality' \
numbers come from.",
            look_for: "\"RTCP Sender Report\" and \"RTCP Receiver Report\" appearing periodically next to an RTP stream.",
        },
        Protocol::Kerberos => Lesson {
            title: "Kerberos — the enterprise login ticket",
            summary: "How Windows domains prove who you are without sending passwords around.",
            body: "Kerberos is the authentication system behind Active Directory. Instead \
of sending your password to every service, you prove yourself once to a central \
authority and get a time-limited 'ticket' you present elsewhere. The AS-REQ/AS-REP \
pair gets your first ticket; TGS-REQ/TGS-REP get tickets for specific services. \
Attackers watch these too — which is why the exchange is worth recognising.",
            look_for: "\"Kerberos AS-REQ\" (asking for a ticket) and \"Kerberos AS-REP\" (getting one), then \"Kerberos TGS-REQ\" for services.",
        },
        Protocol::Ldap => Lesson {
            title: "LDAP — the corporate directory",
            summary: "The protocol apps use to look up users and groups in a directory.",
            body: "LDAP is how software queries the central directory of an organisation \
— 'is this user valid?', 'what groups are they in?'. It also handles logins via a \
'bind'. A plain (unencrypted) simple bind sends the username and password in clear \
text, so seeing one on the wire is a real credential-exposure finding; production \
directories use LDAPS (LDAP over TLS) instead.",
            look_for: "\"LDAP bindRequest — cn=admin,…\" (a login) and \"LDAP searchRequest\" (a lookup).",
        },
        Protocol::Radius => Lesson {
            title: "RADIUS — who gets onto the network",
            summary: "Authenticates Wi-Fi, VPN and 802.1X access from a central server.",
            body: "When you join corporate Wi-Fi or dial a VPN, a RADIUS server usually \
decides whether to let you in. The access device sends an Access-Request with your \
credentials; the server replies Access-Accept, Access-Reject, or Access-Challenge \
for another round. A matching identifier ties each reply to its request. It also \
does accounting — logging when sessions start and stop.",
            look_for: "\"RADIUS Access-Request (id 7)\" then \"RADIUS Access-Accept (id 7)\" — the id pairs them up.",
        },
        Protocol::OpenVpn => Lesson {
            title: "OpenVPN — the classic open-source VPN",
            summary: "A widely used VPN that tunnels traffic over a single UDP or TCP port.",
            body: "OpenVPN builds an encrypted tunnel and runs everything — a TLS control \
channel and the bulk data channel — over one port (usually UDP 1194). netscope \
can't see inside the encryption, but the first byte of each packet reveals its \
type, so you can watch a tunnel negotiate (the hard-reset and control packets) and \
then carry data.",
            look_for: "\"OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2\" starting a tunnel, then \"OpenVPN P_DATA_V2\" carrying traffic.",
        },
        Protocol::WireGuard => Lesson {
            title: "WireGuard — the modern minimalist VPN",
            summary: "A fast, lean VPN built into modern kernels; tiny, fixed-format packets.",
            body: "WireGuard is the newer VPN that trades OpenVPN's flexibility for speed \
and simplicity. A connection is just a four-message handshake (initiation, \
response) followed by transport-data packets — all over UDP, all encrypted. The \
message type is in the clear, so you can see a tunnel come up and then move data, \
even though the contents stay hidden.",
            look_for: "\"WireGuard Handshake Initiation\" / \"Handshake Response\" to start, then \"WireGuard Transport Data\".",
        },
        Protocol::Esp => Lesson {
            title: "ESP — the encrypted half of IPsec",
            summary: "The IPsec payload that encrypts VPN traffic at the IP layer.",
            body: "ESP (Encapsulating Security Payload) is what most IPsec VPNs use to \
encrypt traffic. Unlike TCP or UDP it rides directly on IP, identified only by a \
number called the SPI that names which tunnel (security association) it belongs to, \
plus a sequence number. Everything after that is ciphertext — but the SPI lets you \
tell one tunnel from another.",
            look_for: "\"ESP (IPsec) — SPI 0xdeadbeef, seq 42\" — the SPI stays constant for one tunnel.",
        },
        Protocol::Ah => Lesson {
            title: "AH — IPsec integrity without secrecy",
            summary: "An IPsec header that proves a packet wasn't tampered with, but doesn't hide it.",
            body: "AH (Authentication Header) is the other IPsec mode: it authenticates \
a packet — proving it came from the right peer and wasn't altered — without \
encrypting the contents. It's used less than ESP today, since it breaks with NAT, \
but you'll still meet it. Like ESP it carries an SPI and sequence number, and it \
names the protocol it's protecting.",
            look_for: "\"AH (IPsec) — SPI 0x…, seq 7, protects TCP\".",
        },
        Protocol::Mqtt => Lesson {
            title: "MQTT — the language of IoT",
            summary: "How sensors and smart devices publish readings and receive commands.",
            body: "MQTT is the messaging protocol most of the Internet of Things runs on. \
Devices don't talk to each other directly — they connect to a broker, PUBLISH \
messages to named 'topics' (like sensors/livingroom/temp), and SUBSCRIBE to the \
topics they care about. It's deliberately tiny so it works on battery-powered \
gadgets. Plain MQTT on port 1883 is unencrypted, so topics and payloads are \
readable on the wire.",
            look_for: "\"MQTT CONNECT — client device01\" joining the broker, then \"MQTT PUBLISH — sensors/temp\" carrying a reading.",
        },
        Protocol::Coap => Lesson {
            title: "CoAP — HTTP shrunk for tiny devices",
            summary: "A REST-like request/response protocol for constrained IoT sensors.",
            body: "CoAP brings the familiar web model — GET, POST, PUT, DELETE on URLs — \
to devices too small for full HTTP. It runs over UDP to stay lightweight, with a \
4-byte header and compact binary options, and even supports multicast discovery. \
If MQTT is publish/subscribe messaging, CoAP is the request/response half of IoT — \
you can almost read it as HTTP.",
            look_for: "\"CoAP CON GET /sensors/temp\" (a request) and \"CoAP ACK 2.05\" (a Content response).",
        },
        Protocol::Bgp => Lesson {
            title: "BGP — the routes that hold the internet together",
            summary: "How independent networks tell each other which addresses they can reach.",
            body: "The internet is tens of thousands of separate networks (autonomous \
systems), and BGP is how they exchange 'reachability' — 'to get to these IP \
ranges, come through me'. A pair of routers OPEN a session, exchange UPDATE \
messages advertising or withdrawing routes, and send KEEPALIVEs to hold it. A bad \
BGP UPDATE can misdirect a chunk of the internet, which is why it's worth \
understanding.",
            look_for: "\"BGP OPEN — AS 65001\" starting a session, then \"BGP UPDATE\" (route changes) and periodic \"BGP KEEPALIVE\".",
        },
        Protocol::Ospf => Lesson {
            title: "OSPF — routing inside one network",
            summary: "How routers within an organisation learn the best paths to everywhere.",
            body: "Where BGP connects networks to each other, OSPF works inside a single \
organisation's network. Routers flood each other with 'link-state' information — \
who's connected to whom and at what cost — and each independently computes the \
shortest path to every destination. It starts with Hello packets discovering \
neighbours, then a database-sync exchange keeps everyone's map identical.",
            look_for: "\"OSPFv2 Hello — router 10.0.0.1\" finding neighbours, then \"OSPFv2 Link State Update\" sharing the map.",
        },
        Protocol::Lldp => Lesson {
            title: "LLDP — how the network maps itself",
            summary: "Switches announcing 'I'm this device, on this port' to their neighbours.",
            body: "LLDP is how network gear introduces itself to whatever is plugged in \
next to it — its name, the specific port, its capabilities. Network-management \
tools collect these announcements to draw an accurate topology map without anyone \
documenting the wiring by hand. It never leaves the local link; each switch only \
hears its direct neighbours.",
            look_for: "\"LLDP — switch-core port Gi0/1\" — the device name and the exact port you're connected to.",
        },
        Protocol::Lacp => Lesson {
            title: "LACP — bundling links into one",
            summary: "How two switches agree to treat several cables as a single fat link.",
            body: "When you want more bandwidth (or a backup) between two switches, you \
run several cables and bond them into one logical link. LACP is the conversation \
that sets that up and keeps it healthy — both ends continuously confirm the bundle \
is still valid. It's one of the 802.3 'slow protocols', sent a couple of times a \
second on the link itself.",
            look_for: "\"LACP v1 — link aggregation\" exchanged periodically between two switches forming a bundle.",
        },
        Protocol::Stp => Lesson {
            title: "STP — stopping network loops",
            summary: "The protocol that keeps redundant switch links from melting the network.",
            body: "If you wire switches in a loop (often for redundancy), broadcasts would \
circle forever and bring the network down. Spanning Tree Protocol prevents that: \
the switches elect a 'root bridge' and mathematically disable just enough links to \
break every loop, re-enabling them if an active link fails. The BPDUs you see are \
that election happening and being maintained.",
            look_for: "\"STP Configuration BPDU — root 32768/00:11:22:33:44:55\" — the elected root bridge everyone agrees on.",
        },
        Protocol::Mpls => Lesson {
            title: "MPLS — forwarding by label, not address",
            summary: "How carrier backbones move traffic fast using short labels.",
            body: "Instead of every router doing a full IP-address lookup, MPLS tags each \
packet with a short 'label' at the edge of the network; core routers then forward \
purely on that label — faster, and flexible enough to build VPNs and engineer \
traffic paths. Labels can stack (an outer one for the tunnel, an inner one for the \
service). netscope unwraps the labels and shows the real packet inside.",
            look_for: "\"MPLS label 16 (TTL 64) · IPv4 …\" — the part after the dot is the actual packet being carried.",
        },
        Protocol::Syslog => Lesson {
            title: "Syslog — the system's diary",
            summary: "Devices and servers send their log messages to a central collector.",
            body: "Routers, firewalls and servers can ship their log lines over the \
network to one place. Each message carries a priority that encodes a facility \
(which subsystem) and a severity (how bad), from Emergency down to Debug. It's \
usually plaintext over UDP 514 — handy for ops, but readable by anyone capturing.",
            look_for: "\"Syslog Error (facility 4) — …\" on UDP 514.",
        },
        Protocol::Tftp => Lesson {
            title: "TFTP — tiny file transfer",
            summary: "A bare-bones file copy used to boot devices and load firmware.",
            body: "TFTP is FTP stripped to the bone: no login, no listing, just read \
or write a file in fixed blocks over UDP 69. It's how switches, phones and \
diskless machines pull their config and firmware at boot. No encryption and no \
auth, so it's strictly for trusted local networks.",
            look_for: "\"TFTP Read Request — firmware.bin\" on UDP 69.",
        },
        Protocol::Ssdp => Lesson {
            title: "SSDP — 'who's on my network?'",
            summary: "The discovery chatter behind UPnP — smart TVs, printers, speakers.",
            body: "SSDP is how consumer gadgets find each other. A device shouts an \
M-SEARCH to a multicast address asking 'any media renderers out there?', and \
others answer or announce themselves with NOTIFY. It looks like HTTP but rides \
UDP 1900. Lots of it is normal on home/office LANs.",
            look_for: "\"SSDP M-SEARCH — device discovery\" on UDP 1900.",
        },
        Protocol::Stun => Lesson {
            title: "STUN — finding your way through NAT",
            summary: "Helps voice/video calls discover their public address behind a router.",
            body: "When two people make a WebRTC or VoIP call, each sits behind a home \
router (NAT) and doesn't know its own public address. STUN asks a public server \
'what address do you see me coming from?' so the two sides can connect directly. \
A magic-cookie value in the header identifies it — netscope checks that so it \
only labels real STUN.",
            look_for: "\"STUN Binding Request\" on UDP 3478, around a video call.",
        },
        Protocol::Llmnr => Lesson {
            title: "LLMNR — DNS's little local cousin",
            summary: "Windows machines resolving names on the local link without a DNS server.",
            body: "LLMNR lets computers on the same LAN ask 'who is called PRINTER?' \
without a configured DNS server, using the DNS message format on UDP 5355. It's \
convenient but a known security footgun: attackers can answer these queries to \
impersonate hosts, so many networks disable it.",
            look_for: "\"LLMNR — Query PRINTER\" on UDP 5355.",
        },
        Protocol::Rtsp => Lesson {
            title: "RTSP — the remote control for streams",
            summary: "The 'play/pause' signalling for IP cameras and streaming media.",
            body: "RTSP is like HTTP but for controlling a live media stream: DESCRIBE \
asks what's available, SETUP prepares it, then PLAY and PAUSE act like a remote. \
The actual audio/video usually flows separately as RTP. It's the backbone of IP \
security cameras.",
            look_for: "\"RTSP DESCRIBE — rtsp://cam/stream\" on TCP 554.",
        },
        Protocol::Irc => Lesson {
            title: "IRC — classic text chat",
            summary: "One of the internet's oldest group-chat protocols, still widely used.",
            body: "IRC is plain-text chat: you JOIN a channel and PRIVMSG messages to \
it. Simple and human-readable on TCP 6667 (or TLS on 6697). Because it's easy to \
script, it's also historically been used to control botnets — so unexpected IRC \
from a server is worth a second look.",
            look_for: "\"IRC PRIVMSG — :nick … #channel\" on TCP 6667.",
        },
        Protocol::Rfb => Lesson {
            title: "RFB / VNC — sharing a screen",
            summary: "The remote-desktop protocol behind VNC — see and control another PC.",
            body: "RFB (Remote Framebuffer), better known as VNC, streams one machine's \
screen to another and sends back mouse and keyboard events. A session opens with \
a version banner like 'RFB 003.008'. Plain VNC is unencrypted, so it's often \
tunnelled over SSH or a VPN.",
            look_for: "\"VNC/RFB handshake — RFB 003.008\" on TCP 5900.",
        },
        Protocol::Whois => Lesson {
            title: "WHOIS — who owns this domain?",
            summary: "A plain-text lookup for who registered a domain or IP range.",
            body: "WHOIS is dead simple: connect to a registry on TCP 43, send one line \
(a domain or IP), and read back a text record of who registered it and when. \
Investigators use it to attribute domains and IP blocks.",
            look_for: "\"WHOIS — example.com\" on TCP 43.",
        },
        Protocol::Nntp => Lesson {
            title: "NNTP — Usenet newsgroups",
            summary: "The protocol behind Usenet discussion groups and binary downloads.",
            body: "NNTP moves articles between news servers and to readers, organised \
into newsgroups. Commands like GROUP and ARTICLE fetch content; servers answer \
with 3-digit status codes, much like FTP or SMTP. Still used for both discussion \
and large binary downloads.",
            look_for: "\"NNTP — GROUP comp.lang.rust\" on TCP 119.",
        },
        Protocol::Sctp => Lesson {
            title: "SCTP — TCP's multi-streaming cousin",
            summary: "A reliable transport used heavily in telecom (4G/5G) signalling.",
            body: "SCTP does what TCP does — reliable, ordered delivery — but adds \
multiple independent streams in one connection (so one lost message doesn't \
stall the rest) and multi-homing for failover. You'll mostly see it carrying \
mobile-core signalling like Diameter and S1AP.",
            look_for: "\"SCTP INIT — 1234 → 38412\" — the chunk type names the action.",
        },
        Protocol::Gre => Lesson {
            title: "GRE — a plain tunnel",
            summary: "Wraps one packet inside another to build tunnels and VPNs.",
            body: "GRE is a simple envelope: it takes a whole packet and puts it inside \
another IP packet so it can cross a network that otherwise couldn't route it. \
It's the basis of PPTP VPNs and many router-to-router tunnels. netscope shows \
what kind of packet is riding inside.",
            look_for: "\"GRE — tunnelling IPv4\" — the inner protocol being carried.",
        },
        Protocol::Igmp => Lesson {
            title: "IGMP — joining multicast groups",
            summary: "How a device says 'send me this multicast stream' (IPTV, discovery).",
            body: "Multicast lets one sender reach many receivers efficiently. IGMP is \
how your device tells the local router 'I want the traffic for group 239.1.2.3' \
(a Membership Report) or 'stop sending it' (a Leave). Common around IPTV and \
service discovery.",
            look_for: "\"IGMP v2 Membership Report — group 239.1.2.3\".",
        },
        Protocol::Dhcpv6 => Lesson {
            title: "DHCPv6 — addresses for IPv6",
            summary: "The IPv6 version of DHCP — handing out addresses and settings.",
            body: "Just like DHCP does for IPv4, DHCPv6 assigns IPv6 addresses and \
config (DNS servers, etc.). A device Solicits, servers Advertise, and it \
Requests and gets a Reply. Runs on UDP 546/547.",
            look_for: "\"DHCPv6 Solicit\" / \"DHCPv6 Reply\" on UDP 546-547.",
        },
        Protocol::Rip => Lesson {
            title: "RIP — the simplest router chatter",
            summary: "An old distance-vector routing protocol still seen on small networks.",
            body: "RIP is routing at its most basic: routers periodically tell each \
other 'I can reach network X in N hops'. Simple but slow to react and limited to \
15 hops, so it survives mostly on small or legacy networks. Runs on UDP 520.",
            look_for: "\"RIPv2 Response\" on UDP 520.",
        },
        Protocol::Nbns => Lesson {
            title: "NBNS — old-school Windows name lookup",
            summary: "NetBIOS name resolution — the pre-DNS way Windows hosts found each other.",
            body: "Before DNS took over everywhere, Windows machines used NetBIOS names \
and this service to resolve them on the local network. Like LLMNR, it's a known \
spoofing target and is often disabled in hardened environments. Runs on UDP 137.",
            look_for: "\"NBNS Name Query\" on UDP 137.",
        },
        Protocol::Socks => Lesson {
            title: "SOCKS — a generic proxy",
            summary: "A proxy that forwards any TCP/UDP connection — used by Tor and tunnels.",
            body: "SOCKS is a proxy that doesn't care what protocol you're speaking: \
it just relays your connection to wherever you ask. SOCKS5 adds authentication \
and UDP. It's what tools like Tor and SSH dynamic port-forwarding expose.",
            look_for: "\"SOCKS5 Connect\" on TCP 1080.",
        },
        Protocol::Memcached => Lesson {
            title: "Memcached — a memory cache",
            summary: "A fast in-memory key-value store apps use to cache results.",
            body: "Memcached keeps frequently used data in RAM so applications don't \
have to hit a slower database every time. Simple get/set commands over TCP 11211. \
Left exposed to the internet it has been abused for huge amplification attacks, \
so seeing it on a public interface is worth noting.",
            look_for: "\"Memcached get — session:42\" on TCP 11211.",
        },
        Protocol::BitTorrent => Lesson {
            title: "BitTorrent — peer-to-peer file sharing",
            summary: "Downloads a file in pieces from many peers at once.",
            body: "Instead of one server, BitTorrent gets a file from lots of peers \
simultaneously, each sharing the pieces they have. Connections open with a fixed \
handshake naming the 'BitTorrent protocol'. Common on ports 6881-6889 but peers \
use many ports.",
            look_for: "\"BitTorrent handshake\" — the start of a peer connection.",
        },
        Protocol::Git => Lesson {
            title: "Git — the native git:// transport",
            summary: "The unencrypted protocol behind `git clone git://…`.",
            body: "Git can move repositories over its own lightweight protocol on TCP \
9418. It names a service — upload-pack for clone/fetch, receive-pack for push. \
It has no encryption or authentication, so it's read-only and mostly superseded \
by SSH and HTTPS.",
            look_for: "\"Git — upload-pack (clone/fetch)\" on TCP 9418.",
        },
        Protocol::Xmpp => Lesson {
            title: "XMPP — open instant messaging",
            summary: "The Jabber chat protocol — an XML stream of messages and presence.",
            body: "XMPP (formerly Jabber) is an open standard for chat: an ongoing XML \
stream where <message> carries chat, <presence> says who's online, and <iq> does \
requests. Used by some messaging apps and lots of IoT/push backends. Runs on TCP \
5222.",
            look_for: "\"XMPP message\" / \"XMPP presence\" on TCP 5222.",
        },
        Protocol::Finger => Lesson {
            title: "Finger — 'who is this user?'",
            summary: "A very old service that reports who's logged in on a machine.",
            body: "Finger dates to the early internet: connect to TCP 79, send a \
username, and get back details about that user or everyone logged in. It leaks \
information and is essentially obsolete, so seeing it today is unusual.",
            look_for: "\"Finger — alice\" on TCP 79.",
        },
        Protocol::Vrrp => Lesson {
            title: "VRRP — a shared backup gateway",
            summary: "Lets two routers share one virtual IP so the gateway never goes down.",
            body: "If your default gateway is a single router and it dies, everyone \
loses internet. VRRP has several routers share one virtual IP: one is master, \
the others stand by, and if the master fails a backup takes over in seconds. \
The advertisements you see are the master saying 'I'm still here'.",
            look_for: "\"VRRPv3 Advertisement — VRID 10, priority 100\" (IP protocol 112).",
        },
        Protocol::Pim => Lesson {
            title: "PIM — routing multicast",
            summary: "How routers build delivery trees for multicast traffic.",
            body: "Where IGMP is how a host joins a multicast group, PIM is how the \
routers between the source and the receivers agree on a path to carry that \
stream — without flooding it everywhere. Common wherever IPTV or market-data \
multicast is routed across a network.",
            look_for: "\"PIMv2 Join/Prune\" (IP protocol 103).",
        },
        Protocol::Eigrp => Lesson {
            title: "EIGRP — Cisco's routing protocol",
            summary: "A fast interior routing protocol used inside Cisco networks.",
            body: "EIGRP is how Cisco routers inside one organisation learn which \
networks each other can reach and pick good paths. Hello messages keep neighbours \
alive; Update/Query/Reply exchange routes. It reacts quickly to changes.",
            look_for: "\"EIGRPv2 Hello\" (IP protocol 88).",
        },
        Protocol::Pppoe => Lesson {
            title: "PPPoE — how DSL logs in",
            summary: "Wraps a dial-up-style session over Ethernet — common on DSL links.",
            body: "Many home broadband links (especially DSL) authenticate with PPPoE: \
a short discovery handshake (PADI/PADO/PADR/PADS) finds the access concentrator, \
then a session carries your traffic with a username/password login. It's why your \
router has a 'PPPoE username' field.",
            look_for: "\"PPPoE PADI (discovery init)\" then \"PPPoE session\".",
        },
        Protocol::Eapol => Lesson {
            title: "EAPOL / 802.1X — port access control",
            summary: "The login at the network's edge — and the Wi-Fi WPA handshake.",
            body: "802.1X decides whether a device is even allowed onto the network, \
before it gets an IP. EAPOL carries that conversation. You also see it as the \
WPA/WPA2 4-way 'Key' handshake every time a device joins a protected Wi-Fi.",
            look_for: "\"EAPOL Key (WPA handshake)\" when a device joins Wi-Fi.",
        },
        Protocol::L2tp => Lesson {
            title: "L2TP — a VPN tunnel",
            summary: "Builds a tunnel between sites or clients, usually secured by IPsec.",
            body: "L2TP carries one network's traffic across another by tunnelling it. \
On its own it has no encryption, so it's almost always paired with IPsec (you'll \
see 'L2TP/IPsec' in VPN settings). Control messages set the tunnel up; data \
messages carry the payload.",
            look_for: "\"L2TPv2 control message\" on UDP 1701.",
        },
        Protocol::Gtp => Lesson {
            title: "GTP — the mobile network's tunnel",
            summary: "Carries your phone's data through the 4G/5G core network.",
            body: "When you browse on mobile data, your packets are tunnelled across \
the carrier's core with GTP: a control part (GTP-C) sets up your session, and a \
user part (GTP-U) carries the actual traffic. Central to how 3G/4G/5G data works.",
            look_for: "\"GTP G-PDU (user data)\" on UDP 2152.",
        },
        Protocol::Rmcp => Lesson {
            title: "RMCP / IPMI — managing servers out-of-band",
            summary: "Talks to a server's management chip (BMC/iLO/iDRAC) even when it's off.",
            body: "Servers have a small always-on management processor (a BMC, branded \
iLO or iDRAC) that lets admins power-cycle and monitor the machine remotely, even \
when the OS is down. RMCP/IPMI is how that's reached over the network. Exposed to \
the internet it's a serious risk, so seeing it there matters.",
            look_for: "\"RMCP/IPMI (out-of-band management)\" on UDP 623.",
        },
        Protocol::WsDiscovery => Lesson {
            title: "WS-Discovery — finding printers and cameras",
            summary: "How Windows and ONVIF IP cameras announce and find each other.",
            body: "WS-Discovery is a SOAP/XML discovery protocol: a device sends a \
Probe ('any printers here?') and others answer or announce with Hello/Bye. It's \
what makes network printers and ONVIF security cameras appear automatically.",
            look_for: "\"WS-Discovery Probe (searching)\" on UDP 3702.",
        },
        Protocol::Tacacs => Lesson {
            title: "TACACS+ — who can touch the routers",
            summary: "Cisco's protocol for logging admins into network devices.",
            body: "When an engineer logs into a router or switch, TACACS+ checks their \
username/password (authentication), what commands they're allowed (authorization), \
and logs what they did (accounting) — all against a central server. Unlike RADIUS \
it encrypts the whole body.",
            look_for: "\"TACACS+ Authentication\" on TCP 49.",
        },
        Protocol::Diameter => Lesson {
            title: "Diameter — RADIUS's big successor",
            summary: "The AAA protocol behind mobile-network authentication and billing.",
            body: "Diameter replaced RADIUS for large carriers: it authenticates \
subscribers, authorises services, and drives billing across the mobile core. \
Requests and Answers carry command codes like Credit-Control for charging.",
            look_for: "\"Diameter Device-Watchdog Request\" on TCP/SCTP 3868.",
        },
        Protocol::Rlogin => Lesson {
            title: "rlogin — an obsolete remote login",
            summary: "A BSD-era remote shell — cleartext, insecure, replaced by SSH.",
            body: "rlogin let you log into another Unix machine over the network — but \
it sends everything, including what you type, in the clear, and trusts hosts by \
name. SSH replaced it decades ago, so seeing rlogin today is a red flag.",
            look_for: "\"rlogin — login alice/bob\" on TCP 513.",
        },
        Protocol::Dccp => Lesson {
            title: "DCCP — TCP without the retransmits",
            summary: "A transport for streaming: congestion control, but no re-sending lost data.",
            body: "Some real-time apps want TCP's politeness (not flooding the network) \
but not its insistence on redelivering old data — by the time it arrives, it's \
too late to be useful. DCCP gives congestion control without reliability, aimed \
at streaming and gaming.",
            look_for: "\"DCCP Request — 5001 → 5002\" (IP protocol 33).",
        },
        Protocol::Dtls => Lesson {
            title: "DTLS — TLS for UDP",
            summary: "The encryption behind WebRTC media and some VPNs.",
            body: "TLS needs the reliable, ordered stream that TCP gives it. DTLS is a \
version of TLS redesigned to run over UDP's unreliable datagrams, so real-time \
traffic (video calls, some VPNs) can be encrypted without TCP's delays. Same \
privacy guarantees, datagram-friendly.",
            look_for: "\"DTLS 1.2 Handshake\" / \"DTLS 1.2 Application Data\".",
        },
        Protocol::Netflow => Lesson {
            title: "NetFlow / IPFIX — traffic accounting",
            summary: "Routers summarising 'who talked to whom' and exporting it to a collector.",
            body: "Instead of capturing every packet, a router can keep a running tally \
of flows — source, destination, ports, byte counts — and export those summaries \
with NetFlow (or its standard successor, IPFIX). It's how networks do capacity \
planning and spot anomalies without storing full traffic.",
            look_for: "\"IPFIX flow export\" on UDP 2055/4739.",
        },
        Protocol::Sflow => Lesson {
            title: "sFlow — sampled traffic",
            summary: "Switches sending a random sample of packets plus counters to a collector.",
            body: "sFlow takes a different approach to NetFlow: rather than track every \
flow, it randomly samples 1-in-N packets and ships them, along with interface \
counters, to a collector. Cheap enough to run at line rate on big switches, and \
statistically good enough to see the big picture.",
            look_for: "\"sFlow v5 sample datagram\" on UDP 6343.",
        },
        Protocol::Bfd => Lesson {
            title: "BFD — is the link still up?",
            summary: "A very fast heartbeat between routers so failover happens in milliseconds.",
            body: "Routing protocols can take seconds to notice a dead neighbour. BFD is \
a lightweight, rapid hello between two devices whose only job is to detect a \
broken path in milliseconds and tell the routing protocol to reroute. You'll see \
a steady stream of tiny control packets.",
            look_for: "\"BFDv1 control — state Up\" on UDP 3784.",
        },
        Protocol::Hsrp => Lesson {
            title: "HSRP — Cisco's backup gateway",
            summary: "Cisco's version of VRRP: two routers sharing one gateway IP.",
            body: "Like VRRP, HSRP lets several routers present one virtual gateway so a \
failure is invisible to hosts. One router is Active, another Standby; Hello \
messages keep them in sync and trigger a takeover when the Active one goes quiet.",
            look_for: "\"HSRP Hello (Active)\" on UDP 1985.",
        },
        Protocol::Iscsi => Lesson {
            title: "iSCSI — disks over the network",
            summary: "Carries raw SCSI storage commands over TCP, so a server's 'disk' is remote.",
            body: "iSCSI lets a server use a disk that physically lives on a storage \
array across the network, as if it were local. It wraps the same low-level SCSI \
commands a real disk uses inside TCP. Common in data centres for shared storage.",
            look_for: "\"iSCSI Login Request\" / \"iSCSI SCSI Command\" on TCP 3260.",
        },
        Protocol::Rtmp => Lesson {
            title: "RTMP — live video ingest",
            summary: "The Flash-era streaming protocol, still used to push live video to servers.",
            body: "RTMP was built for Flash but outlived it: it's still how many \
streamers push live video into platforms (which then transcode it to modern \
formats). A session starts with a distinctive handshake, then carries chunked \
audio/video.",
            look_for: "\"RTMP handshake\" on TCP 1935.",
        },
        Protocol::Smpp => Lesson {
            title: "SMPP — sending SMS",
            summary: "The protocol apps and gateways use to send and receive text messages.",
            body: "When an app sends you an SMS (a login code, a delivery alert), it \
usually reaches an SMS gateway over SMPP. It binds as transmitter/receiver, then \
submit_sm sends a message and deliver_sm brings replies back.",
            look_for: "\"SMPP submit_sm\" on TCP 2775.",
        },
        Protocol::OpenFlow => Lesson {
            title: "OpenFlow — software-defined networking",
            summary: "How a central controller programs switches' forwarding tables.",
            body: "In SDN, switches don't decide routing on their own — a central \
controller does, and pushes the decisions down as flow rules over OpenFlow. \
Packet-In asks the controller 'what do I do with this?', Flow-Mod installs the \
answer. It decouples the network's brains from the hardware.",
            look_for: "\"OpenFlow Packet-In\" / \"OpenFlow Flow-Mod\" on TCP 6653.",
        },
        Protocol::Nats => Lesson {
            title: "NATS — cloud messaging",
            summary: "A fast publish/subscribe system tying microservices together.",
            body: "NATS is a lightweight message bus: services PUBlish to subjects and \
SUBscribe to the ones they care about, and the server fans messages out. Its \
text protocol (PUB/SUB/MSG/PING) is simple and very fast, popular in \
cloud-native systems.",
            look_for: "\"NATS PUB — events.orders\" on TCP 4222.",
        },
        Protocol::Stomp => Lesson {
            title: "STOMP — simple broker messaging",
            summary: "A plain-text protocol for talking to message brokers like ActiveMQ.",
            body: "STOMP is deliberately simple: a handful of text commands (CONNECT, \
SEND, SUBSCRIBE, MESSAGE) let almost any language talk to a message broker \
without a heavy client library. Human-readable on the wire.",
            look_for: "\"STOMP SEND\" / \"STOMP MESSAGE\" on TCP 61613.",
        },
        Protocol::Profinet => Lesson {
            title: "PROFINET — factory-floor real-time",
            summary: "Runs the sensors, motors and PLCs on an industrial network in real time.",
            body: "PROFINET carries the tightly-timed data that keeps a production line \
running — a controller reading sensors and driving actuators, often every few \
milliseconds. It rides directly on Ethernet (no IP) for speed. DCP messages \
discover and name devices; RT frames carry the cyclic process data.",
            look_for: "\"PROFINET RT Class 1 (cyclic data)\" or \"PROFINET DCP Identify\".",
        },
        Protocol::Wol => Lesson {
            title: "Wake-on-LAN — powering a machine on remotely",
            summary: "A special broadcast that turns a sleeping computer on over the network.",
            body: "A 'magic packet' contains the target's MAC address repeated 16 times. \
A powered-off-but-plugged-in machine's network card watches for it and boots the \
system when it arrives. Handy for remote admin — and worth noticing if unexpected.",
            look_for: "\"Wake-on-LAN — magic packet for de:ad:be:ef:00:01\".",
        },
        Protocol::Glbp => Lesson {
            title: "GLBP — sharing the load across gateways",
            summary: "Cisco redundancy that also load-balances across several routers.",
            body: "Where HSRP/VRRP keep a backup gateway ready, GLBP goes further and \
lets multiple routers actively share the traffic at the same time, not just stand \
by. Hello messages coordinate which router handles which hosts.",
            look_for: "\"GLBP Hello\" on UDP 3222.",
        },
        Protocol::Wccp => Lesson {
            title: "WCCP — steering traffic to a cache",
            summary: "Lets a router hand web requests to a caching proxy transparently.",
            body: "WCCP is how a router transparently redirects traffic (classically web \
requests) to a nearby cache or security appliance, without reconfiguring clients. \
The router and cache exchange Here-I-Am / I-See-You to stay in sync.",
            look_for: "\"WCCP Here-I-Am\" on UDP 2048.",
        },
        Protocol::Mgcp => Lesson {
            title: "MGCP — controlling VoIP gateways",
            summary: "A call agent telling media gateways how to set up phone calls.",
            body: "In some VoIP designs the intelligence is central: a call agent uses \
MGCP to command simple media gateways to create connections, play tones and \
report events. Commands are four-letter verbs like CRCX (create connection).",
            look_for: "\"MGCP CRCX (command)\" on UDP 2427.",
        },
        Protocol::Nbds => Lesson {
            title: "NetBIOS Datagram — legacy Windows broadcast",
            summary: "The connectionless side of old Windows networking (browsing/announcements).",
            body: "NetBIOS Datagram Service carries the broadcast chatter of classic \
Windows networking — network browsing, host announcements. Like its NBNS cousin \
it's noisy, legacy, and often disabled in modern/hardened networks.",
            look_for: "\"NetBIOS-DGM Broadcast\" on UDP 138.",
        },
        Protocol::Dicom => Lesson {
            title: "DICOM — medical images on the wire",
            summary: "How scanners, PACS and viewers exchange X-rays, CTs and MRIs.",
            body: "DICOM is the standard for medical imaging: a scanner associates with \
an archive (A-ASSOCIATE), then ships images and metadata (P-DATA-TF). Because it \
carries patient data, seeing it in a capture is sensitive by nature.",
            look_for: "\"DICOM A-ASSOCIATE-RQ\" / \"DICOM P-DATA-TF\" on TCP 104/11112.",
        },
        Protocol::Hl7 => Lesson {
            title: "HL7 — hospital data exchange",
            summary: "The text format hospitals use to share admissions, orders and lab results.",
            body: "HL7 v2 is how hospital systems talk: an ADT^A01 message admits a \
patient, ORU^R01 delivers lab results, and so on. It's pipe-delimited text, often \
wrapped in MLLP framing over TCP. Like DICOM, it carries protected health data.",
            look_for: "\"HL7 ADT^A01 (MLLP)\" on TCP 2575.",
        },
        Protocol::Fix => Lesson {
            title: "FIX — the language of trading",
            summary: "How trading systems and exchanges send orders and market data.",
            body: "FIX is the lingua franca of electronic finance: tag=value pairs \
(8=FIX.4.2…35=D…) carry orders (NewOrderSingle), fills (ExecutionReport) and \
market data between brokers, funds and exchanges. Latency-sensitive and \
high-value, so it's tightly monitored.",
            look_for: "\"FIX FIX.4.2 — NewOrderSingle\" — tag 35 is the message type.",
        },
        Protocol::S7comm => Lesson {
            title: "S7comm — talking to Siemens PLCs",
            summary: "The protocol used to program and read Siemens S7 industrial controllers.",
            body: "S7comm is how engineering software and SCADA systems read and write \
the memory of Siemens S7 PLCs — the controllers running physical processes. It \
rides on ISO-on-TCP (port 102). It has no built-in authentication, which is why \
industrial-network monitoring cares about it (recall Stuxnet).",
            look_for: "\"S7comm Job request\" on TCP 102.",
        },
        Protocol::Iec104 => Lesson {
            title: "IEC 60870-5-104 — power-grid telecontrol",
            summary: "SCADA commands and measurements for electrical substations.",
            body: "IEC-104 carries the telemetry and control for power utilities: a \
control centre reads measurements and sends commands (open/close a breaker) to \
substation equipment over TCP. Critical infrastructure, so unexpected IEC-104 \
traffic is a serious flag.",
            look_for: "\"IEC 60870-5-104 I-frame (information)\" on TCP 2404.",
        },
        Protocol::Ldp => Lesson {
            title: "LDP — handing out MPLS labels",
            summary: "How MPLS routers agree on the labels that build forwarding paths.",
            body: "MPLS forwards packets by short labels instead of IP lookups. LDP is \
how routers tell each other 'use label N to reach network X', building the \
label-switched paths. Hello messages find neighbours; Label Mapping messages \
distribute the labels.",
            look_for: "\"LDP Hello\" / \"LDP Label Mapping\" on TCP/UDP 646.",
        },
        Protocol::Goose => Lesson {
            title: "GOOSE — substation trip signals",
            summary: "Ultra-fast IEC 61850 messages that trip breakers in a power substation.",
            body: "When a fault happens in an electrical substation, protection relays \
must act in milliseconds. GOOSE carries those trip/status signals directly over \
Ethernet (no IP) for minimum delay, repeating them for reliability. Seeing \
unexpected GOOSE is a serious grid-security signal.",
            look_for: "\"GOOSE — APPID 0x0001 (IEC 61850 substation event)\".",
        },
        Protocol::Ptp => Lesson {
            title: "PTP — clocks in lockstep",
            summary: "Sub-microsecond time sync for finance, telecom, power and broadcast.",
            body: "Some systems need clocks aligned far tighter than NTP can manage — \
trading timestamps, 5G radios, power-grid measurements, live video. PTP (IEEE \
1588) syncs them to sub-microsecond accuracy by carefully measuring message \
delays. Sync/Follow_Up/Delay_Req are the exchange.",
            look_for: "\"PTP Sync\" / \"PTP Announce\" on Ethernet or UDP 319/320.",
        },
        Protocol::Rsvp => Lesson {
            title: "RSVP — reserving bandwidth",
            summary: "Signals QoS reservations and sets up MPLS traffic-engineering tunnels.",
            body: "RSVP lets a device ask the network to guarantee bandwidth along a \
path (a Path message going out, a Resv coming back). Its main modern use is \
MPLS-TE: building label-switched tunnels with reserved capacity across a \
provider's core.",
            look_for: "\"RSVP Path\" / \"RSVP Resv\" (IP protocol 46).",
        },
        Protocol::Isakmp => Lesson {
            title: "ISAKMP / IKE — negotiating a VPN",
            summary: "The handshake that sets up the keys for an IPsec VPN tunnel.",
            body: "Before IPsec can encrypt traffic, both ends must agree on keys and \
parameters. IKE (carried by ISAKMP) is that negotiation: IKE_SA_INIT and IKE_AUTH \
in IKEv2 establish the secure tunnel. On UDP 500, or 4500 when NAT is in the way.",
            look_for: "\"ISAKMP/IKEv2 IKE_SA_INIT\" on UDP 500/4500.",
        },
        Protocol::Geneve => Lesson {
            title: "Geneve — a flexible overlay",
            summary: "Wraps whole Ethernet frames to build virtual networks (a VXLAN successor).",
            body: "Cloud and data-centre networks build many virtual networks on top of \
one physical fabric. Geneve tunnels a tenant's Ethernet frame inside UDP, tagged \
with a VNI identifying which virtual network it belongs to — like VXLAN, but with \
room for extensible options.",
            look_for: "\"Geneve — VNI 100, carrying Ethernet\" on UDP 6081.",
        },
        Protocol::Capwap => Lesson {
            title: "CAPWAP — controller-managed Wi-Fi",
            summary: "How a wireless controller manages many thin access points.",
            body: "In enterprise Wi-Fi the access points are 'thin' — a central \
controller does the thinking. CAPWAP is the tunnel between them: a control channel \
(usually DTLS-encrypted) configures the APs, and a data channel carries client \
traffic back to the controller.",
            look_for: "\"CAPWAP control (DTLS-encrypted)\" on UDP 5246/5247.",
        },
        Protocol::Teredo => Lesson {
            title: "Teredo — IPv6 through a NAT",
            summary: "Tunnels IPv6 inside IPv4/UDP so it can cross home NAT routers.",
            body: "Teredo is a transition technology: it lets a host with only IPv4 (and \
behind a NAT) still reach the IPv6 internet by wrapping IPv6 packets in IPv4 UDP. \
Handy historically, but also a way traffic can slip past IPv4-only controls, so \
it's worth noticing.",
            look_for: "\"Teredo — tunnelled IPv6 packet\" on UDP 3544.",
        },
        Protocol::Gvcp => Lesson {
            title: "GVCP — machine-vision cameras",
            summary: "Discovers and configures industrial GigE Vision cameras.",
            body: "Factory inspection and robotics use GigE Vision cameras. GVCP is the \
control side: discovering cameras on the network and reading/writing their \
registers (exposure, triggering, IP settings). The high-rate image data rides a \
separate stream.",
            look_for: "\"GVCP Discovery\" / \"GVCP WriteReg\" on UDP 3956.",
        },
        Protocol::Rpc => Lesson {
            title: "ONC RPC / NFS — remote file access",
            summary: "The plumbing behind NFS network file shares and the portmapper.",
            body: "ONC RPC lets a program call a procedure on another machine. Its most \
familiar user is NFS — mounting a remote directory as if it were local. The \
Portmapper (port 111) tells clients which port each RPC service is on; NFS itself \
is program 100003.",
            look_for: "\"NFS call\" / \"Portmap call\" on TCP/UDP 111 and 2049.",
        },
        Protocol::Graphite => Lesson {
            title: "Graphite — pushing metrics",
            summary: "A dead-simple line format apps use to report time-series metrics.",
            body: "Graphite/Carbon accepts metrics as plain text lines — \
`path value timestamp` — which makes almost anything able to emit them. A \
monitoring backend stores and graphs the series. If you see it, something is \
reporting operational metrics.",
            look_for: "\"Graphite — servers.web1.cpu\" on TCP 2003.",
        },
        Protocol::Gearman => Lesson {
            title: "Gearman — farming out jobs",
            summary: "A job server that hands work from clients to worker processes.",
            body: "Gearman lets an application offload work: a client submits a job, the \
server queues it, and an available worker picks it up and returns the result. \
Requests and responses use a small binary framing ('\\0REQ' / '\\0RES').",
            look_for: "\"Gearman request\" / \"Gearman response\" on TCP 4730.",
        },
        Protocol::Beanstalk => Lesson {
            title: "beanstalkd — a simple work queue",
            summary: "A lightweight queue for background jobs, with a plain-text protocol.",
            body: "beanstalkd is a minimal work queue: producers `put` jobs, workers \
`reserve` and then `delete` them when done. Its text protocol is easy to read on \
the wire and easy to speak from any language.",
            look_for: "\"Beanstalk put\" / \"Beanstalk reserve\" on TCP 11300.",
        },
        Protocol::Ethercat => Lesson {
            title: "EtherCAT — a fieldbus on Ethernet",
            summary: "Real-time industrial control that passes one frame down a chain of devices.",
            body: "EtherCAT wires up motors, drives and IO in machines and factories. \
Cleverly, one Ethernet frame flies through every slave device 'on the fly' — each \
reads and writes its slice as the frame passes — giving very low, predictable \
latency. Runs directly on Ethernet, no IP.",
            look_for: "\"EtherCAT LRW (logical read/write)\" (EtherType 0x88A4).",
        },
        Protocol::Fcoe => Lesson {
            title: "FCoE — storage over Ethernet",
            summary: "Carries Fibre Channel storage traffic on a converged Ethernet network.",
            body: "Data centres traditionally ran a separate Fibre Channel network just \
for storage. FCoE puts those same FC frames onto the regular Ethernet fabric, so \
one set of cables carries both LAN and storage. Seeing it means SAN traffic on \
the wire.",
            look_for: "\"FCoE — Fibre Channel device data\" (EtherType 0x8906).",
        },
        Protocol::Macsec => Lesson {
            title: "MACsec — encrypting the wire itself",
            summary: "802.1AE encryption between two directly-connected devices.",
            body: "MACsec encrypts Ethernet frames hop by hop — between a device and \
the switch it plugs into — so even someone tapping that cable sees only ciphertext. \
Unlike a VPN it protects the local link, including traffic that never leaves the \
building.",
            look_for: "\"MACsec — encrypted (AN 1)\" (EtherType 0x88E5).",
        },
        Protocol::Rarp => Lesson {
            title: "RARP — ARP in reverse",
            summary: "A diskless device asking 'I know my MAC — what's my IP?'",
            body: "RARP is the mirror image of ARP: instead of finding a MAC for a known \
IP, a device that only knows its own hardware address asks a server for an IP. \
It's largely obsolete (BOOTP/DHCP replaced it), so it's rare and worth a glance \
when it appears.",
            look_for: "\"RARP Request\" / \"RARP Reply\" (EtherType 0x8035).",
        },
        Protocol::Rtps => Lesson {
            title: "RTPS / DDS — robots' nervous system",
            summary: "The real-time pub/sub bus behind ROS 2, vehicles and defence systems.",
            body: "DDS is a data-distribution middleware where components publish and \
subscribe to topics without knowing each other directly; RTPS is its wire \
protocol. It's the backbone of ROS 2 robotics, autonomous vehicles and many \
industrial/defence systems. Seeing it maps out a control system.",
            look_for: "\"RTPS/DDS DATA\" / \"RTPS/DDS HEARTBEAT\" (magic \"RTPS\").",
        },
        Protocol::Influxdb => Lesson {
            title: "InfluxDB — time-series metrics",
            summary: "A simple text line format for writing measurements to a time-series DB.",
            body: "InfluxDB's line protocol lets anything report metrics as text: a \
measurement name, tags, fields and a timestamp. Monitoring and IoT systems push \
huge volumes of these points. If you see it, something is recording operational \
data.",
            look_for: "\"InfluxDB — cpu\" on UDP 8089.",
        },
        Protocol::MqttSn => Lesson {
            title: "MQTT-SN — MQTT for tiny sensors",
            summary: "A UDP-based variant of MQTT for constrained wireless sensor devices.",
            body: "Plain MQTT needs a TCP connection, which is heavy for a battery \
sensor on a flaky radio. MQTT-SN keeps MQTT's publish/subscribe model but runs \
over UDP with smaller messages and gateways, so very constrained devices can \
still play.",
            look_for: "\"MQTT-SN PUBLISH\" / \"MQTT-SN CONNECT\" on UDP 1883.",
        },
        Protocol::Babel => Lesson {
            title: "Babel — routing for mesh networks",
            summary: "A robust distance-vector routing protocol popular in community meshes.",
            body: "Babel is a routing protocol designed to work well on messy, changing \
networks — wireless mesh and community networks especially — avoiding the loops \
that trip up simpler schemes. Routers periodically exchange updates about which \
destinations they can reach.",
            look_for: "\"Babel routing update (v2)\" on UDP 6696.",
        },
        Protocol::X11 => Lesson {
            title: "X11 — the Unix display protocol",
            summary: "How a Unix GUI app draws on a screen, possibly across the network.",
            body: "On Unix/Linux, the X Window System separates the app from the display: \
an app sends drawing requests to an X server, which can be on the same machine or \
another one. That network-transparency is why you can run a graphical app remotely \
over SSH. It's unencrypted on its own.",
            look_for: "\"X11 connection setup (little-endian)\" on TCP 6000+.",
        },
        Protocol::Rsync => Lesson {
            title: "rsync — efficient file sync",
            summary: "Copies only the changed parts of files between machines.",
            body: "rsync is the classic tool for syncing files and backups: instead of \
resending whole files, it works out which blocks changed and transfers just those. \
Its native daemon transport (port 873) opens with an \"@RSYNCD:\" greeting; it's \
also often tunnelled over SSH.",
            look_for: "\"rsync daemon — @RSYNCD: 31.0\" on TCP 873.",
        },
        Protocol::Svn => Lesson {
            title: "Subversion — centralised version control",
            summary: "The svn:// protocol for a Subversion source-code repository.",
            body: "Subversion is a version-control system (an older, centralised \
alternative to Git). Its svnserve protocol speaks a Lisp-like tuple syntax; a \
session opens with a server greeting. Still common in enterprises with long-lived \
codebases.",
            look_for: "\"SVN — server greeting\" on TCP 3690.",
        },
        Protocol::Rethinkdb => Lesson {
            title: "RethinkDB — a realtime document DB",
            summary: "A JSON document database built around live, pushed query results.",
            body: "RethinkDB stores JSON documents and is known for changefeeds — queries \
that keep pushing updates as the data changes, handy for realtime apps. Clients \
open the connection with a version magic number before running queries.",
            look_for: "\"RethinkDB V1.0 handshake\" on TCP 28015.",
        },
        Protocol::Sv => Lesson {
            title: "Sampled Values — digital measurements",
            summary: "Streams of digitised current/voltage from substation sensors (IEC 61850-9-2).",
            body: "Modern substations replace thick copper wiring from sensors with a \
network: merging units digitise the current and voltage waveforms and stream them \
as Sampled Values many thousands of times a second, directly over Ethernet, to \
the protection relays that watch them.",
            look_for: "\"Sampled Values — APPID 0x4000 (IEC 61850-9-2)\".",
        },
        Protocol::Powerlink => Lesson {
            title: "POWERLINK — deterministic Ethernet",
            summary: "A real-time industrial protocol for tightly-timed motion control.",
            body: "Standard Ethernet is non-deterministic — you can't guarantee exactly \
when a frame arrives. Ethernet POWERLINK adds a strict cyclic schedule (a managing \
node polls each device in turn) so machines and robots get the predictable timing \
that motion control needs.",
            look_for: "\"POWERLINK PRes (Poll Response)\" (EtherType 0x88AB).",
        },
        Protocol::Sercos => Lesson {
            title: "SERCOS III — servo motion bus",
            summary: "A real-time Ethernet bus that commands servo drives in machinery.",
            body: "SERCOS III is a motion-control bus: a controller sends setpoints to \
servo drives and reads back positions, all on a tightly-timed Ethernet ring. \
Master data (MDT) goes out to the drives; drive data (AT) comes back.",
            look_for: "\"SERCOS III MDT (master data)\" (EtherType 0x88CD).",
        },
        Protocol::Knxip => Lesson {
            title: "KNXnet/IP — smart buildings",
            summary: "Carries KNX building-automation commands (lights, HVAC, blinds) over IP.",
            body: "KNX is a widespread building-automation standard: switches, thermostats \
and actuators on a bus. KNXnet/IP tunnels or routes that bus over the IP network, \
so a building controller or app can drive the lights and heating remotely.",
            look_for: "\"KNXnet/IP Routing Indication\" on UDP 3671.",
        },
        Protocol::Statsd => Lesson {
            title: "StatsD — fire-and-forget metrics",
            summary: "Tiny UDP packets an app sends to count events and time operations.",
            body: "StatsD makes instrumenting code cheap: send a one-line UDP packet like \
`api.requests:1|c` and forget about it — no connection, no waiting. An aggregator \
collects and summarises them. Because it's UDP, a lost packet just means a slightly \
undercounted metric.",
            look_for: "\"StatsD — api.requests (counter)\" on UDP 8125.",
        },
        Protocol::Gelf => Lesson {
            title: "GELF — structured logs to Graylog",
            summary: "Ships application logs as structured messages (often to Graylog).",
            body: "Plain syslog lines are hard to search. GELF sends logs as structured \
JSON (with fields, levels and source), optionally compressed or split into chunks \
for UDP. A log server like Graylog collects and indexes them.",
            look_for: "\"GELF (Graylog) — chunked\" on UDP 12201.",
        },
        Protocol::Hartip => Lesson {
            title: "HART-IP — smart field instruments",
            summary: "Brings HART process-instrument data (flow, pressure) onto the IP network.",
            body: "HART is the long-standing protocol for smart field instruments in \
process plants — reading a flow meter, configuring a valve positioner. HART-IP \
carries that same data over Ethernet/IP so modern asset-management systems can \
reach the instruments.",
            look_for: "\"HART-IP Session Initiate\" on UDP/TCP 5094.",
        },
        Protocol::Elasticsearch => Lesson {
            title: "Elasticsearch — cluster transport",
            summary: "The internal binary protocol Elasticsearch nodes use among themselves.",
            body: "Elasticsearch clients usually talk to it over HTTP (port 9200), but the \
nodes of a cluster talk to *each other* over a separate binary transport protocol \
on 9300 — replicating shards, running distributed searches. Seeing it maps the \
cluster's internal chatter.",
            look_for: "\"Elasticsearch transport message\" on TCP 9300.",
        },
        Protocol::Zabbix => Lesson {
            title: "Zabbix — monitoring agents",
            summary: "How Zabbix agents and server exchange monitoring data.",
            body: "Zabbix watches servers and network gear. Agents on the monitored hosts \
send metrics to (or answer requests from) the Zabbix server using this protocol, \
framed with a \"ZBXD\" header. Seeing it means infrastructure monitoring is running.",
            look_for: "\"Zabbix protocol data\" on TCP 10050/10051.",
        },
        Protocol::Nsq => Lesson {
            title: "NSQ — realtime message queue",
            summary: "A distributed messaging platform for decoupling services.",
            body: "NSQ moves messages between producers and consumers at scale, with no \
single broker to bottleneck. Clients open with a \"  V2\" handshake, then PUB to \
publish and SUB to consume topics. Popular in Go-based microservice systems.",
            look_for: "\"NSQ PUB\" / \"NSQ handshake (V2)\" on TCP 4150.",
        },
        Protocol::Zmtp => Lesson {
            title: "ZMTP / ZeroMQ — brokerless messaging",
            summary: "The wire protocol of ZeroMQ, a library for connecting code directly.",
            body: "ZeroMQ isn't a server — it's a library that gives sockets superpowers \
(pub/sub, request/reply, pipelines) with no central broker. ZMTP is what those \
sockets speak on the wire; a connection opens with a recognisable greeting before \
exchanging framed messages.",
            look_for: "\"ZMTP/ZeroMQ greeting (v3.x)\" on arbitrary TCP ports.",
        },
        Protocol::Aerospike => Lesson {
            title: "Aerospike — a fast key-value store",
            summary: "A low-latency database built for huge, real-time workloads.",
            body: "Aerospike is a key-value/document database designed for very high \
throughput and sub-millisecond reads (ad-tech, fraud detection, recommendation). \
Clients talk to it with this binary protocol — Info messages for cluster state, \
AS_MSG for data operations.",
            look_for: "\"Aerospike Message (AS_MSG)\" on TCP 3000.",
        },
        Protocol::Avtp => Lesson {
            title: "AVTP — audio/video over the car network",
            summary: "IEEE 1722 media streaming, big in automotive Ethernet and pro AV.",
            body: "As cars replace bundles of dedicated wires with a single Ethernet \
network, they need to carry synchronised audio and video (cameras, microphones, \
displays) with tight timing. AVTP does exactly that — time-aligned media streams \
— and the same standard powers professional AV installations.",
            look_for: "\"AVTP — AVTP Audio (AAF)\" (EtherType 0x22F0).",
        },
        Protocol::SomeIp => Lesson {
            title: "SOME/IP — services inside a car",
            summary: "How software components (ECUs) call each other in modern vehicles.",
            body: "Modern cars run distributed software across many ECUs. SOME/IP lets one \
component offer a service and others call it or subscribe to its events — remote \
procedure calls and pub/sub for the vehicle. Its Service Discovery variant \
advertises what's available.",
            look_for: "\"SOME/IP Request — service 0x1234\" on UDP/TCP 30490+.",
        },
        Protocol::Doip => Lesson {
            title: "DoIP — plugging into a car over Ethernet",
            summary: "Carries vehicle diagnostics (fault codes, flashing) over IP.",
            body: "When a garage tool reads your car's fault codes or updates an ECU's \
firmware, it increasingly does so over Ethernet using DoIP: it finds the vehicle, \
activates a diagnostic route, then tunnels the UDS diagnostic messages to the \
target ECU.",
            look_for: "\"DoIP Diagnostic message\" on UDP/TCP 13400.",
        },
        Protocol::Xcp => Lesson {
            title: "XCP — tuning an ECU live",
            summary: "Reads and calibrates ECU variables while the engine runs.",
            body: "Engineers developing an engine or controller need to watch internal \
variables and tweak calibration constants in real time. XCP is the standard \
measurement-and-calibration protocol for that, running over CAN, Ethernet (as \
here) and other links.",
            look_for: "\"XCP CONNECT / positive response\" on UDP/TCP 5555.",
        },
        Protocol::Matter => Lesson {
            title: "Matter — smart home, one standard",
            summary: "The cross-vendor protocol so smart-home devices finally interoperate.",
            body: "Matter (backed by Apple, Google, Amazon and others) aims to end the \
smart-home tower of Babel: a lamp, lock or sensor from any vendor speaks the same \
secure protocol over IP, so any hub can control it. You'll see it around smart-home \
gear and Thread border routers.",
            look_for: "\"Matter message (format v0)\" on UDP 5540.",
        },
        Protocol::Afp => Lesson {
            title: "AFP — Mac file sharing",
            summary: "Apple's file-sharing protocol for mounting shared volumes on a Mac.",
            body: "AFP is how Macs traditionally shared files and mounted network volumes \
(before Apple moved toward SMB). It's framed by DSI and opens with a session \
handshake. Seeing it means Apple file sharing, often to a NAS or older macOS \
server.",
            look_for: "\"AFP/DSI OpenSession request\" on TCP 548.",
        },
        Protocol::Dht => Lesson {
            title: "BitTorrent DHT — trackerless torrents",
            summary: "A distributed hash table that lets peers find each other with no tracker.",
            body: "Torrents originally needed a central tracker to introduce peers. The DHT \
removes it: every client is a node in a giant distributed lookup table, so peers \
find each other directly. It's a lot of small UDP queries — ping, find_node, \
get_peers, announce_peer.",
            look_for: "\"BitTorrent DHT get_peers\" on random UDP ports.",
        },
        Protocol::Gnutella => Lesson {
            title: "Gnutella — decentralised file sharing",
            summary: "An early fully-decentralised peer-to-peer file-sharing network.",
            body: "Gnutella was one of the first file-sharing networks with no central \
server at all — peers connect to each other and flood search queries across the \
mesh. A connection opens with a recognisable \"GNUTELLA CONNECT\" handshake.",
            look_for: "\"Gnutella handshake — GNUTELLA CONNECT\" on TCP 6346.",
        },
        Protocol::Edonkey => Lesson {
            title: "eDonkey / eMule — P2P file sharing",
            summary: "A once-huge peer-to-peer network for sharing large files.",
            body: "The eDonkey network (and its popular eMule client) let users share and \
reassemble large files from many peers, coordinated by servers and later a Kademlia \
DHT. The protocol marker byte distinguishes plain eDonkey from eMule's extensions.",
            look_for: "\"eMule extended message\" on TCP 4662.",
        },
        Protocol::SourceQuery => Lesson {
            title: "Source Query (A2S) — game server info",
            summary: "How game clients and server browsers ask what's running on a server.",
            body: "The A2S query protocol lets a client or a server browser ask a game \
server for its name, map, player list and rules — the data you see in a server \
browser. Used by Valve's Source engine and many other games. It's a small \
connectionless UDP request/response.",
            look_for: "\"Source Query A2S_INFO request\" on UDP (often 27015).",
        },
        Protocol::Minecraft => Lesson {
            title: "Minecraft — the Java Edition protocol",
            summary: "How the Minecraft client and server talk (logins, world updates, chat).",
            body: "Minecraft Java Edition speaks its own TCP protocol: length-prefixed \
packets that start with a handshake, then move through login into play — carrying \
world chunks, entity movement and chat. The legacy server-list ping is a special \
older format.",
            look_for: "\"Minecraft handshake\" on TCP 25565.",
        },
        Protocol::Mumble => Lesson {
            title: "Mumble — low-latency voice chat",
            summary: "A voice-chat protocol (control over TCP, audio over UDP).",
            body: "Mumble is a voice-chat system popular with gamers and teams for its low \
latency. A TLS-protected TCP control channel handles logins, channels and text; the \
actual voice audio travels over a separate UDP path. You'll see the control messages \
here.",
            look_for: "\"Mumble Authenticate\" / \"Mumble UserState\" on TCP 64738.",
        },
        Protocol::Pfcp => Lesson {
            title: "PFCP — the 5G core's control lever",
            summary: "Lets the mobile control plane program how user traffic is forwarded.",
            body: "In 4G/5G the 'brains' (control plane) and the 'pipes' (user plane) are \
separate boxes. PFCP is how the brain tells the pipe what to do with a \
subscriber's traffic — set up a session, apply rules, report usage. It's the N4 \
interface, and it's where mobile sessions are born and die.",
            look_for: "\"PFCP Session Establishment Request\" on UDP 8805.",
        },
        Protocol::GtpPrime => Lesson {
            title: "GTP' — the billing feed",
            summary: "Ships Call Detail Records from network nodes to the billing system.",
            body: "Every mobile session produces usage records. GTP prime is the variant \
of GTP dedicated to hauling those Call Detail Records off to the charging \
gateway, so subscribers get billed. Distinct from the GTP that carries your \
actual data.",
            look_for: "\"GTP' (charging) Data Record Transfer Request\" on UDP 3386.",
        },
        Protocol::Megaco => Lesson {
            title: "Megaco / H.248 — driving media gateways",
            summary: "A call agent telling gateways to connect, bridge or tear down media.",
            body: "In carrier VoIP the call logic lives in a softswitch while the actual \
audio passes through media gateways. Megaco (also standardised as H.248) is the \
command channel between them: add this endpoint, connect these two, drop the \
call. The successor to MGCP.",
            look_for: "\"Megaco/H.248 — MEGACO/1 …\" on UDP/TCP 2944.",
        },
        Protocol::Msrp => Lesson {
            title: "MSRP — chat inside a call",
            summary: "Carries instant messages and file transfers in SIP/IMS sessions.",
            body: "SIP sets up sessions; MSRP is what carries the actual text messages and \
files inside one. It's how operator messaging (RCS) and enterprise IMS chat move \
content, negotiated by SIP just like audio would be.",
            look_for: "\"MSRP SEND\" on TCP 2855.",
        },
        Protocol::Pcoip => Lesson {
            title: "PCoIP — a desktop over the network",
            summary: "Teradici/VMware Horizon's protocol for streaming a remote desktop.",
            body: "PCoIP delivers a virtual desktop's screen to a thin client or laptop, \
adapting image quality to the available bandwidth. The payload is encrypted, so \
netscope identifies it by its port rather than decoding the pixels.",
            look_for: "\"PCoIP remote display\" on UDP/TCP 4172.",
        },
        Protocol::Spice => Lesson {
            title: "SPICE — a VM's console",
            summary: "The remote-display protocol for virtual machines (oVirt/QEMU).",
            body: "SPICE gives you a virtual machine's screen, keyboard, mouse, sound and \
USB redirection over the network — the console you open from a virtualisation \
manager. It splits work across separate channels (display, inputs, cursor…), each \
opening with a \"REDQ\" link message.",
            look_for: "\"SPICE link — display channel\".",
        },
        Protocol::Ica => Lesson {
            title: "Citrix ICA — published apps",
            summary: "The thin-client protocol delivering a Citrix desktop or single app.",
            body: "ICA streams the screen of an application or desktop running on a Citrix \
server down to the user's device, sending keystrokes and clicks back. It's the \
core of Citrix's virtual-app delivery, and the session opens with a recognisable \
handshake.",
            look_for: "\"Citrix ICA handshake\" on TCP 1494.",
        },
        Protocol::Ndmp => Lesson {
            title: "NDMP — backing up a NAS",
            summary: "Lets backup software drive a storage appliance's own backup engine.",
            body: "Backing up a big NAS by pulling every file over the network is slow. \
NDMP instead lets the backup server *orchestrate* the NAS to stream data straight \
to a tape or disk target — the control conversation is what you see here.",
            look_for: "\"NDMP CONNECT_OPEN request\" on TCP 10000.",
        },
        Protocol::Dcerpc => Lesson {
            title: "DCE/RPC — Windows' remote calls",
            summary: "The RPC layer under the endpoint mapper, WMI and much of Active Directory.",
            body: "A great deal of Windows administration is remote procedure calls: \
querying WMI, managing services, talking to a domain controller. DCE/RPC (MSRPC) \
is that layer. A client Binds to an interface on port 135 or a dynamic port, then \
issues Requests. It's also a well-trodden lateral-movement path, so it's worth \
watching.",
            look_for: "\"DCE/RPC Bind\" / \"DCE/RPC Request\" on TCP 135.",
        },
        Protocol::Pptp => Lesson {
            title: "PPTP — the legacy VPN",
            summary: "An old Microsoft VPN: control on TCP 1723, data in GRE.",
            body: "PPTP was the classic 'built into Windows' VPN. A TCP control channel \
negotiates the tunnel and the actual traffic rides GRE alongside it. Its \
encryption has known weaknesses and it's considered obsolete, so seeing it today \
is a security note worth raising.",
            look_for: "\"PPTP Start-Control-Connection-Request\" on TCP 1723.",
        },
        Protocol::Radmin => Lesson {
            title: "Radmin — remote control",
            summary: "A Windows remote-administration tool's session traffic.",
            body: "Radmin lets an administrator take over a Windows desktop remotely. The \
session is encrypted, so netscope flags it by port rather than decoding it. Like \
any remote-control tool, unexpected Radmin traffic is worth confirming was \
authorised.",
            look_for: "\"Radmin remote control\" on TCP 4899.",
        },
        Protocol::Skinny => Lesson {
            title: "Skinny (SCCP) — Cisco IP phones",
            summary: "The lightweight signalling between Cisco phones and CallManager.",
            body: "Before SIP took over, Cisco IP phones registered and made calls using \
Skinny (SCCP): a compact binary protocol where the phone reports off-hook, keypad \
presses and call state to CallManager, which drives the display and rings. Still \
common in Cisco voice estates.",
            look_for: "\"Skinny (SCCP) Register\" / \"CallState\" on TCP 2000.",
        },
        Protocol::Plugin(_) => Lesson {
            title: "Custom protocol (plugin)",
            summary: "Traffic named by a user-defined protocol plugin, not a built-in dissector.",
            body: "netscope lets you teach it new protocols without recompiling: a \
small text file in your config directory maps a port (and optionally a \
signature in the first bytes) to a name and a one-line summary. When a packet \
matches, it's labelled with the plugin's name instead of a generic 'TCP/UDP \
payload'. This is how you get a protocol netscope doesn't ship a dissector for \
— a house database, an IoT gadget, a game server — to show up by name.",
            look_for: "A protocol name you configured yourself (e.g. \"Redis\", \"Modbus\") in the protocol column, with the summary your plugin defined.",
        },
        Protocol::Wlan => Lesson {
            title: "802.11 — Wi-Fi at the radio layer",
            summary: "The wireless frames beneath your network traffic — seen in monitor mode.",
            body: "Everything else in netscope sits on top of a link layer; on Wi-Fi \
that layer is 802.11. In monitor mode you can watch the radio itself: beacons \
that access points broadcast to advertise a network, probe requests devices send \
looking for known networks, and the management frames that join and leave. It's a \
different view of the air around you, not the data inside encrypted connections.",
            look_for: "\"802.11 Beacon — \\\"MyWiFi\\\"\" and \"802.11 Probe Request\" frames, often with a signal in dBm.",
        },
        Protocol::Usb => Lesson {
            title: "USB — traffic on the wire to your devices",
            summary: "Requests and data flowing between your PC and USB devices.",
            body: "A USB capture (usbmon on Linux, USBPcap on Windows) shows the \
conversation between the operating system and a device: the host submits a \
request block (URB) to an endpoint on a device, and the device answers. \
Keyboards and mice use tiny periodic Interrupt transfers, storage moves data \
in Bulk transfers, and Control transfers carry setup and configuration.",
            look_for: "\"USB 1.5.1 Bulk IN, 512 bytes\" — bus 1, device 5, endpoint 1; IN means data flows from the device to the PC.",
        },
        Protocol::Bluetooth => Lesson {
            title: "Bluetooth HCI — host talking to the radio",
            summary: "Commands, events and data between your OS and the Bluetooth chip.",
            body: "HCI (Host Controller Interface) is the language every Bluetooth \
stack speaks to its radio chip: the host sends Commands (scan, connect, \
advertise), the controller answers with Events, and ACL packets carry the \
actual data. On Linux, capturing on a bluetoothN interface shows this stream \
— you'll see nearby devices advertising themselves (LE Advertising Reports) \
without pairing to anything.",
            look_for: "\"HCI Command: LE Set Scan Enable\" going out and \"HCI Event: LE Advertising Report\" coming back for every advertiser nearby.",
        },
        Protocol::Can => Lesson {
            title: "CAN bus — the network inside vehicles and machines",
            summary: "Tiny broadcast frames from a car or industrial controller bus.",
            body: "CAN (Controller Area Network) is what a car's parts use to talk: \
every frame is broadcast to the whole bus with an ID that says what it is \
(engine RPM, wheel speed…) and up to 8 data bytes (64 for CAN FD). There are \
no addresses and no connections — receivers just pick the IDs they care \
about. On Linux, SocketCAN exposes canN/vcanN interfaces netscope can \
capture like any NIC.",
            look_for: "\"CAN 0x244 [8]  12 0A 00 F3 …\" — the ID, the byte count, and the raw data bytes.",
        },
        Protocol::Ntlm => Lesson {
            title: "NTLM — Windows network authentication",
            summary: "Microsoft's legacy authentication protocol used to log in to servers.",
            body: "NTLM (NT LAN Manager) is a suite of security protocols used to authenticate, integrity-protect, and secure users in active directory environments. It uses a challenge-response mechanism to verify the identity of a client without sending the password over the network, though it is legacy and vulnerable to relay attacks.",
            look_for: "\"NTLM Negotiate\" (client starts), \"NTLM Challenge\" (server challenges), or \"NTLM Authenticate\" (user credentials).",
        },
        Protocol::Smb => Lesson {
            title: "SMB — Server Message Block",
            summary: "Windows file sharing protocol.",
            body: "SMB is used to share files, printers, and serial ports on local networks.",
            look_for: "SMB traffic on port 445.",
        },
        Protocol::Tds => Lesson {
            title: "TDS — Tabular Data Stream",
            summary: "Microsoft SQL Server database protocol.",
            body: "TDS is used for communication between database clients and MS SQL Server.",
            look_for: "TDS database commands on port 1433.",
        },
        Protocol::Amqp => Lesson {
            title: "AMQP — Advanced Message Queuing Protocol",
            summary: "Message broker queuing protocol.",
            body: "AMQP is an open standard protocol for passing business messages between applications or organizations.",
            look_for: "AMQP broker connection headers on port 5672.",
        },
        Protocol::Kafka => Lesson {
            title: "Kafka — Apache Kafka messaging",
            summary: "Distributed event streaming platform protocol.",
            body: "Kafka protocol handles read/write requests between clients and broker clusters.",
            look_for: "Kafka messages and API requests on port 9092.",
        },
        Protocol::Unknown(_) => Lesson {
            title: "Unknown / other traffic",
            summary: "Something netscope doesn't decode in detail — shown safely anyway.",
            body: "Not every packet is a protocol netscope explains in depth. Rather \
than crash or hide it, netscope shows what it can (addresses, size, IP protocol \
number) and moves on. This includes things like IGMP, GRE tunnels, or IPsec.",
            look_for: "A protocol label in parentheses and a size, e.g. \"IGMP (32 bytes)\".",
        },
    }
}

/// Every protocol lesson, in a sensible teaching order, paired with its
/// protocol so callers can colour or group them.
pub fn all_lessons() -> Vec<(Protocol, Lesson)> {
    [
        Protocol::Dns,
        Protocol::Tcp,
        Protocol::Tls,
        Protocol::Http,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Arp,
        Protocol::Dhcp,
        Protocol::Ntp,
        Protocol::Mdns,
        Protocol::Snmp,
        Protocol::Quic,
        Protocol::Sip,
        Protocol::Ssh,
        Protocol::Ftp,
        Protocol::Smtp,
        Protocol::Imap,
        Protocol::Pop3,
        Protocol::Telnet,
        Protocol::Rdp,
        Protocol::WebSocket,
        Protocol::Http2,
        Protocol::Grpc,
        Protocol::Vxlan,
        Protocol::Postgres,
        Protocol::Mysql,
        Protocol::Mongodb,
        Protocol::Redis,
        Protocol::Cassandra,
        Protocol::Modbus,
        Protocol::Dnp3,
        Protocol::Bacnet,
        Protocol::Enip,
        Protocol::OpcUa,
        Protocol::Rtp,
        Protocol::Rtcp,
        Protocol::Kerberos,
        Protocol::Ldap,
        Protocol::Radius,
        Protocol::OpenVpn,
        Protocol::WireGuard,
        Protocol::Esp,
        Protocol::Ah,
        Protocol::Mqtt,
        Protocol::Coap,
        Protocol::Bgp,
        Protocol::Ospf,
        Protocol::Lldp,
        Protocol::Lacp,
        Protocol::Stp,
        Protocol::Mpls,
        Protocol::Wlan,
        Protocol::Usb,
        Protocol::Bluetooth,
        Protocol::Can,
        Protocol::Syslog,
        Protocol::Tftp,
        Protocol::Ssdp,
        Protocol::Stun,
        Protocol::Llmnr,
        Protocol::Rtsp,
        Protocol::Irc,
        Protocol::Rfb,
        Protocol::Whois,
        Protocol::Nntp,
        Protocol::Sctp,
        Protocol::Gre,
        Protocol::Igmp,
        Protocol::Dhcpv6,
        Protocol::Rip,
        Protocol::Nbns,
        Protocol::Socks,
        Protocol::Memcached,
        Protocol::BitTorrent,
        Protocol::Git,
        Protocol::Xmpp,
        Protocol::Finger,
        Protocol::Vrrp,
        Protocol::Pim,
        Protocol::Eigrp,
        Protocol::Pppoe,
        Protocol::Eapol,
        Protocol::L2tp,
        Protocol::Gtp,
        Protocol::Rmcp,
        Protocol::WsDiscovery,
        Protocol::Tacacs,
        Protocol::Diameter,
        Protocol::Rlogin,
        Protocol::Dccp,
        Protocol::Dtls,
        Protocol::Netflow,
        Protocol::Sflow,
        Protocol::Bfd,
        Protocol::Hsrp,
        Protocol::Iscsi,
        Protocol::Rtmp,
        Protocol::Smpp,
        Protocol::OpenFlow,
        Protocol::Nats,
        Protocol::Stomp,
        Protocol::Profinet,
        Protocol::Wol,
        Protocol::Glbp,
        Protocol::Wccp,
        Protocol::Mgcp,
        Protocol::Nbds,
        Protocol::Dicom,
        Protocol::Hl7,
        Protocol::Fix,
        Protocol::S7comm,
        Protocol::Iec104,
        Protocol::Ldp,
        Protocol::Goose,
        Protocol::Ptp,
        Protocol::Rsvp,
        Protocol::Isakmp,
        Protocol::Geneve,
        Protocol::Capwap,
        Protocol::Teredo,
        Protocol::Gvcp,
        Protocol::Rpc,
        Protocol::Graphite,
        Protocol::Gearman,
        Protocol::Beanstalk,
        Protocol::Ethercat,
        Protocol::Fcoe,
        Protocol::Macsec,
        Protocol::Rarp,
        Protocol::Rtps,
        Protocol::Influxdb,
        Protocol::MqttSn,
        Protocol::Babel,
        Protocol::X11,
        Protocol::Rsync,
        Protocol::Svn,
        Protocol::Rethinkdb,
        Protocol::Sv,
        Protocol::Powerlink,
        Protocol::Sercos,
        Protocol::Knxip,
        Protocol::Statsd,
        Protocol::Gelf,
        Protocol::Hartip,
        Protocol::Elasticsearch,
        Protocol::Zabbix,
        Protocol::Nsq,
        Protocol::Zmtp,
        Protocol::Aerospike,
        Protocol::Avtp,
        Protocol::SomeIp,
        Protocol::Doip,
        Protocol::Xcp,
        Protocol::Matter,
        Protocol::Afp,
        Protocol::Dht,
        Protocol::Gnutella,
        Protocol::Edonkey,
        Protocol::SourceQuery,
        Protocol::Minecraft,
        Protocol::Mumble,
        Protocol::Pfcp,
        Protocol::GtpPrime,
        Protocol::Megaco,
        Protocol::Msrp,
        Protocol::Pcoip,
        Protocol::Spice,
        Protocol::Ica,
        Protocol::Ndmp,
        Protocol::Dcerpc,
        Protocol::Pptp,
        Protocol::Radmin,
        Protocol::Skinny,
        Protocol::Unknown(String::new()),
    ]
    .into_iter()
    .map(|p| {
        let l = lesson(&p);
        (p, l)
    })
    .collect()
}

/// A networking term and its plain-language meaning.
pub struct Term {
    pub term: &'static str,
    pub meaning: &'static str,
}

/// A small glossary of the jargon netscope surfaces.
pub fn glossary() -> &'static [Term] {
    &[
        Term { term: "Packet", meaning: "One small chunk of data sent over the network. Big things are split into many packets." },
        Term { term: "IP address", meaning: "A device's number on the network, like 142.250.74.46 (IPv4) or 2606:4700::1 (IPv6)." },
        Term { term: "Port", meaning: "A numbered 'door' on a device for a specific service. 443 = HTTPS, 80 = HTTP, 53 = DNS." },
        Term { term: "MAC address", meaning: "A device's permanent hardware ID, used only on the local network (e.g. aa:bb:cc:dd:ee:ff)." },
        Term { term: "Handshake", meaning: "The SYN → SYN-ACK → ACK exchange two computers use to agree to start a TCP conversation." },
        Term { term: "SYN / ACK / FIN / RST", meaning: "TCP flags: SYN starts, ACK acknowledges, FIN closes politely, RST aborts." },
        Term { term: "TTL", meaning: "'Time to live' — a countdown that stops a lost packet from circling the internet forever." },
        Term { term: "SNI", meaning: "The site name a browser reveals when starting HTTPS, before encryption kicks in." },
        Term { term: "Payload", meaning: "The actual content of a packet, after the addressing headers." },
        Term { term: "Promiscuous mode", meaning: "Telling the network card to hand over every frame it sees, not just ones addressed to you." },
        Term { term: "BPF filter", meaning: "A rule (like 'tcp port 443') that captures only the packets you care about." },
    ]
}

/// A targeted, one-line explanation of what THIS packet is doing, based on
/// its protocol and summary. Falls back to the protocol's gist.
pub fn explain_packet(pkt: &Packet) -> &'static str {
    let s = &pkt.summary;
    // Order matters: check the specific events before generic protocol gists.
    if s.contains("handshake") || s.contains("3-way") {
        return "Two computers are agreeing to talk before sending data (the TCP handshake).";
    }
    if s.contains("SYN-ACK") {
        return "The server accepted the connection request and is replying — step 2 of the handshake.";
    }
    if s.contains("reset") || s.contains("RST") {
        return "The connection was refused or abruptly aborted (nothing is listening, or it was cut off).";
    }
    if s.contains("closing") || s.contains("FIN") {
        return "One side is politely closing the connection — the conversation is ending.";
    }
    if s.contains("Ping request") {
        return "A reachability test: 'are you there?' Expect a matching reply if the host is up.";
    }
    if s.contains("Ping reply") {
        return "The host answered the reachability test — it's up and responding.";
    }
    if s.contains("unreachable") {
        return "A router is reporting it couldn't deliver the packet to that destination.";
    }
    match pkt.protocol {
        Protocol::Dns if s.contains("Query") => {
            "Your device is asking a DNS server for the IP address behind a name."
        }
        Protocol::Dns if s.contains("Response") => {
            "The DNS server answered with the IP address for the name that was asked."
        }
        Protocol::Dns => "A name-lookup message (DNS).",
        Protocol::Tls if s.contains("HTTPS") => {
            "The start of an encrypted visit to this site — the name is visible, the content isn't."
        }
        Protocol::Tls => "Encrypted web traffic — the content can't be read, by design.",
        Protocol::Http if s.contains("GET") || s.contains("POST") => {
            "A web request sent in plain text — visible to anyone capturing."
        }
        Protocol::Http => "Unencrypted web traffic (HTTP).",
        Protocol::Tcp => "Reliable data transfer over a TCP connection.",
        Protocol::Udp => "A fast, connectionless UDP message (no delivery guarantee).",
        Protocol::Icmp => "A network status/diagnostic message (ICMP).",
        Protocol::Arp => "A local-network lookup matching an IP to a hardware address.",
        Protocol::Dhcp => {
            "Your device is getting (or renewing) its IP address from the network's DHCP server."
        }
        Protocol::Ntp => "A clock-sync message — your device checking the time with a time server.",
        Protocol::Mdns => {
            "Local service discovery (mDNS/Bonjour) — devices finding printers, speakers, etc. on the LAN."
        }
        Protocol::Snmp => "A network-management query/response (SNMP) used to monitor devices.",
        Protocol::Quic => {
            "Encrypted QUIC traffic — the modern transport behind HTTP/3, carried over UDP."
        }
        Protocol::Sip => "VoIP call signalling (SIP) — setting up, ringing, or ending a voice call.",
        Protocol::Ssh => "An encrypted remote-shell session (SSH) — you can see it happens, not what's typed.",
        Protocol::Ftp => "An old-style file transfer (FTP) — commands and passwords travel in plain text.",
        Protocol::Smtp => "Email being handed between mail servers (SMTP).",
        Protocol::Imap => "A mail client reading a mailbox on the server (IMAP).",
        Protocol::Pop3 => "A mail client downloading messages from the server (POP3).",
        Protocol::Telnet => "An unencrypted remote terminal (Telnet) — everything, including passwords, is visible.",
        Protocol::Rdp => "A Windows Remote Desktop session (RDP).",
        Protocol::WebSocket => {
            "A live two-way message on an upgraded web connection (WebSocket) — used by chat, live feeds and dev tools."
        }
        Protocol::Http2 => {
            "Binary web traffic (HTTP/2) — many requests multiplexed as frames on one connection."
        }
        Protocol::Grpc => {
            "One service calling another (gRPC) — a binary remote-procedure call riding on HTTP/2."
        }
        Protocol::Vxlan => {
            "Tunnelled overlay-network traffic (VXLAN) — another network's frames carried inside UDP; the summary shows what's inside."
        }
        Protocol::Postgres => "A PostgreSQL database conversation — SQL queries and their results over TCP 5432.",
        Protocol::Mysql => "A MySQL/MariaDB database conversation — queries and results over TCP 3306.",
        Protocol::Mongodb => "A MongoDB database conversation — document commands (find/insert/update) over TCP 27017.",
        Protocol::Redis => "A Redis command or reply — the in-memory key-value store on TCP 6379.",
        Protocol::Cassandra => "A Cassandra CQL conversation — distributed-database queries over TCP 9042.",
        Protocol::Modbus => "An industrial-control command (Modbus) — reading or writing PLC registers over TCP 502.",
        Protocol::Dnp3 => "A utility SCADA message (DNP3) — grid/water control between a master and remote stations.",
        Protocol::Bacnet => "A building-automation message (BACnet) — HVAC, lighting or access control on UDP 47808.",
        Protocol::Enip => "An industrial-control message (EtherNet/IP) — CIP commands to a PLC over TCP/UDP 44818.",
        Protocol::OpcUa => "An Industry 4.0 data-exchange message (OPC UA) — factory equipment talking to IT systems.",
        Protocol::Rtp => "The live audio/video of a call (RTP) — the media stream SIP set up, carried over UDP.",
        Protocol::Rtcp => "A call-quality report (RTCP) — loss and jitter statistics riding alongside an RTP stream.",
        Protocol::Kerberos => "An enterprise authentication message (Kerberos) — requesting or presenting a login ticket.",
        Protocol::Ldap => "A directory query or login (LDAP) — looking up users/groups, or binding with credentials.",
        Protocol::Radius => "A network-access authentication message (RADIUS) — allowing or denying Wi-Fi/VPN logins.",
        Protocol::OpenVpn => "An OpenVPN tunnel packet — encrypted VPN traffic; the type shows handshake vs. data.",
        Protocol::WireGuard => "A WireGuard tunnel packet — a modern encrypted VPN; the type shows handshake vs. data.",
        Protocol::Esp => "Encrypted IPsec traffic (ESP) — a VPN payload identified only by its SPI tunnel number.",
        Protocol::Ah => "An authenticated IPsec packet (AH) — integrity-protected but not encrypted.",
        Protocol::Mqtt => "An IoT messaging packet (MQTT) — a device publishing to or subscribing on a broker topic.",
        Protocol::Coap => "A constrained-device request/response (CoAP) — HTTP-like IoT traffic over UDP.",
        Protocol::Bgp => "An internet routing message (BGP) — networks telling each other which addresses they reach.",
        Protocol::Ospf => "An interior routing message (OSPF) — routers inside one network sharing link-state maps.",
        Protocol::Lldp => "A neighbour announcement (LLDP) — a switch advertising its identity and port for topology maps.",
        Protocol::Lacp => "A link-aggregation message (LACP) — two switches bonding several cables into one link.",
        Protocol::Stp => "A Spanning Tree message (STP) — switches electing a root bridge to keep the network loop-free.",
        Protocol::Mpls => "A label-switched packet (MPLS) — carrier/backbone forwarding; the inner packet is shown after the label.",
        Protocol::Wlan => "A raw Wi-Fi (802.11) frame — the radio layer beneath your network traffic.",
        Protocol::Usb => "USB bus traffic — a request or data moving between your PC and a USB device.",
        Protocol::Bluetooth => "A Bluetooth HCI packet — your OS talking to the Bluetooth radio (commands, events, data).",
        Protocol::Can => "A CAN bus frame — broadcast data on a vehicle or industrial controller network.",
        Protocol::Ntlm => "NTLM authentication handshake message.",
        Protocol::Smb => "An SMB file-sharing transaction over TCP 445.",
        Protocol::Tds => "A Tabular Data Stream (TDS) database message over TCP 1433.",
        Protocol::Amqp => "An Advanced Message Queuing Protocol (AMQP) message on TCP 5672.",
        Protocol::Kafka => "An Apache Kafka message queuing request/response on TCP 9092.",
        Protocol::Syslog => "A system log message shipped to a central collector (UDP 514) — usually plaintext.",
        Protocol::Tftp => "A trivial file transfer (UDP 69) — often a device pulling firmware or config at boot.",
        Protocol::Ssdp => "UPnP device-discovery chatter (UDP 1900) — gadgets finding each other on the LAN.",
        Protocol::Stun => "A NAT-traversal probe (UDP 3478) used by voice/video calls to find a public path.",
        Protocol::Llmnr => "A link-local name lookup (UDP 5355) — like DNS, but for the local network only.",
        Protocol::Rtsp => "Streaming-media control (TCP 554) — play/pause signalling for an IP camera or stream.",
        Protocol::Irc => "An Internet Relay Chat message (TCP 6667) — plain-text group chat.",
        Protocol::Rfb => "A VNC / remote-framebuffer session (TCP 5900) — one screen shared to another.",
        Protocol::Whois => "A WHOIS registration lookup (TCP 43) — who owns a domain or IP.",
        Protocol::Nntp => "A Usenet news transfer (TCP 119) — fetching or moving newsgroup articles.",
        Protocol::Sctp => "An SCTP transport packet (IP proto 132) — reliable multi-stream, common in telecom signalling.",
        Protocol::Gre => "A GRE tunnel (IP proto 47) — one packet wrapped inside another to cross a network.",
        Protocol::Igmp => "An IGMP message (IP proto 2) — a host joining or leaving an IPv4 multicast group.",
        Protocol::Dhcpv6 => "A DHCPv6 message (UDP 546/547) — IPv6 address assignment, like DHCP for IPv4.",
        Protocol::Rip => "A RIP routing update (UDP 520) — routers telling each other which networks they can reach.",
        Protocol::Nbns => "A NetBIOS name lookup (UDP 137) — the old Windows way of resolving names locally.",
        Protocol::Socks => "A SOCKS proxy negotiation (TCP 1080) — relaying a connection through a proxy.",
        Protocol::Memcached => "A Memcached cache operation (TCP 11211) — reading or writing an in-memory key.",
        Protocol::BitTorrent => "A BitTorrent peer connection (TCP 6881+) — peer-to-peer file sharing.",
        Protocol::Git => "A native Git transfer (TCP 9418) — cloning, fetching or pushing a repository.",
        Protocol::Xmpp => "An XMPP / Jabber message (TCP 5222) — open-standard instant messaging.",
        Protocol::Finger => "A Finger lookup (TCP 79) — an old service reporting who is logged in.",
        Protocol::Vrrp => "A VRRP advertisement (IP proto 112) — routers sharing a virtual gateway IP for failover.",
        Protocol::Pim => "A PIM message (IP proto 103) — routers building paths to deliver multicast.",
        Protocol::Eigrp => "An EIGRP routing message (IP proto 88) — Cisco routers exchanging routes.",
        Protocol::Pppoe => "A PPPoE frame — a DSL-style login/session carried over Ethernet.",
        Protocol::Eapol => "An 802.1X / EAPOL frame — port authentication, or the Wi-Fi WPA key handshake.",
        Protocol::L2tp => "An L2TP tunnel message (UDP 1701) — usually the L2TP/IPsec VPN transport.",
        Protocol::Gtp => "A GTP message (UDP 2123/2152) — carrying mobile data through the 4G/5G core.",
        Protocol::Rmcp => "An RMCP/IPMI message (UDP 623) — out-of-band management of a server's BMC.",
        Protocol::WsDiscovery => "A WS-Discovery message (UDP 3702) — devices like printers/cameras finding each other.",
        Protocol::Tacacs => "A TACACS+ message (TCP 49) — admin login/authorization for network gear.",
        Protocol::Diameter => "A Diameter message (TCP/SCTP 3868) — carrier AAA and billing.",
        Protocol::Rlogin => "An rlogin session (TCP 513) — a legacy cleartext remote login; prefer SSH.",
        Protocol::Dccp => "A DCCP packet (IP proto 33) — congestion-controlled but unreliable transport for streaming.",
        Protocol::Dtls => "A DTLS record — TLS encryption over UDP, as used by WebRTC media and some VPNs.",
        Protocol::Netflow => "A NetFlow/IPFIX export (UDP 2055/4739) — a router reporting traffic-flow summaries.",
        Protocol::Sflow => "An sFlow datagram (UDP 6343) — a switch exporting sampled packets and counters.",
        Protocol::Bfd => "A BFD heartbeat (UDP 3784) — a fast liveness check between routers for quick failover.",
        Protocol::Hsrp => "An HSRP message (UDP 1985) — Cisco routers sharing a virtual gateway IP.",
        Protocol::Iscsi => "An iSCSI PDU (TCP 3260) — SCSI storage commands carried over the network.",
        Protocol::Rtmp => "An RTMP message (TCP 1935) — the streaming protocol used to ingest live video.",
        Protocol::Smpp => "An SMPP PDU (TCP 2775) — an app or gateway sending/receiving SMS text messages.",
        Protocol::OpenFlow => "An OpenFlow message (TCP 6653) — an SDN controller programming a switch.",
        Protocol::Nats => "A NATS message (TCP 4222) — publish/subscribe messaging between services.",
        Protocol::Stomp => "A STOMP frame (TCP 61613) — simple text messaging with a broker.",
        Protocol::Profinet => "A PROFINET frame (EtherType 0x8892) — real-time industrial automation data.",
        Protocol::Wol => "A Wake-on-LAN magic packet — a broadcast that powers a sleeping machine on.",
        Protocol::Glbp => "A GLBP message (UDP 3222) — Cisco routers load-sharing a virtual gateway.",
        Protocol::Wccp => "A WCCP message (UDP 2048) — a router redirecting traffic to a cache/proxy.",
        Protocol::Mgcp => "An MGCP message (UDP 2427) — a call agent controlling a VoIP media gateway.",
        Protocol::Nbds => "A NetBIOS datagram (UDP 138) — legacy Windows broadcast/browsing traffic.",
        Protocol::Dicom => "A DICOM message (TCP 104/11112) — medical imaging devices exchanging studies (patient data).",
        Protocol::Hl7 => "An HL7 v2 message (TCP 2575) — hospital systems exchanging patient/lab data.",
        Protocol::Fix => "A FIX message — a trading system sending orders or market data; tag 35 is the type.",
        Protocol::S7comm => "An S7comm message (TCP 102) — reading/writing a Siemens PLC's memory.",
        Protocol::Iec104 => "An IEC 60870-5-104 message (TCP 2404) — power-grid SCADA telecontrol.",
        Protocol::Ldp => "An LDP message (TCP/UDP 646) — MPLS routers distributing forwarding labels.",
        Protocol::Goose => "A GOOSE frame (EtherType 0x88B8) — fast IEC 61850 substation protection signalling.",
        Protocol::Ptp => "A PTP message (IEEE 1588) — sub-microsecond clock synchronisation.",
        Protocol::Rsvp => "An RSVP message (IP proto 46) — reserving bandwidth / signalling an MPLS-TE tunnel.",
        Protocol::Isakmp => "An ISAKMP/IKE message (UDP 500/4500) — negotiating the keys for an IPsec VPN.",
        Protocol::Geneve => "A Geneve packet (UDP 6081) — a network-virtualisation overlay carrying an inner frame.",
        Protocol::Capwap => "A CAPWAP message (UDP 5246/5247) — a wireless controller managing access points.",
        Protocol::Teredo => "A Teredo packet (UDP 3544) — IPv6 tunnelled through IPv4/NAT.",
        Protocol::Gvcp => "A GVCP message (UDP 3956) — controlling an industrial GigE Vision camera.",
        Protocol::Rpc => "An ONC RPC message (TCP/UDP 111/2049) — the plumbing behind NFS file sharing.",
        Protocol::Graphite => "A Graphite metric (TCP 2003) — an app pushing a time-series data point.",
        Protocol::Gearman => "A Gearman message (TCP 4730) — handing a background job to a worker.",
        Protocol::Beanstalk => "A beanstalkd command (TCP 11300) — a simple background-job work queue.",
        Protocol::Ethercat => "An EtherCAT frame (EtherType 0x88A4) — real-time industrial fieldbus control.",
        Protocol::Fcoe => "An FCoE frame (EtherType 0x8906) — Fibre Channel storage carried over Ethernet.",
        Protocol::Macsec => "A MACsec frame (EtherType 0x88E5) — 802.1AE hop-by-hop link encryption.",
        Protocol::Rarp => "A RARP packet (EtherType 0x8035) — a host asking for its IP given its MAC.",
        Protocol::Rtps => "An RTPS/DDS message — real-time pub/sub middleware (ROS 2, vehicles, industrial).",
        Protocol::Influxdb => "An InfluxDB metric (UDP 8089) — a time-series data point written in line protocol.",
        Protocol::MqttSn => "An MQTT-SN message (UDP 1883) — MQTT for constrained sensor devices over UDP.",
        Protocol::Babel => "A Babel routing update (UDP 6696) — mesh-friendly distance-vector routing.",
        Protocol::X11 => "An X11 message (TCP 6000+) — the Unix display protocol drawing a GUI.",
        Protocol::Rsync => "An rsync transfer (TCP 873) — efficient file synchronisation.",
        Protocol::Svn => "A Subversion message (TCP 3690) — centralised version-control traffic.",
        Protocol::Rethinkdb => "A RethinkDB message (TCP 28015) — a realtime JSON document database.",
        Protocol::Sv => "A Sampled Values frame (EtherType 0x88BA) — digitised substation measurements.",
        Protocol::Powerlink => "An Ethernet POWERLINK frame (0x88AB) — deterministic real-time industrial control.",
        Protocol::Sercos => "A SERCOS III frame (EtherType 0x88CD) — real-time servo motion control.",
        Protocol::Knxip => "A KNXnet/IP message (UDP 3671) — building automation (lights/HVAC) over IP.",
        Protocol::Statsd => "A StatsD metric (UDP 8125) — a fire-and-forget counter/gauge/timer.",
        Protocol::Gelf => "A GELF message (UDP 12201) — a structured application log, often to Graylog.",
        Protocol::Hartip => "A HART-IP message (UDP/TCP 5094) — smart process-instrument data over IP.",
        Protocol::Elasticsearch => "An Elasticsearch transport message (TCP 9300) — internal cluster traffic.",
        Protocol::Zabbix => "A Zabbix message (TCP 10050/10051) — infrastructure monitoring data.",
        Protocol::Nsq => "An NSQ message (TCP 4150) — a realtime distributed message queue.",
        Protocol::Zmtp => "A ZMTP/ZeroMQ message — brokerless messaging between applications.",
        Protocol::Aerospike => "An Aerospike message (TCP 3000) — a low-latency key-value database.",
        Protocol::Avtp => "An AVTP frame (EtherType 0x22F0) — time-synced audio/video (automotive Ethernet / pro AV).",
        Protocol::SomeIp => "A SOME/IP message (UDP/TCP 30490+) — service-oriented communication between car ECUs.",
        Protocol::Doip => "A DoIP message (UDP/TCP 13400) — vehicle diagnostics carried over Ethernet.",
        Protocol::Xcp => "An XCP message (UDP/TCP 5555) — live ECU measurement and calibration.",
        Protocol::Matter => "A Matter message (UDP 5540) — the cross-vendor smart-home standard.",
        Protocol::Afp => "An AFP message (TCP 548) — Apple Filing Protocol for Mac file sharing.",
        Protocol::Dht => "A BitTorrent DHT message — trackerless peer discovery over UDP.",
        Protocol::Gnutella => "A Gnutella message (TCP 6346) — decentralised peer-to-peer file sharing.",
        Protocol::Edonkey => "An eDonkey/eMule message (TCP 4662) — peer-to-peer file sharing.",
        Protocol::SourceQuery => "A Source A2S query — a game client/browser asking a server for its info.",
        Protocol::Minecraft => "A Minecraft message (TCP 25565) — the Java Edition client/server protocol.",
        Protocol::Mumble => "A Mumble control message (TCP 64738) — low-latency voice-chat signalling.",
        Protocol::Pfcp => "A PFCP message (UDP 8805) — the 5G/4G control plane programming user-plane forwarding.",
        Protocol::GtpPrime => "A GTP' message (UDP 3386) — mobile Call Detail Records heading to billing.",
        Protocol::Megaco => "A Megaco/H.248 message (UDP/TCP 2944) — a call agent controlling a media gateway.",
        Protocol::Msrp => "An MSRP message (TCP 2855) — instant messaging/file transfer inside a SIP session.",
        Protocol::Pcoip => "PCoIP traffic (UDP/TCP 4172) — an encrypted remote-desktop display stream.",
        Protocol::Spice => "A SPICE message — the remote console of a virtual machine.",
        Protocol::Ica => "Citrix ICA traffic (TCP 1494) — a published app or virtual desktop session.",
        Protocol::Ndmp => "An NDMP message (TCP 10000) — backup software driving a NAS backup.",
        Protocol::Dcerpc => "A DCE/RPC message (TCP 135) — Windows remote procedure calls (WMI, AD, services).",
        Protocol::Pptp => "A PPTP control message (TCP 1723) — the legacy Microsoft VPN; weak crypto.",
        Protocol::Radmin => "Radmin traffic (TCP 4899) — an encrypted Windows remote-control session.",
        Protocol::Skinny => "A Skinny/SCCP message (TCP 2000) — Cisco IP-phone call signalling.",
        Protocol::Plugin(_) => "Traffic recognised by a user-defined protocol plugin — named by a rule you configured.",
        Protocol::Unknown(_) => "Traffic netscope doesn't decode in detail — shown safely anyway.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn pkt(proto: Protocol, summary: &str) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: proto,
            length: 0,
            summary: summary.into(),
            data: bytes::Bytes::new(),
        }
    }

    #[test]
    fn every_protocol_has_a_nonempty_lesson() {
        for proto in [
            Protocol::Dns,
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Tls,
            Protocol::Http,
            Protocol::Icmp,
            Protocol::Arp,
            Protocol::Unknown("x".into()),
        ] {
            let l = lesson(&proto);
            assert!(!l.title.is_empty());
            assert!(!l.summary.is_empty());
            assert!(!l.body.is_empty());
            assert!(!l.look_for.is_empty());
        }
    }

    #[test]
    fn all_lessons_covers_every_protocol() {
        assert_eq!(all_lessons().len(), 174);
    }

    #[test]
    fn glossary_is_populated() {
        assert!(glossary().len() >= 10);
        assert!(glossary()
            .iter()
            .all(|t| !t.term.is_empty() && !t.meaning.is_empty()));
    }

    #[test]
    fn explain_prioritizes_handshake() {
        let p = pkt(Protocol::Tcp, "TCP Connection opened (3-way handshake)");
        assert!(explain_packet(&p).contains("handshake"));
    }

    #[test]
    fn explain_dns_query_vs_response() {
        let q = pkt(Protocol::Dns, "DNS Query — google.com");
        let r = pkt(Protocol::Dns, "DNS Response — google.com → 1.2.3.4");
        assert!(explain_packet(&q).contains("asking"));
        assert!(explain_packet(&r).contains("answered"));
    }

    #[test]
    fn explain_tls_hides_content() {
        let p = pkt(Protocol::Tls, "TLS — 1360 bytes of encrypted data");
        assert!(explain_packet(&p).contains("can't be read"));
    }

    #[test]
    fn explain_reset() {
        let p = pkt(Protocol::Tcp, "TCP Connection reset (RST)");
        assert!(explain_packet(&p).contains("refused") || explain_packet(&p).contains("aborted"));
    }
}
