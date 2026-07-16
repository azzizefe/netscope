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
        assert_eq!(all_lessons().len(), 78);
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
