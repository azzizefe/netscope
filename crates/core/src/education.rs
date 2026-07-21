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
        Protocol::RedisCluster => Lesson {
            title: "Redis cluster bus — how nodes watch each other",
            summary: "The gossip that decides which members of a cluster are alive.",
            body: "Separate from the client protocol and on its own port (the data port \
plus 10000, so 16379 for a default install), this is where the nodes of a Redis \
cluster keep track of each other. Most of it is routine PING and PONG. The messages \
worth spotting are FAIL, where a node is declared down, and the failover auth \
request and grant that follow — a cluster votes on which replica gets promoted. \
Those are the cause of the errors clients see, not a symptom of them.",
            look_for: "\"Redis cluster FAIL (a node declared down)\" and \"failover auth request\" on TCP 16379.",
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
        Protocol::MBus => Lesson {
            title: "M-Bus — reading the meters in a building",
            summary: "One gateway polling every water, gas, heat and electricity meter.",
            body: "A block of flats has a gateway that walks round every meter in the \
building asking for a reading, and this is that conversation once it has been put \
onto TCP. The reply carries the meter's serial number and, more usefully, what kind \
of meter it is — so a capture tells you what is actually installed.\n\n\
It is worth watching because a meter that has stopped answering is invisible \
otherwise: the gateway keeps asking, the billing system keeps showing the last \
value it received, and nothing looks wrong until someone gets an estimated bill.",
            look_for: "\"M-Bus reply — water meter, serial 12345678\"; a request to a meter with no reply following it.",
        },
        Protocol::Wmbus => Lesson {
            title: "wM-Bus — the wireless meters outside",
            summary: "Radio frames from hundreds of meters collected by a concentrator.",
            body: "Wireless M-Bus (EN 13757-4) is how smart water, gas and heat meters \
report over the air when there is no cable to run. A concentrator on a pole or rooftop \
collects these radio frames — S mode for stationary residential meters, T mode for \
frequent-transmit sensors, C mode for compact battery devices — and forwards them \
onto TCP for the billing system.\n\n\
The frame shares its application layer with wired M-Bus, so a variable-data reply \
names the CI-field and the meter's serial number. Watching this is how you notice \
a meter that has gone quiet — the concentrator still forwards everyone else, and \
the gap is invisible until the estimate arrives.",
            look_for: "\"wM-Bus (S) reply — variable data reply, serial …\"; mode labels and CI-field names; a missing meter in a run of regular readings.",
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
        Protocol::OpcUaPubSub => Lesson {
            title: "OPC UA PubSub — the fire-and-forget industrial data stream",
            summary: "OPC UA's publish/subscribe mode: publishers broadcast data, subscribers listen.",
            body: "OPC UA's client/server model is the handshake — one device asks, another \
answers. PubSub is the broadcast: a publisher sends a UDP datagram (a UADP \
NetworkMessage) to a multicast group or unicast address, and any subscriber \
that cares picks it up. There is no connection, no acknowledgement, and no \
retransmit — a missed datagram is simply gone.\n\n\
The publisher identifies itself with a PublisherId, and groups its output into \
WriterGroups, each carrying DataSetMessages for a particular set of variables. \
Those two IDs — publisher and group — are the address of the data stream: \
if a subscriber stops receiving, the first question is whether the publisher \
is still sending and whether the group IDs match what the subscriber expects.\n\n\
Discovery Request and Discovery Response frames are the control plane: a \
subscriber sends a Discovery Request to find out what publishers are present \
and what groups they offer. Seeing those frames tells you the subscription \
configuration is still being negotiated.",
            look_for: "\"OPC UA PubSub DataSet — publisher N group M\" repeating at a fixed rate \
— that is the live process data. A gap in the sequence means a dropped datagram. \
\"Discovery Request\" means a subscriber is still looking for its publisher.",
        },
        Protocol::CcLinkIeFieldBasic => Lesson {
            title: "CC-Link IE Field Basic — software-based industrial Ethernet",
            summary: "Mitsubishi's open Ethernet protocol for cyclic device exchange based on SLMP.",
            body: "CC-Link IE Field Network Basic brings industrial Ethernet to small-scale \
devices by running on standard Ethernet hardware without dedicated ASICs. It uses UDP/IP \
transmissions on port 61450 for cyclic communication (remote I/O registers RX/RY and RWw/RWr) \
and encapsulates SLMP (Seamless Message Protocol) for transient parameters, configuration, \
and diagnostics. It's the standard software-based fieldbus in Mitsubishi automation environments.",
            look_for: "Packets on UDP 61450 carrying SLMP request/response subheaders (0x5000 / 0xD000) for cyclic read/write commands.",
        },
        Protocol::CcLinkIeControl => Lesson {
            title: "CC-Link IE Control — high-speed industrial backbone",
            summary: "Mitsubishi's high-speed controller-to-controller network on EtherType 0x890F.",
            body: "CC-Link IE Control Network is a high-speed, deterministic Ethernet-based \
backbone network designed for controller-to-controller communication. It operates directly \
over Ethernet layer 2 (EtherType 0x890F) to provide real-time cyclic transmission of large volumes \
of control data, alongside transient messaging. It utilizes a token-passing mechanism to ensure \
highly reliable data transfer without collision.",
            look_for: "Frames on EtherType 0x890F carrying CC-Link IE message structures (such as TokenM, CyclicData, or Transient).",
        },
        Protocol::Codesys => Lesson {
            title: "CODESYS V3 — programming and monitoring PLCs",
            summary: "The runtime protocol behind IEC 61131-3 controllers on TCP 11740.",
            body: "CODESYS is the most widely used IEC 61131-3 development environment. \
A controller running the CODESYS runtime listens on TCP 11740 for engineering-tool \
connections — downloading programs, reading variables, forcing outputs. The Block \
Driver is the most common service group, providing channel-based Read, Write, and \
Notify operations.\n\n\
Seeing CODESYS traffic means someone is talking to a PLC. The operation names tell \
you whether they are reading (monitoring) or writing (changing the program or data), \
which is the difference between watching a machine and altering its behaviour.",
            look_for: "\"CODESYS Block Driver — Read\" (monitoring), \"CODESYS Block Driver — Write\" (a change); UDP discovery broadcasts with device info.",
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
        Protocol::Mka => Lesson {
            title: "MKA — the handshake MACsec needs before it encrypts anything",
            summary: "Key agreement for MACsec, and a very quiet way for it to fail.",
            body: "MACsec encrypts a link at layer 2, but only after both ends agree a \
key. MKA is that agreement: peers announce themselves, elect a key server, and \
the server distributes the session key.\n\n\
Failure here is silent. If key agreement never completes the link does not \
encrypt — and depending on configuration it either carries traffic in the clear \
or carries nothing at all, with no error anywhere above. The tell is the peer \
lists: a peer that stays in the potential list and never reaches the live list \
is one whose messages arrive but whose answers are not accepted, which is almost \
always a mismatched connectivity association key.",
            look_for: "\"MKA key server (priority 0) — live peer list\" when healthy; a peer stuck on \"potential peer list\", or \"MACsec not desired\", when it is not.",
        },
        Protocol::Kpasswd => Lesson {
            title: "kpasswd — changing a Kerberos password, or resetting someone else's",
            summary: "Two very different operations sharing one port.",
            body: "A change is a user replacing their own password, having proved they \
know the old one. A set is an administrator overwriting somebody else's without \
knowing it. Same wire protocol, same port, different version number — and quite \
a different thing to find in a capture you did not expect it in.\n\n\
What netscope cannot tell you is whether it worked. The result code lives inside \
the KRB-PRIV structure, which is encrypted with the session key, so the summary \
stops where the encryption does rather than guessing.",
            look_for: "\"kpasswd password change — request\" for the routine case; \"password set (an administrator overwriting an account's password)\" for the one worth asking about.",
        },
        Protocol::Milter => Lesson {
            title: "Milter — where mail quietly disappears",
            summary: "A mail server asking its filters what to do with each message.",
            body: "A mail server hands each message to its filters — spam scoring, \
signing, virus scanning, policy — and each one answers. Most answers are dull.\n\n\
One is not. A discard tells the server to accept the message and then throw it \
away: the sender is told it succeeded, the recipient never receives anything, and \
no bounce is generated. Mail that vanishes leaving no trace in any log is usually \
this, and the capture is the only place it is visible. A reject, by contrast, \
bounces and is therefore visible to the sender.",
            look_for: "\"milter — discard silently (the sender is told it was accepted)\" — the answer that explains mail nobody can find.",
        },
        Protocol::Lmtp => Lesson {
            title: "LMTP — the last hop, where mail is actually filed",
            summary: "Like SMTP, but with one delivery status per recipient.",
            body: "LMTP looks like SMTP and shares most of its verbs, but it does a \
different job: handing a message from the mail server to whatever stores it. \
Dovecot, Cyrus and Postfix's local delivery all speak it.\n\n\
The difference that matters is at the end. SMTP answers with a single status for \
the whole message; LMTP answers with one status per recipient. That is the whole \
reason it exists — a message to five mailboxes can succeed for four and fail for \
the fifth, and only here is that visible. A message that 'was delivered' but is \
missing from one mailbox is exactly this.",
            look_for: "\"LMTP 1 of 3 recipients failed\" — a partial delivery that no single status upstream could have expressed.",
        },
        Protocol::LinkOam => Lesson {
            title: "Link OAM — a link reporting its own health, and its own death",
            summary: "Mostly dull keepalives, with two exceptions worth knowing.",
            body: "Two devices either end of a link exchange these continuously, and \
almost all of them say nothing. The value is in the exceptions.\n\n\
A dying gasp is the last thing a device sends as its power fails — a modem, an \
ONT or a remote switch gets one frame out before it stops. That single frame is \
the difference between 'the site went down at 04:12' and 'the site's power went \
at 04:12'; nothing else in a capture separates a power cut from a cut fibre.\n\n\
Event notifications carry error counters, so a link that is degrading says so \
before it fails outright. Errored symbols climbing over hours is a transceiver \
or a fibre going bad while everything still nominally works.",
            look_for: "\"Ethernet OAM — dying gasp\" at the moment a remote site goes dark; \"Ethernet OAM event — errored symbol period\" on a link that is about to.",
        },
        Protocol::Esmc => Lesson {
            title: "ESMC — how good is the clock this network is using?",
            summary: "Synchronous Ethernet's way of announcing timing quality hop by hop.",
            body: "Synchronous Ethernet carries frequency in the physical layer, but a \
receiver cannot tell from a clock signal how good that clock is. ESMC carries \
that judgement separately: each hop announces the quality of the source it is \
locked to, and downstream equipment uses it to pick which port to take timing \
from.\n\n\
Watch it degrade. A chain announcing a primary reference clock is locked to a \
caesium-grade source; the same chain announcing a local equipment clock has \
fallen back to its own oscillator and will drift. Mobile basestations notice \
this long before anything else does.\n\n\
One caveat: the quality numbers mean different things under Option 1 (ITU/ETSI) \
and Option 2 (ANSI), and the frame does not say which the network runs. \
netscope names the Option 1 meanings and always shows the raw code too.",
            look_for: "\"ESMC heartbeat — primary reference clock (QL 2)\" when healthy; \"local equipment clock (will drift)\" or \"do not use\" when the sync chain has broken.",
        },
        Protocol::Memberlist => Lesson {
            title: "memberlist — how a cluster decides a node is dead",
            summary: "Gossip that names both the evicted node and the node that evicted it.",
            body: "Serf, Consul and Nomad all sit on the same membership library. Nodes \
ping each other over UDP; a node that does not answer is pinged again indirectly, \
through a third node, in case the direct path is the broken thing. If that also \
fails, the node is gossiped as suspect, and shortly after as dead.\n\n\
What makes this worth reading is that the accusations are signed. A suspect or \
dead message names the node being removed and the node making the claim, so a \
capture answers the question a cluster's logs cannot: is one flapping member \
being reported by everybody, or is a single peer with a broken path evicting \
every node it cannot reach? Those two have identical symptoms and opposite fixes.\n\n\
It also separates a clean shutdown from an eviction. A node leaving on purpose \
gossips its own death, so the accused and the accuser are the same name.",
            look_for: "\"web-1 declared web-3 dead\" — and whether the accuser is always the same node, which points at the accuser rather than the accused.",
        },
        Protocol::ConsulRpc => Lesson {
            title: "Consul RPC — watching a cluster lose its leader",
            summary: "One port carrying agent RPC, Raft, gossip and gRPC, told apart by a single byte.",
            body: "Consul servers multiplex several protocols onto one port and put a type \
byte in front of each connection. The interesting value is Raft, because Raft is \
where a cluster's health is decided.\n\n\
A healthy cluster carries AppendEntries: the leader replicating log entries, and \
using that same call as its heartbeat. RequestVote means a follower stopped \
hearing the heartbeat and started an election. Occasional elections are normal \
after a restart; a capture full of them is a cluster that cannot hold a leader, \
which users experience as writes failing intermittently while every individual \
server looks fine. InstallSnapshot means a follower fell so far behind that \
replaying the log was given up on in favour of shipping the whole state.\n\n\
The type bytes are 0-9, a range RFC 7983 leaves unassigned as TLS content types \
precisely so ports can be multiplexed this way — which is why native TLS on the \
same port cannot be mistaken for them.",
            look_for: "\"RequestVote — an election is under way\" repeating, which means the cluster is churning leaders rather than serving.",
        },
        Protocol::Drbd => Lesson {
            title: "DRBD — a disk mirrored to another machine",
            summary: "Replicated block storage, and the peer-side failures that stall writes locally.",
            body: "DRBD mirrors a block device over the network: writes to the primary are \
sent to the peer, and depending on the configured protocol the write is not \
acknowledged locally until the peer has it. That coupling is why a remote problem \
shows up as a local one — a filesystem that stalls, or a failover that comes up \
holding stale data, with nothing local looking broken.\n\n\
The negative acknowledgements are what explain it. NegAck, NegDReply and \
NegRSDReply are all the peer reporting that its own disk could not serve the \
request. Seeing them means the mirror is the failing side. A run of OutOfSync or \
RSDataRequest is something else entirely — a resynchronisation working through \
the blocks that diverged, which is the expected aftermath of a node rejoining \
rather than a fault.\n\n\
Each resource is configured on its own port, climbing from around 7788, so DRBD \
is recognised by the magic at the head of every packet instead.",
            look_for: "\"NegDReply — the peer's disk is unusable\", which puts the fault on the far node rather than the one that appears stuck.",
        },
        Protocol::Chargen
        | Protocol::Qotd
        | Protocol::Echo
        | Protocol::Discard
        | Protocol::Daytime
        | Protocol::Time
        | Protocol::Tcpmux => Lesson {
            title: "The small services — 1983 debugging aids, now DDoS weapons",
            summary: "Echo, Discard, Daytime, QOTD, Chargen, Time and TCPMUX.",
            body: "These were specified in the early 1980s as debugging aids, when \
every host on the network was known and trusted. Each RFC is about two pages. \
Every one of them is still compiled into equipment shipping today, and on a \
great many devices they are still switched on.\n\n\
The UDP variants are reflectors. A single spoofed datagram to Chargen returns \
up to 512 bytes to whoever the source address claimed to be — and RFC 864 \
states plainly that the request's contents are ignored, so one byte is enough \
to trigger it. QOTD behaves much the same. The attacker sends small packets \
from a forged address, the victim receives the flood, and the reflecting host \
has no idea it is taking part.\n\n\
That makes seeing these at all the finding. Nothing legitimate has used them in \
thirty years. A host answering on UDP 19 from the public internet is a \
reflector waiting to be recruited — usually a printer, a switch management \
port, or an embedded stack that shipped with the defaults left on.\n\n\
Time is the odd one out, and worth a second look for a different reason: it \
counts seconds from 1900 in 32 bits, so it overflows in 2036.",
            look_for: "Any of them answering on UDP at all — and especially a Chargen reply of a few hundred bytes, which is the reflected volume.",
        },
        Protocol::Artnet | Protocol::Sacn => Lesson {
            title: "Art-Net and sACN — two consoles fighting over one universe",
            summary: "Stage lighting control carried over Ethernet.",
            body: "Theatrical lighting runs on DMX512: 512 channels of one byte each, \
grouped into a universe. Art-Net and sACN carry universes over IP so a console \
can drive a rig without a cable per dimmer. Art-Net is the older informal one; \
sACN (ANSI E1.31) is the standardised answer, and both are everywhere.\n\n\
Two fields matter. Every packet for a universe carries an incrementing \
sequence number, so a gap means frames were dropped — which the audience sees \
as the rig stuttering, and which no console will report because from its side \
everything was sent.\n\n\
The second is priority, and it is the classic failure. sACN lets several \
sources send the same universe at different priorities and the receiver obeys \
the highest. Two consoles at the *same* priority is the one that wastes an \
afternoon: the fixtures flicker between two states at packet rate while each \
console displays a perfectly correct output. Nothing but the wire shows that \
there are two senders at all — which is why the source name is worth reading.",
            look_for: "The same universe from two sources at equal priority, or a sequence number that skips.",
        },
        Protocol::Osc => Lesson {
            title: "OSC — control traffic on a port nobody registered",
            summary: "Open Sound Control: addresses like file paths, in plain text.",
            body: "OSC replaced MIDI for anything needing more than seven bits of \
resolution or a name longer than a number. A message is an address pattern that \
looks like a filesystem path — /mixer/1/fader — a type-tag string saying what \
the arguments are, then the arguments.\n\n\
It has no port of its own. Every application picks one, and that is exactly why \
it is worth recognising structurally: on a show network the traffic is plainly \
there, but a capture filtered by port finds nothing at all. netscope identifies \
it by shape instead — an address starting with a slash, everything padded to a \
multiple of four bytes.\n\n\
Bundles are the other half. A bundle groups several messages with a time tag \
saying when they should take effect, which is how a lighting cue and an audio \
change stay together. A bundle whose time tag has already passed is applied \
immediately, and the cue lands out of step with everything it was meant to \
match.",
            look_for: "The address pattern — it names the device and the parameter in plain text, with no lookup needed.",
        },
        Protocol::RtpMidi => Lesson {
            title: "RTP-MIDI — refused, or simply never answered",
            summary: "MIDI over a network, plus the session that has to open first.",
            body: "RTP-MIDI carries MIDI over IP instead of a five-pin cable, which is \
how a keyboard reaches a computer in another room and how Apple's Network MIDI \
works. There are two conversations on adjacent ports: a control port running \
the session protocol, and a data port carrying the MIDI once that succeeds.\n\n\
Reading the control port is the point. A session that never establishes looks, \
at the instrument, exactly like a cable that is not plugged in — no error, no \
sound, nothing on screen. But an invitation that is *rejected* is a completely \
different fault from one that goes unanswered: the far end is present and \
refusing, usually because it is already bound to another host or the name does \
not match what was configured.\n\n\
The clock exchange is worth watching too. RTP-MIDI corrects for network delay \
by measuring it in rounds; rounds that keep repeating mean the estimate never \
settles, and notes will arrive audibly late.",
            look_for: "\"invitation rejected\" rather than no reply at all — the far end is there and saying no.",
        },
        Protocol::Igrp => Lesson {
            title: "IGRP — a router older than its own replacement",
            summary: "Cisco's pre-EIGRP interior routing protocol.",
            body: "IGRP was Cisco's answer to RIP's fifteen-hop ceiling: a \
distance-vector protocol whose metric was built from bandwidth and delay rather \
than a hop count. EIGRP replaced it, and Cisco removed IGRP from IOS long \
ago.\n\n\
That is precisely why finding it matters. IGRP on a capture taken today is not \
a routing design decision — it is a device old enough to predate its vendor's \
own replacement for it, still participating in routing. And it carries no \
authentication of any kind, so anything able to put a packet on the segment can \
advertise a route and have it believed.\n\n\
The three counts in the header — interior, system and exterior — are the useful \
read. Exterior routes are how a default route arrives, so a neighbour that \
suddenly advertises them when it never did before has either gained a new \
upstream or is being spoofed.",
            look_for: "Any IGRP at all, and especially exterior routes from a neighbour that did not advertise them before.",
        },
        Protocol::Etherip => Lesson {
            title: "EtherIP — the far site's broadcasts arriving here",
            summary: "A complete Ethernet segment tunnelled inside IP.",
            body: "EtherIP does one thing: it puts an entire Ethernet frame, headers \
and all, inside an IP packet. Two sites then share one broadcast domain as \
though they were patched into the same switch. OpenBSD bridging and a number of \
layer-2 VPNs use it.\n\n\
The header is two bytes — a version nibble and twelve reserved bits — which is \
about as thin as encapsulation gets. What that thinness hides is the point: \
everything inside is a full Ethernet frame, so the tunnel carries the remote \
site's broadcasts, its spanning tree and its ARP. A broadcast storm at one end \
crosses to the other, and a loop can form between two sites that have no \
physical link at all.\n\n\
At the tunnel endpoint a capture shows only \"IP protocol 97\" unless the frame \
inside is unwrapped, so the tunnel is treated as context here and the frame \
within it is reported as the answer.",
            look_for: "What is inside the tunnel — broadcast and spanning-tree traffic crossing between sites is the thing to catch.",
        },
        Protocol::Nsip => Lesson {
            title: "NS — the heartbeat that takes many cells with it",
            summary: "GPRS Network Service, and why a few missing acks is a large event.",
            body: "GPRS Network Service multiplexes many cells onto a handful of virtual connections between the base station subsystem and the SGSN, and keeps track of which of those connections are alive.

`NS-ALIVE` and its acknowledgement run continuously on each one. When the acknowledgements stop, the connection is declared dead — and every cell multiplexed onto it goes down with it. That is why a handful of missing acknowledgements is a far larger event than it looks: subscribers across several cells lose packet service simultaneously, while the base station's own logs record only that a link went down.

`NS-BLOCK` is the orderly version of the same outcome — a connection taken out of service deliberately. Telling the two apart is the difference between scheduled maintenance and an outage.

`NS-UNITDATA` is the envelope for real traffic. It names the cell in its own header and hands the rest to BSSGP, so a tool that stops at this layer reports \"data\" for exactly the messages worth reading.",
            look_for: "Alive messages without acks — and which cells share that connection.",
        },
        Protocol::Bssgp => Lesson {
            title: "BSSGP — where a cell says it cannot cope",
            summary: "Flow control between a cell and the core, and the data it discarded.",
            body: "Between a GSM/GPRS base station subsystem and the SGSN sits BSS GPRS Protocol. It carries user data, but the reason to read it is everything else: this is where a cell and the core negotiate how much traffic the radio side can actually take.

The radio side has far less capacity than the wire side, and that capacity moves with the number of subscribers in the cell and the quality of their signal. So the BSS continuously tells the SGSN what it can accept — per cell, and per subscriber. When a flow-control message goes unacknowledged the core keeps sending at the old rate, and the overflow shows up as `LLC-DISCARDED`: user data the network accepted and then threw away. No layer above reports a loss. The subscriber sees a download that stalls.

The `STATUS` causes are unusually specific about whose fault something is, and they lead to different teams. `Processor overload` and `SGSN congestion` are the core running out of capacity. `Cell traffic congestion` is the radio side. `Equipment failure` is hardware. `BVCI unknown` and `BVCI blocked` are configuration — one side is addressing a cell the other does not have, or has deliberately taken out of service.

`BVC-RESET` deserves attention because it is not routine: it rebuilds the context for a cell and drops the state for every subscriber on it. A cell that keeps resetting is one whose subscribers keep re-attaching, which they experience as data service that comes and goes for no reason they can see.

Reading the elements needs care: the length is one byte when its top bit is set and two bytes when it is not. Assume one byte always and the walk reads the next element's identifier as data, misreading everything after it.",
            look_for: "LLC-DISCARDED, and a status cause that says whether the radio or the core ran out.",
        },
        Protocol::Mtp3 => Lesson {
            title: "MTP3 — where a lost destination is explained",
            summary: "The SS7 routing layer, and the message that says a point went away.",
            body: "Underneath SCCP, ISUP and everything else in SS7 sits Message Transfer Part level 3: the layer that decides which signalling point a message is for. Modern networks carry it over IP rather than TDM links, but the routing label inside is unchanged.

Service indicator 0 is signalling network management — the network talking about itself — and it is the reason to read this layer at all. A **transfer prohibited** message says a signalling point is no longer reachable through this route. Everything behind it stops working, and every layer above sees only silence: ISUP waits for an answer that will not come, SCCP retries, an application eventually reports a generic network error. The explanation exists here and nowhere else in the capture. The matching *transfer allowed* is how you tell an outage that recovered from one that is still going.

The service indicator also names the user part — SCCP, ISUP, TUP, BICC — which is what separates call setup from database queries riding the same links. A tool that labels all of it \"MTP3\" throws that distinction away.

The routing label rewards care. It is a single 32-bit **little-endian** word holding a 14-bit destination point code, a 14-bit origin point code and a 4-bit link selector, none of them aligned to a byte. Read it big-endian, or read the point codes as 16-bit values, and you still get point codes — plausible ones. On a network where point codes are assigned by a regulator and identify specific operators, a wrong one sends the investigation to a different company.",
            look_for: "A transfer-prohibited message, and whether a transfer-allowed ever followed it.",
        },
        Protocol::SomeIpTp => Lesson {
            title: "SOME/IP-TP — segments with nothing to catch them",
            summary: "How a large vehicle message is split, and what happens when one piece is lost.",
            body: "Plain SOME/IP carries a message that fits in one datagram. A camera's object list, a radar's track list, a diagnostic blob being pulled off an ECU — those do not fit. SOME/IP-TP cuts them into segments and stamps each one with an offset.

What makes it worth separating from ordinary SOME/IP is what it deliberately lacks. There is no retransmission, no acknowledgement, no negative acknowledgement. Over UDP, one dropped datagram silently discards the entire message it belonged to — a whole perception frame, an entire diagnostic response — and the receiver's only evidence is a reassembly that never completes. Nothing on the wire reports an error, and nothing asks for the missing piece.

So the offsets are the diagnosis. A gap between them is the segment that was lost, and therefore the message that will never be delivered. This is usually the only place that loss is visible at all.

The more-segments flag is clear exactly once per message, on the last segment. A stream that never shows it clear is a message truncated in flight, with a receiver still waiting for the rest.

One detail catches implementations out and is worth stating plainly: the offset field is 28 bits, with the low four bits of that word used for flags, so the byte offset is the field **times sixteen**. Read as a plain byte count, every segment lands at a sixteenth of its real position. The segments overlap, reassembly produces a message of roughly the right length made of the wrong bytes, and — because there is no checksum over the reassembled whole — nothing anywhere reports a problem.",
            look_for: "A gap in the offsets, or a message whose last segment never arrives.",
        },
        Protocol::Rgoose => Lesson {
            title: "R-GOOSE — a breaker trip you can route",
            summary: "IEC 61850-90-5, and the two header fields that decide whether that is safe.",
            body: "A GOOSE message is a protection relay telling a circuit breaker to open. It has four milliseconds to arrive, which is why ordinary GOOSE rides straight on Ethernet with no IP layer in the way. IEC 61850-90-5 wraps it in a session header so the same message can be **routed** — between substations, over a wide-area link, into a control centre.

Routing a trip command is as consequential as it sounds, and most of that session header exists to make it survivable. Two fields decide whether it is.

The first is the **simulation flag**. Every APDU says whether it is test traffic or real. A relay honours simulated messages only when it has itself been put into test mode, so the two must agree — and when they disagree the failure is silent in the worst possible direction. A relay left in test mode after commissioning will ignore a genuine trip. A relay taken out of test mode too early will act on an engineer's simulation. Neither writes anything in a log that says which happened.

The second is **authentication**. The header carries a key identifier and an initialisation vector, because a routable trip message that nobody authenticated can be forged by anyone who can reach the network. A key identifier of zero with no vector is exactly that: unauthenticated, routable, and able to open a breaker. On a flat network this was merely bad; on a routed one it is reachable from much further away.

The SPDU number is a plain sequence, and gaps in it are trip messages that did not arrive on a path whose entire budget is four milliseconds.

One implementation detail matters: the initialisation vector is variable-length, and the payload begins after it. Ignore that and the simulation flag gets read out of the vector's own bytes, which makes the test-versus-real distinction meaningless while still producing a plausible answer.",
            look_for: "A session with no key and no vector — and any disagreement between the simulation flag and what the relays expect.",
        },
        Protocol::Opensafety => Lesson {
            title: "openSAFETY — the frame that trusts nothing beneath it",
            summary: "Functional safety over any fieldbus, and the fault that stops the machine.",
            body: "A light curtain in front of a press. An emergency stop. A two-hand control that will not let a press cycle unless both hands are on the buttons. These have to work when the network does not — and the usual answer, \"use a reliable network\", is not one you can certify.

openSAFETY takes the opposite approach, called the **black channel**. The transport underneath is assumed to be completely untrustworthy: it may lose frames, duplicate them, reorder them, corrupt them or deliver them late. Every safety guarantee is carried inside the openSAFETY frame itself, so the same frames ride unchanged over POWERLINK, PROFINET, EtherNet/IP or Modbus. None of those are trusted to do anything but move bytes.

That is why a **consecutive time** count sits in every frame. A receiver that sees the same count twice knows the data is not fresh, whatever the network below claims — which is how a replayed or stalled frame is caught rather than acted on.

The message worth catching is **SN_FAIL**: a safety node reporting a fault. Whatever it guards is about to be, or already is, in its safe state, so this is the message that precedes a machine stopping. It names an error group and a code, which is the difference between \"a node faulted\" and knowing which node and why — a device fault and a vendor-specific code send you to entirely different places.

The state handshake matters too. A node walks through pre-operational and operational before it is permitted to guard anything. A node cycling through that sequence never becomes operational, and the machine simply refuses to start with nothing obviously broken.

One detail catches implementations out: the source address is ten bits, and its top two bits live inside the message identifier byte. Read that byte whole and every node above address 255 becomes an unknown message; mask the address to eight bits and four different nodes look like one.",
            look_for: "SN_FAIL — and the error group, which says whether to look at the device or the vendor.",
        },
        Protocol::Cnip => Lesson {
            title: "CN/IP — the building control channel that keeps re-forming",
            summary: "LonWorks segments tunnelled over IP, and the registration storm.",
            body: "A large building's heating, lighting and door control often still run on LonWorks — a network older than the IP infrastructure that now surrounds it. CN/IP is how those segments are joined across a campus: each router registers with a configuration server, joins a channel, and tunnels its native LonTalk frames to the others.

Once a channel is established, essentially everything should be a data packet. The configuration messages — device registration, channel membership, send list — belong to a channel that is still forming. Seeing them over and over means routers keep dropping out and re-registering, and while that happens, control messages between segments are quietly being lost.

The building does not break in any obvious way. A zone's setpoint occasionally fails to take. A light in one wing sometimes does not respond to its switch. From inside the control software this is invisible, because the software knows only what it sent — which is why the packets are often the only place the answer exists.

Two details in the header are worth reading. CN/IP can **authenticate** its packets, so a channel configured for authentication carrying unauthenticated ones is a misconfigured router — and every device behind it will take commands from anyone on the network. And the **urgent channel** is a port, not a flag: 1629 is the priority path, 1628 the ordinary one. A time-critical device configured onto the wrong one has latency that nothing in the application can explain.

The session identifier separates a router that is retransmitting from one that restarted — a restart resets the session, a retransmission does not.",
            look_for: "Registration and membership traffic long after the channel should have settled.",
        },
        Protocol::Lontalk => Lesson {
            title: "LonTalk — how hard the network was asked to try",
            summary: "Building control messages, and whether anyone confirmed delivery.",
            body: "A thermostat telling an air handler it wants more heat; a switch telling a ballast to dim; a card reader telling a door to unlock. LonTalk is what those devices say to each other, and it has been running commercial buildings since before they had IP.

What makes it worth reading is that every message chooses its own delivery guarantee. **Acknowledged** means the sender waits for confirmation and retries without it. **Unacknowledged, repeated** means the message is simply sent several times and hoped for — nothing confirms any copy arrived. And a **reminder** is the transport layer asking for messages it never received.

A network showing many reminders and repeats is one losing control messages. The failure is intermittent by nature: a setpoint that occasionally does not take, a light that sometimes ignores its switch. Nobody files a ticket for a building that works most of the time, and the control software cannot see it, because it only knows what it transmitted.

LonTalk can also **authenticate** a message, with a challenge and a reply, and one bit in the transport byte says whether it did. On a segment where door controllers share a wire with lighting, an unauthenticated command to a lock is a command anyone with access to that wire can forge — and no part of the building's own software will ever mention it.

The same class number means different things depending on the PDU format: class 0 is `acknowledged` in a transport PDU, `request` in a session PDU, and `challenge` in an authentication PDU.",
            look_for: "Reminders and repeats — and any command to security hardware that was not authenticated.",
        },
        Protocol::FfHse => Lesson {
            title: "Foundation Fieldbus HSE — the write that was refused",
            summary: "Process instruments over Ethernet, and the error nobody sees.",
            body: "A refinery runs on instruments that never stop talking: a flow transmitter publishing a reading several times a second, a valve positioner taking a setpoint, a controller closing the loop between them. Foundation Fieldbus is the language they speak, and HSE is how the field segments reach the control room over Ethernet.

The message type is where the diagnosis lives. Every HSE message is a request, a response, or an **error** — and an error in response to a `write` is a setpoint the plant believes it applied. The operator's screen keeps showing the new value, because the screen shows what was *requested*, not what the device accepted. The valve is somewhere else entirely.

The services divide into three worlds and confusing them wastes hours. **FMS** carries process data — `read`, `write`, and `information report`, which is a device publishing on its own schedule rather than answering anyone. Reports that stop are a device gone quiet without ever disconnecting, so every session still looks healthy. **SM** is system management, where repeated `device annunciation` from one address means a device that keeps restarting. **FDA** is the session underneath both.

One byte carries the protocol identifier in its top six bits and the message type in its low two. Read it whole and every response and every error becomes an unrecognised protocol — which discards precisely the messages worth looking at.

The same service number also means different things depending on whether the message expects an answer: service 2 is `read` when confirmed and `event notification` when not.",
            look_for: "An error response to a write — the setpoint the screen says was applied.",
        },
        Protocol::Flexray => Lesson {
            title: "FlexRay — the null frame nobody notices",
            summary: "A time-triggered bus, and the failure that changes nothing about the timing.",
            body: "CAN decides who transmits by arguing about it: the lowest identifier wins, whenever it wants to talk. That is fine for a window motor and unacceptable for a brake. FlexRay decides in advance instead — the cycle is cut into slots, each slot belongs to one ECU, and that ECU transmits in its slot or not at all. Latency stops being a statistic and becomes a number you can prove before the car is built.

The schedule is also what hides the failure. An ECU that stops producing data does not go quiet: it transmits a **null frame** in its own slot, with the right identifier at exactly the right microsecond, carrying nothing. Bus load is unchanged. Every timing measurement still passes. No error counter moves. Somewhere upstream a control loop is now running on values that stopped updating, and the only thing on the wire that says so is one bit.

That bit is **active low**, which is the trap. `NFI` set means a *normal* frame; `NFI` clear means the frame is null. Read it the intuitive way and every diagnosis inverts — a perfectly healthy bus reads as every ECU having stopped, and the single ECU that really did stop reads as fine.

Two other bits decide whether the cluster starts at all. Only a few nodes are configured as sync nodes, and only those may set the startup indicator. A cluster that will not come up is usually a question about those bits: too few nodes sending them, or a node claiming a role it was never configured for.

The capture format also carries the controller's own error flags. A coding error or a TSS violation is the physical layer failing — termination, wiring, a dying transceiver — and worth separating before anyone spends a day reading application data that was never valid.",
            look_for: "A null frame: the slot arrives on time, with the right ID, carrying nothing.",
        },
        Protocol::Dlr => Lesson {
            title: "DLR — the machine's network wired as a loop",
            summary: "ODVA ring protection, and the beacon that says whether the loop is closed.",
            body: "A machine's network cannot pause. A drive mid-motion, a press mid-stroke, a robot mid-path — none of them can wait the seconds spanning tree takes to reconverge. So EtherNet/IP rings are wired as loops and protected by DLR: one node, the ring supervisor, blocks a port to stop the loop flooding, and releases it within milliseconds when a link breaks.

The supervisor beacons continuously, often every few hundred microseconds. Health is inferred from those beacons arriving, not announced — which is why a capture is often the only place the ring's real state is visible.

The state worth catching is `RING_FAULT_STATE`. A ring in fault is still passing every packet, because that is exactly what the redundancy was for. Production continues, no alarm fires, and the ring is now a line — the next cable pull, the next crushed connector, takes a section of the machine off the network entirely. The window between the first fault and the second is often weeks, and nothing but the beacon reports it.

The beacon also carries the supervisor's address and precedence, which catches a common commissioning mistake: two nodes configured as supervisor on one ring. That does not show up as an error anywhere — it shows up as beacons arriving from two different addresses.

Sign_On and Announce belong to a ring that is forming. On a ring that should have settled hours ago, seeing them repeatedly means it keeps re-forming — a marginal cable or a device rebooting in a loop — and that is invisible from the application until the day it stops working outright.",
            look_for: "A beacon in RING_FAULT_STATE — the machine runs fine and has no redundancy left.",
        },
        Protocol::Erps => Lesson {
            title: "ERPS — the ring that blocks a link on purpose",
            summary: "G.8032 ring protection, and the state that means it has none left.",
            body: "A ring of switches is a loop, and an Ethernet loop floods itself to death within seconds. Spanning tree solves that by blocking links, but it reconverges in seconds — too slow for a factory floor or a substation, where a few hundred milliseconds of blackout is an outage.

G.8032 takes the same idea and makes it fast. One link, the ring protection link, is blocked deliberately, so the ring runs as a line. When a link breaks, a node floods a Signal Fail message, the block is released, and traffic goes the other way around the ring — in tens of milliseconds, because the decision is pre-arranged rather than recomputed.

The state worth watching is not the failure. It is the recovery that never completed. A ring sitting in `No Request` **without** the RPL Blocked bit set is running with no spare path: every host is reachable, no alarm fires, throughput is normal, and the next single link failure takes the ring down completely. The same is true of a `Forced Switch` an engineer left in place after maintenance — the ring looks healthy and has already spent its protection.

Because R-APS carries the sending switch's MAC address, a ring that keeps flapping can be traced to the node that keeps reporting, rather than to \"somewhere in the ring\".

R-APS rides inside the CFM frame format at EtherType 0x8902, as opcode 0x28.",
            look_for: "A No Request with RPL Blocked clear — the ring works and has no protection left.",
        },
        Protocol::Tsp => Lesson {
            title: "RFC 3161 — the timestamp that outlives the certificate",
            summary: "A trusted third party attesting when something existed.",
            body: "A signature proves who signed. It does not prove *when*, and that gap matters because certificates expire. Once the signing certificate is past its date, a verifier cannot tell a signature made while the certificate was valid from one forged afterwards, so it rejects both.

A timestamp authority closes the gap. It signs the hash together with the current time, and its attestation is what lets a verifier say the signature was made while the certificate was still good. This is why signed software keeps verifying years after release, and why archives, invoices and legal documents are timestamped rather than merely signed.

The failure is unusually quiet. Timestamping happens during a build or an archival job, against an external service nobody monitors, and a build that could not reach its authority still produces a signature that verifies perfectly *today*. It stops verifying on the day the signing certificate expires — often years later, long after the build logs are gone.

When the authority does answer with a refusal, the reason narrows the fix sharply. `timeNotAvailable` means the authority has lost its trusted time source and is refusing rather than signing a time it cannot stand behind — the correct behaviour, and an outage on their side. `unacceptedPolicy` means the client asked for a policy this authority does not offer, which is a configuration mismatch rather than an outage. `badAlg` is usually a client still requesting a hash algorithm that has since been withdrawn.

Timestamping travels inside HTTP with its own content types, `application/timestamp-query` and `application/timestamp-reply`, so nothing sees it without looking past the headers.",
            look_for: "A refusal — and especially \"timeNotAvailable\", which means the authority is refusing rather than signing a time it cannot vouch for.",
        },
        Protocol::Cmp => Lesson {
            title: "CMP — why the device could not get a certificate",
            summary: "Automated certificate enrolment, renewal and revocation.",
            body: "Certificate Management Protocol is what runs underneath automated \
PKI: an industrial controller, a phone or a car enrolling with a CA and then \
renewing before its certificate expires, without anyone typing anything.\n\n\
An enrolment failure is worth catching because of *when* it happens. A device \
with no valid certificate has no identity, so nothing will talk to it — and \
renewal happens weeks or months after installation, on a schedule nobody is \
watching. The failure that matters is not the one during deployment but the one \
at three in the morning on a device that has been fine for a year.\n\n\
CMP says exactly which thing went wrong, and the answers need entirely \
different fixes: `badTime` is the device's clock drifting out of tolerance, \
`signerNotTrusted` is the CA not accepting the key that signed the request, \
`badPOP` is a failed proof of possession, `systemUnavail` is the CA simply not \
taking requests. A device's own log will usually record none of that — just \
\"enrolment failed\".\n\n\
Several reasons can be set at once, because they arrive as a bit string rather \
than a single code, so reporting only the first would lose the rest.",
            look_for: "An error body's reason bits — especially \"bad time\", which is a clock problem masquerading as a PKI one.",
        },
        Protocol::Aeron => Lesson {
            title: "Aeron — the NAKs arrive before the latency does",
            summary: "Low-latency messaging that recovers loss itself.",
            body: "Aeron moves messages between processes faster than TCP can, which \
is why trading systems and market-data feeds are built on it. It does over UDP \
roughly what TCP does over IP, but the loss recovery is explicit: a receiver \
notices a gap and asks for the missing range by name.\n\n\
That makes the control frames the interesting ones. A data frame tells you only \
that traffic is flowing.\n\n\
**NAK** is a receiver saying it missed a range. The occasional one is ordinary \
on a busy network. A stream of them is a publisher outrunning the path, and it \
is the earliest signal available — it appears before the latency does.\n\n\
**Status messages** advertise how much receive window is left. A window \
shrinking towards zero is a consumer that cannot keep up, and when it reaches \
zero the publisher stalls. In the application that stall looks like a latency \
spike with no cause, which is exactly the kind of thing a capture ought to \
explain.\n\n\
A publication is identified by session, stream and term together. Two of the \
three matching is a different stream, so all three have to be read before \
concluding two frames belong to the same flow.",
            look_for: "NAKs increasing, or a status window shrinking towards zero — both precede the stall rather than follow it.",
        },
        Protocol::Lorawan => Lesson {
            title: "LoRaWAN — the counter a network silently ignores",
            summary: "Battery sensors on a kilometres-wide radio link.",
            body: "LoRaWAN carries a few bytes at a time from devices that must run \
for years on one battery: water meters, soil probes, parking sensors, cattle \
trackers. The radio reaches a long way and the devices sleep almost all the \
time, and both of those shape what goes wrong.\n\n\
**The frame counter is the failure worth knowing.** Every frame carries one, \
and it exists to stop replay — a receiver ignores anything not ahead of what it \
has already seen. So a device that resets, or gets a battery change on cheap \
hardware, restarts its counter at zero and the network then silently discards \
everything it sends. The device is transmitting perfectly and simply is not \
being listened to. Nothing at the device end shows this at all.\n\n\
**A device stuck on Join Request** is the other one. Joining is a two-step \
exchange, and a capture full of Join Requests with no Accepts is a device whose \
keys the network does not recognise, or whose requests reach a gateway that \
cannot reach the network server. It will retry until the battery is gone.\n\n\
**ADRACKReq** is the device asking whether anyone is still there — it has \
already raised its transmit power as far as it can and heard nothing back.\n\n\
The payload is encrypted end to end, so what the sensor actually reported is \
not readable. The header is the whole of what a capture can say, which is why \
these three fields carry so much of the diagnosis.",
            look_for: "A counter that restarted at zero, or Join Requests with no matching Accept.",
        },
        Protocol::Lin => Lesson {
            title: "LIN — where \"nobody answered\" is the whole diagnosis",
            summary: "The cheap single-wire bus under CAN.",
            body: "CAN costs real money per node, so carmakers put everything that \
needs only a few bytes a second on LIN instead: window motors, seat adjusters, \
mirrors, rain sensors, interior lighting. One master polls a handful of slaves \
over a single wire, and every frame is the master asking one specific slave to \
speak.\n\n\
That structure is why the error flags matter more than the data. **No slave \
response** means the master asked and nothing answered — on a bus this simple, \
the device is dead, unplugged or unpowered. **Checksum error** means something \
did answer but the frame arrived corrupt, which points at wiring rather than at \
the device. **Parity error** means the identifier itself was damaged, so even \
the question did not get there intact.\n\n\
Those three point at three different repairs, and a mechanic replacing the \
wrong part is the ordinary cost of a tool that only says \"LIN error\".\n\n\
Two subtleties decide whether a frame reads correctly. The length, message type \
and checksum type share a single byte, so reading it whole makes every length \
wrong by a factor of sixteen. And the identifier is six bits — the top two are \
its parity, not part of the number.\n\n\
Identifiers 0x3C and 0x3D are reserved for diagnostics and carry the same \
transport CAN uses, so a diagnostic session on LIN reads exactly like one on \
CAN.",
            look_for: "\"no slave response\" against a particular identifier — that identifier names the device that stopped answering.",
        },
        Protocol::Iec101 => Lesson {
            title: "IEC 60870-5-101 — the serial link that reached IP anyway",
            summary: "The same telecontrol messages as -104, over FT1.2 framing.",
            body: "A great many substations are still reached by leased line, radio \
or dial-up, and they speak -101 rather than -104. Gateways then forward that \
serial traffic onto IP unchanged — exactly as Modbus gateways forward RTU — so \
it turns up on captures that ought to contain nothing but Ethernet.\n\n\
The message inside is the same ASDU -104 carries, so a refused breaker command \
reads the same way here. What differs is the frame around it, and the link \
layer says two things -104 has no equivalent for.\n\n\
**NACK — link busy** is the outstation refusing a message outright, at the link \
layer, before any ASDU is involved. A control centre watching a command time \
out cannot tell that from a lost frame unless the link layer is read.\n\n\
**DFC — data flow control** is the outstation saying its buffers are full. On a \
slow serial link this is how an overloaded RTU announces itself, and it is why \
polling appears to stall while the line itself is perfectly healthy.\n\n\
One detail decides whether the control byte reads correctly: the same function \
code means different things in each direction. Code 1 is \"reset user process\" \
from the controlling station and \"NACK\" from the outstation.",
            look_for: "\"NACK — link busy\" or the DFC flag, either of which explains a stalled poll that looks like a dead link.",
        },
        Protocol::Iser => Lesson {
            title: "iSER — the commands are here, the data never is",
            summary: "iSCSI with the block transfers moved onto RDMA.",
            body: "Ordinary iSCSI copies every block through the kernel twice. iSER \
keeps iSCSI's commands and responses but moves the data onto RDMA: the \
initiator advertises a region of its memory and the target reads from or writes \
to it directly. All-flash arrays and NVMe gateways use it because the copying is \
what costs, not the protocol.\n\n\
That split is what makes a capture confusing the first time. Commands appear as \
iSER messages wrapping an ordinary iSCSI PDU, but the blocks those commands move \
never appear at all — they travel as RDMA READ and WRITE operations against the \
advertised region, which is a different opcode on a different packet, and often \
offloaded so far into the adapter that a host capture never sees them. **A \
capture showing commands and no data is not a broken transfer. That is how iSER \
is supposed to look.**\n\n\
The header says which memory regions the target has been granted, which is how \
a command becomes a transfer, and the reject flag is the target refusing \
outright — before iSCSI's own status codes get a chance to say anything.\n\n\
One caveat worth knowing: iSER and SMB Direct both ride on RDMA SEND and \
neither carries a protocol identifier. Which service a queue pair was connected \
for is agreed by the connection manager and never repeated, so a capture that \
misses the connection setup cannot be certain which is which.",
            look_for: "\"rejected by the target\", and the advertised regions — a command advertising neither cannot move data whatever it asks for.",
        },
        Protocol::SmbDirect => Lesson {
            title: "SMB Direct — zero-copy file sharing over RDMA",
            summary: "SMB3 running directly over RDMA (RoCE or InfiniBand) without the TCP/IP overhead.",
            body: "SMB Direct (SMBD) replaces TCP/IP with RDMA transport to allow extremely \
high-speed, low-latency access to shared folders. Instead of segmenting files into TCP \
packets and copying them through the kernel, SMB Direct uses RDMA SEND to carry commands \
and flow-control credits, and directs the network adapter to write/read file blocks \
directly to and from the remote machine's RAM.\n\n\
This means that in a packet capture, the file transfer commands appear as SMB Direct messages \
carrying SMB2 payloads (such as NEGOTIATE or CREATE), but the actual block data is moved by \
subsequent RDMA READ/WRITE operations and does not appear inside the SMB Direct frames themselves.\n\n\
The SMBD header manages flow control via CreditsRequested and CreditsGranted. If those credits \
drop to zero, the connection stalls even if the underlying RDMA fabric is perfectly healthy.",
            look_for: "\"SMB Direct Negotiate\" or \"SMB Direct Data · SMB2 CREATE\" containing the file request, and \"SMB Direct Keep-Alive\" maintaining connection credits.",
        },
        Protocol::ModbusRtu => Lesson {
            title: "Modbus RTU over TCP — the traffic that does not parse",
            summary: "Serial framing forwarded onto port 502 unchanged.",
            body: "Modbus TCP wraps every request in an MBAP header: a transaction \
id, a protocol id of zero, and a length. Modbus RTU is the older serial framing \
and has none of that — a unit address, the PDU, and a CRC.\n\n\
A great many gateways bridge a serial bus onto TCP by doing nothing at all. \
They listen on port 502 and forward RTU frames unchanged. That is not Modbus \
TCP and it does not parse as Modbus TCP: the first two bytes are an address and \
a function code where a transaction id is expected, so read as MBAP the frame \
is garbage. The result is that live control traffic renders as malformed \
packets or as nothing, on a network where knowing what is being written to a \
PLC is the entire reason for capturing.\n\n\
RTU has no header to identify it by — no protocol id, no length, no magic — so \
the CRC is the identification. A sixteen-bit checksum agreeing by chance is \
rare enough to be real evidence, and it is stronger than any guess based on \
field shapes could be.",
            look_for: "Modbus RTU appearing on 502 at all: it means a gateway is bridging a serial bus, and anything reading it as Modbus TCP is seeing nothing.",
        },
        Protocol::ModbusAscii => Lesson {
            title: "Modbus ASCII — the human-readable industrial serial frame",
            summary: "ASCII-encoded serial Modbus frames forwarded onto TCP.",
            body: "Modbus ASCII is the character-oriented serial variant of Modbus. \
Instead of transmitting raw binary bytes, each byte is split into two ASCII hex characters. \
Frames start with a colon (':') and end with a carriage return and line feed (CRLF).\n\n\
Just like Modbus RTU, serial-to-ethernet converters often forward these frames unchanged \
over TCP networks. Because it uses ASCII characters rather than binary representation, it \
cannot be parsed as Modbus TCP. It uses a Longitudinal Redundancy Check (LRC) checksum \
at the end of each frame, which allows self-validation and robust identification.",
            look_for: "Packets starting with a colon (':') and ending with CRLF ('\\r\\n') on port 502, containing hexadecimal characters.",
        },
        Protocol::IsoTp => Lesson {
            title: "ISO-TP — why the diagnostic session stalled",
            summary: "Carrying messages longer than a CAN frame's eight bytes.",
            body: "A CAN frame holds eight bytes and vehicle diagnostics routinely \
need more, so ISO-TP splits a message up: a First Frame announcing the total \
length, then Consecutive Frames carrying the rest, with the receiver sending a \
Flow Control frame in between to say whether it can keep up. Anything that fits \
in one frame is a Single Frame and skips all of it.\n\n\
UDS — the protocol every garage diagnostic tool speaks — rides on top of this. \
Without reading the ISO-TP layer, a diagnostic session on a raw CAN capture is \
just a wall of eight-byte hex lines.\n\n\
Flow Control is the frame worth looking for, because two of its three statuses \
explain a session that hangs. **Wait** is the ECU asking the tester to hold: a \
few are ordinary, a stream of them is an ECU too busy to be diagnosed, and the \
tool eventually gives up with a misleading \"no response\". **Overflow** means \
the ECU cannot buffer the message at all — the transfer is already dead, and \
the tool usually reports it as a generic communication error rather than as the \
ECU refusing on capacity grounds.\n\n\
One deliberate limit: only a Single Frame is handed to UDS. A First Frame is \
the *opening* of a message, and reading its bytes as a complete request would \
report a service code with a truncated body — confidently, and wrongly.",
            look_for: "\"flow control — overflow\" or a run of \"wait\" ahead of a diagnostic tool timing out.",
        },
        Protocol::Ocsp => Lesson {
            title: "OCSP — the two statuses that mean opposite things",
            summary: "Asking a CA whether a certificate has been revoked.",
            body: "When a client is handed a certificate it can ask the issuing CA \
whether that certificate is still valid. The answer decides whether a TLS \
connection may proceed — so an OCSP exchange that goes wrong takes working \
connections down with it, and it does so from a completely different host than \
the one the user was trying to reach. That is what makes it hard to find in a \
capture.\n\n\
The thing to get right is that an OCSP response carries **two** statuses.\n\n\
The outer one is transport-level: did the responder manage to answer at all — \
successful, tryLater, unauthorized. The inner one, buried inside the signed \
response about seven levels down in DER, is the actual verdict on the \
certificate: good, revoked, or unknown.\n\n\
Reading only the outer status is worse than reading nothing, because a revoked \
certificate arrives inside a response whose transport status is *successful*. \
\"OCSP successful\" next to a browser refusing to load a page is exactly the \
confusion worth removing. When the verdict cannot be reached, netscope says so \
rather than reporting the transport status alone — \"successful\" on its own \
would be read as \"the certificate is fine\".",
            look_for: "\"certificate REVOKED\" — and note that its transport status is \"successful\", which is why the outer one cannot be trusted alone.",
        },
        Protocol::Soap => Lesson {
            title: "SOAP — what that POST actually did",
            summary: "Device management hiding inside an HTTP body.",
            body: "A great deal of device management is SOAP over HTTP, and none of \
it shows in the request line. Every call is `POST /onvif/device_service` or \
`POST /` with a 200 back. What the call *did* is an element name inside the \
body, so a capture of a camera being reconfigured and one of a camera being \
polled for the time look identical until the envelope is opened.\n\n\
Two families dominate and the namespace tells them apart. **ONVIF** is IP \
cameras: SetSystemDateAndTime, CreateUsers and SetNetworkInterfaces are the \
calls that change a camera out from under whoever is recording from it. \
**TR-069** is how an ISP manages the router in a subscriber's house: Inform is \
the router checking in, while SetParameterValues and Download are the ACS \
changing configuration or pushing firmware. A Download nobody scheduled is \
worth knowing about.\n\n\
One detail decides whether the reading is right: the operation is the first \
element *inside* the Body element. Taking the first element in the document \
gives `Envelope` every time, and taking the first namespace-prefixed element \
usually gives whatever the SOAP header carries — a security token.",
            look_for: "The operation name: a Set… or Download that nobody scheduled, or a Fault carrying its own reason.",
        },
        Protocol::Bier => Lesson {
            title: "BIER — multicast that keeps no state anywhere",
            summary: "The delivery list travels inside the packet.",
            body: "Traditional multicast asks every router along the path to remember \
a tree per group, and that state is what breaks: it must be built before \
traffic flows, torn down afterwards, and when it goes stale nothing forwards. \
BIER removes it completely. The ingress router writes a bit string into the \
packet — one bit per egress router that should receive a copy — and each hop \
replicates towards whichever bits are still set. Nothing in the middle holds \
anything at all.\n\n\
So the bit string is the diagnosis, and it reads directly: the number of bits \
set is the number of destinations this particular copy is still headed for. A \
packet with fewer bits set than it had at the ingress has already been \
replicated and split, which is correct and expected. One whose bit string is \
empty should not be on the wire — there is nobody left to deliver it to. One \
that never loses bits along a path is being carried further than it needs to \
be.\n\n\
BIER has no EtherType. It rides beneath an MPLS label stack and is told apart \
from an ordinary labelled IP packet by a single nibble: 5, where 4 and 6 would \
mean IPv4 and IPv6. Read as IP by mistake, the bit string would be decoded as \
an IP header.",
            look_for: "An empty bit string, or one that never thins out along a path — the first should not exist, the second is wasted replication.",
        },
        Protocol::Srv6 => Lesson {
            title: "SRv6 — where the packet is actually headed",
            summary: "The itinerary is in the packet, not in the routers.",
            body: "Ordinary routing asks every hop to work out independently where a \
packet should go next. Segment routing puts that decision into the packet: the \
ingress node writes a list of segments — waypoints — into a Segment Routing \
Header, and each listed node forwards to the next. Nothing in between has to \
hold per-flow state, which is the entire point of the design.\n\n\
There is one detail that makes captures confusing until you know it. The \
segment list is stored backwards: Segment List[0] is the *final* waypoint, and \
Segments Left counts down as the packet is steered. So the waypoint being aimed \
at right now is the one at index Segments Left, not the one at the front.\n\n\
That counter is the useful reading. It says how far along its engineered path a \
packet has got. Seeing the same packet at two points with the same count means \
it went somewhere the policy did not intend. A count that never decreases means \
a segment is not being consumed — traffic looping through a waypoint instead of \
past it. Neither is visible from the addresses, because the outer destination is \
only ever the next waypoint rather than the real destination.",
            look_for: "The segment counter not decreasing between two capture points — a waypoint that is not consuming its segment.",
        },
        Protocol::Isns => Lesson {
            title: "iSNS — where storage goes when it disappears",
            summary: "The directory an iSCSI initiator uses to find its targets.",
            body: "An iSCSI initiator does not usually have its targets typed in by \
hand. It registers with an iSNS server, asks which targets it is permitted to \
see, and subscribes to notifications so it hears when one appears or goes away. \
Fibre Channel over IP uses the same directory.\n\n\
That makes iSNS the place where \"the storage disappeared\" is actually \
explained. When a LUN vanishes from a host, the cause is usually not the target \
at all — it is a query that came back empty, a registration that was allowed to \
expire, or an authorisation the server refused. At the initiator those produce \
one identical symptom: the volume is simply gone.\n\n\
Every response carries a status code and every response's function ID is the \
request's with the top bit set, so both the direction and the outcome are \
readable from a single packet without following the conversation.",
            look_for: "\"failed — source unauthorised\" or \"no such entry\" on a query, which puts the fault in the directory rather than the array.",
        },
        Protocol::Hip => Lesson {
            title: "HIP — when a connection never opens and nothing says why",
            summary: "A cryptographic identity for a host, separate from its address.",
            body: "An IP address does two jobs: it says who a host is and where it is. \
That double duty is why moving a laptop between networks breaks its \
connections. HIP splits them — a host gets a permanent cryptographic Host \
Identity, and its address becomes just a current location that can change \
underneath an established connection.\n\n\
Connections open with a four-packet base exchange: I1, R1, I2, R2. R1 hands the \
initiator a puzzle it must solve before the responder commits any state, which \
is what makes HIP resistant to connection floods — the expensive work happens \
on the side trying to connect.\n\n\
NOTIFY is the packet worth finding. When the base exchange fails it fails \
silently as far as the application is concerned: the connection just never \
establishes, with no error to report. NOTIFY is where the responder says which \
step rejected it — authentication failed, no acceptable Diffie-Hellman \
proposal, an HMAC that did not verify, or simply blocked by policy. Those have \
completely different fixes and are indistinguishable from anywhere else.",
            look_for: "\"HIP NOTIFY — ...\" carrying the reason, on a connection that appears to hang rather than fail.",
        },
        Protocol::Dvmrp => Lesson {
            title: "DVMRP — who decided nobody was watching",
            summary: "Flood the multicast everywhere, then wait to be told to stop.",
            body: "DVMRP was the first multicast routing protocol and its design is \
exactly that blunt: send the stream down every path, and let routers that have \
no interested receivers send a Prune back towards the source. When a listener \
appears again, a Graft restarts it. That is why DVMRP does not scale — and it \
is still what carries a great deal of campus and broadcast-plant multicast.\n\n\
Prune is the message worth finding. A multicast stream that stopped arriving \
has usually been pruned, and the prune identifies the router that concluded it \
had no listeners left. That separates \"the source stopped sending\" from \"a \
router upstream decided nobody was watching\" — two causes that look identical \
from the receiver's end.\n\n\
It rides inside IGMP rather than on a protocol number of its own, so a \
multicast *routing* message arrives looking like ordinary group membership \
until the type byte is read. The two versions also number their messages \
differently: code 2 is a Report in version 3 and a Request in version 1.",
            look_for: "\"Prune — a router downstream has no listeners left\" on the path towards a stream that stopped.",
        },
        Protocol::PnPtcp => Lesson {
            title: "PROFINET PTCP — the clock under the isochronous cycle",
            summary: "Sub-microsecond time sync, without which IRT stops working.",
            body: "PROFINET's fastest mode, IRT, does not transmit when a device is \
ready — it transmits on a schedule every device on the segment shares. That \
only works if they agree what time it is to within a fraction of a microsecond, \
and PTCP is how they agree.\n\n\
A sync master sends Announce frames carrying the time. Devices measure cable \
delay to their neighbours with Delay frames so they can correct for \
propagation, and FollowUp frames carry the precise send timestamp that could \
not be written into the Announce before it was already on the wire.\n\n\
The reason to watch it is that losing synchronisation does not present as a \
clock problem. It presents as IO data landing in the wrong cycle — intermittent \
process faults on devices that are each individually healthy — and eventually \
as a device dropping out of the IRT schedule altogether. The sync master's \
Announce frames stopping, or measured delays jumping, is the only place the \
actual cause is visible.\n\n\
One note on reading captures: FrameIDs 0xFF00-0xFF43 are all PTCP. netscope \
used to label that range \"RT Class 3 (isochronous)\", which was wrong — RT \
Class 3 uses the low FrameIDs, and this range is the clock underneath it.",
            look_for: "Announce frames from the sync master stopping, or Delay measurements that jump between frames.",
        },
        Protocol::Ripng => Lesson {
            title: "RIPng — reading a route being withdrawn",
            summary: "RIP for IPv6: a hop count, and sixteen means gone.",
            body: "RIPng keeps RIP's shape — periodic full-table announcements and a \
maximum diameter of fifteen hops — but shares almost none of RIPv2's wire \
format. There is no address family field and no per-route authentication; each \
route is a flat twenty-byte entry: an IPv6 prefix, its length, and a metric.\n\n\
The metric is the whole message. Sixteen means infinity — the sender is saying \
the destination is not reachable through it. That is how RIP withdraws a route, \
and it is what explains traffic that stopped without anything else changing. A \
burst of sixteens is a network reconverging; a steady state full of them is one \
that has partitioned and settled that way.\n\n\
The count-to-infinity problem that hop limit exists to bound is visible here \
too: a prefix whose metric rises by one in each successive announcement is a \
routing loop being slowly discovered, and it will keep climbing until it hits \
sixteen and the route finally disappears.",
            look_for: "\"metric 16\" — a withdrawal, and the reason a prefix stopped being reachable.",
        },
        Protocol::Mip6 => Lesson {
            title: "Mobile IPv6 — why the handset kept its address but lost its traffic",
            summary: "A node keeping one address as it moves between networks.",
            body: "A mobile node has one permanent home address regardless of which \
network it is attached to. When it moves it tells its home agent \"I am now \
reachable at this care-of address\", and the home agent tunnels its traffic \
there. Proxy Mobile IPv6 does the same thing on the node's behalf — that is how \
a mobile operator hands a subscriber between gateways without the handset \
taking part.\n\n\
The Binding Acknowledgement is where this becomes readable. One status byte \
says whether the registration was accepted and, if not, exactly why: \
administratively prohibited, not the home agent for this node, duplicate \
address detection failed, sequence number out of window. Those have entirely \
different causes and produce identical symptoms — a device that has a network \
connection and no working traffic, because packets are still being tunnelled to \
where it used to be.\n\n\
The split is easy to read: below 128 is an acceptance, 128 and above a refusal. \
A Binding Update with a lifetime of zero is not a registration at all — it is \
the node deregistering, which looks almost identical on the wire.",
            look_for: "\"refused: ...\" on a Binding Acknowledgement — the home agent's own reason, in one byte.",
        },
        Protocol::Amt => Lesson {
            title: "AMT — multicast smuggled through networks that block it",
            summary: "Multicast tunnelled inside ordinary unicast UDP.",
            body: "Most of the internet does not forward multicast. AMT gets it \
across anyway: a gateway near the receiver finds a relay near the source and \
tunnels the multicast inside plain unicast UDP. IPTV, market data feeds and \
multicast-based streaming all reach networks this way whose providers never \
enabled multicast routing.\n\n\
The setup is a fixed sequence, and where it stops is the diagnosis. A gateway \
sends Relay Discovery and expects an Advertisement. It then sends a Request and \
expects a Membership Query carrying a nonce. Only then can a Membership Update \
join a group and Multicast Data start flowing.\n\n\
That makes two very different failures easy to separate. Discovery with no \
Advertisement is a relay that is unreachable, or anycast-routed somewhere that \
no longer answers. Requests answered by Queries but no Multicast Data means the \
join succeeded and the source is simply not sending. Without seeing the tunnel \
itself those two are indistinguishable — both look like \"the stream does not \
work\".",
            look_for: "Where the sequence stops: Discovery with no Advertisement, or a completed join with no Multicast Data.",
        },
        Protocol::Prp => Lesson {
            title: "PRP — redundancy you cannot tell is gone",
            summary: "Every frame sent over two separate networks at once.",
            body: "HSR and PRP solve one problem from opposite ends. HSR sends a \
frame both ways round a single ring. PRP duplicates it onto two completely \
separate networks — LAN A and LAN B — and appends a six-byte trailer so the \
receiver can throw away whichever copy arrives second.\n\n\
That is also why PRP failures are invisible. Losing an entire LAN costs \
nothing: every frame still arrives over the other one, the application never \
notices, and the plant keeps running on redundancy that no longer exists. \
Nobody finds out until the second network fails too, and then everything stops \
at once.\n\n\
The trailer is the only place this shows. It names which LAN each copy \
crossed, so a capture carrying only LAN A is a network that is already down to \
one path. Supervision frames are the other half: nodes announce themselves \
periodically, so a node that stops appearing on one LAN has lost that path.",
            look_for: "\"PRP LAN A\" with no matching LAN B traffic — redundancy that is already gone while everything still works.",
        },
        Protocol::PnDcp => Lesson {
            title: "PROFINET DCP — the rename that stops a line",
            summary: "How a PROFINET device gets its name, and how it loses it.",
            body: "PROFINET does not address devices by IP but by name of station. \
An engineer assigns those names when commissioning a line, and the controller \
looks each one up to find the device it should be exchanging IO with. DCP does \
both jobs: Identify discovers devices, Set assigns names and addresses.\n\n\
The problem is that Set is unauthenticated and takes effect immediately. One \
Set can rename a device or change its IP, and the controller's very next \
cyclic exchange fails — the station it was configured for no longer answers to \
that name. The device is powered, the cable is fine, the switch reports no \
errors, and nothing in the IO traffic explains any of it. The Set that caused \
it appears exactly once, and the capture is usually the only record.\n\n\
Identify with the all-selector is the other thing to watch: it makes every \
device on the segment answer with its own name. That is how a line gets \
inventoried, and equally how it gets mapped by someone who should not be \
there.",
            look_for: "\"PROFINET DCP Set — name of station := ...\", especially one nobody scheduled.",
        },
        Protocol::Ecpri => Lesson {
            title: "eCPRI — when the radio says the data came too late",
            summary: "Fronthaul between a radio unit and its baseband.",
            body: "A modern base station is split: the radio unit sits at the top of \
the mast, the baseband unit at the bottom or in a datacentre. eCPRI is the link \
between them and it carries the sampled radio waveform itself.\n\n\
That makes it the most timing-sensitive traffic on any network carrying it. The \
radio must transmit on an exact symbol boundary, so IQ data arriving late is \
not delayed — it is useless, and gets dropped. Users see degraded coverage or \
dropped calls while every switch along the path reports healthy links and zero \
discards, because from the network's point of view nothing went wrong.\n\n\
The Event Indication message is where the radio finally says so. Its fault \
codes separate the possibilities precisely: data that arrived too early, too \
late, or that overran or starved the playout buffer. Those distinguish a \
fronthaul timing problem from a radio hardware fault, and nothing else in the \
capture does.",
            look_for: "\"userplane data received too late\" — a timing fault the switches on the path will all report as healthy.",
        },
        Protocol::Mrp => Lesson {
            title: "MRP — the ring that keeps a factory running",
            summary: "Industrial redundancy: one cut cable must not stop the line.",
            body: "Factory networks are wired as rings so a single cable fault does not \
halt production. A manager sits at the top of the ring, sends test frames both \
ways round, and keeps one port blocked so the ring is not a loop. When the tests \
stop arriving it opens that port and the network reconverges in tens of \
milliseconds — fast enough that the machines never notice.\n\n\
The reconvergence is what to look for. One topology change is a cable being \
replaced. A stream of them is a connection failing intermittently, and the \
machines on that ring will be dropping cycles without anything else in the \
capture saying so.",
            look_for: "\"MRP test — ring closed\" as the steady state; \"MRP topology change\" when something broke, especially repeatedly.",
        },
        Protocol::Hsr => Lesson {
            title: "HSR — sending everything twice so nothing is ever lost",
            summary: "Zero-recovery-time redundancy for substations and power grids.",
            body: "MRP heals a broken ring in tens of milliseconds. For a protection \
relay in an electrical substation that is far too slow, so HSR does not heal at \
all: every frame goes both ways round the ring simultaneously, and the receiver \
keeps whichever copy arrives first. A cut cable costs nothing, because the other \
copy was already in flight.\n\n\
Both copies carry the same sequence number in their tag — that is how the \
receiver spots the duplicate. It is also how you spot a ring that has already \
lost one path: you stop seeing pairs. HSR is designed to hide that from the \
application, so nothing else will tell you until the second path fails too.",
            look_for: "\"HSR path 0, seq 1234 · …\" and \"HSR path 1, seq 1234 · …\" as a pair; a capture with only one path is a ring already running on one leg.",
        },
        Protocol::Mvrp => Lesson {
            title: "MVRP — switches agreeing which VLANs to carry",
            summary: "Automatic VLAN registration, and a common cause of odd one-way faults.",
            body: "A switch does not need to carry a VLAN that nothing downstream is \
using. MVRP is how ports tell each other what they want, so VLANs propagate \
automatically instead of being configured on every trunk by hand.\n\n\
It is worth reading because the symptom of it going wrong is confusing: traffic \
works in one direction, or works until a link flaps and then does not. A Leave \
for a VLAN that should be there explains that immediately, where the switch \
configuration looks perfectly correct.",
            look_for: "\"MVRP JoinIn — VLAN 100\" as ports register; \"MVRP Leave — VLAN 100\" when one stops wanting it.",
        },
        Protocol::Mmrp => Lesson {
            title: "MMRP — registering multicast so it is not flooded everywhere",
            summary: "The multicast counterpart to MVRP, using the same encoding.",
            body: "Without registration, a switch floods multicast out of every port, \
which wastes capacity on every link that did not want it. MMRP lets ports say \
which groups and MAC addresses they actually need, so the switch can forward \
rather than flood. It shares MVRP's attribute encoding — the difference is what \
is being registered.",
            look_for: "\"MMRP JoinIn — MAC address …\" as a receiver subscribes to a group.",
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
        Protocol::MemcachedBin => Lesson {
            title: "Memcached (binary) — the same cache, a different protocol",
            summary: "What client libraries send, as opposed to the text form typed by hand.",
            body: "Memcached speaks two protocols on the same port. The text one is what \
you can type at a telnet prompt; the binary one is what real client libraries use, \
so it is what a production capture is full of. The reply carries a status code, \
which is where cache misses become visible — a capture that is mostly misses \
explains a slow application better than any latency graph.",
            look_for: "\"Memcached Get response — not found (cache miss)\" on TCP 11211.",
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
        Protocol::Profisafe => Lesson {
            title: "PROFIsafe — fail-safe communication over PROFINET",
            summary: "Safety profile (IEC 61784-3-3) for fail-safe PROFINET IO networks.",
            body: "PROFIsafe is a safety protocol designed for functional safety up to SIL3/PLe. \
It runs as a safety profile on top of standard PROFINET IO (or PROFIBUS) using the 'Black Channel' \
principle, meaning the underlying network hardware does not need safety certification.\n\n\
A PROFIsafe PDU (Safety Protocol Data Unit) consists of application safety data, a status/control byte, \
and a 3-byte or 4-byte CRC. In a cyclic capture, it is carried inside the PROFINET RT payload.",
            look_for: "PROFINET IO Real-Time cyclic frames carrying safety-instrumented device values.",
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
        Protocol::S7commPlus => Lesson {
            title: "S7comm-plus — newer Siemens PLC protocol",
            summary: "Siemens S7-1200/1500 communication protocol carried on TCP 102.",
            body: "S7comm-plus is Siemens' modern proprietary industrial protocol for S7-1200 and \
S7-1500 controllers. It is carried over TPKT/COTP (TCP 102) and uses Protocol ID 0x72.\n\n\
Unlike legacy S7comm, it features cryptographic protection for integrity and session anti-replay \
to secure PLC communications against modification and injection.",
            look_for: "Packets on TCP 102 carrying S7comm-plus header markers (protocol ID 0x72) and safety/configuration commands.",
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
        Protocol::SomeIpSd => Lesson {
            title: "SOME/IP-SD — how a car's ECUs find each other",
            summary: "The offers and subscriptions that have to happen before any call can.",
            body: "Before one ECU can call another, the provider has to announce its \
service and the consumer has to subscribe. That negotiation is SOME/IP-SD, and it \
is where the interesting failures live: a feature that 'doesn't work' usually means \
the offer never arrived or the subscription was refused — and neither shows up in \
the calls themselves, because there aren't any.\n\n\
Watch the time-to-live rather than just the message name. An OfferService with a \
TTL of zero is not an offer, it is the withdrawal of one: an ECU announcing it is \
going away. A subscribe with TTL zero is an unsubscribe, and an acknowledgement \
with TTL zero is a refusal. Reading the type without the TTL tells you the \
opposite of what happened.",
            look_for: "\"SOME/IP-SD offering service 0x1234\" normally; \"withdrawing\" or \"refused subscription to\" when something has gone wrong.",
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
        Protocol::Uds => Lesson {
            title: "UDS — what the diagnostic tool actually said",
            summary: "The command inside a DoIP message: read a code, unlock an ECU, flash firmware.",
            body: "DoIP is the envelope; UDS is the letter. A capture full of \
'diagnostic message' has told you nothing, because every interesting difference is \
one byte further in.\n\n\
Two exchanges are worth knowing on sight. SecurityAccess is an ECU being unlocked — \
the tool asks for a seed, sends back a computed key, and the ECU either accepts it \
or refuses with 'invalid key' or 'too many failed attempts'. RequestDownload \
followed by TransferData is firmware being written to an ECU, which is the most \
consequential thing that can happen on a vehicle network.",
            look_for: "\"UDS read fault codes\" for routine work; \"UDS security access — seed request\" and \"UDS download to ECU requested\" when something is being changed.",
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
        Protocol::Cldap => Lesson {
            title: "CLDAP — finding a domain controller",
            summary: "Connectionless LDAP, used by Windows to locate the nearest DC.",
            body: "Before a Windows machine can log you in it must find a domain \
controller. It asks over CLDAP — LDAP in a single UDP round trip. Because a tiny \
query gets a large reply, exposed CLDAP servers are also abused for DDoS \
amplification, so seeing it from the internet is a red flag.",
            look_for: "\"CLDAP searchRequest\" on UDP 389.",
        },
        Protocol::Bmp => Lesson {
            title: "BMP — watching BGP from the outside",
            summary: "A router streaming its BGP tables and peer events to a collector.",
            body: "Rather than logging into routers to inspect BGP, operators have them \
push their view out: BMP streams route updates, peer up/down events and \
statistics to a monitoring system. It's how you see route hijacks and flapping \
across a whole network.",
            look_for: "\"BMP Route Monitoring\" / \"BMP Peer Up\" on TCP 11019.",
        },
        Protocol::RpkiRtr => Lesson {
            title: "RPKI-RTR — checking BGP routes are legitimate",
            summary: "Feeds a router the cryptographically validated list of who may announce what.",
            body: "BGP has no built-in way to know whether a network is allowed to \
announce a prefix — the root of route hijacking. RPKI publishes signed \
authorisations, and RPKI-RTR is how a router pulls that validated data from a \
local cache so it can drop invalid announcements.",
            look_for: "\"RPKI-RTR Cache Response\" / \"IPv4 Prefix\" on TCP 323.",
        },
        Protocol::Mms => Lesson {
            title: "MMS — reading a substation's data model",
            summary: "The client/server half of IEC 61850, alongside GOOSE and Sampled Values.",
            body: "Where GOOSE carries urgent trip signals, MMS is the conversational \
side of a substation: a control system browsing a device's data model, reading \
measurements, receiving reports and issuing controls. It shares port 102 with \
Siemens S7comm, so netscope tells them apart by the framing.",
            look_for: "\"MMS — session CONNECT\" / \"data transfer\" on TCP 102.",
        },
        Protocol::Nrpe => Lesson {
            title: "NRPE — running a Nagios check remotely",
            summary: "A monitoring server asking a host to execute a health check.",
            body: "Nagios-style monitoring often needs data only the host itself can see \
— disk space, process counts. NRPE is the agent that runs those check scripts on \
request and returns the status. Historically it has had command-injection issues, \
so it's worth knowing where it's exposed.",
            look_for: "\"NRPE v2 query\" / \"response\" on TCP 5666.",
        },
        Protocol::Collectd => Lesson {
            title: "collectd — system metrics on the wire",
            summary: "A daemon shipping CPU, memory, disk and network statistics.",
            body: "collectd gathers system statistics and sends them to a central server \
in a compact binary format made of typed parts (host, time, plugin, values). \
Unauthenticated and UDP-based, it has also been used for amplification attacks \
when left open.",
            look_for: "\"collectd — values part\" on UDP 25826.",
        },
        Protocol::Jaeger => Lesson {
            title: "Jaeger — distributed tracing",
            summary: "Services reporting timing spans so a request can be followed across them.",
            body: "When one user request fans out across a dozen microservices, tracing \
is how you find where the time went. Instrumented services emit spans to a local \
Jaeger agent over UDP, encoded with Thrift; the agent forwards them to a collector \
that stitches the trace together.",
            look_for: "\"Jaeger spans (Thrift compact)\" on UDP 6831.",
        },
        Protocol::Ganglia => Lesson {
            title: "Ganglia — cluster monitoring",
            summary: "Nodes multicasting their metrics across an HPC or compute cluster.",
            body: "Ganglia was built for large clusters: each node's gmond announces its \
metrics, and every node can hear them, so the cluster's state is visible without a \
central poller. Values are XDR-encoded, with metadata packets describing each \
metric.",
            look_for: "\"Ganglia gmond — metric metadata\" on UDP 8649.",
        },
        Protocol::Bolt => Lesson {
            title: "Bolt — talking to Neo4j",
            summary: "The binary protocol carrying Cypher graph queries.",
            body: "Bolt is Neo4j's client protocol: a connection opens with a magic \
preamble and version negotiation, then carries Cypher queries and streamed result \
records in a compact binary packing. Seeing it means an application is querying a \
graph database.",
            look_for: "\"Bolt handshake (offering v5.1)\" on TCP 7687.",
        },
        Protocol::Clickhouse => Lesson {
            title: "ClickHouse — columnar analytics",
            summary: "The native protocol of a very fast analytical database.",
            body: "ClickHouse answers analytical queries over huge tables by storing data \
in columns. Its native protocol (faster than the HTTP interface) opens with a \
Hello naming the client, then ships queries and columnar result blocks.",
            look_for: "\"ClickHouse handshake (Hello)\" on TCP 9000.",
        },
        Protocol::Pulsar => Lesson {
            title: "Apache Pulsar — messaging with tiered storage",
            summary: "A distributed pub/sub system that separates serving from storage.",
            body: "Pulsar is a messaging platform in Kafka's space, but it splits brokers \
from the storage layer so it can scale and offload older data. Its binary protocol \
frames a protobuf command, optionally followed by the message payload.",
            look_for: "\"Pulsar command\" on TCP 6650.",
        },
        Protocol::Openwire => Lesson {
            title: "OpenWire — Apache ActiveMQ's native protocol",
            summary: "The binary wire format ActiveMQ clients and brokers use.",
            body: "ActiveMQ speaks several protocols; OpenWire is its native, most \
efficient one. A connection opens with a WireFormatInfo negotiation, then carries \
broker/connection/consumer info and the messages themselves. A deserialisation \
flaw in it caused a well-known critical CVE, so its exposure matters.",
            look_for: "\"OpenWire WireFormatInfo\" / \"ActiveMQMessage\" on TCP 61616.",
        },
        Protocol::Zookeeper => Lesson {
            title: "ZooKeeper — keeping a cluster in agreement",
            summary: "The coordination service behind Kafka, HBase and many clusters.",
            body: "Distributed systems need somewhere to agree on who is the leader, what \
the config is and which nodes are alive. ZooKeeper is that shared source of \
truth, exposing a small filesystem-like tree of znodes with watches. If it's \
struggling, the systems on top of it struggle too.",
            look_for: "\"ZooKeeper getData\" / \"ZooKeeper ping\" on TCP 2181.",
        },
        Protocol::HadoopRpc => Lesson {
            title: "Hadoop RPC — talking to HDFS",
            summary: "The call protocol between clients and the HDFS NameNode.",
            body: "Reading a file from HDFS starts with asking the NameNode where its \
blocks live. That conversation is Hadoop RPC, which opens with an \"hrpc\" magic \
and a version, then carries protobuf-encoded calls.",
            look_for: "\"Hadoop RPC handshake (v9)\" on TCP 8020.",
        },
        Protocol::Fluentd => Lesson {
            title: "Fluentd — collecting logs",
            summary: "Agents forwarding structured log events to a collector.",
            body: "Fluentd unifies logging: agents on each host tag events and forward \
them, MessagePack-encoded, to aggregators that route them onward to storage or \
search. Seeing this is your logging pipeline at work.",
            look_for: "\"Fluentd forward (3 fields, msgpack)\" on TCP 24224.",
        },
        Protocol::Beats => Lesson {
            title: "Elastic Beats — shipping logs to Logstash",
            summary: "Filebeat and friends sending events into the Elastic stack.",
            body: "Beats are lightweight shippers that tail logs or collect metrics and \
send them to Logstash or Elasticsearch. The protocol batches events in windows \
and waits for acknowledgements, so nothing is lost if the far end is slow.",
            look_for: "\"Beats v2 JSON event\" / \"window size\" on TCP 5044.",
        },
        Protocol::Clamav => Lesson {
            title: "ClamAV — scanning content for malware",
            summary: "A mail or file gateway handing data to the clamd daemon.",
            body: "Rather than every application embedding a scanner, they stream content \
to clamd and get a verdict back. A reply ending in FOUND means a signature \
matched — worth noticing in a capture, because it means something malicious was \
in the traffic.",
            look_for: "\"ClamAV INSTREAM\", or a reply containing FOUND, on TCP 3310.",
        },
        Protocol::Spamd => Lesson {
            title: "spamd — scoring mail for spam",
            summary: "A mail server asking SpamAssassin to judge a message.",
            body: "When mail arrives, the server can hand it to spamd, which applies \
rules and returns a spam score and symbols. The client speaks SPAMC and the \
daemon answers SPAMD, with the message body in between.",
            look_for: "\"spamd CHECK request\" on TCP 783.",
        },
        Protocol::ManageSieve => Lesson {
            title: "ManageSieve — server-side mail rules",
            summary: "A mail client uploading the filters that sort your inbox.",
            body: "Sieve scripts move, file and reject mail on the server, so the rules \
apply even when your client is closed. ManageSieve is the small text protocol a \
client uses to list, upload and activate those scripts.",
            look_for: "\"ManageSieve PUTSCRIPT\" on TCP 4190.",
        },
        Protocol::Relp => Lesson {
            title: "RELP — syslog that doesn't lose messages",
            summary: "rsyslog's acknowledged transport for reliable log delivery.",
            body: "Plain syslog over UDP silently drops messages under load — bad when \
the logs are evidence. RELP adds transaction numbers and acknowledgements over \
TCP, so the sender knows a message was accepted and can retry if not.",
            look_for: "\"RELP syslog message (txn 3)\" on TCP 2514.",
        },
        Protocol::Lpd => Lesson {
            title: "LPD — the classic print protocol",
            summary: "Sending a job to a print queue, Unix-style.",
            body: "LPD is the long-standing line-printer protocol still spoken by many \
network printers and print servers: a one-byte command selects the action (send a \
job, query the queue, remove jobs) and names the queue. No authentication or \
encryption.",
            look_for: "\"LPD — receive a printer job on lp\" on TCP 515.",
        },
        Protocol::Ident => Lesson {
            title: "Ident — who owns this connection?",
            summary: "A legacy service naming the local user behind a TCP connection.",
            body: "Ident lets a remote server ask your machine which user account opened \
a connection — historically used by IRC servers and mail relays. Since it hands \
out local usernames on request and is trivially spoofed, it's usually disabled \
now, so seeing it is unusual.",
            look_for: "\"Ident query — ports 6193, 23\" on TCP 113.",
        },
        Protocol::Gopher => Lesson {
            title: "Gopher — the web before the web",
            summary: "A menu-driven document protocol that predates HTTP.",
            body: "Gopher serves documents through nested menus: the client sends a \
selector string and gets back either a document or a tab-separated menu where each \
line's first character says what type the item is. Largely historical, with a \
small enthusiast revival.",
            look_for: "\"Gopher — root menu request\" on TCP 70.",
        },
        Protocol::Rsh => Lesson {
            title: "rsh — an obsolete remote shell",
            summary: "Runs a command on another machine, entirely in the clear.",
            body: "rsh executes a command on a remote host, trusting the client purely by \
hostname and a local user list. The username and the command — and anything it \
prints — cross the network unencrypted. SSH replaced it decades ago, so rsh \
traffic today is a genuine finding.",
            look_for: "\"rsh — alice runs \\\"cat /etc/passwd\\\"\" on TCP 514.",
        },
        Protocol::Cdp => Lesson {
            title: "CDP — Cisco's neighbour discovery",
            summary: "Switches and phones announcing their identity to the device next door.",
            body: "CDP lets a Cisco device tell its direct neighbour who it is: hostname, \
port, model and software version. Great for mapping a network — and equally useful \
to an attacker who plugs in, which is why it's often disabled on user-facing ports.",
            look_for: "\"CDP — sw-core port Gi0/1\" (LLC/SNAP, Cisco OUI).",
        },
        Protocol::Vtp => Lesson {
            title: "VTP — syncing the VLAN list",
            summary: "Propagates the VLAN database from one switch to the rest.",
            body: "Rather than defining VLANs on every switch, VTP has a server push the \
list to the others. Convenient, but famously dangerous: a switch joining with a \
higher revision number can wipe the whole domain's VLANs.",
            look_for: "\"VTP Summary Advertisement\" (LLC/SNAP, Cisco OUI).",
        },
        Protocol::Dtp => Lesson {
            title: "DTP — negotiating a trunk",
            summary: "Two switch ports agreeing to carry every VLAN instead of one.",
            body: "DTP decides automatically whether a link becomes a trunk. Left enabled \
on a port a user can reach, an attacker's device can negotiate a trunk and see \
every VLAN — the classic VLAN-hopping attack. DTP on an access port is a finding.",
            look_for: "\"DTP v1 — trunk negotiation\" (LLC/SNAP, Cisco OUI).",
        },
        Protocol::Pagp => Lesson {
            title: "PAgP — bundling links, Cisco-style",
            summary: "Cisco's proprietary alternative to LACP for building an EtherChannel.",
            body: "To gain bandwidth and redundancy, several physical links are bundled \
into one logical channel. PAgP negotiates that bundle between Cisco devices; LACP \
is the vendor-neutral standard doing the same job.",
            look_for: "\"PAgP v1 — EtherChannel negotiation\" (LLC/SNAP, Cisco OUI).",
        },
        Protocol::Udld => Lesson {
            title: "UDLD — catching a one-way link",
            summary: "Detects fibre links that carry traffic in only one direction.",
            body: "A fibre pair can fail so traffic flows one way but not the other. \
Spanning tree then makes bad decisions and can create a loop. UDLD sends probes and \
expects to see itself echoed back; when it doesn't, it shuts the port down.",
            look_for: "\"UDLD probe\" / \"UDLD echo\" (LLC/SNAP, Cisco OUI).",
        },
        Protocol::Eap => Lesson {
            title: "EAP — how you prove who you are",
            summary: "The authentication method negotiated inside 802.1X and enterprise Wi-Fi.",
            body: "802.1X decides whether a device may join the network; EAP is the \
conversation that actually proves identity — and it comes in flavours. PEAP and \
TTLS wrap a password inside TLS, EAP-TLS uses a client certificate, and the ancient \
MD5-Challenge is trivially broken. Which method you see tells you how strong the \
authentication really is.",
            look_for: "\"EAP Response — PEAP\" / \"EAP Success\" inside EAPOL.",
        },
        Protocol::Ipx => Lesson {
            title: "IPX — Novell NetWare's network layer",
            summary: "The protocol that ran most office LANs before TCP/IP won.",
            body: "Through the late 80s and 90s, NetWare file and print servers spoke IPX \
rather than IP, with SAP broadcasting available services and NCP carrying file \
access. Essentially extinct now, so IPX on a modern network means very old kit — or \
something odd.",
            look_for: "\"IPX SAP (service advertisement)\" (EtherType 0x8137).",
        },
        Protocol::Atalk => Lesson {
            title: "AppleTalk — classic Mac networking",
            summary: "Apple's pre-TCP/IP stack for file and printer sharing.",
            body: "AppleTalk let Macs find each other and share printers with zero \
configuration long before Bonjour, using zones and name binding instead of IP \
addresses. Apple dropped it in Mac OS X 10.6, so it's now purely historical.",
            look_for: "\"AppleTalk DDP — NBP (name binding)\" (EtherType 0x809B).",
        },
        Protocol::Aarp => Lesson {
            title: "AARP — AppleTalk's address resolution",
            summary: "The AppleTalk equivalent of ARP, mapping addresses to hardware.",
            body: "Just as ARP maps an IP address to a MAC address, AARP maps an AppleTalk \
node address to one. It also carries the probe a Mac sends when picking an address, \
to check nobody else already has it.",
            look_for: "\"AARP Probe\" / \"AARP Request\" (EtherType 0x80F3).",
        },
        Protocol::Ipp => Lesson {
            title: "IPP — how modern printing works",
            summary: "The protocol behind CUPS, AirPrint and network printers.",
            body: "IPP carries print jobs and printer queries over HTTP: the client POSTs \
an operation like Print-Job or Get-Printer-Attributes and the printer answers. It's \
what your laptop uses when a printer just appears and works.",
            look_for: "\"IPP 2.0 Print-Job\" on TCP 631.",
        },
        Protocol::Rexec => Lesson {
            title: "rexec — remote execution with a cleartext password",
            summary: "Runs a command on another host, sending the password in the clear.",
            body: "rexec is rsh's authenticating sibling: it asks for a username and \
password before running the command — but sends that password unencrypted, so anyone \
capturing the traffic gets working credentials. If you see rexec, treat the password \
as compromised.",
            look_for: "\"rexec — alice runs … (cleartext password)\" on TCP 512.",
        },
        Protocol::Sane => Lesson {
            title: "SANE — sharing a scanner",
            summary: "Lets one machine use a scanner attached to another.",
            body: "SANE is the Unix scanner stack; its network side (saned) exposes a \
scanner so other hosts can list devices, set options and pull images. It's \
unauthenticated by default, so it belongs on a trusted network only.",
            look_for: "\"SANE GET_DEVICES\" / \"SANE START\" on TCP 6566.",
        },
        Protocol::Tns => Lesson {
            title: "Oracle TNS — reaching an Oracle database",
            summary: "The transport every Oracle client uses to talk to the listener.",
            body: "Before any SQL flows, an Oracle client connects to the listener over \
TNS, which negotiates the session and routes it to a database instance. Almost all \
Oracle traffic you'll see rides inside TNS Data packets.",
            look_for: "\"Oracle TNS Connect\" / \"Oracle TNS Data\" on TCP 1521.",
        },
        Protocol::Drda => Lesson {
            title: "DRDA — IBM Db2's database protocol",
            summary: "How Db2 clients send SQL and receive result sets.",
            body: "DRDA is IBM's standard for distributed database access, used by Db2. \
Its messages are DDM objects identified by code points — EXCSAT to introduce the \
client, ACCRDB to open a database, SQLSTT to carry a statement.",
            look_for: "\"DRDA EXCSAT\" / \"DRDA SQLSTT\" on TCP 50000.",
        },
        Protocol::Firebird => Lesson {
            title: "Firebird — an open-source SQL database",
            summary: "The wire protocol of Firebird and its InterBase ancestor.",
            body: "Firebird is a lightweight relational database descended from Borland \
InterBase, still embedded in plenty of business software. Its protocol is a simple \
sequence of numbered operations: connect, attach, compile a statement, fetch rows.",
            look_for: "\"Firebird attach\" / \"Firebird fetch\" on TCP 3050.",
        },
        Protocol::MysqlX => Lesson {
            title: "MySQL X — the document-store protocol",
            summary: "MySQL's newer protobuf-based protocol, separate from the classic one.",
            body: "Alongside the classic protocol on 3306, MySQL speaks X Protocol on \
33060 for the X DevAPI and its document store — CRUD operations on JSON documents \
as well as SQL, encoded with protocol buffers.",
            look_for: "\"MySQL X StmtExecute\" / \"CrudFind\" on TCP 33060.",
        },
        Protocol::Riak => Lesson {
            title: "Riak — a distributed key-value store",
            summary: "A highly available database designed to survive node failure.",
            body: "Riak spreads data across a cluster so it keeps serving even when nodes \
drop out. Its protocol-buffers interface is the efficient way clients read and write \
keys, each frame a length followed by a message code.",
            look_for: "\"Riak Put request\" / \"Get response\" on TCP 8087.",
        },
        Protocol::Nmea => Lesson {
            title: "NMEA 0183 — GPS and marine sentences",
            summary: "The text format navigation instruments use to report position.",
            body: "A GPS receiver emits a steady stream of comma-separated sentences: GGA \
carries a position fix, RMC the recommended minimum data, GSV the satellites in \
view. Marine networks carry vessel AIS reports the same way, which is how ship \
tracking works.",
            look_for: "\"NMEA GPGGA — position fix\" on TCP 10110.",
        },
        Protocol::Adsb => Lesson {
            title: "ADS-B — aircraft broadcasting their position",
            summary: "Planes reporting identity, altitude and position; Beast is the feed format.",
            body: "Modern aircraft continuously broadcast where they are. A receiver \
(dump1090 and similar) decodes those transponder messages and republishes them in \
the Beast binary format — which is what flight-tracking sites are built on.",
            look_for: "\"ADS-B Beast — Mode S long (ADS-B)\" on TCP 30005.",
        },
        Protocol::Aprs => Lesson {
            title: "APRS — amateur radio's position network",
            summary: "Ham operators sharing position, weather and telemetry beacons.",
            body: "APRS started on radio and gained an internet backbone, APRS-IS, which \
relays those beacons worldwide as text. Each packet names the sending callsign and \
a path, followed by position or telemetry data.",
            look_for: "\"APRS-IS packet from TA1ABC\" on TCP 14580.",
        },
        Protocol::Turn => Lesson {
            title: "TURN — relaying a call that can't connect directly",
            summary: "When NAT defeats a direct path, media is bounced through a relay.",
            body: "STUN tries to find a direct path between two peers. When it can't — \
symmetric NAT, restrictive firewalls — TURN gives up on directness and relays the \
media through a server instead. It costs bandwidth, so a call falling back to TURN \
often explains poor quality or high server load.",
            look_for: "\"TURN relayed data — channel 0x4001\" alongside STUN.",
        },
        Protocol::Decnet => Lesson {
            title: "DECnet — Digital's networking stack",
            summary: "The protocol suite of DEC's VAX/VMS systems, from before TCP/IP won.",
            body: "DECnet connected the VAX and PDP machines that ran much of research and \
industry in the 70s and 80s, with its own routing and node addressing. It survives \
only in museums and a few very long-lived industrial systems.",
            look_for: "\"DECnet Phase IV — endnode hello\" (EtherType 0x6003).",
        },
        Protocol::Vines => Lesson {
            title: "Banyan VINES — an early network OS",
            summary: "A Unix-based server platform that competed with NetWare.",
            body: "VINES offered file, print and directory services across wide-area \
networks, and was notable for StreetTalk, a global directory ahead of its time. The \
company folded in the 90s, so VINES traffic today means genuinely ancient equipment.",
            look_for: "\"Banyan VINES — RTP (routing)\" (EtherType 0x0BAD).",
        },
        Protocol::Erspan => Lesson {
            title: "ERSPAN — mirrored traffic sent across the network",
            summary: "A switch copying traffic and tunnelling it to a remote analyser.",
            body: "Port mirroring normally feeds a monitor plugged into the same switch. \
ERSPAN wraps those copies in GRE so they can travel to an analyser anywhere on the \
network. That means the payload is *someone else's* traffic, deliberately \
duplicated — useful to know, both for capacity and for who is watching what.",
            look_for: "\"ERSPAN v1 — mirrored traffic, session 5\" inside GRE.",
        },
        Protocol::Ppp => Lesson {
            title: "PPP — the link inside your broadband session",
            summary: "Carries IP over a point-to-point link and negotiates the connection.",
            body: "Inside a PPPoE broadband session, PPP is what actually runs: LCP brings \
the link up, an authentication protocol proves who you are, IPCP assigns your IP \
address, and then your traffic flows. Each of those is a different PPP protocol \
number.",
            look_for: "\"PPP — LCP (link control)\" / \"IPCP\" inside a PPPoE session.",
        },
        Protocol::Pap => Lesson {
            title: "PAP — a password sent in the clear",
            summary: "PPP authentication that transmits the username and password unencrypted.",
            body: "PAP proves who you are by simply sending your credentials. Anyone who \
captures the exchange has them. It survives because it's simple and some ISPs still \
accept it, but CHAP or EAP should be used instead — and a PAP login in a capture \
should be treated as a leaked password.",
            look_for: "\"PAP Authenticate-Request — user … (cleartext password)\".",
        },
        Protocol::Chap => Lesson {
            title: "CHAP — proving a secret without sending it",
            summary: "PPP authentication by hashed challenge, so the password never crosses the wire.",
            body: "Instead of transmitting the password, CHAP has the server send a random \
challenge; the client replies with a hash of the challenge plus the shared secret. \
An eavesdropper learns neither the secret nor anything reusable. A clear improvement \
on PAP.",
            look_for: "\"CHAP Challenge from gateway\" then \"CHAP Response\".",
        },
        Protocol::L2cap => Lesson {
            title: "L2CAP — Bluetooth's multiplexer",
            summary: "Splits a Bluetooth connection into channels for the layers above.",
            body: "Every Bluetooth connection carries several conversations at once — \
attribute reads, pairing, audio control. L2CAP is the layer that keeps them apart, \
tagging each with a channel id. Fixed ids mark the important ones: 0x0004 is ATT, \
0x0006 is pairing.",
            look_for: "\"L2CAP signalling (CID 0x0001)\" inside HCI ACL data.",
        },
        Protocol::Att => Lesson {
            title: "ATT — where BLE data actually flows",
            summary: "Reading and writing the characteristics a Bluetooth LE device exposes.",
            body: "A BLE device presents its data as a table of attributes: a heart rate, \
a battery level, a lock state. ATT is how a phone reads them, writes them, or \
subscribes to notifications. If you want to know what a BLE gadget is really doing, \
this is the layer to read.",
            look_for: "\"ATT Handle Value Notification — handle 0x002a\".",
        },
        Protocol::Smp => Lesson {
            title: "SMP — pairing two Bluetooth devices",
            summary: "Negotiates how a BLE link is secured, and exchanges the keys.",
            body: "Pairing is where BLE security is decided: the two devices agree on \
what protection they can manage given their input and output capabilities. Weak \
options like \"Just Works\" pair without any user confirmation and can be \
intercepted, so the pairing exchange tells you how trustworthy the link is.",
            look_for: "\"SMP Pairing Request (BLE pairing)\" on L2CAP CID 0x0006.",
        },
        Protocol::NvmeOf => Lesson {
            title: "NVMe/TCP — fast flash over the network",
            summary: "Puts NVMe SSDs on the network with far less overhead than iSCSI.",
            body: "NVMe was designed for flash, not spinning disks, and NVMe over Fabrics \
extends it across a network so servers can use remote SSDs at close to local speed. \
The TCP transport needs no special hardware, which is why it's displacing iSCSI in \
new deployments.",
            look_for: "\"NVMe/TCP Command Capsule\" on TCP 4420.",
        },
        Protocol::Nbd => Lesson {
            title: "NBD — a remote disk as a local device",
            summary: "Exports a raw block device over the network.",
            body: "Network Block Device hands a client a remote disk that behaves like a \
local one — read and write blocks, put any filesystem on it. It's widely used to \
back virtual-machine disks. Plain NBD has no authentication, so it's meant for a \
trusted network or a tunnel.",
            look_for: "\"NBD write request\" on TCP 10809.",
        },
        Protocol::Fcip => Lesson {
            title: "FCIP — stretching a SAN across a WAN",
            summary: "Tunnels Fibre Channel storage traffic between two sites over IP.",
            body: "Fibre Channel doesn't route across the internet, but replicating \
storage between data centres requires exactly that. FCIP wraps FC frames in TCP so \
two SANs can be joined over a wide-area link, typically for disaster-recovery \
replication.",
            look_for: "\"FCIP — Fibre Channel frame over IP\" on TCP 3225.",
        },
        Protocol::Aoe => Lesson {
            title: "AoE — a disk straight onto the LAN",
            summary: "ATA over Ethernet: storage with no IP layer at all.",
            body: "AoE puts disk commands directly in Ethernet frames — no TCP, no IP, \
almost no overhead. That makes it fast and very simple, but also unroutable and \
unauthenticated: anything on the same LAN segment can reach the disk. Strictly a \
trusted-network technology.",
            look_for: "\"AoE ATA command — shelf 1, slot 0\" (EtherType 0x88A2).",
        },
        Protocol::Roce => Lesson {
            title: "RoCE — reading another machine's memory",
            summary: "RDMA over Ethernet, bypassing the kernel for very low latency.",
            body: "RDMA lets one machine write directly into another's memory without \
either CPU handling the transfer, which is why HPC clusters and high-end storage \
use it. RoCE carries InfiniBand's transport over ordinary Ethernet — fast, but it \
depends on a lossless, carefully tuned network.",
            look_for: "\"RoCE — InfiniBand RDMA READ Request\" (EtherType 0x8915).",
        },
        Protocol::Xdmcp => Lesson {
            title: "XDMCP — logging in to a remote X session",
            summary: "Lets a thin X terminal ask a server for a graphical login.",
            body: "XDMCP is how an X terminal finds a host willing to give it a desktop \
session: it queries, a display manager answers Willing, and a session is negotiated. \
It's unencrypted and long superseded by SSH X-forwarding, so it mostly appears on \
legacy Unix networks.",
            look_for: "\"XDMCP Query\" / \"XDMCP Willing\" on UDP 177.",
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
        Protocol::J1939 => Lesson {
            title: "J1939 — the language trucks speak over CAN",
            summary: "Turns a 29-bit CAN identifier into a message name and a sender.",
            body: "Plain CAN gives you an identifier and eight bytes. J1939, which \
every heavy truck, bus and agricultural machine runs, divides that identifier \
into a priority, a parameter group number naming the message, and the address \
of the ECU that sent it. So a frame stops being hex and becomes 'engine \
temperature, from the engine'. The one to look for is DM1 — the check-engine \
light itself, carrying the code for every fault currently active.\n\n\
Not every 29-bit frame is J1939, so netscope only claims one whose parameter \
group the standard actually defines; anything else stays a plain CAN frame.",
            look_for: "\"J1939 engine speed (from engine)\"; and \"J1939 DM1 — fault lamp lit, SPN 100 FMI 1\" when something is wrong.",
        },
        Protocol::DeviceNet => Lesson {
            title: "DeviceNet — industrial automation over CAN",
            summary: "Decodes 11-bit CAN identifiers into DeviceNet message groups and MAC IDs.",
            body: "DeviceNet runs the Common Industrial Protocol (CIP) on top of standard \
11-bit CAN. Every frame is classified into one of four message groups depending on \
its identifier range, and contains the sender's MAC ID (node address). This lets \
netscope tell you what type of message is being sent (e.g. Master's I/O Poll Command \
or Slave's Explicit Response) and which node it belongs to, separating control traffic \
from configuration changes.",
            look_for: "\"DeviceNet Explicit Request node 5\" or \"DeviceNet I/O Poll Response from node 7\" with its raw hex data.",
        },
        Protocol::J1708 => Lesson {
            title: "J1708 — the legacy truck serial bus",
            summary: "Heavy vehicle diagnostics over RS-485 serial, identified by checksum.",
            body: "Before CAN and J1939, heavy vehicles used J1708 — a 9600 baud serial bus \
built on RS-485. Gateways bridge this serial traffic onto IP networks. J1708 frames \
use a two's-complement checksum where the sum of all bytes in the frame is zero. The \
first byte is the Message ID (MID) which identifies the subsystem (e.g. Engine, Brakes, \
or Transmission) that spoke.",
            look_for: "\"J1708 Engine (MID 0x80) PID 0x5C\" or \"J1708 Transmission (MID 0x88) PID 0x61\".",
        },
        Protocol::Obd2 => Lesson {
            title: "OBD-II — what the garage's scan tool asks your car",
            summary: "Diagnostic requests and replies, decoded into real units.",
            body: "Every car since the mid-90s has a diagnostic port, and what comes \
out of it is OBD-II over CAN. It is the rare CAN protocol you can identify with \
certainty, because the standard reserves the identifiers: 0x7DF asks whichever \
ECU can answer, 0x7E0-0x7E7 ask one directly, and 0x7E8-0x7EF are the replies. \
The encodings are fixed too, so netscope converts them into the numbers a \
mechanic reads — engine speed in rpm, coolant in degrees — rather than leaving \
two bytes of hex.",
            look_for: "\"OBD-II request engine speed\" then \"OBD-II engine speed — 750 rpm\"; \"OBD-II stored fault codes\" when reading why the light is on.",
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
        Protocol::Amqp1 => Lesson {
            title: "AMQP 1.0 — a different protocol with the same name",
            summary: "The OASIS standard behind Azure Service Bus and Qpid, sharing port 5672.",
            body: "AMQP 1.0 and AMQP 0-9-1 are related only by name; they are separate \
protocols that happen to share a port. 0-9-1 is what RabbitMQ speaks natively, while \
1.0 is the ISO standard used by Azure Service Bus, Qpid and ActiveMQ Artemis. Each \
frame carries a 'performative' — the verb — and the useful distinction is between \
'transfer', which moves a message, and 'flow', which is a receiver saying how many \
more it will accept. Lots of flow and little transfer is back-pressure.",
            look_for: "\"AMQP 1.0 transfer (message)\" or \"flow (credit)\" on TCP 5672.",
        },
        Protocol::Kafka => Lesson {
            title: "Kafka — Apache Kafka messaging",
            summary: "Distributed event streaming platform protocol.",
            body: "Kafka protocol handles read/write requests between clients and broker clusters.",
            look_for: "Kafka messages and API requests on port 9092.",
        },
        Protocol::Iax2 => Lesson {
            title: "IAX2 — trunking Asterisk boxes together",
            summary: "Carries VoIP signalling and audio over a single UDP port.",
            body: "IAX2 links Asterisk PBXs to each other. Unlike SIP, which negotiates a separate RTP \
stream on its own random port, IAX2 multiplexes call setup and the audio itself onto UDP \
4569 — which is why it survives NAT and restrictive firewalls so much more easily.",
            look_for: "\"IAX2 NEW\" / \"IAX2 ACK\" on UDP 4569.",
        },
        Protocol::Zrtp => Lesson {
            title: "ZRTP — agreeing on a key inside the call itself",
            summary: "Derives SRTP keys in the media stream, with no certificate authority.",
            body: "ZRTP runs a Diffie-Hellman exchange in the same path the audio takes, so the signalling \
server never sees the key. To rule out a man in the middle the two parties read a short \
authentication string to each other out loud and check that it matches.",
            look_for: "\"ZRTP Hello\" / \"ZRTP Commit\" — the magic sits where RTP keeps its timestamp.",
        },
        Protocol::MssqlBrowser => Lesson {
            title: "SQL Server Browser — finding the right instance",
            summary: "Tells a client which TCP port a named SQL Server instance listens on.",
            body: "A host can run several named SQL Server instances, each on a dynamic port. The Browser \
service listens on UDP 1434 and answers a one-byte query with the full list. That is \
convenient for clients and equally convenient for anyone enumerating your database \
servers, so it is a common scan target.",
            look_for: "\"SQL Browser request\" and instance-name responses on UDP 1434.",
        },
        Protocol::H225Ras => Lesson {
            title: "H.225 RAS — registering with the gatekeeper",
            summary: "How H.323 endpoints register, ask permission to call, and report status.",
            body: "RAS (Registration, Admission, Status) is the first conversation in an H.323 network: a \
phone or codec registers with the gatekeeper, then asks admission before each call so \
the gatekeeper can apply bandwidth and dial-plan policy.",
            look_for: "\"H.225 RAS RRQ/RCF\" (registration) and \"ARQ/ACF\" (admission) on UDP 1719.",
        },
        Protocol::Q931 => Lesson {
            title: "Q.931 — setting up an H.323 call",
            summary: "The ISDN-derived call signalling that H.323 carries over TCP 1720.",
            body: "Q.931 drives the call state machine: SETUP starts it, ALERTING means ringing, CONNECT \
means answered, and RELEASE COMPLETE tears it down carrying a cause code that says why. \
H.323 kept the ISDN message set and wrapped it in a TPKT header.",
            look_for: "\"Q.931 SETUP\" / \"Q.931 CONNECT\" on TCP 1720; the cause code explains failed calls.",
        },
        Protocol::Bfcp => Lesson {
            title: "BFCP — deciding whose turn it is",
            summary: "Arbitrates a shared conference resource such as screen sharing.",
            body: "A conference has resources only one participant can hold at a time — the presenter \
screen, for instance. BFCP calls each of these a floor; clients request it, the floor \
control server grants or denies, and everyone is told who holds it.",
            look_for: "\"BFCP FloorRequest\" / \"FloorStatus\" on TCP 3238.",
        },
        Protocol::Lisp => Lesson {
            title: "LISP — splitting who you are from where you are",
            summary: "Separates an endpoint's identity (EID) from its network location (RLOC).",
            body: "In plain IP an address means both identity and location, so moving a host means \
renumbering it. LISP keeps the EID stable and maps it to whichever RLOC currently \
reaches it, encapsulating traffic between the two. UDP 4341 carries data, 4342 the \
mapping control.",
            look_for: "\"LISP data\" on UDP 4341 and \"Map-Request/Map-Reply\" on 4342.",
        },
        Protocol::L2tpv3 => Lesson {
            title: "L2TPv3 — a pseudowire straight over IP",
            summary: "Tunnels raw layer-2 frames using IP protocol 115, with no UDP underneath.",
            body: "L2TPv3 carries Ethernet (or Frame Relay, or PPP) frames inside IP so two distant switch \
ports behave as if they were patched together. Each direction is identified by a session \
ID in the header.",
            look_for: "IP protocol 115 with a session ID — netscope reports the session and payload size.",
        },
        Protocol::VxlanGpe => Lesson {
            title: "VXLAN-GPE — VXLAN that isn't only Ethernet",
            summary: "Adds a next-protocol field so the overlay can carry IPv4, IPv6 or NSH.",
            body: "Classic VXLAN always encapsulates an Ethernet frame. GPE (Generic Protocol Extension) \
adds a next-protocol byte, which is what lets service-chaining designs push an NSH \
header or a bare IP packet through the same tunnel. It uses UDP 4790 to stay distinct \
from VXLAN's 4789.",
            look_for: "\"VXLAN-GPE\" on UDP 4790, with the inner protocol named.",
        },
        Protocol::Pcp => Lesson {
            title: "PCP / NAT-PMP — asking the NAT to open a port",
            summary: "Lets a client request an inbound mapping through its router.",
            body: "Games, P2P and VoIP need someone outside to be able to reach in. PCP is the modern \
replacement for UPnP IGD: the client asks for a mapping and a lifetime, and the gateway \
answers with the external address and port it actually got.",
            look_for: "\"PCP MAP request\" / \"NAT-PMP\" on UDP 5351.",
        },
        Protocol::Rwho => Lesson {
            title: "rwho — broadcasting who is logged in",
            summary: "A BSD-era service where each host announces its users and load.",
            body: "Every rwho host periodically broadcasts its uptime, load average and logged-in users so \
any machine on the segment can print them. There is no authentication of any kind, and \
it leaks usernames to the whole broadcast domain — seeing it today means something very \
old is still running.",
            look_for: "Periodic broadcasts on UDP 513 (TCP 513 is rlogin, a different protocol).",
        },
        Protocol::DhcpFailover => Lesson {
            title: "DHCP failover — keeping two servers in step",
            summary: "The channel a DHCP server pair uses to share lease state.",
            body: "Two DHCP servers serving one pool must agree on who holds which lease, or they will hand \
the same address to two clients. The failover channel on TCP 647 carries binding updates \
and pool balancing so either server can take over alone.",
            look_for: "\"DHCP failover BNDUPD\" / \"POOLREQ\" on TCP 647.",
        },
        Protocol::Ngap => Lesson {
            title: "NGAP — the 5G core's signalling language",
            summary: "How a 5G cell tower and the mobile core talk about your phone.",
            body: "When your phone connects to 5G, the cell tower (gNB) and the core network (the AMF) exchange NGAP messages to register it, set up a data session, page it when a call arrives, and hand it to another tower as you move. NGAP carries no user data — it is pure control, the paperwork that makes the data path exist. It rides on SCTP and is identified by a payload identifier rather than a port, so operators run it wherever they like.",
            look_for: "\"NGAP InitialUEMessage\" (a phone appearing), \"NGAP PDUSessionResourceSetup\" (data session being built), \"NGAP Paging\" (the network looking for a phone).",
        },
        Protocol::S1ap => Lesson {
            title: "S1AP — NGAP's 4G predecessor",
            summary: "The same job as NGAP, on an LTE network.",
            body: "S1AP is what NGAP replaced. It connects an LTE cell tower (eNB) to the core (the MME) and does the same work: attach a phone, build a bearer for its data, page it, hand it over. The message layout is close enough to NGAP that they look alike on the wire — but the procedure numbers mean different things, so the two are decoded separately. Plenty of live networks still run both side by side.",
            look_for: "\"S1AP InitialUEMessage\", \"S1AP S1Setup (success)\" when a tower comes online, \"S1AP E-RABSetup\" for a data bearer.",
        },
        Protocol::Xnap => Lesson {
            title: "XnAP — one 5G tower talking to the next",
            summary: "Lets neighbouring cells hand your phone over directly.",
            body: "When you walk or drive out of one 5G cell and into another, the two base stations can arrange the handover between themselves over the Xn link instead of asking the core network to broker it. That is faster and is why a call does not drop as you move. XnAP is that conversation.",
            look_for: "\"XnAP HandoverPreparation\" as a phone moves between cells; \"XnAP XnSetup (success)\" when two towers first learn about each other.",
        },
        Protocol::F1ap => Lesson {
            title: "F1AP — inside a single 5G base station",
            summary: "A modern base station is split in two; this joins the halves.",
            body: "A 5G base station is usually not one box. A central unit does the thinking and sits in a data centre, while distributed units sit at the actual antennas. F1AP is the link between them. Seeing it means you are capturing inside an operator's radio network, not on a link between operators.",
            look_for: "\"F1AP F1Setup\" when a radio unit registers with its central unit; \"F1AP UEContextSetup\" when a phone is given radio resources.",
        },
        Protocol::E1ap => Lesson {
            title: "E1AP — splitting control from data",
            summary: "The 5G central unit is itself split; this joins those halves.",
            body: "The central unit of a 5G base station is divided again: a control-plane half that makes decisions and a user-plane half that actually moves your data. Separating them lets an operator scale data capacity without scaling signalling. E1AP is how the two coordinate — mostly about setting up and tearing down the bearers that carry traffic.",
            look_for: "\"E1AP BearerContextSetup\" when a data path is created; \"E1AP DataUsageReport\" for accounting.",
        },
        Protocol::M3ua => Lesson {
            title: "M3UA — SS7 telephony moved onto IP",
            summary: "How phone networks still route calls and texts, now over IP.",
            body: "Before mobile networks ran on IP, operators used SS7 — a separate signalling network for setting up calls, delivering SMS and answering roaming queries. Those SS7 links are mostly gone, but the protocol on top of them was kept, wrapped in M3UA and carried over IP. It is why a text message still reaches you abroad. SS7 was designed for a world of a few trusted operators, so it carries very little authentication, which is why access to it is tightly controlled.",
            look_for: "\"M3UA DATA — SCCP 1001 → 2002\" (a message travelling between two switches), \"M3UA ASPUP\" when a link comes up.",
        },
        Protocol::M2ua => Lesson {
            title: "M2UA — a remote SS7 link, made local",
            summary: "Lets equipment use an SS7 link that is physically somewhere else.",
            body: "M2UA sits one layer below M3UA. A signalling gateway holds the real SS7 link and uses M2UA to present it to a controller elsewhere on the network, so the controller behaves as though the link were plugged into it directly.",
            look_for: "\"M2UA Data\" carrying link traffic; \"M2UA State Indication\" when the link changes state.",
        },
        Protocol::M2pa => Lesson {
            title: "M2PA — two signalling points, straight over IP",
            summary: "Replaces an SS7 link rather than relaying one.",
            body: "M2PA and M2UA look similar but do different jobs. M2UA relays a remote link to a controller; M2PA replaces the link itself, so two signalling points exchange routing messages directly over IP with no SS7 hardware anywhere in the path.",
            look_for: "\"M2PA User Data\" for ordinary traffic; \"M2PA Link Status\" for link housekeeping.",
        },
        Protocol::Sua => Lesson {
            title: "SUA — reaching SS7 without an SS7 stack",
            summary: "Lets a normal server talk to a telephony network.",
            body: "SUA replaces two SS7 layers at once, so an application can query a telephony network — asking where a subscriber is, say — without implementing the SS7 stack underneath. Most of what rides on it is connectionless: one question, one answer.",
            look_for: "\"SUA CLDT\" (a query or its data) and \"SUA CLDR\" (the response).",
        },
        Protocol::Gtpv2 => Lesson {
            title: "GTPv2-C — building your phone's data path",
            summary: "Creates and moves the tunnel your mobile data travels through.",
            body: "When your phone gets mobile data, the core network builds a tunnel for it. GTPv2-C is the control conversation that creates that tunnel, moves it as you travel between cells, and tears it down when you disconnect. The data itself flows through a different protocol (GTP-U); this is only the paperwork. A Create Session Request is roughly the moment your phone gets online.",
            look_for: "\"GTPv2-C Create Session Request\" when data starts, \"Modify Bearer Request\" as you move, \"Delete Session Request\" when it ends.",
        },
        Protocol::Rua => Lesson {
            title: "RUA — carrying 3G signalling from a femtocell",
            summary: "The transport a home base station uses to reach the operator.",
            body: "A femtocell is a small operator-supplied base station that improves coverage inside a building by backhauling over your own broadband. RUA is how it carries 3G control messages to the operator gateway across that ordinary internet connection.",
            look_for: "\"RUA Connect\" when a phone attaches through the femtocell; \"RUA DirectTransfer\" for ongoing signalling.",
        },
        Protocol::Hnbap => Lesson {
            title: "HNBAP — a femtocell checking in",
            summary: "Registers a home base station and its phones with the operator.",
            body: "Before a femtocell can carry traffic it has to register with the operator: prove which unit it is, say where it is, and list which phones are allowed to use it. HNBAP is that registration conversation.",
            look_for: "\"HNBAP HNBRegister\" when the unit comes online; \"HNBAP UERegister\" as a phone attaches to it.",
        },
        Protocol::Nbap => Lesson {
            title: "NBAP — running a 3G base station",
            summary: "How a controller drives the radio hardware on a 3G cell.",
            body: "In 3G the radio hardware (the NodeB) is not very smart on its own — a separate controller tells it which cells to run and which radio links to set up for which phones. NBAP is that instruction channel. 4G and 5G moved most of this intelligence into the base station itself, so NBAP is mostly seen in older networks.",
            look_for: "\"NBAP CellSetup\" when a cell is brought up; \"NBAP RadioLinkSetup\" as a phone is given radio resources.",
        },
        Protocol::SbcAp => Lesson {
            title: "SBc-AP — emergency alerts to LTE phones",
            summary: "The path a public warning takes to reach every phone in an area.",
            body: "When an earthquake, tsunami or missing-child alert is broadcast to every phone in a region, SBc-AP is how the warning reaches the LTE cells that will transmit it. It is broadcast, not addressed — the cell sends it and every phone in range picks it up, so no subscriber list is involved.",
            look_for: "\"SBc-AP WriteReplaceWarning\" when an alert is issued; \"SBc-AP StopWarning\" when it is withdrawn.",
        },
        Protocol::Sabp => Lesson {
            title: "SABP — the 3G version of cell broadcast",
            summary: "Same job as SBc-AP, on an older network generation.",
            body: "SABP delivers area-wide broadcast messages to 3G cells: emergency alerts, and in some countries the area name your phone displays. It predates SBc-AP and does the same work for UMTS networks.",
            look_for: "\"SABP Write-Replace\" when a broadcast starts; \"SABP Kill\" when it is cancelled.",
        },
        Protocol::LcsAp => Lesson {
            title: "LCS-AP — working out where a phone is",
            summary: "The network locating a handset, usually for an emergency call.",
            body: "When you dial an emergency number, the network has to tell the dispatcher where you are, and it can be far more precise than the cell tower alone — combining timing measurements, satellite positioning and known cell positions. LCS-AP carries those requests and results. The same machinery is used for lawful intercept, which is why it is a sensitive protocol to see in a capture.",
            look_for: "\"LCS-AP LocationService\" when a position is requested; \"LCS-AP LocationAbort\" when a request is cancelled.",
        },
        Protocol::M2ap => Lesson {
            title: "M2AP — broadcasting to many phones at once",
            summary: "Sets up a single transmission that thousands of phones share.",
            body: "Normally each phone gets its own data stream. For something everyone wants at the same moment — a live event, a mass software update — that wastes radio capacity. eMBMS sends it once and lets every phone in the cell receive the same transmission. M2AP is how a base station and the coordinating node agree on those sessions.",
            look_for: "\"M2AP SessionStart\" when a broadcast begins; \"M2AP SchedulingInformation\" for its timing.",
        },
        Protocol::M3ap => Lesson {
            title: "M3AP — the core side of mobile broadcast",
            summary: "Connects the broadcast coordinator to the gateway feeding it.",
            body: "M3AP is M2AP's partner one step deeper into the network: where M2AP talks to base stations, M3AP connects the coordinating node to the gateway that actually sources the broadcast content.",
            look_for: "\"M3AP SessionStart\" as a broadcast session is created; \"M3AP M3Setup\" when the two nodes first connect.",
        },
        Protocol::Sccp => Lesson {
            title: "SCCP — addressing inside the phone network",
            summary: "Works out which network element a query should reach.",
            body: "SS7 point codes identify a switch, but not what you want to talk to inside it. SCCP adds a subsystem number that names the actual element — the subscriber database (HLR), the visitor register (VLR), the switch itself (MSC). That is the useful part of an SCCP header: it tells you a query is heading for a subscriber database rather than just to some node.",
            look_for: "\"SCCP UDT — MSC → HLR\", meaning a switch is querying the subscriber database. When the contents are recognised, netscope shows the TCAP operation instead.",
        },
        Protocol::Tcap => Lesson {
            title: "TCAP — what the phone network is actually asking",
            summary: "Pairs a question with its answer, and names the question.",
            body: "TCAP matches a request to its response across the network. On its own that says little, but the operation code it carries names the real work: registering a phone in a new area, fetching authentication keys, or finding out where to deliver a text message. Two of those operations are worth recognising on sight. sendRoutingInfoForSM asks where a subscriber is so a message can be delivered, and anyTimeInterrogation asks where a subscriber physically is. Both are legitimate operations that are also the basis of well-known SS7 tracking and interception abuse, which is why netscope names them rather than leaving them as numbers.",
            look_for: "\"TCAP Begin Invoke — sendRoutingInfoForSM — MSC → HLR\" for SMS routing; \"anyTimeInterrogation\" for a location query; \"updateLocation\" when a phone registers somewhere new.",
        },
        Protocol::Isup => Lesson {
            title: "ISUP — setting up a phone call",
            summary: "The messages that ring a phone, connect it and hang it up.",
            body: "When a call crosses between switches, ISUP carries its state: an Initial Address message starts it and carries the dialled number, Address Complete means the far end is ringing, Answer means it was picked up, and Release ends it. Each message names the circuit it belongs to, so several calls on the same link stay distinguishable.",
            look_for: "\"ISUP IAM (Initial Address) — CIC 42\" starting a call, then \"ACM\" (ringing), \"ANM\" (answered) and \"REL\" (hung up) on the same circuit.",
        },
        Protocol::Ranap => Lesson {
            title: "RANAP — the 3G core's signalling language",
            summary: "The 3G equivalent of NGAP and S1AP.",
            body: "RANAP connects a 3G radio network controller to the core network. It does the same work its 4G and 5G successors do: attach a phone, set up a bearer for its data or voice, page it, hand it between controllers. Unlike NGAP and S1AP it has no transport of its own — it travels inside SCCP, addressed to subsystem 142.",
            look_for: "\"RANAP InitialUE-Message\" when a phone appears; \"RANAP RAB-Assignment\" when a data or voice bearer is set up.",
        },
        Protocol::Rnsap => Lesson {
            title: "RNSAP — two 3G controllers cooperating",
            summary: "Lets a phone be served by two radio controllers at once.",
            body: "In 3G a phone can be connected to cells belonging to two different controllers at the same time — the connection is anchored at one and extended over the Iur link to the other. RNSAP is that link. It is the 3G ancestor of what XnAP does between 5G base stations.",
            look_for: "\"RNSAP RadioLinkSetup\" when a second controller adds a radio link; \"RNSAP RadioLinkFailure\" when one drops.",
        },
        Protocol::Bssap => Lesson {
            title: "BSSAP — the 2G interface, and messages passing through it",
            summary: "Carries base-station control and relays messages meant for the phone.",
            body: "BSSAP is really two protocols behind one byte. BSSMAP messages are between the base station controller and the switch: assigning a channel, ordering encryption, paging. DTAP messages are not for the base station at all — they are between the phone and the switch, with the base station simply relaying them, which is why netscope labels them as relayed and names the protocol inside. Seeing a DTAP SMS message means a text is in transit.",
            look_for: "\"BSSMAP PAGING\" or \"BSSMAP CIPHER MODE COMMAND\" for base-station control; \"BSSAP DTAP — SMS (relayed to the phone)\" for a text message passing through.",
        },
        Protocol::Fins => Lesson {
            title: "FINS — talking to an Omron factory controller",
            summary: "Reads and writes the memory of a PLC on a factory floor.",
            body: "A PLC is the small computer that actually runs a machine — opening a valve, moving a robot arm, stopping a conveyor. FINS is how Omron PLCs are read and commanded over the network. Like most factory protocols it has no authentication at all: a command to write memory or stop the controller is obeyed because it arrived, not because the sender proved who they were. That is normal on an isolated plant network and alarming anywhere else.",
            look_for: "\"FINS MEMORY AREA READ (command)\" for ordinary polling; \"FINS STOP (command)\" or \"MEMORY AREA WRITE\" for anything that changes what the machine does.",
        },
        Protocol::Slmp => Lesson {
            title: "SLMP / MELSEC — Mitsubishi's PLC protocol",
            summary: "The Mitsubishi equivalent of FINS.",
            body: "SLMP does for Mitsubishi controllers what FINS does for Omron: read and write the memory that holds a machine's state, and start or stop the controller. It comes in two frame formats, one of which adds a serial number so replies can be matched to requests. It is likewise unauthenticated.",
            look_for: "\"SLMP Read — station 0.255\" for polling; \"SLMP Remote Stop\" or \"Remote Reset\" for commands that halt a machine.",
        },
        Protocol::Ads => Lesson {
            title: "ADS — Beckhoff TwinCAT automation",
            summary: "How PC-based industrial controllers are read and commanded.",
            body: "Beckhoff builds controllers that are really PCs running real-time software. ADS is the protocol used to reach them. Its unusual feature is addressing: devices are named by an AMS NetId rather than by IP address, so the NetId is what actually identifies which controller you are talking to — two controllers behind the same IP have different NetIds.",
            look_for: "\"ADS Read (request) — 192.168.1.10.1.1:851\", where the dotted number is the AMS NetId, not an IP address; \"ADS Write Control\" changes the controller's run state.",
        },
        Protocol::Hsms => Lesson {
            title: "HSMS / SECS — chip factory equipment",
            summary: "How semiconductor manufacturing tools report to their host.",
            body: "Every tool in a chip fab — the machines that etch, deposit and inspect wafers — talks to a host system using SECS-II messages carried over HSMS. Messages are named by stream and function, so S1F1 is \"are you there\" and S5F1 is an alarm report. A fab capture is mostly the host polling status and tools reporting events, so alarms stand out.",
            look_for: "\"HSMS S1F1 Are You There\" for a health check; \"HSMS S5F1 Alarm Report Send\" when a tool raises an alarm; \"HSMS Linktest.req\" keeping the link alive.",
        },
        Protocol::Cip => Lesson {
            title: "CIP — what the EtherNet/IP envelope is carrying",
            summary: "The actual command sent to a factory controller.",
            body: "EtherNet/IP is only the wrapper. The message inside is CIP, and that is where the meaning lives: reading a tag holding a temperature, writing one that opens a valve, or telling the controller to stop. Every CIP request names both a service (what to do) and an object class (which part of the device), so a single line tells you a Logix controller was asked to halt rather than merely that some EtherNet/IP traffic went past. Like other factory protocols it carries no authentication.",
            look_for: "\"CIP Read Tag — Symbol\" for ordinary polling; \"CIP Write Tag\" when a value is changed; \"CIP Stop — Logix Controller\" for a command that halts the machine.",
        },
        Protocol::CipSafety => Lesson {
            title: "CIP Safety — fail-safe industrial control",
            summary: "Safety-extended CIP messages for fail-safe industrial communication.",
            body: "CIP Safety extends the Common Industrial Protocol (CIP) to provide fail-safe \
communication up to SIL3/PLe. It operates directly over standard networks like EtherNet/IP \
without relying on the underlying medium for safety integrity (the 'Black Channel' principle). \
It can be identified by the use of safety-critical classes (like Safety Supervisor 0x39 or \
Safety Validator 0x3A) and the presence of safety validations, timestamps, and redundant CRCs.",
            look_for: "CIP Safety messages targeting safety validator (0x3A) or safety supervisor (0x39) objects, carrying safety-critical commands.",
        },
        Protocol::Dlms => Lesson {
            title: "DLMS/COSEM — reading the meter on your wall",
            summary: "How electricity, gas and water meters report and are configured.",
            body: "Smart meters send their readings and accept configuration over DLMS/COSEM. The part worth watching is whether the message is encrypted: the standard defines the same operations twice, once in the clear and once ciphered. A GET-Request in the clear means readings are visible to anyone on the path, and a SET-Request in the clear means the meter can be reconfigured without the traffic being protected. netscope marks which form is in use.",
            look_for: "\"DLMS GET-Request — client 1 → server 17\" reading a meter; \"DLMS SET-Request (encrypted)\" reconfiguring one with the body protected.",
        },
        Protocol::Fox => Lesson {
            title: "Niagara Fox — the building's control system",
            summary: "Runs heating, lighting, lifts and door access in large buildings.",
            body: "Tridium Niagara is one of the most widely deployed building-management platforms, and Fox is how its controllers talk. Its opening greeting is unusually revealing: before any login it announces the station name, the product version and the host operating system. That makes it easy to inventory a building's control system from a single packet, which is exactly why it is worth surfacing what the greeting gives away.",
            look_for: "\"Fox hello — BMS-TOWER-3 · Tridium · QNX (x86)\", naming the station, the product and the operating system it runs on.",
        },
        Protocol::SrtpGe => Lesson {
            title: "GE-SRTP — GE Fanuc factory controllers",
            summary: "Reads and writes PLCs made by GE Fanuc and Emerson.",
            body: "SRTP is how GE Fanuc controllers are polled and commanded. It has no published specification, so what is decoded here comes from reverse engineering and is deliberately limited to the fields that are well established — the direction of the message and which service was requested. Requests that write memory or change the privilege level are the ones that alter what a machine is doing.",
            look_for: "\"GE-SRTP Read System Memory (request)\" for polling; \"Write System Memory\" or \"Change PLC Privilege Level\" for anything that changes the controller.",
        },
        Protocol::Pccc => Lesson {
            title: "PCCC — a 1980s command set on a modern network",
            summary: "How older Allen-Bradley controllers are still reached today.",
            body: "Rockwell's newer controllers speak CIP, but a great many PLC-5 and SLC-500 units are still running plants, and they speak PCCC. Rather than replace them, CIP tunnels PCCC through an Execute PCCC service — so a modern EtherNet/IP capture often contains a decades-old command set two layers down. The PCCC function is what tells you whether a controller is being read, written, or told to change processor mode.",
            look_for: "\"PCCC Protected Typed Logical Read\" for polling; \"Protected Typed Logical Write\" or \"Change Processor Mode\" for commands that alter the machine.",
        },
        Protocol::Isis => Lesson {
            title: "IS-IS — the routing protocol that ignores IP",
            summary: "How large carrier networks work out where everything is.",
            body: "Routers have to agree on the shape of the network before they can forward anything. IS-IS is one of the two protocols that does this inside a single operator (OSPF is the other), and it is the one most large carriers chose. Its unusual trait is that it does not run over IP at all — it rides directly on the link layer, so the routing protocol keeps working even while the IP addressing underneath it is broken or being renumbered. Routing is split into two levels: within an area, and between areas.",
            look_for: "\"IS-IS L1 LAN Hello\" as routers find each other; \"L2 Link State PDU\" carrying the map of the network between areas.",
        },
        Protocol::Msdp => Lesson {
            title: "MSDP — multicast across a border",
            summary: "Lets a viewer in one network find a source in another.",
            body: "Multicast normally stops at the edge of a network, because each operator runs its own rendezvous point and knows only about its own sources. MSDP is the bridge: operators peer with each other and announce which multicast sources they have. Without it, multicast video from one provider could not reach subscribers of another.",
            look_for: "\"MSDP Source-Active — 3 sources from RP 10.0.0.1\", one network announcing sources to another; \"MSDP KeepAlive\" holding the peering up.",
        },
        Protocol::Pgm => Lesson {
            title: "PGM — multicast that does not lose data",
            summary: "Adds retransmission to multicast, which normally has none.",
            body: "Plain multicast has no recovery: a packet lost on the way to one receiver is simply gone for that receiver. PGM adds a repair mechanism — receivers notice a gap in the sequence numbers and ask for the missing piece, and the source or a nearby router resends it. That makes it usable for things where loss is unacceptable, like market data feeds. A capture full of NAKs is the signature of a lossy multicast path.",
            look_for: "\"PGM ODATA (original data)\" for the normal flow; a run of \"PGM NAK\" and \"RDATA (repair data)\" means receivers are missing packets and asking for them again.",
        },
        Protocol::Srt => Lesson {
            title: "SRT — live television over the open internet",
            summary: "Carries broadcast video between studios without a dedicated line.",
            body: "Getting live video from a camera in the field back to a studio used to need an expensive dedicated circuit, because the public internet loses packets and a lost packet is a glitch on air. SRT changed that: it adds retransmission and pacing on top of UDP, so a missing piece is asked for again and arrives in time to be used. What to watch is the ratio of data to loss reports. An almost pure stream of data packets means the feed is healthy; a run of NAKs means the path is losing packets and the encoder is working to keep the picture clean.",
            look_for: "\"SRT data — seq 4211, socket 0x12345678\" for the video itself; a burst of \"SRT NAK (loss report)\" means packets are going missing.",
        },
        Protocol::MpegTs => Lesson {
            title: "MPEG-TS — the container television travels in",
            summary: "The packet format behind broadcast TV and IPTV.",
            body: "Almost all broadcast and IPTV video is carried as MPEG transport stream: a relentless run of 188-byte packets, each starting with the same sync byte. Streams inside it are identified by a packet identifier, and a few fixed identifiers carry the tables that describe what the stream contains — which channels exist, what the programme guide says, what the time is. A UDP datagram usually holds seven of these packets, which is where the familiar 1316-byte payload comes from.",
            look_for: "\"MPEG-TS PID 0x0000 PAT (program association) — 7 packets\" listing the channels; a \"transport error\" note means the sender itself flagged the packet as corrupt.",
        },
        Protocol::Thrift => Lesson {
            title: "Thrift — one service calling another",
            summary: "The RPC framing behind HBase, Hive and a lot of internal traffic.",
            body: "Before gRPC became the default, Thrift was how many companies had their services talk to each other, and a great deal of that traffic is still running. Its useful property in a capture is that the method name travels in the clear at the front of every call. So a single packet tells you which operation was requested, not merely that two services exchanged bytes. Thrift is used both with and without a length prefix on each message, and both forms appear in the wild.",
            look_for: "\"Thrift call — getRegionInfo\" for a request; \"Thrift reply\" or \"Thrift exception\" with the same method name for what came back.",
        },
        Protocol::Pcep => Lesson {
            title: "PCEP — asking a controller where to route",
            summary: "Central path computation for traffic-engineered networks.",
            body: "Normally each router works out its own paths. In a traffic-engineered network that is not good enough, because a good path depends on what every other flow is doing. PCEP lets a router ask a controller with a full view of the topology instead, and the controller answers. Later extensions turned this around: the controller can update an existing path or create a new one on its own initiative, which is what makes a segment-routing network centrally steerable.",
            look_for: "\"PCEP Path Computation Request\" and its Reply for the classic exchange; \"PCEP Initiate\" or \"Update\" when the controller is driving.",
        },
        Protocol::Dlsw => Lesson {
            title: "DLSw — mainframe traffic over a modern network",
            summary: "Carries IBM SNA across IP without it noticing.",
            body: "SNA was designed for reliable leased lines and does not cope with the delay and packet loss of a routed network — it will drop a session that goes quiet for a moment. DLSw works around that by ending the SNA link locally at each end and tunnelling between the two switches over TCP, so the mainframe and the terminal each believe they are on a direct, well-behaved link. It is why decades-old terminal traffic still runs over ordinary corporate networks.",
            look_for: "\"DLSw CAP_EXCHANGE\" when two switches meet; \"CANUREACH\" and \"ICANREACH\" locating a mainframe; \"INFOFRAME\" carrying the session data.",
        },
        Protocol::Ceph => Lesson {
            title: "Ceph — storage spread across many machines",
            summary: "How a cluster of ordinary servers becomes one pool of storage.",
            body: "Ceph turns a rack of commodity servers into a single storage system, replicating every object across several machines so losing one loses nothing. The daemons and their clients talk over a messenger protocol that opens with a fixed banner, which is handy because storage daemons spread themselves across hundreds of ports. Most of what you see is either cluster state being agreed or objects being written and read.",
            look_for: "\"Ceph banner — messenger v1\" opening a connection; \"Ceph MSG\" for the traffic itself; \"Ceph BADAUTHORIZER\" when a client is refused.",
        },
        Protocol::Trill => Lesson {
            title: "TRILL — Ethernet that actually routes",
            summary: "Uses every link in a data centre instead of switching some off.",
            body: "Spanning tree keeps a switched network from looping by disabling links until only one path remains, which means expensive links sit idle. TRILL replaces that: each switch gets a nickname, and frames are routed between nicknames using IS-IS, so every link carries traffic and the shortest path is really used. Because it is genuine routing, frames carry a hop count — without one a loop would be fatal rather than merely wasteful.",
            look_for: "\"TRILL 100 → 200, 30 hops left\" for a routed frame; \"TRILL multi-destination\" for one being flooded to a distribution tree.",
        },
        Protocol::Cfm => Lesson {
            title: "CFM — proving a carrier circuit is healthy",
            summary: "The monitoring behind an Ethernet service level agreement.",
            body: "A carrier selling an Ethernet circuit has to show it is up and meeting its promised latency. CFM does that: continuity check messages flow constantly so a break is spotted in milliseconds, and delay and loss measurement exchanges produce the numbers the agreement is judged on. The maintenance level keeps everyone's monitoring separate — the customer, the carrier and any intermediate operator each work at their own level and ignore the others, so nobody sees or interferes with anyone else's checks.",
            look_for: "\"CFM CCM (continuity check) — level 5\" flowing steadily; \"DMM (delay measurement message)\" timing the circuit; \"AIS (alarm indication)\" when something upstream has failed.",
        },
        Protocol::Rpl => Lesson {
            title: "RPL — routing for things that run on batteries",
            summary: "How a mesh of sensors works out where to send data.",
            body: "A sensor on a mesh wakes for a moment, sends a few bytes and sleeps again. It cannot run a routing protocol that floods the state of every link everywhere — that would flatten its battery in days. RPL builds a tree towards a root instead: each node only needs to know how far it is from the root (its rank) and which neighbour is its parent. Traffic climbs the tree and comes back down. A node whose rank keeps changing is one that cannot settle on a parent, which usually means a flapping radio link.",
            look_for: "\"RPL DIO (advertise routing information) — instance 1, version 2, rank 256\" building the tree; \"RPL DAO\" telling a parent which destinations lie below.",
        },
        Protocol::SixLowpan => Lesson {
            title: "6LoWPAN — IPv6 that fits in a radio packet",
            summary: "Compresses a 40-byte IPv6 header down to a handful of bytes.",
            body: "An 802.15.4 radio frame holds at most 127 bytes in total, and an IPv6 header alone is 40 of them before any payload. Sending IPv6 unchanged would leave almost nothing for the data. 6LoWPAN compresses the header by leaving out everything that can be worked out from the link-layer addresses, and splits into fragments whatever still does not fit. It is the layer that lets a battery-powered sensor have a real internet address, and it is what Thread and Matter are built on.",
            look_for: "\"6LoWPAN IPHC compressed header\" for the usual case; \"6LoWPAN fragment 1 of datagram 66 (256 bytes total)\" when a packet was too big for one frame.",
        },
        Protocol::Roughtime => Lesson {
            title: "Roughtime — a clock you can check",
            summary: "Time you do not have to take the server's word for.",
            body: "NTP has an awkward gap: if a time server lies to you, there is no way to prove it. A machine given the wrong time will accept expired certificates or reject valid ones, and nothing in the protocol lets you show what happened. Roughtime closes that. Every answer is signed, and clients chain servers together — each request carries a hash of the previous server's reply, so a server that lies gets caught by the next one and you are left holding cryptographic proof. The times are deliberately coarse, because the goal is catching dishonesty rather than microsecond accuracy.",
            look_for: "\"Roughtime request\" carrying a nonce; \"Roughtime response — signed time\" carrying the signature and the certificate for the key that made it.",
        },
        Protocol::Mle => Lesson {
            title: "MLE — how a Thread mesh holds itself together",
            summary: "Smart-home devices finding a parent and keeping the network alive.",
            body: "A Thread network has no fixed shape. Devices appear, attach to whichever neighbour will parent them, take on a role, and vanish again when a battery dies or someone moves a sensor. MLE is the conversation that runs all of it. Watching a device join is a readable sequence: it asks for a parent, one answers, the device requests an address and is given one. Most live traffic is encrypted with the network key, in which case the command itself is inside the encrypted part and netscope says so rather than guessing.",
            look_for: "\"MLE Parent Request\" then \"Parent Response\", \"Child ID Request\" and \"Child ID Response\" as a device joins; \"MLE encrypted\" for the everyday secured traffic.",
        },
        Protocol::Olsr => Lesson {
            title: "OLSR — how a community mesh stays connected",
            summary: "Routing for networks of rooftop radios with no central owner.",
            body: "A wireless mesh cannot flood link-state the way a wired network does: every node hears every broadcast, so the radio channel would fill with routing chatter and leave nothing for traffic. OLSR's answer is multipoint relays. Each node picks a small set of neighbours that between them can reach everyone two hops away, and only those relay. That reduction is what makes the protocol work on meshes of hundreds of nodes, which is why most large community networks run it.",
            look_for: "\"OLSR HELLO — from 10.0.0.5, 0 hops, TTL 1\" describing a direct link; \"OLSR TC (topology control)\" with a higher hop count, carrying the map of the mesh across it.",
        },
        Protocol::Batman => Lesson {
            title: "batman-adv — a mesh pretending to be one LAN",
            summary: "Routes at the Ethernet layer, so the whole mesh looks like one network.",
            body: "Most mesh protocols route IP packets, which means anything that relies on being on the same LAN stops working across the mesh. batman-adv works a layer lower: it routes Ethernet frames, so the entire mesh appears as one flat network segment and DHCP, local discovery and even non-IP protocols work across it unchanged. The price is that every node must learn about every other node, which is what the originator messages are constantly doing. Nodes on different compatibility versions cannot mesh at all, so seeing two versions in one capture explains a lot.",
            look_for: "\"batman-adv IV OGM (originator message) — v15, TTL 50\" spreading knowledge of who exists; \"batman-adv unicast\" carrying actual traffic.",
        },
        Protocol::Aodv => Lesson {
            title: "AODV — routes found only when needed",
            summary: "Does nothing until someone actually wants to reach somewhere.",
            body: "OLSR keeps a map of the whole mesh up to date at all times. AODV takes the opposite bet: it stores nothing until a node actually needs to send something, then floods a request asking who can reach the destination, and keeps the answer only while it is in use. On a network where most nodes talk to almost nobody that saves a great deal of chatter, at the cost of a pause the first time a conversation starts. A route error is the interesting one — it means a link has just died and the news is spreading.",
            look_for: "\"AODV RREQ — 10.0.0.1 looking for 10.0.0.9\" starting a search; \"AODV RREP\" answering it; \"AODV RERR — 2 destinations unreachable\" when a link breaks.",
        },
        Protocol::Nsh => Lesson {
            title: "NSH — a packet carrying its own itinerary",
            summary: "Steers traffic through a chain of firewalls and inspection boxes.",
            body: "Sending traffic through several appliances in a fixed order used to mean physically cabling them in that order, or fighting with policy routing to fake it. NSH puts the itinerary in the packet instead: a service path identifier names the chain, and a service index counts down as each appliance handles the packet. Watching the index fall tells you exactly how far through its chain a packet has got, and an index that stops falling points at the appliance that swallowed it.",
            look_for: "\"NSH path 42, index 255 — carrying Ethernet\" entering a chain, with the index lower at each subsequent hop.",
        },
        Protocol::Nhrp => Lesson {
            title: "NHRP — VPN branches finding each other",
            summary: "Lets two branch offices talk directly instead of via head office.",
            body: "In a typical multi-site VPN every branch holds one tunnel to a hub. That works, but traffic between two branches then travels to head office and back, wasting bandwidth and adding delay — bad for a phone call between two shops in the same city. NHRP fixes it: a branch asks the hub for the other branch's real public address, then builds a tunnel straight there. Registration messages are how each branch keeps the hub informed of its current address, which matters because most branches have a dynamic one.",
            look_for: "\"NHRP Resolution Request\" then \"Resolution Reply\" just before two sites start talking directly; \"Registration Request\" when a branch checks in with the hub.",
        },
        Protocol::Ovsdb => Lesson {
            title: "OVSDB — configuring the switch inside a server",
            summary: "Manages Open vSwitch, the software switch in most cloud hosts.",
            body: "Virtual machines and containers do not plug into a physical switch; they plug into a software one running on the host, and in most OpenStack and container platforms that switch is Open vSwitch. OVSDB is how its configuration is read and changed — which ports exist, which bridges they belong to, where the tunnels point. Most traffic is a controller subscribing to changes and being notified of them; a transaction is the message that actually alters the switch, so that is the one worth noticing.",
            look_for: "\"OVSDB transact — changing the switch\" when configuration is altered; \"monitor_cond — subscribing to changes\" and \"update3 — reporting a change\" for the steady state.",
        },
        Protocol::IbmMq => Lesson {
            title: "IBM MQ — the queue banks run on",
            summary: "Guarantees a message arrives exactly once, even days later.",
            body: "IBM MQ's promise is narrow and valuable: hand it a message and it will be delivered exactly once, even if the receiving system is down for a week. That is why so much banking, insurance and retail back-office traffic runs through it — a payment that arrives twice or not at all is worse than one that arrives slowly. In a capture the API calls are what matter: a put is a message being handed over, a get is one being collected, and a rollback means work is being undone.",
            look_for: "\"IBM MQ MQPUT (send a message)\" and \"MQGET (read a message)\" for the normal flow; \"MQBACK (roll back)\" when a transaction is abandoned.",
        },
        Protocol::Lustre => Lesson {
            title: "Lustre — storage for supercomputers",
            summary: "One filesystem spread across hundreds of servers at once.",
            body: "When thousands of compute nodes all need to read and write the same dataset, a normal file server becomes the bottleneck immediately. Lustre spreads one filesystem across hundreds of storage servers so the load spreads with it. Its network layer is deliberately one-sided: a put writes straight into a remote node's memory and a get reads out of it, without the far side taking part in each transfer. That is what keeps the servers from spending all their time on bookkeeping.",
            look_for: "\"Lustre LNet PUT (write)\" and \"GET (read)\" for data movement; \"LNet connection request\" when a node joins.",
        },
        Protocol::SapAnnounce => Lesson {
            title: "SAP — the channel guide for multicast",
            summary: "How a receiver discovers which multicast streams exist.",
            body: "A multicast stream has no directory. A receiver that does not already know the group address and the codec simply cannot join — there is nothing to browse. SAP fills that gap: sources periodically announce themselves to a well-known multicast group, carrying an SDP body describing where their media is and what it is. It is how IPTV set-top boxes and broadcast receivers find their channels. A deletion is the opposite message, withdrawing a session that has ended.",
            look_for: "\"SAP announcement — SDP — video on 5004 to 239.1.1.1\" advertising a channel; \"SAP deletion\" when one goes off air.",
        },
        Protocol::Nfs => Lesson {
            title: "NFS — files that live on another machine",
            summary: "Reading and writing a disk that is not in your computer.",
            body: "NFS lets a machine use a filesystem that physically lives elsewhere as though it were local. What matters in a capture is which operation is being performed, because the performance problems look completely different: one large READ is a bandwidth question, while a directory walk that turns into thousands of LOOKUPs is a latency question and will be slow no matter how fast the link is. A burst of WRITEs followed by COMMITs is an application flushing data it cares about. Version 4 folded almost every operation into a single COMPOUND call, so older captures are often easier to read than newer ones.",
            look_for: "\"NFS v3 LOOKUP\" and \"READDIRPLUS\" while browsing; \"NFS v3 READ\" and \"WRITE\" for data; \"Mount v3 MNT (mount a share)\" when a share is first attached.",
        },
        Protocol::NineP => Lesson {
            title: "9P — the Plan 9 filesystem protocol",
            summary: "An old, small protocol that now carries WSL2 and QEMU file shares.",
            body: "9P came from Plan 9, an operating system where everything was a file \
reachable over the network. The idea outlived the system: WSL2 serves the Windows \
filesystem to Linux over 9P, QEMU shares directories with virtual machines over it, \
and several container runtimes use it too. So a developer complaining that files are \
slow inside WSL is describing a 9P problem, and every operation is visible here in \
the clear. Each message carries a tag pairing a request with its reply, which is how \
you find the slow one.",
            look_for: "\"9P Twalk (look up a path)\" and \"9P Tread\" on TCP 564; \"9P Rerror — file does not exist\" when something fails.",
        },
        Protocol::Rx => Lesson {
            title: "RX/AFS — the other network filesystem",
            summary: "The RPC transport underneath AFS, which predates NFS and still runs.",
            body: "AFS is unrelated to NFS and older than most of what replaced it, but \
universities and research sites still run home directories on it. It rides on RX, an \
RPC protocol using ten UDP ports from 7000 up — and the port is what says which \
server you are watching: 7000 is the fileserver, 7003 the volume location server, \
7004 authentication. An abort packet is an RPC failing outright and carries the \
reason as a numeric code.",
            look_for: "\"RX/AFS data (fileserver)\" for normal traffic; \"RX/AFS abort — code -102\" when a call fails.",
        },
        Protocol::GlusterFs => Lesson {
            title: "GlusterFS — one filesystem from many servers",
            summary: "Pools the disks of several machines into a single share.",
            body: "GlusterFS joins the storage of several ordinary servers into one filesystem, replicating or striping files across them so that losing a server does not lose data. It reuses the same ONC RPC framing NFS does, with its own program numbers, so its traffic looks structurally familiar but means something different.",
            look_for: "\"GlusterFS handshake\" when a client attaches to the cluster; \"GlusterFS\" calls carrying the file operations themselves.",
        },
        Protocol::Lwapp => Lesson {
            title: "LWAPP — access points on a leash",
            summary: "A wireless controller steering access points that cannot think for themselves.",
            body: "A thin access point has almost no intelligence of its own. It does not decide which clients to admit, which channel to use or how to hand a phone to the next radio — a central controller decides all of that for the whole site, and the access point simply does as it is told and forwards traffic back. LWAPP is that leash. CAPWAP later standardised the same idea, so LWAPP now mostly turns up in older installations that were never upgraded.",
            look_for: "\"LWAPP Discovery Request\" then \"Join Request\" when an access point comes online and finds its controller; \"WLAN Config Request\" when its wireless networks are pushed to it.",
        },
        Protocol::Twamp => Lesson {
            title: "TWAMP — proving a link is as fast as promised",
            summary: "The measurement behind a network service level agreement.",
            body: "When an operator sells a circuit with a latency and loss commitment, TWAMP is how both sides check it. The control channel on this port negotiates a test — which ports the probes will use, when to start, when to stop — and the probes themselves then run over UDP on whatever ports were agreed. That is why the control exchange is the part worth watching: the measurement traffic is on negotiated ports and hard to find, but the setup says a test is happening and whether it was accepted at all.",
            look_for: "\"TWAMP server greeting\" opening the conversation, then \"Request-TW-Session\" and \"Start-Sessions — accepted\" when a measurement begins; \"rejected\" when the far end refuses.",
        },
        Protocol::Slp => Lesson {
            title: "SLP — asking the network who offers what",
            summary: "Service discovery with no central directory.",
            body: "SLP lets a machine broadcast \"who here offers this service?\" and collect the answers, with no directory server needed. It is best known now for where it turns up rather than what it does: VMware ESXi exposes it, and because a small unauthenticated request can produce a large reply it became a favourite for traffic amplification, and in 2023 an entry point for a wave of ransomware. Seeing it answerable from an untrusted network is worth noticing.",
            look_for: "\"SLP Service Request — service:VMwareInfrastructure\" asking who offers a service; \"Service Reply\" and \"DA Advertisement\" answering.",
        },
        Protocol::CoapTcp => Lesson {
            title: "CoAP over TCP — the same IoT protocol, reframed",
            summary: "CoAP without the reliability machinery it needed on UDP.",
            body: "CoAP was built for UDP, where it has to provide its own message ids and acknowledgements because the transport does not. Over TCP all of that is redundant, so the framing was redesigned: no message id, no message type, and a length field in front instead. The methods and response codes are unchanged, so a GET is still a GET, but a parser written for the UDP form sees nothing it recognises. The TCP form also adds signalling codes that negotiate the connection itself, which have no equivalent on UDP.",
            look_for: "\"CoAP/TCP GET\" and \"2.05 Content\" for ordinary resource access; \"7.01 CSM (capabilities)\" when a connection opens.",
        },
        Protocol::Utp => Lesson {
            title: "µTP — file sharing that gets out of the way",
            summary: "BitTorrent's transport, designed to yield to everything else.",
            body: "Running BitTorrent over ordinary TCP is antisocial: TCP competes on equal terms with every other connection, so a few torrents will starve a video call sharing the same line. µTP was built to fix that. It runs over UDP with a congestion controller that watches how long packets are taking rather than waiting for loss, and backs off the moment a queue starts to build — so it fills spare capacity and steps aside when something interactive needs it. That matters when reading a capture: a link saturated by µTP is a different diagnosis from one saturated by TCP, because µTP is supposed to be giving way.",
            look_for: "\"µTP data — connection 4242, seq 7, 1000 bytes\" for a transfer in progress; a window of 0 means the receiving side has stopped accepting and the transfer has stalled.",
        },
        Protocol::Nflog => Lesson {
            title: "NFLOG — what the firewall decided, and why",
            summary: "A Linux firewall's own log of the packets it acted on.",
            body: "A firewall rule on Linux can hand a packet to a log group as well as dropping it, and a capture can read that group directly. What makes this more useful than watching the traffic itself is the prefix: whoever wrote the rule can attach a name to it, and that name travels with every packet the rule matches. So the capture does not only show that something was blocked — it names the rule that blocked it, which is the question anyone debugging a firewall actually has.",
            look_for: "\"NFLOG [DROP-INBOUND] · TCP Connection opened\" — the text in brackets is the rule's own label, followed by the packet it matched.",
        },
        Protocol::ZeroTier => Lesson {
            title: "ZeroTier — one network across many places",
            summary: "Makes machines in different buildings behave as if they share a switch.",
            body: "ZeroTier builds a virtual Ethernet network over the internet, so a laptop at home and a server in a data centre can behave as though they are plugged into the same switch. The contents are encrypted, but the header is not, and it carries the two ZeroTier node addresses — identifiers of their own, unrelated to any IP address — plus a hop count. That hop count is the useful part when a link feels slow: zero means the two nodes reached each other directly, and anything higher means traffic is being relayed through ZeroTier's infrastructure instead.",
            look_for: "\"ZeroTier deadbeef01 → cafebabe02 — direct\" for a peer-to-peer path; \"2 hops\" means it is being relayed.",
        },
        Protocol::Nebula => Lesson {
            title: "Nebula — a mesh that introduces itself",
            summary: "Hosts find each other through a lighthouse, then talk directly.",
            body: "Nebula avoids the usual VPN bottleneck of routing everything through a central hub. Hosts register with a lighthouse, which tells them where to find each other, and from then on they talk directly. The payload is encrypted but the message type is not, and that exposes the interesting failure: a pair that keeps exchanging handshakes without ever settling into ordinary messages has not managed to reach each other directly, usually because something between them is blocking it.",
            look_for: "\"Nebula message\" for a working tunnel; a run of \"Nebula handshake stage 1\" with no messages following means the direct connection never came up.",
        },
        Protocol::Bitcoin => Lesson {
            title: "Bitcoin — how nodes gossip a blockchain",
            summary: "Peers announcing what they have and fetching what they lack.",
            body: "A Bitcoin node has no central server to sync from. It connects to a handful of peers and they gossip: each announces what it has just heard about, and the others ask for anything they are missing. That is the rhythm you see — an announcement, a request, then the transaction or block itself. One field is worth reading on every line: the network magic. A node accidentally pointed at a test network behaves perfectly normally and looks healthy, and this is the only thing that gives it away.",
            look_for: "\"Bitcoin inv — announcing what it has\" followed by \"getdata\" and then \"tx\" or \"block\"; anything marked [testnet3] or [signet] is not on the real network.",
        },
        Protocol::MacControl => Lesson {
            title: "Ethernet PAUSE — the link asking for a moment",
            summary: "One end telling the other to stop sending, briefly.",
            body: "When a switch or network card runs short of buffer space it can send a PAUSE frame asking the far end to hold off for a moment. That makes these unusually valuable to spot, because the slowdown they cause is invisible from the application's point of view: nothing is lost, nothing is retransmitted, traffic is simply being held. A burst of PAUSE frames explains latency that otherwise looks inexplicable. The newer priority form pauses individual traffic classes rather than the whole link, which is how storage and general traffic can share one wire without one starving the other.",
            look_for: "\"Ethernet PAUSE — 65535 quanta\" asking for the longest possible hold; \"PAUSE — resume\" releasing it; \"Priority flow control — pausing class 3\" for one traffic class only.",
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
/// Every protocol paired with its lesson, for the education browser.
///
/// Derived from the registry rather than hand-listed — the old list had
/// drifted and was missing SMB, Kafka, AMQP, NTLM and TDS, whose lessons
/// existed but were unreachable from the index.
pub fn all_lessons() -> Vec<(Protocol, Lesson)> {
    Protocol::ALL
        .iter()
        .map(|p| (p.clone(), lesson(p)))
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
    // Specific events first: a DNS *query* reads differently from a DNS
    // *response*. Anything without a special case falls through to the
    // protocol's own one-liner, which lives in the registry.
    match pkt.protocol {
        Protocol::Dns if s.contains("Query") => {
            "Your device is asking a DNS server for the IP address behind a name."
        }
        Protocol::Dns if s.contains("Response") => {
            "The DNS server answered with the IP address for the name that was asked."
        }
        Protocol::Tls if s.contains("HTTPS") => {
            "The start of an encrypted visit to this site — the name is visible, the content isn't."
        }
        Protocol::Http if s.contains("GET") || s.contains("POST") => {
            "A web request sent in plain text — visible to anyone capturing."
        }
        ref other => other.blurb(),
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

    /// Despite its name this used to check eight protocols. Now it checks all
    /// of them, so a new registry row cannot ship with a placeholder lesson.
    #[test]
    fn every_protocol_has_a_nonempty_lesson() {
        for proto in Protocol::ALL.iter().chain([&Protocol::Unknown("x".into())]) {
            let l = lesson(proto);
            assert!(!l.title.is_empty(), "{proto:?} lesson has no title");
            assert!(!l.summary.is_empty(), "{proto:?} lesson has no summary");
            assert!(!l.body.is_empty(), "{proto:?} lesson has no body");
            assert!(!l.look_for.is_empty(), "{proto:?} lesson has no look_for");
        }
    }

    #[test]
    fn all_lessons_covers_every_protocol() {
        let lessons = all_lessons();
        assert_eq!(lessons.len(), Protocol::ALL.len());
        for p in Protocol::ALL {
            assert!(
                lessons.iter().any(|(q, _)| q == p),
                "{p:?} is missing from the lesson index"
            );
        }
    }

    /// Regression: SMB, Kafka, AMQP, NTLM and TDS had lessons that the
    /// hand-maintained index never listed, so they were unreachable.
    #[test]
    fn previously_unindexed_protocols_are_listed() {
        let lessons = all_lessons();
        for p in [
            Protocol::Smb,
            Protocol::Kafka,
            Protocol::Amqp,
            Protocol::Ntlm,
            Protocol::Tds,
        ] {
            assert!(lessons.iter().any(|(q, _)| *q == p), "{p:?} not indexed");
        }
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
