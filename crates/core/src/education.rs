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
            look_for: "\"TLS — github.com (HTTPS)\" reveals the site; \"TLS — 1360 bytes of encrypted data\" is content you can't read.",
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

/// Every protocol lesson, in a sensible teaching order.
pub fn all_lessons() -> Vec<Lesson> {
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
        Protocol::Unknown(String::new()),
    ]
    .iter()
    .map(lesson)
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
            data: Vec::new(),
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
        assert_eq!(all_lessons().len(), 14);
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
