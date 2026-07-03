pub mod connections;
pub mod dashboard;
pub mod dns_log;
pub mod learn;
pub mod packets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Packets,
    Dashboard,
    Connections,
    DnsLog,
    Learn,
}

impl View {
    pub fn next(self) -> Self {
        match self {
            View::Packets => View::Dashboard,
            View::Dashboard => View::Connections,
            View::Connections => View::DnsLog,
            View::DnsLog => View::Learn,
            View::Learn => View::Packets,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            View::Packets => View::Learn,
            View::Dashboard => View::Packets,
            View::Connections => View::Dashboard,
            View::DnsLog => View::Connections,
            View::Learn => View::DnsLog,
        }
    }
}
