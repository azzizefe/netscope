// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
pub mod connections;
pub mod dashboard;
pub mod dns_log;
pub mod insights;
pub mod learn;
pub mod packets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Packets,
    Dashboard,
    Connections,
    DnsLog,
    Insights,
    Learn,
}

impl View {
    pub fn next(self) -> Self {
        match self {
            View::Packets => View::Dashboard,
            View::Dashboard => View::Connections,
            View::Connections => View::DnsLog,
            View::DnsLog => View::Insights,
            View::Insights => View::Learn,
            View::Learn => View::Packets,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            View::Packets => View::Learn,
            View::Dashboard => View::Packets,
            View::Connections => View::Dashboard,
            View::DnsLog => View::Connections,
            View::Insights => View::DnsLog,
            View::Learn => View::Insights,
        }
    }

    /// The tab titles, in `next()` order, for the tab strip.
    pub const ORDER: [View; 6] = [
        View::Packets,
        View::Dashboard,
        View::Connections,
        View::DnsLog,
        View::Insights,
        View::Learn,
    ];

    pub fn title(self) -> &'static str {
        match self {
            View::Packets => "Packets",
            View::Dashboard => "Dashboard",
            View::Connections => "Connections",
            View::DnsLog => "DNS Log",
            View::Insights => "Insights",
            View::Learn => "Learn",
        }
    }
}
