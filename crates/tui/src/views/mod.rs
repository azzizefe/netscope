// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
pub mod ai_traffic;
pub mod connections;
pub mod dashboard;
pub mod dns_log;
pub mod industrial_edge_ai;
pub mod insights;
pub mod learn;
pub mod packets;
pub mod pqc_wizard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Packets,
    Dashboard,
    Connections,
    DnsLog,
    Insights,
    Learn,
    AiTraffic,
    IndustrialEdgeAi,
    PqcWizard,
}

impl View {
    pub fn next(self) -> Self {
        match self {
            View::Packets => View::Dashboard,
            View::Dashboard => View::Connections,
            View::Connections => View::DnsLog,
            View::DnsLog => View::Insights,
            View::Insights => View::Learn,
            View::Learn => View::AiTraffic,
            View::AiTraffic => View::IndustrialEdgeAi,
            View::IndustrialEdgeAi => View::PqcWizard,
            View::PqcWizard => View::Packets,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            View::Packets => View::PqcWizard,
            View::Dashboard => View::Packets,
            View::Connections => View::Dashboard,
            View::DnsLog => View::Connections,
            View::Insights => View::DnsLog,
            View::Learn => View::Insights,
            View::AiTraffic => View::Learn,
            View::IndustrialEdgeAi => View::AiTraffic,
            View::PqcWizard => View::IndustrialEdgeAi,
        }
    }

    /// The tab titles, in `next()` order, for the tab strip.
    pub const ORDER: [View; 9] = [
        View::Packets,
        View::Dashboard,
        View::Connections,
        View::DnsLog,
        View::Insights,
        View::Learn,
        View::AiTraffic,
        View::IndustrialEdgeAi,
        View::PqcWizard,
    ];

    pub fn title(self) -> &'static str {
        match self {
            View::Packets => "Packets",
            View::Dashboard => "Dashboard",
            View::Connections => "Connections",
            View::DnsLog => "DNS Log",
            View::Insights => "Insights",
            View::Learn => "Learn",
            View::AiTraffic => "AI Traffic",
            View::IndustrialEdgeAi => "Edge AI",
            View::PqcWizard => "PQC Wizard",
        }
    }
}
