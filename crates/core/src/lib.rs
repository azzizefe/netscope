// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

// What is gated below is what needs something wasm does not have: a socket, a
// thread, a subprocess, a file, a database. Everything else builds everywhere.
//
// Five of these gates were on the wrong module, and the result was that
// `netscope-core` did not compile for wasm32 at all — so neither did
// `netscope-wasm`, and CI's `frontend` job failed before reaching the tests it
// exists to run. `registry` and `ai_traffic` were gated out while `models`,
// `flows`, `education` and `stats` used them unconditionally; `api_server`,
// `remote` and `discover` were left ungated while depending on `capture`,
// `db`, `pipeline` and `pcap`, which are correctly gated.
pub mod ai_traffic;
pub mod baseline;
// Gated because it exports alerts through `siem`, which is itself gated.
#[cfg(not(target_arch = "wasm32"))]
pub mod alerting;
#[cfg(not(target_arch = "wasm32"))]
pub mod api_server;
#[cfg(not(target_arch = "wasm32"))]
pub mod capture;
pub mod config;
pub mod crypto;
#[cfg(not(target_arch = "wasm32"))]
pub mod db;
#[cfg(not(target_arch = "wasm32"))]
pub mod discover;
pub mod dissectors;
#[cfg(not(target_arch = "wasm32"))]
pub mod editcap;
pub mod education;
// `escalation` and `notifications` both reach the network through `ureq`, a
// blocking HTTP client that is not built for wasm32 and is declared only for
// the other targets.
#[cfg(not(target_arch = "wasm32"))]
pub mod escalation;
pub mod expert;
#[cfg(not(target_arch = "wasm32"))]
pub mod export;
pub mod fieldbus;
pub mod filter;
pub mod firewall;
pub mod flows;
#[cfg(not(target_arch = "wasm32"))]
pub mod forensics;
#[cfg(not(target_arch = "wasm32"))]
pub mod formats;
pub mod game_plugins;
pub mod industrial_edge;
pub mod llm_analytics;
pub mod models;
pub mod names;
#[cfg(not(target_arch = "wasm32"))]
pub mod notifications;
pub mod opc_ua_traffic;
pub mod pair_correlation;
#[cfg(not(target_arch = "wasm32"))]
pub mod pcapng;
#[cfg(not(target_arch = "wasm32"))]
pub mod pipeline;
pub mod plugins;
pub mod pqc_analytics;
pub mod pqc_dashboard;
pub mod pqc_handshake;
pub mod pqc_rules;
pub mod pqc_wizard;
pub mod protocol_risk;
pub mod registry;
#[cfg(not(target_arch = "wasm32"))]
pub mod remote;
#[cfg(not(target_arch = "wasm32"))]
pub mod rotate;
#[cfg(not(target_arch = "wasm32"))]
pub mod siem;
pub mod stats;
#[cfg(not(target_arch = "wasm32"))]
pub mod stream;
pub mod threat;
pub mod tls_keylog;
