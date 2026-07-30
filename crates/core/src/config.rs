// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Layered configuration — a single, discoverable home for netscope's
//! user settings, shared by the TUI and desktop (ROADMAP §2.4).
//!
//! Everything lives under one directory:
//!
//! ```text
//! ~/.netscope/
//! ├── config.toml          # this file — global settings + paths below
//! ├── profiles/            # named overlays merged on top of config.toml
//! │   ├── http-analysis.toml
//! │   └── security.toml
//! ├── coloring-rules.toml  # user coloring rules (see crate::coloring)
//! ├── plugins/             # declarative protocol plugins (see crate::plugins)
//! │   └── redis.toml
//! └── geoip.mmdb           # offline GeoIP database
//! ```
//!
//! The location is `$NETSCOPE_CONFIG_DIR` when set (handy for tests and
//! portable installs), otherwise `~/.netscope` (`%USERPROFILE%\.netscope` on
//! Windows). Loading never fails: a missing or malformed `config.toml` yields
//! defaults, so the apps always start.
//!
//! `config.toml` fields (all optional):
//!
//! ```toml
//! [general]
//! resolve_hostnames = true    # passive DNS name resolution
//! profile = "security"        # profile applied on top (profiles/security.toml)
//!
//! [geoip]
//! database = "geoip.mmdb"     # offline MMDB; relative paths resolve to the config dir
//!
//! [coloring]
//! rules = "coloring-rules.toml"
//!
//! [plugins]
//! enabled = true
//! dir = "plugins"
//! ```
//!
//! # Profiles
//!
//! A profile is a partial `config.toml` stored as `profiles/<name>.toml`.
//! Whatever keys the profile sets win over the global file; everything else
//! falls through, so a profile only has to state its differences:
//!
//! ```toml
//! # profiles/security.toml — only overrides what it cares about
//! [general]
//! resolve_hostnames = false
//! ```
//!
//! The active profile comes from `$NETSCOPE_PROFILE`, falling back to the
//! `general.profile` key in `config.toml`. [`Config::load_profile`] applies
//! one explicitly, and [`Config::profiles`] lists what is available.

// Only `shift_rotations` uses this, and that is `cfg(not(target_arch =
// "wasm32"))` because the escalation module it returns types from is not built
// for wasm32 — so on that target the import is unused and warns. The host
// clippy job never sees it (it lints the host target only); the wasm32 build
// does.
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Environment variable that overrides the config directory location.
pub const CONFIG_DIR_ENV: &str = "NETSCOPE_CONFIG_DIR";

/// Environment variable that selects the active profile (wins over the
/// `general.profile` key in `config.toml`).
pub const PROFILE_ENV: &str = "NETSCOPE_PROFILE";

/// Resolve the config directory: `$NETSCOPE_CONFIG_DIR`, else `~/.netscope`.
/// Returns `None` only when neither the override nor a home directory exists.
pub fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    home_dir().map(|h| h.join(".netscope"))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(
            || match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
                (Some(drive), Some(path)) => {
                    let mut p = PathBuf::from(drive);
                    p.push(path);
                    Some(p)
                }
                _ => None,
            },
        );
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home.filter(|p| !p.as_os_str().is_empty())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct General {
    /// Resolve IP addresses to hostnames via passive DNS.
    pub resolve_hostnames: bool,
    /// Name of the profile applied on top of this file (empty = none).
    /// `$NETSCOPE_PROFILE` overrides it.
    pub profile: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            resolve_hostnames: true,
            profile: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Geoip {
    /// Path to an offline MaxMind `.mmdb` file. Empty means "no offline DB".
    pub database: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Coloring {
    /// Path to the coloring-rules file.
    pub rules: String,
}

impl Default for Coloring {
    fn default() -> Self {
        Self {
            rules: "coloring-rules.toml".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Plugins {
    pub enabled: bool,
    /// Directory holding `*.toml` protocol plugins, relative to the config dir.
    pub dir: String,
}

impl Default for Plugins {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: "plugins".into(),
        }
    }
}

/// Where alerts are delivered, on top of showing up in the UI.
///
/// Every field is optional and empty by default, and a channel counts as
/// configured only when the fields it actually needs are filled in — see
/// [`crate::notifications::NotificationConfig`], which this converts into.
/// Nothing is enabled implicitly: an unconfigured channel is simply never
/// contacted, which is why the SOC view can report each one's real state
/// instead of guessing.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Notifications {
    pub email_smtp_host: String,
    pub email_smtp_port: Option<u16>,
    pub email_from: String,
    pub email_to: String,
    pub email_username: String,
    pub email_password: String,
    /// `"starttls"` (default), `"implicit"` or `"none"`.
    ///
    /// Explicit rather than inferred from the port: a silent downgrade to
    /// plaintext is how credentials end up on the wire. `"none"` is allowed —
    /// a local relay on port 25 is a real deployment — but it has to be asked
    /// for by name.
    pub email_tls: String,

    pub slack_webhook_url: String,
    pub telegram_token: String,
    pub telegram_chat_id: String,

    pub syslog_host: String,
    pub syslog_port: Option<u16>,
}

impl Notifications {
    /// Convert into the engine's config, mapping empty strings to `None` so the
    /// engine's own "not configured" checks stay the single source of truth.
    ///
    /// Gated like the module it returns: `notifications` is
    /// `#[cfg(not(target_arch = "wasm32"))]` in `lib.rs` (it sends mail and
    /// opens sockets), so referring to it unconditionally broke the wasm32
    /// build of this crate — and with it the display-filter engine the desktop
    /// frontend loads.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn to_engine_config(&self) -> crate::notifications::NotificationConfig {
        fn opt(s: &str) -> Option<String> {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        crate::notifications::NotificationConfig {
            email_smtp_host: opt(&self.email_smtp_host),
            email_smtp_port: self.email_smtp_port,
            email_from: opt(&self.email_from),
            email_to: opt(&self.email_to),
            email_username: opt(&self.email_username),
            email_password: opt(&self.email_password),
            email_tls: opt(&self.email_tls),
            slack_webhook_url: opt(&self.slack_webhook_url),
            discord_webhook_url: None,
            custom_webhook_url: None,
            telegram_token: opt(&self.telegram_token),
            telegram_chat_id: opt(&self.telegram_chat_id),
            syslog_host: opt(&self.syslog_host),
            syslog_port: self.syslog_port,
        }
    }
}

/// One person in the on-call rotation.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OnCall {
    pub name: String,
    pub email: String,
    pub phone: String,
    /// PagerDuty routing key / Opsgenie API key, if that channel is used.
    pub integration_key: String,
}

/// Who gets woken up when an alert goes unacknowledged, and how fast.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Escalation {
    /// Off unless asked for: escalation pages people, so it never starts by
    /// itself just because a rotation happens to be listed.
    pub enabled: bool,
    /// The rotation, in order. Week *n* takes `oncall[n % len]` as primary and
    /// the next person as backup.
    pub oncall: Vec<OnCall>,
    /// Minutes at each step before handing up the chain: L1, L2, L3, CISO.
    /// Empty uses the engine's default (15 / 30 / 60 minutes).
    pub step_minutes: Vec<u64>,
}

impl Escalation {
    /// Expand the ordered rotation into the week-keyed map the engine wants.
    ///
    /// [`crate::escalation::EscalationEngine::get_on_call_for_time`] looks up
    /// the exact ISO week, so a literal config would need all 53 weeks spelled
    /// out or most of the year would have nobody on call — and the engine
    /// reports that as "Primary: None" rather than as an error. Rotating a
    /// short list across every week is what makes two names enough.
    ///
    /// Gated for the same reason as [`Notifications::to_engine_config`]: the
    /// `escalation` module is not built for wasm32.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn shift_rotations(&self) -> HashMap<u32, crate::escalation::ShiftRotation> {
        let people = &self.oncall;
        if people.is_empty() {
            return HashMap::new();
        }
        let to_user = |u: &OnCall| crate::escalation::OnCallUser {
            name: u.name.clone(),
            email: u.email.clone(),
            phone: u.phone.clone(),
            integration_key: {
                let k = u.integration_key.trim();
                if k.is_empty() {
                    None
                } else {
                    Some(k.to_string())
                }
            },
        };

        // ISO weeks run 1..=53.
        (1..=53u32)
            .map(|week| {
                let i = (week as usize - 1) % people.len();
                let backup = &people[(i + 1) % people.len()];
                (
                    week,
                    crate::escalation::ShiftRotation {
                        week_number: week,
                        primary_user: to_user(&people[i]),
                        // With one person listed they are their own backup;
                        // that is the honest reading of a one-person rotation.
                        backup_user: to_user(backup),
                    },
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub geoip: Geoip,
    pub coloring: Coloring,
    pub plugins: Plugins,
    pub notifications: Notifications,
    pub escalation: Escalation,
    /// Directory this config was loaded from — the anchor for relative paths.
    /// Skipped during deserialization; filled in by [`Config::load`].
    #[serde(skip)]
    dir: PathBuf,
    /// Name of the profile that was merged in, if any.
    #[serde(skip)]
    active_profile: String,
}

impl Config {
    /// Load configuration from the default directory, applying built-in
    /// defaults for anything unset and merging the active profile (from
    /// `$NETSCOPE_PROFILE` or `general.profile`) on top. Never fails — a
    /// missing or unparsable `config.toml` just yields defaults anchored at
    /// the config dir.
    pub fn load() -> Self {
        match config_dir() {
            Some(dir) => Self::load_from(&dir),
            None => Config::default(),
        }
    }

    /// Load from a specific directory (used by [`Config::load`] and tests).
    pub fn load_from(dir: &Path) -> Self {
        let base = read_toml_value(&dir.join("config.toml"));

        // Profile selection: env var wins, then the general.profile key.
        let profile = std::env::var(PROFILE_ENV)
            .ok()
            .filter(|p| !p.is_empty())
            .or_else(|| {
                base.as_ref()
                    .and_then(|v| {
                        v.get("general")?
                            .get("profile")?
                            .as_str()
                            .map(str::to_string)
                    })
                    .filter(|p| !p.is_empty())
            });

        match profile {
            Some(name) => Self::assemble(dir, base, Some(&name)),
            None => Self::assemble(dir, base, None),
        }
    }

    /// Load from a directory with an explicitly chosen profile, ignoring the
    /// `general.profile` key and `$NETSCOPE_PROFILE`.
    pub fn load_profile(dir: &Path, profile: &str) -> Self {
        let base = read_toml_value(&dir.join("config.toml"));
        Self::assemble(dir, base, Some(profile))
    }

    /// Merge the optional base value and optional profile overlay, then
    /// deserialize. Any step failing falls back gracefully.
    fn assemble(dir: &Path, base: Option<toml::Value>, profile: Option<&str>) -> Self {
        let mut merged = base;
        let mut applied = String::new();
        if let Some(name) = profile {
            if let Some(overlay) =
                read_toml_value(&dir.join("profiles").join(format!("{name}.toml")))
            {
                merged = Some(match merged {
                    Some(mut b) => {
                        deep_merge(&mut b, overlay);
                        b
                    }
                    None => overlay,
                });
                applied = name.to_string();
            }
        }
        let mut cfg = merged
            .and_then(|v| v.try_into::<Config>().ok())
            .unwrap_or_default();
        cfg.dir = dir.to_path_buf();
        cfg.active_profile = applied;
        cfg
    }

    /// The config directory itself.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Name of the profile merged into this config, if any.
    pub fn active_profile(&self) -> Option<&str> {
        (!self.active_profile.is_empty()).then_some(self.active_profile.as_str())
    }

    /// Names of the profiles available under `profiles/` (without the `.toml`
    /// extension), sorted. Missing directory yields an empty list.
    pub fn profiles(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.join("profiles"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("toml") {
                    p.file_stem().and_then(|s| s.to_str()).map(str::to_string)
                } else {
                    None
                }
            })
            .collect();
        names.sort();
        names
    }

    /// Resolve a possibly-relative path against the config directory. Absolute
    /// paths are returned unchanged.
    fn resolve(&self, p: &str) -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.dir.join(path)
        }
    }

    /// Absolute path to the offline GeoIP database, if one is configured.
    pub fn geoip_database_path(&self) -> Option<PathBuf> {
        (!self.geoip.database.is_empty()).then(|| self.resolve(&self.geoip.database))
    }

    /// Absolute path to the coloring-rules file.
    pub fn coloring_rules_path(&self) -> PathBuf {
        self.resolve(&self.coloring.rules)
    }

    /// Absolute path to the plugins directory (regardless of whether plugins
    /// are enabled — check [`Plugins::enabled`] separately).
    pub fn plugins_dir(&self) -> PathBuf {
        self.resolve(&self.plugins.dir)
    }
}

/// One user coloring rule from `coloring-rules.toml`: a hex colour (with or
/// without `#`) and a display-filter expression. Compiling the filter and the
/// colour is the UI's job — this type is just the stored form.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ColoringRule {
    pub color: String,
    pub filter: String,
}

#[derive(Debug, Default, Deserialize)]
struct ColoringRulesFile {
    #[serde(default, rename = "rule")]
    rules: Vec<ColoringRule>,
}

/// Parse coloring-rules text in either supported form:
///
/// ```toml
/// [[rule]]
/// color = "ef4444"
/// filter = 'tcp.flags.rst == 1'
/// ```
///
/// or the legacy one-rule-per-line format (`RRGGBB <display filter>`, `#`
/// comments). Unparseable lines are passed through with whatever colour word
/// they carry — the consumer validates colours and filters, so comments and
/// typos are dropped there, not here.
pub fn parse_coloring_rules(text: &str) -> Vec<ColoringRule> {
    if let Ok(file) = toml::from_str::<ColoringRulesFile>(text) {
        if !file.rules.is_empty() {
            return file.rules;
        }
    }
    text.lines()
        .filter_map(|line| {
            let (color, filter) = line.trim().split_once(char::is_whitespace)?;
            Some(ColoringRule {
                color: color.to_string(),
                filter: filter.trim().to_string(),
            })
        })
        .collect()
}

/// Read and parse a TOML file, returning `None` on any failure (missing file,
/// bad UTF-8, syntax error) — configuration loading must never abort startup.
fn read_toml_value(path: &Path) -> Option<toml::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    text.parse::<toml::Value>().ok()
}

/// Recursively merge `overlay` into `base`: tables merge key-by-key, any
/// other value type is replaced wholesale. This is what lets a profile state
/// only its differences.
fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(b), toml::Value::Table(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(slot) => deep_merge(slot, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (slot, v) => *slot = v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh temp config dir for a test, cleaned of any previous run.
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netscope-cfg-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn person(name: &str) -> OnCall {
        OnCall {
            name: name.into(),
            email: format!("{name}@example.com"),
            phone: String::new(),
            integration_key: String::new(),
        }
    }

    /// A short rotation has to cover the whole year.
    ///
    /// `EscalationEngine::get_on_call_for_time` looks up the exact ISO week and
    /// reports a miss as "Primary: None" rather than as an error, so a config
    /// listing two people would leave 51 weeks silently uncovered if the list
    /// were used literally. Every week must resolve to somebody.
    #[test]
    fn oncall_rotation_covers_every_iso_week() {
        let cfg = Escalation {
            enabled: true,
            oncall: vec![person("ayse"), person("mehmet")],
            step_minutes: vec![],
        };
        let rotations = cfg.shift_rotations();

        assert_eq!(rotations.len(), 53, "ISO years can have 53 weeks");
        for week in 1..=53u32 {
            let r = rotations
                .get(&week)
                .unwrap_or_else(|| panic!("week {week} uncovered"));
            assert!(
                !r.primary_user.name.is_empty(),
                "week {week} has no primary"
            );
            assert_ne!(
                r.primary_user.name, r.backup_user.name,
                "week {week} makes one person their own backup",
            );
        }

        // The list is walked in order, starting at week 1.
        assert_eq!(rotations[&1].primary_user.name, "ayse");
        assert_eq!(rotations[&2].primary_user.name, "mehmet");
        assert_eq!(rotations[&3].primary_user.name, "ayse");
        assert_eq!(rotations[&1].backup_user.name, "mehmet");
    }

    /// One name listed is a real answer: that person is always on call. It must
    /// not be mistaken for "nobody".
    #[test]
    fn a_single_person_rotation_still_covers_the_year() {
        let cfg = Escalation {
            enabled: true,
            oncall: vec![person("solo")],
            step_minutes: vec![],
        };
        let rotations = cfg.shift_rotations();
        assert_eq!(rotations.len(), 53);
        assert_eq!(rotations[&17].primary_user.name, "solo");
        assert_eq!(
            rotations[&17].backup_user.name, "solo",
            "with one person listed they back themselves up",
        );
    }

    #[test]
    fn no_oncall_listed_means_no_rotation() {
        let cfg = Escalation::default();
        assert!(cfg.shift_rotations().is_empty());
    }

    /// A blank integration key must read as absent — the engine branches on
    /// `Some(key)` to decide whether it can page PagerDuty at all.
    #[test]
    fn blank_integration_key_becomes_none() {
        let mut p = person("ayse");
        p.integration_key = "   ".into();
        let cfg = Escalation {
            enabled: true,
            oncall: vec![p.clone(), person("mehmet")],
            step_minutes: vec![],
        };
        assert!(cfg.shift_rotations()[&1]
            .primary_user
            .integration_key
            .is_none());

        let mut q = person("ayse");
        q.integration_key = "  R0UT1NG  ".into();
        let cfg = Escalation {
            enabled: true,
            oncall: vec![q, person("mehmet")],
            step_minutes: vec![],
        };
        assert_eq!(
            cfg.shift_rotations()[&1]
                .primary_user
                .integration_key
                .as_deref(),
            Some("R0UT1NG"),
            "whitespace must not reach the PagerDuty routing key",
        );
    }

    /// The whole `[escalation]` block has to survive a real TOML round-trip,
    /// since that is the only way anyone configures it.
    #[test]
    fn escalation_parses_from_toml() {
        let dir = temp_dir("escalation");
        std::fs::write(
            dir.join("config.toml"),
            r#"
[escalation]
enabled = true
step_minutes = [5, 10, 20]

[[escalation.oncall]]
name = "Ayşe"
email = "ayse@example.com"
integration_key = "R0UT1NG"

[[escalation.oncall]]
name = "Mehmet"
email = "mehmet@example.com"
"#,
        )
        .unwrap();

        let cfg = Config::load_from(&dir);
        assert!(cfg.escalation.enabled);
        assert_eq!(cfg.escalation.oncall.len(), 2);
        assert_eq!(cfg.escalation.oncall[0].name, "Ayşe");
        assert_eq!(cfg.escalation.step_minutes, vec![5, 10, 20]);
        assert_eq!(cfg.escalation.shift_rotations().len(), 53);
    }

    /// Escalation stays off unless asked for — it pages people.
    #[test]
    fn escalation_is_off_by_default() {
        let dir = temp_dir("escalation-default");
        let cfg = Config::load_from(&dir);
        assert!(!cfg.escalation.enabled);
        assert!(cfg.escalation.oncall.is_empty());
    }

    #[test]
    fn defaults_when_no_file() {
        let dir = std::env::temp_dir().join("netscope-cfg-none");
        let cfg = Config::load_from(&dir);
        assert!(cfg.general.resolve_hostnames);
        assert!(cfg.plugins.enabled);
        assert_eq!(cfg.geoip_database_path(), None);
        assert_eq!(cfg.coloring_rules_path(), dir.join("coloring-rules.toml"));
        assert_eq!(cfg.plugins_dir(), dir.join("plugins"));
        assert_eq!(cfg.active_profile(), None);
    }

    #[test]
    fn parses_and_resolves_paths() {
        let text = r#"
            [general]
            resolve_hostnames = false

            [geoip]
            database = "db/GeoLite2-City.mmdb"

            [plugins]
            enabled = false
        "#;
        let mut cfg: Config = toml::from_str(text).unwrap();
        cfg.dir = PathBuf::from("/home/u/.netscope");
        assert!(!cfg.general.resolve_hostnames);
        assert!(!cfg.plugins.enabled);
        assert_eq!(
            cfg.geoip_database_path(),
            Some(PathBuf::from("/home/u/.netscope/db/GeoLite2-City.mmdb"))
        );
        // Unset section keeps its default.
        assert_eq!(cfg.coloring.rules, "coloring-rules.toml");
    }

    #[test]
    fn absolute_paths_are_kept() {
        let mut cfg = Config {
            dir: PathBuf::from("/cfg"),
            ..Default::default()
        };
        cfg.geoip.database = if cfg!(windows) {
            "C:/data/geo.mmdb".into()
        } else {
            "/data/geo.mmdb".into()
        };
        let p = cfg.geoip_database_path().unwrap();
        assert!(p.is_absolute());
        assert!(p.ends_with("geo.mmdb"));
    }

    #[test]
    fn env_override_is_honored() {
        // Set the override, resolve, then restore to avoid cross-test leakage.
        let prev = std::env::var_os(CONFIG_DIR_ENV);
        std::env::set_var(CONFIG_DIR_ENV, "/tmp/ns-override");
        assert_eq!(config_dir(), Some(PathBuf::from("/tmp/ns-override")));
        match prev {
            Some(v) => std::env::set_var(CONFIG_DIR_ENV, v),
            None => std::env::remove_var(CONFIG_DIR_ENV),
        }
    }

    #[test]
    fn profile_overrides_only_what_it_sets() {
        let dir = temp_dir("profile-merge");
        std::fs::write(
            dir.join("config.toml"),
            "[general]\nresolve_hostnames = true\n\n[geoip]\ndatabase = \"geo.mmdb\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("profiles")).unwrap();
        std::fs::write(
            dir.join("profiles/security.toml"),
            "[general]\nresolve_hostnames = false\n",
        )
        .unwrap();

        let cfg = Config::load_profile(&dir, "security");
        // Overridden by the profile:
        assert!(!cfg.general.resolve_hostnames);
        // Inherited from the base file:
        assert_eq!(cfg.geoip.database, "geo.mmdb");
        assert_eq!(cfg.active_profile(), Some("security"));
    }

    #[test]
    fn profile_key_in_config_is_applied_on_load() {
        let dir = temp_dir("profile-key");
        std::fs::write(dir.join("config.toml"), "[general]\nprofile = \"quiet\"\n").unwrap();
        std::fs::create_dir_all(dir.join("profiles")).unwrap();
        std::fs::write(
            dir.join("profiles/quiet.toml"),
            "[plugins]\nenabled = false\n",
        )
        .unwrap();

        let cfg = Config::load_from(&dir);
        assert!(!cfg.plugins.enabled);
        assert_eq!(cfg.active_profile(), Some("quiet"));
    }

    #[test]
    fn missing_profile_falls_back_to_base() {
        let dir = temp_dir("profile-missing");
        std::fs::write(dir.join("config.toml"), "[geoip]\ndatabase = \"x.mmdb\"\n").unwrap();
        let cfg = Config::load_profile(&dir, "does-not-exist");
        assert_eq!(cfg.geoip.database, "x.mmdb");
        assert_eq!(cfg.active_profile(), None);
    }

    #[test]
    fn coloring_rules_toml_form() {
        let rules = parse_coloring_rules(
            "[[rule]]\ncolor = \"ef4444\"\nfilter = 'tcp.flags.rst == 1'\n\n\
             [[rule]]\ncolor = \"#a78bfa\"\nfilter = 'dns || mdns'\n",
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].color, "ef4444");
        assert_eq!(rules[1].filter, "dns || mdns");
    }

    #[test]
    fn coloring_rules_legacy_line_form() {
        let rules = parse_coloring_rules(
            "# comment\n\
             ef4444 info contains \"reset\"\n\
             a78bfa dns\n",
        );
        // The comment line comes through as color "#"; consumers drop it when
        // the colour fails to parse.
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[1].color, "ef4444");
        assert_eq!(rules[2].filter, "dns");
    }

    #[test]
    fn profiles_are_listed_sorted() {
        let dir = temp_dir("profile-list");
        std::fs::create_dir_all(dir.join("profiles")).unwrap();
        std::fs::write(dir.join("profiles/b.toml"), "").unwrap();
        std::fs::write(dir.join("profiles/a.toml"), "").unwrap();
        std::fs::write(dir.join("profiles/readme.txt"), "").unwrap();
        let cfg = Config::load_from(&dir);
        assert_eq!(cfg.profiles(), vec!["a".to_string(), "b".to_string()]);
    }
}
