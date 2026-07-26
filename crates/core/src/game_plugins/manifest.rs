use std::collections::HashMap;

use serde::Deserialize;

/// A plugin.toml manifest that declares a game engine dissector plugin.
///
/// ```toml
/// [plugin]
/// name = "unreal-engine"
/// version = "1.0.0"
/// author = "netscope-community"
/// description = "Unreal Engine 4/5 game traffic dissector"
/// engines = ["Unreal Engine 5.4", "Unreal Engine 5.5"]
///
/// [[protocol]]
/// name = "Iris"
/// transport = "udp"
/// ports = [7777, 27015]
/// heuristics = ["iris_bunch_magic"]
///
/// [dependencies]
/// "unreal-core" = ">=1.0"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GamePluginManifest {
    #[serde(rename = "plugin")]
    pub plugin: PluginMeta,
    #[serde(default, rename = "protocol")]
    pub protocols: Vec<ProtocolDecl>,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub engines: Vec<String>,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub repository: String,
    /// Paths to test pcap files bundled with this plugin.
    #[serde(default)]
    pub test_pcaps: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolDecl {
    pub name: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub heuristics: Vec<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub description: String,
}

impl GamePluginManifest {
    pub fn parse(toml_text: &str) -> Result<Self, String> {
        toml::from_str(toml_text).map_err(|e| format!("manifest parse error: {e}"))
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.plugin.name.is_empty() {
            errors.push("plugin.name is required".into());
        }
        if self.plugin.version.is_empty() {
            errors.push("plugin.version is required".into());
        }
        if self.protocols.is_empty() {
            errors.push("at least one [[protocol]] is required".into());
        }

        let name_chars: &[char] = &['/', '\\', ':', ' ', '\t', '\n'];
        if self.plugin.name.contains(name_chars) {
            errors.push(format!(
                "plugin.name contains invalid characters: '{}'",
                self.plugin.name
            ));
        }

        for (i, proto) in self.protocols.iter().enumerate() {
            if proto.name.is_empty() {
                errors.push(format!("protocol[{}].name is required", i));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_unreal_manifest() {
        let toml = r#"
[plugin]
name = "unreal-engine"
version = "1.0.0"
author = "netscope-community"
description = "Unreal Engine 4/5 dissector"
engines = ["Unreal Engine 5.4", "Unreal Engine 5.5"]

[[protocol]]
name = "UnrealIris"
transport = "udp"
ports = [7777, 27015]
heuristics = ["iris_bunch_magic"]

[[protocol]]
name = "UnrealReplicationGraph"
transport = "udp"
ports = [7777]
heuristics = ["rep_graph_header"]
"#;
        let m = GamePluginManifest::parse(toml).unwrap();
        assert_eq!(m.plugin.name, "unreal-engine");
        assert_eq!(m.plugin.version, "1.0.0");
        assert_eq!(m.protocols.len(), 2);
        assert_eq!(m.protocols[0].name, "UnrealIris");
        assert_eq!(m.protocols[0].ports, vec![7777, 27015]);
    }

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[plugin]
name = "godot"
version = "0.1.0"
author = "godot-community"

[[protocol]]
name = "GodotENet"
transport = "udp"
ports = [14000]
"#;
        let m = GamePluginManifest::parse(toml).unwrap();
        assert_eq!(m.plugin.name, "godot");
        assert_eq!(m.protocols[0].name, "GodotENet");
    }

    #[test]
    fn validate_rejects_empty_name() {
        let toml = r#"
[plugin]
name = ""
version = "1.0.0"

[[protocol]]
name = "Test"
"#;
        let m = GamePluginManifest::parse(toml).unwrap();
        let result = m.validate();
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_slash_in_name() {
        let toml = r#"
[plugin]
name = "unreal/engine"
version = "1.0.0"

[[protocol]]
name = "Test"
"#;
        let m = GamePluginManifest::parse(toml).unwrap();
        let result = m.validate();
        assert!(result.is_err());
    }
}
