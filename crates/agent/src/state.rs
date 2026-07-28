use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::offline::OfflineBuffer;

#[derive(Clone)]
pub struct AgentState {
    pub config: Arc<RwLock<AgentConfig>>,
    pub config_path: PathBuf,
    pub sensor_id: Arc<RwLock<Option<Uuid>>>,
    pub http_client: reqwest::Client,
    pub offline: Arc<Mutex<OfflineBuffer>>,
    pub capture_active: Arc<AtomicBool>,
    pub shutdown: Arc<AtomicBool>,
    data_dir: PathBuf,
}

impl AgentState {
    pub async fn new(config: AgentConfig, config_path: PathBuf) -> anyhow::Result<Self> {
        let mut client_builder = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(concat!("netscope-agent/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(
                config.server.connect_timeout_secs,
            ))
            .timeout(std::time::Duration::from_secs(
                config.server.request_timeout_secs,
            ));

        if let (Some(cert_path), Some(key_path)) = (&config.server.tls_cert, &config.server.tls_key)
        {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let mut combined = cert_pem;
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)?;
            client_builder = client_builder.identity(identity);
        }

        if config.server.insecure_skip_verify {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let http_client = client_builder.build()?;

        let data_dir = config
            .offline
            .db_path
            .clone()
            .unwrap_or_else(default_data_dir);
        std::fs::create_dir_all(&data_dir)?;

        let sensor_id = load_sensor_id(&data_dir)?;
        let buffer_path = data_dir.join("buffer.db");
        let offline = OfflineBuffer::new(&buffer_path, config.offline.max_disk_mb)?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
            sensor_id: Arc::new(RwLock::new(sensor_id)),
            http_client,
            offline: Arc::new(Mutex::new(offline)),
            capture_active: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            data_dir,
        })
    }

    pub fn save_sensor_id(&self, id: Uuid) {
        *self.sensor_id.write() = Some(id);
        let path = self.data_dir.join("sensor_id");
        let _ = std::fs::write(&path, id.to_string());
    }

    pub fn get_sensor_id(&self) -> Option<Uuid> {
        *self.sensor_id.read()
    }

    pub fn update_config(&self, new_toml: &str) -> anyhow::Result<()> {
        let overlay: toml::Value = new_toml.parse()?;
        let mut base = if self.config_path.exists() {
            let base_text = std::fs::read_to_string(&self.config_path)?;
            base_text.parse::<toml::Value>().unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
        } else {
            toml::Value::Table(toml::map::Map::new())
        };

        fn deep_merge_values(base_val: &mut toml::Value, overlay_val: toml::Value) {
            match (base_val, overlay_val) {
                (toml::Value::Table(b), toml::Value::Table(o)) => {
                    for (k, v) in o {
                        match b.get_mut(&k) {
                            Some(slot) => deep_merge_values(slot, v),
                            None => {
                                b.insert(k, v);
                            }
                        }
                    }
                }
                (slot, v) => *slot = v,
            }
        }
        deep_merge_values(&mut base, overlay);

        let new_config: AgentConfig = base.clone().try_into()?;
        let merged_toml_text = toml::to_string(&base)?;

        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.config_path, merged_toml_text)?;
        tracing::info!("Successfully persisted updated config to {:?}", self.config_path);

        *self.config.write() = new_config;
        tracing::info!("Applied updated configuration in-memory.");

        Ok(())
    }

    pub async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let url = format!("{}{}", self.config.read().server.url, path);
        let mut req = self.http_client.get(&url);
        if !self.config.read().server.auth_token.is_empty() {
            req = req.header(
                "Authorization",
                format!("Bearer {}", self.config.read().server.auth_token),
            );
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> anyhow::Result<R> {
        let url = format!("{}{}", self.config.read().server.url, path);
        let mut req = self.http_client.post(&url).json(body);
        if !self.config.read().server.auth_token.is_empty() {
            req = req.header(
                "Authorization",
                format!("Bearer {}", self.config.read().server.auth_token),
            );
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_put<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> anyhow::Result<R> {
        let url = format!("{}{}", self.config.read().server.url, path);
        let mut req = self.http_client.put(&url).json(body);
        if !self.config.read().server.auth_token.is_empty() {
            req = req.header(
                "Authorization",
                format!("Bearer {}", self.config.read().server.auth_token),
            );
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_post_raw(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}{}", self.config.read().server.url, path);
        let mut req = self
            .http_client
            .post(&url)
            .header("Content-Type", content_type)
            .body(body);
        if !self.config.read().server.auth_token.is_empty() {
            req = req.header(
                "Authorization",
                format!("Bearer {}", self.config.read().server.auth_token),
            );
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {}: {}", path, text);
        }
        Ok(resp)
    }
}

fn load_sensor_id(data_dir: &Path) -> anyhow::Result<Option<Uuid>> {
    let path = data_dir.join("sensor_id");
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(Some(Uuid::parse_str(content.trim())?))
}

fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("netscope-agent")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/netscope-agent")
    }
    #[cfg(target_os = "macos")]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/Library/Application Support"))
            .join("netscope-agent")
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/netscope-agent")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_config_merging_and_persisting() {
        let temp_dir = std::env::temp_dir().join(format!("netscope-agent-state-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("agent.toml");

        std::fs::write(&config_path, r#"
        [heartbeat]
        interval_secs = 15
        [events]
        batch_max_events = 100
        "#).unwrap();

        let base_config = AgentConfig {
            heartbeat: crate::config::HeartbeatConfig { interval_secs: 15 },
            events: crate::config::EventConfig {
                batch_max_events: 100,
                batch_interval_ms: 500,
                compression: true,
            },
            ..Default::default()
        };

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let state = rt.block_on(async {
            AgentState::new(base_config, config_path.clone()).await.unwrap()
        });

        assert_eq!(state.config.read().heartbeat.interval_secs, 15);
        assert_eq!(state.config.read().events.batch_max_events, 100);

        state.update_config(r#"
        [heartbeat]
        interval_secs = 30
        "#).unwrap();

        assert_eq!(state.config.read().heartbeat.interval_secs, 30);
        assert_eq!(state.config.read().events.batch_max_events, 100);

        let file_text = std::fs::read_to_string(&config_path).unwrap();
        assert!(file_text.contains("interval_secs = 30"));
        assert!(file_text.contains("batch_max_events = 100"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
