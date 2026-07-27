use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::offline::OfflineBuffer;

#[derive(Clone)]
pub struct AgentState {
    pub config: AgentConfig,
    pub sensor_id: Arc<RwLock<Option<Uuid>>>,
    pub http_client: reqwest::Client,
    pub offline: Arc<Mutex<OfflineBuffer>>,
    pub capture_active: Arc<AtomicBool>,
    pub shutdown: Arc<AtomicBool>,
    data_dir: PathBuf,
}

impl AgentState {
    pub async fn new(config: AgentConfig) -> anyhow::Result<Self> {
        let mut client_builder = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(concat!("netscope-agent/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(config.server.connect_timeout_secs))
            .timeout(std::time::Duration::from_secs(config.server.request_timeout_secs));

        if let (Some(cert_path), Some(key_path)) = (&config.server.tls_cert, &config.server.tls_key) {
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

        let data_dir = config.offline.db_path.clone()
            .unwrap_or_else(default_data_dir);
        std::fs::create_dir_all(&data_dir)?;

        let sensor_id = load_sensor_id(&data_dir)?;
        let buffer_path = data_dir.join("buffer.db");
        let offline = OfflineBuffer::new(&buffer_path, config.offline.max_disk_mb)?;

        Ok(Self {
            config,
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

    pub async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let url = format!("{}{}", self.config.server.url, path);
        let mut req = self.http_client.get(&url);
        if !self.config.server.auth_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.config.server.auth_token));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self, path: &str, body: &T,
    ) -> anyhow::Result<R> {
        let url = format!("{}{}", self.config.server.url, path);
        let mut req = self.http_client.post(&url).json(body);
        if !self.config.server.auth_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.config.server.auth_token));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_put<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self, path: &str, body: &T,
    ) -> anyhow::Result<R> {
        let url = format!("{}{}", self.config.server.url, path);
        let mut req = self.http_client.put(&url).json(body);
        if !self.config.server.auth_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.config.server.auth_token));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT {}: {}", path, text);
        }
        Ok(resp.json().await?)
    }

    pub async fn http_post_raw(&self, path: &str, body: Vec<u8>, content_type: &str) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}{}", self.config.server.url, path);
        let mut req = self.http_client.post(&url)
            .header("Content-Type", content_type)
            .body(body);
        if !self.config.server.auth_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.config.server.auth_token));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {}: {}", path, text);
        }
        Ok(resp)
    }

    pub fn current_binary_sha256(&self) -> String {
        use sha2::{Digest, Sha256};
        let path = std::env::current_exe().unwrap_or_default();
        if let Ok(data) = std::fs::read(&path) {
            format!("{:x}", Sha256::digest(&data))
        } else {
            String::new()
        }
    }
}

fn load_sensor_id(data_dir: &PathBuf) -> anyhow::Result<Option<Uuid>> {
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
