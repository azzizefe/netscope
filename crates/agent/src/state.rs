use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use reqwest::tls;
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::offline::OfflineBuffer;

#[derive(Clone)]
pub struct AgentState {
    pub config: AgentConfig,
    pub sensor_id: Arc<RwLock<Option<Uuid>>>,
    pub http_client: reqwest::Client,
    pub offline: Arc<RwLock<OfflineBuffer>>,
    pub capture_active: Arc<AtomicBool>,
    pub shutdown: Arc<AtomicBool>,
    local_db: Arc<RwLock<rusqlite::Connection>>,
}

impl AgentState {
    pub async fn new(config: AgentConfig) -> anyhow::Result<Self> {
        let mut tls_builder = tls::TlsConnector::builder()
            .danger_accept_invalid_certs(config.server.insecure_skip_verify);

        if let Some(ca) = &config.server.tls_ca {
            let cert = std::fs::read(ca)?;
            tls_builder.add_root_certificate(tls::Certificate::from_pem(&cert)?);
        }

        let mut client_builder = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(concat!("netscope-agent/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(config.server.connect_timeout_secs))
            .timeout(std::time::Duration::from_secs(config.server.request_timeout_secs));

        if let (Some(cert), Some(key)) = (&config.server.tls_cert, &config.server.tls_key) {
            let identity = tls::Identity::from_pkcs8_pem(
                &std::fs::read_to_string(cert)?,
                &std::fs::read_to_string(key)?,
            )?;
            client_builder = client_builder.identity(identity);
        }

        let http_client = client_builder.build()?;

        let db_dir = config.offline.db_path.clone()
            .unwrap_or_else(|| {
                let base = dirs_data_dir();
                base
            });
        std::fs::create_dir_all(&db_dir)?;

        let local_db_path = db_dir.join("agent.db");
        let local_db = rusqlite::Connection::open(&local_db_path)?;
        local_db.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS command_cache (
                id TEXT PRIMARY KEY,
                command TEXT NOT NULL,
                parameters TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            );"
        )?;

        let sensor_id = load_sensor_id(&local_db)?;

        let offline = OfflineBuffer::new(db_dir.join("buffer.db"), config.offline.max_disk_mb)?;

        Ok(Self {
            config,
            sensor_id: Arc::new(RwLock::new(sensor_id)),
            http_client,
            offline: Arc::new(RwLock::new(offline)),
            capture_active: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            local_db: Arc::new(RwLock::new(local_db)),
        })
    }

    pub fn save_sensor_id(&self, id: Uuid) {
        *self.sensor_id.write() = Some(id);
        if let Ok(db) = self.local_db.try_write() {
            let _ = db.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('sensor_id', ?1)",
                rusqlite::params![id.to_string()],
            );
        }
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
            anyhow::bail!("GET {}: HTTP {}", path, resp.status());
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
}

fn load_sensor_id(db: &rusqlite::Connection) -> anyhow::Result<Option<Uuid>> {
    let result: Result<String, _> = db.query_row(
        "SELECT value FROM meta WHERE key = 'sensor_id'",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(s) => Ok(Some(Uuid::parse_str(&s)?)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn dirs_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("netscope-agent")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/netscope-agent")
    }
}
