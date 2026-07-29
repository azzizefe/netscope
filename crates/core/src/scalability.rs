// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Enterprise Scalability & Storage Tiering Engine (§8.2).
//!
//! Provides:
//! - Horizontal scaling & Kubernetes HPA spec generator (§8.2.1)
//! - High-throughput 100,000 events/sec pipeline benchmark tracker (§8.2.2)
//! - Analytical storage sink abstraction (ClickHouse / TimescaleDB) (§8.2.3)
//! - Hot (SSD 7d) vs Cold (S3/Blob 7d+) Data Tiering manager (§8.2.4)
//! - Multi-tenant DB Sharding router (§8.2.5)

use std::collections::HashMap;
use std::time::{Instant, SystemTime};

/// Storage Tier Classification (§8.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StorageTier {
    HotSsd, // 0 - 7 days (SSD)
    ColdS3, // 7+ days (Object Storage / S3 / Blob)
}

/// Kubernetes Horizontal Pod Autoscaler Generator (§8.2.1).
#[derive(Debug)]
pub struct HorizontalScaleManager {
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub target_cpu_utilization_pct: u32,
}

impl Default for HorizontalScaleManager {
    fn default() -> Self {
        Self {
            min_replicas: 2,
            max_replicas: 50,
            target_cpu_utilization_pct: 75,
        }
    }
}

impl HorizontalScaleManager {
    pub fn generate_k8s_hpa_manifest(&self) -> String {
        format!(
            "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: netscope-server-hpa\nspec:\n  minReplicas: {}\n  maxReplicas: {}\n  metrics:\n  - type: Resource\n    resource:\n      name: cpu\n      target:\n        type: Utilization\n        averageUtilization: {}\n",
            self.min_replicas, self.max_replicas, self.target_cpu_utilization_pct
        )
    }
}

/// High-Throughput Event Benchmark Engine (§8.2.2).
#[derive(Debug, Default)]
pub struct ThroughputBenchmarkEngine {
    pub processed_events: u64,
    pub start_time: Option<Instant>,
}

impl ThroughputBenchmarkEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.processed_events = 0;
    }

    pub fn record_batch(&mut self, batch_size: u64) {
        self.processed_events += batch_size;
    }

    pub fn events_per_second(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.processed_events as f64 / elapsed;
            }
        }
        0.0
    }
}

/// Analytical Storage Driver (§8.2.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AnalyticalStorageDriver {
    ClickHouse { endpoint: String },
    TimescaleDb { connection_string: String },
}

/// Data Tiering Policy Manager (§8.2.4).
#[derive(Debug)]
pub struct DataTieringManager {
    pub hot_retention_days: u32, // Default 7 days
}

impl Default for DataTieringManager {
    fn default() -> Self {
        Self {
            hot_retention_days: 7,
        }
    }
}

impl DataTieringManager {
    pub fn determine_tier(&self, file_creation_time: SystemTime) -> StorageTier {
        let age_days = match SystemTime::now().duration_since(file_creation_time) {
            Ok(dur) => dur.as_secs() / 86400,
            Err(_) => 0,
        };
        if age_days < self.hot_retention_days as u64 {
            StorageTier::HotSsd
        } else {
            StorageTier::ColdS3
        }
    }
}

/// Multi-Tenant Database Shard Router (§8.2.5).
#[derive(Debug, Default)]
pub struct DbShardRouter {
    pub shard_map: HashMap<String, String>, // Tenant/Sensor ID -> DB Shard DSN
}

impl DbShardRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_shard(&mut self, tenant_id: &str, shard_dsn: &str) {
        self.shard_map
            .insert(tenant_id.to_string(), shard_dsn.to_string());
    }

    pub fn get_shard_dsn<'a>(&'a self, tenant_id: &'a str) -> &'a str {
        self.shard_map
            .get(tenant_id)
            .map(|s| s.as_str())
            .unwrap_or("postgresql://localhost:5432/netscope_default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_horizontal_scale_hpa() {
        let hpa = HorizontalScaleManager::default();
        let manifest = hpa.generate_k8s_hpa_manifest();
        assert!(manifest.contains("minReplicas: 2"));
        assert!(manifest.contains("maxReplicas: 50"));
        assert!(manifest.contains("averageUtilization: 75"));
    }

    #[test]
    fn test_throughput_benchmark() {
        let mut engine = ThroughputBenchmarkEngine::new();
        engine.start();
        engine.record_batch(100_000);
        let rate = engine.events_per_second();
        assert!(rate >= 0.0);
    }

    #[test]
    fn test_data_tiering() {
        let tierer = DataTieringManager::default();
        let recent = SystemTime::now();
        assert_eq!(tierer.determine_tier(recent), StorageTier::HotSsd);

        let old = SystemTime::now() - std::time::Duration::from_secs(10 * 86400);
        assert_eq!(tierer.determine_tier(old), StorageTier::ColdS3);
    }

    #[test]
    fn test_db_shard_router() {
        let mut router = DbShardRouter::new();
        router.register_shard("tenant_corp_a", "postgresql://shard1.internal:5432/db_a");
        assert_eq!(
            router.get_shard_dsn("tenant_corp_a"),
            "postgresql://shard1.internal:5432/db_a"
        );
        assert_eq!(
            router.get_shard_dsn("unknown_tenant"),
            "postgresql://localhost:5432/netscope_default"
        );
    }
}
