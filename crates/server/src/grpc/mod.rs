pub mod proto;

use sqlx::PgPool;
use std::sync::Arc;
use tonic::{async_trait, Request, Response, Status, Streaming};
use uuid::Uuid;

use self::proto::sensor_service_server::{SensorService, SensorServiceServer};
use self::proto::*;
use crate::cache::CacheLayer;
use crate::db::models::{Event, RegisterSensor};
use crate::db::queries;

#[derive(Clone)]
pub struct SensorGrpcService {
    pool: PgPool,
    cache: Option<Arc<CacheLayer>>,
}

#[async_trait]
impl SensorService for SensorGrpcService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let ip: std::net::IpAddr = req
            .ip_address
            .parse()
            .map_err(|_| Status::invalid_argument("invalid ip_address"))?;

        let sensor = RegisterSensor {
            hostname: req.hostname,
            // Parsed above purely to reject junk; stored in its normalised
            // form so the same address always writes the same string.
            ip_address: ip.to_string(),
            os: if req.os.is_empty() {
                None
            } else {
                Some(req.os)
            },
            version: req.version,
            interfaces: Vec::new(),
            cpu_cores: None,
            ram_mb: None,
        };

        let sensor = queries::register_sensor(&self.pool, &sensor)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RegisterResponse {
            sensor_id: sensor.id.to_string(),
            status: "registered".into(),
        }))
    }

    async fn send_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        let sensor_id = Uuid::parse_str(&req.sensor_id)
            .map_err(|_| Status::invalid_argument("invalid sensor_id"))?;

        let hb = crate::db::models::SensorHeartbeat {
            id: 0,
            sensor_id,
            cpu_load_pct: Some(req.cpu_load_pct),
            ram_used_mb: Some(req.ram_used_mb),
            capture_throughput_bps: Some(req.capture_throughput_bps),
            uptime_secs: Some(req.uptime_secs),
            disk_free_mb: Some(req.disk_free_mb),
            interface_stats: None,
            received_at: chrono::Utc::now(),
        };

        queries::update_sensor_heartbeat(&self.pool, sensor_id, &hb)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if let Some(ref cache) = self.cache {
            let key = format!("sensor:heartbeat:{}", sensor_id);
            let hb_json = serde_json::json!({
                "cpu_load_pct": req.cpu_load_pct,
                "ram_used_mb": req.ram_used_mb,
                "capture_throughput_bps": req.capture_throughput_bps,
                "uptime_secs": req.uptime_secs,
                "disk_free_mb": req.disk_free_mb,
            });
            if let Ok(hb_str) = serde_json::to_string(&hb_json) {
                let _ = cache.set_ttl(&key, hb_str, 60).await;
            }
        }

        Ok(Response::new(HeartbeatResponse { acknowledged: true }))
    }

    /// Client-streaming: the sensor pushes events until it closes the stream,
    /// and the single reply says how many were accepted. The proto declares one
    /// `EventSummary`, not a stream of them, so the whole stream is drained here
    /// rather than handed to a spawned task — the caller is waiting for a count
    /// that only exists once the last event has been written.
    async fn stream_events(
        &self,
        request: Request<Streaming<EventMessage>>,
    ) -> Result<Response<EventSummary>, Status> {
        if let Some(ref cache) = self.cache {
            let peer_ip = request
                .remote_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|| "unknown".into());
            let rate_key = format!("rate_limit:grpc:{}", peer_ip);
            if crate::api::events::is_rate_limited(cache, &rate_key, 10, 60).await {
                return Err(Status::resource_exhausted(
                    "Rate limit exceeded for gRPC event stream connections",
                ));
            }
        }

        let mut stream = request.into_inner();
        let mut count = 0i64;

        while let Some(ev) = stream.message().await? {
            let db_event = Event {
                id: Uuid::new_v4(),
                sensor_id: Uuid::parse_str(&ev.sensor_id).ok(),
                event_type: ev.event_type,
                severity: ev.severity,
                title: ev.title,
                description: if ev.description.is_empty() {
                    None
                } else {
                    Some(ev.description)
                },
                source_ip: if ev.source_ip.is_empty() {
                    None
                } else {
                    Some(ev.source_ip)
                },
                dest_ip: if ev.dest_ip.is_empty() {
                    None
                } else {
                    Some(ev.dest_ip)
                },
                protocol: if ev.protocol.is_empty() {
                    None
                } else {
                    Some(ev.protocol)
                },
                port: if ev.port == 0 { None } else { Some(ev.port) },
                raw_data: if ev.raw_data.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::String(ev.raw_data))
                },
                tags: serde_json::Value::Array(Vec::new()),
                timestamp: chrono::Utc::now(),
            };

            if let Ok(inserted_ev) = queries::insert_event(&self.pool, &db_event).await {
                count += 1;
                if let Ok(rules) = queries::list_rules(&self.pool).await {
                    for rule in rules {
                        if rule.enabled
                            && crate::api::events::event_matches_rule(&inserted_ev, &rule)
                        {
                            crate::api::events::evaluate_alert_dedup(
                                &self.pool,
                                self.cache.as_deref(),
                                &inserted_ev,
                                &rule,
                            )
                            .await;
                        }
                    }
                }
            }
        }

        Ok(Response::new(EventSummary {
            accepted: count,
            status: "complete".into(),
        }))
    }

    async fn send_command(
        &self,
        request: Request<SensorCommand>,
    ) -> Result<Response<SensorCommandAck>, Status> {
        let req = request.into_inner();
        tracing::info!("gRPC command for sensor {}: {}", req.sensor_id, req.command);
        Ok(Response::new(SensorCommandAck {
            status: "queued".into(),
            message: format!("Command '{}' accepted", req.command),
        }))
    }
}

pub fn grpc_service(
    pool: PgPool,
    cache: Option<Arc<CacheLayer>>,
) -> SensorServiceServer<SensorGrpcService> {
    SensorServiceServer::new(SensorGrpcService { pool, cache })
}
