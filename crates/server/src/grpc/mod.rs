pub mod proto;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use futures::Stream;
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};
use uuid::Uuid;

use self::proto::sensor_service_server::{SensorService, SensorServiceServer};
use self::proto::*;
use crate::db::models::{Event, RegisterSensor};
use crate::db::queries;

#[derive(Clone)]
pub struct SensorGrpcService {
    pool: PgPool,
}

#[async_trait]
impl SensorService for SensorGrpcService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let ip: std::net::IpAddr = req.ip_address.parse()
            .map_err(|_| Status::invalid_argument("invalid ip_address"))?;

        let sensor = RegisterSensor {
            hostname: req.hostname,
            ip_address: ip,
            os: if req.os.is_empty() { None } else { Some(req.os) },
            version: req.version,
            interfaces: Vec::new(),
            cpu_cores: None,
            ram_mb: None,
        };

        let sensor = queries::register_sensor(&self.pool, &sensor).await
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
            interface_stats: None,
            received_at: chrono::Utc::now(),
        };

        queries::update_sensor_heartbeat(&self.pool, sensor_id, &hb).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(HeartbeatResponse { acknowledged: true }))
    }

    type StreamEventsStream = Pin<
        Box<dyn Stream<Item = Result<EventSummary, Status>> + Send + 'static>,
    >;

    async fn stream_events(
        &self,
        request: Request<Streaming<EventMessage>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let mut stream = request.into_inner();
        let pool = self.pool.clone();
        let (tx, rx) = mpsc::channel(1024);

        tokio::spawn(async move {
            let mut count = 0i64;
            while let Some(msg) = stream.message().await.transpose() {
                match msg {
                    Ok(ev) => {
                        let db_event = Event {
                            id: Uuid::new_v4(),
                            sensor_id: Uuid::parse_str(&ev.sensor_id).ok(),
                            event_type: ev.event_type,
                            severity: ev.severity,
                            title: ev.title,
                            description: if ev.description.is_empty() { None } else { Some(ev.description) },
                            source_ip: if ev.source_ip.is_empty() { None } else { Some(ev.source_ip) },
                            dest_ip: if ev.dest_ip.is_empty() { None } else { Some(ev.dest_ip) },
                            protocol: if ev.protocol.is_empty() { None } else { Some(ev.protocol) },
                            port: if ev.port == 0 { None } else { Some(ev.port) },
                            raw_data: if ev.raw_data.is_empty() { None } else { Some(serde_json::Value::String(ev.raw_data)) },
                            tags: serde_json::Value::Array(Vec::new()),
                            timestamp: chrono::Utc::now(),
                        };
                        if queries::insert_event(&pool, &db_event).await.is_ok() {
                            count += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("gRPC stream event error: {}", e);
                        break;
                    }
                }
            }
            let _ = tx.send(Ok(EventSummary {
                accepted: count,
                status: "complete".into(),
            })).await;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
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

pub fn grpc_service(pool: PgPool) -> SensorServiceServer<SensorGrpcService> {
    SensorServiceServer::new(SensorGrpcService { pool })
}
