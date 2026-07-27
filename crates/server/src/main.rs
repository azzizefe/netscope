mod api;
mod auth;
mod cache;
mod config;
mod db;
mod grpc;
mod tls;
mod tls_listener;
mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::WebSocketUpgrade;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde_json::json;
use tokio::net::TcpListener;
use tonic::transport::Server as GrpcServer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::api::ApiState;
use crate::auth::{JwtState, RbacState};
use crate::cache::CacheLayer;
use crate::config::{AppConfig, CliArgs};
use crate::ws::WsState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,netscope_server=debug")))
        .init();

    let args = CliArgs::parse();

    let config: AppConfig = if args.config.exists() {
        toml::from_str(&std::fs::read_to_string(&args.config)?)
            .context("Failed to parse config file")?
    } else {
        AppConfig { server: None, database: None, redis: None }
    };

    // Database
    let db_url = args.db_url
        .or_else(|| config.database.as_ref().map(|d| d.url.clone()))
        .unwrap_or_else(|| "postgres://netscope:netscope@localhost:5432/netscope".into());

    let max_connections = config.database
        .as_ref()
        .and_then(|d| d.max_connections)
        .unwrap_or(20);

    let pool = db::create_pool(&db_url, max_connections).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("Database connected and migrated");

    // Redis cache
    let redis_url = args.redis_url
        .or_else(|| config.redis.as_ref().map(|r| r.url.clone()));

    let cache = if let Some(url) = redis_url {
        match CacheLayer::new(&url).await {
            Ok(c) => {
                tracing::info!("Redis cache connected");
                Some(Arc::new(c))
            }
            Err(e) => {
                tracing::warn!("Redis unavailable, running without cache: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Auth
    let jwt_secret = args.jwt_secret
        .or_else(|| config.server.as_ref().and_then(|s| s.jwt.as_ref().map(|j| j.secret.clone())))
        .unwrap_or_else(|| {
            let secret = uuid::Uuid::new_v4().to_string();
            tracing::warn!("No JWT secret configured, using auto-generated (sessions invalidate on restart)");
            secret
        });

    let jwt_issuer = config.server.as_ref()
        .and_then(|s| s.jwt.as_ref())
        .and_then(|j| j.issuer.clone());

    let jwt_expiry = config.server.as_ref()
        .and_then(|s| s.jwt.as_ref())
        .and_then(|j| j.expiry_hours);

    let jwt = Arc::new(JwtState::new(jwt_secret, jwt_issuer, jwt_expiry));
    let rbac = Arc::new(RbacState::new());

    // WebSocket broadcast
    let ws_state = Arc::new(WsState::new());
    let api_state = Arc::new(ApiState {
        pool: pool.clone(),
        cache: cache.clone(),
    });

    // ── Build router ──
    // State type is `()` at the top level; sub-routers handle their own
    // state via `with_state()` inside their `routes()` constructors.
    let app = Router::new()
        .route("/ws/events", get(ws_handler))
        .route("/health", get(health))
        .merge(api::build_router(pool.clone(), jwt.clone(), rbac.clone(), cache.clone()))
        .layer(axum::extract::Extension(api_state))
        .layer(axum::extract::Extension(ws_state))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any));

    // ── Start servers concurrently ──
    let listen_addr: SocketAddr = format!(
        "{}:{}",
        args.listen,
        args.port,
    ).parse().context("Invalid listen address")?;

    let grpc_listen_addr: SocketAddr = format!(
        "{}:{}",
        args.listen,
        args.grpc_port,
    ).parse().context("Invalid gRPC listen address")?;

    let tls_cert = args.tls_cert
        .or_else(|| config.server.as_ref().and_then(|s| s.tls.as_ref().map(|t| t.cert.clone())));
    let tls_key = args.tls_key
        .or_else(|| config.server.as_ref().and_then(|s| s.tls.as_ref().map(|t| t.key.clone())));
    let tls_ca = args.tls_ca
        .or_else(|| config.server.as_ref().and_then(|s| s.tls.as_ref().and_then(|t| t.ca.clone())));

    let grpc_enabled = args.grpc_enabled
        || config.server.as_ref().and_then(|s| s.grpc.as_ref()).map(|g| g.enabled).unwrap_or(false);

    // ── gRPC server (separate port) ──
    let grpc_svc = grpc::grpc_service(pool.clone());

    let grpc_handle = if grpc_enabled {
        tracing::info!("gRPC server starting on {}", grpc_listen_addr);
        Some(tokio::spawn(async move {
            if let Err(e) = GrpcServer::builder()
                .add_service(grpc_svc)
                .serve(grpc_listen_addr)
                .await
            {
                tracing::error!("gRPC server error: {}", e);
            }
        }))
    } else {
        None
    };

    // ── HTTP server (with optional TLS) ──
    let http_handle = if let (Some(cert), Some(key)) = (tls_cert.as_ref(), tls_key.as_ref()) {
        let tls = tls_ca.is_some();
        tracing::info!("TLS 1.3 enabled on {} (mTLS: {})", listen_addr, tls);
        let listener = tls_listener::TlsListener::new(
            &listen_addr, cert, key, tls_ca.as_deref(),
        ).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                tracing::error!("HTTP server error: {}", e);
            }
        })
    } else {
        tracing::info!("Starting plain HTTP on {}", listen_addr);
        let listener = TcpListener::bind(listen_addr).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                tracing::error!("HTTP server error: {}", e);
            }
        })
    };

    // Block until either server exits
    tokio::select! {
        _ = http_handle => {},
        _ = async { if let Some(h) = grpc_handle { h.await.unwrap_or(()) } } => {},
    }

    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "netscope-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::Extension(ws_state): axum::extract::Extension<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws::handle_socket(socket, ws_state))
}
