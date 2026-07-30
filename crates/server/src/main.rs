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
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,netscope_server=debug")),
        )
        .init();

    let args = CliArgs::parse();

    let config: AppConfig = if args.config.exists() {
        toml::from_str(&std::fs::read_to_string(&args.config)?)
            .context("Failed to parse config file")?
    } else {
        AppConfig {
            server: None,
            database: None,
            redis: None,
        }
    };

    // Database
    let db_url = args
        .db_url
        .or_else(|| config.database.as_ref().map(|d| d.url.clone()))
        .unwrap_or_else(|| "postgres://netscope:netscope@localhost:5432/netscope".into());

    let max_connections = config
        .database
        .as_ref()
        .and_then(|d| d.max_connections)
        .unwrap_or(20);

    let pool = db::create_pool(&db_url, max_connections).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("Database connected and migrated");

    // Redis cache
    let redis_url = args
        .redis_url
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
    let jwt_secret = args
        .jwt_secret
        .or_else(|| {
            config
                .server
                .as_ref()
                .and_then(|s| s.jwt.as_ref().map(|j| j.secret.clone()))
        })
        .map(Ok)
        .unwrap_or_else(|| {
            // Refuse to start rather than invent one. A generated secret looks
            // like it works — tokens sign and validate — right up to the point
            // where it does not: every session dies on restart, and two
            // instances behind a load balancer reject each other's tokens, so
            // a fleet's logins fail intermittently with nothing in the logs but
            // "invalid or expired token". It was a single warning line among
            // the startup noise, which is not where an operator finds it.
            if args.dev_insecure_jwt {
                tracing::warn!(
                    "--dev-insecure-jwt: signing with a per-process secret. \
                     Sessions end at restart and will not survive more than one \
                     instance. Never use this outside local development."
                );
                Ok(uuid::Uuid::new_v4().to_string())
            } else {
                Err(anyhow::anyhow!(
                    "No JWT secret configured. Set `[server.jwt] secret` in the \
                     config file or pass --jwt-secret. For local development \
                     only, --dev-insecure-jwt generates a throwaway one."
                ))
            }
        })?;

    let jwt_issuer = config
        .server
        .as_ref()
        .and_then(|s| s.jwt.as_ref())
        .and_then(|j| j.issuer.clone());

    let jwt_expiry = config
        .server
        .as_ref()
        .and_then(|s| s.jwt.as_ref())
        .and_then(|j| j.expiry_hours);

    let jwt = Arc::new(JwtState::new(jwt_secret, jwt_issuer, jwt_expiry));
    let rbac = Arc::new(RbacState::new());

    // WebSocket broadcast
    let ws_state = Arc::new(WsState::new());
    let sensor_ws_registry = Arc::new(crate::ws::SensorWsRegistry::new());
    let commands = crate::api::sensors::CommandStore::new();
    let session_mgr = Arc::new(netscope_core::session_manager::SessionManager::new());
    let protector = Arc::new(netscope_core::brute_force_protection::BruteForceProtector::new());
    let api_state = Arc::new(ApiState {
        pool: pool.clone(),
        cache: cache.clone(),
        commands,
        session_mgr,
        protector,
    });

    // ── Build router ──
    // State type is `()` at the top level; sub-routers handle their own
    // state via `with_state()` inside their `routes()` constructors.
    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route("/ws/events", get(ws_handler))
        .route("/health", get(health))
        .merge(api::build_router(
            pool.clone(),
            jwt.clone(),
            rbac.clone(),
            cache.clone(),
        ))
        .layer(axum::extract::Extension(api_state))
        .layer(axum::extract::Extension(ws_state))
        .layer(axum::extract::Extension(sensor_ws_registry))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // ── Start servers concurrently ──
    // Flag beats config file beats built-in default — see the comment on
    // `CliArgs`. Until this chain existed the `[server]` block was parsed and
    // then ignored, so a `port` set in server.toml did nothing at all.
    let listen = args
        .listen
        .or_else(|| config.server.as_ref().map(|s| s.listen.clone()))
        .unwrap_or_else(|| "0.0.0.0".into());

    let port = args
        .port
        .or_else(|| config.server.as_ref().map(|s| s.port))
        .unwrap_or(9443);

    let grpc_port = args
        .grpc_port
        .or_else(|| {
            config
                .server
                .as_ref()
                .and_then(|s| s.grpc.as_ref())
                .map(|g| g.port)
        })
        .unwrap_or(9444);

    let listen_addr: SocketAddr = format!("{listen}:{port}")
        .parse()
        .context("Invalid listen address")?;

    let grpc_listen_addr: SocketAddr = format!("{listen}:{grpc_port}")
        .parse()
        .context("Invalid gRPC listen address")?;

    let tls_cert = args.tls_cert.or_else(|| {
        config
            .server
            .as_ref()
            .and_then(|s| s.tls.as_ref().map(|t| t.cert.clone()))
    });
    let tls_key = args.tls_key.or_else(|| {
        config
            .server
            .as_ref()
            .and_then(|s| s.tls.as_ref().map(|t| t.key.clone()))
    });
    let tls_ca = args.tls_ca.or_else(|| {
        config
            .server
            .as_ref()
            .and_then(|s| s.tls.as_ref().and_then(|t| t.ca.clone()))
    });

    let grpc_enabled = args.grpc_enabled
        || config
            .server
            .as_ref()
            .and_then(|s| s.grpc.as_ref())
            .map(|g| g.enabled)
            .unwrap_or(false);

    // ── gRPC server (separate port) ──
    let grpc_svc = grpc::grpc_service(pool.clone(), cache.clone());

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
        let listener =
            tls_listener::TlsListener::new(&listen_addr, cert, key, tls_ca.as_deref()).await?;
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

async fn dashboard_handler() -> impl IntoResponse {
    axum::response::Html(include_str!("static/dashboard.html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_dashboard_handler_returns_html() {
        let app = Router::new().route("/", get(dashboard_handler));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Netscope SOC Dashboard"));
        assert!(body_str.contains("dracula"));
    }
}
