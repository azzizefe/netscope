pub mod alerts;
pub mod assets;
pub mod auth_routes;
pub mod dashboard;
pub mod events;
pub mod health;
pub mod hunt;
pub mod notifications_routes;
pub mod reports;
pub mod rules;
pub mod sensors;
pub mod sensors_config;
pub mod siem;
pub mod soar;
pub mod upgrade;

use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;

use crate::api::sensors::CommandStore;
use crate::auth::{JwtState, RbacState};
use crate::cache::CacheLayer;

pub fn build_router(
    pool: PgPool,
    jwt: Arc<JwtState>,
    rbac: Arc<RbacState>,
    cache: Option<Arc<CacheLayer>>,
) -> Router {
    let commands = CommandStore::new();
    let session_mgr = Arc::new(netscope_core::session_manager::SessionManager::new());
    let protector = Arc::new(netscope_core::brute_force_protection::BruteForceProtector::new());
    let rbac_engine = Arc::new(netscope_core::rbac_engine::RbacEngine::new());
    let audit_chain = Arc::new(netscope_core::audit_chain::AuditChainManager::new());
    let api_state = Arc::new(ApiState {
        pool,
        cache,
        commands,
        session_mgr,
        protector,
        rbac_engine,
        audit_chain,
    });

    let public = Router::new()
        .nest(
            "/api/v1",
            auth_routes::routes(api_state.clone(), jwt.clone()),
        )
        .nest("/api/v1", upgrade::routes(api_state.clone()))
        .nest("/api/v1", notifications_routes::routes(api_state.clone()));

    // `auth_middleware` establishes *who* the caller is; the permission each
    // route needs is declared on the route itself, inside each module's
    // `routes()`. That split matters: a group-wide layer can only name one
    // permission, but `GET /sensors` and `POST /sensors` sit on the same path
    // at different privilege levels, so one of the two is always mis-gated.
    // Gating at the read permission is what let a `viewer` token command the
    // fleet and inject events; gating at the write permission locked an
    // `operator` out of listing rules.
    let protected = Router::new()
        .nest("/api/v1/sensors", sensors::routes(api_state.clone()))
        .nest("/api/v1/events", events::routes(api_state.clone()))
        .nest("/api/v1/alerts", alerts::routes(api_state.clone()))
        .nest("/api/v1/rules", rules::routes(api_state.clone()))
        .nest("/api/v1/hunt", hunt::routes(api_state.clone()))
        .nest("/api/v1/reports", reports::routes(api_state.clone()))
        .nest("/api/v1/soar", soar::routes(api_state.clone()))
        .nest("/api/v1/dashboard", dashboard::routes(api_state.clone()))
        .nest("/api/v1/assets", assets::routes(api_state.clone()))
        .nest("/api/v1/siem", siem::routes(api_state.clone()))
        // Health carries no data and is what a load balancer polls, so it needs
        // authentication but no particular role.
        .nest("/api/v1", health::routes())
        .layer(axum::middleware::from_fn(crate::auth::auth_middleware));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(axum::extract::Extension(jwt))
        .layer(axum::extract::Extension(rbac))
}

pub struct ApiState {
    pub pool: PgPool,
    pub cache: Option<Arc<CacheLayer>>,
    pub commands: Arc<CommandStore>,
    pub session_mgr: Arc<netscope_core::session_manager::SessionManager>,
    pub protector: Arc<netscope_core::brute_force_protection::BruteForceProtector>,
    pub rbac_engine: Arc<netscope_core::rbac_engine::RbacEngine>,
    pub audit_chain: Arc<netscope_core::audit_chain::AuditChainManager>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// The permission check runs before the handler, so a refusal never reaches
    /// the database — which is what lets this test run without one. A lazy pool
    /// never dials until a query is issued, and the short acquire timeout keeps
    /// the *allowed* cases (which do reach the handler) from spending the
    /// default 30s each discovering there is no database.
    fn app() -> (Router, Arc<JwtState>) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://netscope:netscope@127.0.0.1:1/netscope")
            .expect("a lazy pool does not connect");
        let jwt = Arc::new(JwtState::new("test-secret".into(), None, Some(1)));
        let router = build_router(pool, jwt.clone(), Arc::new(RbacState::new()), None).layer(
            axum::extract::Extension(Arc::new(crate::ws::WsState::new())),
        );
        (router, jwt)
    }

    async fn status_for(role: &str, method: &str, uri: &str) -> StatusCode {
        let (router, jwt) = app();
        let token = jwt
            .create_token(uuid::Uuid::new_v4(), "tester", role)
            .unwrap();
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("[]"))
            .unwrap();
        router.oneshot(request).await.unwrap().status()
    }

    /// The bug this guards: every route in a group carried the group's single
    /// permission, so the write methods sitting alongside a read were gated at
    /// the read. A `viewer` could command sensors and fabricate events.
    #[tokio::test]
    async fn a_read_only_role_is_refused_every_write() {
        for (method, uri) in [
            ("POST", "/api/v1/sensors"),
            ("POST", "/api/v1/sensors/register"),
            ("POST", "/api/v1/events/batch"),
            (
                "PATCH",
                "/api/v1/alerts/00000000-0000-0000-0000-000000000000/status",
            ),
            ("POST", "/api/v1/rules"),
        ] {
            assert_eq!(
                status_for("viewer", method, uri).await,
                StatusCode::FORBIDDEN,
                "a viewer reached {method} {uri}",
            );
        }
    }

    /// Commanding a sensor is its own privilege — an analyst works alerts and
    /// must not be able to make a remote sensor act.
    #[tokio::test]
    async fn commanding_a_sensor_needs_the_command_permission() {
        let uri = "/api/v1/sensors/00000000-0000-0000-0000-000000000000/command";
        assert_eq!(
            status_for("viewer", "POST", uri).await,
            StatusCode::FORBIDDEN,
        );
        assert_eq!(
            status_for("analyst", "POST", uri).await,
            StatusCode::FORBIDDEN,
        );
    }

    /// The other half of the mistake: gating the rules group at `rules:write`
    /// refused an operator the listing its own row grants it.
    #[tokio::test]
    async fn a_read_is_not_refused_to_a_role_that_holds_it() {
        // Not FORBIDDEN — the request gets past authorisation and dies at the
        // unreachable database instead, which is the proof it was let through.
        for (role, uri) in [
            ("operator", "/api/v1/rules"),
            ("viewer", "/api/v1/events"),
            ("analyst", "/api/v1/alerts"),
            ("viewer", "/api/v1/dashboard/summary"),
        ] {
            assert_ne!(
                status_for(role, "GET", uri).await,
                StatusCode::FORBIDDEN,
                "{role} was refused GET {uri}",
            );
        }
    }

    /// A sensor reports in as an operator, so that path has to stay open or the
    /// fleet goes silent.
    #[tokio::test]
    async fn an_operator_can_still_report_events_and_heartbeat() {
        assert_ne!(
            status_for("operator", "POST", "/api/v1/events/batch").await,
            StatusCode::FORBIDDEN,
        );
        assert_ne!(
            status_for(
                "operator",
                "PUT",
                "/api/v1/sensors/00000000-0000-0000-0000-000000000000/heartbeat",
            )
            .await,
            StatusCode::FORBIDDEN,
        );
    }

    /// Authorisation runs behind authentication, not instead of it.
    #[tokio::test]
    async fn an_unauthenticated_request_is_refused_before_any_permission_check() {
        let (router, _) = app();
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/events")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
        );
    }
}
