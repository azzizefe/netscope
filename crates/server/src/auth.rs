use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub struct JwtState {
    issuer: String,
    expiry_hours: i64,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtState {
    /// The raw secret is consumed here and not retained: both keys are derived
    /// from it up front, and nothing else ever needs the bytes back.
    pub fn new(secret: String, issuer: Option<String>, expiry_hours: Option<i64>) -> Self {
        JwtState {
            issuer: issuer.unwrap_or_else(|| "netscope-server".into()),
            expiry_hours: expiry_hours.unwrap_or(24),
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn create_token(
        &self,
        user_id: Uuid,
        username: &str,
        role: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp();
        // Computed in i64 and clamped, not cast. `(hours * 3600) as usize` on a
        // negative or oversized `expiry_hours` wraps to an enormous number and
        // then overflows the addition — a bad value in the config file took the
        // server down instead of being rejected. Clamping at zero also makes a
        // past expiry mean what it says: a token that is already invalid.
        let exp = now
            .saturating_add(self.expiry_hours.saturating_mul(3600))
            .max(0) as usize;
        let claims = Claims {
            sub: user_id,
            username: username.into(),
            role: role.into(),
            exp,
            iat: now.max(0) as usize,
            iss: self.issuer.clone(),
        };
        encode(&Header::default(), &claims, &self.encoding_key)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[derive(Debug, Clone)]
pub struct RbacState {
    inner: Arc<RwLock<Permissions>>,
}

#[derive(Debug, Clone)]
struct Permissions {
    role_permissions: HashMap<String, Vec<String>>,
}

impl RbacState {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "admin".into(),
            vec![
                "sensors:read".into(),
                "sensors:write".into(),
                "sensors:command".into(),
                "events:read".into(),
                "events:write".into(),
                "alerts:read".into(),
                "alerts:write".into(),
                "rules:read".into(),
                "rules:write".into(),
                "users:read".into(),
                "users:write".into(),
                "dashboard:read".into(),
            ],
        );
        // operator is the fleet role, and a fleet's job is producing events, so
        // it holds `events:write` — that is the permission `POST /events/batch`
        // is gated on. Without it a sensor could not report in at all.
        map.insert(
            "operator".into(),
            vec![
                "sensors:read".into(),
                "sensors:write".into(),
                "sensors:command".into(),
                "events:read".into(),
                "events:write".into(),
                "alerts:read".into(),
                "alerts:write".into(),
                "rules:read".into(),
                "dashboard:read".into(),
            ],
        );
        map.insert(
            "analyst".into(),
            vec![
                "events:read".into(),
                "alerts:read".into(),
                "alerts:write".into(),
                "dashboard:read".into(),
            ],
        );
        map.insert(
            "viewer".into(),
            vec![
                "sensors:read".into(),
                "events:read".into(),
                "alerts:read".into(),
                "dashboard:read".into(),
            ],
        );
        RbacState {
            inner: Arc::new(RwLock::new(Permissions {
                role_permissions: map,
            })),
        }
    }

    /// Whether `role` may do `perm`.
    ///
    /// A role the table does not list is refused rather than defaulted to
    /// anything: an unknown role is a misconfiguration, and the safe reading of
    /// a misconfiguration is "no".
    pub fn allows(&self, role: &str, perm: &str) -> bool {
        // admin is deliberately absolute — it is the break-glass role, and
        // listing every future permission against it would be a way to forget
        // one.
        if role == "admin" {
            return true;
        }
        self.inner
            .read()
            .role_permissions
            .get(role)
            .is_some_and(|p| p.iter().any(|held| held == perm))
    }
}

impl Default for RbacState {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    let state = req.extensions().get::<Arc<JwtState>>().cloned();
    let state = match state {
        Some(s) => s,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "JWT state not configured",
            )
                .into_response()
        }
    };

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing authorization header"})),
            )
                .into_response()
        }
    };

    match state.validate_token(token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims.clone());
            next.run(req).await
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid or expired token"})),
        )
            .into_response(),
    }
}

/// A middleware layer that admits only roles holding `perm`.
///
/// [`require_permission`] takes the permission as a third argument, which is
/// one argument more than `axum::middleware::from_fn` accepts — so it could
/// never be attached to a router and, until this existed, never ran. Every
/// endpoint was authenticated but unauthorised: any valid token, whatever its
/// role, reached every route. A `viewer` could delete rules.
///
/// This closes that over the permission so the check can actually be layered on.
pub fn require(
    perm: &'static str,
) -> impl Fn(Request, Next) -> futures::future::BoxFuture<'static, Response>
       + Clone
       + Send
       + Sync
       + 'static {
    move |req, next| Box::pin(require_permission(req, next, perm))
}

pub async fn require_permission(req: Request, next: Next, perm: &'static str) -> Response {
    let claims = req.extensions().get::<Claims>().cloned();
    let claims = match claims {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "not authenticated"})),
            )
                .into_response()
        }
    };

    let rbac = req.extensions().get::<Arc<RbacState>>().cloned();
    let rbac = match rbac {
        Some(r) => r,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "RBAC not configured").into_response(),
    };

    if rbac.allows(&claims.role, perm) {
        next.run(req).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "insufficient permissions"})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The roles exist to be told apart. Until `require` was wired, every one
    /// of these passed — the API authenticated but never authorised.
    #[test]
    fn a_role_only_gets_what_its_row_lists() {
        let rbac = RbacState::new();

        // A viewer reads and nothing else. This is the case that mattered:
        // rule deletion was reachable with any valid token.
        assert!(rbac.allows("viewer", "sensors:read"));
        assert!(!rbac.allows("viewer", "rules:write"));
        assert!(!rbac.allows("viewer", "sensors:command"));

        // An analyst works alerts but does not touch sensors or rules.
        assert!(rbac.allows("analyst", "alerts:write"));
        assert!(!rbac.allows("analyst", "sensors:command"));
        assert!(!rbac.allows("analyst", "rules:write"));

        // An operator runs the fleet but does not author rules.
        assert!(rbac.allows("operator", "sensors:command"));
        assert!(!rbac.allows("operator", "rules:write"));
    }

    /// Reading a thing and writing it are separate rows, and the routes are
    /// gated on the write half. These are the pairs that were collapsed when
    /// each route group carried one permission for every method on it.
    #[test]
    fn holding_read_never_implies_holding_write() {
        let rbac = RbacState::new();

        for role in ["viewer", "analyst"] {
            // Injecting events into the SOC timeline is a write. Both of these
            // roles hold `events:read`, which is what `/events/batch` used to
            // be gated on.
            assert!(rbac.allows(role, "events:read"), "{role}");
            assert!(!rbac.allows(role, "events:write"), "{role}");
        }

        // A viewer sees sensors and alerts; it does not edit or command them.
        assert!(rbac.allows("viewer", "sensors:read"));
        assert!(!rbac.allows("viewer", "sensors:write"));
        assert!(!rbac.allows("viewer", "alerts:write"));

        // An operator must be able to both list rules and report events —
        // gating a whole group at one permission broke one or the other.
        assert!(rbac.allows("operator", "rules:read"));
        assert!(rbac.allows("operator", "events:write"));
    }

    /// admin is the break-glass role: absolute, so that adding a permission
    /// later cannot accidentally lock the administrator out of it.
    #[test]
    fn admin_holds_every_permission_including_unlisted_ones() {
        let rbac = RbacState::new();
        assert!(rbac.allows("admin", "rules:write"));
        assert!(rbac.allows("admin", "something:invented:later"));
    }

    /// An unknown role is a misconfiguration, and the safe reading of one is
    /// "no" rather than "everything".
    #[test]
    fn an_unknown_role_is_refused() {
        let rbac = RbacState::new();
        assert!(!rbac.allows("", "events:read"));
        assert!(!rbac.allows("superuser", "events:read"));
        assert!(!rbac.allows("Admin", "events:read"));
    }

    /// A token has to round-trip, and one signed by a different secret must
    /// not validate — the middleware's whole guarantee rests on this.
    #[test]
    fn a_token_validates_only_against_its_own_secret() {
        let jwt = JwtState::new("s3cret".into(), None, Some(1));
        let id = Uuid::new_v4();
        let token = jwt.create_token(id, "efe", "operator").unwrap();

        let claims = jwt.validate_token(&token).unwrap();
        assert_eq!(claims.sub, id);
        assert_eq!(claims.role, "operator");

        let other = JwtState::new("different".into(), None, Some(1));
        assert!(other.validate_token(&token).is_err());
    }

    /// An expired token is refused. `expiry_hours` is signed into the token,
    /// so this is what stops a leaked one being useful forever.
    #[test]
    fn an_expired_token_is_refused() {
        let jwt = JwtState::new("s3cret".into(), None, Some(-1));
        let token = jwt.create_token(Uuid::new_v4(), "efe", "viewer").unwrap();
        assert!(jwt.validate_token(&token).is_err());
    }

    /// Passwords are stored as an Argon2 hash, never as the password.
    #[test]
    fn a_password_hash_verifies_only_the_right_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!hash.contains("correct horse"));
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());

        // Salted: the same password hashes differently every time.
        let again = hash_password("correct horse battery staple").unwrap();
        assert_ne!(hash, again);
    }
}
