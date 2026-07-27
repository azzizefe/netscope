use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
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

#[derive(Debug, Deserialize)]
pub struct ClaimsFromRequest(pub Claims);

pub struct JwtState {
    secret: String,
    issuer: String,
    expiry_hours: i64,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtState {
    pub fn new(secret: String, issuer: Option<String>, expiry_hours: Option<i64>) -> Self {
        let secret_key = secret.clone();
        JwtState {
            secret,
            issuer: issuer.unwrap_or_else(|| "netscope-server".into()),
            expiry_hours: expiry_hours.unwrap_or(24),
            encoding_key: EncodingKey::from_secret(secret_key.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret_key.as_bytes()),
        }
    }

    pub fn create_token(&self, user_id: Uuid, username: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: user_id,
            username: username.into(),
            role: role.into(),
            exp: now + (self.expiry_hours * 3600) as usize,
            iat: now,
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
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
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
        map.insert("admin".into(), vec![
            "sensors:read".into(), "sensors:write".into(), "sensors:command".into(),
            "events:read".into(), "events:write".into(),
            "alerts:read".into(), "alerts:write".into(),
            "rules:read".into(), "rules:write".into(),
            "users:read".into(), "users:write".into(),
            "dashboard:read".into(),
        ]);
        map.insert("operator".into(), vec![
            "sensors:read".into(), "sensors:write".into(), "sensors:command".into(),
            "events:read".into(),
            "alerts:read".into(), "alerts:write".into(),
            "rules:read".into(),
            "dashboard:read".into(),
        ]);
        map.insert("analyst".into(), vec![
            "events:read".into(),
            "alerts:read".into(), "alerts:write".into(),
            "dashboard:read".into(),
        ]);
        map.insert("viewer".into(), vec![
            "sensors:read".into(),
            "events:read".into(),
            "alerts:read".into(),
            "dashboard:read".into(),
        ]);
        RbacState { inner: Arc::new(RwLock::new(Permissions { role_permissions: map })) }
    }
}

pub async fn auth_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    let state = req.extensions().get::<Arc<JwtState>>().cloned();
    let state = match state {
        Some(s) => s,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "JWT state not configured").into_response(),
    };

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing authorization header"}))).into_response(),
    };

    match state.validate_token(token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims.clone());
            next.run(req).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid or expired token"}))).into_response(),
    }
}

pub async fn require_permission(
    req: Request,
    next: Next,
    perm: &'static str,
) -> Response {
    let claims = req.extensions().get::<Claims>().cloned();
    let claims = match claims {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "not authenticated"}))).into_response(),
    };

    let rbac = req.extensions().get::<Arc<RbacState>>().cloned();
    let rbac = match rbac {
        Some(r) => r,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "RBAC not configured").into_response(),
    };

    let perms = rbac.inner.read().role_permissions.get(&claims.role).cloned();
    match perms {
        Some(p) if p.contains(&perm.to_string()) || claims.role == "admin" => {
            next.run(req).await
        }
        _ => (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "insufficient permissions"}))).into_response(),
    }
}
