// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message;
use crate::state::AgentState;

#[derive(Debug, Deserialize)]
struct WsPayload {
    event: String,
    config: String,
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub async fn ws_loop(state: AgentState) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        let sensor_id = match state.get_sensor_id() {
            Some(id) => id,
            None => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let (ws_url, auth_token, insecure) = {
            let cfg = state.config.read();
            let server_url = cfg.server.url.clone();
            let ws_url = if server_url.starts_with("https://") {
                server_url.replacen("https://", "wss://", 1)
            } else if server_url.starts_with("http://") {
                server_url.replacen("http://", "ws://", 1)
            } else {
                format!("wss://{}", server_url)
            };
            (
                format!("{}/api/v1/sensors/{}/ws", ws_url, sensor_id),
                cfg.server.auth_token.clone(),
                cfg.server.insecure_skip_verify,
            )
        };

        tracing::info!("Connecting WebSocket to {}...", ws_url);

        match connect_and_handle(&state, &ws_url, &auth_token, insecure).await {
            Ok(_) => {
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                tracing::warn!("WebSocket error: {}. Reconnecting in {:?}", e, backoff);
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        }
    }
}

async fn connect_and_handle(
    state: &AgentState,
    ws_url: &str,
    auth_token: &str,
    insecure: bool,
) -> anyhow::Result<()> {
    let mut request = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(ws_url)
        .body(())?;

    if !auth_token.is_empty() {
        request.headers_mut().insert(
            "Authorization",
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!("Bearer {}", auth_token))?,
        );
    }

    let connector = if insecure {
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
            .with_no_client_auth();
        Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(client_config)))
    } else {
        None
    };

    let (mut ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        connector,
    )
    .await?;

    tracing::info!("WebSocket connected successfully to server");

    while let Some(msg_result) = ws_stream.next().await {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        let msg = msg_result?;
        match msg {
            Message::Text(text) => {
                if let Ok(payload) = serde_json::from_str::<WsPayload>(&text) {
                    if payload.event == "config_update" {
                        tracing::info!("Received config_update pushed from server");
                        if let Err(e) = state.update_config(&payload.config) {
                            tracing::error!("Failed to apply updated config: {}", e);
                        }
                    }
                }
            }
            Message::Ping(payload) => {
                let _ = ws_stream.send(Message::Pong(payload)).await;
            }
            Message::Close(_) => {
                tracing::info!("Server closed WebSocket connection");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
