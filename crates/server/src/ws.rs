use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use crate::db::models::Event;
use parking_lot::RwLock;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct WsState {
    pub tx: broadcast::Sender<String>,
    session_count: Arc<RwLock<usize>>,
}

impl WsState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        WsState {
            tx,
            session_count: Arc::new(RwLock::new(0)),
        }
    }

    pub fn broadcast_event(event: &Event, state: &WsState) {
        if let Ok(json) = serde_json::to_string(event) {
            let _ = state.tx.send(json);
        }
    }

    pub fn session_count(&self) -> usize {
        *self.session_count.read()
    }
}

pub async fn handle_socket(mut socket: WebSocket, state: Arc<WsState>) {
    *state.session_count.write() += 1;
    let mut rx = state.tx.subscribe();

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(text) => {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WS client lagged by {} messages", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // ignore client pings/other
                }
            }
        }
    }

    *state.session_count.write() -= 1;
}
