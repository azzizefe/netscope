use std::sync::Arc;

use crate::db::models::Event;
use axum::extract::ws::{Message, WebSocket};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use uuid::Uuid;
use dashmap::DashMap;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct SensorWsRegistry {
    pub sensors: Arc<DashMap<Uuid, mpsc::UnboundedSender<Message>>>,
}

impl SensorWsRegistry {
    pub fn new() -> Self {
        Self {
            sensors: Arc::new(DashMap::new()),
        }
    }

    pub fn register(&self, sensor_id: Uuid, tx: mpsc::UnboundedSender<Message>) {
        self.sensors.insert(sensor_id, tx);
    }

    pub fn unregister(&self, sensor_id: Uuid) {
        self.sensors.remove(&sensor_id);
    }

    pub fn push_config(&self, sensor_id: Uuid, config_data: &str) -> bool {
        if let Some(tx) = self.sensors.get(&sensor_id) {
            let msg = serde_json::json!({
                "event": "config_update",
                "config": config_data
            });
            if let Ok(text) = serde_json::to_string(&msg) {
                return tx.send(Message::Text(text.into())).is_ok();
            }
        }
        false
    }
}

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

    /// Push an event to every connected dashboard.
    ///
    /// Send errors are dropped on purpose: `broadcast::Sender::send` fails only
    /// when nobody is subscribed, which is the normal state of a server with no
    /// dashboard open. It is not a failure of the ingest that produced it.
    pub fn broadcast(&self, event: &Event) {
        if let Ok(json) = serde_json::to_string(event) {
            let _ = self.tx.send(json);
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn event(title: &str) -> Event {
        Event {
            id: Uuid::new_v4(),
            sensor_id: None,
            event_type: "test".into(),
            severity: "high".into(),
            title: title.into(),
            description: None,
            source_ip: None,
            dest_ip: None,
            protocol: None,
            port: None,
            raw_data: None,
            tags: serde_json::json!([]),
            timestamp: Utc::now(),
        }
    }

    /// The reason the endpoint exists: a dashboard sees an event as it lands.
    /// Nothing called this before it was wired into ingest, so `/ws/events`
    /// accepted connections and then stayed silent.
    #[tokio::test]
    async fn a_broadcast_reaches_every_subscriber() {
        let state = WsState::new();
        let mut a = state.tx.subscribe();
        let mut b = state.tx.subscribe();

        state.broadcast(&event("port scan"));

        for rx in [&mut a, &mut b] {
            let got = rx.recv().await.expect("subscriber receives the event");
            assert!(got.contains("port scan"), "{got}");
            assert!(got.contains("\"severity\":\"high\""), "{got}");
        }
    }

    /// A server with no dashboard open is the normal case, and ingest must not
    /// treat it as a failure.
    #[test]
    fn broadcasting_with_nobody_listening_is_not_an_error() {
        let state = WsState::new();
        state.broadcast(&event("nobody home"));
    }

    /// Only events that serialise are sent, and a late subscriber does not
    /// receive what was published before it joined.
    #[tokio::test]
    async fn a_subscriber_only_receives_what_follows_it() {
        let state = WsState::new();
        state.broadcast(&event("before"));

        let mut late = state.tx.subscribe();
        state.broadcast(&event("after"));

        let got = late.recv().await.unwrap();
        assert!(got.contains("after"), "{got}");
        assert!(!got.contains("before"), "{got}");
    }
}
