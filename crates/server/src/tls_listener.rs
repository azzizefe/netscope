use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use axum::serve::Listener;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::tls;

pub struct TlsListener {
    inner: TcpListener,
    acceptor: Arc<TlsAcceptor>,
}

impl TlsListener {
    pub async fn new(
        addr: &SocketAddr,
        cert_path: &Path,
        key_path: &Path,
        ca_path: Option<&Path>,
    ) -> Result<Self> {
        let acceptor = tls::build_tls_acceptor(cert_path, key_path, ca_path)?;
        let inner = TcpListener::bind(addr).await?;
        Ok(Self { inner, acceptor: Arc::new(acceptor) })
    }
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                    continue;
                }
            };

            match self.acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, addr),
                Err(e) => {
                    tracing::warn!("TLS handshake failed from {}: {}", addr, e);
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> Result<Self::Addr, std::io::Error> {
        self.inner.local_addr()
    }
}
