use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

pub fn build_tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
    ca_path: Option<&Path>,
) -> Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = if let Some(ca) = ca_path {
        let ca_certs = load_certs(ca)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)
                .context("Failed to add CA certificate")?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(
            Arc::new(root_store),
        )
        .build()
        .context("Failed to build mTLS client verifier")?;

        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("Failed to configure TLS with mTLS")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to configure TLS")?
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read certificate file: {}", path.display()))?;
    let certs = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path)
        .with_context(|| format!("Failed to read private key file: {}", path.display()))?;
    let mut reader = data.as_slice();
    loop {
        match rustls_pemfile::read_one(&mut reader).context("Failed to parse private key PEM")? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            Some(_) => continue,
            None => anyhow::bail!("No private key found in {}", path.display()),
        }
    }
}
