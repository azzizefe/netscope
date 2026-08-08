use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
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
            root_store
                .add(cert)
                .context("Failed to add CA certificate")?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
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

// These two read PEM through `rustls::pki_types` rather than `rustls-pemfile`.
//
// `rustls-pemfile` carries RUSTSEC-2025-0134 (unmaintained): its job moved into
// `rustls-pki-types`, which rustls already pulls in, so the crate was a second
// copy of code we were depending on anyway. Not a vulnerability — an
// unmaintained crate is one that will not receive the next fix — but this one
// parses key material on the TLS path, which is a poor place to hold a
// dependency nobody is maintaining.
//
// `PrivateKeyDer::from_pem_file` also replaces the hand-rolled loop below it,
// which matched PKCS#1, PKCS#8 and SEC1 by hand and skipped anything else.

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("Failed to read certificate file: {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("No usable private key found in {}", path.display()))
}
