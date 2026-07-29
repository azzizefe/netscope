use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::state::AgentState;

#[derive(Debug, Deserialize)]
pub struct UpgradeInfo {
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// Minisign signature over the binary, base64 as `minisign -S` emits it.
    ///
    /// Optional in the type so a server that does not sign yet produces a
    /// refusal with a clear message rather than a deserialisation error two
    /// layers away from the cause.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Public half of the key that signs agent releases, baked in when the agent is
/// built (`NETSCOPE_AGENT_UPDATE_PUBKEY=<minisign public key>`).
///
/// Compiled in rather than read from the config file on purpose. The threat
/// this defends against is a server — or anything that can answer as one —
/// handing a sensor a binary to run as a service account. A key loaded from
/// disk at runtime is swappable by whoever can write that file, which on a
/// host already compromised is the same attacker, so it would verify the
/// attacker's own signature. A build-time key can only be changed by rebuilding.
const UPDATE_PUBKEY: Option<&str> = option_env!("NETSCOPE_AGENT_UPDATE_PUBKEY");

pub async fn upgrade_loop(state: AgentState) {
    if !state.config.read().upgrade.enabled {
        return;
    }

    // Fail closed, and fail once. Without a compiled-in key nothing that
    // arrives can be verified, so there is no point waking up hourly to
    // discover that again — say so and stop.
    if UPDATE_PUBKEY.is_none() {
        tracing::warn!(
            "Automatic upgrades are disabled: this agent was built without \
             NETSCOPE_AGENT_UPDATE_PUBKEY, so a downloaded binary cannot be \
             verified. Upgrade this sensor out of band."
        );
        return;
    }

    loop {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        let interval =
            std::time::Duration::from_secs(state.config.read().upgrade.check_interval_secs);
        tokio::time::sleep(interval).await;

        match check_upgrade(&state).await {
            Ok(Some(info)) => {
                tracing::info!(
                    "Upgrade available: {} -> {}",
                    env!("CARGO_PKG_VERSION"),
                    info.version
                );
                if let Err(e) = upgrade_binary(&state, &info).await {
                    tracing::error!("Upgrade failed: {}", e);
                }
            }
            Ok(None) => {
                tracing::debug!("No upgrade available");
            }
            Err(e) => {
                tracing::warn!("Upgrade check failed: {}", e);
            }
        }
    }
}

async fn check_upgrade(state: &AgentState) -> anyhow::Result<Option<UpgradeInfo>> {
    let current = env!("CARGO_PKG_VERSION");
    let channel = state.config.read().upgrade.channel.clone();

    let info: UpgradeInfo = state
        .http_get(&format!(
            "/api/v1/upgrade/check?version={}&channel={}",
            current, channel
        ))
        .await?;

    if is_newer(&info.version, current) {
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

/// Whether `offered` supersedes `current`, by version order rather than by
/// string order.
///
/// `"0.10.0" > "0.9.0"` is false when compared as strings — the tenth minor
/// release would never have been offered to a sensor on the ninth. Anything
/// that is not a valid semver falls back to inequality, which offers the
/// upgrade rather than silently pinning a sensor to a build it cannot leave.
fn is_newer(offered: &str, current: &str) -> bool {
    match (
        semver::Version::parse(offered),
        semver::Version::parse(current),
    ) {
        (Ok(offered), Ok(current)) => offered > current,
        _ => offered != current,
    }
}

pub async fn do_upgrade(state: &AgentState) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let channel = state.config.read().upgrade.channel.clone();

    let info: UpgradeInfo = state
        .http_get(&format!(
            "/api/v1/upgrade/check?version={}&channel={}",
            current, channel
        ))
        .await?;

    if !is_newer(&info.version, current) {
        anyhow::bail!(
            "No newer version available (current: {}, latest: {})",
            current,
            info.version
        );
    }

    upgrade_binary(state, &info).await
}

async fn upgrade_binary(state: &AgentState, info: &UpgradeInfo) -> anyhow::Result<()> {
    let tmp_dir = std::env::temp_dir().join("netscope-upgrade");
    std::fs::create_dir_all(&tmp_dir)?;

    let bin_name = current_binary_name();
    let download_path = tmp_dir.join(format!("{}.new", bin_name));
    let backup_path = tmp_dir.join(format!("{}.bak", bin_name));

    let url = if info.url.starts_with("http") {
        info.url.clone()
    } else {
        format!("{}{}", state.config.read().server.url, info.url)
    };

    tracing::info!("Downloading new binary from {}", url);
    let response = state.http_client.get(&url).send().await?;
    let bytes = response.bytes().await?;

    // The checksum is a transport integrity check and nothing more: it arrives
    // from the same response as the URL it describes, so anything able to serve
    // the binary can serve a matching digest. It runs first only because it is
    // the cheaper way to catch a truncated download.
    let hash = Sha256::digest(&bytes);
    let hash_hex = format!("{:x}", hash);
    if hash_hex != info.sha256 {
        anyhow::bail!(
            "SHA256 mismatch: expected {}, got {}",
            info.sha256,
            hash_hex
        );
    }

    // This is the check that actually decides whether to run the thing.
    verify_signature(&bytes, info.signature.as_deref())?;
    tracing::info!("Checksum and signature verified");

    std::fs::write(&download_path, &bytes)?;
    set_executable(&download_path);

    let current_path = std::env::current_exe()?;

    if backup_path.exists() {
        std::fs::remove_file(&backup_path)?;
    }

    std::fs::rename(&current_path, &backup_path)?;
    if let Err(e) = std::fs::rename(&download_path, &current_path) {
        let _ = std::fs::rename(&backup_path, &current_path);
        anyhow::bail!("Swap failed, rollback applied: {}", e);
    }

    tracing::info!("Upgrade to {} complete. Restarting...", info.version);

    restart_process(&current_path);
    Ok(())
}

/// Refuses the binary unless it carries a signature from the release key.
///
/// Every failure path here is a refusal, never a downgrade to "checksum was
/// fine". Replacing the binary means handing the sender code execution as
/// whatever account runs the sensor, so an unsigned or unverifiable download is
/// not a degraded upgrade — it is the attack this exists to stop.
fn verify_signature(bytes: &[u8], signature: Option<&str>) -> anyhow::Result<()> {
    verify_signature_with(UPDATE_PUBKEY, bytes, signature)
}

/// The body of [`verify_signature`], with the key passed in so the refusal
/// paths can be tested without rebuilding the crate with a key baked in.
fn verify_signature_with(
    pubkey: Option<&str>,
    bytes: &[u8],
    signature: Option<&str>,
) -> anyhow::Result<()> {
    let Some(pubkey) = pubkey else {
        anyhow::bail!(
            "refusing to upgrade: agent built without NETSCOPE_AGENT_UPDATE_PUBKEY, \
             so the downloaded binary cannot be verified"
        );
    };

    let Some(signature) = signature else {
        anyhow::bail!("refusing to upgrade: server offered a binary with no signature");
    };

    let pubkey = minisign_verify::PublicKey::from_base64(pubkey.trim())
        .map_err(|e| anyhow::anyhow!("built-in update public key is malformed: {e}"))?;
    let signature = minisign_verify::Signature::decode(signature.trim())
        .map_err(|e| anyhow::anyhow!("update signature is malformed: {e}"))?;

    pubkey
        .verify(bytes, &signature, false)
        .map_err(|e| anyhow::anyhow!("update signature does not verify: {e}"))?;
    Ok(())
}

fn current_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "netscope-agent".into())
}

fn set_executable(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(_path, perms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed minisign public key, used to get past key parsing so the
    /// signature checks below are the thing under test. Nothing is signed with
    /// it — the corresponding secret key does not exist here, which is the
    /// point: no input in these tests should ever verify.
    const SAMPLE_PUBKEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    #[test]
    fn an_agent_without_a_built_in_key_refuses_every_binary() {
        let err = verify_signature_with(None, b"any payload", Some("any signature"))
            .expect_err("no key means nothing can be trusted");
        assert!(
            err.to_string().contains("NETSCOPE_AGENT_UPDATE_PUBKEY"),
            "the refusal should name what is missing: {err}",
        );
    }

    /// The case that made this function necessary: before it existed the
    /// checksum was the only gate, and the checksum comes from whoever served
    /// the binary.
    #[test]
    fn an_unsigned_binary_is_refused() {
        let err = verify_signature_with(Some(SAMPLE_PUBKEY), b"a payload", None)
            .expect_err("an unsigned binary must not be installed");
        assert!(
            err.to_string().contains("no signature"),
            "unexpected refusal: {err}",
        );
    }

    /// Garbage in either field is a refusal, not a pass-through. A parse error
    /// must never be treated as "nothing to check".
    /// The tests below only mean anything if the sample key gets past parsing —
    /// otherwise every one of them would be refusing on a malformed key and the
    /// signature check would never run at all.
    #[test]
    fn the_sample_key_is_a_parseable_minisign_key() {
        minisign_verify::PublicKey::from_base64(SAMPLE_PUBKEY)
            .expect("SAMPLE_PUBKEY must parse, or the refusal tests prove nothing");
    }

    #[test]
    fn a_malformed_key_or_signature_is_refused() {
        assert!(verify_signature_with(Some("not-a-key"), b"payload", Some("sig")).is_err());
        assert!(
            verify_signature_with(Some(SAMPLE_PUBKEY), b"payload", Some("not-a-signature"))
                .is_err()
        );
        assert!(verify_signature_with(Some(SAMPLE_PUBKEY), b"payload", Some("")).is_err());
    }

    /// Version order, not string order. `"0.10.0" > "0.9.0"` is false as
    /// strings, so a sensor on 0.9.0 was never offered 0.10.0.
    #[test]
    fn a_tenth_minor_release_supersedes_a_ninth() {
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.2.1", "0.2.0"));
    }

    #[test]
    fn the_same_or_an_older_version_is_not_an_upgrade() {
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("0.9.0", "0.10.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
    }

    /// A version neither side can parse falls back to inequality: better to
    /// offer an upgrade that the signature check will judge than to pin a
    /// sensor to a build it can never leave.
    #[test]
    fn an_unparseable_version_falls_back_to_inequality() {
        assert!(is_newer("nightly-2026-07-28", "0.2.0"));
        assert!(!is_newer("nightly-2026-07-28", "nightly-2026-07-28"));
    }
}

fn restart_process(new_binary: &Path) {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let _ = std::process::Command::new(new_binary)
        .args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();

    std::process::exit(0);
}
