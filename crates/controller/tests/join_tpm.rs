//! TPM enrollment end to end, against a real (software) TPM: attested join, then mTLS with the
//! TPM-held key. Needs `--features tpm-tests` and `TORNGAT_TEST_TCTI` / `TORNGAT_TEST_EK_CA`
//! (`eval "$(scripts/swtpm.sh start)"`); skipped without them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{env, n};
use torngat_agent::join::{JoinError, join};
use torngat_agent::tpm::TpmKey;
use torngat_agent::{AgentConfig, FakeRuntime, NodeKey};
use torngat_pki::KeyStorage;

fn anchors() -> Vec<Vec<u8>> {
    let path = std::env::var("TORNGAT_TEST_EK_CA").expect("TORNGAT_TEST_EK_CA");
    torngat_pki::pem_certs(&std::fs::read(path).unwrap()).unwrap()
}

const HOUR: time::Duration = time::Duration::hours(1);

// One test: a TPM without a resource manager serves one connection with few object slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tpm_join_and_mtls_with_the_tpm_key() {
    let Ok(tcti) = std::env::var("TORNGAT_TEST_TCTI") else {
        eprintln!("TORNGAT_TEST_TCTI not set: skipping TPM test");
        return;
    };
    let (key, _blob) = TpmKey::create(&tcti).unwrap();
    let key = NodeKey::Tpm(key);

    // Vendor anchors configured.
    let e = env(anchors(), true).await;
    // A token pinned to another TPM refuses this one, and survives.
    let wrong = e.token(None, HOUR, Some("a".repeat(64))).await;
    let err = join(&e.join, &wrong, &n("n2"), &key, false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("not trusted")),
        "{err}"
    );
    assert!(e.token_exists(&wrong).await);

    let text = e.token(None, HOUR, None).await;
    let creds = join(&e.join, &text, &n("n2"), &key, false).await.unwrap();
    assert!(!e.token_exists(&text).await);
    let ident = e.identity("n2").await;
    assert_eq!(ident.key_storage, KeyStorage::Tpm);
    let ek = ident.ek_sha256.clone().unwrap();

    // Running with the TPM key: mTLS handshakes are signed inside the TPM.
    tokio::spawn(torngat_agent::run(
        AgentConfig {
            controller_url: format!("https://{}", e.control),
            controller_name: torngat_pki::CONTROLLER_NAME.into(),
            ca_pem: creds.ca_pem.into_bytes(),
            cert_pem: creds.cert_chain_pem.into_bytes(),
            key: key.clone(),
        },
        FakeRuntime::default(),
        torngat_agent::storage::NoDriver,
        torngat_agent::storage::FakeCrypt::default(),
    ));
    e.wait_active("n2").await;

    // Re-running join (lost answer) gets a certificate without a new token.
    join(&e.join, &text, &n("n2"), &key, true).await.unwrap();

    // Pre-registered hardware: no vendor anchors, but the token pins this TPM's EK.
    let e2 = env(Vec::new(), true).await;
    let unpinned = e2.token(None, HOUR, None).await;
    let err = join(&e2.join, &unpinned, &n("n3"), &key, false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("not trusted")),
        "{err}"
    );
    let pinned = e2.token(None, HOUR, Some(ek.clone())).await;
    join(&e2.join, &pinned, &n("n3"), &key, false)
        .await
        .unwrap();
    assert_eq!(e2.identity("n3").await.ek_sha256, Some(ek));
    e2.store.shutdown().await.unwrap();
    e.store.shutdown().await.unwrap();
}
