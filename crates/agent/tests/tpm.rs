//! TPM tests against a real (software) TPM. Skipped unless `TORNGAT_TEST_TCTI` is set; start one
//! with `eval "$(scripts/swtpm.sh start)"`. `TORNGAT_TEST_EK_CA` names the EK issuer (PEM).

#![cfg(feature = "tpm")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use torngat_agent::tpm::TpmKey;

/// A TPM without a resource manager has room for very few loaded objects: one test at a time.
static TPM: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tcti() -> Option<String> {
    let t = std::env::var("TORNGAT_TEST_TCTI").ok();
    if t.is_none() {
        eprintln!("TORNGAT_TEST_TCTI not set: skipping TPM test");
    }
    t
}

fn anchors() -> Vec<Vec<u8>> {
    let path = std::env::var("TORNGAT_TEST_EK_CA").expect("TORNGAT_TEST_EK_CA");
    pem::parse_many(std::fs::read(path).unwrap())
        .unwrap()
        .into_iter()
        .map(|p| p.into_contents())
        .collect()
}

#[test]
fn key_survives_reload_and_signs_csrs() {
    let _one = TPM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(tcti) = tcti() else { return };
    let (key, blob) = TpmKey::create(&tcti).unwrap();
    let csr = key.csr().unwrap();
    // The CSR is properly self-signed by the TPM key and accepted by the CA.
    let ca = torngat_pki::Ca::generate().unwrap();
    let issued = ca
        .sign_node_csr(&csr, &torngat_api::Name::new("n1").unwrap())
        .unwrap();
    let spki = torngat_pki::spki_sha256(&issued.cert_der).unwrap();
    assert_eq!(spki, torngat_pki::ca::csr_spki_sha256(&csr).unwrap());
    drop(key);

    // Same key after a reload from the blob.
    let again = TpmKey::load(&tcti, &blob).unwrap();
    let csr2 = again.csr().unwrap();
    assert_eq!(torngat_pki::ca::csr_spki_sha256(&csr2).unwrap(), spki);
    // A damaged blob is refused.
    let mut bad = blob.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(TpmKey::load(&tcti, &bad).is_err());
}

#[test]
fn attestation_verifies_with_the_controller_side_code() {
    let _one = TPM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(tcti) = tcti() else { return };
    let (key, _) = TpmKey::create(&tcti).unwrap();
    let csr = key.csr().unwrap();
    let csr_spki = torngat_pki::ca::csr_spki_sha256(&csr).unwrap();
    let att = key.attest().unwrap();

    let ek = torngat_attest::verify_endorsement(&att.ek_cert, &anchors(), None).unwrap();
    let node_public = key.public_marshalled().unwrap();
    let (pending, ch) =
        torngat_attest::begin(&ek, &att.ak_public, &node_public, &csr_spki).unwrap();
    let ans = att
        .answer(&ch.id_object, &ch.encrypted_secret, &ch.nonce)
        .unwrap();
    pending
        .finish(
            &ans.activated_secret,
            &ans.certify_attest,
            &ans.certify_signature,
        )
        .unwrap();

    // A credential made for another AK name cannot be activated by this TPM.
    let (_, wrong) = torngat_attest::begin(&ek, &att.ak_public, &node_public, &csr_spki).unwrap();
    let mut tampered = wrong.id_object.clone();
    tampered[5] ^= 1;
    assert!(
        att.answer(&tampered, &wrong.encrypted_secret, &wrong.nonce)
            .is_err()
    );
}
