//! TPM-held node keys (feature `tpm`).
//!
//! The node key is an ECDSA P-256 signing key created inside the TPM under the standard storage
//! root key (re-derived from its template on every start, so nothing persistent is left in the
//! TPM). It is fixed-TPM and fixed-parent: the TPM never lets it out. On disk there is only the
//! key blob, wrapped by the TPM and useless anywhere else.
//!
//! No authorization values are used, so a wrong value can never trip the TPM's dictionary-attack
//! lockout. Access is controlled by who may open the TPM device.
//!
//! The same TPM proves all this to the controller at join (see `torngat-attest`): an attestation
//! key under the endorsement key certifies the node key.

use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};

use tss_esapi::Context;
use tss_esapi::abstraction::{ak, ek};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{AuthHandle, KeyHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    Data, Digest, EccPoint, EccScheme, EncryptedSecret, HashScheme, HashcheckTicket, IdObject,
    KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder,
    Signature, SignatureScheme, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("tpm: {0}")]
    Tss(#[from] tss_esapi::Error),
    #[error("tpm: {0}")]
    Other(String),
}

fn other(e: impl std::fmt::Display) -> TpmError {
    TpmError::Other(e.to_string())
}

fn open(tcti: &str) -> Result<Context, TpmError> {
    Ok(Context::new(TctiNameConf::from_str(tcti)?)?)
}

/// Whether a TPM answers at `tcti`.
pub fn available(tcti: &str) -> bool {
    open(tcti).is_ok()
}

/// The TPM's RSA 2048 endorsement key certificate (DER), as stored by its manufacturer.
pub fn ek_certificate(tcti: &str) -> Result<Vec<u8>, TpmError> {
    let mut ctx = open(tcti)?;
    Ok(ek::retrieve_ek_pubcert(
        &mut ctx,
        AsymmetricAlgorithm::Rsa.try_into()?,
    )?)
}

fn srk(ctx: &mut Context) -> Result<KeyHandle, TpmError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;
    Ok(ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?
        .key_handle)
}

fn node_key_template() -> Result<Public, TpmError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_is_signing_key(true)
                .with_restricted(false)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn pad32(b: &[u8]) -> Result<[u8; 32], TpmError> {
    if b.len() > 32 {
        return Err(other("coordinate too long"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

struct Inner {
    ctx: Context,
    key: KeyHandle,
}

/// A loaded TPM node key. Cheap to clone; signing is serialized on one TPM context.
#[derive(Clone)]
pub struct TpmKey {
    inner: Arc<Mutex<Inner>>,
    tcti: String,
    public: Public,
    /// Uncompressed SEC1 point.
    point: Vec<u8>,
}

impl std::fmt::Debug for TpmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmKey")
            .field("tcti", &self.tcti)
            .finish_non_exhaustive()
    }
}

/// Uncompressed SEC1 point of an ECC P-256 key, via the same parser the controller uses.
fn point_of(public: &Public) -> Result<Vec<u8>, TpmError> {
    let k = torngat_attest::wire::EccPublic::parse(&public.marshall()?).map_err(other)?;
    let mut p = vec![0x04];
    p.extend_from_slice(&k.x);
    p.extend_from_slice(&k.y);
    Ok(p)
}

fn encode_blob(public: &Public, private: &Private) -> Result<Vec<u8>, TpmError> {
    let pubb = public.marshall()?;
    let privb = private.value();
    let mut v = Vec::with_capacity(4 + pubb.len() + privb.len());
    for part in [pubb.as_slice(), privb] {
        v.extend_from_slice(&u16::try_from(part.len()).map_err(other)?.to_be_bytes());
        v.extend_from_slice(part);
    }
    Ok(v)
}

fn decode_blob(b: &[u8]) -> Result<(Public, Private), TpmError> {
    let bad = || other("malformed key blob");
    let take = |b: &[u8]| -> Result<(Vec<u8>, usize), TpmError> {
        let n = usize::from(u16::from_be_bytes([
            *b.first().ok_or_else(bad)?,
            *b.get(1).ok_or_else(bad)?,
        ]));
        Ok((b.get(2..2 + n).ok_or_else(bad)?.to_vec(), 2 + n))
    };
    let (pubb, n1) = take(b)?;
    let (privb, n2) = take(&b[n1..])?;
    if n1 + n2 != b.len() {
        return Err(bad());
    }
    Ok((Public::unmarshall(&pubb)?, Private::try_from(privb)?))
}

impl TpmKey {
    /// Creates a new node key in the TPM at `tcti`. Returns the key and its blob to save.
    pub fn create(tcti: &str) -> Result<(Self, Vec<u8>), TpmError> {
        let mut ctx = open(tcti)?;
        let parent = srk(&mut ctx)?;
        let template = node_key_template()?;
        let created = ctx.execute_with_nullauth_session(|c| {
            c.create(parent, template, None, None, None, None)
        })?;
        let blob = encode_blob(&created.out_public, &created.out_private)?;
        let key = ctx.execute_with_nullauth_session(|c| {
            c.load(parent, created.out_private, created.out_public.clone())
        })?;
        ctx.flush_context(parent.into())?;
        Ok((Self::wrap(ctx, key, tcti, created.out_public)?, blob))
    }

    /// Loads a key blob made by [`TpmKey::create`] on this TPM.
    pub fn load(tcti: &str, blob: &[u8]) -> Result<Self, TpmError> {
        let (public, private) = decode_blob(blob)?;
        let mut ctx = open(tcti)?;
        let parent = srk(&mut ctx)?;
        let key = ctx.execute_with_nullauth_session(|c| c.load(parent, private, public.clone()))?;
        ctx.flush_context(parent.into())?;
        Self::wrap(ctx, key, tcti, public)
    }

    fn wrap(ctx: Context, key: KeyHandle, tcti: &str, public: Public) -> Result<Self, TpmError> {
        Ok(Self {
            point: point_of(&public)?,
            inner: Arc::new(Mutex::new(Inner { ctx, key })),
            tcti: tcti.to_owned(),
            public,
        })
    }

    /// The key's public part as the TPM describes it (marshalled `TPMT_PUBLIC`).
    pub fn public_marshalled(&self) -> Result<Vec<u8>, TpmError> {
        Ok(self.public.marshall()?)
    }

    /// Signs SHA-256(`msg`); returns a DER ECDSA signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, TpmError> {
        use sha2::Digest as _;
        let digest = Digest::try_from(sha2::Sha256::digest(msg).to_vec())?;
        let ticket = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        })?;
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let key = g.key;
        let sig = g.ctx.execute_with_nullauth_session(|c| {
            c.sign(key, digest, SignatureScheme::Null, ticket)
        })?;
        let Signature::EcDsa(s) = sig else {
            return Err(other("unexpected signature type"));
        };
        let sig = p256::ecdsa::Signature::from_scalars(
            pad32(s.signature_r().value())?,
            pad32(s.signature_s().value())?,
        )
        .map_err(other)?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// A CSR (DER) for this key.
    pub fn csr(&self) -> Result<Vec<u8>, TpmError> {
        let p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(other)?;
        Ok(p.serialize_request(self).map_err(other)?.der().to_vec())
    }

    /// Attests this key for a join: reads the EK certificate and creates an attestation key.
    pub fn attest(&self) -> Result<Attestation, TpmError> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let ctx = &mut g.ctx;
        let ek_cert = ek::retrieve_ek_pubcert(ctx, AsymmetricAlgorithm::Rsa.try_into()?)?;
        let ek = ek::create_ek_object(ctx, AsymmetricAlgorithm::Rsa, None)?;
        let created = ak::create_ak(
            ctx,
            ek,
            HashingAlgorithm::Sha256,
            SignatureSchemeAlgorithm::EcDsa,
            None,
            None,
        )?;
        let ak_public = created.out_public.marshall()?;
        let ak = ak::load_ak(ctx, ek, None, created.out_private, created.out_public)?;
        Ok(Attestation {
            key: self.clone(),
            ek,
            ak,
            ek_cert,
            ak_public,
        })
    }
}

/// An attestation in progress: the EK and AK stay loaded until it is dropped.
pub struct Attestation {
    key: TpmKey,
    ek: KeyHandle,
    ak: KeyHandle,
    pub ek_cert: Vec<u8>,
    /// Marshalled `TPMT_PUBLIC` of the attestation key.
    pub ak_public: Vec<u8>,
}

impl std::fmt::Debug for Attestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Attestation")
    }
}

/// The node's answer to a challenge.
#[derive(Debug)]
pub struct Answer {
    pub activated_secret: Vec<u8>,
    /// Marshalled `TPMS_ATTEST` and `TPMT_SIGNATURE` of the AK certifying the node key.
    pub certify_attest: Vec<u8>,
    pub certify_signature: Vec<u8>,
}

impl Attestation {
    /// Activates the controller's credential and certifies the node key over `nonce`.
    pub fn answer(
        &self,
        id_object: &[u8],
        encrypted_secret: &[u8],
        nonce: &[u8],
    ) -> Result<Answer, TpmError> {
        let mut g = self
            .key
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = g.key;
        let ctx = &mut g.ctx;

        // ActivateCredential: the AK needs a plain HMAC session, the EK a policy session
        // satisfied by PolicySecret on the endorsement hierarchy (its default policy).
        let (attrs, mask) = SessionAttributesBuilder::new().build();
        let hmac = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| other("no session"))?;
        ctx.tr_sess_set_attributes(hmac, attrs, mask)?;
        let policy = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or_else(|| other("no session"))?;
        ctx.tr_sess_set_attributes(policy, attrs, mask)?;
        ctx.execute_with_session(Some(hmac), |c| {
            c.policy_secret(
                PolicySession::try_from(policy)?,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })?;
        ctx.set_sessions((Some(hmac), Some(policy), None));
        let secret = ctx.activate_credential(
            self.ak,
            self.ek,
            IdObject::try_from(id_object.to_vec())?,
            EncryptedSecret::try_from(encrypted_secret.to_vec())?,
        );
        ctx.clear_sessions();
        ctx.flush_context(SessionHandle::from(hmac).into())?;
        ctx.flush_context(SessionHandle::from(policy).into())?;
        let secret = secret?;

        let ak = self.ak;
        let (attest, sig) = ctx.execute_with_sessions(
            (
                Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
                Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
                None,
            ),
            |c| {
                c.certify(
                    ObjectHandle::from(key),
                    ak,
                    Data::try_from(nonce.to_vec())?,
                    SignatureScheme::Null,
                )
            },
        )?;
        Ok(Answer {
            activated_secret: secret.value().to_vec(),
            certify_attest: attest.marshall()?,
            certify_signature: sig.marshall()?,
        })
    }
}

impl Drop for Attestation {
    fn drop(&mut self) {
        let mut g = self
            .key
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _ = g.ctx.flush_context(self.ak.into());
        let _ = g.ctx.flush_context(self.ek.into());
    }
}

impl rcgen::PublicKeyData for TpmKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for TpmKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        TpmKey::sign(self, msg).map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// The key as a rustls client-authentication key.
#[derive(Debug)]
pub struct TlsKey(pub TpmKey);

impl rustls::sign::SigningKey for TlsKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(TlsSigner(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct TlsSigner(TpmKey);

impl rustls::sign::Signer for TlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0
            .sign(message)
            .map_err(|e| rustls::Error::General(e.to_string()))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}
