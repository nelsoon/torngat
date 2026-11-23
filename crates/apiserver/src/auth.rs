//! Bootstrap authentication: a single admin bearer token (M0 only; replaced by OIDC and IAM).

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{ApiError, AppState};

/// Minimum length of the bootstrap token, to rule out guessable values.
pub const MIN_TOKEN_LEN: usize = 32;

/// The expected token, stored only as a SHA-256 digest.
#[derive(Clone)]
pub struct AdminToken([u8; 32]);

impl std::fmt::Debug for AdminToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminToken(<redacted>)")
    }
}

impl AdminToken {
    pub fn new(token: &str) -> Result<Self, String> {
        if token.len() < MIN_TOKEN_LEN {
            return Err(format!(
                "admin token must be at least {MIN_TOKEN_LEN} characters"
            ));
        }
        Ok(Self(Sha256::digest(token.as_bytes()).into()))
    }

    /// Constant-time check. Comparing digests also hides the token length.
    fn matches(&self, presented: &str) -> bool {
        let d: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        bool::from(self.0.ct_eq(&d))
    }
}

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| state.token.matches(t));
    if !ok {
        return Err(ApiError::Unauthenticated);
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rules() {
        assert!(AdminToken::new("short").is_err());
        let t = AdminToken::new(&"x".repeat(40)).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(t.matches(&"x".repeat(40)));
        assert!(!t.matches(&"x".repeat(39)));
        assert!(!format!("{t:?}").contains('x'));
    }
}
