//! Sys-routes for sealing — seal-status / init / unseal / seal.
//!
//! Plan 17 §S7. Mounted under `/api/v1/vault/sys/*`. Admin-key gated
//! for Phase 2; the init / seal / unseal endpoints are operator-level
//! actions that bypass the per-request seal gate (you can't unseal a
//! sealed vault if every endpoint refuses sealed access).

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::ctx::VaultCtx;
use crate::error::VaultError;
use crate::router::vault_err_to_response;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultCtx: FromRef<S>,
{
    Router::new()
        .route("/sys/seal-status", get(seal_status::<S>))
        .route("/sys/seal", post(seal_op::<S>))
        .route("/sys/unseal", post(unseal_op::<S>))
        .route("/sys/init", post(init_op::<S>))
}

#[derive(Deserialize)]
struct InitBody {
    /// Number of shares operators receive.
    shares_count: u8,
    /// Threshold needed to unseal — must be ≥ 1 and ≤ shares_count.
    threshold: u8,
}

#[derive(Serialize)]
struct InitResponse {
    kid: String,
    /// One base64-encoded share per entry. Operators MUST store these
    /// — the engine will not return them again.
    shares_b64: Vec<String>,
    threshold: u8,
    shares_count: u8,
}

async fn init_op<S>(
    State(vault): State<VaultCtx>,
    axum::Json(body): axum::Json<InitBody>,
) -> Response
where
    S: Clone + Send + Sync + 'static,
    VaultCtx: FromRef<S>,
{
    let store = match vault.seal_store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return vault_err_to_response(VaultError::Invalid(
                "sealing backend not configured on this engine".into(),
            ));
        }
    };
    match store.init_shamir(body.threshold, body.shares_count).await {
        Ok((kid, kek_digest, shares)) => {
            // Re-prime the runtime SealState so subsequent /sys/unseal
            // calls accumulate against the just-initialised KEK.
            vault.seal_state.reset_sealed_shamir(
                kid.clone(),
                kek_digest,
                body.threshold,
                body.shares_count,
            );
            let resp = InitResponse {
                kid,
                shares_b64: shares
                    .into_iter()
                    .map(|s| data_encoding::BASE64.encode(&s))
                    .collect(),
                threshold: body.threshold,
                shares_count: body.shares_count,
            };
            (StatusCode::CREATED, axum::Json(resp)).into_response()
        }
        Err(e) => vault_err_to_response(e),
    }
}

#[derive(Serialize)]
struct SealStatusResponse {
    sealed: bool,
    method: String,
    kid: Option<String>,
    shares_progress: u8,
    share_threshold: Option<u8>,
    share_count: Option<u8>,
}

async fn seal_status<S>(State(vault): State<VaultCtx>) -> Response
where
    S: Clone + Send + Sync + 'static,
    VaultCtx: FromRef<S>,
{
    let st = vault.seal_state.status();
    axum::Json(SealStatusResponse {
        sealed: st.sealed,
        method: st.method.as_column().to_string(),
        kid: st.kid,
        shares_progress: st.shares_progress,
        share_threshold: st.share_threshold,
        share_count: st.share_count,
    })
    .into_response()
}

async fn seal_op<S>(State(vault): State<VaultCtx>) -> Response
where
    S: Clone + Send + Sync + 'static,
    VaultCtx: FromRef<S>,
{
    if let Err(e) = vault.seal_state.seal() {
        return vault_err_to_response(e);
    }
    let kid = vault.seal_state.status().kid;
    if let (Some(store), Some(kid)) = (vault.seal_store.as_ref(), kid)
        && let Err(e) = store.set_sealed(&kid, true).await
    {
        return vault_err_to_response(e);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
#[cfg_attr(not(feature = "vault-sealing-shamir"), allow(dead_code))]
struct UnsealBody {
    /// Base64-encoded share bytes — exactly the shape returned by an
    /// init ceremony (each share is one entry from the
    /// `crypto::sealing::shamir::Share` collection).
    share_b64: String,
}

async fn unseal_op<S>(
    #[cfg_attr(not(feature = "vault-sealing-shamir"), allow(unused_variables))] State(vault): State<
        VaultCtx,
    >,
    axum::Json(body): axum::Json<UnsealBody>,
) -> Response
where
    S: Clone + Send + Sync + 'static,
    VaultCtx: FromRef<S>,
{
    #[cfg(feature = "vault-sealing-shamir")]
    {
        let share_bytes = match data_encoding::BASE64.decode(body.share_b64.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                return vault_err_to_response(VaultError::Invalid(
                    "share_b64 is not valid base64".into(),
                ));
            }
        };
        match vault.seal_state.submit_shamir_share(share_bytes) {
            Ok(st) => {
                if !st.sealed
                    && let (Some(store), Some(kid)) = (vault.seal_store.as_ref(), st.kid.as_ref())
                    && let Err(e) = store.set_sealed(kid, false).await
                {
                    let _ = vault.seal_state.seal();
                    return vault_err_to_response(e);
                }
                axum::Json(SealStatusResponse {
                    sealed: st.sealed,
                    method: st.method.as_column().to_string(),
                    kid: st.kid,
                    shares_progress: st.shares_progress,
                    share_threshold: st.share_threshold,
                    share_count: st.share_count,
                })
                .into_response()
            }
            Err(e) => vault_err_to_response(e),
        }
    }
    #[cfg(not(feature = "vault-sealing-shamir"))]
    {
        let _ = body;
        vault_err_to_response(VaultError::Invalid(
            "vault-sealing-shamir feature is not enabled in this build".into(),
        ))
    }
}

#[cfg(all(test, feature = "vault-sealing-shamir"))]
mod tests {
    use super::*;
    use crate::crypto::aead::random_dek;
    use crate::crypto::kek_store::full_kek_digest;
    use crate::crypto::sealing::SealStore;
    use crate::crypto::sealing::shamir::split_kek;
    use crate::error::Result as VaultResult;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct MemorySealStore {
        kid: String,
        digest: [u8; 32],
        shares: Vec<Vec<u8>>,
        flags: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait::async_trait]
    impl SealStore for MemorySealStore {
        async fn init_shamir(
            &self,
            threshold: u8,
            shares_count: u8,
        ) -> VaultResult<(String, [u8; 32], Vec<Vec<u8>>)> {
            if (threshold, shares_count) != (3, 5) {
                return Err(VaultError::Invalid("expected 3-of-5".into()));
            }
            Ok((self.kid.clone(), self.digest, self.shares.clone()))
        }

        async fn set_sealed(&self, _kid: &str, sealed: bool) -> VaultResult<()> {
            self.flags.lock().unwrap().push(sealed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn init_immediately_rebinds_shared_state_and_persists_unseal_and_seal() {
        let key = random_dek();
        let kid = crate::crypto::kek::mint_kid(&key);
        let digest = full_kek_digest(&key);
        let shares = split_kek(&key, 3, 5)
            .unwrap()
            .into_iter()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        let flags = Arc::new(Mutex::new(Vec::new()));
        let ctx = VaultCtx::new().with_seal_store(MemorySealStore {
            kid: kid.clone(),
            digest,
            shares: shares.clone(),
            flags: flags.clone(),
        });
        let app = router::<VaultCtx>().with_state(ctx.clone());
        let init = app
            .clone()
            .oneshot(
                Request::post("/sys/init")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"threshold":3,"shares_count":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init.status(), StatusCode::CREATED);
        let status = ctx.seal_state.status();
        assert!(status.sealed);
        assert_eq!(status.kid.as_deref(), Some(kid.as_str()));

        for (index, share) in shares.iter().take(3).enumerate() {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/sys/unseal")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "share_b64": data_encoding::BASE64.encode(share)
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(body["sealed"], index < 2);
        }
        assert_eq!(*flags.lock().unwrap(), vec![false]);

        let sealed = app
            .oneshot(Request::post("/sys/seal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(sealed.status(), StatusCode::NO_CONTENT);
        assert_eq!(*flags.lock().unwrap(), vec![false, true]);
    }
}
