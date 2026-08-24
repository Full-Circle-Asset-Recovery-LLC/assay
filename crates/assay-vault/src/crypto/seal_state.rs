//! Live in-memory sealing state for a running engine instance.
//!
//! Companion to [`crate::crypto::kek_store`] (which handles the
//! at-rest representation) and [`crate::crypto::sealing`] (which holds
//! the primitives). This module owns the runtime state machine:
//!
//! - When `sealed = true`, the active [`KekHandle`] is logically gone;
//!   every KV / transit / collection-key operation should refuse.
//! - When `sealed = false`, the handle in the unsealed slot is the
//!   active KEK and operations proceed.
//! - During an unseal ceremony the [`UnsealAccumulator`] collects
//!   submitted shares until the threshold is reached, then yields the
//!   reconstructed KEK.

use parking_lot::RwLock;
use std::sync::Arc;

use crate::crypto::kek::KekHandle;
use crate::crypto::sealing::SealingMethod;
use crate::error::{Result, VaultError};

/// Snapshot of the live sealing state. Cheap to clone.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SealStatus {
    pub method: SealingMethod,
    pub sealed: bool,
    /// kek_metadata.kid for the active row.
    pub kid: Option<String>,
    /// For Shamir: how many shares have been submitted toward the next
    /// unseal. Resets on successful unseal or `seal`.
    pub shares_progress: u8,
    pub share_threshold: Option<u8>,
    pub share_count: Option<u8>,
}

/// Mutable runtime state. Held by [`crate::ctx::VaultCtx`] behind an
/// `Arc<RwLock<…>>`.
#[non_exhaustive]
pub struct SealStateInner {
    pub method: SealingMethod,
    pub kid: Option<String>,
    /// `None` when sealed; `Some(handle)` when unsealed.
    pub handle: Option<KekHandle>,
    /// Active accumulator for Shamir-method unseal. `None` when sealed
    /// with non-Shamir or already unsealed.
    pub accumulator: Option<UnsealAccumulator>,
    pub share_threshold: Option<u8>,
    pub share_count: Option<u8>,
    kek_digest: Option<[u8; 32]>,
    pending_activation: bool,
}

pub struct PendingKek {
    kid: String,
    handle: KekHandle,
}

impl PendingKek {
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

pub enum ShareSubmission {
    Progress(SealStatus),
    Ready(PendingKek),
}

impl ShareSubmission {
    pub fn status(&self) -> Option<&SealStatus> {
        match self {
            Self::Progress(status) => Some(status),
            Self::Ready(_) => None,
        }
    }
}

/// Cheap clonable wrapper.
#[derive(Clone)]
#[non_exhaustive]
pub struct SealState {
    inner: Arc<RwLock<SealStateInner>>,
}

impl SealState {
    /// Construct from a fully-resolved unsealed KEK. Used by Phase 1's
    /// plaintext-on-boot flow (the KEK row decrypts trivially) and by
    /// the post-unseal path on the Shamir flow.
    pub fn unsealed(method: SealingMethod, kid: String, handle: KekHandle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SealStateInner {
                method,
                kid: Some(kid),
                handle: Some(handle),
                accumulator: None,
                share_threshold: None,
                share_count: None,
                kek_digest: None,
                pending_activation: false,
            })),
        }
    }

    /// Construct in the sealed Shamir state — engine boot calls this
    /// when `kek_metadata.sealed = TRUE` and an operator must unseal.
    /// The `kid` parameter is the content-addressed identifier from
    /// `vault.kek_metadata`; submitted shares must reconstruct a key
    /// whose own kid matches, otherwise the submission is rejected as
    /// corrupt.
    pub fn sealed_shamir(
        kid: String,
        kek_digest: [u8; 32],
        threshold: u8,
        shares_count: u8,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SealStateInner {
                method: SealingMethod::Shamir {
                    threshold,
                    shares_count,
                },
                kid: Some(kid),
                handle: None,
                accumulator: Some(UnsealAccumulator::new(threshold)),
                share_threshold: Some(threshold),
                share_count: Some(shares_count),
                kek_digest: Some(kek_digest),
                pending_activation: false,
            })),
        }
    }

    /// Drop the in-memory KEK; future ops fail with [`VaultError::Sealed`].
    /// For Shamir-method state, primes a fresh accumulator for the next
    /// unseal.
    pub fn seal(&self) -> Result<()> {
        let mut g = self.inner.write();
        g.handle = None;
        g.pending_activation = false;
        match &g.method {
            SealingMethod::Shamir { threshold, .. } => {
                g.accumulator = Some(UnsealAccumulator::new(*threshold));
            }
            _ => {
                g.accumulator = None;
            }
        }
        Ok(())
    }

    /// Snapshot the public state.
    pub fn status(&self) -> SealStatus {
        let g = self.inner.read();
        SealStatus {
            method: g.method.clone(),
            sealed: g.handle.is_none(),
            kid: g.kid.clone(),
            shares_progress: g.accumulator.as_ref().map(|a| a.len() as u8).unwrap_or(0),
            share_threshold: g.share_threshold,
            share_count: g.share_count,
        }
    }

    /// Borrow the unsealed KEK or surface [`VaultError::Sealed`].
    pub fn require_unsealed(&self) -> Result<KekHandle> {
        let g = self.inner.read();
        g.handle.clone().ok_or(VaultError::Sealed)
    }

    /// Submit one Shamir unseal share. Returns the new
    /// [`SealStatus`]; if the threshold was hit by this submission,
    /// the state transitions to unsealed and `status.sealed = false`.
    /// Pass the raw share bytes the operator received from `init`.
    #[cfg(feature = "vault-sealing-shamir")]
    pub fn submit_shamir_share(&self, share_bytes: Vec<u8>) -> Result<ShareSubmission> {
        use crate::crypto::sealing::shamir::{Share, combine_shares};

        let mut g = self.inner.write();
        if g.handle.is_some() {
            return Err(VaultError::Invalid("vault is already unsealed".into()));
        }
        if g.pending_activation {
            return Err(VaultError::Invalid(
                "a reconstructed KEK is awaiting persistence".into(),
            ));
        }
        // Snapshot the read-only fields under the mutable lock before
        // taking the &mut borrow on accumulator — the borrow checker
        // wants exactly one borrow of `g` outstanding at a time.
        let threshold = g
            .share_threshold
            .ok_or_else(|| VaultError::Invalid("Shamir threshold missing".into()))?;
        let kid = g.kid.clone().unwrap_or_default();
        let expected_digest = g
            .kek_digest
            .ok_or_else(|| VaultError::Invalid("Shamir KEK digest missing".into()))?;
        if share_bytes.len() != 33 || !(1..=5).contains(&share_bytes[0]) {
            g.accumulator = Some(UnsealAccumulator::new(threshold));
            return Err(VaultError::Invalid(
                "Shamir share must be canonical 33-byte form with index 1..=5".into(),
            ));
        }
        let share_index = share_bytes[0];
        let acc = g
            .accumulator
            .as_mut()
            .ok_or_else(|| VaultError::Invalid("no unseal ceremony in progress".into()))?;

        if acc.contains_index(share_index) {
            *acc = UnsealAccumulator::new(threshold);
            return Err(VaultError::Invalid(
                "duplicate Shamir share index; ceremony reset".into(),
            ));
        }

        acc.push(Share::from_bytes(share_bytes));

        if (acc.len() as u8) >= threshold {
            // Try to combine; on failure the accumulator gets reset so
            // a fresh unseal ceremony can start.
            let key = match combine_shares(threshold, acc.shares()) {
                Ok(k) => k,
                Err(e) => {
                    *acc = UnsealAccumulator::new(threshold);
                    return Err(e);
                }
            };
            // Shamir's Secret Sharing has no integrity check — if a
            // share is corrupted but the math still succeeds, we get a
            // garbage 32-byte value. The kid is content-addressed (a
            // domain-separated SHA-256 truncation of the KEK), so we
            // compare the reconstructed kid against the stored one to
            // catch this silent-failure case.
            let recovered_kid = crate::crypto::kek::mint_kid(&key);
            let recovered_digest = crate::crypto::kek_store::full_kek_digest(&key);
            if recovered_digest != expected_digest || recovered_kid != kid {
                *acc = UnsealAccumulator::new(threshold);
                return Err(VaultError::Crypto(format!(
                    "shamir reconstructed an unexpected key (kid mismatch: \
                     stored '{kid}', recovered '{recovered_kid}'). Likely a \
                     corrupted or tampered share."
                )));
            }
            let handle = KekHandle::from_zeroizing(kid.clone(), key);
            g.accumulator = None;
            g.pending_activation = true;
            return Ok(ShareSubmission::Ready(PendingKek { kid, handle }));
        }

        // Status snapshot under the same write lock so the caller sees
        // a consistent post-state.
        Ok(ShareSubmission::Progress(SealStatus {
            method: g.method.clone(),
            sealed: g.handle.is_none(),
            kid: g.kid.clone(),
            shares_progress: g.accumulator.as_ref().map(|a| a.len() as u8).unwrap_or(0),
            share_threshold: g.share_threshold,
            share_count: g.share_count,
        }))
    }

    /// Replace the active KEK (for KEK rotation / KMS auto-unseal).
    pub fn set_unsealed(&self, kid: String, handle: KekHandle) {
        let mut g = self.inner.write();
        g.kid = Some(kid);
        g.handle = Some(handle);
        g.accumulator = None;
        g.pending_activation = false;
    }

    pub fn activate_pending(&self, pending: PendingKek) -> Result<()> {
        let mut g = self.inner.write();
        if !g.pending_activation || g.kid.as_deref() != Some(pending.kid.as_str()) {
            return Err(VaultError::Invalid(
                "pending KEK does not match the active ceremony".into(),
            ));
        }
        g.handle = Some(pending.handle);
        g.pending_activation = false;
        Ok(())
    }

    pub fn abort_pending_and_reset(&self) {
        let mut g = self.inner.write();
        g.handle = None;
        g.pending_activation = false;
        if let Some(threshold) = g.share_threshold {
            g.accumulator = Some(UnsealAccumulator::new(threshold));
        }
    }

    pub fn reset_sealed_shamir(
        &self,
        kid: String,
        kek_digest: [u8; 32],
        threshold: u8,
        shares_count: u8,
    ) {
        let mut g = self.inner.write();
        g.method = SealingMethod::Shamir {
            threshold,
            shares_count,
        };
        g.kid = Some(kid);
        g.handle = None;
        g.accumulator = Some(UnsealAccumulator::new(threshold));
        g.share_threshold = Some(threshold);
        g.share_count = Some(shares_count);
        g.kek_digest = Some(kek_digest);
        g.pending_activation = false;
    }
}

/// Collected shares during a Shamir unseal ceremony.
#[non_exhaustive]
pub struct UnsealAccumulator {
    threshold: u8,
    #[cfg(feature = "vault-sealing-shamir")]
    shares: Vec<crate::crypto::sealing::shamir::Share>,
}

impl UnsealAccumulator {
    pub fn new(threshold: u8) -> Self {
        Self {
            threshold,
            #[cfg(feature = "vault-sealing-shamir")]
            shares: Vec::new(),
        }
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    #[cfg(feature = "vault-sealing-shamir")]
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    #[cfg(not(feature = "vault-sealing-shamir"))]
    pub fn len(&self) -> usize {
        0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(feature = "vault-sealing-shamir")]
    pub fn push(&mut self, share: crate::crypto::sealing::shamir::Share) {
        self.shares.push(share);
    }

    #[cfg(feature = "vault-sealing-shamir")]
    pub fn shares(&self) -> &[crate::crypto::sealing::shamir::Share] {
        &self.shares
    }

    #[cfg(feature = "vault-sealing-shamir")]
    fn contains_index(&self, index: u8) -> bool {
        self.shares
            .iter()
            .any(|share| share.0.first() == Some(&index))
    }
}

#[cfg(test)]
#[cfg(feature = "vault-sealing-shamir")]
mod tests {
    use super::*;
    use crate::crypto::aead::random_dek;
    use crate::crypto::sealing::shamir::{Share, split_kek};

    fn submit(state: &SealState, bytes: Vec<u8>) -> Result<SealStatus> {
        match state.submit_shamir_share(bytes)? {
            ShareSubmission::Progress(status) => Ok(status),
            ShareSubmission::Ready(pending) => {
                state.activate_pending(pending)?;
                Ok(state.status())
            }
        }
    }

    #[test]
    fn unsealed_round_trip() {
        let kek = random_dek();
        let handle = KekHandle::from_bytes("kek-test", kek);
        let s = SealState::unsealed(SealingMethod::Plaintext, "kek-test".into(), handle);
        assert!(!s.status().sealed);
        let _h = s.require_unsealed().unwrap();
        s.seal().unwrap();
        assert!(s.status().sealed);
        assert!(matches!(s.require_unsealed(), Err(VaultError::Sealed)));
    }

    #[test]
    fn shamir_unseal_via_share_submission() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let s = SealState::sealed_shamir(kid, digest, 3, 5);
        assert!(s.status().sealed);

        // First two shares — still sealed.
        for sh in &shares[..2] {
            let st = submit(&s, sh.as_bytes().to_vec()).unwrap();
            assert!(st.sealed);
        }
        assert_eq!(s.status().shares_progress, 2);

        // Third share trips the threshold.
        let st = submit(&s, shares[2].as_bytes().to_vec()).unwrap();
        assert!(!st.sealed, "threshold submission must unseal");
        // Reconstructed KEK matches the original — proven by wrapping
        // a known DEK on each side and comparing the unwrap result.
        let h = s.require_unsealed().unwrap();
        let test_dek = random_dek();
        let original = KekHandle::from_bytes(crate::crypto::kek::mint_kid(&kek), kek);
        let wrapped_by_original = original.wrap_dek(&test_dek).unwrap();
        let recovered = h.unwrap_dek(&wrapped_by_original).unwrap();
        assert_eq!(recovered, test_dek);
    }

    #[test]
    fn submit_after_unsealed_errors() {
        let kek = random_dek();
        let h = KekHandle::from_bytes("k", kek);
        let s = SealState::unsealed(SealingMethod::Plaintext, "k".into(), h);
        let res = s.submit_shamir_share(vec![1, 2, 3]);
        assert!(matches!(res, Err(VaultError::Invalid(_))));
    }

    #[test]
    fn corrupt_share_resets_accumulator() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let s = SealState::sealed_shamir(kid.clone(), digest, 3, 5);

        // Two good shares.
        submit(&s, shares[0].as_bytes().to_vec()).unwrap();
        submit(&s, shares[1].as_bytes().to_vec()).unwrap();
        // Garbled third share — combine either fails outright or
        // reconstructs a bogus key whose kid doesn't match. Both paths
        // reset the accumulator and return an error.
        let mut bad = shares[2].as_bytes().to_vec();
        for b in &mut bad {
            *b ^= 0xff;
        }
        let res = s.submit_shamir_share(bad);
        assert!(
            res.is_err(),
            "corrupt share must either fail combine or fail kid validation"
        );
        // Accumulator was reset.
        assert!(s.status().sealed);
        assert_eq!(s.status().shares_progress, 0);
        // A fresh ceremony with the real shares should succeed.
        submit(&s, shares[0].as_bytes().to_vec()).unwrap();
        submit(&s, shares[1].as_bytes().to_vec()).unwrap();
        let st = submit(&s, shares[2].as_bytes().to_vec()).unwrap();
        assert!(!st.sealed);
    }

    #[test]
    fn duplicate_shares_fail_and_reset_accumulator() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let state = SealState::sealed_shamir(kid, digest, 3, 5);
        assert!(
            state
                .submit_shamir_share(shares[0].as_bytes().to_vec())
                .is_ok()
        );
        assert!(
            state
                .submit_shamir_share(shares[0].as_bytes().to_vec())
                .is_err()
        );
        assert_eq!(state.status().shares_progress, 0);
        assert!(state.status().sealed);
    }

    #[test]
    fn seal_clears_handle_and_resets_accumulator() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let s = SealState::sealed_shamir(kid, digest, 3, 5);
        for sh in &shares[..3] {
            submit(&s, sh.as_bytes().to_vec()).unwrap();
        }
        assert!(!s.status().sealed);
        s.seal().unwrap();
        assert!(s.status().sealed);
        assert_eq!(s.status().shares_progress, 0);
    }

    /// Ensures the type-erased `Share` import doesn't get optimised
    /// away by the dead-code lint.
    #[test]
    fn share_bytes_round_trip() {
        let share = Share::from_bytes(vec![1, 2, 3]);
        assert_eq!(share.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn shared_state_can_transition_to_verified_shamir() {
        let old = KekHandle::generate_ephemeral();
        let state = SealState::unsealed(SealingMethod::Plaintext, old.kid().to_string(), old);
        let observer = state.clone();
        let key = random_dek();
        let kid = crate::crypto::kek::mint_kid(&key);
        let digest = crate::crypto::kek_store::full_kek_digest(&key);
        state.reset_sealed_shamir(kid.clone(), digest, 3, 5);
        let status = observer.status();
        assert!(status.sealed);
        assert_eq!(status.kid.as_deref(), Some(kid.as_str()));
        assert_eq!(status.share_threshold, Some(3));
        assert!(matches!(status.method, SealingMethod::Shamir { .. }));
    }

    #[test]
    fn threshold_returns_pending_kek_without_exposing_it() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let state = SealState::sealed_shamir(kid, digest, 3, 5);
        for share in &shares[..2] {
            assert!(matches!(
                state.submit_shamir_share(share.0.clone()).unwrap(),
                ShareSubmission::Progress(_)
            ));
        }
        let pending = match state.submit_shamir_share(shares[2].0.clone()).unwrap() {
            ShareSubmission::Ready(pending) => pending,
            ShareSubmission::Progress(_) => panic!("threshold must produce pending KEK"),
        };
        assert!(matches!(state.require_unsealed(), Err(VaultError::Sealed)));
        state.activate_pending(pending).unwrap();
        assert!(state.require_unsealed().is_ok());
    }

    #[test]
    fn malformed_out_of_range_and_duplicate_shares_reset_immediately() {
        let kek = random_dek();
        let shares = split_kek(&kek, 3, 5).unwrap();
        let kid = crate::crypto::kek::mint_kid(&kek);
        let digest = crate::crypto::kek_store::full_kek_digest(&kek);
        let state = SealState::sealed_shamir(kid, digest, 3, 5);

        state.submit_shamir_share(shares[0].0.clone()).unwrap();
        assert!(state.submit_shamir_share(vec![1, 2]).is_err());
        assert_eq!(state.status().shares_progress, 0);

        let mut out_of_range = shares[0].0.clone();
        out_of_range[0] = 6;
        assert!(state.submit_shamir_share(out_of_range).is_err());
        assert_eq!(state.status().shares_progress, 0);

        state.submit_shamir_share(shares[0].0.clone()).unwrap();
        assert!(state.submit_shamir_share(shares[0].0.clone()).is_err());
        assert_eq!(state.status().shares_progress, 0);
    }
}
