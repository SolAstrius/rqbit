//! Diffie-Hellman key exchange for MSE/PE.
//!
//! Uses the fixed 768-bit safe prime and generator G=2 from the Message Stream
//! Encryption spec. Private keys are 160-bit random integers (the spec's
//! recommended size). All public values are 768 bits == 96 bytes, big-endian,
//! left zero-padded.

use std::sync::LazyLock;

use num_bigint::BigUint;
use rand::RngCore;

/// Length in bytes of P, S, Ya, Yb (768 bits).
pub(crate) const DH_LEN: usize = 96;

// The MSE prime P (768-bit safe prime), hex without the "0x" prefix.
const P_HEX: &[u8] = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563";

static P: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::parse_bytes(P_HEX, 16).expect("valid MSE prime P"));

fn left_pad(bytes: &[u8]) -> [u8; DH_LEN] {
    // `bytes` is a big-endian integer of at most DH_LEN bytes (since value < P < 2^768).
    debug_assert!(bytes.len() <= DH_LEN);
    let mut out = [0u8; DH_LEN];
    out[DH_LEN - bytes.len()..].copy_from_slice(bytes);
    out
}

pub(crate) struct DhKeys {
    private: BigUint,
    /// Our public key Y = G^X mod P, as 96 big-endian bytes.
    pub public: [u8; DH_LEN],
}

impl DhKeys {
    /// Derive the shared secret S = peer_public^X mod P.
    pub fn shared_secret(&self, peer_public: &[u8; DH_LEN]) -> [u8; DH_LEN] {
        let y = BigUint::from_bytes_be(peer_public);
        left_pad(&y.modpow(&self.private, &P).to_bytes_be())
    }
}

/// Generate a fresh DH keypair with a 160-bit private key.
pub(crate) fn generate() -> DhKeys {
    let mut x = [0u8; 20]; // 160-bit private key
    rand::rng().fill_bytes(&mut x);
    let private = BigUint::from_bytes_be(&x);
    let public = BigUint::from(2u32).modpow(&private, &P);
    DhKeys {
        public: left_pad(&public.to_bytes_be()),
        private,
    }
}

#[cfg(test)]
mod tests {
    use super::{DH_LEN, generate};

    #[test]
    fn dh_agreement() {
        let a = generate();
        let b = generate();
        let sa = a.shared_secret(&b.public);
        let sb = b.shared_secret(&a.public);
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), DH_LEN);
        // Vanishingly unlikely to be all-zero for a real exchange.
        assert!(sa.iter().any(|&x| x != 0));
    }
}
