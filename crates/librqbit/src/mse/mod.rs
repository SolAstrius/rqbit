//! MSE/PE — Message Stream Encryption / Protocol Encryption.
//!
//! This implements the (Vuze/Azureus) Message Stream Encryption v1.0 spec: a
//! Diffie-Hellman key exchange followed by RC4-obfuscated traffic, used by
//! BitTorrent clients to defeat passive protocol identification and ISP traffic
//! shaping.
//!
//! IMPORTANT: this is obfuscation, NOT security. There is no peer
//! authentication (it is trivially MITM-able by anyone who knows the
//! info-hash), and RC4 is cryptographically weak. The info-hash is the shared
//! secret (`SKEY`). Treat this purely as anti-throttling.

mod dh;
mod handshake;
mod rc4;
mod stream;

#[cfg(test)]
mod tests;

pub(crate) use handshake::{handshake_incoming, handshake_outgoing};

use serde::{Deserialize, Serialize};

use crate::type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite};

/// Protocol-obfuscation (MSE/PE) policy.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encryption {
    /// Never use MSE. Plaintext BitTorrent only. This is the default.
    #[default]
    Disabled,
    /// Outgoing: attempt MSE, offering RC4 and plaintext in the crypto bitfield.
    /// Incoming: accept both MSE and plaintext peers.
    Enabled,
    /// Outgoing: MSE with RC4 only. Incoming: reject plaintext peers.
    Required,
}

impl Encryption {
    /// Whether MSE is on at all (for both incoming probing and outgoing
    /// initiation).
    pub(crate) fn enabled(self) -> bool {
        matches!(self, Encryption::Enabled | Encryption::Required)
    }

    /// Whether plaintext is acceptable as a fallback.
    pub(crate) fn allow_plaintext(self) -> bool {
        !matches!(self, Encryption::Required)
    }
}

/// The crypto method negotiated by the handshake (`crypto_select`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoMethod {
    Plaintext,
    Rc4,
}

impl std::fmt::Display for CryptoMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoMethod::Plaintext => f.write_str("plaintext"),
            CryptoMethod::Rc4 => f.write_str("rc4"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MseError {
    #[error("io error during MSE handshake: {0}")]
    Io(#[source] std::io::Error),
    #[error("peer disconnected during MSE handshake")]
    UnexpectedEof,
    #[error("MSE handshake exceeded size limit")]
    HandshakeTooLong,
    #[error("could not find MSE synchronization point")]
    ResyncFailed,
    #[error("MSE verification constant mismatch (wrong info-hash or not an MSE peer)")]
    BadVc,
    #[error("no MSE crypto method in common with peer")]
    NoCommonCryptoMethod,
    #[error("incoming MSE connection for an unknown torrent")]
    NoMatchingTorrent,
}

/// Wrap a reader so it re-emits `prefix` before the underlying stream. Used to
/// push back a byte peeked off a legacy (non-MSE) plaintext connection.
pub(crate) fn prepend(reader: BoxAsyncReadVectored, prefix: Vec<u8>) -> BoxAsyncReadVectored {
    Box::new(stream::EncryptedReader::new(reader, None, prefix))
}

pub(crate) struct MseOutgoing {
    pub reader: BoxAsyncReadVectored,
    pub writer: BoxAsyncWrite,
    pub method: CryptoMethod,
}

pub(crate) struct MseIncoming {
    pub reader: BoxAsyncReadVectored,
    pub writer: BoxAsyncWrite,
    pub method: CryptoMethod,
    pub info_hash: librqbit_core::hash_id::Id20,
}
