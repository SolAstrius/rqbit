//! The MSE/PE 5-step handshake, for the initiator (A, outgoing) and receiver
//! (B, incoming).
//!
//! We always send an empty `IA` (initial payload) block. That keeps the
//! BitTorrent handshake out of the MSE layer entirely: once these functions
//! return the wrapped streams, the normal BT handshake/message code runs on top
//! of `EncryptedReader`/`EncryptedWriter` unchanged.
//!
//!   1 A->B: Ya, PadA
//!   2 B->A: Yb, PadB
//!   3 A->B: HASH('req1',S), HASH('req2',SKEY) xor HASH('req3',S),
//!           ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA))
//!   4 B->A: ENCRYPT(VC, crypto_select, len(PadD), PadD), ENCRYPT2(payload)
//!   5 A->B: ENCRYPT2(payload)

use librqbit_core::hash_id::Id20;
use rand::Rng;
use sha1w::{ISha1, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::dh::{self, DH_LEN};
use super::rc4::Rc4;
use super::stream::{EncryptedReader, EncryptedWriter};
use super::{CryptoMethod, MseError, MseIncoming, MseOutgoing};
use crate::type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite};

const VC: [u8; 8] = [0u8; 8];
const CRYPTO_PLAINTEXT: u32 = 0x01;
const CRYPTO_RC4: u32 = 0x02;
const MAX_PAD: usize = 512;

// Hard cap on bytes buffered while searching for a sync point. PadA/PadB are at
// most 512 bytes, plus the value/needle we're aligning to.
const MAX_SCAN: usize = DH_LEN + MAX_PAD + 64;

fn sha1_2(a: &[u8], b: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(a);
    h.update(b);
    h.finish()
}

fn sha1_3(a: &[u8], b: &[u8], c: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(a);
    h.update(b);
    h.update(c);
    h.finish()
}

fn rc4_key(label: &[u8], s: &[u8; DH_LEN], skey: &[u8; 20]) -> Rc4 {
    let mut c = Rc4::new(&sha1_3(label, s, skey));
    c.discard(1024);
    c
}

fn xor20(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut o = [0u8; 20];
    for i in 0..20 {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn random_pad() -> Vec<u8> {
    let len = rand::rng().random_range(0..=MAX_PAD);
    let mut v = vec![0u8; len];
    rand::fill(&mut v[..]);
    v
}

/// Buffered read/write helper for the handshake. Raw (undecrypted) bytes are
/// accumulated in `buf`; `pos` tracks how much has been consumed. Decryption is
/// applied by the caller after `take()`, since which bytes are encrypted depends
/// on the step.
struct HsIo {
    r: BoxAsyncReadVectored,
    w: BoxAsyncWrite,
    buf: Vec<u8>,
    pos: usize,
}

impl HsIo {
    fn new(r: BoxAsyncReadVectored, w: BoxAsyncWrite) -> Self {
        Self {
            r,
            w,
            buf: Vec::with_capacity(1024),
            pos: 0,
        }
    }

    fn avail(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    async fn read_more(&mut self) -> Result<usize, MseError> {
        let mut tmp = [0u8; 1024];
        let n = self.r.read(&mut tmp).await.map_err(MseError::Io)?;
        if n > 0 {
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    /// Ensure at least `n` bytes are available, reading from the socket as
    /// needed.
    async fn ensure(&mut self, n: usize) -> Result<(), MseError> {
        while self.avail().len() < n {
            if self.avail().len() > MAX_SCAN {
                return Err(MseError::HandshakeTooLong);
            }
            if self.read_more().await? == 0 {
                return Err(MseError::UnexpectedEof);
            }
        }
        Ok(())
    }

    /// Take `n` raw bytes (still encrypted, if applicable), advancing past them.
    async fn take(&mut self, n: usize) -> Result<Vec<u8>, MseError> {
        self.ensure(n).await?;
        let out = self.avail()[..n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// Discard bytes up to and including the next occurrence of `needle`,
    /// reading more as needed. Used to skip PadA/PadB and align on a known
    /// marker.
    async fn sync_to(&mut self, needle: &[u8]) -> Result<(), MseError> {
        loop {
            if let Some(off) = find_sub(self.avail(), needle) {
                self.pos += off + needle.len();
                return Ok(());
            }
            if self.avail().len() > MAX_SCAN {
                return Err(MseError::ResyncFailed);
            }
            if self.read_more().await? == 0 {
                return Err(MseError::ResyncFailed);
            }
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), MseError> {
        self.w.write_all(data).await.map_err(MseError::Io)
    }

    /// Consume the helper, returning the raw streams and any unconsumed raw
    /// bytes (the start of the payload stream).
    fn into_parts(self) -> (BoxAsyncReadVectored, BoxAsyncWrite, Vec<u8>) {
        let leftover = self.buf[self.pos..].to_vec();
        (self.r, self.w, leftover)
    }
}

fn select_to_method(select: u32, allow_plaintext: bool) -> Result<CryptoMethod, MseError> {
    if select == CRYPTO_RC4 {
        Ok(CryptoMethod::Rc4)
    } else if select == CRYPTO_PLAINTEXT && allow_plaintext {
        Ok(CryptoMethod::Plaintext)
    } else {
        Err(MseError::NoCommonCryptoMethod)
    }
}

/// Initiator side (A). Performs the MSE handshake over an already-connected
/// transport and returns RC4-wrapped (or plaintext passthrough) streams.
///
/// `allow_plaintext` controls whether we offer plaintext alongside RC4 in
/// `crypto_provide` (true for `Enabled`, false for `Required`).
pub(crate) async fn handshake_outgoing(
    r: BoxAsyncReadVectored,
    w: BoxAsyncWrite,
    info_hash: &Id20,
    allow_plaintext: bool,
) -> Result<MseOutgoing, MseError> {
    let mut io = HsIo::new(r, w);
    let keys = dh::generate();
    let skey = info_hash.0;

    // Step 1: Ya, PadA
    let mut step1 = Vec::with_capacity(DH_LEN + MAX_PAD);
    step1.extend_from_slice(&keys.public);
    step1.extend_from_slice(&random_pad());
    io.write_all(&step1).await?;

    // Step 2: read Yb (the first 96 bytes; PadB follows and is skipped later).
    let yb: [u8; DH_LEN] = io.take(DH_LEN).await?.try_into().unwrap();
    let s = keys.shared_secret(&yb);
    let mut enc = rc4_key(b"keyA", &s, &skey); // A encrypts with keyA
    let mut dec = rc4_key(b"keyB", &s, &skey); // A decrypts B with keyB

    // Step 3: HASH('req1',S), HASH('req2',SKEY) xor HASH('req3',S),
    //         ENCRYPT(VC, crypto_provide, len(PadC)=0, len(IA)=0)
    let provide = if allow_plaintext {
        CRYPTO_RC4 | CRYPTO_PLAINTEXT
    } else {
        CRYPTO_RC4
    };
    let mut step3 = Vec::new();
    step3.extend_from_slice(&sha1_2(b"req1", &s));
    step3.extend_from_slice(&xor20(&sha1_2(b"req2", &skey), &sha1_2(b"req3", &s)));
    let mut enc_part = Vec::new();
    enc_part.extend_from_slice(&VC);
    enc_part.extend_from_slice(&provide.to_be_bytes());
    enc_part.extend_from_slice(&0u16.to_be_bytes()); // len(PadC) = 0
    enc_part.extend_from_slice(&0u16.to_be_bytes()); // len(IA)  = 0
    enc.apply(&mut enc_part);
    step3.extend_from_slice(&enc_part);
    io.write_all(&step3).await?;

    // Step 4: resync on ENCRYPT(VC). B encrypts VC first with keyB, so the
    // ciphertext is exactly `dec` applied to 8 zero bytes; applying it both
    // computes the needle and advances `dec` past VC.
    let mut needle = VC;
    dec.apply(&mut needle);
    io.sync_to(&needle).await?;

    // crypto_select (4) + len(PadD) (2), still RC4 under keyB.
    let mut head = io.take(6).await?;
    dec.apply(&mut head);
    let select = u32::from_be_bytes(head[0..4].try_into().unwrap());
    let pad_d_len = u16::from_be_bytes(head[4..6].try_into().unwrap()) as usize;
    if pad_d_len > MAX_PAD {
        return Err(MseError::HandshakeTooLong);
    }
    let mut pad_d = io.take(pad_d_len).await?;
    dec.apply(&mut pad_d); // discard

    let method = select_to_method(select, allow_plaintext)?;

    // Everything still buffered is the start of B's payload stream.
    let (r, w, mut leftover) = io.into_parts();
    let (reader_rc4, writer_rc4) = match method {
        CryptoMethod::Rc4 => {
            dec.apply(&mut leftover); // decrypt the already-read payload prefix
            (Some(dec), Some(enc))
        }
        CryptoMethod::Plaintext => (None, None),
    };

    Ok(MseOutgoing {
        reader: Box::new(EncryptedReader::new(r, reader_rc4, leftover)),
        writer: Box::new(EncryptedWriter::new(w, writer_rc4)),
        method,
    })
}

/// Receiver side (B). `first_byte` is the already-consumed first byte of the
/// connection (the first byte of Ya). `known_info_hashes` are the torrents we
/// serve, used to resolve SKEY. `allow_plaintext` is false for `Required`.
pub(crate) async fn handshake_incoming(
    r: BoxAsyncReadVectored,
    w: BoxAsyncWrite,
    first_byte: u8,
    known_info_hashes: &[Id20],
    allow_plaintext: bool,
) -> Result<MseIncoming, MseError> {
    let mut io = HsIo::new(r, w);
    io.buf.push(first_byte); // the peeked byte is Ya[0]

    let keys = dh::generate();

    // Step 1: read Ya (96 bytes incl. the peeked one).
    let ya: [u8; DH_LEN] = io.take(DH_LEN).await?.try_into().unwrap();
    let s = keys.shared_secret(&ya);

    // Step 2: Yb, PadB
    let mut step2 = Vec::with_capacity(DH_LEN + MAX_PAD);
    step2.extend_from_slice(&keys.public);
    step2.extend_from_slice(&random_pad());
    io.write_all(&step2).await?;

    // Step 3: resync on HASH('req1',S), skipping PadA.
    io.sync_to(&sha1_2(b"req1", &s)).await?;

    // HASH('req2',SKEY) xor HASH('req3',S): recover HASH('req2',SKEY) and find
    // the matching torrent.
    let xored: [u8; 20] = io.take(20).await?.try_into().unwrap();
    let req2 = xor20(&xored, &sha1_2(b"req3", &s));
    let info_hash = known_info_hashes
        .iter()
        .find(|ih| sha1_2(b"req2", &ih.0) == req2)
        .copied()
        .ok_or(MseError::NoMatchingTorrent)?;
    let skey = info_hash.0;

    let mut dec = rc4_key(b"keyA", &s, &skey); // B decrypts A with keyA
    let mut enc = rc4_key(b"keyB", &s, &skey); // B encrypts with keyB

    // ENCRYPT(VC, crypto_provide, len(PadC)): 8 + 4 + 2 bytes.
    let mut head = io.take(14).await?;
    dec.apply(&mut head);
    if head[0..8] != VC {
        return Err(MseError::BadVc);
    }
    let provide = u32::from_be_bytes(head[8..12].try_into().unwrap());
    let pad_c_len = u16::from_be_bytes(head[12..14].try_into().unwrap()) as usize;
    if pad_c_len > MAX_PAD {
        return Err(MseError::HandshakeTooLong);
    }
    let mut pad_c = io.take(pad_c_len).await?;
    dec.apply(&mut pad_c); // discard

    let mut len_ia = io.take(2).await?;
    dec.apply(&mut len_ia);
    let ia_len = u16::from_be_bytes(len_ia[..].try_into().unwrap()) as usize;
    let mut ia = io.take(ia_len).await?;
    dec.apply(&mut ia); // decrypted start of A's payload

    // Choose a method: prefer RC4, fall back to plaintext if offered & allowed.
    let method = if provide & CRYPTO_RC4 != 0 {
        CryptoMethod::Rc4
    } else if provide & CRYPTO_PLAINTEXT != 0 && allow_plaintext {
        CryptoMethod::Plaintext
    } else {
        return Err(MseError::NoCommonCryptoMethod);
    };
    let select = match method {
        CryptoMethod::Rc4 => CRYPTO_RC4,
        CryptoMethod::Plaintext => CRYPTO_PLAINTEXT,
    };

    // Step 4: ENCRYPT(VC, crypto_select, len(PadD)=0)
    let mut step4 = Vec::new();
    step4.extend_from_slice(&VC);
    step4.extend_from_slice(&select.to_be_bytes());
    step4.extend_from_slice(&0u16.to_be_bytes()); // len(PadD) = 0
    enc.apply(&mut step4);
    io.write_all(&step4).await?;

    // Payload = decrypted IA, then whatever else is already buffered.
    let (r, w, mut tail) = io.into_parts();
    let (reader_rc4, writer_rc4) = match method {
        CryptoMethod::Rc4 => {
            dec.apply(&mut tail);
            (Some(dec), Some(enc))
        }
        CryptoMethod::Plaintext => (None, None),
    };
    let mut leftover = ia;
    leftover.extend_from_slice(&tail);

    Ok(MseIncoming {
        reader: Box::new(EncryptedReader::new(r, reader_rc4, leftover)),
        writer: Box::new(EncryptedWriter::new(w, writer_rc4)),
        method,
        info_hash,
    })
}
