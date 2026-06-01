//! Transparent RC4-encrypting/decrypting stream wrappers.
//!
//! After the MSE handshake completes, peer traffic is wrapped in these so the
//! existing BitTorrent code (handshake, messages) operates unchanged on top of
//! an obfuscated stream. For the negotiated `plaintext` method the cipher is
//! `None` and the wrappers only drain any handshake leftover before passing
//! through.

use std::{
    io::IoSliceMut,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::rc4::Rc4;
use crate::{
    type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite},
    vectored_traits::AsyncReadVectored,
};

pub(crate) struct EncryptedReader {
    inner: BoxAsyncReadVectored,
    // None => plaintext passthrough.
    rc4: Option<Rc4>,
    // Already-decrypted payload bytes that were read past the handshake sync
    // point. Served before anything is pulled from `inner`.
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl EncryptedReader {
    pub fn new(inner: BoxAsyncReadVectored, rc4: Option<Rc4>, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            rc4,
            leftover,
            leftover_pos: 0,
        }
    }
}

impl AsyncRead for EncryptedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain already-decrypted leftover first.
        if this.leftover_pos < this.leftover.len() {
            let rem = &this.leftover[this.leftover_pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            this.leftover_pos += n;
            if this.leftover_pos == this.leftover.len() {
                this.leftover = Vec::new();
                this.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let pre = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if let Some(rc4) = this.rc4.as_mut() {
            rc4.apply(&mut buf.filled_mut()[pre..]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadVectored for EncryptedReader {
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        vec: &mut [IoSliceMut<'_>],
    ) -> Poll<std::io::Result<usize>> {
        // RC4 is a byte stream; vectored reads buy nothing once we have to
        // decrypt in place, so degrade to filling the first non-empty slice and
        // reuse poll_read (which also handles leftover + decryption).
        let first = match vec.iter_mut().find(|s| !s.is_empty()) {
            Some(s) => &mut **s,
            None => return Poll::Ready(Ok(0)),
        };
        let mut rb = ReadBuf::new(first);
        ready!(self.poll_read(cx, &mut rb))?;
        Poll::Ready(Ok(rb.filled().len()))
    }
}

pub(crate) struct EncryptedWriter {
    inner: BoxAsyncWrite,
    // None => plaintext passthrough.
    rc4: Option<Rc4>,
    // Ciphertext buffered when `inner` accepted only part of an encrypted write.
    // Always fully drained before a new plaintext buffer is accepted, so on any
    // `Ready(Ok(n))` return `pending` is empty.
    pending: Vec<u8>,
    pending_pos: usize,
}

impl EncryptedWriter {
    pub fn new(inner: BoxAsyncWrite, rc4: Option<Rc4>) -> Self {
        Self {
            inner,
            rc4,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    fn drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write encrypted bytes to peer",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for EncryptedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.rc4.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // If pending is non-empty we were re-polled after a partial write; the
        // current `buf` is identical to the one already encrypted into pending
        // (write_all re-passes the same slice), so don't re-encrypt.
        if this.pending.is_empty() {
            let mut ct = buf.to_vec();
            this.rc4.as_mut().unwrap().apply(&mut ct);
            this.pending = ct;
            this.pending_pos = 0;
        }
        ready!(this.drain_pending(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
