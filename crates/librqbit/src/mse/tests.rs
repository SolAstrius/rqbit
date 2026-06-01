use librqbit_core::hash_id::Id20;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{CryptoMethod, MseError, handshake_incoming, handshake_outgoing};
use crate::type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite};
use crate::vectored_traits::AsyncReadVectoredIntoCompat;

fn boxed(s: tokio::io::DuplexStream) -> (BoxAsyncReadVectored, BoxAsyncWrite) {
    let (r, w) = tokio::io::split(s);
    (Box::new(r.into_vectored_compat()), Box::new(w))
}

/// Run both sides of the handshake concurrently over an in-memory pipe and
/// return their results.
async fn run_handshake(
    a_info: Id20,
    b_known: Vec<Id20>,
    a_allow_plaintext: bool,
    b_allow_plaintext: bool,
) -> (
    Result<super::MseOutgoing, MseError>,
    Result<super::MseIncoming, MseError>,
) {
    let (a_sock, b_sock) = tokio::io::duplex(128 * 1024);
    let (ar, aw) = boxed(a_sock);
    let (mut br, bw) = boxed(b_sock);

    let a = async move { handshake_outgoing(ar, aw, &a_info, a_allow_plaintext).await };
    let b = async move {
        // Mirror the real inbound path: the first byte is peeked to discriminate
        // MSE vs a legacy plaintext BT handshake.
        let mut first = [0u8; 1];
        let n = br.read(&mut first).await.map_err(MseError::Io)?;
        if n == 0 {
            return Err(MseError::UnexpectedEof);
        }
        handshake_incoming(br, bw, first[0], &b_known, b_allow_plaintext).await
    };

    tokio::join!(a, b)
}

#[tokio::test]
async fn rc4_handshake_and_payload_roundtrip() {
    let info = Id20::new([0x42; 20]);
    let (a, b) = run_handshake(info, vec![info], true, true).await;
    let out = a.expect("A handshake");
    let inc = b.expect("B handshake");

    assert_eq!(out.method, CryptoMethod::Rc4);
    assert_eq!(inc.method, CryptoMethod::Rc4);
    assert_eq!(inc.info_hash, info);

    let mut ar = out.reader;
    let mut aw = out.writer;
    let mut br = inc.reader;
    let mut bw = inc.writer;

    // A -> B
    aw.write_all(b"hello from A").await.unwrap();
    aw.flush().await.unwrap();
    let mut buf = [0u8; 12];
    br.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello from A");

    // B -> A
    bw.write_all(b"hi back from B!!").await.unwrap();
    bw.flush().await.unwrap();
    let mut buf2 = [0u8; 16];
    ar.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"hi back from B!!");
}

#[tokio::test]
async fn larger_payload_roundtrip() {
    let info = Id20::new([1; 20]);
    let (a, b) = run_handshake(info, vec![info], false, false).await;
    let out = a.expect("A handshake");
    let inc = b.expect("B handshake");
    assert_eq!(out.method, CryptoMethod::Rc4);

    let mut aw = out.writer;
    let mut br = inc.reader;

    let payload: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let writer = async move {
        aw.write_all(&payload).await.unwrap();
        aw.flush().await.unwrap();
    };
    let reader = async move {
        let mut got = vec![0u8; expected.len()];
        br.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
    };
    tokio::join!(writer, reader);
}

#[tokio::test]
async fn resync_survives_random_padding() {
    // The pads are randomized per run; loop to exercise many lengths.
    for _ in 0..40 {
        let info = Id20::new([0x37; 20]);
        let (a, b) = run_handshake(info, vec![info], true, true).await;
        let out = a.expect("A handshake");
        let inc = b.expect("B handshake");

        let mut aw = out.writer;
        let mut br = inc.reader;
        aw.write_all(b"sync-ok").await.unwrap();
        aw.flush().await.unwrap();
        let mut buf = [0u8; 7];
        br.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"sync-ok");
    }
}

#[tokio::test]
async fn wrong_info_hash_is_rejected() {
    let a_info = Id20::new([0xAA; 20]);
    let b_info = Id20::new([0xBB; 20]);
    let (a, b) = run_handshake(a_info, vec![b_info], true, true).await;
    // B can't resolve SKEY -> errors out; A then fails too (pipe closed).
    assert!(matches!(b, Err(MseError::NoMatchingTorrent)));
    assert!(a.is_err());
}

#[tokio::test]
async fn b_picks_correct_torrent_among_many() {
    let target = Id20::new([0x5A; 20]);
    let known = vec![
        Id20::new([1; 20]),
        Id20::new([2; 20]),
        target,
        Id20::new([3; 20]),
    ];
    let (a, b) = run_handshake(target, known, true, true).await;
    a.expect("A handshake");
    let inc = b.expect("B handshake");
    assert_eq!(inc.info_hash, target);
}
