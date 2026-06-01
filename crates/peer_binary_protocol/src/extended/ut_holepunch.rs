use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{DoubleBufHelper, MessageDeserializeError, SerializeError};

// BEP-55 message types.
const MSG_RENDEZVOUS: u8 = 0;
const MSG_CONNECT: u8 = 1;
const MSG_ERROR: u8 = 2;
// BEP-55 address types.
const ADDR_V4: u8 = 0;
const ADDR_V6: u8 = 1;

/// BEP-55 (uTP holepunch) message. Unlike most extended messages this is a packed
/// *binary* payload, not bencode:
///
/// ```text
/// msg_type: u8    (0=rendezvous, 1=connect, 2=error)
/// addr_type: u8   (0=IPv4, 1=IPv6)
/// addr: 4 or 16 bytes (network order)
/// port: u16       (big endian)
/// err_code: u32   (big endian, ONLY present for error messages)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtHolepunch {
    /// Sent to a connectable peer asking it to introduce us to `target`.
    Rendezvous(SocketAddr),
    /// Sent by the rendezvous peer telling us to connect to `target` now.
    Connect(SocketAddr),
    /// Sent by the rendezvous peer when it can't help with `target`.
    Error { target: SocketAddr, err_code: u32 },
}

impl UtHolepunch {
    /// The peer named by this message (target of the rendezvous/connect/error).
    pub fn target(&self) -> SocketAddr {
        match self {
            UtHolepunch::Rendezvous(a) | UtHolepunch::Connect(a) => *a,
            UtHolepunch::Error { target, .. } => *target,
        }
    }

    pub fn serialize(&self, writer: &mut Cursor<&mut [u8]>) -> Result<(), SerializeError> {
        let (msg_type, addr, err_code) = match self {
            UtHolepunch::Rendezvous(a) => (MSG_RENDEZVOUS, *a, None),
            UtHolepunch::Connect(a) => (MSG_CONNECT, *a, None),
            UtHolepunch::Error { target, err_code } => (MSG_ERROR, *target, Some(*err_code)),
        };
        writer.write_all(&[msg_type])?;
        match addr.ip() {
            IpAddr::V4(v4) => {
                writer.write_all(&[ADDR_V4])?;
                writer.write_all(&v4.octets())?;
            }
            IpAddr::V6(v6) => {
                writer.write_all(&[ADDR_V6])?;
                writer.write_all(&v6.octets())?;
            }
        }
        writer.write_all(&addr.port().to_be_bytes())?;
        if let Some(code) = err_code {
            writer.write_all(&code.to_be_bytes())?;
        }
        Ok(())
    }

    pub fn deserialize(mut buf: DoubleBufHelper<'_>) -> Result<Self, MessageDeserializeError> {
        fn missing(m: usize) -> MessageDeserializeError {
            MessageDeserializeError::NotEnoughData(m, None)
        }
        let msg_type = buf.read_u8().ok_or(missing(1))?;
        let addr_type = buf.read_u8().ok_or(missing(1))?;
        let ip: IpAddr = match addr_type {
            ADDR_V4 => IpAddr::V4(Ipv4Addr::from(buf.consume::<4>().map_err(missing)?)),
            ADDR_V6 => IpAddr::V6(Ipv6Addr::from(buf.consume::<16>().map_err(missing)?)),
            other => return Err(MessageDeserializeError::UtHolepunchBadAddrType(other)),
        };
        let port = u16::from_be_bytes(buf.consume::<2>().map_err(missing)?);
        let addr = SocketAddr::new(ip, port);
        match msg_type {
            MSG_RENDEZVOUS => Ok(UtHolepunch::Rendezvous(addr)),
            MSG_CONNECT => Ok(UtHolepunch::Connect(addr)),
            MSG_ERROR => Ok(UtHolepunch::Error {
                target: addr,
                err_code: buf.read_u32_be().map_err(missing)?,
            }),
            other => Err(MessageDeserializeError::UtHolepunchBadMsgType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DoubleBufHelper;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[track_caller]
    fn roundtrip(msg: UtHolepunch) {
        let mut buf = [0u8; 64];
        let mut cur = Cursor::new(&mut buf[..]);
        msg.serialize(&mut cur).unwrap();
        let n = cur.position() as usize;
        // contiguous
        let got = UtHolepunch::deserialize(DoubleBufHelper::new(&buf[..n], &[])).unwrap();
        assert_eq!(msg, got);
        // split across the double buffer at every point
        for split in 0..=n {
            let (a, b) = buf[..n].split_at(split);
            let got = UtHolepunch::deserialize(DoubleBufHelper::new(a, b)).unwrap();
            assert_eq!(msg, got, "split at {split}");
        }
    }

    #[test]
    fn test_roundtrip() {
        roundtrip(UtHolepunch::Rendezvous(
            (Ipv4Addr::new(1, 2, 3, 4), 6881).into(),
        ));
        roundtrip(UtHolepunch::Connect((Ipv4Addr::new(9, 8, 7, 6), 51413).into()));
        roundtrip(UtHolepunch::Connect(
            (Ipv6Addr::new(0x2a03, 0x1b20, 4, 0xf011, 0, 0, 0, 0xa02e), 1234).into(),
        ));
        roundtrip(UtHolepunch::Error {
            target: (Ipv4Addr::new(5, 5, 5, 5), 80).into(),
            err_code: 2,
        });
    }
}
