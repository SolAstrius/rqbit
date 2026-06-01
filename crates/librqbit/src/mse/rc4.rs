//! Minimal RC4 stream cipher for MSE/PE.
//!
//! RC4 is cryptographically weak. It is used here ONLY for BitTorrent protocol
//! obfuscation (defeating passive traffic shaping / DPI), never as a real
//! security boundary. See the Message Stream Encryption spec.

pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initialize from a key (KSA). The MSE key is a 20-byte SHA1 digest.
    pub fn new(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty());
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = i as u8;
            }
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[idx as usize]
    }

    /// XOR `data` in place with the keystream (encrypt == decrypt).
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b ^= self.next_byte();
        }
    }

    /// Discard `n` keystream bytes. MSE discards the first 1024 after keying.
    pub fn discard(&mut self, n: usize) {
        for _ in 0..n {
            self.next_byte();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rc4;

    // Standard RC4 test vectors (key "Key", plaintext "Plaintext").
    #[test]
    fn rc4_known_vector() {
        let mut c = Rc4::new(b"Key");
        let mut data = *b"Plaintext";
        c.apply(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn rc4_roundtrip() {
        let mut enc = Rc4::new(b"a-test-key-1234567890");
        let mut dec = Rc4::new(b"a-test-key-1234567890");
        let mut buf = *b"the quick brown fox jumps over the lazy dog";
        let orig = buf;
        enc.apply(&mut buf);
        assert_ne!(buf, orig);
        dec.apply(&mut buf);
        assert_eq!(buf, orig);
    }
}
