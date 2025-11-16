//
// Copyright (c) 2025 murilo ijanc' <murilo@ijanc.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//! STUN Message Structure
//!
//!```norust
//!       0                   1                   2                   3
//!       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |0 0|     STUN Message Type     |         Message Length        |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |                         Magic Cookie                          |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |                                                               |
//!      |                     Transaction ID (96 bits)                  |
//!      |                                                               |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!```

/// TransactionId
///
///```norust
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                                                               |
///      |                     Transaction ID (96 bits)                  |
///      |                                                               |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId([u8; 12]);

impl TryFrom<&[u8]> for TransactionId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(value);

        if value.len() == 12 {
            Ok(Self(transaction_id))
        } else {
            // TODO(msi): Move to Error
            Err("Invalid transaction id size")
        }
    }
}

impl TransactionId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        let mut transaction_id = [0u8; 12];
        let hash_bytes = hash.to_le_bytes();
        transaction_id[0..8].copy_from_slice(&hash_bytes);

        // Fill remaining bytes with more entropy
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        transaction_id[8..12].copy_from_slice(&nanos.to_le_bytes());

        Self(transaction_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_id_from_bytes() {
        let bytes = [1u8; 12];
        let res = TransactionId::try_from(bytes.as_slice());
        assert!(res.is_ok());
        assert_eq!(&bytes, res.unwrap().as_bytes());
    }

    #[test]
    fn transaction_bytes() {
        let bytes = [1u8; 12];
        let t1 = TransactionId(bytes);
        assert_eq!(&bytes, t1.as_bytes())
    }

    #[test]
    fn pseudo_random_transaction() {
        let t1 = TransactionId::default();
        let t2 = TransactionId::default();
        assert_ne!(t1, t2)
    }
}
