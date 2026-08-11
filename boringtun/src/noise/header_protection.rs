// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 3.0 header protection.
//!
//! A raw ChaCha20 keystream is XORed over the WireGuard message that follows an
//! AmneziaWG junk prefix, so the message-type field -- the one part of a
//! WireGuard datagram with a small, fixed set of legal values -- no longer sits
//! in the clear where a classifier can range-test it.
//!
//! # What this is not
//!
//! It is *masking*, not encryption, and nothing under the keystream is secret:
//! a handshake initiation carries the message type, sender index, the
//! **unencrypted** ephemeral public key, two AEAD ciphertexts and two MACs, all
//! of which vanilla WireGuard puts on the wire in the clear. A transport packet
//! contributes only its 16-byte header -- type, receiver index, counter. So a
//! repeated nonce costs identification-resistance, not confidentiality: an
//! observer who catches one recovers keystream, unmasks the type field, and can
//! classify the flow again. That is the property this feature sells, and the
//! only one it can lose.
//!
//! # Nonce
//!
//! The nonce is the datagram's own first 12 bytes -- the start of the junk
//! prefix -- which is why AmneziaWG requires every configured S size to be at
//! least [`NONCE_SIZE`] once a key is set. It is not a counter and nothing
//! guarantees it is unique; it is random only because the prefix normally is.
//! Under protocol imitation the prefix is protocol-shaped instead, and that
//! entropy drops sharply (a DNS header varies only in its transaction id). See
//! [`AmneziaConfig::validate`](super::amnezia::AmneziaConfig::validate), which
//! warns about the combination rather than refusing it.
//!
//! # Wire compatibility
//!
//! Byte-compatible with amneziawg-go v3 (`device/noise-protocol.go`
//! `HeaderProtectionCipher`, the four `XORKeyStream` sites in `device/send.go`,
//! and `device/receive.go`). The subtlety worth stating: the receiver consumes
//! the keystream **contiguously** -- four bytes to unmask the type field for
//! classification, then the remainder of the message from offset four -- which
//! is what makes it line up with a sender that XORed the whole message in one
//! pass from offset zero.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

/// Bytes of the junk prefix used as the ChaCha20 nonce.
pub(crate) const NONCE_SIZE: usize = 12;

/// Bytes of keystream reserved for the message-type field.
///
/// Held at keystream offset 0 for every packet kind, regardless of how large
/// the junk prefix in front of it is, which is what lets one mask classify a
/// datagram whose padding is not yet known.
pub(crate) const TYPE_MASK_SIZE: usize = 4;

/// A device-wide header-protection key, shared out of band.
///
/// All-zero means "off", matching amneziawg-go's `IsZero` check -- a distinction
/// worth keeping because it makes an unset key a no-op rather than a valid key
/// that happens to be weak.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderProtectionKey([u8; 32]);

impl std::fmt::Debug for HeaderProtectionKey {
    /// Never prints the key. It is shared secret material, and `AmneziaConfig`
    /// derives `Debug`, so an unguarded impl would put it into any log line
    /// that formats a config.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_set() {
            "HeaderProtectionKey(set)"
        } else {
            "HeaderProtectionKey(unset)"
        })
    }
}

impl HeaderProtectionKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn is_set(&self) -> bool {
        self.0 != [0u8; 32]
    }

    /// A cipher for one datagram, keyed by this key and nonced by `nonce`.
    ///
    /// Returns `None` when the key is unset, so every call site reads as
    /// "protect if configured" without a second branch.
    fn cipher(&self, nonce: &[u8; NONCE_SIZE]) -> Option<ChaCha20> {
        if !self.is_set() {
            return None;
        }
        Some(ChaCha20::new(&self.0.into(), nonce.into()))
    }

    /// Mask an outbound datagram in place.
    ///
    /// `datagram` is the whole frame, junk prefix included; `offset` is where
    /// the WireGuard message starts and `len` how much of it to cover -- the
    /// entire message for the handshake kinds, only the 16-byte header for
    /// transport data, matching amneziawg-go.
    ///
    /// A no-op when the key is unset. Returns `false` only when the prefix is
    /// too short to supply a nonce, which config validation is supposed to have
    /// already prevented.
    pub(crate) fn mask_outbound(&self, datagram: &mut [u8], offset: usize, len: usize) -> bool {
        if !self.is_set() {
            return true;
        }
        if offset < NONCE_SIZE || datagram.len() < offset + len {
            return false;
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&datagram[..NONCE_SIZE]);
        let Some(mut cipher) = self.cipher(&nonce) else {
            return true;
        };
        cipher.apply_keystream(&mut datagram[offset..offset + len]);
        true
    }

    /// The four keystream bytes that unmask a message-type field.
    ///
    /// Generated by encrypting zeroes, so the result *is* the keystream, which
    /// can then be XORed against a candidate tag at any offset without
    /// disturbing the cipher -- the receiver has to try several paddings before
    /// it knows which one applies.
    pub(crate) fn type_mask(&self, datagram: &[u8]) -> Option<[u8; TYPE_MASK_SIZE]> {
        if !self.is_set() || datagram.len() < NONCE_SIZE {
            return None;
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&datagram[..NONCE_SIZE]);
        let mut cipher = self.cipher(&nonce)?;
        let mut mask = [0u8; TYPE_MASK_SIZE];
        cipher.apply_keystream(&mut mask);
        Some(mask)
    }

    /// Unmask an inbound message in place, once its padding is known.
    ///
    /// Skips the first [`TYPE_MASK_SIZE`] bytes: the caller has already applied
    /// [`Self::type_mask`] to the type field in order to classify the datagram,
    /// and re-applying it here would mask it straight back. The cipher is
    /// *seeked* to that offset rather than restarted, so the stream stays
    /// continuous with the sender's single pass.
    pub(crate) fn unmask_inbound(&self, datagram: &mut [u8], offset: usize, len: usize) -> bool {
        if !self.is_set() {
            return true;
        }
        if offset < NONCE_SIZE || datagram.len() < offset + len || len < TYPE_MASK_SIZE {
            return false;
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&datagram[..NONCE_SIZE]);
        let Some(mut cipher) = self.cipher(&nonce) else {
            return true;
        };
        cipher.seek(TYPE_MASK_SIZE as u64);
        let body = offset + TYPE_MASK_SIZE;
        cipher.apply_keystream(&mut datagram[body..offset + len]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> HeaderProtectionKey {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        HeaderProtectionKey::new(k)
    }

    /// The property the whole feature rests on: mask then unmask is identity,
    /// with the type field taken out of band exactly as the receiver does it.
    #[test]
    fn mask_then_unmask_round_trips_a_whole_message() {
        const OFFSET: usize = 120;
        const LEN: usize = 148;
        let k = key();

        let mut wire = vec![0u8; OFFSET + LEN];
        for (i, b) in wire.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let original = wire.clone();

        assert!(k.mask_outbound(&mut wire, OFFSET, LEN));
        assert_ne!(
            &wire[OFFSET..OFFSET + LEN],
            &original[OFFSET..OFFSET + LEN],
            "masking must actually change the message"
        );
        assert_eq!(
            &wire[..OFFSET],
            &original[..OFFSET],
            "the junk prefix carries the nonce and must not itself be masked"
        );

        // The receiver's two-step: type field via the standalone mask, body via
        // the seeked cipher.
        let mask = k.type_mask(&wire).expect("key is set");
        for i in 0..TYPE_MASK_SIZE {
            wire[OFFSET + i] ^= mask[i];
        }
        assert!(k.unmask_inbound(&mut wire, OFFSET, LEN));
        assert_eq!(wire, original, "round trip must be the identity");
    }

    /// The type mask must be the same four bytes whatever the padding is --
    /// that is what lets a receiver classify before it knows the padding.
    #[test]
    fn the_type_mask_does_not_depend_on_the_padding_length() {
        let k = key();
        let nonce_and_more = [0xa5u8; 200];
        let a = k.type_mask(&nonce_and_more[..50]).unwrap();
        let b = k.type_mask(&nonce_and_more[..180]).unwrap();
        assert_eq!(a, b, "only the first 12 bytes may influence the mask");
    }

    /// A different prefix is a different nonce is a different keystream. If
    /// this ever fails, the nonce is not reaching the cipher.
    #[test]
    fn a_different_nonce_gives_a_different_mask() {
        let k = key();
        let mut a = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        b[0] = 1;
        assert_ne!(k.type_mask(&a).unwrap(), k.type_mask(&b).unwrap());
        // ... and the same nonce gives the same mask, or the round trip above
        // would be proving nothing.
        a[0] = 1;
        assert_eq!(k.type_mask(&a).unwrap(), k.type_mask(&b).unwrap());
    }

    #[test]
    fn an_unset_key_is_a_no_op_in_both_directions() {
        let k = HeaderProtectionKey::default();
        assert!(!k.is_set());
        assert_eq!(k.type_mask(&[0u8; 64]), None);

        let mut wire = vec![0xccu8; 200];
        let original = wire.clone();
        assert!(k.mask_outbound(&mut wire, 120, 64));
        assert_eq!(wire, original, "an unset key must not touch the datagram");
        assert!(k.unmask_inbound(&mut wire, 120, 64));
        assert_eq!(wire, original);
    }

    /// A prefix shorter than the nonce cannot produce one. Config validation
    /// should stop this, so the check here is the backstop -- and it must
    /// refuse rather than silently mask with a truncated nonce.
    #[test]
    fn a_prefix_too_short_for_a_nonce_is_refused() {
        let k = key();
        let mut wire = vec![0u8; 100];
        assert!(!k.mask_outbound(&mut wire, NONCE_SIZE - 1, 20));
        assert!(!k.unmask_inbound(&mut wire, NONCE_SIZE - 1, 20));
        // Exactly the nonce size is legal.
        assert!(k.mask_outbound(&mut wire, NONCE_SIZE, 20));
    }

    #[test]
    fn the_key_never_appears_in_debug_output() {
        let rendered = format!("{:?}", key());
        assert_eq!(rendered, "HeaderProtectionKey(set)");
        assert!(!rendered.contains('1'), "no key bytes may be rendered");
        assert_eq!(
            format!("{:?}", HeaderProtectionKey::default()),
            "HeaderProtectionKey(unset)"
        );
    }
}
