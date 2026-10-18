// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{handshake::ObfuscationRanges, PacketData};
use crate::noise::errors::WireGuardError;
use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use rand_core::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
// 64 * 128 = 8192 counters of reordering, the window Linux and wireguard-go
// keep (theirs is 8192 bits less one word): 1 KiB per session, 8 KiB for a
// tunnel's eight session slots.
const N_WORDS: u64 = 128;
const N_BITS: u64 = WORD_SIZE * N_WORDS;

/// Reject-After-Messages, whitepaper section 6.2: `2^64 - 2^13 - 1`. A counter
/// at or above it is never sent and never accepted, so the 64-bit AEAD nonce
/// cannot wrap under one key -- whether or not the session timers ever fire.
/// Every counter that is used therefore lies in `0..REJECT_AFTER_MESSAGES`,
/// which also keeps the replay window's `counter + N_BITS` and `counter + 1`
/// clear of overflow.
pub(super) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

// By hand: `Default` is derived for arrays of at most 32 elements.
impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        ReceivingKeyCounterValidator {
            next: 0,
            receive_cnt: 0,
            bitmap: [0; N_WORDS as usize],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::InvalidCounter);
        }
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::InvalidCounter);
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while i % WORD_SIZE != 0 && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Mutex::new(Default::default()),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// True once every nonce below [`REJECT_AFTER_MESSAGES`] has been used:
    /// the session can still receive, but must not send again.
    pub(super) fn sending_exhausted(&self) -> bool {
        self.sending_key_counter.load(Ordering::Relaxed) >= REJECT_AFTER_MESSAGES
    }

    /// Claim the next sending nonce, or `None` once the session is exhausted.
    ///
    /// A compare-and-swap rather than `fetch_add`: a refused claim must leave
    /// the counter where it is. Incrementing first and checking after would
    /// move an exhausted counter on with every refused send, and 2^13 of them
    /// would wrap it back to nonces already used under this key.
    fn claim_sending_nonce(&self) -> Option<u64> {
        self.sending_key_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
                if counter < REJECT_AFTER_MESSAGES {
                    Some(counter + 1)
                } else {
                    None
                }
            })
            .ok()
    }

    /// Fast-forward the sending counter, so the limit can be tested without
    /// sending 2^64 packets.
    #[cfg(test)]
    pub(super) fn set_sending_counter(&self, counter: u64) {
        self.sending_key_counter.store(counter, Ordering::Relaxed);
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the formatted packet
    ///
    /// `dst` must hold `src.len() + pad + DATA_OVERHEAD_SZ`; otherwise this
    /// returns
    /// [`WireGuardError::DestinationBufferTooSmall`]. It used to panic instead,
    /// which was not survivable: every caller reaches this through
    /// `ffi::wireguard_write` and friends, and those are `extern "C"`, so the
    /// panic hit rustc's nounwind shim and aborted the process rather than
    /// unwinding. Sizing `dst` to the tunnel MTU -- which needs
    /// `MTU + DATA_OVERHEAD_SZ` -- was enough to do it.
    pub(super) fn format_packet_data<'a>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        src: &[u8],
        pad: usize,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        // The sealed plaintext is `src` followed by `pad` zero bytes -- AmneziaWG
        // 3.0 `content_padding_addition`. Every caller draws `pad` from
        // `AmneziaConfig::content_padding_for_frame`, the one place the budget is
        // computed, so the padded length already fits both `dst` and
        // `MAX_SENDABLE_DATAGRAM`; this bound is the same check the base frame
        // always had, widened by `pad`.
        if dst.len() < src.len() + pad + super::DATA_OVERHEAD_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        // Checked first, deliberately: this counter must not advance for a
        // packet that was never formatted, or the rejected call would burn a
        // nonce. Note this bound covers the base frame only -- the Amnezia S4
        // prefix is added later, by `write_to_network` -- so `Tunn::encapsulate`
        // preflights the full wire size before calling this.
        //
        // An exhausted session is `ConnectionExpired`. `Tunn` does not route a
        // send here once `sending_exhausted` holds -- it starts a handshake
        // instead -- so this is the backstop, not the normal path.
        let sending_key_counter = self
            .claim_sending_nonce()
            .ok_or(WireGuardError::ConnectionExpired)?;

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&obf.random_h4(rng).to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        let plaintext_len = src.len() + pad;
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            data[..src.len()].copy_from_slice(src);
            // Zero the padding explicitly. The receiver relies on it: a
            // zero-first-byte plaintext is a keepalive, and a data packet is
            // trimmed by its IP length field, so the trailer must be zeros and
            // not whatever the buffer held.
            data[src.len()..plaintext_len].fill(0);
            self.sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..plaintext_len],
                )
                .map(|tag| {
                    data[plaintext_len..plaintext_len + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    plaintext_len + AEAD_SIZE
                })
                .unwrap()
        };

        Ok(&mut dst[..DATA_OFFSET + n])
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // Was a panic, on the grounds that it is "a very incorrect use of
            // the library". It is incorrect, but it is not the library's to
            // punish that way: this runs inside `extern "C"` FFI callees, where
            // a panic aborts rather than unwinds, so a caller who sized `dst`
            // for the plaintext rather than the frame lost the whole process.
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption.
        // This also refuses a counter at or above REJECT_AFTER_MESSAGES before
        // any cryptography, as `InvalidCounter` -- the same pre-AEAD refusal a
        // counter behind the window already gets.
        self.receiving_counter_quick_check(packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
            self.receiver
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut dst[..ct_len],
                )
                .map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(packet.counter)?;
        Ok(ret)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::convert::TryInto;

    /// Two halves of one session: what `a` seals, `b` opens.
    fn session_pair() -> (Session, Session) {
        let a_to_b = [1u8; 32];
        let b_to_a = [2u8; 32];
        (
            Session::new(1, 2, b_to_a, a_to_b),
            Session::new(2, 1, a_to_b, b_to_a),
        )
    }

    fn seal(session: &Session, src: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let mut dst = vec![0u8; src.len() + super::super::DATA_OVERHEAD_SZ];
        session
            .format_packet_data(ObfuscationRanges::default(), &mut OsRng, src, 0, &mut dst)
            .map(|p| p.to_vec())
    }

    fn open(session: &Session, frame: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let packet = PacketData {
            receiver_idx: u32::from_le_bytes(frame[4..8].try_into().unwrap()),
            counter: u64::from_le_bytes(frame[8..16].try_into().unwrap()),
            encrypted_encapsulated_packet: &frame[DATA_OFFSET..],
        };
        let mut dst = vec![0u8; frame.len()];
        session
            .receive_packet_data(packet, &mut dst)
            .map(|p| p.to_vec())
    }

    fn counter_of(frame: &[u8]) -> u64 {
        u64::from_le_bytes(frame[8..16].try_into().unwrap())
    }

    #[test]
    fn reject_after_messages_is_the_whitepaper_value() {
        // 2^64 - 2^13 - 1, written out independently of the definition.
        assert_eq!(REJECT_AFTER_MESSAGES, 0xFFFF_FFFF_FFFF_DFFF);
    }

    #[test]
    fn the_last_counter_below_the_limit_is_sent_and_received() {
        let (a, b) = session_pair();
        a.set_sending_counter(REJECT_AFTER_MESSAGES - 1);
        assert!(!a.sending_exhausted());

        let frame = seal(&a, b"last").unwrap();
        assert_eq!(counter_of(&frame), REJECT_AFTER_MESSAGES - 1);
        assert_eq!(open(&b, &frame).unwrap(), b"last");
        assert!(a.sending_exhausted());
    }

    #[test]
    fn an_exhausted_session_refuses_to_send_and_never_moves_its_counter() {
        let (a, _b) = session_pair();
        a.set_sending_counter(REJECT_AFTER_MESSAGES);
        assert!(a.sending_exhausted());

        // Far more refusals than the 2^13 headroom: if a refusal advanced the
        // counter, these would carry it past u64::MAX and back to 0.
        for _ in 0..(1u32 << 14) {
            assert!(matches!(
                seal(&a, b"x"),
                Err(WireGuardError::ConnectionExpired)
            ));
        }
        assert_eq!(
            a.sending_key_counter.load(Ordering::Relaxed),
            REJECT_AFTER_MESSAGES
        );
    }

    #[test]
    fn a_too_small_dst_is_refused_before_the_limit_is_consulted() {
        // The capacity error stays the first one reported, so a caller that
        // retries with a larger buffer does not see a different error first.
        let (a, _b) = session_pair();
        a.set_sending_counter(REJECT_AFTER_MESSAGES);
        let mut dst = [0u8; 8];
        assert!(matches!(
            a.format_packet_data(ObfuscationRanges::default(), &mut OsRng, b"x", 0, &mut dst),
            Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }

    #[test]
    fn a_counter_at_or_above_the_limit_is_refused_before_decryption() {
        // A sealed frame relabelled with a counter at the limit: a counter
        // check that ran after the AEAD would report InvalidAeadTag instead.
        let (a, b) = session_pair();
        let mut frame = seal(&a, b"data").unwrap();
        for counter in [REJECT_AFTER_MESSAGES, REJECT_AFTER_MESSAGES + 1, u64::MAX] {
            frame[8..16].copy_from_slice(&counter.to_le_bytes());
            assert!(matches!(
                open(&b, &frame),
                Err(WireGuardError::InvalidCounter)
            ));
        }
    }

    #[test]
    fn the_replay_window_refuses_the_limit_without_overflowing() {
        let mut c: ReceivingKeyCounterValidator = Default::default();
        for counter in [REJECT_AFTER_MESSAGES, u64::MAX - N_BITS, u64::MAX] {
            assert!(matches!(
                c.will_accept(counter),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(matches!(
                c.mark_did_receive(counter),
                Err(WireGuardError::InvalidCounter)
            ));
        }
        // The highest usable counter moves `next` to the limit without
        // wrapping, after which every replay and the limit itself stay refused.
        assert!(c.mark_did_receive(REJECT_AFTER_MESSAGES - 1).is_ok());
        assert_eq!(c.next, REJECT_AFTER_MESSAGES);
        assert!(c.mark_did_receive(REJECT_AFTER_MESSAGES - 1).is_err());
        assert!(c.mark_did_receive(REJECT_AFTER_MESSAGES).is_err());
        assert!(c.will_accept(0).is_err());
    }

    /// The window is 8192 counters: the oldest still inside it is accepted
    /// once, one older is too far back.
    #[test]
    fn the_replay_window_holds_8192_counters() {
        assert_eq!(N_BITS, 8192);
        let mut c: ReceivingKeyCounterValidator = Default::default();
        let top = 3 * N_BITS + 17;
        assert!(c.mark_did_receive(top).is_ok());
        let oldest = top + 1 - N_BITS;
        assert!(c.will_accept(oldest).is_ok());
        assert!(c.mark_did_receive(oldest).is_ok());
        assert!(matches!(
            c.mark_did_receive(oldest),
            Err(WireGuardError::InvalidCounter)
        ));
        assert!(matches!(
            c.will_accept(oldest - 1),
            Err(WireGuardError::InvalidCounter)
        ));
        // Every counter between them arrives, in reverse, exactly once.
        for counter in (oldest + 1..top).rev() {
            assert!(c.mark_did_receive(counter).is_ok(), "{}", counter);
        }
        for counter in oldest..=top {
            assert!(c.mark_did_receive(counter).is_err(), "{}", counter);
        }
    }

    /// A jump of at least the window clears every bit, so nothing seen before
    /// it aliases a counter after it; a smaller jump clears exactly the
    /// skipped counters.
    #[test]
    fn a_large_jump_forgets_the_old_window() {
        let mut c: ReceivingKeyCounterValidator = Default::default();
        for counter in 0..N_BITS {
            assert!(c.mark_did_receive(counter).is_ok());
        }
        let after = N_BITS + N_BITS + 5;
        assert!(c.mark_did_receive(after).is_ok());
        for counter in after + 1 - N_BITS..after {
            assert!(c.will_accept(counter).is_ok(), "{}", counter);
        }
        let mut c: ReceivingKeyCounterValidator = Default::default();
        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(1000).is_ok());
        for counter in 1..1000 {
            assert!(c.will_accept(counter).is_ok(), "{}", counter);
        }
        assert!(c.will_accept(0).is_err());
    }

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
