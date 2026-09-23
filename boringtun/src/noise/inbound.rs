// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Receiving a datagram that could be more than one packet kind.
//!
//! AmneziaWG puts a different junk prefix in front of each packet kind, so the
//! outer shape of a datagram -- its length, and the tag at each kind's offset --
//! can fit more than one kind at once. [`AmneziaConfig::inbound_candidates`]
//! lists every kind that fits, at most one each; this module decides which of
//! them, if any, the datagram actually is. The answer is the first candidate
//! that *authenticates*: a shape that fits and then fails its MAC or AEAD is
//! evidence against that reading only, never against the others.
//!
//! That is only safe because trying a reading changes nothing. The trial is
//! split from the acceptance at the points where receive used to mutate
//! partway through -- the handshake's timestamp and in-flight state, the
//! cookie, the replay window -- so a reading that fails leaves the tunnel as
//! it found it, and the datagram bytes too: a header-protected candidate is
//! unmasked in a copy ([`AmneziaConfig::candidate_message`]).
//!
//! Two receive paths share this: [`Tunn::decapsulate`], which every caller of
//! the core tunnel reaches (the FFI, JNI and a peer on a connected socket), and
//! the device's anonymous ingress, which has to find the peer before it has a
//! `Tunn`. They differ only in what a trial is, which is why that is the
//! closure.
//!
//! [`Tunn::decapsulate`]: super::Tunn::decapsulate

use std::net::IpAddr;

use super::amnezia::{AmneziaConfig, InboundCandidates};
use super::errors::WireGuardError;
use super::handshake::ObfuscationRanges;
use super::rate_limiter::{CookieDemand, HandshakeGate, LoadDecision, RateLimiter};
use super::{HandshakeInit, HandshakeResponse, Packet, Tunn};

/// What became of one received datagram.
pub(crate) enum Inbound<T> {
    /// No packet kind fits its shape: not AmneziaWG traffic at all.
    NotOurs,
    /// A candidate authenticated; this is what its trial returned. No other
    /// candidate was tried after it.
    Accepted(T),
    /// No candidate was accepted, and one of them -- a handshake message with
    /// a valid mac1, under load, without a valid mac2 -- is owed a cookie reply.
    Cookie(CookieDemand),
    /// No candidate was accepted; this is the reason to report.
    Refused(WireGuardError),
}

/// Try each candidate reading of `datagram` in order, and accept the first
/// that `trial` authenticates.
///
/// For each candidate: recover its canonical message from the untouched
/// datagram, parse it with the strict parser, and -- for the two handshake
/// kinds -- apply the rate limiter's mac1 and load checks, all before `trial`
/// sees it. `trial` must not change anything unless it returns `Ok`; its `Err`
/// means only "not this reading", and the next one is tried.
///
/// The load decision is taken at most once for the datagram, however many
/// handshake readings reach it. A reading that under load earns only a cookie
/// reply, or only `UnderLoad` for want of a source address, has not
/// authenticated anything, so it is held back rather than answered: a later
/// reading that does authenticate wins. When none does, the outcome is the one
/// the datagram got when a single reading was all there was -- a cookie reply
/// if any reading earned one, then `UnderLoad`, then the first refusal.
///
/// Bounded by the candidate list: at most four readings, so at most one
/// initiation's and one response's worth of Noise work, and no retries.
pub(crate) fn receive<T>(
    amnezia: &AmneziaConfig,
    obf: ObfuscationRanges,
    limiter: &RateLimiter,
    src_addr: Option<IpAddr>,
    candidates: &InboundCandidates,
    datagram: &[u8],
    mut trial: impl FnMut(Packet<'_>) -> Result<T, WireGuardError>,
) -> Inbound<T> {
    let mut load = LoadDecision::default();
    // Allocated only when a candidate is header-protected, and reused by the
    // candidates after it.
    let mut scratch = Vec::new();
    let mut cookie = None;
    let mut under_load = false;
    let mut refusal = None;

    for candidate in candidates.iter() {
        let Some(message) = amnezia.candidate_message(datagram, candidate, &mut scratch) else {
            refusal.get_or_insert(WireGuardError::InvalidPacket);
            continue;
        };
        // The canonical message goes through the strict parser, which applies
        // the size and tag rules again -- the candidate list only says where to
        // look, never what a message may be.
        let packet = match Tunn::parse_incoming_packet(obf, message) {
            Ok(packet) => packet,
            Err(e) => {
                refusal.get_or_insert(e);
                continue;
            }
        };

        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            match limiter.gate_handshake(src_addr, message, sender_idx, &mut load) {
                HandshakeGate::Pass => {}
                HandshakeGate::BadMac => {
                    refusal.get_or_insert(WireGuardError::InvalidMac);
                    continue;
                }
                HandshakeGate::UnderLoad => {
                    under_load = true;
                    continue;
                }
                HandshakeGate::CookieDemanded(demand) => {
                    cookie.get_or_insert(demand);
                    continue;
                }
            }
        }

        match trial(packet) {
            Ok(accepted) => return Inbound::Accepted(accepted),
            Err(e) => {
                refusal.get_or_insert(e);
            }
        }
    }

    if let Some(demand) = cookie {
        return Inbound::Cookie(demand);
    }
    if under_load {
        return Inbound::Refused(WireGuardError::UnderLoad);
    }
    match refusal {
        Some(e) => Inbound::Refused(e),
        None => Inbound::NotOurs,
    }
}

/// Datagrams that fit several packet kinds at once, built on purpose.
///
/// Shared with the device tests, which drive the same datagrams through the
/// anonymous ingress.
#[cfg(test)]
pub(crate) mod fixtures {
    use crate::noise::amnezia::AmneziaConfig;

    /// S1..S4 at which every kind's canonical size lands on one datagram
    /// length: 52 + 148 = 108 + 92 = 136 + 64 = 148 + 52 = [`WIRE`], the last a
    /// transport packet carrying [`bare_ipv4`]. Each kind's first eight bytes
    /// -- tag and index -- fall inside the junk prefix of every kind after it,
    /// which is where [`plant`] writes a false one; and every S holds the
    /// 12-byte nonce, so the same sizes run with header protection on.
    pub(crate) const S: [u16; 4] = [52, 108, 136, 148];
    pub(crate) const WIRE: usize = 200;
    pub(crate) const INIT_AT: usize = S[0] as usize;
    pub(crate) const RESPONSE_AT: usize = S[1] as usize;
    pub(crate) const COOKIE_AT: usize = S[2] as usize;
    pub(crate) const DATA_AT: usize = S[3] as usize;

    /// The colliding sizes, with a header-protection key when one is given.
    pub(crate) fn colliding(key: Option<[u8; 32]>) -> AmneziaConfig {
        let amnezia = AmneziaConfig::new(S[0], S[1], S[2], S[3]);
        match key {
            Some(key) => amnezia.with_header_protection(key),
            None => amnezia,
        }
    }

    /// The smallest well-formed IPv4 packet: a bare 20-byte header, whose
    /// transport frame is 52 bytes when it is sent into a buffer of exactly
    /// [`WIRE`] -- which leaves no room for the usual rounding of the plaintext
    /// up to 16 bytes, and so no padding.
    pub(crate) fn bare_ipv4() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet
    }

    /// Write a false message header -- `tag`, then `index` in the field after
    /// it -- at `offset` of `wire`, masked the way a sender under `amnezia`
    /// masks a real one. `offset` must be past the nonce, which is left alone.
    pub(crate) fn plant(
        wire: &mut [u8],
        amnezia: &AmneziaConfig,
        offset: usize,
        tag: u32,
        index: u32,
    ) {
        const NONCE: usize = crate::noise::header_protection::NONCE_SIZE;
        assert!(offset >= NONCE, "a plant must not disturb the nonce");
        // The first eight keystream bytes, or zeroes with no key set.
        let mut keystream = wire[..NONCE].to_vec();
        keystream.resize(NONCE + 8, 0);
        assert!(amnezia
            .header_protection
            .mask_outbound(&mut keystream, NONCE, 8));
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&tag.to_le_bytes());
        header[4..].copy_from_slice(&index.to_le_bytes());
        for (i, b) in header.iter().enumerate() {
            wire[offset + i] = b ^ keystream[NONCE + i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::noise::handshake::{b2s_hash, b2s_keyed_mac_16, LABEL_MAC1};
    use crate::noise::{Authenticated, TunnResult, HANDSHAKE_INIT_SZ};
    use crate::x25519;
    use rand_core::OsRng;
    use std::sync::Arc;

    const KEY: [u8; 32] = [0x5a; 32];
    /// A tag in no H range under the default `ObfuscationRanges`.
    const NO_KIND: u32 = 0xffff_ffff;
    const SRC: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)));

    /// An initiator and a responder under `amnezia`, the responder's rate
    /// limiter given `their_budget` (`None` for the default).
    fn pair(amnezia: &AmneziaConfig, their_budget: Option<u64>) -> (Tunn, Tunn) {
        let my_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let my_public = x25519::PublicKey::from(&my_secret);
        let their_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let their_public = x25519::PublicKey::from(&their_secret);
        let mine = Tunn::new_with_obfuscation(
            my_secret,
            their_public,
            None,
            None,
            0x0000_1234,
            None,
            ObfuscationRanges::default(),
            amnezia.clone(),
        )
        .unwrap();
        let theirs = Tunn::new_with_obfuscation(
            their_secret,
            my_public,
            None,
            None,
            0x0000_5678,
            their_budget.map(|b| Arc::new(RateLimiter::new(&their_public, b))),
            ObfuscationRanges::default(),
            amnezia.clone(),
        )
        .unwrap();
        (mine, theirs)
    }

    fn network(result: TunnResult) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected a datagram for the network, got {:?}", other),
        }
    }

    /// The canonical message of the first candidate reading of `wire`.
    fn first_message(tunn: &Tunn, wire: &[u8]) -> Vec<u8> {
        let candidates = tunn.amnezia.inbound_candidates(tunn.handshake.obf, wire);
        let first = candidates
            .iter()
            .next()
            .expect("a reading of our own traffic");
        let mut scratch = Vec::new();
        tunn.amnezia
            .candidate_message(wire, first, &mut scratch)
            .unwrap()
            .to_vec()
    }

    /// Complete a handshake, returning the responder's sender index -- the
    /// index its cookie state now expects a cookie reply to name.
    fn handshake(mine: &mut Tunn, theirs: &mut Tunn) -> u32 {
        let mut buf = vec![0u8; 2048];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let response = network(theirs.decapsulate(SRC, &init, &mut buf));
        let their_idx = match Tunn::parse_incoming_packet(
            theirs.handshake.obf,
            &first_message(theirs, &response),
        ) {
            Ok(Packet::HandshakeResponse(p)) => p.sender_idx,
            other => panic!("expected a response, got {:?}", other),
        };
        let keepalive = network(mine.decapsulate(SRC, &response, &mut buf));
        assert!(matches!(
            theirs.decapsulate(SRC, &keepalive, &mut buf),
            TunnResult::Done
        ));
        their_idx
    }

    /// Overwrite every fixture offset before `genuine_at` with a tag in no H
    /// range, so a test that means one reading has exactly one -- rather than
    /// one plus whatever the random junk happens to spell.
    fn only_genuine(wire: &mut [u8], amnezia: &AmneziaConfig, genuine_at: usize) {
        for offset in [INIT_AT, RESPONSE_AT, COOKIE_AT] {
            if offset < genuine_at {
                plant(wire, amnezia, offset, NO_KIND, 0);
            }
        }
    }

    fn keys() -> [Option<[u8; 32]>; 2] {
        [None, Some(KEY)]
    }

    /// Every kind whose canonical size and H range fit is a candidate, each at
    /// its own offset, in trial order -- and nothing else is.
    #[test]
    fn one_candidate_per_kind_at_its_own_offset_and_nowhere_else() {
        let obf = ObfuscationRanges::default();
        for key in keys() {
            let amnezia = colliding(key);
            let mut wire = vec![0u8; WIRE];
            for (i, b) in wire.iter_mut().enumerate() {
                *b = (i * 13 + 7) as u8;
            }
            for (offset, tag) in [(INIT_AT, 1), (RESPONSE_AT, 2), (COOKIE_AT, 3), (DATA_AT, 4)] {
                plant(&mut wire, &amnezia, offset, tag, 0);
            }
            assert_eq!(
                amnezia.inbound_candidates(obf, &wire).offsets(),
                vec![INIT_AT, RESPONSE_AT, COOKIE_AT, DATA_AT],
                "equal wire sizes from different S offsets: every kind is a candidate"
            );

            // A tag outside its kind's H range removes that kind only.
            let mut wrong_tag = wire.clone();
            plant(&mut wrong_tag, &amnezia, RESPONSE_AT, 3, 0);
            assert_eq!(
                amnezia.inbound_candidates(obf, &wrong_tag).offsets(),
                vec![INIT_AT, COOKIE_AT, DATA_AT]
            );

            // One byte longer and no handshake size fits; transport is a minimum.
            let mut longer = wire.clone();
            longer.push(0);
            assert_eq!(
                amnezia.inbound_candidates(obf, &longer).offsets(),
                vec![DATA_AT]
            );
        }

        // With a key set the tags are read through the mask, so the same bytes
        // planted unmasked are not ours.
        let mut unmasked = vec![0u8; WIRE];
        for (offset, tag) in [(INIT_AT, 1), (RESPONSE_AT, 2), (COOKIE_AT, 3), (DATA_AT, 4)] {
            plant(&mut unmasked, &colliding(None), offset, tag, 0);
        }
        assert_eq!(
            colliding(Some(KEY))
                .inbound_candidates(obf, &unmasked)
                .offsets(),
            Vec::<usize>::new()
        );
    }

    /// A transport packet whose junk prefix also reads as an initiation, a
    /// response and a cookie reply is still delivered -- once.
    ///
    /// Before candidates, the initiation reading won because it was tested
    /// first, failed mac1, and took the datagram down with it. The false cookie
    /// names the responder's real cookie index, so it gets past the index check
    /// to the XChaCha20-Poly1305 open and fails *there*, and the cookie it did
    /// not carry must not be stored.
    #[test]
    fn transport_is_accepted_behind_three_false_readings_of_its_bytes() {
        for key in keys() {
            let amnezia = colliding(key);
            let (mut mine, mut theirs) = pair(&amnezia, None);
            let their_idx = handshake(&mut mine, &mut theirs);

            let mut buf = vec![0u8; 2048];
            let mut wire = network(mine.encapsulate(&bare_ipv4(), &mut [0u8; WIRE]));
            assert_eq!(wire.len(), WIRE, "the fixture's arithmetic");
            plant(&mut wire, &amnezia, INIT_AT, 1, 0x0bad_0001);
            plant(&mut wire, &amnezia, RESPONSE_AT, 2, 0x0bad_0002);
            plant(&mut wire, &amnezia, COOKIE_AT, 3, their_idx);
            let obf = theirs.handshake.obf;
            assert_eq!(
                amnezia.inbound_candidates(obf, &wire).offsets(),
                vec![INIT_AT, RESPONSE_AT, COOKIE_AT, DATA_AT],
                "precondition: four readings, and the first-match rule would take the initiation"
            );

            // The false cookie reaches the AEAD, so this is an authentication
            // failure and not an index miss.
            let mut scratch = Vec::new();
            let cookie_reading = amnezia
                .inbound_candidates(obf, &wire)
                .iter()
                .nth(2)
                .copied();
            let message = amnezia
                .candidate_message(&wire, &cookie_reading.unwrap(), &mut scratch)
                .unwrap();
            match Tunn::parse_incoming_packet(obf, message) {
                Ok(Packet::PacketCookieReply(p)) => assert!(matches!(
                    theirs.handshake.authenticate_cookie_reply(&p),
                    Err(WireGuardError::InvalidAeadTag)
                )),
                other => panic!("expected a cookie reading, got {:?}", other),
            }

            match theirs.decapsulate(SRC, &wire, &mut buf) {
                TunnResult::WriteToTunnelV4(packet, _) => assert_eq!(packet, &bare_ipv4()[..]),
                other => panic!(
                    "key {:?}: transport was not delivered: {:?}",
                    key.is_some(),
                    other
                ),
            }
            assert!(
                !theirs.handshake.has_cookie(),
                "a false cookie reading must not store a cookie"
            );
            assert!(
                matches!(theirs.decapsulate(SRC, &wire, &mut buf), TunnResult::Err(_)),
                "one datagram is accepted at most once"
            );
        }
    }

    /// A handshake response whose junk prefix also reads as an initiation
    /// completes the handshake.
    #[test]
    fn a_response_is_accepted_behind_a_false_initiation() {
        for key in keys() {
            let amnezia = colliding(key);
            let (mut mine, mut theirs) = pair(&amnezia, None);
            let mut buf = vec![0u8; 2048];
            let init = network(mine.format_handshake_initiation(&mut buf, false));
            let mut response = network(theirs.decapsulate(SRC, &init, &mut buf));
            assert_eq!(response.len(), WIRE);
            plant(&mut response, &amnezia, INIT_AT, 1, 0);
            assert_eq!(
                amnezia
                    .inbound_candidates(mine.handshake.obf, &response)
                    .offsets(),
                vec![INIT_AT, RESPONSE_AT]
            );

            let keepalive = network(mine.decapsulate(SRC, &response, &mut buf));
            assert!(matches!(
                theirs.decapsulate(SRC, &keepalive, &mut buf),
                TunnResult::Done
            ));
            assert!(mine.time_since_last_handshake().is_some());
        }
    }

    /// A cookie reply whose junk prefix also reads as an initiation and a
    /// response -- the response naming our in-flight handshake -- is stored.
    #[test]
    fn a_cookie_reply_is_accepted_behind_false_handshake_readings() {
        for key in keys() {
            let amnezia = colliding(key);
            let (mut mine, mut theirs) = pair(&amnezia, Some(0));
            let mut buf = vec![0u8; 2048];
            let init = network(mine.format_handshake_initiation(&mut buf, false));
            let my_idx =
                match Tunn::parse_incoming_packet(mine.handshake.obf, &first_message(&mine, &init))
                {
                    Ok(Packet::HandshakeInit(p)) => p.sender_idx,
                    other => panic!("expected an initiation, got {:?}", other),
                };
            let mut cookie = network(theirs.decapsulate(SRC, &init, &mut buf));
            assert_eq!(
                cookie.len(),
                WIRE,
                "a starved responder answers with a cookie"
            );
            plant(&mut cookie, &amnezia, INIT_AT, 1, 0);
            plant(&mut cookie, &amnezia, RESPONSE_AT, 2, my_idx);
            assert_eq!(
                amnezia
                    .inbound_candidates(mine.handshake.obf, &cookie)
                    .offsets(),
                vec![INIT_AT, RESPONSE_AT, COOKIE_AT]
            );

            assert!(!mine.handshake.has_cookie());
            assert!(matches!(
                mine.decapsulate(SRC, &cookie, &mut buf),
                TunnResult::Done
            ));
            assert!(
                mine.handshake.has_cookie(),
                "the real cookie was not stored"
            );
        }
    }

    /// A 200-byte datagram whose initiation reading carries a valid mac1 for
    /// `public`, and whose other three readings are only shapes.
    fn gated_initiation_and_three_shapes(public: &x25519::PublicKey) -> Vec<u8> {
        let amnezia = colliding(None);
        let mut wire = vec![0xeeu8; WIRE];
        for (offset, tag) in [(INIT_AT, 1), (RESPONSE_AT, 2), (COOKIE_AT, 3), (DATA_AT, 4)] {
            plant(&mut wire, &amnezia, offset, tag, 0);
        }
        let mac1_at = INIT_AT + HANDSHAKE_INIT_SZ - 32;
        let mac1 = b2s_keyed_mac_16(
            &b2s_hash(LABEL_MAC1, public.as_bytes()),
            &wire[INIT_AT..mac1_at],
        );
        wire[mac1_at..mac1_at + 16].copy_from_slice(&mac1);
        wire
    }

    fn kind(packet: &Packet) -> &'static str {
        match packet {
            Packet::HandshakeInit(_) => "init",
            Packet::HandshakeResponse(_) => "response",
            Packet::PacketCookieReply(_) => "cookie",
            Packet::PacketData(_) => "data",
        }
    }

    /// The first reading a trial accepts is the answer; no reading after it is
    /// tried, and a reading refused before it does not end the search.
    #[test]
    fn an_accepted_reading_ends_the_search() {
        let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
        let limiter = RateLimiter::new(&public, 100);
        let wire = gated_initiation_and_three_shapes(&public);
        let amnezia = colliding(None);
        let obf = ObfuscationRanges::default();
        let candidates = amnezia.inbound_candidates(obf, &wire);

        let mut tried = Vec::new();
        let outcome = receive(&amnezia, obf, &limiter, SRC, &candidates, &wire, |p| {
            tried.push(kind(&p));
            match p {
                Packet::PacketCookieReply(_) => Ok("cookie"),
                _ => Err(WireGuardError::InvalidAeadTag),
            }
        });
        assert!(matches!(outcome, Inbound::Accepted("cookie")));
        // The response reading failed mac1 and never reached a trial; transport
        // came after the accepted cookie and was never tried.
        assert_eq!(tried, vec!["init", "cookie"]);
    }

    /// Under load, a reading owed only a cookie challenge -- or only
    /// `UnderLoad`, for want of an address -- has authenticated nothing, so it
    /// does not preempt a later reading that authenticates. When none does,
    /// the datagram gets what the challenged reading alone would have got.
    #[test]
    fn a_load_refusal_does_not_preempt_a_reading_that_authenticates() {
        let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
        let wire = gated_initiation_and_three_shapes(&public);
        let amnezia = colliding(None);
        let obf = ObfuscationRanges::default();
        let candidates = amnezia.inbound_candidates(obf, &wire);
        let transport_only = |p: Packet<'_>| match p {
            Packet::PacketData(_) => Ok(()),
            _ => Err(WireGuardError::InvalidAeadTag),
        };
        let nothing =
            |_: Packet<'_>| -> Result<(), WireGuardError> { Err(WireGuardError::InvalidAeadTag) };

        for src in [SRC, None] {
            let starved = RateLimiter::new(&public, 0);
            assert!(matches!(
                receive(
                    &amnezia,
                    obf,
                    &starved,
                    src,
                    &candidates,
                    &wire,
                    transport_only
                ),
                Inbound::Accepted(())
            ));

            let starved = RateLimiter::new(&public, 0);
            match (
                src,
                receive(&amnezia, obf, &starved, src, &candidates, &wire, nothing),
            ) {
                (Some(_), Inbound::Cookie(_)) => {}
                (None, Inbound::Refused(WireGuardError::UnderLoad)) => {}
                (_, Inbound::Accepted(_)) => panic!("nothing authenticated"),
                (src, _) => panic!("with src {:?}, the deferred outcome was lost", src),
            }
        }
    }

    /// A datagram is one load event however many of its readings reach the
    /// limiter.
    #[test]
    fn one_datagram_is_one_load_event() {
        let public = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
        let wire = gated_initiation_and_three_shapes(&public);
        let message = &wire[INIT_AT..];
        // A budget of two: counted once, one more datagram still fits.
        let limiter = RateLimiter::new(&public, 2);

        let mut load = LoadDecision::default();
        for _ in 0..3 {
            assert!(matches!(
                limiter.gate_handshake(None, message, 0, &mut load),
                HandshakeGate::Pass
            ));
        }
        assert!(
            matches!(
                limiter.gate_handshake(None, message, 0, &mut LoadDecision::default()),
                HandshakeGate::Pass
            ),
            "the three readings of one datagram were counted more than once"
        );
        assert!(matches!(
            limiter.gate_handshake(None, message, 0, &mut LoadDecision::default()),
            HandshakeGate::UnderLoad
        ));
    }

    /// Authenticating an initiation records nothing: the same initiation is
    /// still fresh afterwards. Accepting it is what records the timestamp.
    #[test]
    fn authenticating_an_initiation_commits_nothing() {
        let amnezia = colliding(Some(KEY));
        let (mut mine, mut theirs) = pair(&amnezia, None);
        let mut buf = vec![0u8; 2048];
        let init = network(mine.format_handshake_initiation(&mut buf, false));

        let message = first_message(&theirs, &init);
        let packet = Tunn::parse_incoming_packet(theirs.handshake.obf, &message).unwrap();
        assert!(matches!(
            theirs.authenticate(packet, &mut buf),
            Ok(Authenticated::HandshakeInit(_))
        ));

        network(theirs.decapsulate(SRC, &init, &mut buf));
        assert!(
            matches!(
                theirs.decapsulate(SRC, &init, &mut buf),
                TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
            ),
            "accepting the initiation must record its timestamp"
        );
    }

    /// Authenticating a response leaves the initiation it answers in flight.
    #[test]
    fn authenticating_a_response_leaves_the_handshake_in_flight() {
        let amnezia = colliding(Some(KEY));
        let (mut mine, mut theirs) = pair(&amnezia, None);
        let mut buf = vec![0u8; 2048];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let mut response = network(theirs.decapsulate(SRC, &init, &mut buf));
        only_genuine(&mut response, &amnezia, RESPONSE_AT);

        let message = first_message(&mine, &response);
        let packet = Tunn::parse_incoming_packet(mine.handshake.obf, &message).unwrap();
        assert!(matches!(
            mine.authenticate(packet, &mut buf),
            Ok(Authenticated::HandshakeResponse(_))
        ));
        assert!(mine.handshake.is_in_progress());

        network(mine.decapsulate(SRC, &response, &mut buf));
        assert!(matches!(
            mine.decapsulate(SRC, &response, &mut buf),
            TunnResult::Err(WireGuardError::UnexpectedPacket)
        ));
    }

    /// Authenticating a cookie reply stores no cookie.
    #[test]
    fn authenticating_a_cookie_reply_stores_no_cookie() {
        let amnezia = colliding(Some(KEY));
        let (mut mine, mut theirs) = pair(&amnezia, Some(0));
        let mut buf = vec![0u8; 2048];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let cookie = network(theirs.decapsulate(SRC, &init, &mut buf));

        let message = first_message(&mine, &cookie);
        let packet = Tunn::parse_incoming_packet(mine.handshake.obf, &message).unwrap();
        assert!(matches!(
            mine.authenticate(packet, &mut buf),
            Ok(Authenticated::CookieReply(_))
        ));
        assert!(!mine.handshake.has_cookie());

        assert!(matches!(
            mine.decapsulate(SRC, &cookie, &mut buf),
            TunnResult::Done
        ));
        assert!(mine.handshake.has_cookie());
    }

    /// A transport reading that fails its AEAD does not mark its counter, so
    /// the genuine packet with that counter is still accepted -- once.
    #[test]
    fn a_failed_transport_reading_leaves_the_replay_window_alone() {
        let amnezia = colliding(Some(KEY));
        let (mut mine, mut theirs) = pair(&amnezia, None);
        handshake(&mut mine, &mut theirs);
        let mut buf = vec![0u8; 2048];
        let mut wire = network(mine.encapsulate(&bare_ipv4(), &mut [0u8; WIRE]));
        assert_eq!(wire.len(), WIRE);
        only_genuine(&mut wire, &amnezia, DATA_AT);

        let mut forged = wire.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            theirs.decapsulate(SRC, &forged, &mut buf),
            TunnResult::Err(WireGuardError::InvalidAeadTag)
        ));
        assert!(matches!(
            theirs.decapsulate(SRC, &wire, &mut buf),
            TunnResult::WriteToTunnelV4(..)
        ));
        assert!(matches!(
            theirs.decapsulate(SRC, &wire, &mut buf),
            TunnResult::Err(WireGuardError::DuplicateCounter)
        ));
    }

    /// Once a reading has authenticated, a failure after that belongs to it:
    /// the datagram is not read again as another kind, and what acceptance
    /// consumed stays consumed.
    #[test]
    fn an_accepted_reading_is_not_reread_when_its_processing_fails() {
        for key in keys() {
            let amnezia = colliding(key);
            let (mut mine, mut theirs) = pair(&amnezia, None);
            let their_idx = handshake(&mut mine, &mut theirs);
            let mut buf = vec![0u8; 2048];

            // Transport whose plaintext is no IP packet: a total length of 10.
            let mut malformed = bare_ipv4();
            malformed[2..4].copy_from_slice(&10u16.to_be_bytes());
            let mut wire = network(mine.encapsulate(&malformed, &mut [0u8; WIRE]));
            assert_eq!(wire.len(), WIRE);
            plant(&mut wire, &amnezia, INIT_AT, 1, 0);
            plant(&mut wire, &amnezia, RESPONSE_AT, 2, 0);
            plant(&mut wire, &amnezia, COOKIE_AT, 3, their_idx);
            // `InvalidPacket` is transport's own verdict; had every reading been
            // refused, the first refusal -- the initiation's `InvalidMac` --
            // would be reported instead.
            assert!(matches!(
                theirs.decapsulate(SRC, &wire, &mut buf),
                TunnResult::Err(WireGuardError::InvalidPacket)
            ));
            let mut bare = wire.clone();
            only_genuine(&mut bare, &amnezia, DATA_AT);
            assert!(
                matches!(
                    theirs.decapsulate(SRC, &bare, &mut buf),
                    TunnResult::Err(WireGuardError::DuplicateCounter)
                ),
                "the transport packet was accepted, so its counter is spent"
            );

            // An initiation accepted into a buffer too small for its answer.
            let (mut mine, mut theirs) = pair(&amnezia, None);
            let init = network(mine.format_handshake_initiation(&mut buf, false));
            assert!(matches!(
                theirs.decapsulate(SRC, &init, &mut [0u8; 150]),
                TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
            ));
            assert!(
                matches!(
                    theirs.decapsulate(SRC, &init, &mut buf),
                    TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
                ),
                "the initiation was accepted before its answer failed"
            );
        }
    }
}
