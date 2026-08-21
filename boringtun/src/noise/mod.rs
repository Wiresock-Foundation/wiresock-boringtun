// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod amnezia;
pub mod errors;
pub mod handshake;
// `pub(crate)` rather than private: `device::probe_reply` builds the replies
// from the same modules that generate the outbound cover traffic, which is the
// whole point -- a classifier and a responder that share a parser cannot drift
// apart. Still crate-private, so none of it is public API.
pub(crate) mod imitation;
pub mod rate_limiter;

// AmneziaWG 3.0 header protection: ChaCha20 keystream mask, nonce from the junk prefix.
pub mod header_protection;
// QUIC Initial imitation generator (always compiled; pulls in `aes`).
pub(crate) mod quic;
mod session;
// Widened ahead of the AmneziaWG 3.0 tunable-timer comparison in `device::api`;
// no consumer outside `noise` on this branch yet. Present tense would be a claim
// this tree does not support -- this PR is mergeable to master on its own.
pub(crate) mod timers;

use amnezia::AmneziaConfig;
use handshake::ObfuscationRanges;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;
#[cfg(feature = "mock-instant")]
use mock_instant::thread_local::Instant;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    amnezia: AmneziaConfig,
    pending_amnezia_junk: Option<PendingAmneziaJunk>,
    rate_limiter: Arc<RateLimiter>,
}

struct PendingAmneziaJunk {
    /// Pre-generated standalone imitation datagrams (DNS/SIP/STUN sequence or
    /// browser QUIC Initials), each with the delay to wait before emitting it.
    /// Emitted one per call before any random/protocol junk and the handshake
    /// initiation; these use protocol-natural timing, not the Jd delay.
    imitation_datagrams: VecDeque<(Duration, Vec<u8>)>,
    remaining: u16,
    last_packet_at: Option<Instant>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

/// The wire sizes above, re-exported for the ingress tests in `device`.
///
/// `device::reply_policy` decides whether a cookie reply is larger than the
/// packet that provoked it. The decision itself takes both lengths as
/// arguments, so production needs none of these constants — but its tests do,
/// and asserting against remembered numbers instead would leave a change to
/// either packet size to be discovered in the field.
///
/// Gated rather than three `pub(crate)` constants, for the reason
/// [`amnezia::conforming_initiation`] gives for living in `noise` at all:
/// widening a protocol constant crate-wide and permanently, to serve a test,
/// is a larger change than the test is worth. The `device` half of the gate
/// matters too — without it these are dead code in every build of the crate
/// that leaves the feature off.
#[cfg(all(test, feature = "device"))]
pub(crate) mod packet_sizes {
    pub(crate) const HANDSHAKE_INIT_SZ: usize = super::HANDSHAKE_INIT_SZ;
    pub(crate) const HANDSHAKE_RESP_SZ: usize = super::HANDSHAKE_RESP_SZ;
    pub(crate) const COOKIE_REPLY_SZ: usize = super::COOKIE_REPLY_SZ;
}

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(
        obf: ObfuscationRanges,
        src: &[u8],
    ) -> Result<Packet<'_>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (v, HANDSHAKE_INIT_SZ) if obf.matches_h1(v) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (v, HANDSHAKE_RESP_SZ) if obf.matches_h2(v) => {
                Packet::HandshakeResponse(HandshakeResponse {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                        .expect("length already checked above"),
                    encrypted_nothing: &src[44..60],
                })
            }
            (v, COOKIE_REPLY_SZ) if obf.matches_h3(v) => {
                Packet::PacketCookieReply(PacketCookieReply {
                    receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    nonce: &src[8..32],
                    encrypted_cookie: &src[32..64],
                })
            }
            (v, DATA_OVERHEAD_SZ..=std::usize::MAX) if obf.matches_h4(v) => {
                Packet::PacketData(PacketData {
                    receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                    encrypted_encapsulated_packet: &src[16..],
                })
            }
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    // The eight trailing `u32`s are the H1-H4 tag ranges, spelled out rather
    // than passed as the `ObfuscationRanges` they build. In-tree this is only
    // reached from tests -- `device` and the C bindings both go to
    // `new_with_amnezia` -- but it is a `pub` constructor of a library crate,
    // so narrowing it breaks consumers outside this repository. That belongs in
    // an API change, not a lint fix.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        h1_init_start: u32,
        h1_init_end: u32,
        h2_resp_start: u32,
        h2_resp_end: u32,
        h3_cookie_start: u32,
        h3_cookie_end: u32,
        h4_data_start: u32,
        h4_data_end: u32,
    ) -> Result<Self, String> {
        Self::new_with_amnezia(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            h1_init_start,
            h1_init_end,
            h2_resp_start,
            h2_resp_end,
            h3_cookie_start,
            h3_cookie_end,
            h4_data_start,
            h4_data_end,
            AmneziaConfig::default(),
        )
    }

    /// Create a new tunnel with Amnezia S1-S4 junk prefix handling.
    // As `new` above, plus the `AmneziaConfig`. This is the one the C bindings
    // actually reach (`ffi::new_tunnel_with_amnezia_config`), and a C caller
    // cannot hand over an `ObfuscationRanges`, so the eight scalars have to
    // survive at least as far as this frame.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_amnezia(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        h1_init_start: u32,
        h1_init_end: u32,
        h2_resp_start: u32,
        h2_resp_end: u32,
        h3_cookie_start: u32,
        h3_cookie_end: u32,
        h4_data_start: u32,
        h4_data_end: u32,
        amnezia: AmneziaConfig,
    ) -> Result<Self, String> {
        let obf = ObfuscationRanges::new(
            h1_init_start,
            h1_init_end,
            h2_resp_start,
            h2_resp_end,
            h3_cookie_start,
            h3_cookie_end,
            h4_data_start,
            h4_data_end,
        )?;

        Self::new_with_obfuscation(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            obf,
            amnezia,
        )
    }

    /// As [`Self::new_with_amnezia`], but taking obfuscation ranges that have
    /// already been validated.
    ///
    /// Callers holding an [`ObfuscationRanges`] should prefer this: the raw
    /// eight-integer form has to re-run `ObfuscationRanges::new`, which can
    /// only fail on input the caller has by definition already rejected, so the
    /// error it returns is unreachable and tempts callers into `expect`.
    ///
    /// # Errors
    ///
    /// Two. Seeding the per-tunnel RNG from OS entropy, which is real but rare.
    /// And, when `amnezia` carries a header-protection key, any of S1..S4 below
    /// `NONCE_SIZE`: header protection takes each datagram's nonce from its own
    /// junk prefix, so a prefix shorter than that cannot supply one and the
    /// packet kind it precedes can never be sent. Every position is fatal, by a
    /// different route -- S1 short means no initiation, so an initiator never
    /// forms a session at all; S2 means no response, so a responder never
    /// completes one; S3 costs cookie replies under load; S4 means the
    /// handshake completes and then no data crosses. The error names the
    /// offending size. Configurations without a key are unaffected.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_obfuscation(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        obf: ObfuscationRanges,
        amnezia: AmneziaConfig,
    ) -> Result<Self, String> {
        // A junk prefix shorter than the header-protection nonce cannot supply
        // one, so `prepend_outbound` refuses that packet kind for the life of
        // the tunnel. The refusal is per-kind, not global -- only the kind
        // whose own S is short -- but every position is fatal by some route,
        // and on a *fresh* tunnel S1 is fatal immediately: no initiation means
        // no session, so nothing else is ever reached. See the constructor's
        // rustdoc for the per-position table.
        //
        // Refused here, where the constructor already returns
        // `Result<_, String>` and can name the offending S size, rather than at
        // send time as a `DestinationBufferTooSmall` pointing the caller at a
        // buffer that was never the problem.
        //
        // Parity, not added strictness: amneziawg-go refuses the same four in
        // `mergeWithDevice` against its own `HeaderCipherNonceSize = 12`.
        //
        // Only this rule, not the whole of `validate` -- for compatibility, not
        // policy. `validate` is universal now (the cookie-reflection policy
        // moved out to `device::api`, its one responder), but these
        // constructors predate it and have accepted timer and size shapes
        // `validate` refuses; widening the check here would break existing
        // Rust callers for configurations that, like the kernel module, merely
        // run badly. The struct-based C constructor, which has no such legacy,
        // does run the whole of `validate`.
        amnezia.check_header_protection_nonce()?;

        let static_public = x25519::PublicKey::from(&static_private);

        Ok(Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                // `index << 8`, not `index`: the low byte is the cyclic session
                // counter `Handshake::inc_index` advances, so the device's peer
                // index has to sit in the top 24 bits. `Device` demuxes every
                // inbound response, cookie and data packet with
                // `peers_by_idx.get(&(receiver_idx >> 8))`, and that only finds
                // the peer if the index on the wire was seeded shifted.
                index << 8,
                preshared_key,
                obf,
            )?,
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
            amnezia,
            pending_amnezia_junk: None,

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        })
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
        self.pending_amnezia_junk = None;
    }

    /// Replace this tunnel's AmneziaWG obfuscation settings.
    ///
    /// H1-H4 and S1-S4 are interface-wide in AmneziaWG, so when the device's
    /// settings change every peer must follow: a peer left on the old values
    /// tags and pads its packets differently from the interface that has to
    /// parse them, and the tunnel dies silently and permanently.
    ///
    /// Live sessions are kept. Obfuscation is a framing concern, not a
    /// cryptographic one — the keys and the Noise state are untouched, so
    /// forcing a re-handshake would drop traffic for no benefit. Any queued
    /// pre-handshake junk is dropped, since it was generated under the previous
    /// configuration.
    ///
    /// The tunable timers are re-drawn for the same reason the H/S values are
    /// pushed at all: they are cached per-arming, so without this an
    /// established session keeps running the *previous* configuration's
    /// deadlines while `update_session_timers` already expires it on the new
    /// `reject_after_time`.
    ///
    /// Only when they actually changed, though. This method is called for any
    /// AmneziaWG edit -- an `s1`, a magic header, a padding range -- and every
    /// one of those would otherwise move an established session's rekey
    /// deadline and replace the in-flight cycle's retransmission budget, which
    /// is precisely the per-session and per-cycle latching the caches exist to
    /// provide.
    pub fn set_obfuscation(&mut self, obf: ObfuscationRanges, amnezia: AmneziaConfig) {
        let timers_changed = self.amnezia.timers != amnezia.timers;
        self.handshake.set_obfuscation(obf);
        self.amnezia = amnezia;
        self.pending_amnezia_junk = None;
        if timers_changed {
            self.redraw_tunable_timers();
        }
    }

    /// Update only the MTU the content padding is clamped against.
    ///
    /// The MTU is runtime link state, not obfuscation configuration, so this
    /// deliberately does not go through [`Self::set_obfuscation`]: that path
    /// drops any queued pre-handshake junk burst, which is right when the
    /// operator changed the framing and wrong for a link property that moved
    /// under us -- and it moves at every wg-quick bring-up, where the MTU is
    /// set *after* `wg setconf`, exactly when the first handshake's burst is
    /// most likely in flight.
    pub fn set_content_padding_mtu(&mut self, mtu: u16) {
        self.amnezia.content_padding_mtu = mtu;
    }

    /// The MTU `content_padding` currently clamps against.
    ///
    /// Test-only, and `pub(crate)` for the FFI setter's tests rather than for
    /// production: nothing shipped needs to read this back -- the device holds
    /// its own copy in `DeviceConfig` and compares against that. The tests do
    /// need it, because the two failure modes that matter are invisible on the
    /// wire. A refused value must not have been stored, and an oversize one
    /// must saturate rather than truncate -- and a clamp of 0 pads a
    /// 1280-byte packet exactly like a clamp of 65535 does, so no amount of
    /// datagram measurement can tell `65536 as u16` from a correct saturation.
    ///
    /// `ffi-bindings` is in the gate as well as `test`, because those tests are
    /// the only caller: a default-feature `cargo test` compiles no `ffi` module,
    /// and a bare `#[cfg(test)]` left this carrying a `dead_code` warning on
    /// every such build.
    #[cfg(all(test, feature = "ffi-bindings"))]
    pub(crate) fn content_padding_mtu(&self) -> u16 {
        self.amnezia.content_padding_mtu
    }

    /// Update the persistent-keepalive interval.
    ///
    /// Purely a timer change, so live sessions are kept: the peer's keys are
    /// unaffected and re-handshaking would be gratuitous.
    pub fn set_persistent_keepalive(&mut self, keepalive: Option<u16>) {
        self.timers.set_persistent_keepalive(keepalive);
    }

    /// The peer's optional pre-shared key.
    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        self.handshake.preshared_key()
    }

    /// Replace the peer's optional pre-shared key.
    ///
    /// Unlike the keepalive, this **discards every established session**. The
    /// pre-shared key is mixed into the handshake, so sessions derived under the
    /// old value are cryptographically stale; keeping them would leave the peer
    /// authenticated by a key the operator has just revoked. This mirrors what
    /// [`Self::set_static_private`] does for the static key.
    ///
    /// No-op when the key is unchanged, so a configuration reload that re-sends
    /// the same value does not tear down live tunnels.
    pub fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        // Compare the *effective* key, not the `Option`. The handshake mixes
        // `preshared_key.unwrap_or([0u8; 32])`, so `None` and `Some([0; 32])`
        // are the same key cryptographically -- and wg's tooling clears a PSK
        // by sending 32 zero bytes rather than omitting the field, so a plain
        // `Option` comparison would treat a routine reload as a key change and
        // tear down every session for a peer that never had a PSK.
        let effective = |key: Option<[u8; 32]>| key.unwrap_or([0u8; 32]);
        let unchanged = effective(self.handshake.preshared_key()) == effective(preshared_key);

        // Always store the caller's value, even when it is cryptographically
        // equivalent. `Peer` keeps its own copy for `get=1`, and skipping the
        // write here would let the two disagree -- the handshake holding
        // `Some([0; 32])` while the peer reports `None`, or the reverse.
        self.handshake.set_preshared_key(preshared_key);

        // Only the teardown is conditional: sessions derived from an equivalent
        // key are still valid, so discarding them would drop live traffic for
        // no gain.
        if unchanged {
            return;
        }
        for s in &mut self.sessions {
            *s = None;
        }
        self.pending_amnezia_junk = None;
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// A `dst` too small for the packet this would produce yields
    /// `TunnResult::Err(WireGuardError::DestinationBufferTooSmall)`. Without
    /// Amnezia padding, dst should be at least src.len() + 32, and no less than
    /// 148 bytes. With Amnezia enabled, callers must also allow for the
    /// configured S-prefix on the emitted packet type; when no session is
    /// established, the first output can instead be a standalone pre-handshake
    /// junk packet up to 1280 bytes.
    ///
    /// The established-session path used to *panic* on a short dst while the
    /// no-session path beside it returned this error. Since both are reached
    /// through `extern "C"` FFI callees, where a panic aborts instead of
    /// unwinding, that inconsistency cost the caller their process.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        let transport_junk = self.amnezia.transport_junk_size();
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // The whole wire size, not just the base frame. `format_packet_data`
            // checks only `src.len() + DATA_OVERHEAD_SZ` and then advances the
            // sending counter, while the S4 prefix is added afterwards by
            // `write_to_network` -- so a dst falling between those two sizes
            // used to burn a nonce on every rejected call.
            //
            // This has to stay inside the established-session branch. The
            // no-session branch below emits a handshake initiation, or a
            // standalone pre-handshake junk datagram, and neither size has
            // anything to do with `src.len()` or S4. Gating those on a
            // transport-shaped bound would stop the tunnel coming up at all,
            // and would drop the packet instead of queueing it for retry.
            if dst.len() < src.len() + DATA_OVERHEAD_SZ + transport_junk {
                return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
            }

            // The padding budget lives in one place -- `content_padding_for_frame`
            // owns the committed/space arithmetic for this site and the
            // keepalive site both, so the two bounds cannot drift apart.
            let pad = self.amnezia.content_padding_for_frame(
                src.len(),
                dst.len(),
                transport_junk,
                &mut self.handshake.rng,
            );

            // Send the packet using an established session
            let packet_size = match session.format_packet_data(
                self.handshake.obf,
                &mut self.handshake.rng,
                src,
                pad,
                dst,
            ) {
                Ok(packet) => packet.len(),
                Err(e) => return TunnResult::Err(e),
            };
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return self.write_to_network(dst, packet_size);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        // The received datagram's length as it arrived on the wire, taken
        // before the rebind below strips the junk prefix. The cookie-reply
        // guard further down compares wire length against wire length --
        // the same two numbers `device::reply_policy::cookie_verdict` uses
        // (`packet_len` from `recv_from` against `cookie_reply_len`) -- so the
        // two guards cannot disagree about what "larger than the packet that
        // provoked it" means.
        let wire_len = datagram.len();

        // Header protection has to be undone before anything reads the message
        // type, and undoing it mutates. The public signature takes `&[u8]`, and
        // widening it would push a `&mut` requirement through `device`, the C
        // API and the JNI bindings -- and make `wireguard_read` scribble on a
        // buffer its header describes as the received packet. So the protected
        // path copies instead.
        //
        // The copy is one allocation per inbound datagram, and only when a key
        // is set; the unprotected path below is untouched. A buffer owned by
        // `Tunn` would avoid it, but it cannot be borrowed across the `&mut
        // self` calls further down, so that wants `mem::take` and a restore on
        // every early return -- worth doing, not worth doing first.
        let unmasked;
        let datagram = if self.amnezia.header_protection_enabled() {
            let mut buf = datagram.to_vec();
            match self
                .amnezia
                .unmask_and_classify_inbound(self.handshake.obf, &mut buf)
            {
                Some(junk) => {
                    unmasked = buf;
                    &unmasked[junk..]
                }
                None => return TunnResult::Err(WireGuardError::InvalidPacket),
            }
        } else {
            // A datagram that matches no configured shape is rejected here
            // rather than re-parsed at offset 0. With a junk prefix configured
            // this is the S-prefix doing its job as an input filter.
            match self.amnezia.strip_inbound(self.handshake.obf, datagram) {
                Some(d) => d,
                None => return TunnResult::Err(WireGuardError::InvalidPacket),
            }
        };
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self.rate_limiter.verify_packet(
            self.handshake.obf,
            &mut self.handshake.rng,
            src_addr,
            datagram,
            &mut cookie,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                // The one place a `Tunn` emits a packet to an address it has
                // not authenticated: `verify_packet` produces a cookie on a
                // valid mac1, and mac1 is keyed on our *public* key, so any
                // holder of a client config can provoke this from a forged
                // source. If the reply as it would leave the wire -- cookie
                // plus its S3 junk prefix -- is larger than the datagram that
                // provoked it, sending would make this port a reflection
                // amplifier, so it is not sent. Suppressed here, at the emit
                // site, rather than trusted to configuration checks: this
                // guard holds for every `Tunn` however it was built, including
                // through the C constructors, which deliberately accept an
                // amplifying S3 because a *client* is handed that value by its
                // server and never reaches this arm (`wireguard_read` passes
                // no source address, so `verify_packet` bails on `UnderLoad`
                // before formatting). The device's ingress path applies the
                // same parity rule through `reply_policy::cookie_verdict`,
                // which reads the same `amnezia::reply_amplifies` this does --
                // one expression, so the two cannot drift on which side of
                // parity is allowed. That path covers the device's *unconnected*
                // socket only; a peer promoted to a connected socket reaches
                // this arm instead, which is why the warning below is here.
                //
                // `Done` and not an error: the datagram was valid, the peer
                // simply gets no cookie -- the same outcome the device's
                // suppression produces, and the same thing the peer sees from
                // a server whose reply was lost in the flood that put the
                // limiter under load in the first place.
                let packet_size = cookie.len();
                if self
                    .amnezia
                    .cookie_reply_would_amplify(packet_size, wire_len)
                {
                    // Said, not dropped in silence, for the reason
                    // `device::reply_policy` gives at its own suppression site:
                    // the cost of this is every handshake failing for as long as
                    // the flood lasts, the fix is to lower S3, and the operator
                    // can only make it if they are told. This arm is the one the
                    // device's warning does *not* cover -- a peer on a connected
                    // socket (`use_connected_socket` is the default) reaches
                    // `decapsulate` and never the ingress path that warns, and a
                    // Rust embedder driving `decapsulate(Some(addr), ..)` has no
                    // ingress path at all.
                    //
                    // Latched process-wide rather than logged per packet: this
                    // arm fires under flood, which is precisely when a line per
                    // datagram would be its own denial of service. `static` and
                    // not a field on `Tunn`, matching `prepend_outbound`'s
                    // warning -- a tunnel in this state suppresses every reply,
                    // so the second line would only be noise.
                    static WARNED: std::sync::Once = std::sync::Once::new();
                    WARNED.call_once(|| {
                        tracing::warn!(
                            message = "suppressing a cookie reply: S3 makes it larger than the \
                                       packet that provoked it, which is a reflection amplifier. \
                                       Handshakes will fail while this tunnel is under load; \
                                       lower S3.",
                            reply_len = self.amnezia.cookie_reply_len(packet_size),
                            request_len = wire_len,
                        )
                    });
                    return TunnResult::Done;
                }
                // Every other short-buffer exit in this function reports
                // `DestinationBufferTooSmall`; without this one the slice below
                // panics instead, and `decapsulate` is `extern "C"`-reachable,
                // where a panic cannot unwind and the FFI hook turns it into a
                // raised SIGSEGV. Measured before this line existed: a
                // `decapsulate(Some(addr), init, &mut [0u8; 32])` against a
                // zero-budget limiter panicked with "range end index 64 out of
                // range for slice of length 32". Checked here rather than left
                // to `write_to_network`, which only sees the buffer after the
                // copy has already run.
                if dst.len() < packet_size {
                    return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
                }
                dst[..packet_size].copy_from_slice(cookie);
                return self.write_to_network(dst, packet_size);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;
        let packet_size = packet.len();

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(self.write_to_network(dst, packet_size))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        // Checked before the response is consumed, not after. The keepalive
        // below is a data packet with an empty payload, so it needs exactly
        // DATA_OVERHEAD_SZ plus whatever S4 prefix `write_to_network` will add
        // -- a fixed requirement, knowable here.
        // `receive_handshake_response` clears the handshake state
        // (handshake.rs:869-873), so an error raised after it would discard a
        // valid response and leave the retry -- with a correct buffer -- failing
        // as UnexpectedPacket. Unlike the data path, whose equivalent error is
        // retryable, that would cost the keepalive for good.
        let transport_junk = self.amnezia.transport_junk_size();
        if dst.len() < DATA_OVERHEAD_SZ + transport_junk {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let session = self.handshake.receive_handshake_response(p)?;

        // A keepalive is padded too -- upstream draws against an empty plaintext.
        // The zero-fill in `format_packet_data` is what keeps it a keepalive: the
        // peer classifies any zero-first-byte plaintext as one. Same budget
        // helper as the data path, so the two frames' bounds cannot drift.
        let pad = self.amnezia.content_padding_for_frame(
            0,
            dst.len(),
            transport_junk,
            &mut self.handshake.rng,
        );

        let keepalive_packet = session.format_packet_data(
            self.handshake.obf,
            &mut self.handshake.rng,
            &[],
            pad,
            dst,
        )?;
        let keepalive_packet_size = keepalive_packet.len();
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(self.write_to_network(dst, keepalive_packet_size)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.pending_amnezia_junk.is_some() {
            return self.advance_amnezia_junk(dst);
        }

        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        if self.amnezia.emits_pre_handshake() {
            let imitation_datagrams = self
                .amnezia
                .pre_handshake_imitation_datagrams(&mut self.handshake.rng);
            // Like wgbooster (execute_imitation_obfuscation then
            // send_random_packets then the handshake), the imitation sequence and
            // the Jc random/protocol-shaped junk are both emitted: the sequence
            // first, then `packet_count` junk packets, then the initiation.
            self.pending_amnezia_junk = Some(PendingAmneziaJunk {
                imitation_datagrams,
                remaining: self.amnezia.pre_handshake_junk.packet_count,
                last_packet_at: None,
            });
            return self.advance_amnezia_junk(dst);
        }

        self.format_handshake_initiation_now(dst, force_resend)
    }

    fn format_handshake_initiation_now<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                let packet_size = packet.len();
                tracing::debug!("Sending handshake_initiation");

                // One retransmission deadline per send, like upstream's
                // `timersHandshakeInitiated`; one attempt limit per cycle, like
                // its per-cycle `maxHandshakeAttempts` snapshot. Unset ranges
                // return the classic constants without touching the RNG.
                self.timers.retransmit_current = self
                    .amnezia
                    .timers
                    .retransmit_timeout(&mut self.handshake.rng);
                if starting_new_handshake {
                    // The cycle's first initiation is not a retransmission, so
                    // the counter starts empty; the budget is drawn once here
                    // and spent by the retries.
                    self.timers.handshake_attempts = 0;
                    self.timers.max_retransmissions_current = self
                        .amnezia
                        .timers
                        .max_retransmissions(&mut self.handshake.rng);
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                } else {
                    self.timers.handshake_attempts =
                        self.timers.handshake_attempts.saturating_add(1);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                self.write_to_network(dst, packet_size)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    fn advance_amnezia_junk<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let Some(pending) = self.pending_amnezia_junk.as_ref() else {
            return TunnResult::Done;
        };

        // The next imitation datagram carries its own protocol-natural delay;
        // random/protocol junk uses the configured Jd delay.
        let next_datagram_delay = pending.imitation_datagrams.front().map(|(d, _)| *d);
        let delay = next_datagram_delay.unwrap_or_else(|| self.amnezia.pre_handshake_junk.delay());
        let delay_elapsed = pending
            .last_packet_at
            .map(|last| last.elapsed() >= delay)
            .unwrap_or(true);
        let has_queued_datagram = next_datagram_delay.is_some();
        let remaining = pending.remaining;
        // `pending` (immutable borrow) ends here; the rest reborrows as needed.

        if !delay_elapsed {
            return TunnResult::Done;
        }

        // Emit any pre-generated standalone imitation datagrams (DNS/SIP/STUN or
        // browser QUIC Initials) first, one per call.
        if has_queued_datagram {
            let pending = self
                .pending_amnezia_junk
                .as_mut()
                .expect("pending checked above");
            // Check capacity before dequeuing so a too-small buffer can be
            // retried without losing the datagram.
            let size = pending
                .imitation_datagrams
                .front()
                .expect("queue checked non-empty above")
                .1
                .len();
            if dst.len() < size {
                return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
            }
            let (_, datagram) = pending.imitation_datagrams.pop_front().unwrap();
            // wgbooster uses a delay-AFTER model: the imitation sequence has no
            // trailing sleep, and send_random_packets() emits its first packet
            // immediately. So once the imitation queue is drained, clear
            // last_packet_at to make the first Jc junk packet (or the handshake,
            // when Jc=0) due immediately rather than waiting one extra Jd. While
            // datagrams remain, time the next one's delay from now.
            pending.last_packet_at = if pending.imitation_datagrams.is_empty() {
                None
            } else {
                Some(Instant::now())
            };
            dst[..size].copy_from_slice(&datagram);
            return TunnResult::WriteToNetwork(&mut dst[..size]);
        }

        if remaining == 0 {
            // The initiation was deliberately deferred behind the junk packets, so
            // it must be emitted now: force the (re)format. A previous attempt may
            // have already moved the handshake into `InitSent` before
            // `write_to_network` failed on an oversized prefix, and a non-forced
            // retry would otherwise hit the `is_in_progress()` guard, return `Done`,
            // and silently drop the initiation. Clear the pending state only once
            // the initiation packet is actually written to the network, so a retry
            // with a larger buffer resends only the initiation, never the junk.
            let result = self.format_handshake_initiation_now(dst, true);
            if matches!(result, TunnResult::WriteToNetwork(_)) {
                self.pending_amnezia_junk = None;
            }
            return result;
        }

        let packet = match self
            .amnezia
            .fill_pre_handshake_junk(dst, &mut self.handshake.rng)
        {
            Ok(packet) => packet,
            Err(e) => return TunnResult::Err(e),
        };

        if let Some(pending) = &mut self.pending_amnezia_junk {
            pending.remaining -= 1;
            pending.last_packet_at = Some(Instant::now());
        }

        TunnResult::WriteToNetwork(packet)
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        // A keepalive is empty -- or, from a peer using AmneziaWG's
        // `content_padding_addition`, a run of zero bytes, since the padding is
        // appended to an empty payload. amneziawg-go accepts both with a single
        // test on the first byte (`len(packet) == 0 || packet[0] == 0` in
        // device/receive.go), so we do too; rejecting the padded form strands
        // every peer that pads.
        //
        // What rejecting it actually cost is narrower than "the tunnel dies":
        // `handle_data` ticks `TimeLastPacketReceived` *before* calling this, so
        // liveness was never at risk. But `TunnResult::Err` makes the device
        // layer `continue` past `Peer::set_endpoint`, so a roaming peer whose
        // only traffic is keepalives never moves its endpoint, and the
        // connected-socket path logs one line per keepalive.
        //
        // `first()` rather than `packet[0]`: nothing but arm ordering kept the
        // old index in bounds, and this runs under `extern "C"` FFI where an
        // index panic aborts the caller's process instead of unwinding.
        //
        // No valid IP packet starts with a zero byte -- the version nibble would
        // have to be 0 -- so this cannot swallow real traffic. It can still
        // swallow a plaintext that merely starts with one and carries something
        // else after it, which the catch-all below used to report, so note it
        // rather than drop it silently.
        //
        // The note does not call that plaintext malformed, because nothing here
        // establishes it is: this arm cannot tell padding from garbage, and a
        // peer padding with something other than zeros would land in it. It says
        // what was observed and nothing more. Accepting it either way is what
        // matches amneziawg-go, whose rule at device/receive.go is the same
        // first-byte test and which logs every keepalive it takes.
        if matches!(packet.first(), None | Some(&0)) {
            if packet.iter().any(|&b| b != 0) {
                tracing::debug!(
                    message = "Discarding a zero-prefixed plaintext with a non-zero tail",
                    len = packet.len()
                );
            }
            return TunnResult::Done;
        }

        let (computed_len, src_ip_address) =
            if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                let computed_len = u16::from_be_bytes(len_bytes) as usize;
                // The IPv4 total-length field covers the header too, so a value below
                // the minimum header size describes a packet that cannot exist. The
                // upper-bound check below does not catch it, and the truncation at the
                // end would then hand the tun device a runt -- an empty write, for a
                // total length of 0 -- while crediting `rx_bytes` with the field
                // rather than the bytes received. wireguard-go rejects the same case
                // (`int(length) < ipv4.HeaderLen`). The v6 branch needs no equivalent:
                // it adds IPV6_MIN_HEADER_SIZE to the payload length.
                if computed_len < IPV4_MIN_HEADER_SIZE {
                    return TunnResult::Err(WireGuardError::InvalidPacket);
                }
                (computed_len, IpAddr::from(addr_bytes))
            } else if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            } else {
                return TunnResult::Err(WireGuardError::InvalidPacket);
            };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn write_to_network<'a>(&mut self, dst: &'a mut [u8], packet_size: usize) -> TunnResult<'a> {
        match self.amnezia.prepend_outbound(
            self.handshake.obf,
            dst,
            packet_size,
            &mut self.handshake.rng,
        ) {
            Ok(packet) => TunnResult::WriteToNetwork(packet),
            Err(e) => TunnResult::Err(e),
        }
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};
    use std::convert::TryInto;

    fn create_two_tuns() -> (Tunn, Tunn) {
        create_two_tuns_with_keepalive(None)
    }

    fn create_two_tuns_with_keepalive(persistent_keepalive: Option<u16>) -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            persistent_keepalive,
            my_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        .unwrap();

        let their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        .unwrap();

        (my_tun, their_tun)
    }

    fn create_two_tuns_with_amnezia(amnezia: AmneziaConfig) -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new_with_amnezia(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            amnezia.clone(),
        )
        .unwrap();

        let their_tun = Tunn::new_with_amnezia(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            amnezia,
        )
        .unwrap();

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn unwrap_network_packet(result: TunnResult) -> Vec<u8> {
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        if let TunnResult::WriteToNetwork(sent) = result {
            sent.to_vec()
        } else {
            unreachable!();
        }
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        create_two_tuns_and_handshake_with_keepalive(None)
    }

    fn create_two_tuns_and_handshake_with_keepalive(
        persistent_keepalive: Option<u16>,
    ) -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns_with_keepalive(persistent_keepalive);
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_two_tuns_and_handshake_with_amnezia(amnezia: AmneziaConfig) -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    /// Move time forward past a pacing gate, whichever clock is compiled in.
    ///
    /// The imitation and Jc sequences are paced by `Instant::now()`, so a test
    /// that waits for the next datagram has to advance the clock the production
    /// code is actually reading. `std::thread::sleep` only advances the real
    /// one: under `mock-instant` the mocked clock stays put, `update_timers`
    /// finds nothing due, and the test sees `Done` where it expected a
    /// datagram. That is what `cargo hack test --each-feature` hit — these
    /// tests passed under every other feature and failed under this one.
    ///
    /// Advancing the mock is also strictly better where it applies: no real
    /// sleeping, and no dependence on the scheduler waking us late enough.
    fn advance_past_pacing_gate(d: Duration) {
        #[cfg(feature = "mock-instant")]
        mock_instant::thread_local::MockClock::advance(d);
        #[cfg(not(feature = "mock-instant"))]
        std::thread::sleep(d);
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(tun.handshake.obf, packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::thread_local::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        mock_instant::thread_local::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    #[test]
    fn amnezia_s1_to_s4_full_handshake_and_data() {
        let amnezia = AmneziaConfig::new(5, 7, 11, 13);
        let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);
        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5);
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );

        let resp = create_handshake_response(&mut their_tun, &init);
        assert_eq!(resp.len(), HANDSHAKE_RESP_SZ + 7);
        assert_eq!(
            u32::from_le_bytes(resp[7..11].try_into().unwrap()),
            HANDSHAKE_RESP
        );

        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        assert_eq!(keepalive.len(), DATA_OVERHEAD_SZ + 13);
        assert_eq!(
            u32::from_le_bytes(keepalive[13..17].try_into().unwrap()),
            DATA
        );
        parse_keepalive(&mut their_tun, &keepalive);

        let sent_packet_buf = create_ipv4_udp_packet();
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };
        assert_eq!(u32::from_le_bytes(data[13..17].try_into().unwrap()), DATA);

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    #[test]
    fn amnezia_full_handshake_and_data_for_each_imitation_protocol() {
        use amnezia::AmneziaImitationProtocol as P;

        for protocol in [P::None, P::Dns, P::Quic, P::Sip, P::Stun] {
            let amnezia = AmneziaConfig::new(5, 7, 11, 13)
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);

            // Each non-None protocol emits a standalone pre-handshake sequence
            // before the initiation (QUIC's omitted browser defaults to curl = 1
            // Initial). Sleep past the protocol-natural inter-datagram delays
            // (max 20 ms) so the queued datagrams become due.
            let pre_handshake_count = match protocol {
                P::Dns => 3,
                P::Sip | P::Stun => 2,
                P::Quic => 1,
                P::None => 0,
            };
            let mut dst = vec![0u8; 2048];
            let mut result = my_tun.format_handshake_initiation(&mut dst, false);
            for _ in 0..pre_handshake_count {
                assert!(
                    matches!(result, TunnResult::WriteToNetwork(_)),
                    "expected pre-handshake datagram for protocol={:?}",
                    protocol
                );
                advance_past_pacing_gate(Duration::from_millis(25));
                result = my_tun.update_timers(&mut dst);
            }
            let init = unwrap_network_packet(result);

            // Full handshake: every packet type carries a protocol-shaped S-prefix
            // and must still be stripped and parsed by the peer.
            assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5, "protocol={protocol:?}");
            let resp = create_handshake_response(&mut their_tun, &init);
            assert_eq!(resp.len(), HANDSHAKE_RESP_SZ + 7, "protocol={protocol:?}");
            let keepalive = parse_handshake_resp(&mut my_tun, &resp);
            assert_eq!(
                keepalive.len(),
                DATA_OVERHEAD_SZ + 13,
                "protocol={protocol:?}"
            );
            parse_keepalive(&mut their_tun, &keepalive);

            // Data packet round-trips through the real decapsulate path.
            let sent_packet_buf = create_ipv4_udp_packet();
            let mut my_dst = [0u8; 2048];
            let mut their_dst = [0u8; 2048];
            let data = unwrap_network_packet(my_tun.encapsulate(&sent_packet_buf, &mut my_dst));
            let recv = their_tun.decapsulate(None, &data, &mut their_dst);
            let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = recv {
                recv
            } else {
                panic!(
                    "expected WriteToTunnelV4 for protocol={:?}, got {:?}",
                    protocol, recv
                );
            };
            assert_eq!(sent_packet_buf, recv_packet_buf, "protocol={protocol:?}");
        }
    }

    /// The counter a data packet carries, read straight out of the wire format.
    ///
    /// The sending counter is private to `Session`, and the point of these
    /// checks is what a peer would see anyway.
    fn counter_of(packet: &[u8]) -> u64 {
        u64::from_le_bytes(packet[8..16].try_into().unwrap())
    }

    // The four checks below cover the two `dst`-too-small sites in
    // `noise::session`, which used to `panic!`. Every caller reaches them
    // through `ffi::wireguard_write` / `_read` / `_tick`, and those are
    // `extern "C"` -- so the panic met rustc's nounwind shim and aborted the
    // process instead of unwinding. What reads here as an ordinary error was,
    // for anyone coming through the C or JNI bindings, the loss of their whole
    // process, and for JNI callers specifically the loss of the JVM.

    #[test]
    fn encapsulate_errors_when_dst_cannot_hold_the_data_packet() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        let packet = create_ipv4_udp_packet();

        let mut one_short = vec![0u8; packet.len() + DATA_OVERHEAD_SZ - 1];
        assert!(matches!(
            my_tun.encapsulate(&packet, &mut one_short),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));

        // The boundary itself, not just the error: an off-by-one in the check
        // would satisfy the assertion above while rejecting valid calls.
        let mut exact = vec![0u8; packet.len() + DATA_OVERHEAD_SZ];
        assert!(matches!(
            my_tun.encapsulate(&packet, &mut exact),
            TunnResult::WriteToNetwork(_)
        ));
    }

    #[test]
    fn encapsulate_at_the_tunnel_mtu_errors_rather_than_aborting() {
        // The most ordinary way in: size both buffers to the tunnel MTU. 1420
        // bytes of payload needs 1452 to seal.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        let src = vec![0u8; 1420];
        let mut dst = vec![0u8; 1420];
        assert!(matches!(
            my_tun.encapsulate(&src, &mut dst),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }

    #[test]
    fn a_rejected_encapsulate_does_not_advance_the_nonce() {
        // The size check runs before the sending counter is incremented. If it
        // ran after, every rejected call would burn a nonce -- invisible until
        // a peer with a tight replay window started dropping live traffic.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];

        let first = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));
        let before = counter_of(&first);

        let mut too_small = vec![0u8; 8];
        for _ in 0..4 {
            assert!(matches!(
                my_tun.encapsulate(&packet, &mut too_small),
                TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
            ));
        }

        let next = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));
        assert_eq!(
            counter_of(&next),
            before + 1,
            "four rejected calls advanced the nonce"
        );
    }

    #[test]
    fn decapsulate_errors_when_dst_cannot_hold_the_plaintext() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));

        // A caller who sized dst for the plaintext is one AEAD tag short.
        let mut too_small = vec![0u8; packet.len()];
        assert!(matches!(
            their_tun.decapsulate(None, &sent, &mut too_small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));

        // ... and the datagram survives the refusal. The size check runs before
        // the replay counter is marked, so retrying with a real buffer works
        // rather than being rejected as a replay.
        let mut big = vec![0u8; 2048];
        match their_tun.decapsulate(None, &sent, &mut big) {
            TunnResult::WriteToTunnelV4(recv, _) => assert_eq!(&packet[..], recv),
            // Positional, not `{other:?}`: this crate is edition 2018, where a
            // single-argument `panic!` is not a format string and would print
            // the braces verbatim.
            other => panic!("expected the retry to be accepted, got {:?}", other),
        }
    }

    #[test]
    fn a_padded_keepalive_is_a_keepalive_not_an_invalid_packet() {
        // AmneziaWG's `content_padding_addition` appends zeros to the plaintext,
        // so a keepalive from such a peer arrives as a run of zero bytes rather
        // than as a zero-length payload. amneziawg-go accepts both forms; we used
        // to reject the padded one as InvalidPacket, which makes the device layer
        // skip the endpoint update for a roaming peer and log one line per
        // keepalive.
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];
        let mut their_dst = vec![0u8; 2048];

        // 0 is the unpadded form: it pins the empty-plaintext case that the
        // padded one now shares a branch with, so neither can be removed alone.
        for pad in [0usize, 1, 16, 100] {
            let padded_keepalive = vec![0u8; pad];
            let sent = unwrap_network_packet(my_tun.encapsulate(&padded_keepalive, &mut dst));

            match their_tun.decapsulate(None, &sent, &mut their_dst) {
                TunnResult::Done => {}
                // Positional, not `{pad}`/`{other:?}`: this crate is edition
                // 2018, where the single-argument `panic!` next door would print
                // the braces verbatim. Keeping every message in one style is what
                // stops the broken arity from being reintroduced by copy-paste.
                other => panic!(
                    "a {}-byte padded keepalive must be Done, got {:?}",
                    pad, other
                ),
            }
        }

        // The actual new semantic: acceptance keys on the FIRST BYTE, not on the
        // plaintext being all zeros. amneziawg-go does the same
        // (`len(packet) == 0 || packet[0] == 0`), and matching it is the point --
        // narrowing this to `iter().all(|b| b == 0)` would reject a padded
        // keepalive from any implementation whose padding is not zero-filled,
        // restoring the roaming-endpoint bug this PR exists to fix. Nothing
        // pinned that until now: the narrowing left the whole suite green.
        let mut zero_prefixed = vec![0u8; 1];
        zero_prefixed.extend_from_slice(&[0x45, 0x00, 0x14]);
        let sent = unwrap_network_packet(my_tun.encapsulate(&zero_prefixed, &mut dst));
        assert!(
            matches!(
                their_tun.decapsulate(None, &sent, &mut their_dst),
                TunnResult::Done
            ),
            "a plaintext whose first byte is zero must be a keepalive even when \
             later bytes are not"
        );

        // The shape padding actually produces for *data*: a real packet with the
        // zeros appended. The IPv4 total-length field, not the plaintext length,
        // decides what reaches the tunnel, so the padding has to be trimmed --
        // neither delivered to the interface nor grounds for rejecting the
        // packet. This is the half of padding tolerance that the keepalive cases
        // above do not exercise, since a keepalive declares no length.
        let packet = create_ipv4_udp_packet();
        let mut padded = packet.clone();
        padded.extend_from_slice(&[0u8; 16]);
        let sent = unwrap_network_packet(my_tun.encapsulate(&padded, &mut dst));
        match their_tun.decapsulate(None, &sent, &mut their_dst) {
            TunnResult::WriteToTunnelV4(recv, _) => assert_eq!(&packet[..], recv),
            other => panic!("a padded IPv4 packet must arrive trimmed, got {:?}", other),
        }
    }

    #[test]
    fn an_ipv4_total_length_below_the_header_size_is_rejected_not_truncated() {
        // The total-length field covers the header, so anything under 20 is not a
        // packet. Only the upper bound was checked, so these truncated to
        // `packet[..computed_len]` and were handed to the tun device as a runt --
        // an empty write for a total length of 0 -- while `rx_bytes` was credited
        // with the field rather than the bytes actually received. Reaching this
        // needs a peer that completed the handshake, so it is a malicious- or
        // buggy-peer case, not a remote one; wireguard-go rejects it too
        // (`int(length) < ipv4.HeaderLen`).
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut dst = vec![0u8; 2048];
        let mut their_dst = vec![0u8; 2048];

        for bogus_total_len in [0u16, 1, IPV4_MIN_HEADER_SIZE as u16 - 1] {
            let mut runt = create_ipv4_udp_packet();
            runt[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                .copy_from_slice(&bogus_total_len.to_be_bytes());
            let sent = unwrap_network_packet(my_tun.encapsulate(&runt, &mut dst));

            match their_tun.decapsulate(None, &sent, &mut their_dst) {
                TunnResult::Err(WireGuardError::InvalidPacket) => {}
                other => panic!(
                    "an IPv4 total length of {} must be InvalidPacket, got {:?}",
                    bogus_total_len, other
                ),
            }
        }

        // The smallest total length that does describe a packet still works, so
        // the new bound rejects only what it must.
        let mut minimal = create_ipv4_udp_packet();
        minimal[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
            .copy_from_slice(&(IPV4_MIN_HEADER_SIZE as u16).to_be_bytes());
        let sent = unwrap_network_packet(my_tun.encapsulate(&minimal, &mut dst));
        match their_tun.decapsulate(None, &sent, &mut their_dst) {
            TunnResult::WriteToTunnelV4(recv, _) => {
                assert_eq!(recv.len(), IPV4_MIN_HEADER_SIZE)
            }
            other => panic!(
                "a total length of exactly the header size must be accepted, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn handshake_response_with_a_short_dst_errors_and_stays_retryable() {
        // A dst that comfortably held the 148-byte initiation, but not the
        // 32-byte keepalive the response path emits on the way to a session.
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);

        let mut too_small = vec![0u8; DATA_OVERHEAD_SZ - 1];
        assert!(matches!(
            my_tun.decapsulate(None, &resp, &mut too_small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));

        // The refusal must not have consumed the response.
        // `receive_handshake_response` clears the handshake state, and the
        // session is not stored until after the keepalive is formatted -- so an
        // error raised between those two points destroys a perfectly good
        // handshake, and the retry below comes back as UnexpectedPacket
        // instead. An error a caller cannot recover from is barely better than
        // the panic this replaced.
        let mut dst = vec![0u8; 2048];
        let keepalive = unwrap_network_packet(my_tun.decapsulate(None, &resp, &mut dst));
        assert_eq!(keepalive.len(), DATA_OVERHEAD_SZ);
    }

    #[test]
    fn update_timers_errors_when_dst_cannot_hold_a_keepalive() {
        // The nastiest shape of the original defect: identical calls with
        // identical arguments return Done, until a persistent keepalive falls
        // due and the same call reaches the formatter. Nothing the caller can
        // inspect beforehand tells the two apart, so this could not be fixed by
        // validating arguments at the FFI boundary.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake_with_keepalive(Some(1));
        let mut small = vec![0u8; DATA_OVERHEAD_SZ - 1];

        assert!(matches!(my_tun.update_timers(&mut small), TunnResult::Done));

        advance_past_pacing_gate(Duration::from_millis(1100));
        assert!(matches!(
            my_tun.update_timers(&mut small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }

    #[test]
    fn a_rejected_amnezia_encapsulate_does_not_advance_the_nonce() {
        // The S4 form of the same rule, and the reason the preflight lives in
        // `encapsulate` rather than in `format_packet_data`: the formatter
        // bounds only the base frame and then advances the counter, while the
        // S4 prefix is added afterwards by `write_to_network`. A dst between
        // those two sizes burned one nonce per rejected call.
        const S4: usize = 600;
        let (mut my_tun, _their_tun) =
            create_two_tuns_and_handshake_with_amnezia(AmneziaConfig::new(0, 0, 0, S4 as u16));
        let packet = create_ipv4_udp_packet();
        let exact = packet.len() + DATA_OVERHEAD_SZ + S4;

        let mut roomy = vec![0u8; 2048];
        let first = unwrap_network_packet(my_tun.encapsulate(&packet, &mut roomy));
        // The emitted datagram carries the S4 prefix, so the WireGuard frame --
        // and the counter inside it -- begins S4 bytes in.
        let before = counter_of(&first[S4..]);

        let mut in_the_window = vec![0u8; exact - 1];
        for _ in 0..8 {
            assert!(matches!(
                my_tun.encapsulate(&packet, &mut in_the_window),
                TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
            ));
        }

        // The boundary pinned from below too: an off-by-one preflight would
        // satisfy every assertion above while rejecting a valid send.
        let mut at_the_boundary = vec![0u8; exact];
        let next = unwrap_network_packet(my_tun.encapsulate(&packet, &mut at_the_boundary));
        assert_eq!(next.len(), exact);
        assert_eq!(
            counter_of(&next[S4..]),
            before + 1,
            "eight rejected calls advanced the nonce"
        );
    }

    #[test]
    fn handshake_response_with_a_short_dst_stays_retryable_under_amnezia() {
        // As the non-Amnezia case, but the requirement is DATA_OVERHEAD_SZ + S4.
        // Preflighting only the base frame let a dst in between consume the
        // response and then fail, losing the keepalive for good.
        const S4: usize = 64;
        let (mut my_tun, mut their_tun) =
            create_two_tuns_with_amnezia(AmneziaConfig::new(0, 0, 0, S4 as u16));
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);

        let mut too_small = vec![0u8; DATA_OVERHEAD_SZ + S4 - 1];
        assert!(matches!(
            my_tun.decapsulate(None, &resp, &mut too_small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));

        // Exactly enough, and the same response: this asserts both that the
        // preflight is not off by one and that the refusal did not consume it.
        let mut exact = vec![0u8; DATA_OVERHEAD_SZ + S4];
        let keepalive = unwrap_network_packet(my_tun.decapsulate(None, &resp, &mut exact));
        assert_eq!(keepalive.len(), DATA_OVERHEAD_SZ + S4);
    }

    #[test]
    fn encapsulate_without_a_session_is_not_gated_on_the_transport_size() {
        // The preflight belongs to the established-session branch alone. With
        // no session, `encapsulate` emits a 148-byte handshake initiation and
        // queues the packet for retry -- neither of which has anything to do
        // with src.len() or S4. Hoisting the preflight out of that branch would
        // fail this call, leave the tunnel unable to come up at all, and drop
        // the packet instead of queueing it.
        //
        // This is here because the rest of the suite does not notice that
        // mistake: every other test passes with the preflight hoisted.
        const S4: usize = 4000;
        let (mut my_tun, _their_tun) =
            create_two_tuns_with_amnezia(AmneziaConfig::new(0, 0, 0, S4 as u16));
        let packet = create_ipv4_udp_packet();

        // The buffer every other test here uses, and far short of the
        // src.len() + DATA_OVERHEAD_SZ + S4 a transport packet would need.
        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            my_tun.packet_queue.len(),
            1,
            "the packet must be queued for retry, not dropped"
        );
    }

    /// A junk prefix too short to hold a nonce is refused at construction.
    ///
    /// Header protection reads its nonce out of the junk prefix, so with S below
    /// `NONCE_SIZE` every outbound packet is refused for the life of the tunnel.
    /// That used to surface at send time as `DestinationBufferTooSmall`, which
    /// points a library consumer at a buffer that was never the problem -- and
    /// it is reachable from the public API alone, not just from the UAPI where
    /// `validate` would have caught it.
    #[test]
    fn a_prefix_too_short_to_nonce_is_refused_at_construction() {
        const KEY: [u8; 32] = [0x5a; 32];
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let public = x25519::PublicKey::from(&secret);

        // S1 = 0 with a key set: no nonce can ever be taken from it.
        let broken = AmneziaConfig::new(0, 130, 110, 80).with_header_protection(KEY);
        let err = match Tunn::new_with_obfuscation(
            secret.clone(),
            public,
            None,
            None,
            100,
            None,
            Default::default(),
            broken,
        ) {
            Ok(_) => panic!("a config that can never emit a datagram was accepted"),
            Err(e) => e,
        };
        assert!(
            err.contains("S1") && err.contains("nonce"),
            "the error must name the offending S size: {}",
            err
        );

        // The same sizes without a key are fine -- the rule is conditional on
        // header protection being on, which is also what upstream does.
        assert!(
            Tunn::new_with_obfuscation(
                secret,
                public,
                None,
                None,
                100,
                None,
                Default::default(),
                AmneziaConfig::new(0, 130, 110, 80),
            )
            .is_ok(),
            "the nonce rule must not fire when no key is set"
        );
    }

    /// The guard measures the datagram in hand, not the initiation it assumes.
    ///
    /// A cookie is demanded for a handshake **response** as well as an
    /// initiation (`RateLimiter::verify_packet` matches both), and a response is
    /// `HANDSHAKE_RESP_SZ + S2` on the wire -- 56 bytes shorter than an
    /// initiation before any prefix. So a reply that attenuates against an
    /// initiation can still amplify against a response, and the sibling test
    /// above cannot see it: every case there provokes with an initiation and
    /// sets S2 = 0.
    ///
    /// This is not hypothetical coverage. Replacing the guard's `wire_len` with
    /// `HANDSHAKE_INIT_SZ + S1` -- the shape someone writes when they picture
    /// only the initiation path -- leaves every case of the sibling test green,
    /// and is killed here.
    #[test]
    fn the_response_bound_is_measured_against_the_response() {
        // S1 = 120, S3 = 100: a 164-byte reply. Against the initiation
        // (148 + 120 = 268) it attenuates, so the initiation-only view says
        // "send". Against the response it is the S2 that decides.
        //
        // (S2, must the reply be suppressed, what the sizes mean)
        let cases = [
            (
                0u16,
                true,
                "amplifying: 164-byte reply to a 92-byte response",
            ),
            (
                200,
                false,
                "attenuating: 164-byte reply to a 292-byte response",
            ),
            (100, false, "parity: 164-byte reply to a 164-byte response"),
        ];
        for (s2, expect_suppressed, label) in cases {
            // The *initiator* is starved here, so it is the one that demands a
            // cookie -- for the response its peer sends back.
            let (mut my_tun, mut their_tun) = cookie_provoking_pair_with_budgets(
                AmneziaConfig::new(120, s2, 100, 0),
                Some(0),
                None,
            );

            let mut dst = vec![0u8; 2048];
            let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));

            let src = Some(std::net::IpAddr::from([10, 0, 0, 1]));
            let mut their_dst = vec![0u8; 2048];
            let response =
                unwrap_network_packet(their_tun.decapsulate(src, &init, &mut their_dst)).to_vec();
            assert_eq!(
                response.len(),
                HANDSHAKE_RESP_SZ + s2 as usize,
                "sanity: the provoking packet must be a response: {}",
                label
            );

            let mut my_dst = vec![0u8; 2048];
            let result = my_tun.decapsulate(src, &response, &mut my_dst);

            let reply_len = COOKIE_REPLY_SZ + 100;
            assert_eq!(
                expect_suppressed,
                reply_len > response.len(),
                "the case table's own arithmetic disagrees with its expectation: {}",
                label
            );
            // And the initiation view really would disagree, or this test is
            // not covering the thing it says it covers.
            assert!(
                reply_len <= init.len(),
                "sanity: this reply must attenuate against the initiation,                  or the sibling test would already catch the mutation: {}",
                label
            );

            if expect_suppressed {
                assert!(
                    matches!(result, TunnResult::Done),
                    "{}: the reply must be suppressed, got {:?}",
                    label,
                    result
                );
            } else {
                let cookie = match result {
                    TunnResult::WriteToNetwork(c) => c,
                    other => panic!("{}: the cookie must still be sent, got {:?}", label, other),
                };
                assert_eq!(cookie.len(), reply_len, "{}", label);
            }
        }
    }

    /// An initiator and a responder sharing `amnezia`, the responder's rate
    /// limiter opened with a zero budget.
    ///
    /// Budget zero means the first handshake message the responder sees is
    /// already "under load", so it draws a cookie reply instead of being
    /// processed -- which is the only way to reach the cookie arm of
    /// `decapsulate` without flooding, and why the tests that use this cannot
    /// flake. Three of them need exactly this pair and differ only in the
    /// config, so it is written once.
    fn cookie_provoking_pair(amnezia: AmneziaConfig) -> (Tunn, Tunn) {
        cookie_provoking_pair_with_budgets(amnezia, None, Some(0))
    }

    /// The same pair with either end's rate-limit budget chosen.
    ///
    /// `None` is the ordinary `PEER_HANDSHAKE_RATE_LIMIT`; `Some(0)` makes that
    /// end treat its first handshake message as already under load. Which end
    /// is starved decides *which packet kind* provokes the cookie, and that is
    /// the whole point of having this knob: starving the responder provokes a
    /// reply to an **initiation** (`HANDSHAKE_INIT_SZ + S1` on the wire),
    /// starving the initiator provokes one to a **response**
    /// (`HANDSHAKE_RESP_SZ + S2`). A guard that compared against the initiation
    /// bound instead of the datagram in hand passes every initiation-provoked
    /// test, so the second shape is not redundant coverage -- it is the only
    /// thing that distinguishes the two.
    fn cookie_provoking_pair_with_budgets(
        amnezia: AmneziaConfig,
        my_budget: Option<u64>,
        their_budget: Option<u64>,
    ) -> (Tunn, Tunn) {
        let my_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let my_public = x25519::PublicKey::from(&my_secret);
        let their_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let their_public = x25519::PublicKey::from(&their_secret);

        let my_tun = Tunn::new_with_obfuscation(
            my_secret,
            their_public,
            None,
            None,
            100,
            my_budget.map(|b| Arc::new(RateLimiter::new(&my_public, b))),
            Default::default(),
            amnezia.clone(),
        )
        .unwrap();
        let their_tun = Tunn::new_with_obfuscation(
            their_secret,
            my_public,
            None,
            None,
            101,
            their_budget.map(|b| Arc::new(RateLimiter::new(&their_public, b))),
            Default::default(),
            amnezia,
        )
        .unwrap();
        (my_tun, their_tun)
    }

    /// A cookie reply the caller's buffer cannot hold is an error, not a panic.
    ///
    /// `decapsulate` is reachable through `extern "C"` entry points, where a
    /// panic cannot unwind and the FFI panic hook turns it into `raise(SIGSEGV)`
    /// -- so the difference between these two outcomes is a host process that
    /// keeps running and one that does not. Every other short-buffer exit in
    /// `decapsulate` already reports `DestinationBufferTooSmall`; this arm did
    /// not, and panicked with "range end index 64 out of range for slice of
    /// length 32" instead.
    ///
    /// S3 = 0, so the amplification guard above does not claim the return
    /// first: this has to reach the copy to test anything.
    #[test]
    fn a_cookie_reply_that_does_not_fit_the_destination_is_an_error() {
        let (mut my_tun, mut their_tun) = cookie_provoking_pair(AmneziaConfig::default());

        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));

        let src = Some(std::net::IpAddr::from([10, 0, 0, 1]));
        let mut too_small = vec![0u8; COOKIE_REPLY_SZ - 1];
        assert!(
            matches!(
                their_tun.decapsulate(src, &init, &mut too_small),
                TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
            ),
            "a destination too small for the cookie reply must be reported, not panicked on"
        );

        // And a buffer that is exactly big enough still gets the reply, or the
        // check above could be refusing everything.
        let mut exact = vec![0u8; COOKIE_REPLY_SZ];
        let cookie = unwrap_network_packet(their_tun.decapsulate(src, &init, &mut exact));
        assert_eq!(cookie.len(), COOKIE_REPLY_SZ);
    }

    /// A `Tunn` refuses to emit a cookie reply larger than the packet that
    /// provoked it, whoever built the tunnel and however it is driven.
    ///
    /// This is the guard at the emit site itself, and it exists because every
    /// other defence is positional. The config-time complaint is refused only
    /// on the device's `set=1` door and deliberately *accepted* by the C
    /// constructors (a client is handed S3 by its server); the device's
    /// `reply_policy::cookie_verdict` runs only on the device's own ingress
    /// path; and the C ABI is safe only because `wireguard_read` passes no
    /// source address. None of that protects a Rust embedder calling
    /// `decapsulate(Some(addr), ..)` -- which is public API -- or a future
    /// address-carrying FFI read. This does: the comparison is wire length
    /// against wire length, the same parity rule `cookie_verdict` applies, so
    /// an amplifying configuration can exist without an amplifying *port*
    /// existing anywhere.
    ///
    /// Three shapes: an amplifying reply is suppressed, an attenuating reply
    /// still goes out (the guard is not a blanket drop of WireGuard's flood
    /// defence), and exact parity still goes out (the bound is `>`, matching
    /// `cookie_verdict` -- at parity reflection gains an attacker nothing).
    ///
    /// A limiter with a zero budget forces the cookie on the first message, so
    /// this needs no flooding and cannot flake.
    #[test]
    fn an_amplifying_cookie_reply_is_suppressed_at_the_emit_site() {
        // (S1, S3, must the reply be suppressed, what the sizes mean). The
        // provoking packet is an initiation of HANDSHAKE_INIT_SZ + S1 wire
        // bytes; the reply would be COOKIE_REPLY_SZ + S3.
        //
        // The expectation is declared per case, not recomputed from the sizes:
        // with `if reply_len > init.len()` deciding which assertion runs, moving
        // one S3 during a refactor could drop every case into the "must be sent"
        // branch and the suppression assertion would stop executing without any
        // test going red.
        let cases = [
            (
                0u16,
                100u16,
                true,
                "amplifying: 164-byte reply to a 148-byte packet",
            ),
            (
                120,
                110,
                false,
                "attenuating: 174-byte reply to a 268-byte packet",
            ),
            (0, 84, false, "parity: 148-byte reply to a 148-byte packet"),
        ];
        for (s1, s3, expect_suppressed, label) in cases {
            let (mut my_tun, mut their_tun) =
                cookie_provoking_pair(AmneziaConfig::new(s1, 0, s3, 0));

            let mut dst = vec![0u8; 2048];
            let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
            assert_eq!(
                init.len(),
                HANDSHAKE_INIT_SZ + s1 as usize,
                "sanity: {}",
                label
            );

            let src = Some(std::net::IpAddr::from([10, 0, 0, 1]));
            let mut their_dst = vec![0u8; 2048];
            let result = their_tun.decapsulate(src, &init, &mut their_dst);

            // Named from the constants, not from 64 and 148, so a change to
            // either wire size is caught here rather than in the field -- the
            // reason `packet_sizes` exists for the `device` tests.
            let reply_len = COOKIE_REPLY_SZ + s3 as usize;
            assert_eq!(
                expect_suppressed,
                reply_len > init.len(),
                "the case table's own arithmetic disagrees with its expectation: {}",
                label
            );
            if expect_suppressed {
                assert!(
                    matches!(result, TunnResult::Done),
                    "{}: the reply must be suppressed, got {:?}",
                    label,
                    result
                );
            } else {
                let cookie = match result {
                    TunnResult::WriteToNetwork(c) => c,
                    other => panic!("{}: the cookie must still be sent, got {:?}", label, other),
                };
                assert_eq!(cookie.len(), reply_len, "{}", label);
            }
        }
    }

    /// A cookie reply must round-trip masked too.
    ///
    /// It is the fourth packet kind and the one the handshake round-trip above
    /// cannot reach: cookies come out of the rate limiter under load, not the
    /// handshake formatter. It also takes different rows in the masking code --
    /// its own S3 prefix and its own H3 tag range -- and `masked_len` covers the
    /// whole 64-byte message rather than the 16-byte transport header, so none
    /// of the other kinds exercises that combination.
    ///
    /// A limiter with a zero budget forces the reply on the first message, so
    /// this needs no flooding and cannot flake.
    #[test]
    fn header_protection_round_trips_a_cookie_reply() {
        const KEY: [u8; 32] = [0x5a; 32];
        let (mut my_tun, mut their_tun) = cookie_provoking_pair(
            AmneziaConfig::new(120, 130, 110, 80).with_header_protection(KEY),
        );

        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));

        let src = Some(std::net::IpAddr::from([10, 0, 0, 1]));
        let mut their_dst = vec![0u8; 2048];
        let cookie = unwrap_network_packet(their_tun.decapsulate(src, &init, &mut their_dst));

        // S3 is the cookie prefix, so 110 -- not S1.
        assert_eq!(
            cookie.len(),
            110 + COOKIE_REPLY_SZ,
            "the reply must carry the S3 prefix"
        );

        // The tag on the wire must NOT be in the H3 range: if it were, the whole
        // reply went out unmasked and this test would pass vacuously.
        let obf = my_tun.handshake.obf;
        let wire_tag = u32::from_le_bytes(cookie[110..114].try_into().unwrap());
        assert!(
            !obf.matches_h3(wire_tag),
            "the cookie tag is still range-matchable on the wire, so nothing was masked"
        );

        // And the initiator must be able to consume it: a cookie it cannot
        // unmask is a handshake that never completes under load.
        let mut my_dst = vec![0u8; 2048];
        match my_tun.decapsulate(None, &cookie, &mut my_dst) {
            TunnResult::Done => {}
            other => panic!("expected the cookie to be accepted, got {:?}", other),
        }
        assert!(
            my_tun.handshake.has_cookie(),
            "mac2 must be derived from the cookie the responder sent"
        );
    }

    /// Header protection, end to end through the real state machine.
    ///
    /// The unit tests in `header_protection` prove the cipher round-trips a
    /// buffer. This proves the whole path lines up: masked at the right offset
    /// for the right length on the three kinds this test exchanges -- an
    /// initiation, a response, and transport data (the post-handshake keepalive
    /// and one payload packet) -- unmasked before the H1-H4 range test, and the
    /// keystream consumed contiguously across the type field and the body. Any
    /// of those wrong and the handshake never completes.
    ///
    /// The fourth kind does not cross *this* test: a cookie reply leaves the
    /// rate limiter under load, not the handshake formatter, and two handshake
    /// messages per tunnel never approach `PEER_HANDSHAKE_RATE_LIMIT`. It has
    /// its own round trip in `header_protection_round_trips_a_cookie_reply`.
    #[test]
    fn header_protection_round_trips_a_handshake_and_data() {
        const KEY: [u8; 32] = [0x5a; 32];
        // Every S at or above the 12-byte nonce minimum.
        let amnezia = AmneziaConfig::new(120, 130, 110, 80).with_header_protection(KEY);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);

        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));

        // The tag on the wire must NOT be in the H4 range -- if it were, the
        // masking would not have happened and this test would pass vacuously.
        let obf = my_tun.handshake.obf;
        let wire_tag = u32::from_le_bytes(sent[80..84].try_into().unwrap());
        assert!(
            !obf.matches_h4(wire_tag),
            "the transport tag is still range-matchable on the wire, so nothing was masked"
        );

        let mut their_dst = vec![0u8; 2048];
        match their_tun.decapsulate(None, &sent, &mut their_dst) {
            TunnResult::WriteToTunnelV4(recv, _) => assert_eq!(&packet[..], recv),
            other => panic!("expected the packet to arrive, got {:?}", other),
        }
    }

    /// The non-vacuity control for the round-trip test above: it proves the
    /// bytes on the wire are actually masked.
    ///
    /// Asserted at the classifier seam rather than through a handshake. The
    /// first version of this test built its two tunnels from two independent
    /// keypair generations and asserted only `TunnResult::Err(_)`, so mac1
    /// failed on the receiver whatever the masking did -- it passed with
    /// `masked_len` forced to 0, i.e. with masking a complete no-op, which is
    /// the one thing it existed to rule out.
    #[test]
    fn a_mismatched_header_protection_key_does_not_interoperate() {
        let protected = AmneziaConfig::new(120, 130, 110, 80).with_header_protection([0x5a; 32]);
        let unprotected = AmneziaConfig::new(120, 130, 110, 80);
        let wrong_key = AmneziaConfig::new(120, 130, 110, 80).with_header_protection([0xa5; 32]);

        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(protected.clone());
        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        let obf = my_tun.handshake.obf;

        // A receiver with no key range-tests the tag raw. If it matches, the
        // initiation went out unmasked and the feature did nothing.
        assert!(
            unprotected.strip_inbound(obf, &init).is_none(),
            "an unprotected receiver classified a protected initiation, so nothing was masked"
        );

        // The wrong key derives the wrong keystream, so the tag still misses.
        let mut buf = init.clone();
        assert!(
            wrong_key
                .unmask_and_classify_inbound(obf, &mut buf)
                .is_none(),
            "the wrong key must not unmask"
        );

        // ... and the matching key recovers it, at the S1 offset.
        let mut buf = init.clone();
        assert_eq!(
            protected.unmask_and_classify_inbound(obf, &mut buf),
            Some(120),
            "the matching key must unmask and report the S1 junk offset"
        );
    }

    /// A datagram the header-protection classifier rejects must be handed back
    /// byte-for-byte unchanged, because the caller passes it on to probe
    /// detection. The type-field XOR happens in place, so doing it before the
    /// body unmask can fail would corrupt four bytes of someone else's traffic.
    #[test]
    fn a_rejected_datagram_is_not_modified() {
        let cfg = AmneziaConfig::new(120, 130, 110, 80).with_header_protection([0x5a; 32]);
        let obf = ObfuscationRanges::default();

        // Not ours: right length for nothing, tag matches no range once unmasked.
        let original: Vec<u8> = (0..200u32).map(|i| (i * 7 + 1) as u8).collect();
        let mut buf = original.clone();
        assert_eq!(cfg.unmask_and_classify_inbound(obf, &mut buf), None);
        assert_eq!(buf, original, "a rejected datagram must be left untouched");
    }

    /// Header protection needs 12 bytes of prefix for its nonce, so a
    /// configuration that cannot supply one is refused rather than run
    /// unprotected -- an operator who set a key and got no masking would have
    /// no way to notice.
    /// A zero S size with header protection on must not emit in the clear.
    ///
    /// The constructors now refuse this configuration outright, so the only door
    /// left into it is `set_obfuscation`, which is public and infallible -- it
    /// takes an already-built `AmneziaConfig` and cannot report a problem. This
    /// is the backstop for that door. Refusing to send is the only safe answer:
    /// emitting unmasked is precisely what setting a key is meant to prevent,
    /// and the caller cannot tell it happened.
    #[test]
    fn a_zero_prefix_with_header_protection_refuses_rather_than_emitting_cleartext() {
        // S1 = 0, so the very first packet -- the handshake initiation -- has no
        // prefix and therefore no nonce. Using S4 instead would be a worse test:
        // it makes the tunnel unusable before a session exists, so the handshake
        // helper cannot even reach the assertion.
        let broken = AmneziaConfig::new(0, 130, 110, 80).with_header_protection([0x5a; 32]);
        assert!(
            broken.validate().is_err(),
            "precondition: validate must reject this, or the test proves nothing \
             about the path that bypasses it"
        );

        // Built valid, then switched to the broken config the way a live device
        // would -- this is the path no `Result` guards.
        let (mut my_tun, _their_tun) =
            create_two_tuns_with_amnezia(AmneziaConfig::new(120, 130, 110, 80));
        my_tun.set_obfuscation(Default::default(), broken);

        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];

        match my_tun.encapsulate(&packet, &mut dst) {
            TunnResult::Err(_) => {}
            TunnResult::WriteToNetwork(sent) => panic!(
                "emitted {} bytes with header protection on and no prefix to nonce it",
                sent.len()
            ),
            other => panic!("expected an error, got {:?}", other),
        }
    }

    #[test]
    fn header_protection_requires_every_s_to_hold_a_nonce() {
        let ok = AmneziaConfig::new(12, 12, 12, 12).with_header_protection([1u8; 32]);
        assert!(ok.validate().is_ok(), "12 bytes is exactly enough");

        // Every position, not just S1: the name says "every S", and pinning one
        // of them let a narrowing to S1-only pass. An S4 under the nonce length
        // is the nastiest of the four -- the handshake completes and then every
        // transport packet fails to send, so the tunnel is "up" and carries
        // nothing.
        //
        // S3 stays small in each case so the cookie-reply amplification rule --
        // a different check with a different reason -- cannot be what fails.
        // Exactly one size is under the nonce length in each case, and it is the
        // first one `validate` reaches -- otherwise the error would name an
        // earlier position and the assertion would pass for the wrong reason.
        for (label, sizes) in [
            ("S1", (11u16, 130u16, 12u16, 80u16)),
            ("S2", (120, 11, 12, 80)),
            ("S3", (120, 130, 11, 80)),
            ("S4", (120, 130, 12, 11)),
        ] {
            let too_small = AmneziaConfig::new(sizes.0, sizes.1, sizes.2, sizes.3)
                .with_header_protection([1u8; 32]);
            let err = too_small
                .validate()
                .expect_err("11 bytes cannot nonce a datagram");
            assert!(
                err.contains(label) && err.contains("header protection"),
                "the error must name {} and the reason: {}",
                label,
                err
            );
        }

        // ... and without a key the same sizes are fine, since nothing needs a
        // nonce. This is what keeps the rule scoped to header protection.
        assert!(AmneziaConfig::new(11, 130, 11, 80).validate().is_ok());
    }

    #[test]
    fn amnezia_encapsulate_errors_when_dst_cannot_hold_s4_prefix() {
        // Establish a session, then try to send into a buffer that comfortably
        // fits the base transport packet but not the configured 600-byte S4
        // prefix.
        let (mut my_tun, _their_tun) =
            create_two_tuns_and_handshake_with_amnezia(AmneziaConfig::new(0, 0, 0, 600));

        let sent_packet_buf = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 256];
        assert!(matches!(
            my_tun.encapsulate(&sent_packet_buf, &mut dst),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }

    #[test]
    fn amnezia_pre_handshake_junk_precedes_handshake_initiation() {
        let amnezia = AmneziaConfig::new(5, 0, 0, 0).with_pre_handshake_junk(2, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let junk1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert!((10..=20).contains(&junk1.len()));
        assert!(matches!(
            Tunn::parse_incoming_packet(my_tun.handshake.obf, &junk1),
            Err(WireGuardError::InvalidPacket)
        ));

        let junk2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((10..=20).contains(&junk2.len()));

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5);
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    #[test]
    fn set_preshared_key_treats_all_zero_as_absent() {
        // The handshake mixes `preshared_key.unwrap_or([0u8; 32])`, so an
        // all-zero key and `None` are the same key. wg clears a PSK by sending
        // 32 zero bytes, so this transition happens on ordinary reloads and
        // must not be mistaken for a key change.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(my_tun.sessions.iter().any(|s| s.is_some()));

        my_tun.set_preshared_key(Some([0u8; 32]));
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "None -> all-zero is not a key change and must keep sessions"
        );
        assert_eq!(
            my_tun.preshared_key(),
            Some([0u8; 32]),
            "the stored value must follow the caller, so `Peer`'s copy cannot disagree"
        );

        my_tun.set_preshared_key(None);
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "all-zero -> None must keep sessions too"
        );
        assert_eq!(my_tun.preshared_key(), None, "stored value follows back");

        // A genuine key still resets, since sessions derived under the old key
        // are cryptographically stale.
        my_tun.set_preshared_key(Some([7u8; 32]));
        assert!(
            my_tun.sessions.iter().all(|s| s.is_none()),
            "a real key change must discard sessions"
        );
    }

    #[test]
    fn set_obfuscation_reframes_without_dropping_sessions() {
        // H/S are interface-wide, so a live change has to reach every peer or
        // the peer frames packets the interface can no longer parse. It is a
        // framing change, not a cryptographic one, so sessions must survive.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        let new_obf = ObfuscationRanges::new(10, 20, 30, 40, 50, 60, 70, 80).unwrap();
        let new_amnezia = AmneziaConfig::new(3, 5, 7, 9);
        my_tun.set_obfuscation(new_obf, new_amnezia.clone());

        assert_eq!(my_tun.handshake.obf, new_obf, "tag ranges updated");
        assert_eq!(my_tun.amnezia, new_amnezia, "junk sizes updated");
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "reframing must not tear down established sessions"
        );

        // A handshake initiation now carries the new H1 tag and S1 prefix.
        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, true));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 3, "S1 = 3 applied");
        let tag = u32::from_le_bytes(init[3..7].try_into().unwrap());
        assert!((10..=20).contains(&tag), "H1 in new range, got {}", tag);
    }

    #[test]
    fn set_persistent_keepalive_updates_interval_without_dropping_sessions() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        my_tun.set_persistent_keepalive(Some(25));
        assert_eq!(my_tun.persistent_keepalive(), Some(25));
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "a keepalive change is a timer change; sessions must survive"
        );

        // None disables it, matching how Timers::new reads the same argument.
        my_tun.set_persistent_keepalive(None);
        assert_eq!(my_tun.persistent_keepalive(), None);
    }

    #[test]
    fn set_preshared_key_discards_sessions_only_when_it_actually_changes() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        // Re-applying the same value must not disturb live tunnels -- a config
        // reload re-sends every peer's block unchanged.
        let current = my_tun.preshared_key();
        my_tun.set_preshared_key(current);
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "unchanged key must not tear down sessions"
        );

        // A real change invalidates them: sessions derived under the old key are
        // cryptographically stale.
        my_tun.set_preshared_key(Some([7u8; 32]));
        assert_eq!(my_tun.preshared_key(), Some([7u8; 32]));
        assert!(
            my_tun.sessions.iter().all(|s| s.is_none()),
            "changed key must discard every session"
        );
    }

    #[test]
    fn amnezia_responder_skips_pre_handshake_but_keeps_padding() {
        // Same configuration as the test above, but adapted for a responder:
        // the initiation must come out immediately, with no junk datagrams
        // ahead of it, while S1 padding is still applied.
        let amnezia = AmneziaConfig::new(5, 0, 0, 0)
            .with_pre_handshake_junk(2, 10, 20, 0)
            .with_protocol_imitation(crate::noise::amnezia::AmneziaImitationProtocol::Quic, None)
            .as_responder();
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));

        assert_eq!(
            init.len(),
            HANDSHAKE_INIT_SZ + 5,
            "a responder emits the initiation directly, still S1-padded"
        );
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );
        // The imitation protocol is retained, so the padding is still
        // protocol-shaped rather than random: QUIC uses a 1-RTT short header.
        assert_eq!(init[0] & 0xc0, 0x40, "S1 padding keeps its QUIC shape");
    }

    #[test]
    fn amnezia_pending_junk_completes_after_expired_handshake_state() {
        let amnezia = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        my_tun.handshake.set_expired();

        let junk = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert!((10..=20).contains(&junk.len()));

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    #[test]
    fn amnezia_init_buffer_too_small_preserves_pending_without_junk_replay() {
        // S1 = 64 so the handshake initiation needs HANDSHAKE_INIT_SZ + 64 bytes,
        // while a single pre-handshake junk packet is only 10..=20 bytes.
        let amnezia = AmneziaConfig::new(64, 0, 0, 0).with_pre_handshake_junk(1, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut big = vec![0u8; 2048];

        // First call drains the single junk packet. Use the non-forced path
        // (the one `encapsulate` uses): the failed initiation below moves the
        // handshake into `InitSent`, and a non-forced retry must still re-emit
        // the initiation rather than returning `Done` and dropping it.
        let junk = unwrap_network_packet(my_tun.format_handshake_initiation(&mut big, false));
        assert!((10..=20).contains(&junk.len()));

        // Retry the (now due) initiation into a buffer that fits the base
        // WireGuard packet but not the S1 prefix: prepend_outbound must reject it
        // and the pending junk state must survive so we don't replay junk.
        let mut small = vec![0u8; HANDSHAKE_INIT_SZ + 16];
        assert!(matches!(
            my_tun.update_timers(&mut small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
        assert!(my_tun.pending_amnezia_junk.is_some());

        // Retrying with a large enough buffer emits the initiation directly,
        // without re-emitting any junk packets.
        let init = unwrap_network_packet(my_tun.update_timers(&mut big));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 64);
        assert_eq!(
            u32::from_le_bytes(init[64..68].try_into().unwrap()),
            HANDSHAKE_INIT
        );
        assert!(my_tun.pending_amnezia_junk.is_none());
    }

    #[test]
    fn amnezia_quic_browser_imitation_emits_chrome_initials_before_handshake() {
        let amnezia = AmneziaConfig::new(0, 0, 0, 0).with_protocol_imitation_browser(
            amnezia::AmneziaImitationProtocol::Quic,
            None,
            amnezia::AmneziaImitationBrowser::Chrome,
        );
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // Chrome opens with two QUIC Initials carrying the split ClientHello.
        let p1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(p1.len(), 1250);
        let p2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(p2.len(), 1250);

        // Then the real handshake initiation follows.
        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );

        // The two emitted datagrams reassemble to a real Chrome ClientHello.
        let fp = quic::fingerprint::fingerprint_of_packets(&[p1, p2]);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(fp.supported_groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(fp.alpn, vec!["h3".to_string()]);
        assert!(fp.sni.is_some(), "imitation carries a generated SNI");
    }

    #[test]
    fn amnezia_dns_sip_stun_imitation_emit_sequence_before_handshake() {
        use amnezia::AmneziaImitationProtocol as P;

        for (protocol, count) in [(P::Dns, 3usize), (P::Sip, 2), (P::Stun, 2)] {
            let amnezia = AmneziaConfig::new(0, 0, 0, 0)
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
            let mut dst = vec![0u8; 2048];

            let mut datagrams = vec![unwrap_network_packet(
                my_tun.format_handshake_initiation(&mut dst, false),
            )];
            // Sleep past the protocol-natural inter-datagram delays (max 20 ms).
            for _ in 1..count {
                advance_past_pacing_gate(Duration::from_millis(25));
                datagrams.push(unwrap_network_packet(my_tun.update_timers(&mut dst)));
            }
            assert_eq!(datagrams.len(), count, "protocol={protocol:?}");

            // The handshake initiation follows the imitation sequence.
            let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
            assert_eq!(init.len(), HANDSHAKE_INIT_SZ, "protocol={protocol:?}");
            assert_eq!(
                u32::from_le_bytes(init[..4].try_into().unwrap()),
                HANDSHAKE_INIT
            );

            // Spot-check the protocol shape of the first emitted datagram.
            match protocol {
                P::Dns => assert_eq!(&datagrams[0][2..4], &[0x01, 0x00], "DNS RD flag"),
                P::Stun => {
                    assert_eq!(&datagrams[0][0..2], &[0x00, 0x01], "STUN Binding Request");
                    assert_eq!(
                        &datagrams[0][4..8],
                        &[0x21, 0x12, 0xa4, 0x42],
                        "magic cookie"
                    );
                }
                P::Sip => assert!(datagrams[0].starts_with(b"INVITE sip:"), "SIP INVITE"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn amnezia_imitation_and_jc_junk_both_precede_handshake() {
        // wgbooster emits the imitation sequence AND the Jc random/protocol-shaped
        // junk before the handshake; Jc is not dropped when imitation is set.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(2, 28, 100, 0)
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Stun, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let mut datagrams = 0;
        let mut result = my_tun.format_handshake_initiation(&mut dst, false);
        loop {
            let pkt = unwrap_network_packet(result);
            if pkt.len() == HANDSHAKE_INIT_SZ
                && u32::from_le_bytes(pkt[..4].try_into().unwrap()) == HANDSHAKE_INIT
            {
                break;
            }
            datagrams += 1;
            assert!(datagrams <= 8, "imitation sequence did not terminate");
            advance_past_pacing_gate(Duration::from_millis(25));
            result = my_tun.update_timers(&mut dst);
        }
        // 2 STUN imitation packets + 2 Jc junk packets, then the initiation.
        assert_eq!(datagrams, 4);
    }

    #[test]
    fn amnezia_first_jc_packet_is_immediate_after_imitation_with_jd() {
        // wgbooster's delay-after model: the first send_random_packets() packet
        // is emitted immediately after the imitation sequence (no leading Jd),
        // and Jd only spaces the subsequent Jc packets.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(2, 28, 100, 150) // Jc=2, Jd=150ms
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Stun, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // Drain the two STUN imitation packets (second after its 15 ms delay).
        let s1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(&s1[0..2], &[0x00, 0x01], "STUN Binding Request");
        advance_past_pacing_gate(Duration::from_millis(20));
        let s2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(&s2[0..2], &[0x00, 0x01]);

        // The first Jc packet must be due *immediately* — no extra Jd wait.
        let j1 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((28..=100).contains(&j1.len()), "STUN-shaped Jc junk");

        // The second Jc packet, however, must wait Jd: an immediate poll is Done.
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
    }

    #[test]
    fn amnezia_pre_handshake_junk_uses_protocol_imitation() {
        // QUIC imitation (omitted browser -> curl) emits one full Initial, then
        // the Jc QUIC-shaped junk packet, then the handshake.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 10, 20, 0)
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Quic, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // curl QUIC Initial.
        let initial = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(initial.len(), 1250);
        assert_eq!(initial[0] & 0xc0, 0xc0);

        // Jc QUIC-shaped junk packet.
        let junk = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((1200..=1252).contains(&junk.len()));
        assert_eq!(junk[0] & 0xc0, 0xc0);

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    // ---- ObfuscationRanges unit tests ----

    use crate::noise::handshake::{ObfuscationRanges, TagRange};

    #[test]
    fn obf_default_mapping() {
        // (0,0) for all ranges yields default WG constants
        let obf = ObfuscationRanges::new(0, 0, 0, 0, 0, 0, 0, 0).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 1, end: 1 });
        assert_eq!(obf.h2_resp, TagRange { start: 2, end: 2 });
        assert_eq!(obf.h3_cookie, TagRange { start: 3, end: 3 });
        assert_eq!(obf.h4_data, TagRange { start: 4, end: 4 });
    }

    #[test]
    fn obf_fixed_mapping() {
        // start=end yields a single-element range
        let obf = ObfuscationRanges::new(10, 10, 20, 20, 30, 30, 40, 40).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 10, end: 10 });
        assert_eq!(obf.h2_resp, TagRange { start: 20, end: 20 });
        assert_eq!(obf.h3_cookie, TagRange { start: 30, end: 30 });
        assert_eq!(obf.h4_data, TagRange { start: 40, end: 40 });
    }

    #[test]
    fn obf_back_compat_single_value() {
        // (start, 0) where start != 0 => [start..=start]
        let obf = ObfuscationRanges::new(10, 0, 20, 0, 30, 0, 40, 0).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 10, end: 10 });
        assert_eq!(obf.h2_resp, TagRange { start: 20, end: 20 });
        assert_eq!(obf.h3_cookie, TagRange { start: 30, end: 30 });
        assert_eq!(obf.h4_data, TagRange { start: 40, end: 40 });
    }

    #[test]
    fn obf_overlap_detection() {
        // H1 [10..20] and H4 [20..30] overlap at boundary 20
        let result = ObfuscationRanges::new(10, 20, 100, 110, 200, 210, 20, 30);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("H1"), "Error should mention H1: {}", msg);
        assert!(msg.contains("H4"), "Error should mention H4: {}", msg);
        assert!(
            msg.contains("overlaps"),
            "Error should mention overlaps: {}",
            msg
        );
    }

    #[test]
    fn obf_overlap_detection_h2_h3() {
        let result = ObfuscationRanges::new(10, 20, 50, 60, 55, 65, 100, 110);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("H2"), "Error should mention H2: {}", msg);
        assert!(msg.contains("H3"), "Error should mention H3: {}", msg);
    }

    #[test]
    fn obf_start_greater_than_end() {
        let result = ObfuscationRanges::new(20, 10, 100, 110, 200, 210, 300, 310);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("H1"),
            "Error should identify range H1: {}",
            msg
        );
        assert!(msg.contains("start"), "Error should mention start: {}", msg);
    }

    #[test]
    fn obf_incoming_accept_reject() {
        let obf = ObfuscationRanges::new(10, 20, 30, 40, 50, 60, 70, 80).unwrap();

        // H1: packet with correct range and size should be accepted
        let mut init_packet = vec![0u8; HANDSHAKE_INIT_SZ];
        init_packet[0..4].copy_from_slice(&15u32.to_le_bytes()); // within [10..20]
        let result = Tunn::parse_incoming_packet(obf, &init_packet);
        assert!(matches!(result, Ok(Packet::HandshakeInit(_))));

        // H1: tag outside range but correct size should be rejected
        init_packet[0..4].copy_from_slice(&25u32.to_le_bytes()); // outside [10..20]
        let result = Tunn::parse_incoming_packet(obf, &init_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H2: packet with correct range and size
        let mut resp_packet = vec![0u8; HANDSHAKE_RESP_SZ];
        resp_packet[0..4].copy_from_slice(&35u32.to_le_bytes()); // within [30..40]
        let result = Tunn::parse_incoming_packet(obf, &resp_packet);
        assert!(matches!(result, Ok(Packet::HandshakeResponse(_))));

        // H2: tag outside range
        resp_packet[0..4].copy_from_slice(&45u32.to_le_bytes()); // outside [30..40]
        let result = Tunn::parse_incoming_packet(obf, &resp_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H3: cookie reply
        let mut cookie_packet = vec![0u8; COOKIE_REPLY_SZ];
        cookie_packet[0..4].copy_from_slice(&55u32.to_le_bytes()); // within [50..60]
        let result = Tunn::parse_incoming_packet(obf, &cookie_packet);
        assert!(matches!(result, Ok(Packet::PacketCookieReply(_))));

        cookie_packet[0..4].copy_from_slice(&65u32.to_le_bytes()); // outside [50..60]
        let result = Tunn::parse_incoming_packet(obf, &cookie_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H4: data packet (minimum size)
        let mut data_packet = vec![0u8; DATA_OVERHEAD_SZ];
        data_packet[0..4].copy_from_slice(&75u32.to_le_bytes()); // within [70..80]
        let result = Tunn::parse_incoming_packet(obf, &data_packet);
        assert!(matches!(result, Ok(Packet::PacketData(_))));

        data_packet[0..4].copy_from_slice(&85u32.to_le_bytes()); // outside [70..80]
        let result = Tunn::parse_incoming_packet(obf, &data_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));
    }

    #[test]
    fn obf_outgoing_random_within_bounds() {
        let obf = ObfuscationRanges::new(100, 200, 300, 400, 500, 600, 700, 800).unwrap();
        let mut rng = OsRng;
        for _ in 0..1000 {
            let v = obf.random_h1(&mut rng);
            assert!(
                (100..=200).contains(&v),
                "H1 random {} out of range [100..200]",
                v
            );
            let v = obf.random_h2(&mut rng);
            assert!(
                (300..=400).contains(&v),
                "H2 random {} out of range [300..400]",
                v
            );
            let v = obf.random_h3(&mut rng);
            assert!(
                (500..=600).contains(&v),
                "H3 random {} out of range [500..600]",
                v
            );
            let v = obf.random_h4(&mut rng);
            assert!(
                (700..=800).contains(&v),
                "H4 random {} out of range [700..800]",
                v
            );
        }
    }

    #[test]
    fn obf_fixed_range_random_is_constant() {
        let obf = ObfuscationRanges::new(42, 42, 99, 99, 7, 7, 13, 13).unwrap();
        let mut rng = OsRng;
        for _ in 0..100 {
            assert_eq!(obf.random_h1(&mut rng), 42);
            assert_eq!(obf.random_h2(&mut rng), 99);
            assert_eq!(obf.random_h3(&mut rng), 7);
            assert_eq!(obf.random_h4(&mut rng), 13);
        }
    }

    #[test]
    fn obf_ranges_handshake_roundtrip() {
        // Verify that tunnels with matching range config can handshake
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let mut my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
        )
        .unwrap();
        let mut their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
        )
        .unwrap();

        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);
    }

    #[test]
    fn obf_ranges_near_u32_max_random_within_bounds() {
        let h1_min = u32::MAX - 10;
        let h1_max = u32::MAX;
        let h2_min = u32::MAX - 30;
        let h2_max = u32::MAX - 21;
        let h3_min = u32::MAX - 50;
        let h3_max = u32::MAX - 41;
        let h4_min = u32::MAX - 70;
        let h4_max = u32::MAX - 61;
        let obf = ObfuscationRanges::new(
            h1_min, h1_max, h2_min, h2_max, h3_min, h3_max, h4_min, h4_max,
        )
        .unwrap();
        let mut rng = OsRng;
        for _ in 0..10_000 {
            let t1 = obf.random_h1(&mut rng);
            assert!(t1 >= h1_min && t1 <= h1_max);
            let t2 = obf.random_h2(&mut rng);
            assert!(t2 >= h2_min && t2 <= h2_max);
            let t3 = obf.random_h3(&mut rng);
            assert!(t3 >= h3_min && t3 <= h3_max);
            let t4 = obf.random_h4(&mut rng);
            assert!(t4 >= h4_min && t4 <= h4_max);
        }
    }

    #[test]
    fn obf_ranges_near_u32_max_overlap_rejected() {
        let h1_min = u32::MAX - 10;
        let h1_max = u32::MAX;
        let h2_min = u32::MAX - 5;
        let h2_max = u32::MAX - 1;
        let h3_min = u32::MAX - 30;
        let h3_max = u32::MAX - 21;
        let h4_min = u32::MAX - 50;
        let h4_max = u32::MAX - 41;
        let res = ObfuscationRanges::new(
            h1_min, h1_max, h2_min, h2_max, h3_min, h3_max, h4_min, h4_max,
        );
        assert!(res.is_err());
    }

    /// A content-padded data packet grows on the wire and round-trips intact.
    ///
    /// The peer trims by the IP length field, so the original bytes come back
    /// byte-for-byte across an untouched receive path. Padding is send-only.
    #[test]
    fn content_padding_grows_a_data_packet_and_round_trips() {
        // A wide, deterministic range and no MTU clamp (0), so a small packet is
        // always grown -- the packet is 32 bytes, far under any MTU.
        let amnezia =
            AmneziaConfig::new(120, 130, 110, 80).with_content_padding_addition(40, 80, 0);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);

        let packet = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 2048];
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst)).to_vec();

        // The wire datagram carries the padding: S4 + 16 header + plaintext(len +
        // pad) + 16 tag. With no padding it would be S4 + 32 + len; the added
        // 40..80 bytes must show.
        let unpadded = 80 + 32 + packet.len(); // S4 = 80
        assert!(
            sent.len() >= unpadded + 40,
            "wire len {} did not grow by the padding (unpadded {})",
            sent.len(),
            unpadded
        );

        let mut their_dst = vec![0u8; 2048];
        match their_tun.decapsulate(None, &sent, &mut their_dst) {
            TunnResult::WriteToTunnelV4(recv, _) => assert_eq!(&packet[..], recv),
            other => panic!("expected the padded packet to arrive, got {:?}", other),
        }
    }

    /// A padded keepalive is still classified as a keepalive by the peer.
    ///
    /// The zero-fill in `format_packet_data` is load-bearing: a non-zero trailer
    /// would be `InvalidPacket` at the receiver, breaking session establishment.
    #[test]
    fn a_content_padded_keepalive_is_still_a_keepalive() {
        let amnezia =
            AmneziaConfig::new(120, 130, 110, 80).with_content_padding_addition(40, 80, 0);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);

        // An empty encapsulate is a keepalive. The buffer is deliberately
        // dirty: the padding region must be zeroed by `format_packet_data`
        // itself, not inherited from a fresh allocation -- with a pre-zeroed
        // buffer, deleting the zero-fill leaves this test green while every
        // production caller that reuses buffers sends garbage trailers.
        let mut dst = vec![0xAA_u8; 2048];
        let sent = unwrap_network_packet(my_tun.encapsulate(&[], &mut dst)).to_vec();

        let mut their_dst = vec![0xAA_u8; 2048];
        match their_tun.decapsulate(None, &sent, &mut their_dst) {
            // A keepalive decapsulates to Done -- no tunnel write, no error.
            TunnResult::Done => {}
            other => panic!("a padded keepalive was not a keepalive: {:?}", other),
        }
    }

    /// Padding never eats the S4 headroom: with a dst that has no slack, the
    /// pad clamps to zero and the send still succeeds at the exact size.
    ///
    /// This is the `space` budget in `encapsulate` doing its job. A budget
    /// that forgets the junk prefix (`committed` without `transport_junk`)
    /// pads into the room the S4 prefix needs, and `write_to_network` then
    /// fails with `DestinationBufferTooSmall` *after* the sending counter
    /// advanced -- the burned-nonce regression
    /// `a_rejected_amnezia_encapsulate_does_not_advance_the_nonce` guards
    /// against, reintroduced only when padding is active.
    #[test]
    fn content_padding_clamps_to_zero_when_dst_has_no_slack() {
        const S4: usize = 64;
        let amnezia =
            AmneziaConfig::new(0, 0, 0, S4 as u16).with_content_padding_addition(40, 80, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);

        let packet = create_ipv4_udp_packet();
        let exact = packet.len() + DATA_OVERHEAD_SZ + S4;
        let mut dst = vec![0u8; exact];
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut dst));
        assert_eq!(
            sent.len(),
            exact,
            "no room means no padding, and the send must still succeed"
        );
    }

    /// The targeted MTU update moves the clamp and nothing else.
    ///
    /// `set_content_padding_mtu` exists so the device's once-a-second MTU
    /// refresh does not go through `set_obfuscation`, which discards any
    /// queued pre-handshake junk burst -- right when the operator changed the
    /// framing, wrong for a link property that moved under us. wg-quick sets
    /// the MTU after `wg setconf`, so the refresh lands precisely when the
    /// first handshake's burst is most likely in flight; this pins that the
    /// burst survives it.
    #[test]
    fn set_content_padding_mtu_updates_the_clamp_and_keeps_a_queued_burst() {
        let amnezia = AmneziaConfig::new(120, 130, 110, 80)
            .with_pre_handshake_junk(4, 64, 128, 0)
            .with_content_padding_addition(40, 80, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);

        // Start a handshake so a junk burst is queued and partially sent.
        let mut dst = vec![0u8; 2048];
        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(
            my_tun.pending_amnezia_junk.is_some(),
            "precondition: a burst must be in flight, or this test proves nothing"
        );

        my_tun.set_content_padding_mtu(1280);
        assert_eq!(my_tun.amnezia.content_padding_mtu, 1280);
        assert_eq!(
            my_tun.amnezia.content_padding_addition,
            (40, 80),
            "only the clamp may move"
        );
        assert!(
            my_tun.pending_amnezia_junk.is_some(),
            "an MTU refresh must not cost a mid-handshake peer its junk burst"
        );
    }

    /// A configured rekey_after_time governs the active rekey, not the
    /// classic constant.
    ///
    /// The tunable mirror of `new_handshake_after_two_mins`, at 30 seconds:
    /// the band is pinned from both sides -- one second before the drawn
    /// deadline nothing happens, one second after it the initiator rekeys,
    /// ninety seconds before REKEY_AFTER_TIME would have fired.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_configured_rekey_after_time_governs_the_active_rekey() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_after_time: (30, 30),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);
        let mut my_dst = [0u8; 2048];

        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));

        // A full data round trip, not a lone send: an unanswered data packet
        // arms the KEEPALIVE+REKEY_TIMEOUT new-handshake trigger at ~15s,
        // which would fire long before the 30-second deadline under test.
        let packet = create_ipv4_udp_packet();
        let mut their_dst = [0u8; 2048];
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut my_dst)).to_vec();
        assert!(matches!(
            their_tun.decapsulate(None, &sent, &mut their_dst),
            TunnResult::WriteToTunnelV4(..)
        ));
        let reply = unwrap_network_packet(their_tun.encapsulate(&packet, &mut their_dst)).to_vec();
        assert!(matches!(
            my_tun.decapsulate(None, &reply, &mut my_dst),
            TunnResult::WriteToTunnelV4(..)
        ));

        // 29 seconds into the session: not yet.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(28));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));

        // 31 seconds: past the configured deadline, far before the constant.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(2));
        update_timer_results_in_handshake(&mut my_tun);
    }

    /// A configured reject_after_time expires the session at its high end --
    /// the most permissive draw a re-picking peer could be running.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_configured_reject_after_time_expires_the_session() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_after_time: (40, 40),
            reject_after_time: (50, 60),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);
        let mut dst = [0u8; 2048];

        // 59 seconds: inside the high end, the session must survive.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(59));
        let _ = my_tun.update_timers(&mut dst);
        assert!(
            my_tun.time_since_last_handshake().is_some(),
            "session dropped before the reject high end"
        );

        // 61 seconds: past the high end, 119 seconds before the constant.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(2));
        let _ = my_tun.update_timers(&mut dst);
        assert!(
            my_tun.time_since_last_handshake().is_none(),
            "the tunable reject_after_time did not expire the session"
        );

        // 181 seconds: past reject-hi x 3, the key-zeroing window -- the
        // constant's would not fire until 540.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(120));
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
    }

    /// A configured max_handshake_attempts caps the number of initiations, and
    /// caps it at the same number amneziawg-go would send.
    ///
    /// Counted, not timed. `N = 3` buys five initiations: upstream's counter
    /// starts at zero, increments once per retransmission, and gives up only
    /// once it is *greater than* N, which its own log line reports as `N + 2`.
    /// The knob has to mean the same number of packets on both ends, so the
    /// off-by-two is reproduced rather than corrected -- an operator sharing
    /// one profile between a go peer and this one gets one behaviour.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_configured_attempt_count_gives_up_early() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            max_handshake_attempts: (3, 3),
            rekey_timeout: (2, 2),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = [0u8; 2048];

        // Initiation 1 of 5 starts the cycle.
        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));

        // Initiations 2..=5, each at the configured 2-second retransmission
        // interval -- a cadence the constant REKEY_TIMEOUT (5s) would not
        // produce, so these also pin that `rekey_timeout` is in force.
        for initiation in 2..=5 {
            mock_instant::thread_local::MockClock::advance(Duration::from_secs(3));
            assert!(
                matches!(
                    my_tun.update_timers(&mut dst),
                    TunnResult::WriteToNetwork(_)
                ),
                "initiation {} of 5 was not sent",
                initiation
            );
        }

        // The next retransmission deadline: the budget is spent, so the cycle
        // expires instead of sending a sixth initiation -- long before the
        // classic 18-initiation limit would have given up.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(3));
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
    }

    /// An untuned tunnel keeps the classic absolute give-up bound, even when
    /// the caller polls sparsely.
    ///
    /// Counting retransmissions measures nothing if `update_timers` is not
    /// called: one poll 100 seconds after the initiation used to expire the
    /// cycle, and under a count-only rule would instead send a retry and carry
    /// on. The device's 250ms poll hides it; the FFI callers, which drive this
    /// loop themselves, do not. A tunnel with no timer tunables set must
    /// behave exactly as it did before they existed.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn an_untuned_tunnel_expires_on_the_classic_window_under_sparse_polling() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let mut dst = [0u8; 2048];

        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));

        // A single poll, well past REKEY_ATTEMPT_TIME: expire, do not retry.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(100));
        assert!(
            matches!(
                my_tun.update_timers(&mut dst),
                TunnResult::Err(WireGuardError::ConnectionExpired)
            ),
            "a 100-second gap must expire an untuned cycle, not retransmit"
        );
    }

    /// A tuned tunnel is bounded by its count, not by the classic window.
    ///
    /// The mirror of the test above: with `max_handshake_attempts` set, the
    /// same sparse poll must retry rather than expire, because the operator
    /// asked for a budget rather than for 90 seconds.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_tuned_tunnel_is_bounded_by_its_count_not_the_classic_window() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            max_handshake_attempts: (6, 6),
            rekey_timeout: (2, 2),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = [0u8; 2048];

        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));

        mock_instant::thread_local::MockClock::advance(Duration::from_secs(100));
        assert!(
            matches!(
                my_tun.update_timers(&mut dst),
                TunnResult::WriteToNetwork(_)
            ),
            "a configured budget must survive a gap longer than REKEY_ATTEMPT_TIME"
        );
    }

    /// The two give-up paths say which one fired, and carry the numbers.
    ///
    /// They expire for different reasons -- an untuned tunnel on the classic
    /// 90-second window, a tuned one on its retransmission budget, at whatever
    /// time the draws reach it -- so one shared `REKEY_ATTEMPT_TIME` message
    /// would report a window for a cycle that never consulted one. An operator
    /// correlating a drop with their configuration reads this line.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn the_two_give_up_paths_are_distinguishable_in_the_log() {
        let _serialized = crate::tracing_test_lock();
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        #[derive(Default)]
        struct Captured {
            message: String,
            budget: Option<u64>,
        }
        impl Visit for Captured {
            fn record_u64(&mut self, field: &Field, value: u64) {
                if field.name() == "budget" {
                    self.budget = Some(value);
                }
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "message" {
                    self.message = value.to_owned();
                }
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" && self.message.is_empty() {
                    self.message = format!("{:?}", value);
                }
            }
        }
        struct Capture(Arc<Mutex<Vec<Captured>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut c = Captured::default();
                event.record(&mut c);
                self.0.lock().unwrap().push(c);
            }
        }

        let run = |amnezia: Option<AmneziaConfig>| -> Vec<Captured> {
            let events: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
            {
                let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&events)));
                tracing::subscriber::with_default(subscriber, || {
                    let (mut tun, _peer) = match amnezia {
                        Some(a) => create_two_tuns_with_amnezia(a),
                        None => create_two_tuns(),
                    };
                    let mut dst = [0u8; 2048];
                    assert!(matches!(
                        tun.format_handshake_initiation(&mut dst, false),
                        TunnResult::WriteToNetwork(_)
                    ));
                    // One long gap: the untuned tunnel expires on the window,
                    // the tuned one retries until its budget runs out.
                    for _ in 0..12 {
                        mock_instant::thread_local::MockClock::advance(Duration::from_secs(30));
                        if matches!(
                            tun.update_timers(&mut dst),
                            TunnResult::Err(WireGuardError::ConnectionExpired)
                        ) {
                            break;
                        }
                    }
                });
            }
            let captured = std::mem::take(&mut *events.lock().unwrap());
            captured
        };

        let untuned = run(None);
        assert!(
            untuned
                .iter()
                .any(|c| c.message.contains("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)")),
            "an untuned tunnel must report the window it expired on: {:?}",
            untuned.iter().map(|c| &c.message).collect::<Vec<_>>()
        );

        let tuned = run(Some(AmneziaConfig::default().with_tunable_timers(
            amnezia::AwgTimers {
                max_handshake_attempts: (2, 2),
                rekey_timeout: (7, 7),
                ..amnezia::AwgTimers::default()
            },
        )));
        let budget_line = tuned
            .iter()
            .find(|c| {
                c.message
                    .contains("CONNECTION_EXPIRED(MAX_HANDSHAKE_ATTEMPTS)")
            })
            .unwrap_or_else(|| {
                panic!(
                    "a tuned tunnel must report the budget it exhausted: {:?}",
                    tuned.iter().map(|c| &c.message).collect::<Vec<_>>()
                )
            });
        // N = 2 buys N + 1 retransmissions, and the line has to carry it.
        assert_eq!(budget_line.budget, Some(3));
        assert!(
            !tuned
                .iter()
                .any(|c| c.message.contains("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)")),
            "a tuned tunnel must not blame the classic window"
        );
    }

    /// An unrelated AmneziaWG edit must not disturb the cached timer draws.
    ///
    /// `set_obfuscation` is called for any AWG change -- an `s1`, a magic
    /// header, a padding range. Re-drawing on those would move an established
    /// session's rekey deadline and replace the in-flight cycle's
    /// retransmission budget, which is exactly the per-session and per-cycle
    /// latching the caches exist to provide.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn an_unrelated_obfuscation_change_leaves_the_timer_draws_alone() {
        let timers = amnezia::AwgTimers {
            rekey_after_time: (30, 90),
            keepalive_timeout: (3, 9),
            ..amnezia::AwgTimers::default()
        };
        let amnezia = AmneziaConfig::default().with_tunable_timers(timers);
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia.clone());

        let rekey_before = my_tun.timers.rekey_after_current;
        let refresh_before = my_tun.timers.refresh_receive_current;

        // Same timers, different S1: the draws must survive.
        let mut only_s1 = amnezia.clone();
        only_s1.init_packet_junk_size = 77;
        my_tun.set_obfuscation(my_tun.handshake.obf, only_s1);
        assert_eq!(
            (
                my_tun.timers.rekey_after_current,
                my_tun.timers.refresh_receive_current
            ),
            (rekey_before, refresh_before),
            "an s1 edit re-drew the session's rekey deadlines"
        );

        // A real timer edit does reach them. The ranges are wide and disjoint
        // from the old ones, so a redraw cannot coincidentally land on the
        // same value.
        let mut retuned = amnezia;
        retuned.timers.rekey_after_time = (500, 900);
        my_tun.set_obfuscation(my_tun.handshake.obf, retuned);
        assert_ne!(
            my_tun.timers.rekey_after_current, rekey_before,
            "a timer edit did not reach the session's rekey deadline"
        );
    }

    /// A wide `rekey_timeout` range must not eat the attempt budget.
    ///
    /// The give-up rule used to be a wall-clock window sized as `attempts x
    /// rekey_timeout.lo`, while each retransmission drew from the whole range.
    /// With `rekey_timeout = 1-20` that window is 18 seconds, which two or
    /// three draws exhaust, so the peer expired after a couple of initiations
    /// where every reference implementation sends eighteen. Counting attempts
    /// removes the race: retries are bounded by the count, whatever interval
    /// each one happens to draw.
    ///
    /// The range's high end is kept modest on purpose. The whole cycle still
    /// has to finish inside `keychain_expire() * 3` (540s at the default
    /// `reject_after_time`), which zeroes key material on its own schedule
    /// regardless of the handshake -- 17 retries of up to 21s stay under it.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_wide_retransmission_range_still_gets_its_full_attempt_budget() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_timeout: (1, 20),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = [0u8; 2048];

        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));

        // The classic count is 18 initiations: the first plus 17 retries. Step
        // past each drawn interval so every retry is actually due.
        for attempt in 2..=18 {
            let wait = my_tun.timers.retransmit_current;
            mock_instant::thread_local::MockClock::advance(wait + Duration::from_secs(1));
            assert!(
                matches!(
                    my_tun.update_timers(&mut dst),
                    TunnResult::WriteToNetwork(_)
                ),
                "attempt {} was cut short by the give-up rule",
                attempt
            );
        }

        // Only now is the budget spent.
        let wait = my_tun.timers.retransmit_current;
        mock_instant::thread_local::MockClock::advance(wait + Duration::from_secs(1));
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
    }

    /// A configured keepalive_timeout governs the passive keepalive.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_configured_keepalive_timeout_governs_the_passive_keepalive() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            keepalive_timeout: (3, 3),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];

        // One data packet mine -> theirs, a second after the handshake, so
        // their side owes a keepalive: the trigger needs
        // `data_packet_received > aut_packet_sent`, and at the handshake
        // instant both timestamps are equal. `timer_tick` stamps events with
        // the `TimeCurrent` of the *last* `update_timers` call (the device
        // runs it every 250ms; a test must run it by hand), so their clock
        // reference is refreshed before the packet lands.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        let packet = create_ipv4_udp_packet();
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut my_dst)).to_vec();
        assert!(matches!(
            their_tun.decapsulate(None, &sent, &mut their_dst),
            TunnResult::WriteToTunnelV4(..)
        ));

        // 2 seconds since their side last sent: not yet.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            their_tun.update_timers(&mut their_dst),
            TunnResult::Done
        ));

        // 4 seconds: past the configured 3, six seconds before the constant.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(2));
        assert!(matches!(
            their_tun.update_timers(&mut their_dst),
            TunnResult::WriteToNetwork(_)
        ));
    }

    /// A live `set_obfuscation` reaches the cached timer draws.
    ///
    /// The five deadlines other than key expiry are drawn where their timer
    /// arms, so a `set=1` on a running device would otherwise leave an
    /// established session on the *previous* configuration until its next
    /// handshake -- while `update_session_timers` already expires it on the
    /// new `reject_after_time`. This is not a hypothetical ordering: the
    /// assertion below failed before `set_obfuscation` re-drew, and the
    /// counterfactual (the same sequence with the short config present from
    /// construction) passed, so the stale draw was the whole difference.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_live_reconfiguration_reaches_the_cached_timer_draws() {
        // Session established under a long rekey age.
        let long = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_after_time: (100, 100),
            reject_after_time: (200, 200),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(long);
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];

        // A full round trip, so the on-send rekey trigger is armed and the
        // unanswered-data trigger is not (see the sibling tests).
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let packet = create_ipv4_udp_packet();
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut my_dst)).to_vec();
        assert!(matches!(
            their_tun.decapsulate(None, &sent, &mut their_dst),
            TunnResult::WriteToTunnelV4(..)
        ));
        let reply = unwrap_network_packet(their_tun.encapsulate(&packet, &mut their_dst)).to_vec();
        assert!(matches!(
            my_tun.decapsulate(None, &reply, &mut my_dst),
            TunnResult::WriteToTunnelV4(..)
        ));

        // The operator shortens the rekey age on the live tunnel.
        let short = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_after_time: (10, 10),
            reject_after_time: (200, 200),
            ..amnezia::AwgTimers::default()
        });
        let obf = my_tun.handshake.obf;
        my_tun.set_obfuscation(obf, short);

        // 21 seconds into the session: twice the new rekey age, a fifth of the
        // old one. It must be the handshake the new config asks for, not the
        // keepalive that also comes due around here.
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(20));
        let data = unwrap_network_packet(my_tun.update_timers(&mut my_dst));
        let parsed = Tunn::parse_incoming_packet(obf, &data).expect("a well-formed packet");
        assert!(
            matches!(parsed, Packet::HandshakeInit(_)),
            "a live reconfiguration must reach rekey_after_current, not leave \
             the session on the draw made under the previous configuration"
        );
    }

    /// Each armed deadline is ONE draw: the latch guards in `timer_tick` are
    /// what make it so.
    ///
    /// Without them every packet re-draws, and a deadline re-drawn against a
    /// 250ms poll fires near the low end of its range with high probability
    /// (first passage) instead of uniformly across it -- which is not the
    /// distribution a range configures, and puts the RNG on the per-packet
    /// data path besides. Upstream guards the same way (`timersDataReceived`
    /// mods `sendKeepalive` only `if !peer.timers.sendKeepalive.IsPending()`).
    ///
    /// Pinned from the observable side: a latched deadline must keep the value
    /// drawn when it armed. Deleting either guard left the suite green before
    /// this test existed.
    ///
    /// Both ranges are wide *and both are set*, which is what makes the second
    /// half discriminating: `new_handshake_timeout` is
    /// `keepalive.hi + pick(rekey_timeout)`, so with `rekey_timeout` left unset
    /// it is a constant and a re-draw is indistinguishable from no re-draw.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn a_latched_deadline_keeps_the_draw_it_armed_with() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            keepalive_timeout: (3, 9),
            rekey_timeout: (2, 40),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake_with_amnezia(amnezia);
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];

        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));

        // One data packet mine -> theirs: their side now owes a keepalive, and
        // the deadline it will use was drawn at this instant.
        let packet = create_ipv4_udp_packet();
        let sent = unwrap_network_packet(my_tun.encapsulate(&packet, &mut my_dst)).to_vec();
        assert!(matches!(
            their_tun.decapsulate(None, &sent, &mut their_dst),
            TunnResult::WriteToTunnelV4(..)
        ));
        let armed = their_tun.timers.keepalive_current;
        assert!(
            (3..=9).contains(&armed.as_secs()),
            "the armed keepalive {:?} is outside the configured 3..=9",
            armed
        );

        // Further inbound packets re-latch an ALREADY latched keepalive. The
        // guard is what stops each of them re-drawing the deadline.
        for _ in 0..8 {
            let more = unwrap_network_packet(my_tun.encapsulate(&packet, &mut my_dst)).to_vec();
            assert!(matches!(
                their_tun.decapsulate(None, &more, &mut their_dst),
                TunnResult::WriteToTunnelV4(..)
            ));
            assert_eq!(
                their_tun.timers.keepalive_current, armed,
                "a packet arriving on an already-armed keepalive must not re-draw \
                 its deadline"
            );
        }

        // And the same holds for the unanswered-data deadline on the sending
        // side, whose latch `timer_tick(TimeLastPacketSent)` arms.
        let armed_new_handshake = my_tun.timers.new_handshake_current;
        for _ in 0..8 {
            let _ = my_tun.encapsulate(&packet, &mut my_dst);
            assert_eq!(
                my_tun.timers.new_handshake_current, armed_new_handshake,
                "a send on an already-armed new-handshake latch must not re-draw \
                 its deadline"
            );
        }
    }

    /// Every initiation send re-draws the retransmission interval, including a
    /// retransmission -- upstream's `timersHandshakeInitiated` runs on each
    /// send, not once per cycle.
    ///
    /// One draw per cycle would make every retry in that cycle wait the
    /// identical interval, which is the fixed inter-packet timing the tunable
    /// exists to remove. Moving the draw under `starting_new_handshake` left
    /// the suite green before this test existed.
    #[test]
    #[cfg(feature = "mock-instant")]
    fn every_initiation_send_redraws_the_retransmission_interval() {
        let amnezia = AmneziaConfig::default().with_tunable_timers(amnezia::AwgTimers {
            rekey_timeout: (2, 30),
            // More attempts than the loop below consumes, so the retries are
            // never cut short by the cycle's attempt limit.
            max_handshake_attempts: (5_000, 5_000),
            ..amnezia::AwgTimers::default()
        });
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = [0u8; 2048];

        assert!(matches!(
            my_tun.format_handshake_initiation(&mut dst, false),
            TunnResult::WriteToNetwork(_)
        ));

        let mut seen = std::collections::HashSet::new();
        seen.insert(my_tun.timers.retransmit_current);
        for _ in 0..24 {
            // Step past whatever this send drew, so the next poll retransmits.
            let wait = my_tun.timers.retransmit_current;
            mock_instant::thread_local::MockClock::advance(wait + Duration::from_secs(1));
            assert!(matches!(
                my_tun.update_timers(&mut dst),
                TunnResult::WriteToNetwork(_)
            ));
            seen.insert(my_tun.timers.retransmit_current);
        }
        assert!(
            seen.len() > 1,
            "every retransmission reused the same {:?} interval: the draw is \
             happening once per cycle, not once per send",
            seen
        );
    }
}
