// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// The classic WireGuard timings, which every unset `AwgTimers` range falls
// back to. Not gated: `AwgTimers` is compiled on every build.
use super::timers::{
    KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT,
};
// For `conforming_initiation` only, and gated exactly as it is: its caller is
// `device::probe_reply`, which does not exist without the `device` feature.
#[cfg(all(test, feature = "device"))]
use super::HANDSHAKE_INIT;
use super::{
    handshake::ObfuscationRanges, COOKIE_REPLY_SZ, DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ,
    HANDSHAKE_RESP_SZ,
};
use crate::noise::errors::WireGuardError;
use crate::noise::header_protection::{HeaderProtectionKey, NONCE_SIZE, TYPE_MASK_SIZE};
use crate::noise::rate_limiter::CookieDefense;
use rand_core::RngCore;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

const DNS_OPT_FIXED_LEN: usize = 11;
const DNS_OPT_MIN_WIRE_SIZE: usize = DNS_OPT_FIXED_LEN + 4;
const DEFAULT_JUNK_PACKET_SIZE_MIN: u16 = 50;
const DEFAULT_JUNK_PACKET_SIZE_MAX: u16 = 1000;
const MAX_JUNK_PACKET_COUNT: u16 = 128;
const MAX_JUNK_PACKET_SIZE: u16 = 1280;
const MAX_JUNK_PACKET_DELAY_MS: u16 = 200;
/// Largest datagram that can actually be sent: the IPv4 UDP payload limit,
/// `65535 - 20 (IP header) - 8 (UDP header)`. IPv6 allows 27 bytes more, but the
/// stricter bound is used so a configuration validated once is sendable over
/// either family — a device may be listening on both.
///
/// The kernel module bounds the same sizes by `MESSAGE_MAX_SIZE = 65535`
/// (`amneziawg-linux-kernel-module/src/messages.h:132`), which is the protocol
/// ceiling rather than the transport one. The 28-byte difference is deliberate:
/// a configuration in that window passes the kernel's check and then fails at
/// send time with `EMSGSIZE`, so it does not work there either. Rejecting it up
/// front is not a parity break: nothing that *functions* on the kernel module
/// is refused on size grounds here.
///
/// That is a claim about size only, and it is the whole of what `validate`
/// refuses on these grounds. The fork's one deliberate parity break — never
/// sending a cookie reply larger than the datagram that provoked it, which the
/// kernel does — is *not* in `validate`, and is not a configuration refusal at
/// all: it is enforced per datagram where cookie replies leave, and a
/// configuration that would need it is only *reported*, by
/// [`AmneziaConfig::cookie_amplification_complaint`]. The argument for it is
/// there.
const MAX_SENDABLE_DATAGRAM: usize = 65535 - 20 - 8;
/// AmneziaWG rounds unpadded transport plaintext up to this multiple, matching
/// amneziawg-go's `PaddingMultiple` and vanilla WireGuard's 16-byte boundary.
const PADDING_MULTIPLE: usize = 16;
/// A transport message's header -- type, receiver index, counter -- ahead of
/// its ciphertext. amneziawg-go's `MessageTransportHeaderSize`.
const DATA_OFFSET_SZ: usize = 16;
const DNS_JUNK_SIZE_MIN: usize = 50;
const DNS_JUNK_SIZE_MAX: usize = 200;
const QUIC_JUNK_SIZE_MIN: usize = 1200;
const QUIC_JUNK_SIZE_MAX: usize = 1252;
const SIP_JUNK_SIZE_MIN: usize = 200;
const SIP_JUNK_SIZE_MAX: usize = 1200;
/// The shortest S prefix `fill_sip` writes a SIP request line into. Below it
/// the prefix stays random; from it up, the prefix's first 12 bytes -- the
/// header-protection nonce -- are the start of one of a few fixed request
/// lines. One constant for the generator and for the header-protection policy
/// that refuses what the generator does to the nonce.
const SIP_REQUEST_LINE_MIN: usize = 31;
const STUN_JUNK_SIZE_MIN: usize = 28;
const STUN_JUNK_SIZE_MAX: usize = 100;
// RFC 5389 STUN magic cookie, present at bytes 4..8 of every STUN message.
// Imported rather than restated: `crate::noise::imitation::stun::MAGIC_COOKIE`
// is the crate's single definition. A private alias, not a re-export -- that
// would be `pub use` and would put the constant in this module's public API.
//
// A line comment, not a doc comment: rustdoc does not process docs on a
// private `use`, so a `///` here documents nothing and cannot be checked.
use crate::noise::imitation::stun::MAGIC_COOKIE as STUN_MAGIC_COOKIE;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationProtocol {
    #[default]
    None = 0,
    Dns = 1,
    Quic = 2,
    Sip = 3,
    Stun = 4,
}

impl TryFrom<u8> for AmneziaImitationProtocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Dns),
            2 => Ok(Self::Quic),
            3 => Ok(Self::Sip),
            4 => Ok(Self::Stun),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationProtocol {
    /// Every variant, so a caller offering these as choices cannot fall behind
    /// the enum. `boringtun-cli` builds its `--imitate-protocol` value list from
    /// this rather than restating it.
    pub const ALL: [Self; 5] = [Self::None, Self::Dns, Self::Quic, Self::Sip, Self::Stun];

    /// The name used on the command line and in `Ip =` config values.
    ///
    /// A `match` over `self` rather than a lookup table: adding a variant fails
    /// to compile here, which is the whole point. The previous arrangement had
    /// the CLI map these strings with a `_ =>` catch-all, so a new variant that
    /// nobody wired up silently meant "no imitation".
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Dns => "dns",
            Self::Quic => "quic",
            Self::Sip => "sip",
            Self::Stun => "stun",
        }
    }

    /// Does this protocol's cover traffic carry a hostname?
    ///
    /// `None` and `Stun` do not, and [`AmneziaImitation::new`] silently drops a
    /// domain supplied with them. A caller that took one from an operator should
    /// use this to say so rather than let it vanish.
    pub fn uses_domain(self) -> bool {
        matches!(self, Self::Dns | Self::Sip | Self::Quic)
    }
}

impl std::str::FromStr for AmneziaImitationProtocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `.iter().copied()`, not `.into_iter()`: in edition 2018 the latter on
        // an array yields references, so this would be a `Result<&Self, _>`.
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or(())
    }
}

/// What protocol imitation leaves of the header-protection nonce.
///
/// Header protection nonces each datagram with the first 12 bytes of its own
/// S prefix, and imitation shapes that prefix, so the imitation protocol
/// decides how many distinct nonces -- and so distinct header-protection masks
/// -- one key sees. A repeated nonce repeats the mask, which lets an observer
/// compare the masked headers of those datagrams: weaker header masking and
/// easier traffic fingerprinting. The WireGuard payload's encryption and
/// authentication do not depend on it. Measured on the production fillers,
/// and derived only by [`AmneziaConfig::header_protection_nonce`], the one
/// classifier every configuration door consults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderProtectionNonce {
    /// Random, or all but a few fixed bits: no imitation (12 random bytes),
    /// QUIC (a short-header first byte taking 16 values, then 11 random
    /// bytes), and SIP while every S is below [`SIP_REQUEST_LINE_MIN`], where
    /// the SIP filler leaves the prefix random.
    Full,
    /// STUN: the message type, length and magic cookie are fixed, so only the
    /// four transaction-ID bytes 8..12 vary -- a nonce space of about 2^32.
    /// A repeat becomes likely after roughly 77,000 datagrams under one key.
    Bounded32,
    /// DNS: only the 16-bit transaction ID varies -- 65,536 nonces. A repeat
    /// is likely within about 300 datagrams, and on a long-lived key most
    /// datagrams share their mask with an earlier one.
    Weak16,
    /// SIP with any S at [`SIP_REQUEST_LINE_MIN`] or more: that prefix starts
    /// with one of a few fixed request lines, so its nonce takes a handful of
    /// values and nearly every datagram repeats a mask. Refused.
    Degenerate,
}

/// Browser fingerprint for QUIC protocol imitation. All variants emit a full
/// browser-fingerprinted QUIC Initial; `Default` resolves to curl, matching
/// wgbooster's default browser when a domain is set but `Ib` is omitted.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationBrowser {
    #[default]
    Default = 0,
    Chrome = 1,
    Firefox = 2,
    Curl = 3,
    Random = 4,
}

impl TryFrom<u8> for AmneziaImitationBrowser {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Default),
            1 => Ok(Self::Chrome),
            2 => Ok(Self::Firefox),
            3 => Ok(Self::Curl),
            4 => Ok(Self::Random),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationBrowser {
    /// Map to a QUIC generator profile. `Default` resolves to curl, matching
    /// wgbooster's default browser when a domain is set but no `Ib` is given —
    /// so an omitted browser still produces a full QUIC Initial rather than the
    /// lightweight QUIC-shaped junk.
    fn to_quic(self) -> crate::noise::quic::profiles::BrowserProfile {
        use crate::noise::quic::profiles::BrowserProfile;
        match self {
            AmneziaImitationBrowser::Default | AmneziaImitationBrowser::Curl => {
                BrowserProfile::Curl
            }
            AmneziaImitationBrowser::Chrome => BrowserProfile::Chrome,
            AmneziaImitationBrowser::Firefox => BrowserProfile::Firefox,
            AmneziaImitationBrowser::Random => BrowserProfile::Random,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaImitation {
    pub(crate) protocol: AmneziaImitationProtocol,
    domain: Option<String>,
    pub(crate) browser: AmneziaImitationBrowser,
}

impl AmneziaImitation {
    pub fn new(
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        // DNS QNAMEs and SIP URIs need a strict LDH host (the latter is spliced
        // into text headers, so this also prevents injection). The QUIC SNI is a
        // length-prefixed TLS extension, so it accepts UTF-8/IDN like wgbooster.
        // Invalid hosts are dropped (a random one is generated at emit time).
        let domain = match protocol {
            AmneziaImitationProtocol::Dns | AmneziaImitationProtocol::Sip => {
                domain.filter(|domain| is_valid_imitation_host(domain))
            }
            AmneziaImitationProtocol::Quic => domain.filter(|domain| is_valid_quic_sni(domain)),
            _ => None,
        };
        // Browser only applies to QUIC.
        let browser = if protocol == AmneziaImitationProtocol::Quic {
            browser
        } else {
            AmneziaImitationBrowser::Default
        };

        Self {
            protocol,
            domain,
            browser,
        }
    }

    /// The domain that survived validation, if any.
    ///
    /// `pub` so a caller can tell whether the hostname it supplied was actually
    /// kept: [`Self::new`] drops an invalid host and falls back to a randomly
    /// generated one at emit time, which is a silent substitution an operator
    /// would otherwise only discover in a packet capture.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// A conforming AmneziaWG handshake initiation, before and after
/// [`AmneziaConfig::prepend_outbound`].
///
/// Lives here, next to the padding rules, because `device::probe_reply`'s
/// ordering test needs a datagram that is *simultaneously* valid AmneziaWG and a
/// valid DNS query — which is exactly what this module produces under `ip=dns`.
/// Building it there instead meant exporting `HANDSHAKE_INIT` and
/// `HANDSHAKE_INIT_SZ` crate-wide for a test, permanently widening two
/// protocol constants that nothing in production needs outside `noise`.
///
/// Gated on `device` as well as `test`, for the reason [`super::packet_sizes`]
/// gives: the only caller is behind that feature, so a test build without it
/// carries a `dead_code` warning for this function -- and `cargo hack test
/// --each-feature`, which CI runs, compiles exactly that configuration.
#[cfg(all(test, feature = "device"))]
pub(crate) fn conforming_initiation(
    cfg: &AmneziaConfig,
    obf: ObfuscationRanges,
    rng: &mut impl RngCore,
) -> (Vec<u8>, Vec<u8>) {
    let mut original = vec![0u8; HANDSHAKE_INIT_SZ];
    original[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
    for (i, byte) in original[4..].iter_mut().enumerate() {
        *byte = (i as u8) ^ 0x5a;
    }

    let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 1280];
    buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&original);
    let padded = cfg
        .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, rng)
        .expect("S1 must leave room for the initiation")
        .to_vec();

    (original, padded)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaConfig {
    pub(crate) init_packet_junk_size: u16,
    pub(crate) response_packet_junk_size: u16,
    pub(crate) cookie_packet_junk_size: u16,
    pub(crate) transport_packet_junk_size: u16,
    pub(crate) pre_handshake_junk: AmneziaPreHandshakeJunk,
    pub(crate) imitation: AmneziaImitation,
    /// Suppress the client-only pre-handshake burst (Jc junk packets and the
    /// protocol imitation sequence) while keeping every other AmneziaWG
    /// behaviour. See [`AmneziaConfig::as_responder`].
    pub(crate) suppress_pre_handshake: bool,
    /// AmneziaWG 3.0 header protection. Unset by default, and unset means off.
    ///
    /// Both ends must carry the same key: it is not negotiated and there is no
    /// in-band signal, so a mismatch is a tunnel that never forms rather than
    /// one that degrades.
    pub(crate) header_protection: HeaderProtectionKey,
    /// AmneziaWG 3.0 `content_padding_addition`, the inclusive `(lo, hi)` range
    /// of zero bytes appended to each transport plaintext, inside the AEAD.
    /// `(0, 0)` is the unset sentinel, matching amneziawg-go's `UintRange`.
    ///
    /// Send-only: the receiver trims a data packet by its IP length field and
    /// treats a zero-first-byte plaintext as a keepalive, so a padded datagram
    /// needs no cooperation on the far end.
    pub(crate) content_padding_addition: (u32, u32),
    /// The MTU the padding is clamped against, so a full-MTU packet grows by
    /// zero and never turns a deliverable frame into `EMSGSIZE`. `0` means "no
    /// MTU known" -- the raw `Tunn`/FFI path, where the caller's buffer is the
    /// only bound; the device sets it from the interface MTU.
    pub(crate) content_padding_mtu: u16,
    /// AmneziaWG 3.0 tunable timers. All-default is vanilla WireGuard: every
    /// accessor falls back to its classic constant.
    pub(crate) timers: AwgTimers,
    /// AmneziaWG 3.1 `RandomTrailers`. Off by default, and off is exactly the
    /// 3.0 wire: handshake messages at their fixed sizes, transport padded as
    /// before.
    ///
    /// On, each handshake message carries an unauthenticated random suffix
    /// after its canonical bytes -- outside Noise, the MACs, the cookie AEAD and
    /// header protection -- so a receiver reads handshake sizes as minimums
    /// rather than exact values. Transport grows too, but *inside* its AEAD:
    /// the addition is zero padding of the plaintext, never bytes after the
    /// tag. How much of either is drawn against the tunnel's observed UDP
    /// window; see [`DEFAULT_UDP_WINDOW`].
    ///
    /// A receiver must agree: a peer that is off rejects every trailer-extended
    /// handshake message. It is not negotiated.
    pub(crate) random_trailers: bool,
    /// AmneziaWG 3.1 `DisableCookies`. Off by default, and off is WireGuard's
    /// under-load cookie defense exactly as it was.
    ///
    /// On, a handshake message whose mac1 holds bypasses the *whole* under-load
    /// cookie-defense branch: the load decision is never taken (so the message
    /// is not counted against the handshake budget), mac2 is not checked, no
    /// source address is needed, and no cookie reply is formed. The message
    /// goes straight on to Noise. That is amneziawg-go v3.1.20260828's
    /// `!disableCookies && IsUnderLoad()` (b5928ef, "disable the whole
    /// underload"). The first 3.1 release only stopped the reply being *sent*,
    /// and still refused, under load, every handshake whose mac2 it could no
    /// longer ask for.
    ///
    /// Not "disable cookie replies": it leaves mac1, Noise and its static-key
    /// authentication, the handshake timestamp check, transport replay
    /// protection and the cookie replies a peer sends *us* exactly as they
    /// are -- those are still decrypted and stored, and our own handshakes
    /// still carry the mac2 they earn. It is local responder policy, not
    /// negotiated, so the two ends need not agree; S3 keeps its meaning,
    /// because the peer may still send cookie replies.
    pub(crate) disable_cookies: bool,
}

/// What a live configuration change does to a pre-handshake burst already in
/// flight. See [`AmneziaConfig::pending_burst_change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingBurstChange {
    /// Nothing the burst captured changed: it goes on, and what it still has
    /// to send -- junk and the initiation behind it -- is produced under the
    /// new configuration as it goes out.
    Keep,
    /// The Jc count, the imitation or whether there is a burst at all
    /// changed: the burst is rebuilt from the new configuration.
    Restart,
}

/// How much RandomTrailers suffix an outgoing handshake message may carry: the
/// window it is drawn against, and a ceiling on the whole datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrailerRoom {
    udp_window: u32,
    max_wire: usize,
}

impl TrailerRoom {
    /// An initiation or a response: drawn against the tunnel's UDP window.
    pub(crate) fn window(udp_window: u32) -> Self {
        Self {
            udp_window,
            max_wire: usize::MAX,
        }
    }

    /// A cookie reply to a `request_len`-byte datagram.
    ///
    /// Drawn against the fixed [`DEFAULT_UDP_WINDOW`], never the tunnel's grown
    /// one -- amneziawg-go's cookie path calls the device-level
    /// `randomTrailer`, which has no peer to ask. And never past `request_len`,
    /// the whole datagram that provoked it: a cookie reply goes to an address
    /// nothing has authenticated, so WireSock does not let it be larger than
    /// what was sent (#42), and a trailer is bounded to the room parity leaves
    /// rather than drawn freely and then suppressed. Equality is allowed. The
    /// reference draws the suffix without this ceiling; the wire is the same
    /// shape either way.
    pub(crate) fn cookie_reply(request_len: usize) -> Self {
        Self {
            udp_window: DEFAULT_UDP_WINDOW,
            max_wire: request_len,
        }
    }
}

/// The UDP window a tunnel starts from, in bytes, and the fixed window a cookie
/// reply's trailer is drawn against. amneziawg-go's `DefaultUdpWindow`.
///
/// A tunnel's window is the largest datagram it has seen go by in either
/// direction on the current endpoint, never less than this; RandomTrailers draws
/// every addition from the room between the packet at hand and that window, so
/// padding never makes a datagram larger than the path has already carried.
/// Runtime state, so it lives on `Tunn`, one per peer, not here.
pub(crate) const DEFAULT_UDP_WINDOW: u32 = 500;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct AmneziaPreHandshakeJunk {
    pub(crate) packet_count: u16,
    pub(crate) packet_size_min: u16,
    pub(crate) packet_size_max: u16,
    pub(crate) packet_delay_ms: u16,
}

impl AmneziaPreHandshakeJunk {
    pub fn new(
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        let packet_count = if packet_count <= MAX_JUNK_PACKET_COUNT {
            packet_count
        } else {
            0
        };

        let (packet_size_min, packet_size_max) = if packet_count == 0 {
            (packet_size_min, packet_size_max)
        } else if packet_size_min == 0 && packet_size_max == 0 {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        } else if packet_size_min > 0
            && packet_size_min <= packet_size_max
            && packet_size_max <= MAX_JUNK_PACKET_SIZE
        {
            (packet_size_min, packet_size_max)
        } else {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        };

        let packet_delay_ms = if delay_ms <= MAX_JUNK_PACKET_DELAY_MS {
            delay_ms
        } else {
            0
        };

        Self {
            packet_count,
            packet_size_min,
            packet_size_max,
            packet_delay_ms,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.packet_count > 0
    }

    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.packet_delay_ms as u64)
    }
}

/// AmneziaWG 3.0 tunable timers, each an inclusive `(lo, hi)` range --
/// seconds, except `max_handshake_attempts`, which counts retries. `(0, 0)` is
/// the unset sentinel, matching amneziawg-go's `UintRange`: the classic
/// WireGuard constant governs, so an all-default struct is byte-identical
/// vanilla behaviour and an unset accessor never touches the RNG.
///
/// Each accessor reproduces which *end* of the range its amneziawg-go
/// namesake reads (device/timers.go, confirmed against the kernel module's
/// src/timers.c): a fresh draw where upstream calls `PickOne()` per use, the
/// low end where it wants the deterministic minimum (the receive-refresh
/// subtraction), the high end where it wants the most permissive bound (key
/// expiry, and the keepalive term of the new-handshake deadline).
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct AwgTimers {
    pub rekey_after_time: (u32, u32),
    pub rekey_timeout: (u32, u32),
    pub reject_after_time: (u32, u32),
    pub keepalive_timeout: (u32, u32),
    pub max_handshake_attempts: (u32, u32),
}

impl AwgTimers {
    /// A fresh draw from `range` in whole seconds, or `default` when unset.
    fn pick(range: (u32, u32), default: Duration, rng: &mut impl RngCore) -> Duration {
        if range == (0, 0) {
            return default;
        }
        Duration::from_secs(random_usize_inclusive(range.0 as usize, range.1 as usize, rng) as u64)
    }

    fn lo(range: (u32, u32), default: Duration) -> Duration {
        if range == (0, 0) {
            default
        } else {
            Duration::from_secs(range.0 as u64)
        }
    }

    fn hi(range: (u32, u32), default: Duration) -> Duration {
        if range == (0, 0) {
            default
        } else {
            Duration::from_secs(range.1 as u64)
        }
    }

    /// The initiator's active-rekey age: a session older than this is rekeyed
    /// on the next send. amneziawg-go's `keyRefreshTimeoutSending`.
    pub(crate) fn key_refresh_sending(&self, rng: &mut impl RngCore) -> Duration {
        Self::pick(self.rekey_after_time, REKEY_AFTER_TIME, rng)
    }

    /// The initiator's last-minute rekey age on receive:
    /// `reject - keepalive - rekey_timeout`, with upstream's exact end choices
    /// (draw, low, low) and its `max(0, ..)` clamp as saturating subtraction.
    /// amneziawg-go's `keyRefreshTimeoutReceiving`.
    ///
    /// Saturating even though [`AmneziaConfig::validate`] refuses orderings
    /// that could go negative: the raw `Tunn` builder path does not validate,
    /// and a `Duration` underflow is a panic that crosses the FFI boundary as
    /// a process abort.
    pub(crate) fn key_refresh_receiving(&self, rng: &mut impl RngCore) -> Duration {
        Self::pick(self.reject_after_time, REJECT_AFTER_TIME, rng)
            .saturating_sub(Self::lo(self.keepalive_timeout, KEEPALIVE_TIMEOUT))
            .saturating_sub(Self::lo(self.rekey_timeout, REKEY_TIMEOUT))
    }

    /// The initiation retransmission interval, drawn fresh per send.
    /// amneziawg-go's `retransmitHandshakeTimeout`.
    pub(crate) fn retransmit_timeout(&self, rng: &mut impl RngCore) -> Duration {
        Self::pick(self.rekey_timeout, REKEY_TIMEOUT, rng)
    }

    /// The unanswered-data deadline after which a new handshake is forced:
    /// keepalive high end plus a fresh rekey-timeout draw. amneziawg-go's
    /// `newHandshakeTimeout`.
    pub(crate) fn new_handshake_timeout(&self, rng: &mut impl RngCore) -> Duration {
        Self::hi(self.keepalive_timeout, KEEPALIVE_TIMEOUT)
            + Self::pick(self.rekey_timeout, REKEY_TIMEOUT, rng)
    }

    /// The passive-keepalive delay, drawn fresh per arming. amneziawg-go's
    /// `sendKeepaliveTimeout`.
    pub(crate) fn keepalive(&self, rng: &mut impl RngCore) -> Duration {
        Self::pick(self.keepalive_timeout, KEEPALIVE_TIMEOUT, rng)
    }

    /// The key-expiry age: the high end, the most permissive draw a peer that
    /// re-picks inside the same range could be running. amneziawg-go's
    /// `keychainExpireTime`.
    pub(crate) fn keychain_expire(&self) -> Duration {
        Self::hi(self.reject_after_time, REJECT_AFTER_TIME)
    }

    /// How many handshake *retransmissions* one cycle may send. The cycle's
    /// first initiation is not one of them, so the total number of initiations
    /// is one more than this.
    ///
    /// Upstream *counts* attempts rather than measuring a window
    /// (`handshakeAttempts > maxHandshakeAttempts` in amneziawg-go's
    /// `expiredRetransmitHandshake`; `timer_handshake_attempts >
    /// max_handshake_attempts` in the kernel module's
    /// `wg_expired_retransmit_handshake`), and so does this crate now.
    ///
    /// A window cannot express the same thing once `rekey_timeout` is a range:
    /// it would have to be sized from one fixed per-try cost while every retry
    /// draws its own. Sizing it from the low end -- the first shape of this
    /// code -- produced a give-up deadline shorter than a single
    /// retransmission, so `rekey_timeout = 1-20` expired the peer after two or
    /// three initiations, where every reference implementation sends eighteen.
    ///
    /// The two regimes differ deliberately, because they answer to different
    /// authorities:
    ///
    /// * **Configured**: `N + 1` retransmissions, i.e. `N + 2` initiations in
    ///   total. That is what a peer running the same `max_handshake_attempts =
    ///   N` gets from amneziawg-go, whose counter starts at zero, increments
    ///   once per retransmission, and gives up only once it is *greater than*
    ///   `N` -- its own log line reports the total as `maxAttempts + 2`. The
    ///   knob has to mean the same number of packets on both ends, so the
    ///   off-by-two is reproduced rather than corrected.
    /// * **Unset**: the classic count, `REKEY_ATTEMPT_TIME / REKEY_TIMEOUT`
    ///   initiations -- 17 retransmissions after the first. That is this
    ///   crate's long-standing behaviour (the 90-second `REKEY_ATTEMPT_TIME`
    ///   window at 5-second intervals) and it stays exactly as it was: an
    ///   unconfigured tunnel must not change. It is derived rather than
    ///   written as `18` so retuning either constant moves it, and pinned to
    ///   the literal 18 by a test so retuning cannot silently redefine what
    ///   the classic count is.
    pub(crate) fn max_retransmissions(&self, rng: &mut impl RngCore) -> u32 {
        let classic = (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as u32;
        if self.max_handshake_attempts == (0, 0) {
            // 18 initiations total, the last at t=85, expiring at t=90 -- the
            // same instant the old wall-clock window fired.
            return classic.saturating_sub(1);
        }
        let n = random_usize_inclusive(
            self.max_handshake_attempts.0 as usize,
            self.max_handshake_attempts.1 as usize,
            rng,
        ) as u32;
        n.saturating_add(1)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PacketKind {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

/// The control kinds an upstream receiver tries before transport, each with
/// its canonical message size, in the order it tries them.
const UPSTREAM_CONTROL_KINDS: [(PacketKind, usize); 3] = [
    (PacketKind::HandshakeInit, HANDSHAKE_INIT_SZ),
    (PacketKind::HandshakeResponse, HANDSHAKE_RESP_SZ),
    (PacketKind::CookieReply, COOKIE_REPLY_SZ),
];

/// Framings a transport datagram may get, in total, to avoid an upstream
/// receiver misreading it (`AmneziaConfig::avoid_upstream_control_collision`):
/// the ordinary one plus at most fifteen redraws. With the stock installer's H
/// ranges a single framing collides with probability at most about 7%, so the
/// cap is essentially never reached; it bounds the work for configurations
/// whose H ranges are wide enough to collide nearly always.
const UPSTREAM_COLLISION_CANDIDATES: usize = 16;

/// One way to read an inbound datagram: a packet kind at that kind's S offset.
///
/// Carries everything needed to recover the canonical message from the
/// original datagram again -- where it starts, how long it is, and whether it
/// was header-protected -- so each reading can be normalised from the same
/// untouched bytes. Built only by [`AmneziaConfig::inbound_candidates`], and
/// only meaningful against the datagram it was built from.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct InboundCandidate {
    kind: PacketKind,
    /// Where the canonical message starts: the kind's S size.
    offset: usize,
    /// The canonical message's length -- the kind's fixed size for the
    /// handshake kinds, the rest of the datagram for transport.
    message_len: usize,
    /// The datagram's length as it arrived.
    wire_len: usize,
    /// Whether the message was header-protected and must be unmasked.
    protected: bool,
}

/// The candidate readings of one datagram, at most one per packet kind, in
/// trial order: initiation, response, cookie reply, transport.
///
/// A fixed array rather than a `Vec`, because the bound is structural -- four
/// kinds, one offset each -- and building it runs for every datagram received.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct InboundCandidates([Option<InboundCandidate>; 4]);

impl InboundCandidate {
    /// Where the canonical message starts: the kind's S size.
    #[cfg(test)]
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
}

impl InboundCandidates {
    /// No reading fits: the datagram is not AmneziaWG traffic at all. What
    /// the device's ingress asks before it lets probe classification look.
    #[cfg(feature = "device")]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.iter().all(Option::is_none)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &InboundCandidate> {
        self.0.iter().flatten()
    }

    /// Each candidate's offset, in trial order -- which, in a fixture whose S
    /// sizes are distinct, says which kinds were found.
    #[cfg(test)]
    pub(crate) fn offsets(&self) -> Vec<usize> {
        self.iter().map(|c| c.offset).collect()
    }
}

/// Whether a cookie reply of `reply_len` wire bytes amplifies the `request_len`
/// datagram that provoked it.
///
/// The one spelling of the bound. Both runtime guards read it — `Tunn::decapsulate`
/// through [`AmneziaConfig::cookie_reply_would_amplify`], and
/// `device::reply_policy::cookie_verdict` directly, because that one is handed
/// both lengths by its caller and has no config to ask — so the two cannot drift
/// on which side of parity is allowed.
///
/// Strictly greater, deliberately: at parity a reflector gains an attacker
/// nothing, and refusing there would drop cookie replies that are not amplifiers
/// and with them WireGuard's flood defence.
///
/// Ungated, because `Tunn::decapsulate` reaches it on every build — the same
/// reason [`AmneziaConfig::cookie_reply_len`] carries no gate.
///
/// Named `reply_amplifies` and not `cookie_reply_amplifies` because
/// [`AmneziaConfig::cookie_reply_amplifies`] already exists and answers a
/// different question — *which* bound a configuration violates, for the
/// complaint text — and two unrelated things under one name in one file is how
/// a reader ends up reasoning about the wrong one.
pub(crate) fn reply_amplifies(request_len: usize, reply_len: usize) -> bool {
    reply_len > request_len
}

impl AmneziaConfig {
    /// Create a config with the AmneziaWG S1-S4 junk prefix sizes.
    ///
    /// `s1`/`s2`/`s3`/`s4` are the number of junk bytes prepended to handshake
    /// initiation, handshake response, cookie reply, and transport-data packets
    /// respectively. They are used verbatim and are not clamped: callers must
    /// size their output buffers to fit the base WireGuard packet plus the
    /// configured prefix, otherwise `prepend_outbound` (and therefore
    /// `Tunn::encapsulate`) returns [`WireGuardError::DestinationBufferTooSmall`].
    pub fn new(s1: u16, s2: u16, s3: u16, s4: u16) -> Self {
        Self {
            init_packet_junk_size: s1,
            response_packet_junk_size: s2,
            cookie_packet_junk_size: s3,
            transport_packet_junk_size: s4,
            pre_handshake_junk: AmneziaPreHandshakeJunk::default(),
            imitation: AmneziaImitation::default(),
            suppress_pre_handshake: false,
            header_protection: HeaderProtectionKey::default(),
            content_padding_addition: (0, 0),
            content_padding_mtu: 0,
            timers: AwgTimers::default(),
            random_trailers: false,
            disable_cookies: false,
        }
    }

    pub fn with_pre_handshake_junk(
        mut self,
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        self.pre_handshake_junk =
            AmneziaPreHandshakeJunk::new(packet_count, packet_size_min, packet_size_max, delay_ms);
        self
    }

    /// Enable AmneziaWG 3.0 header protection with a shared key.
    ///
    /// An all-zero key means off, matching amneziawg-go, so this is also how it
    /// is disabled again.
    pub fn with_header_protection(mut self, key: [u8; 32]) -> Self {
        self.header_protection = HeaderProtectionKey::new(key);
        self
    }

    /// Enable AmneziaWG 3.0 `content_padding_addition`.
    ///
    /// `lo`/`hi` are the inclusive range of zero bytes appended to each
    /// transport plaintext; `mtu` clamps the result so a full-MTU packet is not
    /// grown past what the link can carry (`0` = clamp only by the caller's
    /// buffer). `(0, 0)` is the unset sentinel and falls back to the spec
    /// 16-byte rounding.
    ///
    /// A transposed pair is normalized, not silently mapped to the unset
    /// sentinel: `(0, 0)` does not mean "off", it means the 16-byte-rounding
    /// fallback -- a third behaviour a caller who wrote `(hi, lo)` did not ask
    /// for and would only discover in a packet capture. The UAPI never arrives
    /// here inverted (`parse_uint_range` rejects `hi-lo`, as amneziawg-go's
    /// `UintRange::FromString` does); this guards the public builder.
    pub fn with_content_padding_addition(mut self, lo: u32, hi: u32, mtu: u16) -> Self {
        self.content_padding_addition = (lo.min(hi), lo.max(hi));
        self.content_padding_mtu = mtu;
        self
    }

    /// Enable or disable AmneziaWG 3.1 `RandomTrailers`. See the field.
    ///
    /// Both ends must agree. Switching it on a live tunnel keeps the tunnel's
    /// sessions and UDP window; only framing changes.
    pub fn with_random_trailers(mut self, on: bool) -> Self {
        self.random_trailers = on;
        self
    }

    /// Enable or disable AmneziaWG 3.1 `DisableCookies`. See the field: `true`
    /// bypasses the under-load cookie-defense branch after mac1, and nothing
    /// else.
    ///
    /// Local policy; the peer need not agree. Switching it on a live tunnel
    /// keeps the tunnel's sessions, UDP window and timers; only how a future
    /// handshake is met under load changes.
    pub fn with_disable_cookies(mut self, on: bool) -> Self {
        self.disable_cookies = on;
        self
    }

    /// What switching from this configuration to `next` does to a
    /// pre-handshake burst already in flight -- see `Tunn::set_obfuscation`.
    ///
    /// A burst captures only two things when it is built
    /// (`Tunn::new_pre_handshake_burst`): the imitation datagrams, generated
    /// whole, and the Jc count. Every other field is read when the next junk
    /// datagram, the initiation or a transport frame actually goes out, so a
    /// change to it reaches the rest of the burst by itself and the burst is
    /// kept. A change to what was captured leaves the burst describing a
    /// configuration that is gone, so it is rebuilt.
    ///
    /// Every field is named, the Jc group's included, so a field added later
    /// fails to compile here until it is classified.
    pub(crate) fn pending_burst_change(&self, next: &AmneziaConfig) -> PendingBurstChange {
        let AmneziaConfig {
            // Framing, read by `prepend_outbound_with_trailer` for each
            // message as it goes out.
            init_packet_junk_size: _,
            response_packet_junk_size: _,
            cookie_packet_junk_size: _,
            transport_packet_junk_size: _,
            pre_handshake_junk,
            // The imitation sequence is generated whole when the burst is
            // built.
            imitation,
            // Decides whether there is a burst at all.
            suppress_pre_handshake,
            // Masking, applied as each message goes out.
            header_protection: _,
            // Transport only.
            content_padding_addition: _,
            content_padding_mtu: _,
            // Drawn per send, cycle and session; `Tunn::set_obfuscation`
            // redraws them itself when they change.
            timers: _,
            // The trailer is drawn when the message is framed.
            random_trailers: _,
            // Receive policy: nothing this end sends depends on it.
            disable_cookies: _,
        } = self;
        let AmneziaPreHandshakeJunk {
            // Captured: how many junk datagrams the burst still owes.
            packet_count,
            // Read for each junk datagram as it is filled.
            packet_size_min: _,
            packet_size_max: _,
            // Read at each pacing check.
            packet_delay_ms: _,
        } = pre_handshake_junk;
        if *packet_count != next.pre_handshake_junk.packet_count
            || *imitation != next.imitation
            || *suppress_pre_handshake != next.suppress_pre_handshake
        {
            PendingBurstChange::Restart
        } else {
            PendingBurstChange::Keep
        }
    }

    /// Whether the rate limiter's under-load cookie defense applies to a
    /// handshake message this configuration receives. The one place the flag
    /// is turned into the limiter's policy, so every receive path reads it the
    /// same way.
    pub(crate) fn cookie_defense(&self) -> CookieDefense {
        if self.disable_cookies {
            CookieDefense::Bypassed
        } else {
            CookieDefense::Armed
        }
    }

    /// Replace the AmneziaWG 3.0 tunable-timer ranges wholesale.
    ///
    /// `(0, 0)` ranges are unset -- the classic constant governs -- so the
    /// default [`AwgTimers`] is a no-op.
    ///
    /// Transposed pairs are normalized, exactly as
    /// [`Self::with_content_padding_addition`] normalizes its own range and
    /// for the same reason: the accessors disagree about an inverted pair
    /// rather than rejecting it. `hi()` would return the *smaller* number
    /// while `pick()` returned the larger (`random_usize_inclusive` yields
    /// `min` when `min >= max`), so `reject_after_time: (200, 100)` would
    /// expire every session after 100s while arming its last-minute rekey for
    /// 185s -- a rekey that can never fire, and a configuration
    /// [`Self::validate`] would certify as coherent because it reads `.0` as
    /// the low end. The UAPI never arrives here inverted (`parse_uint_range`
    /// rejects `hi-lo`, as amneziawg-go's `UintRange::FromString` does); this
    /// guards the public builder, which is also the only path an FFI or
    /// `DeviceConfig` embedder takes.
    ///
    /// The value floors stay in [`Self::validate`], which the device path runs
    /// on every merge; the timer arithmetic saturates regardless, so an
    /// unvalidated raw-`Tunn` configuration misbehaves rather than panics.
    pub fn with_tunable_timers(mut self, timers: AwgTimers) -> Self {
        let norm = |(lo, hi): (u32, u32)| (lo.min(hi), lo.max(hi));
        self.timers = AwgTimers {
            rekey_after_time: norm(timers.rekey_after_time),
            rekey_timeout: norm(timers.rekey_timeout),
            reject_after_time: norm(timers.reject_after_time),
            keepalive_timeout: norm(timers.keepalive_timeout),
            max_handshake_attempts: norm(timers.max_handshake_attempts),
        };
        self
    }

    /// The number of zero bytes to append to a `src_len`-byte transport
    /// plaintext bound for a frame with `dst_len` bytes of buffer and a
    /// `transport_junk`-byte S4 prefix.
    ///
    /// Owns the whole budget: the room padding may use is whatever the base
    /// frame (`src_len + DATA_OVERHEAD_SZ + transport_junk`) does not, capped
    /// so the padded datagram can cross neither the caller's buffer nor
    /// `MAX_SENDABLE_DATAGRAM`. One function rather than a computation copied
    /// into each call site, because the two sites that needed it (the data
    /// path and the keepalive path) bound different frames and could drift:
    /// a term added to one copy and missed in the other would over-pad the
    /// keepalive, and `format_packet_data` then rejects it *after*
    /// `receive_handshake_response` has cleared the handshake state -- the
    /// keepalive lost for good, only on links near the MTU, only with padding
    /// active.
    ///
    /// `udp_window` is the tunnel's window, already grown to cover this frame
    /// (see [`Self::transport_window_observation`]). It is read only when
    /// RandomTrailers is on: with it off, padding is exactly what it was before
    /// 3.1 existed -- see [`Self::window_padding`] for why that is deliberate.
    pub(crate) fn content_padding_for_frame(
        &self,
        src_len: usize,
        dst_len: usize,
        transport_junk: usize,
        udp_window: u32,
        rng: &mut impl RngCore,
    ) -> usize {
        let committed = src_len + DATA_OVERHEAD_SZ + transport_junk;
        let space = dst_len
            .saturating_sub(committed)
            .min(MAX_SENDABLE_DATAGRAM.saturating_sub(committed));
        if self.random_trailers {
            self.window_padding(committed, udp_window, rng).min(space)
        } else {
            self.content_padding(src_len, space, rng)
        }
    }

    /// The AmneziaWG 3.1 transport padding: amneziawg-go's
    /// `randomPaddingAddition`, else its `randomTrailer`, drawn against the UDP
    /// window rather than the MTU. `base` is the unpadded frame on the wire,
    /// `S4 + 32 + plaintext`.
    ///
    /// Precedence is by *selection*, not by amount: an active
    /// `content_padding_addition` range decides, even when it draws zero, and
    /// RandomTrailers never falls through to the 16-byte rounding, even when it
    /// draws zero. The rounding is what a tunnel with neither sends, and with
    /// RandomTrailers on that tunnel does not exist.
    ///
    /// Only reached with RandomTrailers on, and that is a WireSock decision
    /// that differs from amneziawg-go 3.1. Upstream moved
    /// `content_padding_addition` onto the window unconditionally, so every
    /// 3.0 configuration that pads changes its distribution the day it is
    /// upgraded, with no configuration change -- the maximum moves from "one
    /// MTU unit less the plaintext" to "the largest datagram seen less this
    /// one". Here a 3.0 configuration (RandomTrailers off) keeps
    /// [`Self::content_padding`] exactly, and the window governs only a tunnel
    /// that has opted into 3.1 framing. The wire stays interoperable either
    /// way: padding is inside the AEAD, and every receiver trims by the inner
    /// IP length.
    ///
    /// The window already covers `base` (the caller observes the frame first,
    /// as upstream's `RoutineEncryption` does), so the headroom is never
    /// negative; `saturating_sub` is for a caller that forgets.
    fn window_padding(&self, base: usize, udp_window: u32, rng: &mut impl RngCore) -> usize {
        let headroom = (udp_window as usize).saturating_sub(base);
        let (lo, hi) = self.content_padding_addition;
        if lo != 0 || hi != 0 {
            random_usize_inclusive(lo as usize, hi as usize, rng).min(headroom)
        } else {
            random_below(headroom, rng)
        }
    }

    /// What sending a transport frame of `src_len` plaintext bytes (before
    /// padding) shows the UDP window: `S4 + 32 + src_len`, the frame's unpadded
    /// wire size. amneziawg-go's `RoutineEncryption` observes exactly this
    /// before it draws the padding, keepalives included.
    pub(crate) fn transport_window_observation(&self, src_len: usize) -> usize {
        self.transport_junk_size() + DATA_OVERHEAD_SZ + src_len
    }

    /// What receiving an authenticated transport frame with a `plaintext_len`
    /// plaintext (padding included, AEAD tag not) shows the UDP window:
    /// `S4 + 16 + plaintext_len`.
    ///
    /// Sixteen bytes short of the datagram: the header is counted and the tag
    /// is not. That is amneziawg-go's `RoutineSequentialReceiver`, which adds
    /// `MessageTransportHeaderSize` to the decrypted length where
    /// `RoutineEncryption` adds `MinMessageSize` to the plaintext. Reproduced
    /// on purpose rather than corrected, because the window decides how much
    /// padding each end draws, and an implementation that disagreed with the
    /// reference here would fingerprint itself by its size distribution.
    /// `the_receive_window_observation_is_sixteen_short_of_the_datagram` pins
    /// the asymmetry.
    pub(crate) fn received_window_observation(&self, plaintext_len: usize) -> usize {
        self.transport_junk_size() + DATA_OFFSET_SZ + plaintext_len
    }

    /// The number of zero bytes to append to a `src_len`-byte transport
    /// plaintext, given the room actually available (`space`, already the
    /// smaller of the caller's buffer and `MAX_SENDABLE_DATAGRAM`).
    ///
    /// Transcribes amneziawg-go's `randomPaddingAddition` (send.go) and its
    /// `calculatePaddingSize` fallback: a value drawn from the configured range,
    /// or -- when the range is unset -- rounding the plaintext up to a 16-byte
    /// multiple. In both, an over-MTU plaintext is measured against one MTU
    /// *unit* (`% mtu`), and the amount is capped by the MTU and then by
    /// `space`.
    ///
    /// The rounding applies to every tunnel, vanilla WireGuard included. That
    /// is the spec's own padding rule, and it is what the kernel
    /// (`calculate_skb_padding`), wireguard-go and amneziawg-go
    /// (`calculatePaddingSize`) all do unconditionally -- until this crate
    /// rounded, a boringtun sender was the one implementation whose transport
    /// lengths were not 16-multiples, itself a wire fingerprint. Interop is
    /// unaffected: every receiver, this one included, trims a data packet by
    /// its inner IP length. A keepalive stays zero-length -- rounding an empty
    /// plaintext adds nothing -- so vanilla receivers, which classify a
    /// keepalive by zero length, never see a difference.
    pub(crate) fn content_padding(
        &self,
        src_len: usize,
        space: usize,
        rng: &mut impl RngCore,
    ) -> usize {
        let mtu = self.content_padding_mtu as usize;
        // One MTU unit: an over-MTU plaintext (only reachable when `mtu == 0`
        // does not clamp `space`) is measured against its remainder, matching
        // upstream's `if packetSize > mtu { packetSize %= mtu }`.
        let last_unit = if mtu != 0 && src_len > mtu {
            src_len % mtu
        } else {
            src_len
        };

        let (lo, hi) = self.content_padding_addition;
        let want = if lo != 0 || hi != 0 {
            // An active range. `random_usize_inclusive` casts to u64 before the
            // +1, so a full-width range does not overflow on a 32-bit target.
            random_usize_inclusive(lo as usize, hi as usize, rng)
        } else {
            // Unset: round the plaintext up to a 16-byte multiple, never past
            // the MTU. Mirrors upstream `calculatePaddingSize`, which every
            // implementation applies to every tunnel when no range is set.
            let padded = last_unit.next_multiple_of(PADDING_MULTIPLE);
            let padded = if mtu != 0 { padded.min(mtu) } else { padded };
            padded.saturating_sub(last_unit)
        };

        // Cap by the room left in one MTU unit, then by what the buffer holds.
        let want = if mtu != 0 {
            want.min(mtu.saturating_sub(last_unit))
        } else {
            want
        };
        want.min(space)
    }

    pub(crate) fn header_protection_enabled(&self) -> bool {
        self.header_protection.is_set()
    }

    /// S1..S4 with their names, in packet-kind order.
    fn labelled_junk_sizes(&self) -> [(&'static str, u16); 4] {
        [
            ("S1", self.init_packet_junk_size),
            ("S2", self.response_packet_junk_size),
            ("S3", self.cookie_packet_junk_size),
            ("S4", self.transport_packet_junk_size),
        ]
    }

    /// The header-protection nonce this configuration's imitation leaves, or
    /// `None` without a header-protection key, where there is no nonce.
    ///
    /// The single source of the header-protection policy under imitation:
    /// [`Self::check_header_protection_nonce`] refuses
    /// [`HeaderProtectionNonce::Degenerate`] for every door, and
    /// `header_protection_nonce_complaint` words the warnings the doors log.
    /// Decided by the key, the imitation protocol and -- for SIP only -- the S
    /// sizes, since the imitation filler shapes every packet kind's prefix.
    /// An exhaustive match: a new imitation protocol does not compile until
    /// it has a classification of its own.
    pub(crate) fn header_protection_nonce(&self) -> Option<HeaderProtectionNonce> {
        if !self.header_protection_enabled() {
            return None;
        }
        Some(match self.imitation.protocol {
            AmneziaImitationProtocol::None | AmneziaImitationProtocol::Quic => {
                HeaderProtectionNonce::Full
            }
            AmneziaImitationProtocol::Stun => HeaderProtectionNonce::Bounded32,
            AmneziaImitationProtocol::Dns => HeaderProtectionNonce::Weak16,
            AmneziaImitationProtocol::Sip => match self.sip_request_line_prefix() {
                Some(_) => HeaderProtectionNonce::Degenerate,
                None => HeaderProtectionNonce::Full,
            },
        })
    }

    /// The first S size long enough for the SIP filler to write a request
    /// line into, as `(name, size)`; `None` while every S is below
    /// [`SIP_REQUEST_LINE_MIN`].
    fn sip_request_line_prefix(&self) -> Option<(&'static str, u16)> {
        self.labelled_junk_sizes()
            .iter()
            .copied()
            .find(|&(_, size)| size as usize >= SIP_REQUEST_LINE_MIN)
    }

    /// The warning a configuration door logs for an accepted header-protection
    /// nonce weaker than random, or `None` when there is nothing to say --
    /// no key, a random nonce, or a SIP request line (refused, not warned).
    ///
    /// Gated like [`Self::cookie_amplification_complaint`], for the same
    /// reason: the doors that log it are `device::api` and the C struct
    /// constructor, so without either feature it would be dead code.
    #[cfg(any(test, feature = "device", feature = "ffi-bindings"))]
    pub(crate) fn header_protection_nonce_complaint(&self) -> Option<String> {
        match self.header_protection_nonce()? {
            HeaderProtectionNonce::Full | HeaderProtectionNonce::Degenerate => None,
            HeaderProtectionNonce::Bounded32 => Some(
                "STUN imitation shapes the header-protection nonce (the first 12 bytes \
                 of each S prefix): only the 4 transaction-ID bytes vary, a bounded \
                 nonce space of about 2^32, so on a long-lived key nonces repeat -- a \
                 repeat becomes likely after roughly 77,000 datagrams -- and each nonce \
                 reuse repeats the header-protection mask. Repeated masks weaken header \
                 masking and make traffic easier to fingerprint; payload encryption \
                 and authentication are unaffected."
                    .to_owned(),
            ),
            HeaderProtectionNonce::Weak16 => Some(
                "DNS imitation shapes the header-protection nonce (the first 12 bytes \
                 of each S prefix): only the 16-bit DNS transaction ID varies, so there \
                 are just 65,536 nonces. Nonce reuse is quick -- a repeat is likely \
                 within about 300 datagrams, and on a long-lived key most datagrams \
                 repeat an earlier header-protection mask -- which substantially \
                 weakens header masking and makes traffic easier to fingerprint. \
                 Payload encryption and authentication are unaffected. Prefer QUIC \
                 imitation where header masking matters."
                    .to_owned(),
            ),
        }
    }

    /// Log [`Self::header_protection_nonce_complaint`] at WARN, if there is
    /// one. The one reporter the configuration doors share, so the wording and
    /// the fields live here rather than in each door. Called once per
    /// accepted configuration by the door that accepted it, not by `Tunn`,
    /// which a device builds and reconfigures once per peer.
    #[cfg(any(feature = "device", feature = "ffi-bindings"))]
    pub(crate) fn warn_header_protection_nonce(&self) {
        if let Some(complaint) = self.header_protection_nonce_complaint() {
            tracing::warn!(
                message = "protocol imitation weakens AmneziaWG header protection: \
                           the header-protection nonce space is small, so masks repeat",
                protocol = self.imitation.protocol.as_str(),
                detail = %complaint
            );
        }
    }

    /// The header-protection key as lowercase hex, or `None` when unset.
    ///
    /// Deliberately the only way out of [`HeaderProtectionKey`]: it exists so
    /// `get=1` can round-trip the configuration, and nothing else needs the
    /// bytes. `Debug` on the key still refuses to render them.
    pub(crate) fn header_protection_key_hex(&self) -> Option<String> {
        self.header_protection.to_hex()
    }

    pub fn with_protocol_imitation(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, AmneziaImitationBrowser::Default);
        self
    }

    /// As [`Self::with_protocol_imitation`], plus a browser fingerprint for QUIC.
    pub fn with_protocol_imitation_browser(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, browser);
        self
    }

    /// The header-protection nonce rules on their own: every S size must be
    /// able to supply the 12 nonce bytes once a key is set, and the imitation
    /// must leave those bytes more than a few fixed values (below).
    ///
    /// Header protection nonces every datagram with its own first 12 bytes, so a
    /// prefix shorter than that cannot supply one. Refused rather than silently
    /// left unprotected: an operator who set a key and got no masking would have
    /// no way to tell.
    ///
    /// What it catches is per-kind, not global: `prepend_outbound` refuses only
    /// the kind whose own S is short. So this rejects a superset of the configs
    /// that can never emit anything -- on a fresh tunnel S1 short is exactly
    /// that, since no initiation means no session, while S2, S3 and S4 put
    /// datagrams on the wire and lose the tunnel later. Every position is fatal,
    /// by a different route; the table is on
    /// [`Tunn::new_with_obfuscation`](crate::noise::Tunn::new_with_obfuscation).
    ///
    /// Split out of [`Self::validate`] because it is the only rule the `Tunn`
    /// constructors can enforce for themselves. The rest of `validate` refuses
    /// timer and size shapes those constructors have always accepted, so
    /// widening the check here would break existing Rust callers; the
    /// struct-based C constructor, which has no such legacy, runs the whole of
    /// `validate`. The cookie-amplification rule is in neither -- it is not a
    /// validity question: such a configuration loads everywhere, with a
    /// warning built from [`Self::cookie_amplification_complaint`], and the
    /// reflection itself is stopped per datagram where cookie replies leave.
    ///
    /// Parity with amneziawg-go, which refuses the same four sizes in
    /// `mergeWithDevice` against its own `HeaderCipherNonceSize = 12`.
    ///
    /// The second rule is the header-protection policy's one refusal: SIP
    /// imitation with any S at [`SIP_REQUEST_LINE_MIN`] or more
    /// ([`HeaderProtectionNonce::Degenerate`]). The SIP filler writes a
    /// request line into such a prefix, so its nonce is one of a few fixed
    /// strings and nearly every datagram repeats a mask: the key is configured
    /// and the masking it stands for is effectively absent, which an operator
    /// could not tell from a working setup. Every other imitation loads -- the
    /// weaker STUN and DNS nonces with a warning from the door that accepts
    /// them (`header_protection_nonce_complaint`). Here rather than in
    /// [`Self::validate`] alone because this is the check every door runs:
    /// the `Tunn` constructors, `Tunn::set_obfuscation`, and through
    /// `validate` the UAPI `set=1` and the C struct constructor behind JNI.
    /// Not an amneziawg-go rule -- its S bytes are always random.
    pub(crate) fn check_header_protection_nonce(&self) -> Result<(), String> {
        if !self.header_protection_enabled() {
            return Ok(());
        }
        for (label, junk) in self.labelled_junk_sizes() {
            if (junk as usize) < NONCE_SIZE {
                return Err(format!(
                    "{} is {} bytes, but header protection needs at least {} \
                     to nonce each datagram; raise {} or clear the key",
                    label, junk, NONCE_SIZE, label
                ));
            }
        }
        if self.header_protection_nonce() == Some(HeaderProtectionNonce::Degenerate) {
            let (label, size) = self
                .sip_request_line_prefix()
                .expect("a degenerate nonce is a SIP request-line prefix");
            return Err(format!(
                "SIP imitation with header protection: {} is {} bytes, and from {} bytes \
                 the SIP imitation writes a request line into the S prefix, so the \
                 header-protection nonce (its first 12 bytes) takes only a few fixed \
                 values and header protection's masking is effectively absent. Keep \
                 S1-S4 at {} or below, choose another imitation protocol, or disable \
                 header protection",
                label,
                size,
                SIP_REQUEST_LINE_MIN,
                SIP_REQUEST_LINE_MIN - 1
            ));
        }
        Ok(())
    }

    /// Check that every S-prefix can coexist with the packet it precedes.
    ///
    /// [`Self::new`] deliberately does not clamp, because the sizes are part of
    /// the wire contract and a peer configured differently must still be
    /// describable. But a configuration whose prefix cannot fit alongside its
    /// base packet can never emit a valid datagram: `prepend_outbound` returns
    /// [`WireGuardError::DestinationBufferTooSmall`] forever, which surfaces as
    /// a tunnel that simply never completes a handshake, with nothing pointing
    /// at the configuration. Callers accepting operator input should reject it
    /// at the point of entry instead.
    ///
    /// The bounds correspond to the kernel module's own validation
    /// (`amneziawg-linux-kernel-module/src/device.c:584-601`), but are 28 bytes
    /// stricter: the kernel bounds by the protocol ceiling
    /// (`MESSAGE_MAX_SIZE = 65535`) while this uses `MAX_SENDABLE_DATAGRAM`,
    /// what a UDP socket can actually carry.
    ///
    /// The relationship is therefore one-way, not symmetric: on **size**, a
    /// configuration landing in the 28-byte gap is accepted by the kernel and
    /// rejected here, and nothing is lost — it fails on the kernel too, at send
    /// time with `EMSGSIZE`, so it never worked there either. See
    /// `MAX_SENDABLE_DATAGRAM` for the arithmetic.
    ///
    /// Every rule here is universal: it holds for either end of the tunnel, and
    /// violating it harms the configuration's own operator. What this
    /// deliberately does **not** contain is the cookie-reflection policy.
    /// An S3 whose cookie reply would outgrow the packet that provokes it is
    /// not an impossible configuration: S3 is symmetric and interface-wide, so
    /// a *client* is handed it by whichever server it dials and cannot lower it
    /// without losing the ability to parse that server's cookie replies, and
    /// the stock AmneziaWG installer rolls such values routinely. The policy is
    /// enforced where replies are sent instead: `device::reply_policy`
    /// suppresses an amplifying reply on the device's ingress, and
    /// [`Tunn::decapsulate`] refuses to emit one no matter who built the
    /// tunnel -- each against the actual length of the datagram in hand. The
    /// configuration doors (`device::api` on `set=1`, the C struct constructor)
    /// accept it and warn, from the crate-internal reporter
    /// `cookie_amplification_complaint`; not linked, because a `pub` doc cannot
    /// link a `pub(crate)` item.
    ///
    /// The header-protection policy under protocol imitation follows the same
    /// split. QUIC loads silently; STUN and DNS load, and the doors warn that
    /// their header-protection nonce space is small; SIP with any S of 31 bytes
    /// or more is refused -- through the header-protection check this runs
    /// first -- because the SIP request line leaves header protection's
    /// masking effectively absent.
    ///
    /// [`Tunn::decapsulate`]: crate::noise::Tunn::decapsulate
    pub fn validate(&self) -> Result<(), String> {
        // First, and as its own pass rather than interleaved with the size rule
        // below, because the `Tunn` constructors call it on their own.
        self.check_header_protection_nonce()?;
        for (label, junk, base) in [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
            ("S3", self.cookie_packet_junk_size, COOKIE_REPLY_SZ),
            ("S4", self.transport_packet_junk_size, DATA_OVERHEAD_SZ),
        ] {
            if junk as usize + base > MAX_SENDABLE_DATAGRAM {
                return Err(format!(
                    "{} is too large: {} junk bytes + {} packet bytes exceed the {}-byte maximum datagram",
                    label, junk, base, MAX_SENDABLE_DATAGRAM
                ));
            }
        }

        // Header protection under protocol imitation is judged per protocol by
        // `header_protection_nonce`, not here: its one refusal (a SIP request
        // line in the prefix) is in `check_header_protection_nonce` above, and
        // the weaker-but-working STUN and DNS nonces are warnings the accepting
        // door logs through `warn_header_protection_nonce` -- `validate` stays
        // silent and says only what is valid. Nothing under the mask is
        // secret: a repeated nonce repeats the mask, which weakens header
        // masking, and leaks no payload plaintext or key material.

        // Timer floors. These are OURS, deliberately: neither amneziawg-go's
        // UAPI nor the kernel module's netlink validates timer values at all,
        // so a configuration refused here *loads* on the reference
        // implementations -- it just runs badly (a zero-second retry storm, or
        // keys rejected while the peer's state machine still considers them
        // fresh, which surfaces as one-way blackholing minutes later).
        // Refusing at `awg set`, naming the numbers, is the failure the
        // operator can act on.
        let t = &self.timers;
        // The four *duration* ranges only. `max_handshake_attempts` is a
        // count, and a drawn 0 is not degenerate there: it buys one
        // retransmission (`N + 1`), so `0-3` is a perfectly ordinary "retry at
        // least once" configuration that amneziawg-go runs the same way.
        // Refusing it would refuse a working reference config for no gain.
        for (label, (lo, hi)) in [
            ("rekey_after_time", t.rekey_after_time),
            ("rekey_timeout", t.rekey_timeout),
            ("reject_after_time", t.reject_after_time),
            ("keepalive_timeout", t.keepalive_timeout),
        ] {
            // A bare `0` parses to `(0, 0)` and means "use the built-in
            // default"; a zero *inside* a set range (`0-30`) is not unset, it
            // is a zero-second timer the draw can land on -- for rekey_timeout
            // an unthrottled initiation storm, for keepalive_timeout a
            // keepalive every poll. amneziawg-go draws and runs these.
            if (lo, hi) != (0, 0) && lo == 0 {
                return Err(format!(
                    "{} = 0-{}: a set range must not contain 0 (a bare 0 means \
                     \"use the built-in default\"; a 0 drawn from a range is a \
                     zero-second timer)",
                    label, hi
                ));
            }
        }

        // The orderings the timer state machine depends on, checked against
        // the worst draw of every participating range; the classic constant
        // stands in for an unset one, so a lone shortened key is still caught.
        // Through the accessors, not a third hand-copy of the sentinel rule:
        // the validator's whole job is to agree with what the timer wheel will
        // actually do, so it has to read the ranges the same way.
        let eff = |range: (u32, u32), default: Duration| -> (u64, u64) {
            (
                AwgTimers::lo(range, default).as_secs(),
                AwgTimers::hi(range, default).as_secs(),
            )
        };
        let (reject_lo, _) = eff(t.reject_after_time, REJECT_AFTER_TIME);
        let (_, rekey_after_hi) = eff(t.rekey_after_time, REKEY_AFTER_TIME);
        let (_, rekey_timeout_hi) = eff(t.rekey_timeout, REKEY_TIMEOUT);
        let (_, keepalive_hi) = eff(t.keepalive_timeout, KEEPALIVE_TIMEOUT);

        // A key must be replaceable before it is rejectable: the rekey that
        // replaces a session begins at rekey_after_time and needs a
        // rekey_timeout to complete, so a reject_after_time draw shorter than
        // that discards keys the peer still considers live.
        if reject_lo < rekey_after_hi + rekey_timeout_hi {
            return Err(format!(
                "reject_after_time can draw {}s while rekey_after_time + rekey_timeout \
                 can draw {}s: keys would be rejected before the rekey replacing them \
                 completes. Raise reject_after_time to at least {}, or lower \
                 rekey_after_time/rekey_timeout.",
                reject_lo,
                rekey_after_hi + rekey_timeout_hi,
                rekey_after_hi + rekey_timeout_hi
            ));
        }

        // The last-minute rekey window is reject - keepalive - rekey_timeout;
        // a draw combination that zeroes it turns the receive-side refresh
        // into "rekey immediately, always".
        if reject_lo <= keepalive_hi + rekey_timeout_hi {
            return Err(format!(
                "reject_after_time can draw {}s while keepalive_timeout + rekey_timeout \
                 can draw {}s: the last-minute rekey window (reject - keepalive - \
                 rekey_timeout) would be zero or negative. Raise reject_after_time \
                 above {}, or lower keepalive_timeout/rekey_timeout.",
                reject_lo,
                keepalive_hi + rekey_timeout_hi,
                keepalive_hi + rekey_timeout_hi
            ));
        }

        Ok(())
    }

    /// Adapt this configuration for the responder (server) side of a tunnel.
    ///
    /// A server must *tolerate* a client's pre-handshake camouflage but must
    /// never emit it: the Jc junk burst and the protocol imitation sequence are
    /// things a client sends to open a conversation. Emitting them from a
    /// responder is both directionally wrong — it looks like the server is
    /// opening a QUIC/DNS/SIP/STUN exchange with its own peer — and slow, since
    /// the queue drains one datagram per `update_timers` tick, delaying any
    /// server-initiated handshake by the length of the sequence.
    ///
    /// Everything else is preserved, including the imitation protocol itself:
    /// S1-S4 padding is still filled with protocol-shaped bytes
    /// (`fill_outbound_junk`), so the server's own traffic keeps the
    /// same byte distribution as the client's. Only the *standalone* datagrams
    /// are suppressed.
    pub fn as_responder(mut self) -> Self {
        self.suppress_pre_handshake = true;
        self
    }

    /// True when a full protocol-natural imitation sequence should be emitted
    /// for the pre-handshake phase. DNS/SIP/STUN/QUIC all qualify (QUIC's omitted
    /// browser defaults to curl, matching wgbooster); only `None` does not.
    pub(crate) fn has_imitation_sequence(&self) -> bool {
        self.imitation.protocol != AmneziaImitationProtocol::None
    }

    /// True when this endpoint should emit a pre-handshake burst at all —
    /// false for a responder, and for a client with neither Jc nor imitation.
    pub(crate) fn emits_pre_handshake(&self) -> bool {
        !self.suppress_pre_handshake
            && (self.pre_handshake_junk.is_enabled() || self.has_imitation_sequence())
    }

    /// The configured imitation host, or a generated random one (DNS query name
    /// / SIP URI host / QUIC SNI).
    fn imitation_host(&self, rng: &mut impl RngCore) -> String {
        self.imitation
            .domain()
            .map(str::to_owned)
            .unwrap_or_else(|| random_imitation_domain(rng))
    }

    /// Generate the standalone imitation datagram sequence for the pre-handshake
    /// phase, each paired with the delay to wait *before* emitting it. Imitation
    /// ignores the generic Jd delay and uses protocol-natural timing (the first
    /// datagram always has zero delay): DNS sends A+AAAA in parallel then HTTPS
    /// after 15 ms; SIP waits 20 ms before the CANCEL; STUN waits 15 ms before
    /// the nomination check; QUIC Initials go back-to-back.
    pub(crate) fn pre_handshake_imitation_datagrams(
        &self,
        rng: &mut impl RngCore,
    ) -> std::collections::VecDeque<(Duration, Vec<u8>)> {
        use crate::noise::imitation::{dns, sip, stun};

        let (datagrams, delays_ms): (Vec<Vec<u8>>, &[u16]) = match self.imitation.protocol {
            AmneziaImitationProtocol::Dns => {
                (dns::generate(&self.imitation_host(rng), rng), &[0, 0, 15])
            }
            AmneziaImitationProtocol::Sip => {
                (sip::generate(&self.imitation_host(rng), rng), &[0, 20])
            }
            AmneziaImitationProtocol::Stun => (stun::generate(rng), &[0, 15]),
            AmneziaImitationProtocol::Quic => {
                let browser = self.imitation.browser.to_quic();
                let datagrams = crate::noise::quic::generator::generate_client_initials(
                    browser,
                    &self.imitation_host(rng),
                    rng,
                );
                (datagrams, &[])
            }
            AmneziaImitationProtocol::None => (Vec::new(), &[]),
        };

        datagrams
            .into_iter()
            .enumerate()
            .map(|(i, datagram)| {
                let ms = delays_ms.get(i).copied().unwrap_or(0);
                (Duration::from_millis(ms as u64), datagram)
            })
            .collect()
    }

    fn inbound_junk_size(&self, kind: PacketKind) -> usize {
        (match kind {
            PacketKind::HandshakeInit => self.init_packet_junk_size,
            PacketKind::HandshakeResponse => self.response_packet_junk_size,
            PacketKind::CookieReply => self.cookie_packet_junk_size,
            PacketKind::TransportData => self.transport_packet_junk_size,
        }) as usize
    }

    fn outbound_junk_size(&self, kind: PacketKind) -> usize {
        self.inbound_junk_size(kind)
    }

    /// The S4 prefix a transport data packet will carry on the wire.
    ///
    /// Exists so `Tunn::encapsulate` can size `dst` for the whole frame before
    /// formatting anything. It reads through [`Self::outbound_junk_size`], the
    /// same accessor [`Self::prepend_outbound`] uses, so the prediction cannot
    /// drift from the production by way of two spellings of one lookup -- the
    /// same reasoning as [`Self::cookie_reply_len_on_wire`].
    ///
    /// Assuming the *kind* is safe here in a way it would not be in general:
    /// `prepend_outbound` derives it from the tag on the wire, and
    /// `format_packet_data` always writes `obf.random_h4(rng)`. Since
    /// `ObfuscationRanges::new` rejects overlapping H ranges, that tag can
    /// never match H1/H2/H3, so a self-emitted transport packet always
    /// classifies as [`PacketKind::TransportData`] -- including at the lengths
    /// that collide with `HANDSHAKE_INIT_SZ`, `HANDSHAKE_RESP_SZ` and
    /// `COOKIE_REPLY_SZ`, where the match arms fall through on their tag guard.
    pub(crate) fn transport_junk_size(&self) -> usize {
        self.outbound_junk_size(PacketKind::TransportData)
    }

    /// The message-type tag at `offset`, with `mask` XORed off it.
    ///
    /// `mask` is the header-protection keystream when a key is set and all
    /// zeroes otherwise, so the unprotected path stays bit-for-bit what it was
    /// -- XOR with zero is the identity, and there is no second code path to
    /// drift out of step with this one.
    fn read_tag_masked(packet: &[u8], offset: usize, mask: [u8; TYPE_MASK_SIZE]) -> Option<u32> {
        let tag = packet.get(offset..offset + 4)?;
        let mut bytes: [u8; 4] = tag.try_into().ok()?;
        for (b, m) in bytes.iter_mut().zip(mask.iter()) {
            *b ^= m;
        }
        Some(u32::from_le_bytes(bytes))
    }

    fn read_tag(packet: &[u8], offset: usize) -> Option<u32> {
        Self::read_tag_masked(packet, offset, [0u8; TYPE_MASK_SIZE])
    }

    fn tag_matches(obf: ObfuscationRanges, kind: PacketKind, tag: u32) -> bool {
        match kind {
            PacketKind::HandshakeInit => obf.matches_h1(tag),
            PacketKind::HandshakeResponse => obf.matches_h2(tag),
            PacketKind::CookieReply => obf.matches_h3(tag),
            PacketKind::TransportData => obf.matches_h4(tag),
        }
    }

    /// Every packet kind an inbound datagram could be, in trial order.
    ///
    /// At most one candidate per kind, each at that kind's own S offset: the
    /// three handshake kinds by exact size -- by minimum size, with
    /// RandomTrailers, the canonical message still their fixed size and the
    /// rest a suffix -- transport by minimum size, and each
    /// only when the tag at its offset -- unmasked, when a header-protection key
    /// is set -- falls in its kind's H range. Nothing else is scanned, neither
    /// another offset nor another length, so the list is bounded at four and
    /// costs four length compares, four range tests and at most one keystream
    /// block to build.
    ///
    /// The padding rule is *per packet kind*, not global: a kind whose S is
    /// non-zero must arrive padded, while a kind whose S is zero must arrive
    /// unpadded. A configuration with `S1 = 15, S4 = 0` therefore rejects a
    /// bare initiation and accepts a bare transport packet, and both are
    /// correct. A datagram matching no kind is not re-read at offset 0 either:
    /// the S-prefix is an input filter, as in the kernel module, which drops
    /// such a datagram outright (`prepare_awg_message`, `src/receive.c`).
    ///
    /// The list can hold more than one candidate. The H ranges are disjoint, so
    /// one offset matches at most one kind -- but the offsets differ per kind. A
    /// datagram of `S1 + 148` bytes whose tag at `S1` is in H1 is *also* a
    /// transport candidate when `S1 + 148 >= S4 + 32` and its bytes at `S4`
    /// happen to be in H4, and two handshake kinds collide the same way when
    /// their S sizes differ by the gap between their message sizes. Which
    /// reading is real is settled only by authenticating it, so the receive
    /// paths try every candidate in this order, and a reading that fails does
    /// not end the search (`noise::inbound`).
    ///
    /// Empty means the datagram is not AmneziaWG traffic, and is what sends it
    /// on to probe classification. With every S at zero these tests reduce to
    /// the (tag, length) pairs `Tunn::parse_incoming_packet` applies, and the
    /// three handshake sizes are distinct, so plain WireGuard always sees the
    /// one candidate it always did.
    ///
    /// With a key set, the tag is range-tested *unmasked*: the tag on the wire
    /// is XORed, so testing it raw would reject every packet and accept packets
    /// nobody masked. The same four keystream bytes apply at every offset,
    /// because the sender starts its keystream at the message, whatever the
    /// padding in front of it. A candidate whose prefix cannot hold the nonce
    /// is left out rather than read unprotected; the constructors refuse such a
    /// configuration, but a device configuration supplied at startup does not
    /// pass through them.
    pub(crate) fn inbound_candidates(
        &self,
        obf: ObfuscationRanges,
        datagram: &[u8],
    ) -> InboundCandidates {
        if !self.header_protection_enabled() {
            // No key: the ordinary path, byte-identical to before.
            return self.candidates_under_mask(obf, datagram, [0u8; TYPE_MASK_SIZE], false);
        }
        match self.header_protection.type_mask(datagram) {
            Some(mask) => self.candidates_under_mask(obf, datagram, mask, true),
            // Too short to nonce, and so too short for any packet kind.
            None => InboundCandidates::default(),
        }
    }

    /// [`Self::inbound_candidates`] with the type mask already chosen.
    fn candidates_under_mask(
        &self,
        obf: ObfuscationRanges,
        datagram: &[u8],
        mask: [u8; TYPE_MASK_SIZE],
        protected: bool,
    ) -> InboundCandidates {
        let wire_len = datagram.len();
        let mut found = InboundCandidates::default();
        for (slot, (kind, exact_len)) in [
            (PacketKind::HandshakeInit, Some(HANDSHAKE_INIT_SZ)),
            (PacketKind::HandshakeResponse, Some(HANDSHAKE_RESP_SZ)),
            (PacketKind::CookieReply, Some(COOKIE_REPLY_SZ)),
            // Transport is variable length, so a minimum rather than an exact
            // size. With S4 = 0 the offset is 0 and this is the vanilla check.
            (PacketKind::TransportData, None),
        ]
        .iter()
        .enumerate()
        {
            let kind = *kind;
            let offset = self.inbound_junk_size(kind);
            // A handshake message is exactly its size, or -- with
            // RandomTrailers -- at least its size, the rest an unauthenticated
            // suffix. Its canonical extent is the fixed size either way: the
            // suffix never reaches the parser, the MACs, Noise, the cookie
            // AEAD or header protection. Transport's minimum is unchanged,
            // because its RandomTrailers addition is inside the AEAD.
            let (fits, message_len) = match *exact_len {
                Some(len) if self.random_trailers => (wire_len >= offset + len, len),
                Some(len) => (wire_len == offset + len, len),
                None => (
                    wire_len >= offset + DATA_OVERHEAD_SZ,
                    wire_len.saturating_sub(offset),
                ),
            };
            if !fits || (protected && offset < NONCE_SIZE) {
                continue;
            }
            let tag_matches = Self::read_tag_masked(datagram, offset, mask)
                .map(|tag| Self::tag_matches(obf, kind, tag))
                .unwrap_or(false);
            if tag_matches {
                found.0[slot] = Some(InboundCandidate {
                    kind,
                    offset,
                    message_len,
                    wire_len,
                    protected,
                });
            }
        }
        found
    }

    /// The canonical message `candidate` reads out of `datagram`.
    ///
    /// Only the canonical extent: a handshake message's RandomTrailers suffix
    /// is left behind in `datagram`, never parsed, authenticated or unmasked.
    ///
    /// Borrowed straight from `datagram` when the candidate is unprotected.
    /// Otherwise copied into `scratch` and unmasked there, so `datagram` stays
    /// the bytes that arrived: every candidate starts from them, and so does
    /// probe classification if none of them is ours. Unmasking in place would
    /// leave a failed reading's XOR behind for the next one to trip over.
    ///
    /// `None` only if the unmask refuses, which the conditions
    /// [`Self::inbound_candidates`] applies already rule out.
    pub(crate) fn candidate_message<'a>(
        &self,
        datagram: &'a [u8],
        candidate: &InboundCandidate,
        scratch: &'a mut Vec<u8>,
    ) -> Option<&'a [u8]> {
        debug_assert_eq!(datagram.len(), candidate.wire_len);
        let message = datagram.get(candidate.offset..candidate.offset + candidate.message_len)?;
        if !candidate.protected {
            return Some(message);
        }
        scratch.clear();
        scratch.extend_from_slice(message);
        let masked = Self::masked_len(candidate.kind, candidate.message_len);
        if !self
            .header_protection
            .unmask_detached(datagram, scratch, masked)
        {
            return None;
        }
        Some(scratch)
    }

    /// The first candidate's message, with the tag read through no mask.
    ///
    /// The one-verdict view the receive path had before it learned to try
    /// several readings, kept for the tests written against it: they pin the
    /// shape rules, which [`Self::candidates_under_mask`] still applies. The
    /// zero mask is deliberate even with a key set -- several of those tests
    /// use it to show what an *unprotected* receiver would accept.
    #[cfg(test)]
    pub(crate) fn strip_inbound<'a>(
        &self,
        obf: ObfuscationRanges,
        packet: &'a [u8],
    ) -> Option<&'a [u8]> {
        self.candidates_under_mask(obf, packet, [0u8; TYPE_MASK_SIZE], false)
            .iter()
            .next()
            .map(|c| &packet[c.offset..c.offset + c.message_len])
    }

    /// Unmask the first candidate in place and return its offset -- the old
    /// receive step, rebuilt on the candidate list for the tests written
    /// against it. A datagram with no candidate is left untouched.
    #[cfg(test)]
    pub(crate) fn unmask_and_classify_inbound(
        &self,
        obf: ObfuscationRanges,
        packet: &mut [u8],
    ) -> Option<usize> {
        let candidate = *self.inbound_candidates(obf, packet).iter().next()?;
        let mut scratch = Vec::new();
        let message = self
            .candidate_message(packet, &candidate, &mut scratch)?
            .to_vec();
        packet[candidate.offset..candidate.offset + message.len()].copy_from_slice(&message);
        Some(candidate.offset)
    }

    /// How many bytes of a message of `kind` the sender masked.
    ///
    /// The whole message for the handshake kinds; only the 16-byte header for
    /// transport data, whose payload is already sealed. Matches amneziawg-go's
    /// four send sites.
    fn masked_len(kind: PacketKind, message_len: usize) -> usize {
        /// Type, receiver index and counter -- the same 16 bytes as
        /// `session::DATA_OFFSET`, spelled again here because that one is
        /// private to the session module.
        ///
        /// NOT pinned by a unit test, and it cannot be: every in-crate test
        /// round-trips this value against itself, so any wrong constant stays
        /// self-consistent and the suite stays green while the wire format
        /// diverges from amneziawg-go. The external oracle is
        /// `scripts/hp-interop.py`, which runs our masking against a real
        /// amneziawg-go v3 peer -- that is what catches a change here.
        const TRANSPORT_HEADER_SZ: usize = 16;
        match kind {
            PacketKind::TransportData => TRANSPORT_HEADER_SZ,
            _ => message_len,
        }
    }

    fn classify_outbound(&self, obf: ObfuscationRanges, packet: &[u8]) -> Option<PacketKind> {
        let tag = Self::read_tag(packet, 0)?;
        match packet.len() {
            HANDSHAKE_INIT_SZ if obf.matches_h1(tag) => Some(PacketKind::HandshakeInit),
            HANDSHAKE_RESP_SZ if obf.matches_h2(tag) => Some(PacketKind::HandshakeResponse),
            COOKIE_REPLY_SZ if obf.matches_h3(tag) => Some(PacketKind::CookieReply),
            len if len >= DATA_OVERHEAD_SZ && obf.matches_h4(tag) => {
                Some(PacketKind::TransportData)
            }
            _ => None,
        }
    }

    /// How many bytes a `cookie_len`-byte cookie reply will occupy on the wire,
    /// S3 prefix included.
    ///
    /// Exists so the ingress path can decide whether the reply is an amplifier
    /// *before* [`Self::prepend_outbound`] generates junk for it. With S3 near
    /// its 65443-byte maximum, filling a prefix for a reply that policy then
    /// refuses would itself be the flood — one forged 148-byte initiation per
    /// 65 KB of keystream, which is a cheaper attack than the amplification it
    /// was meant to prevent.
    ///
    /// Reads the prefix size through [`Self::outbound_junk_size`], the same
    /// accessor `prepend_outbound` uses, so the prediction cannot drift from
    /// the production by way of two spellings of one lookup. What it still has
    /// to assume is the packet *kind*, which `prepend_outbound` derives from
    /// the tag on the wire, so
    /// [`tests::the_predicted_cookie_reply_length_is_the_one_actually_produced`]
    /// pins the two together.
    ///
    /// No longer feature-gated: `Tunn::decapsulate` reads it on every build to
    /// refuse emitting an amplifying reply, so it stopped being dead code
    /// outside `device` the day that guard moved into the core.
    pub(crate) fn cookie_reply_len(&self, cookie_len: usize) -> usize {
        cookie_len.saturating_add(self.outbound_junk_size(PacketKind::CookieReply))
    }

    /// Whether the cookie reply this configuration would emit is larger than
    /// `request_len`, the datagram that provoked it.
    ///
    /// The pairing of [`Self::cookie_reply_len`] with the bound, so the two
    /// runtime guards read one expression rather than two copies of it:
    /// [`Tunn::decapsulate`]'s emit-site check calls this directly, and
    /// `device::reply_policy::cookie_verdict` — which is handed both lengths
    /// already and has no `AmneziaConfig` to ask — calls
    /// [`reply_amplifies`] underneath. Before this existed the same
    /// comparison was written out at both sites, and each site's tests pinned
    /// only its own copy, so flipping one bound left the other green — measured:
    /// `>` to `>=` at either site failed exactly one test, and never the other
    /// site's.
    ///
    /// [`Tunn::decapsulate`]: crate::noise::Tunn::decapsulate
    pub(crate) fn cookie_reply_would_amplify(&self, cookie_len: usize, request_len: usize) -> bool {
        reply_amplifies(request_len, self.cookie_reply_len(cookie_len))
    }

    /// The S sizes at which a cookie reply would be larger than the packet that
    /// provokes it, if there are any.
    ///
    /// Every request kind the reply would exceed, tightest bound first, as
    /// `(kind, request_len, smallest_junk_that_clears_it)`, where `kind` is
    /// `"S1"` (an initiation) or `"S2"` (a response). Empty when the
    /// configuration does not amplify.
    ///
    /// Both runtime guards -- `device::reply_policy::cookie_verdict` on the
    /// device's ingress and the emit-site check in `Tunn::decapsulate` --
    /// suppress such a reply, because a cookie reply aimed at a forged source
    /// is a reflector and the ratio is fixed entirely by this configuration: an
    /// attacker cannot influence it, beyond sending the smallest request the
    /// framing allows. Both kinds are real triggers. A response reaches the
    /// under-load gate on a valid mac1 alone, before any index is looked up,
    /// and mac1 is keyed on this end's *public* key -- exactly as it is for an
    /// initiation, and exactly as the kernel module and amneziawg-go do it.
    ///
    /// The cost of the suppression is liveness, never safety, and it differs
    /// by kind. A suppressed reply to a *response* means a peer answering a
    /// handshake this end initiated never learns the cookie, so while this end
    /// stays over `HANDSHAKE_RATE_LIMIT` those handshakes may fail -- the
    /// peer's own initiations still get theirs if the initiation bound holds.
    /// A suppressed reply to an *initiation* means an incoming handshake cannot
    /// complete for as long as the overload lasts.
    ///
    /// This exists so the operator hears about that when they set the sizes,
    /// rather than during the flood. The condition is decidable from S1/S2/S3
    /// alone — `64 + S3 > 148 + S1` for an initiation, `64 + S3 > 92 + S2` for a
    /// response — so there is no reason to discover it at send time.
    ///
    /// Both kinds can be violated at once, and they are independent: S3 has to
    /// clear *both*. That is why this reports all of them rather than the first
    /// or the tightest. At S1=100, S2=0, S3=185 the reply is 249 bytes against a
    /// 248-byte initiation and a 92-byte response — advice naming either alone
    /// leaves the other failing, and the operator is sent round twice.
    ///
    /// The `min_junk` values are always reachable: `min_junk + base` is exactly
    /// `COOKIE_REPLY_SZ + S3`, and both callers of the complaint run
    /// [`Self::validate`] first, which bounds that by `MAX_SENDABLE_DATAGRAM`
    /// -- so following this advice can never trip the size check instead.
    ///
    /// This function only *reports*. [`Self::cookie_amplification_complaint`]
    /// turns it into a message, which both configuration doors -- `device::api`
    /// on `set=1` and the C struct constructor -- log at WARN while accepting
    /// the configuration. Neither refuses it: the runtime guards are the
    /// security boundary, and refusing would only decline a profile the
    /// reference implementations run.
    ///
    /// Gated the same way as the complaint, its only non-test caller.
    #[cfg(any(test, feature = "device", feature = "ffi-bindings"))]
    fn cookie_amplification_bounds(&self) -> Vec<(&'static str, usize, usize)> {
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        let mut bounds: Vec<(&'static str, usize, usize)> = [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
        ]
        .iter()
        // Filter before the subtraction, not after: `reply - base` underflows
        // on a configuration that does not amplify, which is most of them.
        // `reply > base + junk` implies `reply > base`, so the map is safe only
        // in this order.
        .filter(|&&(_, junk, base)| reply > base + junk as usize)
        .map(|&(label, junk, base)| (label, base + junk as usize, reply - base))
        .collect();
        // Stable, so an equal pair still reports S1 first and the message stays
        // the same for the common symmetric configuration.
        bounds.sort_by_key(|&(_, request, _)| request);
        bounds
    }

    /// The cookie-reflection complaint this configuration earns, or `None`.
    ///
    /// A diagnostic, not a verdict, which is why this is not part of
    /// [`Self::validate`]: such a configuration is valid, and loads. Both
    /// configuration doors read this and log it at WARN -- `device::api` on
    /// every `set=1` whose merged result still earns it, and
    /// `new_tunnel_with_awg_params` for a tunnel built through the C ABI. The
    /// security boundary is elsewhere and does not depend on either door:
    /// `device::reply_policy::cookie_verdict` on the device's ingress and
    /// `Tunn::decapsulate` at its emit site refuse to send any cookie reply
    /// larger than the datagram actually in hand, so an amplification-prone
    /// *configuration* never becomes an amplifying *port*. What the operator
    /// loses is liveness under overload, and the message says which.
    ///
    /// The AmneziaWG kernel module and amneziawg-go both accept these
    /// combinations and send the configured reply regardless of size -- there
    /// is no analogous rule in either -- so the runtime guard is ours; this
    /// message only explains its consequence in advance.
    ///
    /// The message names the binding bound (sizes and the S value), then the
    /// consequence of every violated bound -- a response bound costs
    /// handshakes this end *initiates* while overloaded, an initiation bound
    /// costs *incoming* handshakes -- once each, in one message, so a
    /// configuration violating both logs one line rather than two.
    ///
    /// Both alternatives the message offers have to work in one pass. The
    /// "raise" side therefore names every violated bound, not just the binding
    /// one: at S1=100, S2=0, S3=185 both are violated, and raising S2 alone
    /// still leaves the initiation a byte short.
    ///
    /// `None` with [`Self::disable_cookies`] on, whatever the sizes: the only
    /// thing that forms a cookie reply is the under-load branch it bypasses,
    /// so this end emits none and there is nothing to warn about. The sizes are
    /// judged again the moment it goes off -- `device::api` asks this of the
    /// whole configuration a `set=1` would leave, so turning cookies back on
    /// over an amplification-prone S3 is applied and warned about in the same
    /// transaction. What stays unconditional is [`Self::validate`]: S3 still
    /// frames the cookie replies a peer sends us, so an S3 that cannot frame
    /// one is refused whatever this flag says.
    ///
    /// Gated because the config-time doors are the only callers -- the warnings
    /// `device::api` logs on `set=1` and the C struct constructor logs -- so without either
    /// feature this is dead code and the crate would carry a `dead_code`
    /// warning for it. The *runtime* guard needs none of this: `decapsulate`
    /// compares lengths through `cookie_reply_len`, which is unconditional.
    /// `test` is in the list so the message tests run on a default-feature
    /// `cargo test`.
    #[cfg(any(test, feature = "device", feature = "ffi-bindings"))]
    pub(crate) fn cookie_amplification_complaint(&self) -> Option<String> {
        if self.disable_cookies {
            return None;
        }
        let bounds = self.cookie_amplification_bounds();
        let &(which, request, _) = bounds.first()?;
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        let raise = bounds
            .iter()
            .map(|&(label, _, min_junk)| format!("{} to at least {}", label, min_junk))
            .collect::<Vec<_>>()
            .join(" and ");
        // One clause per violated bound, in the same tightest-first order:
        // what the suppression costs, stated as liveness. Nothing here may
        // suggest the reply goes out -- it does not.
        let consequences = bounds
            .iter()
            .map(|&(label, request, _)| {
                if label == "S1" {
                    format!(
                        "a minimum-size handshake initiation ({} bytes) gets no cookie reply, so incoming handshakes may fail",
                        request
                    )
                } else {
                    format!(
                        "a minimum-size handshake response ({} bytes) gets no cookie reply, so handshakes this end initiates may fail",
                        request
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(format!(
            "S3 = {} makes a cookie reply {} bytes, larger than the {}-byte packet that provokes it ({} = {}). A cookie reply is never sent larger than the datagram that provoked it, so while this end is under load {}. Lower S3 to at most {}, or raise {}.",
            self.cookie_packet_junk_size,
            reply,
            request,
            which,
            request
                - if which == "S1" {
                    HANDSHAKE_INIT_SZ
                } else {
                    HANDSHAKE_RESP_SZ
                },
            consequences,
            request - COOKIE_REPLY_SZ,
            raise
        ))
    }

    /// The **binding** bound as `(kind, request_len, reply_len)` — the shortest
    /// provoking packet, the one S3 actually has to clear — or `None` when the
    /// configuration does not amplify.
    ///
    /// A view over [`Self::cookie_amplification_bounds`], not a second
    /// derivation. [`Self::cookie_amplification_complaint`] needs every violated
    /// bound, so it calls that directly; this narrower shape is only convenient
    /// for asserting *which* bound binds, and `#[cfg(test)]` accordingly — left
    /// ungated it is dead code, and the crate carries a `dead_code` warning for
    /// it with or without the `device` feature.
    #[cfg(test)]
    fn cookie_reply_amplifies(&self) -> Option<(&'static str, usize, usize)> {
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        // Sorted tightest-first, so the first entry is the binding one.
        let (label, request, _) = self.cookie_amplification_bounds().into_iter().next()?;
        Some((label, request, reply))
    }

    /// Frame an outgoing packet with no RandomTrailers suffix: its S prefix and
    /// header protection only. A suffix of zero is always valid on the wire, so
    /// this is correct for any configuration. Test-only: every send path in the
    /// crate now goes through [`Self::prepend_outbound_with_trailer`], and the
    /// framing tests that predate 3.1 pin the prefix and masking through this.
    #[cfg(test)]
    pub(crate) fn prepend_outbound<'a>(
        &self,
        obf: ObfuscationRanges,
        buffer: &'a mut [u8],
        packet_size: usize,
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.prepend_outbound_with_trailer(obf, buffer, packet_size, None, rng)
    }

    /// Frame the canonical packet in `buffer[..packet_size]` for the wire: the
    /// S prefix in front, header protection over the canonical bytes, and --
    /// for a handshake message with RandomTrailers on -- a random suffix
    /// behind, as large as `room` allows.
    ///
    /// The suffix is optional and so never an error: it shrinks to whatever
    /// the buffer, [`MAX_SENDABLE_DATAGRAM`] and `room`'s wire ceiling leave,
    /// down to nothing. Only the mandatory frame -- prefix plus canonical
    /// packet -- can fail for want of space, exactly as before 3.1. Header
    /// protection masks the canonical bytes only, nonced by the prefix as
    /// always; the suffix is written after and is never masked.
    pub(crate) fn prepend_outbound_with_trailer<'a>(
        &self,
        obf: ObfuscationRanges,
        buffer: &'a mut [u8],
        packet_size: usize,
        room: Option<TrailerRoom>,
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        let packet = buffer
            .get(..packet_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        let Some(kind) = self.classify_outbound(obf, packet) else {
            return Ok(&mut buffer[..packet_size]);
        };

        let junk_size = self.outbound_junk_size(kind);
        let new_size = packet_size
            .checked_add(junk_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        let trailer = self.trailer_len(kind, new_size, buffer.len(), room, rng);

        // With header protection off, no prefix means nothing to do. With it on,
        // no prefix also means no nonce -- and returning here would emit the
        // packet in the clear, which is the one outcome setting a key is meant
        // to prevent. `validate` rejects that configuration, but
        // `Tunn::new_with_obfuscation` does not call `validate`, so the public
        // constructors reach it. Falling through instead routes it into the
        // masking backstop below, which refuses. A suffix is work to do too.
        if junk_size == 0 && !self.header_protection_enabled() && trailer == 0 {
            return Ok(&mut buffer[..packet_size]);
        }

        if buffer.len() < new_size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        buffer.copy_within(0..packet_size, junk_size);
        self.fill_outbound_junk(&mut buffer[..junk_size], packet_size, rng);

        // The canonical transport header, kept before masking when this frame
        // is one an upstream receiver could misread (see
        // `avoid_upstream_control_collision`). Local to the call: every later
        // framing candidate is masked afresh from it, never from a masked one.
        let canonical_header = if self.upstream_collision_applies(kind, new_size + trailer) {
            let mut header = [0u8; DATA_OFFSET_SZ];
            header.copy_from_slice(&buffer[junk_size..junk_size + DATA_OFFSET_SZ]);
            Some(header)
        } else {
            None
        };

        // Masking comes last: the junk is the nonce, so it has to be final
        // before any keystream is derived from it, and the message has to be
        // sitting at its wire offset.
        let masked = Self::masked_len(kind, packet_size);
        if !self
            .header_protection
            .mask_outbound(&mut buffer[..new_size], junk_size, masked)
        {
            // Only reachable with a junk size below the nonce length. The `Tunn`
            // constructors now refuse that configuration outright, so the one
            // door left is `Tunn::set_obfuscation`, which is public and
            // infallible. Dropping the packet is right -- emitting it unmasked
            // would be readable by the classifier the operator asked to defeat
            // -- but `DestinationBufferTooSmall` is about the caller's buffer,
            // and here the buffer is fine, so say so once.
            //
            // Process-wide rather than per-config: `AmneziaConfig` derives
            // `Clone`/`PartialEq` and an interior-mutable latch would break
            // both, and a tunnel in this state fails on every packet, so the
            // second line would only be noise.
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::error!(
                    message = "header protection is on but the junk prefix for this \
                               packet is shorter than the 12-byte nonce, so nothing \
                               can be sent; raise S1-S4 or clear the key",
                    junk_size = junk_size
                )
            });
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        if let Some(canonical) = canonical_header {
            self.avoid_upstream_control_collision(
                obf,
                &mut buffer[..new_size],
                junk_size,
                &canonical,
                rng,
            );
        }
        // `trailer_len` bounded this by the buffer, so the slice is in range.
        let wire_len = new_size + trailer;
        fill_random(&mut buffer[new_size..wire_len], rng);
        Ok(&mut buffer[..wire_len])
    }

    /// Whether an outbound frame gets the upstream-collision check at all:
    /// transport only, with header protection on, an imitation protocol whose
    /// redraws are known to steer clear (see
    /// [`imitation_redraw_avoids_upstream_collisions`]), and a final wire
    /// length that admits at least one control reading upstream.
    ///
    /// Header protection off is skipped, deliberately: with no mask, a redraw
    /// changes only readings whose offset lies inside the S4 prefix, never
    /// those in the header or ciphertext, so prefix-only avoidance is not
    /// generally sufficient there. A broader strategy is out of scope.
    fn upstream_collision_applies(&self, kind: PacketKind, wire_len: usize) -> bool {
        kind == PacketKind::TransportData
            && self.header_protection_enabled()
            && imitation_redraw_avoids_upstream_collisions(self.imitation.protocol)
            && UPSTREAM_CONTROL_KINDS
                .iter()
                .any(|&(control, base)| self.upstream_control_length_fits(control, base, wire_len))
    }

    /// The upstream receivers' length test for one control kind: at least
    /// `S + base` with RandomTrailers on, exactly `S + base` with it off.
    fn upstream_control_length_fits(&self, kind: PacketKind, base: usize, wire_len: usize) -> bool {
        let need = self.inbound_junk_size(kind) + base;
        if self.random_trailers {
            wire_len >= need
        } else {
            wire_len == need
        }
    }

    /// Would an upstream AmneziaWG receiver take this transport datagram for an
    /// earlier control message?
    ///
    /// The AmneziaWG 3.1 kernel module (`awg_determine_type_and_padding`, as of
    /// amneziawg-linux-kernel-module 4569c4c) and amneziawg-go
    /// (`DeterminePacketTypeAndPadding`, as of b5928ef) classify a datagram by
    /// the first kind -- initiation, response, cookie reply, then transport --
    /// whose length test passes and whose tag, read at that kind's S offset
    /// and XORed with the same four header-protection mask bytes, falls in its
    /// H range. They commit to it before authenticating anything and never
    /// fall through, so a transport frame that also fits an earlier kind is
    /// dropped. `mask` is those four bytes for this datagram's nonce.
    ///
    /// Only the three control kinds are checked: a transport frame always
    /// passes the transport test, so "some control kind matches" is exactly
    /// "the receiver does not pick transport". Nothing is parsed, authenticated
    /// or range-checked beyond that, and every read is length-checked first --
    /// an offset may lie in the prefix, the transport header or the
    /// ciphertext, all of which the receiver reads alike.
    fn upstream_control_collision(
        &self,
        obf: ObfuscationRanges,
        datagram: &[u8],
        mask: [u8; TYPE_MASK_SIZE],
    ) -> bool {
        UPSTREAM_CONTROL_KINDS.iter().any(|&(kind, base)| {
            self.upstream_control_length_fits(kind, base, datagram.len())
                && Self::read_tag_masked(datagram, self.inbound_junk_size(kind), mask)
                    .is_some_and(|tag| Self::tag_matches(obf, kind, tag))
        })
    }

    /// An upstream receiver compatibility workaround: re-frame a transport
    /// datagram that `upstream_control_collision` says an upstream receiver
    /// would misread, by drawing a new S4 prefix -- a new header-protection
    /// nonce, so the mask every candidate tag is read through changes -- and
    /// masking the canonical header under it. The new prefix comes from the
    /// same filler as the first, so under protocol imitation every candidate
    /// is a fresh, equally valid instance of that protocol's prefix.
    ///
    /// `datagram` is the fully framed candidate 1, masked from `canonical`.
    /// Everything the protocol authenticates or counts is already final and
    /// is not touched here: the counter, the padding choice, the UDP-window
    /// observation, the ciphertext and its tag, the length. Only the prefix
    /// and the masked header change, and each candidate is masked once from
    /// the canonical header, never over a previous mask. At most
    /// `UPSTREAM_COLLISION_CANDIDATES` framings are tried in total, the
    /// original included; if every one collides -- extremely unlikely with
    /// ordinary ranges, but possible with pathological ranges or an unlucky
    /// sequence of draws -- the last is sent anyway: it is valid on the wire,
    /// and sending it is exactly what happened before this existed.
    ///
    /// Candidate 1's mask is recovered as the XOR of its canonical and masked
    /// type words rather than derived again, so the check costs no extra
    /// keystream block. The workaround does change the distribution of
    /// framings a transport datagram can have -- the colliding ones are no
    /// longer sent -- which a party knowing the S and H values may be able to
    /// observe statistically.
    fn avoid_upstream_control_collision(
        &self,
        obf: ObfuscationRanges,
        datagram: &mut [u8],
        junk_size: usize,
        canonical: &[u8; DATA_OFFSET_SZ],
        rng: &mut impl RngCore,
    ) {
        for candidate in 1..=UPSTREAM_COLLISION_CANDIDATES {
            let mut mask = [0u8; TYPE_MASK_SIZE];
            for (i, m) in mask.iter_mut().enumerate() {
                *m = canonical[i] ^ datagram[junk_size + i];
            }
            if candidate == UPSTREAM_COLLISION_CANDIDATES
                || !self.upstream_control_collision(obf, datagram, mask)
            {
                return;
            }
            datagram[junk_size..junk_size + DATA_OFFSET_SZ].copy_from_slice(canonical);
            let len = datagram.len();
            self.fill_outbound_junk(&mut datagram[..junk_size], len - junk_size, rng);
            // Cannot fail: candidate 1 was masked with the same sizes.
            let masked = self
                .header_protection
                .mask_outbound(datagram, junk_size, DATA_OFFSET_SZ);
            debug_assert!(masked);
        }
    }

    /// How long a RandomTrailers suffix a `kind` message whose mandatory frame
    /// is `base` bytes gets, in a `buffer_len`-byte buffer.
    ///
    /// Zero -- without touching `rng` -- unless RandomTrailers is on, the
    /// message is a handshake kind and the caller supplied `room`. Otherwise
    /// amneziawg-go's `randomTrailer`: a uniform draw from `0..(window - base)`,
    /// exclusive, so one byte of headroom still draws zero. Where the
    /// reference simply draws, this first intersects that range with every
    /// ceiling the suffix has to respect -- the buffer, the largest sendable
    /// datagram and `room.max_wire` -- and draws within what is left, so a
    /// ceiling narrows the distribution instead of refusing the packet.
    fn trailer_len(
        &self,
        kind: PacketKind,
        base: usize,
        buffer_len: usize,
        room: Option<TrailerRoom>,
        rng: &mut impl RngCore,
    ) -> usize {
        let Some(room) = room else { return 0 };
        if !self.random_trailers || kind == PacketKind::TransportData {
            return 0;
        }
        let headroom = (room.udp_window as usize).saturating_sub(base);
        let ceiling = buffer_len
            .min(MAX_SENDABLE_DATAGRAM)
            .min(room.max_wire)
            .saturating_sub(base);
        random_below(headroom.min(ceiling.saturating_add(1)), rng)
    }

    pub fn fill_pre_handshake_junk<'a>(
        &self,
        buffer: &'a mut [u8],
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        if !self.pre_handshake_junk.is_enabled() {
            return Ok(&mut buffer[..0]);
        }

        let size = self.pre_handshake_junk_size(rng);
        if buffer.len() < size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let packet = &mut buffer[..size];
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(packet, rng),
            AmneziaImitationProtocol::Dns => fill_dns(packet, 0, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Quic => fill_quic_initial(packet, rng),
            AmneziaImitationProtocol::Sip => fill_sip(packet, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Stun => fill_stun(packet, rng),
        }

        Ok(packet)
    }

    fn pre_handshake_junk_size(&self, rng: &mut impl RngCore) -> usize {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => random_usize_inclusive(
                self.pre_handshake_junk.packet_size_min as usize,
                self.pre_handshake_junk.packet_size_max as usize,
                rng,
            ),
            AmneziaImitationProtocol::Dns => {
                random_usize_inclusive(DNS_JUNK_SIZE_MIN, DNS_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Quic => {
                random_usize_inclusive(QUIC_JUNK_SIZE_MIN, QUIC_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Sip => {
                random_usize_inclusive(SIP_JUNK_SIZE_MIN, SIP_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Stun => {
                random_usize_inclusive(STUN_JUNK_SIZE_MIN, STUN_JUNK_SIZE_MAX, rng)
            }
        }
    }

    fn fill_outbound_junk(&self, dst: &mut [u8], trailing_size: usize, rng: &mut impl RngCore) {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(dst, rng),
            protocol => {
                fill_protocol_like(protocol, self.imitation.domain(), dst, trailing_size, rng)
            }
        }
    }
}

/// Whether redrawing a transport frame's S4 prefix under `protocol` reliably
/// moves it off an upstream control reading, so the upstream-collision
/// avoidance may retry it.
///
/// Decided per protocol from measurement of the production filler, not from
/// its shape alone, and matched exhaustively so that a new protocol cannot
/// become eligible without its own decision. A redraw helps only through the
/// header-protection nonce -- the prefix's first 12 bytes -- and whatever
/// else of the prefix a control reading covers:
///
/// * `None`: the prefix is uniformly random.
/// * `Quic`: a short header whose first byte takes 16 values and whose next
///   11 bytes are random, for every S4.
/// * `Stun`: bytes 8..12 are transaction-ID bytes, so 2^32 nonces.
/// * `Dns`: bytes 0..2 are the transaction ID, the rest of the header fixed,
///   so 65,536 nonces -- each a different mask, enough that sixteen framings
///   essentially never all collide, including when a control reading covers
///   the fixed query bytes.
/// * `Sip`: excluded. Once the prefix holds a request line (31 bytes or
///   more) its first 12 bytes are one of three -- `OPTIONS sip:`,
///   `REGISTER sip`, `MESSAGE sip:` -- and a control reading may cover the
///   fixed request text itself, so some frames have no framing an upstream
///   receiver reads as transport; measured, 16 framings exhausted for
///   roughly 0.16% of eligible frames across installer-style profiles.
///
/// Eligibility says only that the redraw fixes the upstream first-match
/// misreading. It says nothing about header-protection strength: a 16- or
/// 32-bit nonce space repeats the header mask far sooner than a random
/// prefix does, which is a separate property of those imitation modes.
fn imitation_redraw_avoids_upstream_collisions(protocol: AmneziaImitationProtocol) -> bool {
    match protocol {
        AmneziaImitationProtocol::None
        | AmneziaImitationProtocol::Quic
        | AmneziaImitationProtocol::Stun
        | AmneziaImitationProtocol::Dns => true,
        AmneziaImitationProtocol::Sip => false,
    }
}

/// Generate a plausible random host name when no domain is configured for an
/// imitation that needs one (DNS query name, SIP URI host, QUIC SNI).
fn random_imitation_domain(rng: &mut impl RngCore) -> String {
    const TLDS: [&str; 4] = ["com", "net", "org", "io"];
    let label_len = 7 + (rng.next_u32() % 10) as usize; // 7..=16 chars
    let mut host = String::with_capacity(label_len + 4);
    for _ in 0..label_len {
        host.push((b'a' + (rng.next_u32() % 26) as u8) as char);
    }
    host.push('.');
    host.push_str(TLDS[(rng.next_u32() as usize) % TLDS.len()]);
    host
}

/// A uniform draw from `0..n`, exclusive, and `0` for an empty range.
///
/// amneziawg-go's `fastrandn`, the draw its `randomTrailer` makes: the upper
/// bound is never produced, so one byte of headroom still draws 0, and no
/// headroom at all is 0 rather than a panic on an empty range.
fn random_below(n: usize, rng: &mut impl RngCore) -> usize {
    if n == 0 {
        return 0;
    }
    random_usize_inclusive(0, n - 1, rng)
}

fn random_usize_inclusive(min: usize, max: usize, rng: &mut impl RngCore) -> usize {
    if min >= max {
        return min;
    }

    let range_size = (max - min) as u64 + 1;
    let threshold = u64::MAX - (u64::MAX % range_size);
    loop {
        let val = rng.next_u64();
        if val < threshold {
            return min + (val % range_size) as usize;
        }
    }
}

fn fill_protocol_like(
    protocol: AmneziaImitationProtocol,
    domain: Option<&str>,
    dst: &mut [u8],
    trailing_size: usize,
    rng: &mut impl RngCore,
) {
    match protocol {
        AmneziaImitationProtocol::None => fill_random(dst, rng),
        AmneziaImitationProtocol::Dns => fill_dns(dst, trailing_size, domain, rng),
        // Always a 1-RTT short header, for every packet kind. A long header
        // carries a length field that would have to frame the bytes that
        // follow -- but those are the immutable WireGuard packet, which this
        // prefix cannot describe, so any long-header form parses as malformed.
        // A short header has no version or length field, so the remaining
        // bytes are indistinguishable from encrypted 1-RTT payload.
        //
        // The S-region is also far too small for a valid Initial: S2 + 92 and
        // S3 + 64 are nowhere near the 1200-byte minimum of RFC 9000 §14.1
        // (contrast `pre_handshake_junk_size`, where the QUIC branch picks
        // QUIC_JUNK_SIZE_MIN..=MAX = 1200..=1252 precisely so that a
        // long-header Initial is legal). And S2/S3 travel responder -> peer,
        // so emitting an Initial there inverts the direction of a real QUIC
        // handshake, where the Initial is the client's first packet.
        AmneziaImitationProtocol::Quic => fill_quic_short(dst, rng),
        AmneziaImitationProtocol::Sip => fill_sip(dst, domain, rng),
        AmneziaImitationProtocol::Stun => fill_stun(dst, rng),
    }
}

fn fill_random(dst: &mut [u8], rng: &mut impl RngCore) {
    let mut chunks = dst.chunks_exact_mut(4);
    for chunk in &mut chunks {
        chunk.copy_from_slice(&rng.next_u32().to_le_bytes());
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let bytes = rng.next_u32().to_le_bytes();
        rem.copy_from_slice(&bytes[..rem.len()]);
    }
}

fn random_byte(rng: &mut impl RngCore) -> u8 {
    (rng.next_u32() & 0xff) as u8
}

fn fill_quic_short(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.is_empty() {
        return;
    }

    let spin = ((rng.next_u32() >> 8) & 0x01) as u8;
    let key_phase = ((rng.next_u32() >> 8) & 0x01) as u8;
    let pn_len = (rng.next_u32() & 0x03) as u8;
    dst[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len;
    for byte in &mut dst[1..] {
        *byte = random_byte(rng);
    }
}

fn fill_quic_initial(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if !dst.is_empty() {
        dst[0] = 0xc0 | (rng.next_u32() & 0x03) as u8;
    }
    if dst.len() >= 5 {
        dst[1] = 0x00;
        dst[2] = 0x00;
        dst[3] = 0x00;
        dst[4] = 0x01;
    }
    if dst.len() >= 6 {
        dst[5] = ((rng.next_u32() % 17) + 4) as u8;
    }
}

fn fill_stun(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    let size = dst.len();

    if size >= 2 {
        dst[0] = 0x00;
        dst[1] = 0x01;
    }

    let body = if size > 20 { (size - 20) & !0x03 } else { 0 };
    let value_len = if body >= 4 { (body - 4).min(124) } else { 0 };
    let attr_len = if body >= 4 { 4 + value_len } else { 0 };

    if size >= 4 {
        let len = attr_len as u16;
        dst[2] = (len >> 8) as u8;
        dst[3] = len as u8;
    }
    if size >= 8 {
        dst[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    }
    if size > 8 {
        for byte in &mut dst[8..size.min(20)] {
            *byte = random_byte(rng);
        }
    }
    if attr_len >= 4 {
        let value_len = value_len as u16;
        dst[20] = 0x80;
        dst[21] = 0x22;
        dst[22] = (value_len >> 8) as u8;
        dst[23] = value_len as u8;
        for byte in &mut dst[24..24 + value_len as usize] {
            *byte = 0x20 + (random_byte(rng) % 0x5f);
        }
    }
    if size >= 20 + attr_len {
        for byte in &mut dst[20 + attr_len..] {
            *byte = random_byte(rng);
        }
    }
}

fn fill_sip(dst: &mut [u8], domain: Option<&str>, rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if dst.len() < SIP_REQUEST_LINE_MIN {
        return;
    }

    static SEEDS: [(&str, &str, &str); 6] = [
        ("OPTIONS", "u", "x"),
        ("OPTIONS", "100", "pbx"),
        ("REGISTER", "101", "gw"),
        ("MESSAGE", "noc", "lan"),
        ("OPTIONS", "m", "voip"),
        ("REGISTER", "sip", "edge"),
    ];

    let seed = SEEDS[(rng.next_u32() as usize) % SEEDS.len()];
    if run_sip_candidate_chain(dst, seed, domain, true, rng) {
        return;
    }
    let _ = run_sip_candidate_chain(dst, seed, domain, false, rng);
}

fn run_sip_candidate_chain(
    dst: &mut [u8],
    seed: (&str, &str, &str),
    domain: Option<&str>,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    if let Some(domain) = domain {
        if emit_sip(
            dst,
            seed.0,
            seed.1,
            &format!("{}.{}", seed.2, domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, seed.0, seed.1, domain, require_via, rng) {
            return true;
        }
        if emit_sip(
            dst,
            "OPTIONS",
            "u",
            &format!("x.{}", domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, "OPTIONS", "u", domain, require_via, rng) {
            return true;
        }
    }

    emit_sip(dst, seed.0, seed.1, seed.2, require_via, rng)
        || emit_sip(dst, "OPTIONS", "u", "x", require_via, rng)
}

fn emit_sip(
    dst: &mut [u8],
    method: &str,
    user: &str,
    host: &str,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    let token = rng.next_u32();
    let mut pos = 0usize;

    if !put_sip_line(
        dst,
        &mut pos,
        &format!("{method} sip:{user}@{host} SIP/2.0\r\n"),
    ) {
        return false;
    }

    let via_ok = put_sip_line(
        dst,
        &mut pos,
        &format!("Via: SIP/2.0/UDP {host};branch=z9hG4bK{token:08x}\r\n"),
    );
    if require_via && !via_ok {
        return false;
    }

    if via_ok {
        let _ = put_sip_line(dst, &mut pos, "Max-Forwards: 70\r\n")
            && put_sip_line(
                dst,
                &mut pos,
                &format!("From: <sip:{user}@{host}>;tag={:04x}\r\n", token & 0xffff),
            )
            && put_sip_line(dst, &mut pos, &format!("To: <sip:{user}@{host}>\r\n"))
            && put_sip_line(dst, &mut pos, &format!("Call-ID: {token:08x}@{host}\r\n"))
            && put_sip_line(dst, &mut pos, &format!("CSeq: 1 {method}\r\n"));
    }

    dst[pos] = b'\r';
    dst[pos + 1] = b'\n';
    pos += 2;
    for byte in &mut dst[pos..] {
        *byte = b' ';
    }
    true
}

fn put_sip_line(dst: &mut [u8], pos: &mut usize, line: &str) -> bool {
    let add = line.len();
    if *pos + add + 2 > dst.len() {
        return false;
    }
    dst[*pos..*pos + add].copy_from_slice(line.as_bytes());
    *pos += add;
    true
}

fn fill_dns(dst: &mut [u8], trailing_size: usize, domain: Option<&str>, rng: &mut impl RngCore) {
    let size = dst.len();
    if size == 0 {
        return;
    }
    let total_len = size.saturating_add(trailing_size);

    if let Some(domain) = domain {
        let max_qname = size.saturating_sub(16);
        if let Some(name) = choose_dns_domain_qname(domain, max_qname, DNS_OPT_MIN_WIRE_SIZE, rng) {
            if emit_dns_domain(dst, total_len, &name, rng) {
                return;
            }
        }
    }

    if trailing_size > 0 && size >= 12 + 1 + 4 + DNS_OPT_MIN_WIRE_SIZE {
        let mut pos = write_dns_header(dst, rng);
        dst[pos] = 0x00;
        pos += 1;
        write_dns_question_tail(dst, &mut pos);
        if write_dns_opt_padding(dst, size, total_len, &mut pos, 10) {
            return;
        }
    }

    fill_dns_minimal_root_query(dst, rng);
}

fn emit_dns_domain(dst: &mut [u8], total_len: usize, name: &str, rng: &mut impl RngCore) -> bool {
    let qname_size = dns_qname_wire_size(name);
    if qname_size == 0 || dst.len() < 12 + qname_size + 4 + DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }

    let mut pos = write_dns_header(dst, rng);
    if !write_dns_qname(dst, &mut pos, name) {
        return false;
    }
    write_dns_question_tail(dst, &mut pos);
    write_dns_opt_padding(dst, dst.len(), total_len, &mut pos, 10)
}

fn fill_dns_minimal_root_query(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.len() >= 2 {
        dst[0] = random_byte(rng);
        dst[1] = random_byte(rng);
    }
    if dst.len() >= 4 {
        // Flags 0x0120 (RD+AD): S-prefix DNS shaping matching wgbooster's
        // protocol-aware padding (Windows DNS Client); see write_dns_header.
        dst[2] = 0x01;
        dst[3] = 0x20;
    }
    if dst.len() >= 6 {
        dst[4] = 0x00;
        dst[5] = 0x01;
    }
    let header_tail_end = dst.len().min(12);
    if header_tail_end > 6 {
        for byte in &mut dst[6..header_tail_end] {
            *byte = 0x00;
        }
    }
    if dst.len() > 12 {
        dst[12] = 0x00;
    }
    if dst.len() > 13 {
        dst[13] = 0x00;
    }
    if dst.len() > 14 {
        dst[14] = 0x01;
    }
    if dst.len() > 15 {
        dst[15] = 0x00;
    }
    if dst.len() > 16 {
        dst[16] = 0x01;
    }
    if dst.len() > 17 {
        for byte in &mut dst[17..] {
            *byte = 0x00;
        }
    }
}

fn write_dns_header(dst: &mut [u8], rng: &mut impl RngCore) -> usize {
    dst[0] = random_byte(rng);
    dst[1] = random_byte(rng);
    // Flags 0x0120 (RD=1, AD=1): this is the S1-S4 prefix DNS shaping, which
    // faithfully matches wgbooster's `protocol_aware_padding_generator` (it sets
    // AD to mimic the Windows DNS Client). The standalone pre-handshake DNS
    // queries in `imitation::dns` deliberately use 0x0100 (RD only) instead, to
    // match wgbooster's live-query path (`simulate_browser_dns_resolution`).
    dst[2] = 0x01;
    dst[3] = 0x20;
    dst[4] = 0x00;
    dst[5] = 0x01;
    for byte in &mut dst[6..12] {
        *byte = 0x00;
    }
    12
}

fn write_dns_question_tail(dst: &mut [u8], pos: &mut usize) {
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x01;
    dst[*pos + 2] = 0x00;
    dst[*pos + 3] = 0x01;
    *pos += 4;
}

fn dns_qname_wire_size(name: &str) -> usize {
    if is_valid_imitation_host(name) {
        name.len() + 2
    } else {
        0
    }
}

fn write_dns_qname(dst: &mut [u8], pos: &mut usize, name: &str) -> bool {
    let wire_size = dns_qname_wire_size(name);
    if wire_size == 0 || *pos > dst.len() || wire_size > dst.len() - *pos {
        return false;
    }

    for label in name.split('.') {
        let label_len = label.len();
        if label_len == 0 || label_len > 63 || *pos + 1 + label_len > dst.len() {
            return false;
        }
        dst[*pos] = label_len as u8;
        *pos += 1;
        dst[*pos..*pos + label_len].copy_from_slice(label.as_bytes());
        *pos += label_len;
    }
    if *pos >= dst.len() {
        return false;
    }
    dst[*pos] = 0x00;
    *pos += 1;
    true
}

fn choose_dns_domain_qname(
    domain: &str,
    max_wire_size: usize,
    opt_reserve: usize,
    rng: &mut impl RngCore,
) -> Option<String> {
    if !is_valid_imitation_host(domain) {
        return None;
    }

    const PREFIXES: [&str; 5] = ["www", "api", "cdn", "dns", ""];
    let start = (rng.next_u32() as usize) % PREFIXES.len();
    let budgets = [
        if opt_reserve > 0 && opt_reserve <= max_wire_size {
            max_wire_size - opt_reserve
        } else {
            0
        },
        max_wire_size,
    ];

    for budget in budgets {
        if budget == 0 {
            continue;
        }
        for i in 0..PREFIXES.len() {
            let prefix = PREFIXES[(start + i) % PREFIXES.len()];
            let candidate = if prefix.is_empty() {
                domain.to_owned()
            } else {
                format!("{prefix}.{domain}")
            };
            let wire_size = dns_qname_wire_size(&candidate);
            if wire_size > 0 && wire_size <= budget {
                return Some(candidate);
            }
        }
    }

    None
}

fn write_dns_opt_padding(
    dst: &mut [u8],
    write_limit: usize,
    total_len: usize,
    pos: &mut usize,
    arcount_pos: usize,
) -> bool {
    if total_len < write_limit {
        return false;
    }
    if *pos > write_limit || write_limit - *pos < DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }
    if arcount_pos >= write_limit.saturating_sub(1) {
        return false;
    }
    if total_len - *pos - DNS_OPT_FIXED_LEN > 0xffff {
        return false;
    }

    let option_code = if total_len > write_limit {
        0xfde9u16
    } else {
        0x000cu16
    };

    // EDNS(0) OPT pseudo-record: root NAME (0x00), TYPE=OPT (0x0029),
    // CLASS=requestor UDP payload size (0x1000), TTL=0 (extended RCODE/flags).
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x00;
    dst[*pos + 2] = 0x29;
    dst[*pos + 3] = 0x10;
    dst[*pos + 4] = 0x00;
    dst[*pos + 5] = 0x00;
    dst[*pos + 6] = 0x00;
    dst[*pos + 7] = 0x00;
    dst[*pos + 8] = 0x00;
    *pos += 9;

    let rdata_len = total_len - *pos - 2;
    dst[*pos] = ((rdata_len >> 8) & 0xff) as u8;
    dst[*pos + 1] = (rdata_len & 0xff) as u8;
    *pos += 2;

    let pad_value_len = rdata_len - 4;
    dst[*pos] = (option_code >> 8) as u8;
    dst[*pos + 1] = option_code as u8;
    dst[*pos + 2] = ((pad_value_len >> 8) & 0xff) as u8;
    dst[*pos + 3] = (pad_value_len & 0xff) as u8;
    *pos += 4;

    while *pos < write_limit {
        dst[*pos] = 0x00;
        *pos += 1;
    }

    dst[arcount_pos] = 0x00;
    dst[arcount_pos + 1] = 0x01;
    true
}

/// Permissive validation for a QUIC ClientHello SNI: unlike DNS QNAMEs and SIP
/// URIs, the SNI is a length-prefixed TLS extension, so UTF-8/IDN host names are
/// accepted (matching wgbooster). Only emptiness, the 253-byte RFC 1035 bound,
/// and control bytes (which never appear in a real SNI) are rejected.
fn is_valid_quic_sni(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && !host.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn is_valid_imitation_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.starts_with('-')
        || host.ends_with('.')
        || host.ends_with('-')
    {
        return false;
    }

    let mut label_len = 0usize;
    let mut label_start = true;
    let mut previous_hyphen = false;

    for byte in host.bytes() {
        if byte == b'.' {
            if label_len == 0 || previous_hyphen {
                return false;
            }
            label_len = 0;
            label_start = true;
            previous_hyphen = false;
            continue;
        }

        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
        if label_start && byte == b'-' {
            return false;
        }

        label_len += 1;
        if label_len > 63 {
            return false;
        }
        label_start = false;
        previous_hyphen = byte == b'-';
    }

    label_len > 0 && !previous_hyphen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{COOKIE_REPLY, DATA, HANDSHAKE_INIT, HANDSHAKE_RESP};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    /// The suffix length: zero, and no draw at all, unless RandomTrailers is on
    /// for a handshake kind with room supplied; otherwise below the window,
    /// exclusive, and inside every ceiling at once.
    #[test]
    fn trailer_len_is_drawn_inside_every_ceiling() {
        let off = AmneziaConfig::new(0, 0, 0, 0);
        let on = off.clone().with_random_trailers(true);
        let room = Some(TrailerRoom::window(DEFAULT_UDP_WINDOW));
        let init = PacketKind::HandshakeInit;

        // Off, transport, or no room: zero, and the RNG is not touched -- so
        // every 3.0 wire stays byte-identical under a seeded RNG.
        let mut a = ChaCha8Rng::seed_from_u64(1);
        let b = a.clone();
        assert_eq!(off.trailer_len(init, 148, 4096, room, &mut a), 0);
        assert_eq!(
            on.trailer_len(PacketKind::TransportData, 148, 4096, room, &mut a),
            0
        );
        assert_eq!(on.trailer_len(init, 148, 4096, None, &mut a), 0);
        assert_eq!(a, b, "no draw may be made when no trailer is possible");

        let mut rng = ChaCha8Rng::seed_from_u64(2);
        for _ in 0..200 {
            // The window: exclusive, so one byte of headroom draws zero.
            assert!(on.trailer_len(init, 148, 4096, room, &mut rng) < 500 - 148);
            assert_eq!(on.trailer_len(init, 499, 4096, room, &mut rng), 0);
            assert_eq!(on.trailer_len(init, 500, 4096, room, &mut rng), 0);
            assert_eq!(on.trailer_len(init, 900, 4096, room, &mut rng), 0);
            // The buffer.
            assert!(on.trailer_len(init, 148, 148 + 5, room, &mut rng) <= 5);
            assert_eq!(on.trailer_len(init, 148, 148, room, &mut rng), 0);
            assert_eq!(on.trailer_len(init, 148, 100, room, &mut rng), 0);
            // The largest sendable datagram, however wide the window.
            let wide = Some(TrailerRoom::window(u32::MAX));
            let near = MAX_SENDABLE_DATAGRAM - 3;
            assert!(on.trailer_len(init, near, usize::MAX, wide, &mut rng) <= 3);
            assert_eq!(
                on.trailer_len(init, MAX_SENDABLE_DATAGRAM, usize::MAX, wide, &mut rng),
                0
            );
            // A cookie reply: the fixed window, and never past the request.
            let reply = PacketKind::CookieReply;
            let to_request = |len| Some(TrailerRoom::cookie_reply(len));
            assert!(on.trailer_len(reply, 64, 4096, to_request(64 + 3), &mut rng) <= 3);
            assert_eq!(on.trailer_len(reply, 64, 4096, to_request(64), &mut rng), 0);
            assert_eq!(on.trailer_len(reply, 64, 4096, to_request(10), &mut rng), 0);
            assert!(on.trailer_len(reply, 64, 4096, to_request(60_000), &mut rng) < 500 - 64);
        }
        // Within a ceiling the whole range is still reachable, the ceiling included.
        let seen: std::collections::BTreeSet<usize> = (0..400)
            .map(|_| on.trailer_len(init, 148, 148 + 3, room, &mut rng))
            .collect();
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    /// The suffix follows the canonical message, outside header protection:
    /// the receiver recovers exactly the canonical bytes, whatever the suffix
    /// holds. With no S prefix and no key the suffix is still added -- the
    /// early return for "nothing to frame" does not swallow it.
    #[test]
    fn the_suffix_follows_the_masked_core_and_is_not_masked() {
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let mut canonical = vec![0u8; HANDSHAKE_INIT_SZ];
        canonical[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
        for (i, b) in canonical[4..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let room = Some(TrailerRoom::window(DEFAULT_UDP_WINDOW));

        for cfg in [
            AmneziaConfig::new(40, 24, 32, 160).with_header_protection([0x5a; 32]),
            AmneziaConfig::new(40, 24, 32, 160),
            AmneziaConfig::new(0, 0, 0, 0),
        ] {
            let cfg = cfg.with_random_trailers(true);
            let s1 = cfg.init_packet_junk_size as usize;
            let mut longest = 0;
            for _ in 0..64 {
                let mut buffer = vec![0u8; 2048];
                buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&canonical);
                let mut wire = cfg
                    .prepend_outbound_with_trailer(
                        obf,
                        &mut buffer,
                        HANDSHAKE_INIT_SZ,
                        room,
                        &mut rng,
                    )
                    .unwrap()
                    .to_vec();
                assert!(wire.len() >= s1 + HANDSHAKE_INIT_SZ && wire.len() < 500);
                longest = longest.max(wire.len());
                // Rewrite the suffix: the canonical message is unaffected.
                let end = wire.len();
                wire[s1 + HANDSHAKE_INIT_SZ..end].fill(0x99);
                let found = cfg.inbound_candidates(obf, &wire);
                let reading = found.iter().next().expect("our own initiation");
                let mut scratch = Vec::new();
                assert_eq!(
                    cfg.candidate_message(&wire, reading, &mut scratch).unwrap(),
                    &canonical[..]
                );
            }
            assert!(
                longest > s1 + HANDSHAKE_INIT_SZ,
                "a suffix must be drawn: {}",
                longest
            );
        }
    }

    /// The mandatory frame is still the only thing that can fail for space:
    /// exactly enough buffer sends it with no suffix, one byte less refuses it.
    #[test]
    fn only_the_mandatory_frame_can_fail_for_space() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(40, 24, 32, 160).with_random_trailers(true);
        let room = Some(TrailerRoom::window(u32::MAX));
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let mut make = |len: usize| {
            let mut buffer = vec![0u8; len];
            buffer[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
            cfg.prepend_outbound_with_trailer(obf, &mut buffer, HANDSHAKE_INIT_SZ, room, &mut rng)
                .map(|w| w.len())
        };
        assert!(matches!(make(40 + HANDSHAKE_INIT_SZ), Ok(n) if n == 40 + HANDSHAKE_INIT_SZ));
        assert!(matches!(
            make(40 + HANDSHAKE_INIT_SZ - 1),
            Err(WireGuardError::DestinationBufferTooSmall)
        ));
        for _ in 0..32 {
            assert!(make(40 + HANDSHAKE_INIT_SZ + 2).unwrap() <= 40 + HANDSHAKE_INIT_SZ + 2);
        }
    }

    /// RandomTrailers is off unless asked for, and the builder switches it both
    /// ways without touching anything else.
    #[test]
    fn random_trailers_defaults_off_and_toggles() {
        let base = AmneziaConfig::new(52, 108, 136, 148);
        assert!(!base.random_trailers);
        assert!(!AmneziaConfig::default().random_trailers);
        let on = base.clone().with_random_trailers(true);
        assert!(on.random_trailers);
        assert_eq!(on.clone().with_random_trailers(false), base);
    }

    /// DisableCookies is off unless asked for, and is its own switch: it moves
    /// nothing else, and nothing else moves it.
    #[test]
    fn disable_cookies_defaults_off_and_toggles_independently() {
        let base = AmneziaConfig::new(52, 108, 136, 148);
        assert!(!base.disable_cookies);
        assert!(!AmneziaConfig::default().disable_cookies);
        assert_eq!(base.cookie_defense(), CookieDefense::Armed);

        let off = base.clone().with_disable_cookies(true);
        assert!(off.disable_cookies);
        assert_eq!(off.cookie_defense(), CookieDefense::Bypassed);
        assert_eq!(off.clone().with_disable_cookies(false), base);

        // Composes with every other 3.x setting in either order.
        let full = base
            .clone()
            .with_random_trailers(true)
            .with_header_protection([7; 32])
            .with_content_padding_addition(8, 24, 1420)
            .with_tunable_timers(AwgTimers {
                rekey_after_time: (30, 40),
                ..AwgTimers::default()
            });
        let full_off = full.clone().with_disable_cookies(true);
        assert!(full_off.random_trailers);
        assert_eq!(full_off.header_protection, full.header_protection);
        assert_eq!(full_off.content_padding_addition, (8, 24));
        assert_eq!(full_off.timers, full.timers);
        assert_eq!(full_off.clone().with_disable_cookies(false), full);
        assert!(
            base.clone()
                .with_disable_cookies(true)
                .with_random_trailers(false)
                .disable_cookies
        );
        assert!(full_off.validate().is_ok());
    }

    /// Every field classified for a burst in flight: the three that were
    /// captured when it was built restart it; every other field keeps it, and
    /// so does no change at all.
    #[test]
    fn a_burst_restarts_only_for_what_it_captured() {
        use PendingBurstChange::{Keep, Restart};
        let base = AmneziaConfig::new(52, 108, 136, 148).with_pre_handshake_junk(3, 64, 64, 100);
        assert_eq!(base.pending_burst_change(&base), Keep, "no change");

        let with = |f: &dyn Fn(&mut AmneziaConfig)| {
            let mut c = base.clone();
            f(&mut c);
            c
        };
        let cases: Vec<(&str, AmneziaConfig, PendingBurstChange)> = vec![
            ("s1", with(&|c| c.init_packet_junk_size += 1), Keep),
            ("s2", with(&|c| c.response_packet_junk_size += 1), Keep),
            ("s3", with(&|c| c.cookie_packet_junk_size += 1), Keep),
            ("s4", with(&|c| c.transport_packet_junk_size += 1), Keep),
            (
                "jmin/jmax",
                base.clone().with_pre_handshake_junk(3, 80, 90, 100),
                Keep,
            ),
            (
                "jd",
                base.clone().with_pre_handshake_junk(3, 64, 64, 30),
                Keep,
            ),
            (
                "header protection",
                base.clone().with_header_protection([9; 32]),
                Keep,
            ),
            (
                "padding",
                base.clone().with_content_padding_addition(8, 24, 0),
                Keep,
            ),
            (
                "padding mtu",
                base.clone().with_content_padding_addition(0, 0, 1280),
                Keep,
            ),
            (
                "timers",
                base.clone().with_tunable_timers(AwgTimers {
                    rekey_after_time: (30, 40),
                    ..AwgTimers::default()
                }),
                Keep,
            ),
            (
                "random trailers",
                base.clone().with_random_trailers(true),
                Keep,
            ),
            (
                "disable cookies",
                base.clone().with_disable_cookies(true),
                Keep,
            ),
            (
                "jc",
                base.clone().with_pre_handshake_junk(5, 64, 64, 100),
                Restart,
            ),
            (
                "jc to 0",
                base.clone().with_pre_handshake_junk(0, 64, 64, 100),
                Restart,
            ),
            (
                "imitation protocol",
                base.clone()
                    .with_protocol_imitation(AmneziaImitationProtocol::Dns, None),
                Restart,
            ),
            (
                "imitation domain",
                base.clone().with_protocol_imitation(
                    AmneziaImitationProtocol::Dns,
                    Some("example.com".into()),
                ),
                Restart,
            ),
            (
                "imitation browser",
                base.clone().with_protocol_imitation_browser(
                    AmneziaImitationProtocol::Quic,
                    None,
                    AmneziaImitationBrowser::Chrome,
                ),
                Restart,
            ),
            ("responder", base.clone().as_responder(), Restart),
        ];
        for (name, next, want) in cases {
            assert_eq!(base.pending_burst_change(&next), want, "{}", name);
            // A Keep-class change riding along does not soften a Restart.
            if want == Restart {
                assert_eq!(
                    base.pending_burst_change(&next.clone().with_random_trailers(true)),
                    Restart,
                    "{} with RT",
                    name
                );
            }
        }
        // Between two imitation configurations, too.
        let dns = base
            .clone()
            .with_protocol_imitation(AmneziaImitationProtocol::Dns, None);
        let stun = base
            .clone()
            .with_protocol_imitation(AmneziaImitationProtocol::Stun, None);
        assert_eq!(dns.pending_burst_change(&stun), Restart);
        assert_eq!(dns.pending_burst_change(&dns.clone()), Keep);
    }

    /// The cookie-reflection complaint is about replies this end would emit.
    /// With DisableCookies on it emits none, so an amplifying S3 draws no
    /// complaint; the same sizes draw it again the moment cookies are back on.
    /// `validate` is not the complaint and does not change with the flag.
    #[test]
    fn the_cookie_complaint_applies_only_while_cookies_are_on() {
        let amplifying = AmneziaConfig::new(0, 0, 100, 0);
        assert!(amplifying.cookie_amplification_complaint().is_some());
        let off = amplifying.clone().with_disable_cookies(true);
        assert_eq!(off.cookie_amplification_complaint(), None);
        assert!(off
            .clone()
            .with_disable_cookies(false)
            .cookie_amplification_complaint()
            .is_some());
        // The size arithmetic itself is untouched: the reply would still be
        // larger than its request, which is what the runtime guard reads.
        assert!(off.cookie_reply_would_amplify(COOKIE_REPLY_SZ, HANDSHAKE_INIT_SZ));

        // Universal validity is unconditional: an S3 that cannot frame a
        // cookie reply at all is refused either way, because a peer may still
        // send us one.
        let unframable = AmneziaConfig::new(0, 0, u16::MAX, 0);
        assert!(unframable.validate().is_err());
        assert!(unframable.with_disable_cookies(true).validate().is_err());

        // And a configuration that does not amplify is clean either way.
        let clean = AmneziaConfig::new(100, 40, 20, 160);
        assert_eq!(clean.cookie_amplification_complaint(), None);
        assert_eq!(
            clean
                .with_disable_cookies(true)
                .cookie_amplification_complaint(),
            None
        );
    }

    /// `random_below` is amneziawg-go's `fastrandn`: exclusive, and zero for an
    /// empty range rather than a panic.
    #[test]
    fn random_below_is_exclusive_and_total() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        for _ in 0..64 {
            assert_eq!(random_below(0, &mut rng), 0);
            assert_eq!(
                random_below(1, &mut rng),
                0,
                "one byte of room still draws 0"
            );
            assert!(random_below(5, &mut rng) < 5);
        }
    }

    /// The two window observations, and the sixteen bytes between them: a
    /// sent frame counts its whole unpadded size, a received one counts its
    /// header and padded plaintext but not its AEAD tag. The reference's
    /// numbers, reproduced rather than reconciled -- see
    /// `received_window_observation`.
    #[test]
    fn the_receive_window_observation_is_sixteen_short_of_the_datagram() {
        let cfg = AmneziaConfig::new(0, 0, 0, 148);
        assert_eq!(cfg.transport_window_observation(0), 148 + 32);
        assert_eq!(cfg.transport_window_observation(1000), 148 + 32 + 1000);
        // A 1000-byte padded plaintext arrives as a 148 + 16 + 1000 + 16 byte
        // datagram, and is recorded as 16 bytes less than that.
        let datagram = 148 + 16 + 1000 + 16;
        assert_eq!(cfg.received_window_observation(1000), datagram - 16);
    }

    /// With RandomTrailers on, the padding precedence is by selection:
    /// an active `content_padding_addition` range decides, else RandomTrailers,
    /// and a zero from either is final -- neither falls through to the 16-byte
    /// rounding.
    #[test]
    fn window_padding_precedence_is_by_selection_not_by_amount() {
        let rt = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let mut rng = ChaCha8Rng::seed_from_u64(9);

        // RandomTrailers alone, with no room: 0, not the 16-byte rounding a
        // 20-byte plaintext would otherwise get (12 bytes).
        let base = 32 + 20;
        assert_eq!(rt.window_padding(base, base as u32, &mut rng), 0);
        assert_eq!(
            rt.content_padding(20, 4096, &mut rng),
            12,
            "what it would have been"
        );
        // One byte of room still draws 0; more is drawn below the window.
        assert_eq!(rt.window_padding(base, base as u32 + 1, &mut rng), 0);
        for _ in 0..64 {
            assert!(rt.window_padding(base, 500, &mut rng) < 500 - base);
        }

        // An active range that can draw zero: every result is the range's,
        // never a RandomTrailers draw against 448 bytes of room.
        let cpa = rt.clone().with_content_padding_addition(0, 1, 1420);
        let draws: Vec<usize> = (0..200)
            .map(|_| cpa.window_padding(base, 500, &mut rng))
            .collect();
        assert!(draws.iter().all(|&d| d <= 1), "{:?}", draws);
        assert!(
            draws.contains(&0),
            "the range must be able to draw zero here"
        );

        // The range is capped by the window, not by the MTU unit.
        let wide = rt.with_content_padding_addition(400, 400, 1420);
        assert_eq!(wide.window_padding(132, 500, &mut rng), 500 - 132);
    }

    /// A 3.0 configuration pads exactly as before 3.1 existed; only one that
    /// turned RandomTrailers on draws against the window. The concrete case
    /// the two models disagree on: a 100-byte plaintext, a constant 400-byte
    /// addition, a 1420-byte MTU and a 500-byte window -- the MTU unit leaves
    /// room for all 400, the window for only 368.
    #[test]
    fn content_padding_keeps_its_3_0_meaning_unless_random_trailers_is_on() {
        let legacy = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(400, 400, 1420);
        let rt = legacy.clone().with_random_trailers(true);
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let window = DEFAULT_UDP_WINDOW;

        assert_eq!(
            legacy.content_padding_for_frame(100, 4096, 0, window, &mut rng),
            400,
            "RandomTrailers off: the MTU-unit clamp, exactly as in 3.0"
        );
        assert_eq!(
            legacy.content_padding_for_frame(100, 4096, 0, window, &mut rng),
            legacy.content_padding(100, 4096 - 132, &mut rng),
            "and by the very same function"
        );
        assert_eq!(
            rt.content_padding_for_frame(100, 4096, 0, window, &mut rng),
            500 - 132,
            "RandomTrailers on: the window clamp"
        );
        // The window is read only when RandomTrailers is on.
        assert_eq!(
            legacy.content_padding_for_frame(100, 4096, 0, 60_000, &mut rng),
            400
        );
    }

    /// The window model never pads past the caller's buffer or the largest
    /// sendable datagram, however wide the window has grown.
    #[test]
    fn window_padding_is_bounded_by_the_buffer_and_the_datagram_limit() {
        let rt = AmneziaConfig::new(0, 0, 0, 0)
            .with_random_trailers(true)
            .with_content_padding_addition(60_000, 60_000, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        assert_eq!(
            rt.content_padding_for_frame(100, 200, 0, u32::MAX, &mut rng),
            200 - 132
        );
        let near_max = MAX_SENDABLE_DATAGRAM - 32 - 10;
        assert_eq!(
            rt.content_padding_for_frame(near_max, usize::MAX, 0, u32::MAX, &mut rng),
            10
        );
        assert_eq!(
            rt.content_padding_for_frame(MAX_SENDABLE_DATAGRAM, usize::MAX, 0, u32::MAX, &mut rng),
            0
        );
    }

    fn write_tag(packet: &mut [u8], tag: u32) {
        packet[..4].copy_from_slice(&tag.to_le_bytes());
    }

    fn packet_after_prepend(
        cfg: &AmneziaConfig,
        packet_size: usize,
        tag: u32,
        capacity: usize,
    ) -> Vec<u8> {
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; capacity];
        write_tag(&mut buffer, tag);
        buffer[4] = 0x42;

        cfg.prepend_outbound(obf, &mut buffer, packet_size, &mut rng)
            .unwrap()
            .to_vec()
    }

    fn expected_junk(cfg: &AmneziaConfig, tag: u32) -> usize {
        let size = match tag {
            HANDSHAKE_INIT => cfg.init_packet_junk_size,
            HANDSHAKE_RESP => cfg.response_packet_junk_size,
            COOKIE_REPLY => cfg.cookie_packet_junk_size,
            DATA => cfg.transport_packet_junk_size,
            _ => unreachable!(),
        };
        size as usize
    }

    /// For every packet kind, S-size combination, and imitation protocol, a
    /// packet that is prefixed by `prepend_outbound` must be recovered exactly
    /// by `strip_inbound`. This is the core invariant the wire protocol relies
    /// on, and it exercises every protocol-shaped filler against the stripper.
    #[test]
    fn prepend_then_strip_roundtrips_across_configs_and_protocols() {
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
        ];

        for base in bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut original = vec![0u8; base_size];
                    write_tag(&mut original, tag);
                    for (i, byte) in original[4..].iter_mut().enumerate() {
                        *byte = (i as u8) ^ 0x5a;
                    }

                    let mut buffer = vec![0u8; base_size + 1280];
                    buffer[..base_size].copy_from_slice(&original);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();

                    let junk = expected_junk(&cfg, tag);
                    assert_eq!(
                        padded.len(),
                        base_size + junk,
                        "unexpected padded size: protocol={protocol:?} tag={tag} junk={junk}"
                    );

                    // Every shape produced by prepend_outbound must be accepted:
                    // this is the property that makes the stricter filter safe.
                    let stripped = cfg.strip_inbound(obf, &padded);
                    assert_eq!(
                        stripped,
                        Some(original.as_slice()),
                        "roundtrip mismatch: protocol={protocol:?} tag={tag} junk={junk}"
                    );
                }
            }
        }
    }

    /// What our own outbound cover traffic looks like to the probe detector.
    ///
    /// This table is the reason a server must classify AmneziaWG *before* it
    /// considers answering a probe. Three properties, all observed rather than
    /// assumed -- the verdicts were printed first and locked in afterwards:
    ///
    /// 1. **No cross-protocol confusion.** Across every protocol x packet kind
    ///    x S-size combination, the verdict is either `None` or the protocol we
    ///    configured. Our DNS cover traffic is never mistaken for STUN, and so
    ///    on. This is the safety property and it holds unconditionally.
    ///
    /// 2. **DNS and SIP cover traffic is detected as a probe.** At realistic S
    ///    sizes -- the installer rolls S1-S4 in 15..150 -- a datagram we emit
    ///    under `ip=dns` is a well-formed DNS query, because `fill_dns` frames
    ///    the WireGuard ciphertext inside an EDNS OPT padding option. A server
    ///    that asked "is this a probe?" first would answer its own clients
    ///    instead of handshaking with them, and would do so *more* often the
    ///    better the imitation became.
    ///
    /// 3. **QUIC and STUN are never self-detected**, and both are structural
    ///    rather than incidental:
    ///    - `fill_quic_short` writes a 1-RTT short header, so the leading two
    ///      bits are `0b01` and the long-header test cannot fire.
    ///    - `fill_stun` frames `msg_len` over the junk region only, while the
    ///      datagram continues with the WireGuard packet, so the detector's
    ///      `len == 20 + msg_len` check fails.
    ///
    ///    Both are worth pinning: this test fails the day someone extends
    ///    `fill_stun` to frame the whole datagram, or reverts S2/S3 to a QUIC
    ///    long header -- changes that would look like fidelity improvements
    ///    while silently making the server answer its own peers.
    #[test]
    fn our_cover_traffic_is_detected_as_the_protocol_we_imitate() {
        use crate::noise::imitation::detect::{detect, Probe};
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        // The last entry mirrors what `amneziawg-install` actually generates.
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
            AmneziaConfig::new(120, 130, 110, 80),
        ];

        let mut self_detected = 0usize;

        for base in &bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut buffer = vec![0u8; base_size + 1280];
                    write_tag(&mut buffer, tag);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();
                    let junk = expected_junk(&cfg, tag);
                    let verdict = detect(&padded);

                    // Checked before the generic cross-protocol assertion
                    // below, which would otherwise fire first here and report
                    // "cover traffic for None detected as Dns" -- true, but a
                    // worse description of the failure than this one. Random
                    // junk resembling any probe means the detector is too
                    // loose, and that is what a reader needs told.
                    if protocol == None {
                        assert!(
                            verdict.is_none(),
                            "random junk was detected as {:?} (junk={}, tag={})",
                            verdict,
                            junk,
                            tag
                        );
                    }

                    // (1) never a *different* protocol.
                    if let Some(p) = verdict {
                        assert!(
                            p.is(protocol),
                            "cover traffic for {:?} detected as {:?} (junk={}, tag={})",
                            protocol,
                            p,
                            junk,
                            tag
                        );
                        self_detected += 1;
                    }

                    // (3) QUIC and STUN never frame the whole datagram.
                    if matches!(protocol, Quic | Stun) {
                        assert!(
                            verdict.is_none(),
                            "{:?} imitation became self-detecting (junk={}, tag={}); see this test's doc comment before changing it",
                            protocol,
                            junk,
                            tag
                        );
                    }
                }
            }
        }

        // (2) the hazard is real, not hypothetical: at installer-realistic S
        // sizes every DNS and SIP datagram we emit is a valid probe. Asserted
        // as a count so the test fails if imitation quietly stops working, not
        // only if it starts misfiring.
        let realistic = AmneziaConfig::new(120, 130, 110, 80);
        for protocol in [Dns, Sip] {
            let cfg = realistic
                .clone()
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let mut rng = ChaCha8Rng::seed_from_u64(0xA53);
            for &(tag, base_size) in &kinds {
                let mut buffer = vec![0u8; base_size + 1280];
                write_tag(&mut buffer, tag);
                let padded = cfg
                    .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                    .unwrap()
                    .to_vec();
                let verdict = detect(&padded);
                assert!(
                    verdict.is_some_and(|p| p.is(protocol)),
                    "{:?} cover traffic at realistic S sizes must be self-detecting, got {:?} (tag={})",
                    protocol,
                    verdict,
                    tag
                );
            }
        }

        // Actual is 13 across the four S configurations. The bound guards
        // against imitation regressing toward zero, so it sits well below that
        // rather than one step under it -- a threshold of 12 would fail on any
        // legitimate change that drops a single combination.
        assert!(
            self_detected >= 8,
            "expected our cover traffic to be probe-shaped in many cases, saw only {}; if imitation regressed this is where it shows",
            self_detected
        );
        let _: fn(&[u8]) -> Option<Probe> = detect;
    }

    /// The full input matrix for `strip_inbound`, written before the change
    /// that made it fallible rather than after. The risk of that change is
    /// dropping *valid* traffic, so every configuration shape is enumerated:
    /// all-zero (plain WireGuard), fully padded, and mixed.
    #[test]
    fn strip_inbound_accepts_every_conforming_shape_and_rejects_the_rest() {
        let obf = ObfuscationRanges::default();

        // --- all S zero: must behave exactly like plain WireGuard ---------
        let vanilla = AmneziaConfig::new(0, 0, 0, 0);
        for (tag, size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ] {
            let mut p = vec![0xaa; size];
            write_tag(&mut p, tag);
            assert_eq!(
                vanilla.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "vanilla must accept tag {:#x} unchanged",
                tag
            );
        }
        // Too short to be anything, and a tag that matches no range.
        assert_eq!(vanilla.strip_inbound(obf, &[0u8; 10]), None);
        let mut bogus = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bogus, 0x5555_5555);
        assert_eq!(vanilla.strip_inbound(obf, &bogus), None, "unknown tag");

        // --- every S configured -------------------------------------------
        let padded = AmneziaConfig::new(120, 130, 110, 80);
        for (tag, size, junk) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, 120usize),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, 130),
            (COOKIE_REPLY, COOKIE_REPLY_SZ, 110),
            (DATA, DATA_OVERHEAD_SZ + 48, 80),
        ] {
            let mut p = vec![0xaa; junk + size];
            write_tag(&mut p[junk..], tag);
            assert_eq!(
                padded.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "padded tag {:#x} must strip to its base size",
                tag
            );

            // The same packet *unpadded* is not ours and must be rejected.
            let mut bare = vec![0xaa; size];
            write_tag(&mut bare, tag);
            assert_eq!(
                padded.strip_inbound(obf, &bare),
                None,
                "unpadded tag {:#x} must be dropped when its S is configured",
                tag
            );
        }

        // --- mixed: S1 set, S4 zero ----------------------------------------
        let mixed = AmneziaConfig::new(15, 0, 0, 0);
        let mut init = vec![0xaa; 15 + HANDSHAKE_INIT_SZ];
        write_tag(&mut init[15..], HANDSHAKE_INIT);
        assert_eq!(
            mixed.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );
        // S4 = 0, so unpadded transport is still the conforming shape and must
        // keep working. This is the case a naive 'reject anything unpadded'
        // would break.
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 16];
        write_tag(&mut data, DATA);
        assert_eq!(
            mixed.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 16),
            "S4 = 0 means unpadded transport is conforming"
        );
        // But an unpadded init is not, because S1 is set.
        let mut bare_init = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bare_init, HANDSHAKE_INIT);
        assert_eq!(mixed.strip_inbound(obf, &bare_init), None);
    }

    #[test]
    fn strips_inbound_s1_to_s4_when_magic_matches() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);

        let mut init = vec![0xaa; cfg.init_packet_junk_size as usize + HANDSHAKE_INIT_SZ];
        write_tag(
            &mut init[cfg.init_packet_junk_size as usize..],
            HANDSHAKE_INIT,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );

        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(
            &mut resp[cfg.response_packet_junk_size as usize..],
            HANDSHAKE_RESP,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &resp).map(|d| d.len()),
            Some(HANDSHAKE_RESP_SZ)
        );

        let mut cookie = vec![0xaa; cfg.cookie_packet_junk_size as usize + COOKIE_REPLY_SZ];
        write_tag(
            &mut cookie[cfg.cookie_packet_junk_size as usize..],
            COOKIE_REPLY,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &cookie).map(|d| d.len()),
            Some(COOKIE_REPLY_SZ)
        );

        let mut data = vec![0xaa; cfg.transport_packet_junk_size as usize + DATA_OVERHEAD_SZ + 8];
        write_tag(&mut data[cfg.transport_packet_junk_size as usize..], DATA);
        assert_eq!(
            cfg.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 8)
        );
    }

    #[test]
    fn rejects_inbound_packet_whose_magic_does_not_match_its_shape() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(&mut resp[cfg.response_packet_junk_size as usize..], DATA);

        // The size says handshake response, the tag says transport data: it
        // matches no configured shape. Previously this was handed back for
        // the caller to reject; rejecting it here is the same outcome reached
        // one layer earlier, and without a second chance to be misread.
        assert_eq!(cfg.strip_inbound(obf, &resp), None);
    }

    #[test]
    fn rejects_unpadded_transport_when_s4_is_configured() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 32];
        write_tag(&mut data, DATA);

        // S4 is configured, so a conforming peer always pads. Handing this
        // back would let the caller re-read the tag at offset 0 and accept
        // it, which is the filtering gap this rejection closes.
        assert_eq!(cfg.strip_inbound(obf, &data), None);
    }

    #[test]
    fn strips_padded_transport_when_junk_prefix_also_looks_like_h4() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let junk_size = cfg.transport_packet_junk_size as usize;
        let mut data = vec![0xaa; junk_size + DATA_OVERHEAD_SZ + 32];

        write_tag(&mut data, DATA);
        write_tag(&mut data[junk_size..], DATA);
        data[junk_size + 4] = 0x42;

        let stripped = cfg.strip_inbound(obf, &data);

        assert_eq!(stripped, Some(&data[junk_size..]));
    }

    #[test]
    fn prepends_outbound_junk_for_matching_packet_type() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 64];
        write_tag(&mut buffer, HANDSHAKE_INIT);
        buffer[4] = 0x42;

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .unwrap();

        assert_eq!(packet.len(), HANDSHAKE_INIT_SZ + 7);
        assert_eq!(&packet[7..11], &HANDSHAKE_INIT.to_le_bytes());
        assert_eq!(packet[11], 0x42);
    }

    #[test]
    fn validate_accepts_sizes_that_fit_and_rejects_those_that_cannot() {
        // Junk + base packet must fit in one sendable UDP datagram
        // (MAX_SENDABLE_DATAGRAM = 65507, the IPv4 payload limit) -- not the
        // 65535 protocol ceiling the kernel module bounds by.
        assert!(AmneziaConfig::new(0, 0, 0, 0).validate().is_ok());
        assert!(AmneziaConfig::new(1000, 1000, 1000, 1000)
            .validate()
            .is_ok());

        // Exactly at the limit for each packet type.
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let max_s2 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_RESP_SZ) as u16;
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        let max_s4 = (MAX_SENDABLE_DATAGRAM - DATA_OVERHEAD_SZ) as u16;
        assert!(AmneziaConfig::new(max_s1, max_s2, max_s3, max_s4)
            .validate()
            .is_ok());

        // One byte over, each in turn.
        for (cfg, want) in [
            (AmneziaConfig::new(max_s1 + 1, 0, 0, 0), "S1"),
            (AmneziaConfig::new(0, max_s2 + 1, 0, 0), "S2"),
            (AmneziaConfig::new(0, 0, max_s3 + 1, 0), "S3"),
            (AmneziaConfig::new(0, 0, 0, max_s4 + 1), "S4"),
        ] {
            let err = cfg.validate().expect_err("must be rejected");
            assert!(err.contains(want), "error should name {}: {}", want, err);
        }
    }

    #[test]
    fn validate_rejects_sizes_that_fit_the_protocol_but_not_a_udp_datagram() {
        // The protocol ceiling is 65535, but an IPv4 UDP payload tops out at
        // 65535 - 20 - 8 = 65507. Sizes in between pass the kernel module's
        // check and then fail at send time with EMSGSIZE, so they must be
        // rejected here rather than accepted into a tunnel that never works.
        const PROTOCOL_MAX: usize = 65535;
        assert_eq!(MAX_SENDABLE_DATAGRAM, 65507);

        // For each field: the size the protocol ceiling alone would allow.
        let cases = [
            ("S1", HANDSHAKE_INIT_SZ, 0usize),
            ("S2", HANDSHAKE_RESP_SZ, 1),
            ("S3", COOKIE_REPLY_SZ, 2),
            ("S4", DATA_OVERHEAD_SZ, 3),
        ];

        for (label, base, slot) in cases {
            let over = (PROTOCOL_MAX - base) as u16;
            let mut s = [0u16; 4];
            s[slot] = over;
            let cfg = AmneziaConfig::new(s[0], s[1], s[2], s[3]);

            let err = cfg.validate().expect_err(&format!(
                "{}={} yields a {}-byte datagram, unsendable over IPv4",
                label,
                over,
                over as usize + base
            ));
            assert!(err.contains(label), "error should name {}: {}", label, err);
        }
    }

    #[test]
    fn validated_max_size_actually_round_trips_through_prepend_outbound() {
        // The bound is only meaningful if the largest accepted configuration can
        // still emit a packet -- otherwise validate() would be off by one.
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let cfg = AmneziaConfig::new(max_s1, 0, 0, 0);
        cfg.validate().unwrap();

        let mut buffer = vec![0u8; MAX_SENDABLE_DATAGRAM];
        write_tag(&mut buffer, HANDSHAKE_INIT);

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .expect("largest validated S1 must still fit");
        assert_eq!(packet.len(), MAX_SENDABLE_DATAGRAM);
    }

    /// [`AmneziaConfig::cookie_reply_len`] must agree with the length
    /// `prepend_outbound` actually produces, for every S3 from zero to the
    /// largest `validate` admits.
    ///
    /// The ingress path predicts the length so it can refuse an amplifying
    /// cookie reply *without* paying to generate its junk. A prediction that
    /// ran low would let the amplifier through; one that ran high would silence
    /// cookie replies for a configuration that is not an amplifier at all. Both
    /// are silent, so the two are pinned to each other here rather than left to
    /// agree by inspection.
    #[test]
    fn the_predicted_cookie_reply_length_is_the_one_actually_produced() {
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        for s3 in [0u16, 1, 110, 1280, max_s3] {
            // Two shapes per S3, because the prediction has to hold for both and
            // they are the two ends of the rule it feeds. The derived S1/S2 are
            // the smallest values that keep the reply an attenuator. The zeroed
            // pair is the shape that amplifies once S3 passes 84 -- `validate`
            // accepts it (the reflection policy moved out to the responder's
            // door), and it is the shape the runtime guards actually fire on, so
            // leaving it out would pin the prediction everywhere except where it
            // is used.
            for (s1, s2, shape) in [
                (
                    s3.saturating_sub(84),
                    s3.saturating_sub(28),
                    "S1/S2 derived",
                ),
                (0, 0, "S1 = S2 = 0"),
            ] {
                let cfg = AmneziaConfig::new(s1, s2, s3, 0);
                cfg.validate().expect("S3 within the validated range");

                let produced = packet_after_prepend(
                    &cfg,
                    COOKIE_REPLY_SZ,
                    COOKIE_REPLY,
                    COOKIE_REPLY_SZ + s3 as usize,
                )
                .len();

                assert_eq!(
                    cfg.cookie_reply_len(COOKIE_REPLY_SZ),
                    produced,
                    "S3 = {} ({}): predicted length must match the datagram \
                     prepend_outbound emits",
                    s3,
                    shape
                );
            }
        }
    }

    #[test]
    fn quic_imitation_uses_short_header_for_every_packet_kind() {
        let cfg = AmneziaConfig::new(8, 9, 10, 11)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);

        // Every S-region is a 1-RTT short header: form bit clear, fixed bit
        // set. A long header would carry a length field that cannot frame the
        // WireGuard packet that follows, and S2/S3 are far below the 1200-byte
        // minimum a valid Initial requires (RFC 9000 §14.1).
        let cases = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 4),
        ];

        for (tag, packet_size) in cases {
            let junk_size = expected_junk(&cfg, tag);
            let packet = packet_after_prepend(&cfg, packet_size, tag, packet_size + 64);

            assert_eq!(
                packet[0] & 0xc0,
                0x40,
                "tag={:#x} must use a 1-RTT short header, got first byte {:#04x}",
                tag,
                packet[0]
            );
            assert_eq!(
                &packet[junk_size..junk_size + 4],
                &tag.to_le_bytes(),
                "tag={:#x} payload must start right after the junk prefix",
                tag
            );
        }
    }

    #[test]
    fn quic_pre_handshake_junk_keeps_long_header_initial_at_rfc_minimum_size() {
        // The Jc path is the one place a long-header Initial is legal: it is a
        // standalone client->server datagram and its size is drawn from
        // QUIC_JUNK_SIZE_MIN..=MAX, which starts at the RFC 9000 §14.1 minimum.
        // Deliberately an independent literal rather than QUIC_JUNK_SIZE_MIN:
        // this is an external requirement imposed by the RFC, and the point of
        // the test is that our constant satisfies it. Asserting against
        // QUIC_JUNK_SIZE_MIN would be tautological, since the junk length is
        // drawn from that very constant.
        const RFC9000_MIN_INITIAL_DATAGRAM: usize = 1200;
        // A `const` item, so this is a compile error rather than a test
        // failure: both sides are constants, so there is nothing to wait until
        // runtime for. That also costs the formatted message -- `assert!` in a
        // const context takes a literal only -- so the two values are named in
        // the text instead. (An item, not an inline-const block, which needs
        // Rust 1.79; the Win7 targets build with 1.75.)
        const _: () = assert!(
            QUIC_JUNK_SIZE_MIN >= RFC9000_MIN_INITIAL_DATAGRAM,
            "QUIC_JUNK_SIZE_MIN must not drop below 1200, the RFC 9000 \
             §14.1 minimum, or the Jc path emits invalid Initials"
        );

        let cfg = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 0, 0, 0)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buffer = vec![0u8; QUIC_JUNK_SIZE_MAX];

        let junk = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert!(
            junk.len() >= RFC9000_MIN_INITIAL_DATAGRAM,
            "a long-header Initial needs a >={} byte datagram, got {}",
            RFC9000_MIN_INITIAL_DATAGRAM,
            junk.len()
        );
        assert_eq!(junk[0] & 0xc0, 0xc0, "long header form + fixed bit");
        assert_eq!(&junk[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
    }

    #[test]
    fn dns_imitation_wraps_trailing_wireguard_payload_in_opt_record() {
        let cfg = AmneziaConfig::new(0, 0, 0, 64).with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 8, DATA, DATA_OVERHEAD_SZ + 128);
        let prefix = &packet[..64];
        assert_eq!(&prefix[10..12], &[0x00, 0x01]);

        let mut pos = 12usize;
        while prefix[pos] != 0 {
            pos += 1 + prefix[pos] as usize;
        }
        pos += 1 + 4;
        assert_eq!(prefix[pos], 0x00);
        assert_eq!(&prefix[pos + 1..pos + 3], &[0x00, 0x29]);

        let rdlen = u16::from_be_bytes([prefix[pos + 9], prefix[pos + 10]]) as usize;
        assert_eq!(rdlen, packet.len() - pos - DNS_OPT_FIXED_LEN);
    }

    #[test]
    fn sip_imitation_reuses_valid_configured_domain_when_it_fits() {
        let cfg = AmneziaConfig::new(96, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Sip,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(
            &cfg,
            HANDSHAKE_INIT_SZ,
            HANDSHAKE_INIT,
            HANDSHAKE_INIT_SZ + 128,
        );
        let prefix = std::str::from_utf8(&packet[..96]).unwrap();
        assert!(
            prefix.starts_with("OPTIONS")
                || prefix.starts_with("REGISTER")
                || prefix.starts_with("MESSAGE")
        );
        assert!(prefix.contains("sip:"));
        assert!(prefix.contains("example.com"));
    }

    #[test]
    fn stun_imitation_emits_binding_request_prefix() {
        let cfg = AmneziaConfig::new(0, 0, 0, 40)
            .with_protocol_imitation(AmneziaImitationProtocol::Stun, None);

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 4, DATA, DATA_OVERHEAD_SZ + 64);
        let prefix = &packet[..40];
        assert_eq!(&prefix[..2], &[0x00, 0x01]);
        assert_eq!(&prefix[4..8], &[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(u16::from_be_bytes([prefix[2], prefix[3]]) % 4, 0);
    }

    #[test]
    fn pre_handshake_junk_allows_fixed_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 42, 42, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; 128];

        let packet = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert_eq!(packet.len(), 42);
    }

    #[test]
    fn quic_sni_accepts_utf8_idn_while_dns_sip_require_ldh() {
        // QUIC SNI is a length-prefixed TLS extension: UTF-8/IDN accepted.
        assert!(is_valid_quic_sni("xn--nxasmq6b.com"));
        assert!(is_valid_quic_sni("пример.рф"));
        assert!(!is_valid_quic_sni(""));
        assert!(!is_valid_quic_sni("bad\r\nhost"));
        assert!(!is_valid_quic_sni(&"a".repeat(254)));

        // A non-ASCII domain is kept for QUIC but dropped for DNS/SIP (strict).
        let quic = AmneziaImitation::new(
            AmneziaImitationProtocol::Quic,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(quic.domain(), Some("пример.рф"));
        let dns = AmneziaImitation::new(
            AmneziaImitationProtocol::Dns,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(dns.domain(), None);
    }

    #[test]
    fn quic_default_browser_emits_single_curl_initial() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
        );
        assert!(cfg.has_imitation_sequence());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let seq = cfg.pre_handshake_imitation_datagrams(&mut rng);
        // Omitted browser -> curl -> one Initial, back-to-back (zero delay).
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].0, Duration::from_millis(0));
        assert_eq!(seq[0].1.len(), 1250);
    }

    #[test]
    fn pre_handshake_junk_rejects_zero_min_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 0, 10, 0);

        assert_eq!(
            cfg.pre_handshake_junk.packet_size_min,
            DEFAULT_JUNK_PACKET_SIZE_MIN
        );
        assert_eq!(
            cfg.pre_handshake_junk.packet_size_max,
            DEFAULT_JUNK_PACKET_SIZE_MAX
        );
    }

    #[test]
    fn protocol_imitation_fillers_tolerate_tiny_buffers() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for size in 0..32 {
            let mut stun = vec![0u8; size];
            fill_stun(&mut stun, &mut rng);

            let mut dns = vec![0u8; size];
            fill_dns_minimal_root_query(&mut dns, &mut rng);
        }
    }

    /// `cookie_reply_amplifies` agrees with the rule `reply_policy` enforces,
    /// on both packet kinds and at the boundary.
    ///
    /// The two live in different modules and neither can see the other, so the
    /// only thing keeping them in step is this test. The response bound
    /// (`S3 > S2 + 28`) is the tighter of the two and had no coverage at all.
    #[test]
    fn cookie_reply_amplifies_agrees_with_the_rule_that_suppresses() {
        // Parity exactly: 64 + S3 == 148 + S1 and == 92 + S2. Not an amplifier.
        let ok = AmneziaConfig::new(100, 156, 184, 0);
        assert_eq!(
            ok.cookie_reply_amplifies(),
            None,
            "parity is not amplifying"
        );

        // One byte over on the initiation side.
        let over_s1 = AmneziaConfig::new(100, 156, 185, 0);
        assert_eq!(
            over_s1.cookie_reply_amplifies(),
            Some(("S1", 248, 249)),
            "one byte past the initiation bound must be reported"
        );

        // The response bound is tighter, so a config can clear S1 and fail S2.
        let over_s2 = AmneziaConfig::new(200, 100, 250, 0);
        assert_eq!(
            over_s2.cookie_reply_amplifies(),
            Some(("S2", 192, 314)),
            "the response bound is the tighter one and must be checked too"
        );

        // The shape a real installer rolls: S1 small, S3 large.
        let installer = AmneziaConfig::new(15, 15, 150, 0);
        assert!(
            installer.cookie_reply_amplifies().is_some(),
            "S1=15 S3=150 is a shape independent rolls produce, and it amplifies"
        );

        // And the interop harness's own sizes must not trip it.
        let harness = AmneziaConfig::new(120, 130, 110, 80);
        assert_eq!(
            harness.cookie_reply_amplifies(),
            None,
            "the sizes scripts/awg-interop-poc.sh runs must keep their cookies"
        );
    }

    /// `validate` is universal; the reflection policy lives outside it.
    ///
    /// One door, not two: `validate` answers "is this configuration possible
    /// for anyone", and the cookie-reflection question is reported separately
    /// by `cookie_amplification_complaint`, which no door turns into a refusal
    /// (`device::api` warns and loads, pinned by
    /// `a_set_transaction_accepts_and_warns_on_the_s3_the_ffi_constructor_accepts`);
    /// the runtime guards enforce the bound per datagram.
    /// Without this test the separation is invisible to a later reader, who
    /// would quite reasonably fold the complaint back into `validate` --
    /// re-refusing, for every client, a server-dictated S3 the client cannot
    /// change.
    ///
    /// The second half stops the separation from over-reaching: everything
    /// *else* `validate` refuses, it must keep refusing.
    #[test]
    fn the_reflection_policy_is_not_part_of_validate() {
        // The measured profile: 64 + 120 = 184 > 92 + 86 = 178.
        let amplifying = AmneziaConfig::new(65, 86, 120, 0);
        amplifying
            .validate()
            .expect("an amplifying S3 is the server's choice, not an impossibility");
        let complaint = amplifying
            .cookie_amplification_complaint()
            .expect("but it still earns the complaint both doors warn with");
        assert!(
            complaint.contains("larger than") && complaint.contains("S2"),
            "which must name the binding bound: {}",
            complaint
        );

        // The universal rules are all still there. A timer ordering that
        // rejects keys before their rekey completes is self-harm regardless of
        // which end of the tunnel runs it.
        let incoherent = AmneziaConfig::new(0, 0, 0, 0).with_tunable_timers(AwgTimers {
            reject_after_time: (20, 20),
            ..Default::default()
        });
        let err = incoherent.validate().expect_err(
            "moving the reflection policy out must not take the universal rules with it",
        );
        assert!(err.contains("reject_after_time"), "{}", err);

        // And a clean configuration passes with nothing to complain about, so
        // neither check is simply firing on everything.
        let clean = AmneziaConfig::new(65, 86, 114, 0);
        clean.validate().expect("clean config validates");
        assert!(
            clean.cookie_amplification_complaint().is_none(),
            "nothing to complain about at parity"
        );
    }

    /// The complaint fires on both packet kinds and exactly at the boundary.
    ///
    /// The rule itself is deliberately stricter than the AmneziaWG kernel
    /// module, which accepts these combinations and sends the configured reply
    /// whatever its size: a config this complains about runs there, weakly
    /// reflecting, and runs here without reflecting, losing handshake liveness
    /// under load where the runtime guards suppress its cookie replies. Both
    /// doors -- `device::api` on `set=1` and the C constructor -- warn with it
    /// and load, so this pins the *message*: where it fires, what it names, and
    /// where it stays silent.
    #[test]
    fn the_complaint_fires_on_both_packet_kinds_and_at_the_boundary() {
        // Parity exactly: 64 + S3 == 148 + S1 and == 92 + S2. Legal.
        assert!(
            AmneziaConfig::new(100, 156, 184, 0)
                .cookie_amplification_complaint()
                .is_none(),
            "parity is not amplification"
        );

        // One byte past the initiation bound.
        let err = AmneziaConfig::new(100, 156, 185, 0)
            .cookie_amplification_complaint()
            .expect("one byte over must earn the complaint");
        assert!(
            err.contains("S1"),
            "the message must name the binding value: {}",
            err
        );
        assert!(
            err.contains("249") && err.contains("248"),
            "and both sizes, so the operator can see the margin: {}",
            err
        );

        // The response bound is the tighter of the two, so a config can clear
        // S1 and still fail on S2.
        let err = AmneziaConfig::new(200, 100, 250, 0)
            .cookie_amplification_complaint()
            .expect("the response bound must be checked too");
        assert!(
            err.contains("S2"),
            "the message must name S2 here, not S1: {}",
            err
        );

        // The shape an installer rolling S values independently produces.
        assert!(
            AmneziaConfig::new(15, 15, 150, 0)
                .cookie_amplification_complaint()
                .is_some(),
            "S1=15 S3=150 amplifies and must be complained about"
        );

        // And the sizes the interop harness runs must stay silent, or this
        // rule has broken the project's own reference configuration.
        assert!(
            AmneziaConfig::new(120, 130, 110, 80)
                .cookie_amplification_complaint()
                .is_none(),
            "scripts/awg-interop-poc.sh must stay a clean config"
        );

        // As must the default: vanilla WireGuard has no S values at all.
        assert!(
            AmneziaConfig::default()
                .cookie_amplification_complaint()
                .is_none(),
            "the default configuration must stay clean"
        );
    }

    /// The complaint says what each violated bound costs, once each, and never
    /// suggests the reply goes out.
    ///
    /// The configuration doors log this at WARN and load, so its consequence
    /// clause is the whole of what an operator learns. A response bound costs
    /// handshakes this end initiates while overloaded; an initiation bound
    /// costs incoming ones. The stock-installer profile violates only the
    /// first; S1=15, S2=15, S3=150 -- an independent roll of the installer's
    /// 15..=150 ranges -- violates both, which must read as one message naming
    /// both consequences, not two.
    #[test]
    fn the_complaint_states_each_violated_bounds_consequence_once() {
        // The stock amneziawg-install profile the live Raspberry Pi run used:
        // a 213-byte reply against a 151-byte response and a 284-byte
        // initiation. Only the response bound is violated.
        let stock = AmneziaConfig::new(136, 59, 149, 16)
            .cookie_amplification_complaint()
            .expect("64 + 149 > 92 + 59: the stock profile earns the complaint");
        assert!(
            stock.contains("S3 = 149")
                && stock.contains("213 bytes")
                && stock.contains("151-byte")
                && stock.contains("S2 = 59"),
            "the binding bound, with both sizes: {}",
            stock
        );
        assert!(
            stock.contains("minimum-size handshake response (151 bytes)")
                && stock.contains("handshakes this end initiates may fail"),
            "the response bound's consequence: {}",
            stock
        );
        assert!(
            !stock.contains("handshake initiation") && !stock.contains("incoming handshakes"),
            "284 >= 213, so the initiation bound holds and must not be blamed: {}",
            stock
        );
        assert!(
            stock.contains("never sent larger than the datagram that provoked it"),
            "the message must say the reply is suppressed, not sent: {}",
            stock
        );
        assert!(
            stock.ends_with("Lower S3 to at most 87, or raise S2 to at least 121."),
            "the advice is the boundary the UAPI tests pin (S3=87 / S2=121): {}",
            stock
        );

        // Both bounds violated: one message, each consequence exactly once.
        let both = AmneziaConfig::new(15, 15, 150, 0)
            .cookie_amplification_complaint()
            .expect("S1=15 S2=15 S3=150 violates both bounds");
        for clause in [
            "minimum-size handshake response (107 bytes)",
            "handshakes this end initiates may fail",
            "minimum-size handshake initiation (163 bytes)",
            "incoming handshakes may fail",
        ] {
            assert_eq!(
                both.matches(clause).count(),
                1,
                "{:?} must appear exactly once in: {}",
                clause,
                both
            );
        }

        // Initiation bound only: S2 large enough, S1 not.
        let init_only = AmneziaConfig::new(0, 200, 100, 0)
            .cookie_amplification_complaint()
            .expect("64 + 100 > 148 + 0");
        assert!(
            init_only.contains("incoming handshakes may fail")
                && !init_only.contains("handshakes this end initiates"),
            "only the initiation bound's consequence: {}",
            init_only
        );
    }

    /// Following the error message's advice must actually produce a loadable
    /// configuration.
    ///
    /// The message names a maximum S3. If the helper reports whichever bound it
    /// checks first rather than the binding one, that maximum can still be too
    /// high -- at S1=100, S2=0, S3=185 the initiation bound advises 184, and 184
    /// still fails the response bound of 28. This asserts the property the
    /// operator actually cares about rather than the mechanism: take the number
    /// the message gives, apply it, and the config must validate.
    #[test]
    fn the_maximum_s3_the_error_recommends_actually_validates() {
        for (s1, s2, s3) in [
            (100u16, 0u16, 185u16), // both bounds violated, response the tighter
            (0, 100, 185),          // both violated, initiation the tighter
            (15, 15, 150),          // the installer shape
            (0, 0, 100),            // no S padding at all
            (100, 156, 185),        // one byte past a symmetric parity
        ] {
            let cfg = AmneziaConfig::new(s1, s2, s3, 0);
            let (_, request, _) = cfg
                .cookie_reply_amplifies()
                .unwrap_or_else(|| panic!("S1={} S2={} S3={} should amplify", s1, s2, s3));

            let advised = (request - COOKIE_REPLY_SZ) as u16;
            let followed = AmneziaConfig::new(s1, s2, advised, 0);
            followed.validate().unwrap_or_else(|e| {
                panic!(
                    "S1={} S2={}: advised S3={} still rejected: {}",
                    s1, s2, advised, e
                )
            });
            if let Some(c) = followed.cookie_amplification_complaint() {
                panic!(
                    "S1={} S2={}: advised S3={} still complained about: {}",
                    s1, s2, advised, c
                );
            }

            // And it is the *largest* such value, or the advice is needlessly
            // strict and the operator loses padding they could have kept.
            assert!(
                AmneziaConfig::new(s1, s2, advised + 1, 0)
                    .cookie_amplification_complaint()
                    .is_some(),
                "S1={} S2={}: S3={} should have been advised instead",
                s1,
                s2,
                advised + 1
            );
        }
    }

    /// The message's *other* alternative has to work in one pass too.
    ///
    /// "Lower S3, or raise S1/S2" offers two routes and an operator may take
    /// either. When both bounds are violated they are independent, so naming
    /// only the binding one leaves the other failing: at S1=100, S2=0, S3=185,
    /// raising S2 to parity still leaves the initiation a byte short.
    ///
    /// Parses the minima back out of the rendered string rather than calling
    /// the helper, because the string is what the operator acts on. A helper
    /// that is right while the message is wrong still sends them round twice.
    #[test]
    fn every_raise_the_error_recommends_applied_together_actually_validates() {
        /// -> [("S1", 101), ("S2", 157)] from "... or raise S1 to at least 101
        /// and S2 to at least 157."
        fn parse_raises(msg: &str) -> Vec<(String, u16)> {
            let tail = msg
                .split_once(", or raise ")
                .unwrap_or_else(|| panic!("no raise advice in: {}", msg))
                .1
                .trim_end_matches('.');
            tail.split(" and ")
                .map(|clause| {
                    let (label, value) = clause
                        .split_once(" to at least ")
                        .unwrap_or_else(|| panic!("malformed raise clause: {}", clause));
                    (
                        label.to_string(),
                        value
                            .parse()
                            .unwrap_or_else(|e| panic!("bad number in {}: {}", clause, e)),
                    )
                })
                .collect()
        }

        for (s1, s2, s3, expected_count) in [
            (100u16, 0u16, 185u16, 2), // both bounds violated
            (0, 100, 185, 2),          // both violated, the other way round
            (200, 100, 250, 1),        // clears S1, fails S2
            (15, 15, 150, 2),          // the installer shape
            (100, 156, 185, 2),        // one byte past a symmetric parity
        ] {
            let err = AmneziaConfig::new(s1, s2, s3, 0)
                .cookie_amplification_complaint()
                .expect("this configuration must be complained about");
            let raises = parse_raises(&err);
            assert_eq!(
                raises.len(),
                expected_count,
                "S1={} S2={} S3={}: wrong number of bounds named in {}",
                s1,
                s2,
                s3,
                err
            );

            // Apply every raise the message names, all at once, and the
            // configuration must load.
            let mut raised_s1 = s1;
            let mut raised_s2 = s2;
            for (label, min) in &raises {
                match label.as_str() {
                    "S1" => raised_s1 = *min,
                    "S2" => raised_s2 = *min,
                    other => panic!("unexpected label {} in {}", other, err),
                }
            }
            let followed = AmneziaConfig::new(raised_s1, raised_s2, s3, 0);
            followed.validate().unwrap_or_else(|e| {
                panic!(
                    "S1={}->{} S2={}->{} S3={}: following the advice still fails: {}",
                    s1, raised_s1, s2, raised_s2, s3, e
                )
            });
            if let Some(c) = followed.cookie_amplification_complaint() {
                panic!(
                    "S1={}->{} S2={}->{} S3={}: following the advice still complains: {}",
                    s1, raised_s1, s2, raised_s2, s3, c
                );
            }

            // And each is the *smallest* value that works, or the advice costs
            // the operator padding they could have kept.
            for (label, min) in &raises {
                let (probe_s1, probe_s2) = match label.as_str() {
                    "S1" => (min - 1, raised_s2),
                    _ => (raised_s1, min - 1),
                };
                assert!(
                    AmneziaConfig::new(probe_s1, probe_s2, s3, 0)
                        .cookie_amplification_complaint()
                        .is_some(),
                    "S1={} S2={} S3={}: {} = {} would have done, so {} is too strict",
                    s1,
                    s2,
                    s3,
                    label,
                    min - 1,
                    min
                );
            }
        }
    }

    /// The content-padding decision transcribes amneziawg-go, clamp and all.
    ///
    /// An active range draws inside `[lo, hi]` and produces more than one
    /// distinct amount over many packets; a full-MTU packet grows by zero; an
    /// over-MTU plaintext is measured against one MTU unit; and the amount never
    /// exceeds the space the caller offers.
    #[test]
    fn content_padding_follows_the_range_and_the_mtu() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xC0FFEE);
        let cfg = AmneziaConfig::new(120, 130, 110, 80).with_content_padding_addition(8, 24, 1420);

        // In band, and genuinely random -- a draw-once mutation collapses this.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let pad = cfg.content_padding(200, 4096, &mut rng);
            assert!((8..=24).contains(&pad), "pad {} out of [8,24]", pad);
            seen.insert(pad);
        }
        assert!(seen.len() > 1, "padding never varied: {:?}", seen);

        // A full-MTU plaintext must grow by zero, or the datagram exceeds the
        // link and stalls.
        assert_eq!(cfg.content_padding(1420, 4096, &mut rng), 0);

        // An over-MTU plaintext is measured against one MTU unit: src = mtu + 1
        // has last_unit == 1, so the room is mtu - 1 = 1419 and the full [8, 24]
        // draw fits. Asserting the band, not just an upper bound: measuring
        // against `src_len` instead of `src_len % mtu` leaves room = 0 and pad =
        // 0, which a bare `pad <= 24` would wave through.
        let pad = cfg.content_padding(1421, 4096, &mut rng);
        assert!(
            (8..=24).contains(&pad),
            "pad {} ignored the MTU-unit remainder (src measured whole?)",
            pad
        );

        // Never exceeds the caller's space.
        assert!(cfg.content_padding(200, 5, &mut rng) <= 5);
    }

    /// A transposed builder range is normalized, not silently unset.
    ///
    /// `(0, 0)` is not "off" -- it is the 16-byte-rounding fallback -- so
    /// mapping an inverted pair onto it would hand a caller who wrote
    /// `(hi, lo)` a third behaviour they never asked for, with no error and no
    /// log. The UAPI cannot arrive here inverted (`parse_uint_range` rejects
    /// it, pinned elsewhere); this pins the public builder.
    #[test]
    fn an_inverted_builder_range_is_normalized_not_unset() {
        let cfg = AmneziaConfig::default().with_content_padding_addition(24, 8, 1420);
        assert_eq!(cfg.content_padding_addition, (8, 24));
        assert_eq!(cfg.content_padding_mtu, 1420);
    }

    /// An unset range on an AmneziaWG tunnel rounds the plaintext up to 16.
    #[test]
    fn unset_padding_rounds_an_amnezia_tunnel_to_16() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        // No content-padding range, but S-sizes set -> an AmneziaWG tunnel.
        let cfg = AmneziaConfig::new(120, 130, 110, 80);
        for (src, want) in [(33usize, 15usize), (32, 0), (1, 15), (16, 0), (17, 15)] {
            assert_eq!(
                cfg.content_padding(src, 4096, &mut rng),
                want,
                "src {} should round to a 16-byte multiple",
                src
            );
        }
    }

    /// A vanilla tunnel rounds to 16 like every other implementation.
    ///
    /// Kernel WireGuard (`calculate_skb_padding`), wireguard-go and
    /// amneziawg-go (`calculatePaddingSize`) all round every outbound
    /// transport plaintext up to a 16-byte multiple, clamped to the MTU --
    /// unconditionally, vanilla tunnels included. Until this crate rounded, a
    /// boringtun sender was the one implementation whose transport lengths
    /// were not 16-multiples: a wire fingerprint. The keepalive rows are the
    /// safety half of the claim -- `round16(0)` is 0, and vanilla receivers
    /// classify a keepalive by zero length, so an empty plaintext must never
    /// grow.
    #[test]
    fn a_vanilla_tunnel_rounds_to_16_like_every_other_implementation() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        // No MTU learned (the raw `Tunn`/FFI path): pure rounding.
        let cfg = AmneziaConfig::default();
        for (src, want) in [(1usize, 15usize), (15, 1), (32, 0), (33, 15), (200, 8)] {
            assert_eq!(
                cfg.content_padding(src, 4096, &mut rng),
                want,
                "src {} must round to a 16-byte multiple",
                src
            );
        }
        assert_eq!(
            cfg.content_padding(0, 4096, &mut rng),
            0,
            "a keepalive must stay empty"
        );

        // With the interface MTU learned (every device tunnel): the clamp
        // holds. A full-MTU packet grows by zero; a near-full one only up to
        // the MTU, exactly as upstream clamps `paddedSize` to `mtu`.
        let cfg = AmneziaConfig::default().with_content_padding_addition(0, 0, 1420);
        assert_eq!(
            cfg.content_padding(1420, 4096, &mut rng),
            0,
            "a full-MTU packet must not grow"
        );
        assert_eq!(
            cfg.content_padding(1419, 4096, &mut rng),
            1,
            "rounding is clamped to the MTU, not to the next multiple"
        );
        assert_eq!(cfg.content_padding(200, 4096, &mut rng), 8);
        assert_eq!(
            cfg.content_padding(0, 4096, &mut rng),
            0,
            "a keepalive must stay empty whatever MTU is stored"
        );
    }

    /// The tunable-timer accessors reproduce upstream's end choices, fall
    /// back to the classic constants when unset, and never draw outside a
    /// configured range.
    #[test]
    fn awg_timers_draw_inside_ranges_and_default_to_the_constants() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        // Unset: every accessor is exactly its classic constant.
        let unset = AwgTimers::default();
        assert_eq!(unset.key_refresh_sending(&mut rng), REKEY_AFTER_TIME);
        assert_eq!(unset.retransmit_timeout(&mut rng), REKEY_TIMEOUT);
        assert_eq!(unset.keepalive(&mut rng), KEEPALIVE_TIMEOUT);
        assert_eq!(unset.keychain_expire(), REJECT_AFTER_TIME);
        assert_eq!(
            unset.new_handshake_timeout(&mut rng),
            KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
        );
        assert_eq!(
            unset.key_refresh_receiving(&mut rng),
            REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        );
        // The classic attempt count, asserted as a literal as well as
        // symbolically. Deriving it everywhere gives consistency, not
        // correctness: with only the symbolic form, retuning REKEY_ATTEMPT_TIME
        // would move code, comment and assertion together and quietly redefine
        // what "18 attempts, the same as amneziawg-go's MaxTimerHandshakes"
        // means.
        // 17 retransmissions after the first initiation = 18 in total.
        assert_eq!(unset.max_retransmissions(&mut rng) + 1, 18);
        assert_eq!(
            unset.max_retransmissions(&mut rng) + 1,
            (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as u32
        );
        assert_eq!(REKEY_ATTEMPT_TIME, Duration::from_secs(90));
        assert_eq!(REKEY_TIMEOUT, Duration::from_secs(5));

        // Set: draws stay inside the band and genuinely vary -- a draw-once
        // mutation collapses the set below.
        let t = AwgTimers {
            rekey_after_time: (20, 40),
            rekey_timeout: (2, 4),
            reject_after_time: (100, 120),
            keepalive_timeout: (5, 7),
            max_handshake_attempts: (3, 5),
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = t.key_refresh_sending(&mut rng).as_secs();
            assert!((20..=40).contains(&d), "draw {} outside 20..=40", d);
            seen.insert(d);
        }
        assert!(seen.len() > 1, "a range must draw more than one value");

        // The deliberate end choices. Expiry honours the high end (the most
        // permissive draw a re-picking peer could be running); the receive
        // refresh subtracts the *low* ends from a reject draw; the
        // new-handshake deadline adds the keepalive *high* end to a
        // rekey_timeout draw. The attempt limit is a plain count -- it must
        // stay inside its own range and never be scaled by any interval.
        assert_eq!(t.keychain_expire(), Duration::from_secs(120));
        for _ in 0..32 {
            let d = t.key_refresh_receiving(&mut rng).as_secs();
            assert!(
                (93..=113).contains(&d),
                "refresh {} outside pick(100..=120)-5-2",
                d
            );
            // A configured N buys N+1 retransmissions, i.e. N+2 initiations,
            // which is what the same N buys on amneziawg-go.
            let a = t.max_retransmissions(&mut rng);
            assert!((4..=6).contains(&a), "budget {} outside pick(3..=5)+1", a);
            let n = t.new_handshake_timeout(&mut rng).as_secs();
            assert!(
                (9..=11).contains(&n),
                "deadline {} outside 7+pick(2..=4)",
                n
            );
        }
    }

    /// Pathological ranges degrade instead of panicking.
    ///
    /// The raw `Tunn` builder path does not run `validate`, and a `Duration`
    /// underflow is a panic that crosses the FFI boundary as a process abort.
    /// The saturating subtraction is the guard, and this pins it: the naive
    /// `-` panics on exactly this input.
    #[test]
    fn awg_timer_arithmetic_saturates_on_unvalidated_configs() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let t = AwgTimers {
            reject_after_time: (1, 1),
            keepalive_timeout: (500, 500),
            rekey_timeout: (500, 500),
            ..AwgTimers::default()
        };
        assert_eq!(t.key_refresh_receiving(&mut rng), Duration::from_secs(0));

        // The attempt limit is a count, so the widest range it can carry is
        // still just a number: no interval multiplies it, and nothing here can
        // overflow. (It used to be multiplied into a window, which is what made
        // a `u32::MAX` range worth worrying about.)
        let t = AwgTimers {
            max_handshake_attempts: (u32::MAX, u32::MAX),
            ..AwgTimers::default()
        };
        assert_eq!(t.max_retransmissions(&mut rng), u32::MAX);

        // An inverted range cannot reach the accessors through the builder --
        // it is normalized on the way in, like the padding range beside it.
        let cfg = AmneziaConfig::default().with_tunable_timers(AwgTimers {
            reject_after_time: (200, 100),
            ..AwgTimers::default()
        });
        assert_eq!(cfg.timers.reject_after_time, (100, 200));
    }

    /// The timer floors refuse what the reference implementations would run
    /// badly -- and only that.
    ///
    /// This is a deliberate divergence: amneziawg-go and the kernel module
    /// accept any parseable value, so a configuration refused here loads
    /// there and misbehaves (zero-second retry storms; keys rejected while
    /// the peer still uses them). Each floor names the numbers and both ways
    /// out.
    #[test]
    fn timer_floors_refuse_zero_draws_and_broken_orderings() {
        let check = |t: AwgTimers| AmneziaConfig::default().with_tunable_timers(t).validate();

        // All-default passes, and so does a coherent tuning.
        assert!(check(AwgTimers::default()).is_ok());
        assert!(check(AwgTimers {
            rekey_after_time: (30, 40),
            reject_after_time: (60, 80),
            ..AwgTimers::default()
        })
        .is_ok());

        // A zero inside a set *duration* range is refused, naming the key.
        let err = check(AwgTimers {
            rekey_timeout: (0, 5),
            ..AwgTimers::default()
        })
        .unwrap_err();
        assert!(err.contains("rekey_timeout"), "{}", err);

        // But `max_handshake_attempts` is a count, not a duration: a drawn 0
        // buys one retransmission (`N + 1`), so `0-3` is an ordinary "retry at
        // least once" config that amneziawg-go runs the same way. Refusing it
        // would refuse a working reference configuration.
        assert!(
            check(AwgTimers {
                max_handshake_attempts: (0, 3),
                ..AwgTimers::default()
            })
            .is_ok(),
            "a count range containing 0 must be accepted"
        );

        // reject_after_time shorter than the (default) rekey_after_time +
        // rekey_timeout: keys would be rejected before the rekey replacing
        // them completes.
        let err = check(AwgTimers {
            reject_after_time: (60, 80),
            ..AwgTimers::default()
        })
        .unwrap_err();
        assert!(err.contains("rekey_after_time + rekey_timeout"), "{}", err);

        // Passing the first ordering is not enough: with rekey_after lowered,
        // a reject_after_time at exactly keepalive + rekey_timeout still
        // zeroes the last-minute-rekey window.
        let err = check(AwgTimers {
            rekey_after_time: (10, 10),
            reject_after_time: (15, 15),
            ..AwgTimers::default()
        })
        .unwrap_err();
        assert!(err.contains("keepalive_timeout + rekey_timeout"), "{}", err);
    }
}
