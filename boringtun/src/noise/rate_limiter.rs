use super::handshake::{
    b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24, ObfuscationRanges,
};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError};

#[cfg(feature = "mock-instant")]
use mock_instant::thread_local::Instant;
use portable_atomic::{AtomicU64, Ordering};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use super::handshake::constant_time_eq;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

/// The share of the aggregate handshake budget one source may use: a source
/// is under load on its own once it sends more than `limit / SOURCE_SHARE`
/// handshake messages in a second. So one flooding address gets cookie
/// replies while everyone else keeps the full Noise path, and it takes about
/// this many abusive sources -- or a spoofed flood, which no per-source count
/// can see -- to put the whole limiter under load.
pub(crate) const SOURCE_SHARE: u64 = 5;

/// The least share a source gets, however small `limit` is (and never more
/// than `limit`). A tunnel's own limiter allows 10 a second, a fifth of which
/// would cookie a peer that merely re-handshakes three times in a second.
const SOURCE_FLOOR: u64 = 5;

/// The per-source counts: [`SOURCE_ROWS`] rows of [`SOURCE_SLOTS`] slots,
/// fixed at construction (16 KiB), so no number of distinct sources can grow
/// them.
const SOURCE_ROWS: usize = 2;
const SOURCE_SLOTS: usize = 1024;

type Cookie = [u8; COOKIE_SIZE];

/// Where a handshake message came from, as far as the receiver knows it.
///
/// The cookie is a MAC over the source, so a cookie handed to one endpoint is
/// no good from another -- whitepaper section 5.4.7 makes it the IP address
/// *and* UDP port. A receiver that knows only the address (the public
/// [`Tunn::decapsulate`], which takes an `IpAddr`) gets a cookie over the
/// address alone: no port is assumed, and the two forms can never produce the
/// same cookie. A receiver that knows nothing (the C `wireguard_read`) cannot
/// demand a cookie at all; see [`HandshakeGate::UnderLoad`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Endpoint(SocketAddr),
    Address(IpAddr),
}

impl From<SocketAddr> for Source {
    fn from(endpoint: SocketAddr) -> Self {
        Source::Endpoint(endpoint)
    }
}

impl From<IpAddr> for Source {
    fn from(address: IpAddr) -> Self {
        Source::Address(address)
    }
}

impl Source {
    /// The source address exactly as it was given.
    pub(crate) fn address(self) -> IpAddr {
        match self {
            Source::Endpoint(endpoint) => endpoint.ip(),
            Source::Address(address) => address,
        }
    }

    /// The source address, with an IPv4-mapped IPv6 address taken as the IPv4
    /// address it maps: the same host whichever socket family it reached.
    fn ip(self) -> IpAddr {
        let ip = self.address();
        match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        }
    }

    /// The cookie's input. A tag byte keeps the four shapes apart -- an
    /// endpoint from its bare address, and IPv4 from IPv6, which zero-padding
    /// the IPv4 octets to 16 bytes used to conflate (`a.b.c.d` and
    /// `ab:cd::`). The cookie is only ever checked by the responder that made
    /// it, so its encoding is local: the initiator echoes it opaquely.
    fn cookie_input(self, out: &mut [u8; 19]) -> &[u8] {
        let port = match self {
            Source::Endpoint(endpoint) => Some(endpoint.port()),
            Source::Address(_) => None,
        };
        let len = match self.ip() {
            IpAddr::V4(v4) => {
                out[0] = if port.is_some() { 0x04 } else { 0x14 };
                out[1..5].copy_from_slice(&v4.octets());
                5
            }
            IpAddr::V6(v6) => {
                out[0] = if port.is_some() { 0x06 } else { 0x16 };
                out[1..17].copy_from_slice(&v6.octets());
                17
            }
        };
        match port {
            Some(port) => {
                out[len..len + 2].copy_from_slice(&port.to_be_bytes());
                &out[..len + 2]
            }
            None => &out[..len],
        }
    }

    /// What one source's handshake budget is keyed on: an IPv4 address, or an
    /// IPv6 /64 -- one host can hold a whole /64, so a finer key would hand it
    /// as many budgets as it has addresses. The Linux ratelimiter keys IPv6 on
    /// the /64 as well. Never the port: a source cannot multiply its budget by
    /// rotating ports.
    fn budget_key(self) -> (u8, u64) {
        match self.ip() {
            IpAddr::V4(v4) => (4, u64::from(u32::from(v4))),
            IpAddr::V6(v6) => (6, (u128::from(v6) >> 64) as u64),
        }
    }
}

/// Handshake messages per source in the current one-second window, in a fixed
/// table that holds no addresses at all.
///
/// Each source maps to one slot in each of [`SOURCE_ROWS`] rows through a
/// randomly keyed SipHash, and its count is the smaller of its slots' counts.
/// Sharing a slot can only *raise* a count, so a collision makes the limiter
/// stricter for a source, never laxer. What stricter costs depends on the
/// table: in the share table it asks a legitimate peer for a cookie, one
/// round trip; in the proven table, which only applies once the aggregate is
/// spent, a source sharing every slot with one past its proven share has its
/// cookie-proven messages dropped as `UnderLoad` until the window ends. That
/// is the price of bounded memory; with two rows of 1024 slots a given pair
/// of sources shares every slot with probability 2^-20. The key is drawn per
/// limiter and never leaves it, so a sender cannot pick addresses that land
/// on a victim's slots. Each slot packs `(window << 32) | count`; a count from
/// an earlier window reads as zero, so the table expires by itself, with no
/// sweep and no dependence on anyone calling `reset_count`.
struct SourceCounts {
    hasher: RandomState,
    slots: Box<[AtomicU64]>,
}

impl SourceCounts {
    fn new() -> Self {
        SourceCounts {
            hasher: RandomState::new(),
            slots: (0..SOURCE_ROWS * SOURCE_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect(),
        }
    }

    /// Count one message from `source` in `window`, and return the source's
    /// count including it.
    fn count(&self, source: Source, window: u32) -> u32 {
        self.slots_of(source)
            .map(|slot| Self::bump(&self.slots[slot], window))
            .min()
            .unwrap_or(0)
    }

    /// The slot `source` counts in, in each row.
    fn slots_of(&self, source: Source) -> impl Iterator<Item = usize> {
        let hash = self.hasher.hash_one(source.budget_key());
        (0..SOURCE_ROWS)
            .map(move |row| row * SOURCE_SLOTS + (hash >> (32 * row)) as usize % SOURCE_SLOTS)
    }

    fn bump(slot: &AtomicU64, window: u32) -> u32 {
        // A slot another thread has already moved to a later window is counted
        // in that window, not reset back to this one: a caller that read the
        // clock just before the second ticked over would otherwise wipe the
        // newer window's count. "Later" is modulo 2^32 within half the range,
        // which holds for the first 68 years of a limiter's life.
        let next = |packed: u64| {
            let (slot_window, count) = ((packed >> 32) as u32, packed as u32);
            if slot_window == window || (slot_window.wrapping_sub(window) as i32) > 0 {
                (slot_window, count.saturating_add(1))
            } else {
                (window, 1)
            }
        };
        let previous = slot
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |packed| {
                let (window, count) = next(packed);
                Some((u64::from(window) << 32) | u64::from(count))
            })
            .unwrap_or_else(|packed| packed);
        next(previous).1
    }
}

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset: messages admitted past their source's
    /// share, against the aggregate `limit`.
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
    /// Each source's share of `limit`; see [`SOURCE_SHARE`].
    source_limit: u64,
    /// Every mac1-valid message, by source: what decides a source's own load.
    sources: SourceCounts,
    /// Messages with a valid mac2 while under load, by source. Kept apart from
    /// `sources` because these alone prove their source address, so a flood
    /// spoofing a peer's address cannot spend that peer's allowance here.
    proven: SourceCounts,
    /// Load decisions taken since the last reset, for tests: `count` no longer
    /// sees a message its source's share already refused.
    #[cfg(test)]
    decisions: AtomicU64,
}

impl RateLimiter {
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
            // Zero stays zero, so a zero-budget limiter is under load from the
            // first message, as it always was.
            source_limit: (limit / SOURCE_SHARE).max(limit.min(SOURCE_FLOOR)),
            sources: SourceCounts::new(),
            proven: SourceCounts::new(),
            #[cfg(test)]
            decisions: AtomicU64::new(0),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second)
    pub fn reset_count(&self) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let current_time = Instant::now();
        let mut last_reset_time = self.last_reset.lock();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            #[cfg(test)]
            self.decisions.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source
    fn current_cookie(&self, source: Source) -> Cookie {
        let mut input = [0u8; 19];
        let input = source.cookie_input(&mut input);

        // The current cookie for a given source is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address || initiator.udp_port)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), input)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    /// Whether one more handshake message from `source` finds the limiter
    /// under load, and why: its source past its share, or the aggregate past
    /// `limit`.
    ///
    /// A message its source's share refuses is not counted against the
    /// aggregate, or one flooding address would still exhaust it and put every
    /// peer into cookie mode -- the very thing the per-source count is for.
    /// Without a source only the aggregate applies.
    fn is_under_load(&self, source: Option<Source>) -> Load {
        #[cfg(test)]
        self.decisions.fetch_add(1, Ordering::SeqCst);
        if let Some(source) = source {
            if u64::from(self.sources.count(source, self.window())) > self.source_limit {
                return Load::SourceShare;
            }
        }
        if self.count.fetch_add(1, Ordering::SeqCst) >= self.limit {
            Load::Aggregate
        } else {
            Load::Clear
        }
    }

    /// The current one-second window of the per-source counts. `u32` seconds
    /// wrap after 136 years; a wrap could at worst merge two windows.
    fn window(&self) -> u32 {
        Instant::now().duration_since(self.start_time).as_secs() as u32
    }

    /// How many load decisions have been taken since the last reset: what
    /// `is_under_load` has counted. For tests that must see a message *not*
    /// counted, which no outcome can show while the budget is not yet spent.
    #[cfg(test)]
    pub(crate) fn load_events(&self) -> u64 {
        self.decisions.load(Ordering::SeqCst)
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::COOKIE_REPLY_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&obf.random_h3(rng).to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed.
    ///
    /// Always with the under-load cookie defense armed, as it always was: the
    /// public entry point has no configuration to ask. AmneziaWG
    /// `DisableCookies` reaches the receive paths through
    /// [`Self::gate_handshake`].
    pub fn verify_packet<'a, 'b>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        src_addr: Option<IpAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet(obf, src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            match self.gate_handshake(
                src_addr.map(Source::from),
                src,
                sender_idx,
                CookieDefense::Armed,
                &mut LoadDecision::default(),
            ) {
                HandshakeGate::Pass => {}
                HandshakeGate::BadMac => return Err(TunnResult::Err(WireGuardError::InvalidMac)),
                HandshakeGate::UnderLoad => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                HandshakeGate::CookieDemanded(demand) => {
                    let cookie_packet = self
                        .format_cookie_demand(obf, rng, &demand, dst)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
            }
        }

        Ok(packet)
    }

    /// The mac1 and load checks for one handshake message, without formatting
    /// anything.
    ///
    /// `message` is the canonical initiation or response, macs included. The
    /// order is the one `verify_packet` has always applied: mac1 first, and
    /// only a message with a valid mac1 is counted against the load budget.
    ///
    /// `load` is where the load decision for the *datagram* lives. A receiver
    /// reading one datagram as several packet kinds may reach this more than
    /// once -- an initiation at one offset, a response at another -- and a
    /// datagram is one event for the budget however many ways it is read. The
    /// first call that gets past mac1 decides and records it; later calls
    /// reuse it without counting again. The same holds for the charge a
    /// cookie-proven message makes: the first reading with a valid mac2 is
    /// charged and its admission recorded, and every later one with a valid
    /// mac2 shares it, so a reading that Noise then refuses neither spends
    /// the budget twice nor keeps another reading of the same datagram out.
    ///
    /// `defense` is the receiver's AmneziaWG `DisableCookies` policy
    /// ([`AmneziaConfig::cookie_defense`]). [`CookieDefense::Bypassed`] skips
    /// everything after mac1 -- the load decision itself included, so the
    /// message is not counted and `load` is left undecided -- and passes the
    /// message on to Noise: no mac2, no source address needed, no cookie. That
    /// is amneziawg-go v3.1.20260828's `!disableCookies && IsUnderLoad()`,
    /// where the short circuit keeps `IsUnderLoad`'s own bookkeeping from
    /// running too. mac1 is checked either way.
    ///
    /// [`AmneziaConfig::cookie_defense`]: super::amnezia::AmneziaConfig::cookie_defense
    pub(crate) fn gate_handshake(
        &self,
        src_addr: Option<Source>,
        message: &[u8],
        sender_idx: u32,
        defense: CookieDefense,
        load: &mut LoadDecision,
    ) -> HandshakeGate {
        let (msg, macs) = message.split_at(message.len() - 32);
        let (mac1, mac2) = macs.split_at(16);

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
        if !constant_time_eq(&computed_mac1[..16], mac1) {
            return HandshakeGate::BadMac;
        }

        if defense == CookieDefense::Bypassed {
            return HandshakeGate::Pass;
        }

        let under_load = *load
            .load
            .get_or_insert_with(|| self.is_under_load(src_addr));
        if under_load == Load::Clear {
            return HandshakeGate::Pass;
        }
        let addr = match src_addr {
            None => return HandshakeGate::UnderLoad,
            Some(addr) => addr,
        };

        // Only given an address can we validate mac2
        let cookie = self.current_cookie(addr);
        let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

        if !constant_time_eq(&computed_mac2[..16], mac2) {
            let mut last_mac1 = [0u8; 16];
            last_mac1.copy_from_slice(mac1);
            return HandshakeGate::CookieDemanded(CookieDemand {
                sender_idx,
                cookie,
                mac1: last_mac1,
            });
        }
        if *load
            .proven
            .get_or_insert_with(|| self.admit_proven(under_load, addr))
        {
            HandshakeGate::Pass
        } else {
            HandshakeGate::UnderLoad
        }
    }

    /// Charge one cookie-proven message from `addr`, found under load for
    /// `under_load`, and say whether it is admitted.
    fn admit_proven(&self, under_load: Load, addr: Source) -> bool {
        // A valid mac2 proves the address, and is what a source refused its
        // share returns with -- so without a bound of its own, a source that
        // fetched one cookie could buy unlimited Noise work under load.
        //
        // Refused only its own share, it is admitted against the aggregate
        // instead, which bounds the Noise work at `limit` a second. Its share
        // is per address, and a client behind the same NAT that spent it --
        // mac1-only messages are enough -- must not get its neighbours'
        // proven handshakes dropped: they are cookied, then let through.
        if under_load == Load::SourceShare && self.count.fetch_add(1, Ordering::SeqCst) < self.limit
        {
            return true;
        }
        // With the aggregate over, each proven source gets its share again,
        // counted only over proven messages -- as the Linux ratelimiter
        // applies its per-IP bucket only past the cookie check, and only when
        // the whole device is under load -- so a flood spoofing a peer's
        // address cannot spend that peer's allowance. At least
        // `SOURCE_FLOOR`: a limiter made to be under load from its first
        // message (`limit` 0) still has to let a cookie through.
        u64::from(self.proven.count(addr, self.window())) <= self.source_limit.max(SOURCE_FLOOR)
    }

    /// Format the cookie reply a [`HandshakeGate::CookieDemanded`] called for.
    pub(crate) fn format_cookie_demand<'a>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        demand: &CookieDemand,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.format_cookie_reply(
            obf,
            rng,
            demand.sender_idx,
            demand.cookie,
            &demand.mac1,
            dst,
        )
    }
}

/// Whether the under-load cookie defense applies to a handshake message whose
/// mac1 holds: AmneziaWG 3.1 `DisableCookies`, as the limiter takes it. See
/// [`RateLimiter::gate_handshake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieDefense {
    /// WireGuard's defense: under load, mac2 is required and a cookie reply
    /// demanded without it; without a source address, `UnderLoad`.
    Armed,
    /// `DisableCookies`: past mac1, the whole under-load branch is skipped --
    /// the load decision included -- and the message goes on to Noise.
    Bypassed,
}

/// Whether the limiter was under load when one received datagram reached it,
/// and whether a cookie-proven message in it was admitted, each decided at
/// most once per datagram. See [`RateLimiter::gate_handshake`].
#[derive(Default)]
pub(crate) struct LoadDecision {
    load: Option<Load>,
    proven: Option<bool>,
}

/// Why a handshake message found the limiter under load, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Load {
    Clear,
    /// Its source is past its share; the aggregate was not consulted.
    SourceShare,
    /// The aggregate is past `limit`.
    Aggregate,
}

#[cfg(test)]
impl LoadDecision {
    /// Whether a load decision has been taken for this datagram.
    pub(crate) fn is_decided(&self) -> bool {
        self.load.is_some()
    }
}

/// What [`RateLimiter::gate_handshake`] makes of one handshake message.
pub(crate) enum HandshakeGate {
    /// mac1 holds, and either the limiter is not under load or mac2 holds too:
    /// the message may go on to the Noise handshake.
    Pass,
    /// mac1 does not hold. Not a handshake message to this key.
    BadMac,
    /// Under load, and either no source address to check mac2 against, or a
    /// valid mac2 from a source past its share of proven messages: dropped,
    /// with nothing sent.
    UnderLoad,
    /// Under load, and mac2 does not hold: the answer is a cookie reply, not
    /// Noise work. Nothing about the sender has been authenticated -- mac1 is
    /// keyed on our *public* key -- which is why a receiver with other readings
    /// of the datagram to try holds this back until they have all failed.
    CookieDemanded(CookieDemand),
}

/// The inputs to the cookie reply a [`HandshakeGate::CookieDemanded`] calls
/// for, kept so the reply can be formatted only once it is known to be the
/// answer.
pub(crate) struct CookieDemand {
    sender_idx: u32,
    cookie: Cookie,
    mac1: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn limiter(limit: u64) -> RateLimiter {
        let secret = crate::x25519::StaticSecret::random_from_rng(OsRng);
        RateLimiter::new(&crate::x25519::PublicKey::from(&secret), limit)
    }

    fn endpoint(s: &str) -> Source {
        Source::Endpoint(s.parse().unwrap())
    }

    /// A canonical-length handshake message with a valid mac1 and, given a
    /// cookie, the mac2 it makes.
    fn message(limiter: &RateLimiter, cookie: Option<Cookie>) -> Vec<u8> {
        let mut message = vec![0u8; super::super::HANDSHAKE_INIT_SZ];
        OsRng.fill_bytes(&mut message[..116]);
        let mac1 = b2s_keyed_mac_16(&limiter.mac1_key, &message[..116]);
        message[116..132].copy_from_slice(&mac1);
        if let Some(cookie) = cookie {
            let mac2 = b2s_keyed_mac_16_2(&cookie, &message[..116], &mac1);
            message[132..].copy_from_slice(&mac2);
        }
        message
    }

    fn gate(limiter: &RateLimiter, source: Option<Source>, message: &[u8]) -> HandshakeGate {
        limiter.gate_handshake(
            source,
            message,
            1,
            CookieDefense::Armed,
            &mut LoadDecision::default(),
        )
    }

    fn passes(limiter: &RateLimiter, source: Source) -> bool {
        matches!(
            gate(limiter, Some(source), &message(limiter, None)),
            HandshakeGate::Pass
        )
    }

    #[test]
    fn the_cookie_covers_the_port_and_keeps_every_source_shape_apart() {
        let l = limiter(0);
        let cookies = [
            l.current_cookie(endpoint("192.0.2.1:1000")),
            l.current_cookie(endpoint("192.0.2.1:1001")),
            l.current_cookie(endpoint("192.0.2.2:1000")),
            l.current_cookie(Source::Address("192.0.2.1".parse().unwrap())),
            // The old zero-padded encoding made these two the same input.
            l.current_cookie(Source::Address("42.1.2.3".parse().unwrap())),
            l.current_cookie(Source::Address("2a01:203::".parse().unwrap())),
            l.current_cookie(endpoint("[2a01:203::]:1000")),
        ];
        for (i, a) in cookies.iter().enumerate() {
            for b in &cookies[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Stable for one endpoint, and an IPv4-mapped address is its IPv4.
        assert_eq!(cookies[0], l.current_cookie(endpoint("192.0.2.1:1000")));
        assert_eq!(
            cookies[0],
            l.current_cookie(endpoint("[::ffff:192.0.2.1]:1000"))
        );
    }

    /// A cookie answers the endpoint it was issued to: from another port of
    /// the same address -- another client behind the same NAT -- its mac2
    /// does not hold and a fresh cookie is demanded.
    #[test]
    fn a_cookie_validates_only_from_the_endpoint_it_was_issued_to() {
        let l = limiter(0);
        let issued = endpoint("198.51.100.7:40000");
        let message = message(&l, Some(l.current_cookie(issued)));
        assert!(matches!(
            gate(&l, Some(issued), &message),
            HandshakeGate::Pass
        ));
        for other in [
            endpoint("198.51.100.7:40001"),
            endpoint("198.51.100.8:40000"),
            Source::Address("198.51.100.7".parse().unwrap()),
        ] {
            assert!(matches!(
                gate(&l, Some(other), &message),
                HandshakeGate::CookieDemanded(_)
            ));
        }
        // No source at all: nothing to bind a cookie to.
        assert!(matches!(gate(&l, None, &message), HandshakeGate::UnderLoad));
    }

    #[test]
    fn the_share_follows_the_limit() {
        for (limit, share) in [(0, 0), (1, 1), (3, 3), (10, 5), (100, 20), (1000, 200)] {
            assert_eq!(limiter(limit).source_limit, share, "limit {}", limit);
        }
    }

    /// One flooding source is held to its share and gets cookies; another
    /// source, and the aggregate, are untouched by it.
    // Mock clock only: a real one could cross a window boundary mid-test
    // and reset the count being asserted on.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn one_flooding_source_does_not_put_everyone_under_load() {
        let l = limiter(100);
        let flooder = endpoint("203.0.113.1:5000");
        for _ in 0..20 {
            assert!(passes(&l, flooder));
        }
        for _ in 0..1000 {
            assert!(matches!(
                gate(&l, Some(flooder), &message(&l, None)),
                HandshakeGate::CookieDemanded(_)
            ));
        }
        assert_eq!(
            l.count.load(Ordering::SeqCst),
            20,
            "refused messages counted"
        );
        assert!(passes(&l, endpoint("198.51.100.9:6000")));
    }

    /// Ports do not multiply a budget, and neither do the addresses of one
    /// IPv6 /64; a different /64 is a different source.
    // Mock clock only: a real one could cross a window boundary mid-test
    // and reset the count being asserted on.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn a_budget_is_per_address_and_per_ipv6_slash_64() {
        let l = limiter(100);
        for port in 0..20u16 {
            assert!(passes(
                &l,
                Source::Endpoint((Ipv4Addr::new(192, 0, 2, 1), port).into())
            ));
        }
        assert!(!passes(&l, endpoint("192.0.2.1:9999")));

        let l = limiter(100);
        for host in 0..20u16 {
            let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host);
            assert!(passes(&l, Source::Endpoint((ip, 443).into())));
        }
        assert!(!passes(&l, endpoint("[2001:db8:0:1::ffff]:443")));
        assert!(passes(&l, endpoint("[2001:db8:0:2::1]:443")));
    }

    /// Sources that each stay inside their share -- as a spoofed flood does --
    /// are caught by the aggregate, and then everyone is asked for a cookie.
    #[test]
    fn many_sources_still_reach_the_aggregate_limit() {
        let l = limiter(100);
        for i in 0..100u32 {
            assert!(passes(
                &l,
                Source::Endpoint((Ipv4Addr::from(0x0a00_0000 + i), 1).into())
            ));
        }
        assert!(!passes(&l, endpoint("198.51.100.9:6000")));
    }

    /// With the aggregate over, a source returning with a valid mac2 is let
    /// through for its share of proven messages, then dropped -- one cookie
    /// does not buy unlimited Noise work. Mac1-only messages spoofing its
    /// address do not spend that allowance, and another proven source has its
    /// own.
    // Mock clock only, for the reason given on the tests above.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn a_proven_source_is_held_to_its_share_and_spoofing_cannot_spend_it() {
        let l = limiter(100);
        // A spoofed flood: sources that each stay inside their share.
        for i in 0..100u32 {
            assert!(passes(
                &l,
                Source::Endpoint((Ipv4Addr::from(0x0a00_0000 + i), 1).into())
            ));
        }
        let peer = endpoint("198.51.100.7:40000");
        let spoof = |source| {
            for _ in 0..1000 {
                assert!(!passes(&l, source));
            }
        };
        spoof(peer);
        let cookie = l.current_cookie(peer);
        for _ in 0..20 {
            assert!(matches!(
                gate(&l, Some(peer), &message(&l, Some(cookie))),
                HandshakeGate::Pass
            ));
            spoof(peer);
        }
        assert!(matches!(
            gate(&l, Some(peer), &message(&l, Some(cookie))),
            HandshakeGate::UnderLoad
        ));

        let other = endpoint("203.0.113.9:1");
        assert!(matches!(
            gate(&l, Some(other), &message(&l, Some(l.current_cookie(other)))),
            HandshakeGate::Pass
        ));
    }

    /// One client behind a shared address can spend that address's share --
    /// mac1-only messages are enough, its own cookie on top -- but its NAT
    /// neighbours are then cookied and let through while the aggregate has
    /// room: their proven messages are charged to it. Once the aggregate is
    /// spent, clients sharing an address share its proven share too, as on
    /// Linux, so the excess is dropped for the neighbour as well.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn a_nat_neighbour_is_cookied_not_dropped_while_the_aggregate_has_room() {
        let l = limiter(100);
        let attacker = endpoint("198.51.100.7:1");
        let neighbour = endpoint("198.51.100.7:2");
        for _ in 0..21 {
            gate(&l, Some(attacker), &message(&l, None));
        }
        let own = l.current_cookie(attacker);
        for _ in 0..21 {
            assert!(matches!(
                gate(&l, Some(attacker), &message(&l, Some(own))),
                HandshakeGate::Pass
            ));
        }
        assert!(matches!(
            gate(&l, Some(neighbour), &message(&l, None)),
            HandshakeGate::CookieDemanded(_)
        ));
        assert!(matches!(
            gate(
                &l,
                Some(neighbour),
                &message(&l, Some(l.current_cookie(neighbour)))
            ),
            HandshakeGate::Pass
        ));
        // Proven messages from an address over its share draw on the
        // aggregate, so Noise work stays bounded at `limit`: once it is spent
        // the per-source proven share applies to them too.
        for _ in 0..200 {
            gate(&l, Some(attacker), &message(&l, Some(own)));
        }
        assert!(l.count.load(Ordering::SeqCst) >= 100);
        assert!(matches!(
            gate(&l, Some(attacker), &message(&l, Some(own))),
            HandshakeGate::UnderLoad
        ));
        assert!(matches!(
            gate(
                &l,
                Some(neighbour),
                &message(&l, Some(l.current_cookie(neighbour)))
            ),
            HandshakeGate::UnderLoad
        ));
    }

    /// A zero-budget limiter, under load from the first message, still lets a
    /// few cookie-carrying messages per source through.
    #[test]
    fn a_zero_budget_limiter_still_honours_cookies() {
        let l = limiter(0);
        let peer = endpoint("198.51.100.7:40000");
        let cookie = l.current_cookie(peer);
        assert!(matches!(
            gate(&l, Some(peer), &message(&l, Some(cookie))),
            HandshakeGate::Pass
        ));
    }

    /// A slot already moved on to a later window by another thread is counted
    /// there, not reset to the caller's older window.
    #[test]
    fn a_late_count_does_not_reset_a_newer_window() {
        let counts = SourceCounts::new();
        let source = endpoint("192.0.2.33:1");
        for _ in 0..3 {
            counts.count(source, 8);
        }
        assert_eq!(counts.count(source, 7), 4);
        assert_eq!(counts.count(source, 8), 5);
        assert_eq!(counts.count(source, 9), 1);
    }

    /// The table never grows, however many sources it has seen.
    #[test]
    fn the_per_source_table_is_bounded() {
        let l = limiter(u64::MAX);
        for i in 0..100_000u32 {
            l.sources
                .count(Source::Address(IpAddr::V4(Ipv4Addr::from(i))), 0);
        }
        assert_eq!(l.sources.slots.len(), SOURCE_ROWS * SOURCE_SLOTS);
    }

    /// Concurrent counts from many threads lose no update.
    #[test]
    fn concurrent_counts_are_exact() {
        let counts = std::sync::Arc::new(SourceCounts::new());
        let source = endpoint("192.0.2.33:1");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let counts = std::sync::Arc::clone(&counts);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        counts.count(source, 7);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(counts.count(source, 7), 8001);
        // A later window starts from nothing.
        assert_eq!(counts.count(source, 8), 1);
    }

    /// A datagram read as two handshake messages, each with a valid mac2, is
    /// charged once: the second reading shares the first's admission, even
    /// when the first took the source's last proven slot -- so a reading that
    /// Noise then refuses does not keep the other one out.
    #[test]
    fn a_datagram_read_twice_is_charged_once() {
        let l = limiter(0);
        let peer = endpoint("198.51.100.7:40000");
        let cookie = l.current_cookie(peer);
        // Spend all but one of the proven share (`SOURCE_FLOOR` at limit 0).
        for _ in 0..SOURCE_FLOOR - 1 {
            assert!(matches!(
                gate(&l, Some(peer), &message(&l, Some(cookie))),
                HandshakeGate::Pass
            ));
        }
        let mut load = LoadDecision::default();
        for _ in 0..2 {
            assert!(matches!(
                l.gate_handshake(
                    Some(peer),
                    &message(&l, Some(cookie)),
                    1,
                    CookieDefense::Armed,
                    &mut load
                ),
                HandshakeGate::Pass
            ));
        }
        // One slot was charged for the datagram, so the share is now spent.
        assert!(matches!(
            gate(&l, Some(peer), &message(&l, Some(cookie))),
            HandshakeGate::UnderLoad
        ));
    }

    /// The bounded table's trade-off, pinned: a source that shares every
    /// proven slot with one past its proven share has its own cookie-proven
    /// messages dropped -- not cookied -- until the window ends.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn a_full_collision_in_the_proven_table_drops_until_the_window_ends() {
        let l = limiter(0);
        let slots = |ip: u32| -> Vec<usize> {
            l.proven
                .slots_of(Source::Address(IpAddr::V4(Ipv4Addr::from(ip))))
                .collect()
        };
        // Two sources sharing every slot: about 2^11 such pairs among 2^16.
        let mut seen = std::collections::HashMap::new();
        let (a, b) = (0..1u32 << 16)
            .find_map(|ip| seen.insert(slots(ip), ip).map(|first| (first, ip)))
            .expect("a full collision among 2^16 sources");
        let source = |ip: u32| Source::Endpoint((Ipv4Addr::from(ip), 1).into());
        let (a, b) = (source(a), source(b));
        for _ in 0..SOURCE_FLOOR {
            assert!(matches!(
                gate(&l, Some(a), &message(&l, Some(l.current_cookie(a)))),
                HandshakeGate::Pass
            ));
        }
        assert!(matches!(
            gate(&l, Some(b), &message(&l, Some(l.current_cookie(b)))),
            HandshakeGate::UnderLoad
        ));
        mock_instant::thread_local::MockClock::advance(std::time::Duration::from_secs(1));
        assert!(matches!(
            gate(&l, Some(b), &message(&l, Some(l.current_cookie(b)))),
            HandshakeGate::Pass
        ));
    }

    /// A source's share comes back in the next second without anyone calling
    /// `reset_count`; the aggregate keeps its existing reset.
    #[cfg(feature = "mock-instant")]
    #[test]
    fn a_source_share_expires_with_its_window() {
        let l = limiter(100);
        let source = endpoint("203.0.113.1:5000");
        for _ in 0..20 {
            assert!(passes(&l, source));
        }
        assert!(!passes(&l, source));
        mock_instant::thread_local::MockClock::advance(std::time::Duration::from_secs(1));
        assert!(passes(&l, source));
    }
}
