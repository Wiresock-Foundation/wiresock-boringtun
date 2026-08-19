// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <stdint.h>
#include <stdbool.h>

struct wireguard_tunnel; // This corresponds to the Rust type

enum
{
    MAX_WIREGUARD_PACKET_SIZE = 65536 + 64,
};

enum result_type
{
    WIREGUARD_DONE = 0,
    WRITE_TO_NETWORK = 1,
    WIREGUARD_ERROR = 2,
    WRITE_TO_TUNNEL_IPV4 = 4,
    WRITE_TO_TUNNEL_IPV6 = 6,
};

struct wireguard_result
{
    enum result_type op;
    size_t size;
};

struct stats
{
    int64_t time_since_last_handshake;
    size_t tx_bytes;
    size_t rx_bytes;
    float estimated_loss;
    int32_t estimated_rtt; // rtt estimated on time it took to complete latest initiated handshake in ms
    uint8_t reserved[56];  // decrement appropriately when adding new fields
};

struct x25519_key
{
    uint8_t key[32];
};

// Generates a fresh x25519 secret key
struct x25519_key x25519_secret_key();
// Computes an x25519 public key from a secret key
struct x25519_key x25519_public_key(struct x25519_key private_key);
// Encodes a public or private x25519 key to base64. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_base64(struct x25519_key key);
// Encodes a public or private x25519 key to hex. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_hex(struct x25519_key key);
// Free string pointer obtained from either x25519_key_to_base64 or x25519_key_to_hex
void x25519_key_to_str_free(const char *key_str);
// Check if a null terminated string represents a valid x25519 key
// Returns 0 if not
int check_base64_encoded_x25519_key(const char *key);

/// Sets the default tracing_subscriber to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default tracing_subscriber
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
bool set_logging_function(void (*log_func)(const char *));

/// ---------------------------------------------------------------------------
/// Tunnel constructors
///
/// New code should call new_tunnel_with_awg_params(), declared at the end of
/// this header: it takes one extensible struct, is the only entry point that
/// can express the AmneziaWG 3.0 features (header protection, content padding,
/// tunable timers), and validates the whole configuration before a tunnel
/// exists.
///
/// The seven constructors immediately below are the earlier interface, one per
/// combination of features, and they remain supported -- their signatures and
/// behaviour are unchanged and existing callers need do nothing. They cannot
/// reach the 3.0 parameters, and each new feature would have doubled their
/// number again, which is why the struct form exists.
/// ---------------------------------------------------------------------------

/// Allocate a new tunnel, returning NULL on failure.
///
/// Keys must be valid base64-encoded 32-byte keys.
/// `preshared_key` may be NULL if no PSK is used.
///
/// ## Amnezia obfuscation tag ranges (H1-H4)
///
/// Each WireGuard packet type has an associated 4-byte "message type" tag.
/// The h1-h4 start/end pairs let you override these tags with inclusive
/// ranges [start, end].  On outgoing packets a value is chosen uniformly
/// at random from the range; on incoming packets any value within the range
/// is accepted for that packet type.
///
/// **Sentinel rules for each (start, end) pair:**
///
/// | start | end   | Resolved range                              |
/// |-------|-------|---------------------------------------------|
/// | 0     | 0     | Default WireGuard constant (1, 2, 3, or 4)  |
/// | S > 0 | 0     | Fixed value [S, S]  (back-compat shorthand) |
/// | S     | E >= S| Custom inclusive range [S, E]                |
/// | S     | E < S | **Invalid** - returns NULL                   |
///
/// **Non-overlap requirement:**
///
/// The four resolved ranges must not overlap (including at boundaries).
/// For example H1=[10, 20] and H4=[20, 30] is rejected because value 20
/// belongs to both.  On conflict the function returns NULL.
///
/// **Quick-start examples:**
///
///   // Standard WireGuard (no obfuscation):
///   new_tunnel(priv, pub, NULL, 25, idx, 0,0, 0,0, 0,0, 0,0);
///
///   // Fixed Amnezia-style tags (single values):
///   new_tunnel(priv, pub, NULL, 25, idx, 10,10, 20,20, 30,30, 40,40);
///
///   // Random tags from non-overlapping ranges:
///   new_tunnel(priv, pub, NULL, 25, idx, 100,199, 200,299, 300,399, 400,499);
///
struct wireguard_tunnel *new_tunnel(const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,       // Keep alive interval in seconds
                                    uint32_t index,            // The 24bit index prefix for session indexes
                                    uint32_t h1_init_start,    // H1 (handshake init) inclusive range start
                                    uint32_t h1_init_end,      // H1 (handshake init) inclusive range end
                                    uint32_t h2_resp_start,    // H2 (handshake resp) inclusive range start
                                    uint32_t h2_resp_end,      // H2 (handshake resp) inclusive range end
                                    uint32_t h3_cookie_start,  // H3 (cookie reply)   inclusive range start
                                    uint32_t h3_cookie_end,    // H3 (cookie reply)   inclusive range end
                                    uint32_t h4_data_start,    // H4 (transport data) inclusive range start
                                    uint32_t h4_data_end);     // H4 (transport data) inclusive range end

/// Allocates a new tunnel with AmneziaWG S1-S4 junk prefix handling.
///
/// This preserves the H1-H4 tag range behavior from new_tunnel() and additionally
/// configures byte prefixes for each WireGuard packet type:
///   S1: handshake initiation junk
///   S2: handshake response junk
///   S3: cookie reply junk
///   S4: transport-data junk
///
/// Passing zero for all S-values gives the same packet sizes as new_tunnel().
///
/// Callers must size output buffers for the configured prefixes. For example,
/// handshake initiation may require 148 + S1 bytes, handshake response 92 + S2
/// bytes, cookie reply 64 + S3 bytes, and transport packets their encrypted
/// WireGuard size + S4 bytes. If the destination buffer is too small, the
/// operation returns WIREGUARD_ERROR.
struct wireguard_tunnel *new_tunnel_with_amnezia(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk);

/// Allocates a new tunnel with AmneziaWG pre-handshake junk packets and S1-S4
/// junk prefix handling.
///
/// Jc/Jmin/Jmax/Jd configure standalone junk packets emitted before each
/// handshake initiation:
///   Jc: number of junk packets; values above 128 disable standalone junk
///   Jmin/Jmax: random junk packet size bounds for random junk. When junk is
///     enabled, both zero values or invalid ranges fall back to 50..1000 bytes;
///     valid custom ranges require 1 <= Jmin <= Jmax <= 1280.
///   Jd: delay in milliseconds after each junk packet before the next packet
///     or handshake initiation; values above 200 are treated as zero delay.
///
/// BoringTun returns one UDP datagram per API call. After a call returns a junk
/// packet, call wireguard_tick() periodically to emit the remaining junk packets
/// and the delayed handshake initiation.
/// Output buffers used with wireguard_write(), wireguard_force_handshake(), and
/// wireguard_tick() must also fit standalone junk packets (up to 1280 bytes).
struct wireguard_tunnel *new_tunnel_with_amnezia_junk(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk,
                                    uint16_t junk_packet_count,
                                    uint16_t junk_packet_size_min,
                                    uint16_t junk_packet_size_max,
                                    uint16_t junk_packet_delay_ms);

// Protocol imitation selector. Beyond shaping the S1-S4 junk prefixes, a
// non-NONE protocol emits a standalone, protocol-natural datagram sequence
// before the handshake initiation: DNS sends A/AAAA/HTTPS queries; SIP sends an
// INVITE then a matching CANCEL; STUN sends two ICE Binding Requests (the second
// with USE-CANDIDATE) carrying MESSAGE-INTEGRITY and FINGERPRINT. QUIC sends full
// browser-fingerprinted QUIC Initial(s); the browser defaults to curl when none
// is given (see new_tunnel_with_amnezia_imitation_browser and
// wireguard_amnezia_browser_profile). The imitation sequence is followed by the
// Jc protocol-shaped junk packets (if any) and then the handshake. The caller
// must drain all of these via wireguard_write()/wireguard_tick() (one datagram
// per call) as for any pre-handshake junk.
enum wireguard_amnezia_imitation_protocol {
    WIREGUARD_AMNEZIA_IMITATION_NONE = 0,
    WIREGUARD_AMNEZIA_IMITATION_DNS = 1,
    WIREGUARD_AMNEZIA_IMITATION_QUIC = 2,
    WIREGUARD_AMNEZIA_IMITATION_SIP = 3,
    WIREGUARD_AMNEZIA_IMITATION_STUN = 4,
};

/// Allocates a new tunnel with AmneziaWG S1-S4 junk prefix handling and protocol
/// imitation.
///
/// `imitation_protocol` uses enum wireguard_amnezia_imitation_protocol values
/// and triggers the pre-handshake imitation sequence described on that enum.
/// `imitation_domain` may be NULL; it is the DNS query name / SIP URI host / QUIC
/// SNI. DNS and SIP require a strict LDH host name; the QUIC SNI also accepts
/// UTF-8/IDN. Invalid values are dropped and a random host is generated instead.
/// If both this protocol imitation and a non-zero junk_packet_count (Jc) are
/// configured, the imitation sequence is emitted first, then the Jc
/// protocol-shaped junk packets, then the handshake.
struct wireguard_tunnel *new_tunnel_with_amnezia_imitation(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk,
                                    uint8_t imitation_protocol,
                                    const char *imitation_domain);

/// Allocates a new tunnel with AmneziaWG pre-handshake junk packets, S1-S4 junk
/// prefix handling, and protocol-shaped junk bytes.
///
/// When imitation is enabled, standalone pre-handshake junk packets use
/// protocol-appropriate sizes instead of Jmin/Jmax. S1-S4 padding still uses the
/// configured S sizes. The imitation_protocol and imitation_domain rules are the
/// same as new_tunnel_with_amnezia_imitation. The Jc/Jd bounds and output buffer
/// requirements are the same as new_tunnel_with_amnezia_junk.
struct wireguard_tunnel *new_tunnel_with_amnezia_junk_imitation(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk,
                                    uint16_t junk_packet_count,
                                    uint16_t junk_packet_size_min,
                                    uint16_t junk_packet_size_max,
                                    uint16_t junk_packet_delay_ms,
                                    uint8_t imitation_protocol,
                                    const char *imitation_domain);

// Browser fingerprint selector for QUIC protocol imitation. Every value emits a
// full browser-fingerprinted QUIC Initial; DEFAULT resolves to CURL (matching
// wgbooster's default when a domain is set but no browser is given), and RANDOM
// picks Chrome, Firefox, or curl per connection. Only meaningful when
// imitation_protocol is QUIC.
enum wireguard_amnezia_browser_profile {
    WIREGUARD_AMNEZIA_BROWSER_DEFAULT = 0,
    WIREGUARD_AMNEZIA_BROWSER_CHROME = 1,
    WIREGUARD_AMNEZIA_BROWSER_FIREFOX = 2,
    WIREGUARD_AMNEZIA_BROWSER_CURL = 3,
    WIREGUARD_AMNEZIA_BROWSER_RANDOM = 4,
};

/// Allocates a new tunnel with AmneziaWG S1-S4 junk prefix handling and a
/// browser-fingerprinted QUIC Initial imitation.
///
/// `imitation_browser` uses enum wireguard_amnezia_browser_profile and is only
/// meaningful when imitation_protocol is QUIC. For any value (DEFAULT resolves to
/// curl), the pre-handshake phase emits the standalone browser QUIC Initial(s)
/// (two for Chrome/Firefox, one for curl) carrying a ClientHello whose SNI is
/// imitation_domain (a random host is generated when NULL/invalid).
struct wireguard_tunnel *new_tunnel_with_amnezia_imitation_browser(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk,
                                    uint8_t imitation_protocol,
                                    const char *imitation_domain,
                                    uint8_t imitation_browser);

/// Allocates a new tunnel with AmneziaWG pre-handshake junk packets, S1-S4 junk
/// prefix handling, and a browser-fingerprinted QUIC Initial imitation.
///
/// As new_tunnel_with_amnezia_imitation_browser plus the Jc/Jmin/Jmax/Jd
/// pre-handshake junk knobs. When a QUIC browser is selected the standalone
/// browser Initial(s) are emitted before the handshake regardless of Jc; output
/// buffers must fit them (up to 1252 bytes).
struct wireguard_tunnel *new_tunnel_with_amnezia_junk_imitation_browser(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    uint32_t h1_init_start,
                                    uint32_t h1_init_end,
                                    uint32_t h2_resp_start,
                                    uint32_t h2_resp_end,
                                    uint32_t h3_cookie_start,
                                    uint32_t h3_cookie_end,
                                    uint32_t h4_data_start,
                                    uint32_t h4_data_end,
                                    uint16_t s1_init_junk,
                                    uint16_t s2_response_junk,
                                    uint16_t s3_cookie_junk,
                                    uint16_t s4_transport_junk,
                                    uint16_t junk_packet_count,
                                    uint16_t junk_packet_size_min,
                                    uint16_t junk_packet_size_max,
                                    uint16_t junk_packet_delay_ms,
                                    uint8_t imitation_protocol,
                                    const char *imitation_domain,
                                    uint8_t imitation_browser);

/// An inclusive [lo, hi] range.
///
/// {0, 0} is the unset sentinel, exactly as it is in the AmneziaWG UAPI and on
/// the wire: the built-in default governs and nothing is drawn. A degenerate
/// range (lo == hi) is a fixed value.
struct wireguard_awg_range
{
    uint32_t lo;
    uint32_t hi;
};

/// Every AmneziaWG parameter this build understands, in one extensible struct.
///
/// Pass to new_tunnel_with_awg_params. This is the only way to reach the
/// AmneziaWG 3.0 features -- header protection, content padding and the tunable
/// timers -- which none of the new_tunnel_with_amnezia* constructors above can
/// express.
///
/// VERSIONING. Set `size` to sizeof(struct wireguard_awg_params) and zero the
/// rest, e.g.
///
///     struct wireguard_awg_params p = {0};
///     p.size = sizeof(p);
///
/// That is what lets this struct grow without another entry point. A struct
/// SMALLER than the library knows is a caller built against an older header;
/// the missing tail reads as unset. A LARGER one is accepted only if every byte
/// past what the library understands is zero -- i.e. the caller is not using
/// the newer fields. If any is non-zero the call fails rather than silently
/// dropping a parameter that was set: a discarded header-protection key would
/// produce a tunnel that is mutually unreachable with its peer, which is far
/// worse than a refused constructor.
///
/// LAYOUT. Every field is a uint32_t, an array of them, or a fixed byte array;
/// there is no pointer and no sub-word member, so the struct has no padding and
/// the same size (160 bytes) and layout in 32- and 64-bit builds. The imitation
/// domain is a string and so is passed as its own argument.
struct wireguard_awg_params
{
    /// sizeof(struct wireguard_awg_params). See VERSIONING above.
    uint32_t size;

    /// S1-S4: junk prepended to handshake initiation, handshake response,
    /// cookie reply and transport packets. 0 disables that prefix. Output
    /// buffers must fit the base packet plus the configured prefix.
    uint32_t s1_init_junk;
    uint32_t s2_response_junk;
    uint32_t s3_cookie_junk;
    uint32_t s4_transport_junk;

    /// Jc/Jmin/Jmax/Jd: the pre-handshake junk burst -- packet count, size
    /// bounds, and the delay between packets in milliseconds.
    uint32_t junk_packet_count;
    uint32_t junk_packet_size_min;
    uint32_t junk_packet_size_max;
    uint32_t junk_packet_delay_ms;

    /// H1-H4: message-type tag ranges for initiation, response, cookie reply
    /// and transport packets. Unset leaves the vanilla WireGuard type.
    struct wireguard_awg_range h1_init;
    struct wireguard_awg_range h2_resp;
    struct wireguard_awg_range h3_cookie;
    struct wireguard_awg_range h4_data;

    /// Protocol imitation, and the browser profile QUIC imitates; the browser
    /// is ignored for every other protocol. Same values the constructors above
    /// take.
    uint32_t imitation_protocol;
    uint32_t imitation_browser;

    /// AmneziaWG 3.0 content_padding_addition: zero bytes appended to each
    /// transport plaintext, inside the AEAD. Unset still rounds the plaintext
    /// up to a 16-byte multiple, as every WireGuard implementation does.
    struct wireguard_awg_range content_padding_addition;
    /// The MTU the padding is clamped against, so a full-MTU packet is not
    /// grown past what the link carries. 0 means "no MTU known", leaving the
    /// caller's buffer as the only bound.
    uint32_t content_padding_mtu;

    /// AmneziaWG 3.0 tunable timers, in seconds -- except
    /// max_handshake_attempts, which is a count. Unset means the classic
    /// WireGuard constant governs, so an all-zero block is vanilla timing.
    struct wireguard_awg_range rekey_after_time;
    struct wireguard_awg_range rekey_timeout;
    struct wireguard_awg_range reject_after_time;
    struct wireguard_awg_range keepalive_timeout;
    struct wireguard_awg_range max_handshake_attempts;

    /// AmneziaWG 3.0 header_protection_key: a 32-byte key masking the
    /// message-type field. All zero means off, matching amneziawg-go, so this
    /// is also how it is disabled again. Both ends must carry the same key --
    /// it is not negotiated, so a mismatch is a tunnel that never forms.
    uint8_t header_protection_key[32];
};

/// Allocate a new tunnel from a full set of AmneziaWG parameters.
///
/// The one constructor that can express every AmneziaWG feature this build
/// implements. Keys must be valid base64-encoded 32-byte keys.
///
/// `params` may be NULL, which is a plain WireGuard tunnel with no AmneziaWG
/// behaviour at all. `imitation_domain` may be NULL, and is ignored by the
/// protocols that do not carry a hostname.
///
/// Unlike the constructors above, the whole configuration is validated before a
/// tunnel exists: parameters that could never emit a valid datagram, or timers
/// ordered so that keys would be rejected before the rekey replacing them
/// completes, fail here rather than becoming a tunnel that silently never
/// works.
///
/// Returns NULL on failure, with the reason in last_tunnel_error().
struct wireguard_tunnel *new_tunnel_with_awg_params(
                                    const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,
                                    uint32_t index,
                                    const struct wireguard_awg_params *params,
                                    const char *imitation_domain);

// Returns a pointer to the last error message from any tunnel constructor, or
// NULL if no error is stored. The pointer is valid until the next constructor
// call on the same thread, or until freed with last_tunnel_error_free.
const char *last_tunnel_error();

// Frees the last error string stored by a tunnel constructor. After this call
// last_tunnel_error will return NULL until the next failure.
void last_tunnel_error_free();

// Deallocate the tunnel
void tunnel_free(struct wireguard_tunnel *);

struct wireguard_result wireguard_write(const struct wireguard_tunnel *tunnel,
                                        const uint8_t *src,
                                        uint32_t src_size,
                                        uint8_t *dst,
                                        uint32_t dst_size);

struct wireguard_result wireguard_read(const struct wireguard_tunnel *tunnel,
                                       const uint8_t *src,
                                       uint32_t src_size,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_tick(const struct wireguard_tunnel *tunnel,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_force_handshake(const struct wireguard_tunnel *tunnel,
                                                  uint8_t *dst,
                                                  uint32_t dst_size);

struct stats wireguard_stats(const struct wireguard_tunnel *tunnel);
