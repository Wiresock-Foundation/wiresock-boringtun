// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Compile-time check that wireguard_ffi.h declares the ABI the Rust side
// implements.
//
// The header is hand-written -- there is no cbindgen -- so the C and Rust
// declarations can only drift apart silently, and a layout disagreement is not
// a build failure in either language. It is a caller's `reject_after_time`
// arriving as somebody else's field.
//
// The numbers below are the same literals `ffi::tests::awg_params_layout_is_pinned`
// asserts on the Rust side. Neither set is derived from the other, which is the
// point: the two declarations are checked against one shared, written-down
// answer rather than against each other.
//
// Built by CI for both 32- and 64-bit targets. `size` is the ABI's
// forward-compatibility anchor, so a struct whose size differed between them
// would make the versioning rule meaningless -- hence no pointer and no
// sub-word member anywhere in it.
//
// Nothing here runs; every check is a static assertion.

#include <stddef.h>
#include "../boringtun/src/wireguard_ffi.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define WG_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
// C99 fallback: a negative-width bit-field is a constraint violation, so this
// fails the build with the message in the type name.
#define WG_STATIC_ASSERT(cond, msg) \
    typedef struct { int static_assertion_failed : ((cond) ? 1 : -1); } \
        wg_static_assert_##__LINE__##_t
#endif

WG_STATIC_ASSERT(sizeof(struct wireguard_awg_range) == 8,
                 "wireguard_awg_range must be two uint32_t and nothing else");

WG_STATIC_ASSERT(sizeof(struct wireguard_awg_params) == 160,
                 "wireguard_awg_params size is the ABI version anchor; it must "
                 "match AWG_PARAMS_SIZE_VER0 and be identical on 32- and 64-bit");

// EVERY field offset, not a sample. Sampling is not enough: narrowing one
// member to uint16_t only moves the two bytes after it into padding, leaving
// both the total size and every later offset untouched -- a change that
// silently reinterprets one field while passing any check that looks only at
// sizeof and a few landmarks. The exhaustive list is also what makes "no
// padding" a real claim rather than an arithmetic identity, since consecutive
// offsets must differ by exactly the member's width.
#define WG_OFF(field) offsetof(struct wireguard_awg_params, field)

WG_STATIC_ASSERT(WG_OFF(size) == 0,
                 "size must lead the struct: it is read before anything else is trusted");
WG_STATIC_ASSERT(WG_OFF(s1_init_junk) == 4, "s1_init_junk moved");
WG_STATIC_ASSERT(WG_OFF(s2_response_junk) == 8, "s2_response_junk moved");
WG_STATIC_ASSERT(WG_OFF(s3_cookie_junk) == 12, "s3_cookie_junk moved");
WG_STATIC_ASSERT(WG_OFF(s4_transport_junk) == 16, "s4_transport_junk moved");
WG_STATIC_ASSERT(WG_OFF(junk_packet_count) == 20, "junk_packet_count moved");
WG_STATIC_ASSERT(WG_OFF(junk_packet_size_min) == 24, "junk_packet_size_min moved");
WG_STATIC_ASSERT(WG_OFF(junk_packet_size_max) == 28, "junk_packet_size_max moved");
WG_STATIC_ASSERT(WG_OFF(junk_packet_delay_ms) == 32, "junk_packet_delay_ms moved");
WG_STATIC_ASSERT(WG_OFF(h1_init) == 36, "h1_init moved");
WG_STATIC_ASSERT(WG_OFF(h2_resp) == 44, "h2_resp moved");
WG_STATIC_ASSERT(WG_OFF(h3_cookie) == 52, "h3_cookie moved");
WG_STATIC_ASSERT(WG_OFF(h4_data) == 60, "h4_data moved");
WG_STATIC_ASSERT(WG_OFF(imitation_protocol) == 68, "imitation_protocol moved");
WG_STATIC_ASSERT(WG_OFF(imitation_browser) == 72, "imitation_browser moved");
WG_STATIC_ASSERT(WG_OFF(content_padding_addition) == 76, "content_padding_addition moved");
WG_STATIC_ASSERT(WG_OFF(content_padding_mtu) == 84, "content_padding_mtu moved");
WG_STATIC_ASSERT(WG_OFF(rekey_after_time) == 88, "rekey_after_time moved");
WG_STATIC_ASSERT(WG_OFF(rekey_timeout) == 96, "rekey_timeout moved");
WG_STATIC_ASSERT(WG_OFF(reject_after_time) == 104, "reject_after_time moved");
WG_STATIC_ASSERT(WG_OFF(keepalive_timeout) == 112, "keepalive_timeout moved");
WG_STATIC_ASSERT(WG_OFF(max_handshake_attempts) == 120, "max_handshake_attempts moved");
WG_STATIC_ASSERT(WG_OFF(header_protection_key) == 128, "header_protection_key moved");

// EVERY member's width as well. Offsets and sizeof share a blind spot:
// narrowing a member to uint16_t is absorbed by the padding that follows it,
// so the total size and every later offset stay exactly where they were while
// the member now reads two bytes instead of four. Nothing above catches that;
// this does. (Found by mutating the header and watching the check pass.)
#define WG_FIELD_SIZE(field) sizeof(((struct wireguard_awg_params *)0)->field)

WG_STATIC_ASSERT(WG_FIELD_SIZE(size) == 4, "size must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(s1_init_junk) == 4, "s1_init_junk must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(s2_response_junk) == 4, "s2_response_junk must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(s3_cookie_junk) == 4, "s3_cookie_junk must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(s4_transport_junk) == 4, "s4_transport_junk must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(junk_packet_count) == 4, "junk_packet_count must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(junk_packet_size_min) == 4, "junk_packet_size_min must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(junk_packet_size_max) == 4, "junk_packet_size_max must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(junk_packet_delay_ms) == 4, "junk_packet_delay_ms must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(h1_init) == 8, "h1_init must be a wireguard_awg_range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(h2_resp) == 8, "h2_resp must be a wireguard_awg_range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(h3_cookie) == 8, "h3_cookie must be a wireguard_awg_range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(h4_data) == 8, "h4_data must be a wireguard_awg_range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(imitation_protocol) == 4, "imitation_protocol must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(imitation_browser) == 4, "imitation_browser must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(content_padding_addition) == 8,
                 "content_padding_addition must be a wireguard_awg_range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(content_padding_mtu) == 4, "content_padding_mtu must be uint32_t");
WG_STATIC_ASSERT(WG_FIELD_SIZE(rekey_after_time) == 8, "rekey_after_time must be a range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(rekey_timeout) == 8, "rekey_timeout must be a range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(reject_after_time) == 8, "reject_after_time must be a range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(keepalive_timeout) == 8, "keepalive_timeout must be a range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(max_handshake_attempts) == 8,
                 "max_handshake_attempts must be a range");
WG_STATIC_ASSERT(WG_FIELD_SIZE(header_protection_key) == 32,
                 "header_protection_key must be 32 bytes");

// The declaration the client links against. Taking its address is enough to
// require that it exists with exactly this signature.
static struct wireguard_tunnel *(*const check_ctor)(
    const char *, const char *, const char *, uint16_t, uint32_t,
    const struct wireguard_awg_params *, const char *) = new_tunnel_with_awg_params;

// Referenced so no compiler warns it is unused; never called.
const void *wg_ffi_layout_check_anchor(void) { return (const void *)check_ctor; }
