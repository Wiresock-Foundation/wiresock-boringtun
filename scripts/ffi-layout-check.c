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

// The header comes FIRST and pulls its own dependencies, which is half the
// check: a client translation unit that includes wireguard_ffi.h before
// anything else must compile. Including <stddef.h> ahead of it -- as this file
// originally did -- silently supplied the size_t that the header itself was
// failing to declare, so the one job that compiles the header was structurally
// blind to whether the header stands alone.
#include "../boringtun/src/wireguard_ffi.h"

#include <stddef.h>

// C11 or newer only. There was a C99 fallback here that could not work: `##`
// suppresses expansion of its operands, so `wg_static_assert_##__LINE__##_t`
// pastes the literal identifier `wg_static_assert___LINE___t` for every
// assertion rather than one per line, and the second typedef of that name is a
// constraint violation. It also dropped `msg` entirely, so the message was not
// "in the type name" as its comment claimed. Every one of the assertions below
// would have failed, independently of whether the ABI was correct -- a check
// that cries wolf is worse than no check. An explicit #error says what is
// needed instead of pretending to cope.
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#error "ffi-layout-check.c requires C11 for _Static_assert; build with -std=c11 (MSVC: /std:c11)"
#endif

#define WG_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

// The nested range, inside and out. `sizeof == 8` alone does not pin it:
// swapping `lo` and `hi` leaves the size, the alignment, and every offset and
// width in the outer struct untouched, so this file passed clean against a
// header in which every range in the ABI was inverted. For the timers and the
// content padding the Rust side then re-sorts the transposed pair silently, so
// nothing downstream complains either.
WG_STATIC_ASSERT(sizeof(struct wireguard_awg_range) == 8,
                 "wireguard_awg_range must be two uint32_t and nothing else");
WG_STATIC_ASSERT(offsetof(struct wireguard_awg_range, lo) == 0,
                 "lo must lead wireguard_awg_range");
WG_STATIC_ASSERT(offsetof(struct wireguard_awg_range, hi) == 4,
                 "hi must follow lo in wireguard_awg_range");
WG_STATIC_ASSERT(sizeof(((struct wireguard_awg_range *)0)->lo) == 4, "lo must be uint32_t");
WG_STATIC_ASSERT(sizeof(((struct wireguard_awg_range *)0)->hi) == 4, "hi must be uint32_t");

WG_STATIC_ASSERT(sizeof(struct wireguard_awg_params) == 160,
                 "wireguard_awg_params size is the ABI version anchor; it must "
                 "match AWG_PARAMS_SIZE_VER0 and be identical on 32- and 64-bit");

// Alignment as well as size, matching what `ffi::tests::awg_params_layout_is_pinned`
// pins with `align_of`. Neither side's offsets can see it: a `#pragma pack(1)`
// over a struct that has no padding to begin with leaves every offset and the
// total size exactly where they are, so only an explicit alignment assertion
// notices that the C declaration now permits an object the Rust declaration
// does not.
WG_STATIC_ASSERT(_Alignof(struct wireguard_awg_range) == 4,
                 "wireguard_awg_range must stay 4-byte aligned");
WG_STATIC_ASSERT(_Alignof(struct wireguard_awg_params) == 4,
                 "wireguard_awg_params must stay 4-byte aligned");

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

// `wireguard_result` and `stats` -- the two structs in this header whose size
// really does change with the word size (16/88 on LP64, 8/80 on ILP32, because
// both hold `size_t`), and both crossed BY VALUE as return types, which is the
// most ABI-sensitive crossing there is. The struct this file was written for
// cannot differ between the two, so it was the only one checked; these two,
// which can, had no pin anywhere in the tree. Expressed relative to
// `sizeof(size_t)` so one set of assertions holds under -m32 and -m64.
WG_STATIC_ASSERT(sizeof(struct wireguard_result) == 2 * sizeof(size_t),
                 "wireguard_result must be an enum and a size_t with no tail padding");
WG_STATIC_ASSERT(offsetof(struct wireguard_result, size) == sizeof(size_t),
                 "wireguard_result::size moved");
WG_STATIC_ASSERT(sizeof(((struct wireguard_result *)0)->size) == sizeof(size_t),
                 "wireguard_result::size must be size_t");
WG_STATIC_ASSERT(sizeof(((struct wireguard_result *)0)->op) == sizeof(int),
                 "wireguard_result::op must be a plain enum");

// The five published `stats` members, pinned where they are. `reserved` is
// deliberately NOT pinned by offset: shrinking it to make room for a new field
// is the documented, size-preserving way to extend this struct, and an
// offsetof(reserved) assertion would fail on exactly that safe path.
WG_STATIC_ASSERT(offsetof(struct stats, time_since_last_handshake) == 0, "stats layout changed");
WG_STATIC_ASSERT(offsetof(struct stats, tx_bytes) == 8, "stats::tx_bytes moved");
WG_STATIC_ASSERT(offsetof(struct stats, rx_bytes) == 8 + sizeof(size_t), "stats::rx_bytes moved");
WG_STATIC_ASSERT(offsetof(struct stats, estimated_loss) == 8 + 2 * sizeof(size_t),
                 "stats::estimated_loss moved");
WG_STATIC_ASSERT(offsetof(struct stats, estimated_rtt) == 12 + 2 * sizeof(size_t),
                 "stats::estimated_rtt moved");
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->time_since_last_handshake) == 8,
                 "stats::time_since_last_handshake must be int64_t");
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->tx_bytes) == sizeof(size_t),
                 "stats::tx_bytes must be size_t");
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->rx_bytes) == sizeof(size_t),
                 "stats::rx_bytes must be size_t");
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->estimated_loss) == 4,
                 "stats::estimated_loss must be float");
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->estimated_rtt) == 4,
                 "stats::estimated_rtt must be int32_t");
// `reserved`'s WIDTH, which the total below cannot see. `stats` has tail
// padding on both word sizes, so shrinking `reserved` by up to seven bytes
// leaves `sizeof(struct stats)` exactly where it was: `uint8_t reserved[55]`
// compiles clean here under both -m32 and -m64. The Rust counterpart already
// asserts this width, so without it a header-only edit passes CI while the
// identical Rust edit fails -- the one-sided blindness this file exists to
// remove, pointing the other way. (Found by mutating the header and watching
// the check pass.)
WG_STATIC_ASSERT(sizeof(((struct stats *)0)->reserved) == 56,
                 "stats::reserved must be 56 bytes; tail padding hides a shrink from sizeof");
// The rule `reserved`'s comment states -- "decrement appropriately when adding
// new fields" -- made mechanical. The TOTAL is what must not move: 88 bytes on
// LP64, 80 on ILP32. Adding a field and shrinking `reserved` to match keeps
// this true, which is the whole point; adding one without shrinking `reserved`
// grows a struct both sides hardcode the size of, and fails here. (The safe
// path does still require editing the `reserved` width above, here and in the
// Rust test -- deliberately, so the new field cannot land on one side only.)
WG_STATIC_ASSERT(sizeof(struct stats) == 16 + 2 * sizeof(size_t) + 56,
                 "stats total size must not change; decrement reserved when adding a field");

// The declaration the client links against. Taking its address is enough to
// require that it exists with exactly this signature.
static struct wireguard_tunnel *(*const check_ctor)(
    const char *, const char *, const char *, uint16_t, uint32_t,
    const struct wireguard_awg_params *, const char *) = new_tunnel_with_awg_params;

// Referenced so no compiler warns it is unused; never called. Returns the
// address OF the pointer, not the pointer cast to void*: converting a function
// pointer to an object pointer is not conforming C (ISO C 6.3.2.3 covers only
// object pointers), and -Wpedantic diagnoses it -- an odd thing to leave in the
// one file whose job is to police conformance.
const void *wg_ffi_layout_check_anchor(void) { return (const void *)&check_ctor; }
