// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Check that wireguard_ffi.h is usable from C++ and that its declarations keep
// C linkage.
//
// The consumer this header is written for is a C++ product, so "a client
// translation unit that includes this header must compile" has to mean C++ as
// well. Without the `extern "C"` guard in the header, this file still compiles
// -- the failure is a link error at integration time, which no compile-only
// check can see. So the CI step that builds this file also greps the object's
// undefined symbols: the reference below must appear unmangled, as
// `new_tunnel_with_awg_params`, and not as a C++-mangled name that will never
// match the Rust `#[no_mangle] extern "C"` export.
//
// Kept separate from ffi-layout-check.c because that file is C by
// construction: `_Static_assert` and its `#error` guard on `__STDC_VERSION__`
// mean it cannot be compiled as C++ at all.
//
// Nothing here runs.

#include "../boringtun/src/wireguard_ffi.h"

// Referencing the newest entry point is what puts its symbol in the object's
// undefined list. The signature is written out rather than deduced so a
// parameter-type change on either side is a compile error here too.
static struct wireguard_tunnel *(*const check_ctor)(
    const char *, const char *, const char *, uint16_t, uint32_t,
    const struct wireguard_awg_params *, const char *) = new_tunnel_with_awg_params;

// One legacy constructor as well, so the check covers the pre-existing surface
// the client links against today and not only the new struct form.
static struct wireguard_tunnel *(*const check_legacy)(
    const char *, const char *, const char *, uint16_t, uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) = new_tunnel;

// The C++ side of the layout contract. The Rust and C guards both pin these;
// a C++ compiler is a third implementation of the same rules, and it is the
// one the consumer actually uses.
static_assert(sizeof(struct wireguard_awg_range) == 8, "range must be two uint32_t");
static_assert(sizeof(struct wireguard_awg_params) == 160, "params size is the ABI anchor");
static_assert(offsetof(struct wireguard_awg_params, header_protection_key) == 128,
              "header_protection_key moved");

// Returns the addresses OF the pointers, never the pointers themselves: a
// function pointer compared against null is a diagnosable tautology under
// -Wall, and converting one to an object pointer is not conforming.
extern "C" const void *wg_ffi_cpp_check_anchor(int which);
const void *wg_ffi_cpp_check_anchor(int which)
{
    return which == 0 ? (const void *)&check_ctor : (const void *)&check_legacy;
}
