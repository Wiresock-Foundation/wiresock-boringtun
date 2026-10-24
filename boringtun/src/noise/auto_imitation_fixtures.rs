// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Recorded and constructed imitation preludes whose bytes also fit an
//! AmneziaWG packet shape. Shared by the core and device Auto tests.

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};
use super::handshake::ObfuscationRanges;
use super::Tunn;
use crate::x25519;
use rand_core::OsRng;

/// The five pre-handshake datagrams of one real STUN client burst, recorded
/// from the published BoringTun CLI (amneziawg-install evidence
/// `sipinj-diagnosis/preludes/stun.datagrams`, lines 1-5). The first two are
/// the burst's Binding Requests: 104 and 108 bytes, sharing one USERNAME, so
/// both carry `hIew` at offset 36. The last three are S-shaped junk that is no
/// valid Binding Request.
pub(crate) fn recorded_stun_prelude() -> [Vec<u8>; 5] {
    const HEX: [&str; 5] = [
        "000100542112a442027e6bd2f7ff3deb813e6425802200074d6f7a696c6c61000006000e6849657771723a4a756662516169000000240004c5fa6273802a000845d99c2e60c4ded800080014efa63cf930cac0d7de37ca8ec7fa64460699fc69802800044f493e0e",
        "000100582112a442896179c6cbd6866777069204802200074d6f7a696c6c61000006000e6849657771723a4a756662516169000000240004c5fa6273802a000845d99c2e60c4ded80025000000080014befd28daeb5824d502054a71df0ede2c330b891180280004442c8f28",
        "000100482112a442f32aa87b94518ad0a257fd0e80220044474c4531384067476f445d657a2b45652a623e284e2b243f3d6e3854794c362d4363385d21245f60213b532f63205d526a5066374a45535f456049773f6b723f733d475904df94",
        "000100242112a442e404f4e8040d5d5a230ca0e580220020632f7a314f2c26203c452c78745274252c3d65613934484876315e245c263340a3",
        "000100482112a4429c13d34bd4bf1ef29b48b03a80220044453b6b5a7b377e3c41375d4f4424416f61475f276c773c2a3b245a5861574f2c452335364c413e417c2970653d645d346a425250204f5f5a564e5459305a60435f2d3f62f6a0e1",
    ];
    HEX.map(hex)
}

pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The recorded run's S1..S4.
pub(crate) const RECORDED_S: [u16; 4] = [110, 57, 133, 36];
/// The recorded run's H1..H3.
pub(crate) const RECORDED_H: [(u32, u32); 3] = [
    (66_166_068, 166_166_067),
    (862_271_148, 962_271_147),
    (1_349_667_297, 1_449_667_296),
];
/// The recorded run's H4, which holds the u32 `hIew` both Binding Requests
/// carry at S4 = 36.
pub(crate) const COLLIDING_H4: (u32, u32) = (1_917_290_954, 2_017_290_953);
/// An H4 that holds none of the recorded bytes at S4.
pub(crate) const CONTROL_H4: (u32, u32) = (2_030_000_000, 2_129_999_999);

/// The recorded H1..H3 with `h4`.
pub(crate) fn recorded_obf(h4: (u32, u32)) -> ObfuscationRanges {
    let [h1, h2, h3] = RECORDED_H;
    ObfuscationRanges::new(h1.0, h1.1, h2.0, h2.1, h3.0, h3.1, h4.0, h4.1)
        .expect("disjoint H ranges")
}

/// The recorded sizes, unprotected, imitating `protocol`.
pub(crate) fn recorded_layout(protocol: P) -> AmneziaConfig {
    let [s1, s2, s3, s4] = RECORDED_S;
    AmneziaConfig::new(s1, s2, s3, s4).with_protocol_imitation(protocol, None)
}

/// An H4 range of +-50 around the tag `datagram` carries at `s4`, read
/// through `amnezia`'s header-protection mask when it has one, and checked
/// disjoint from the recorded H1..H3.
pub(crate) fn colliding_h4_for(datagram: &[u8], s4: usize, amnezia: &AmneziaConfig) -> (u32, u32) {
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&datagram[s4..s4 + 4]);
    if amnezia.header_protection_enabled() {
        let mask = amnezia
            .header_protection
            .type_mask(datagram)
            .expect("a nonce-sized datagram");
        for (b, m) in tag.iter_mut().zip(mask) {
            *b ^= m;
        }
    }
    let tag = u32::from_le_bytes(tag);
    let h4 = (tag.saturating_sub(50), tag.saturating_add(50));
    let [h1, h2, h3] = RECORDED_H;
    assert!(
        ObfuscationRanges::new(h1.0, h1.1, h2.0, h2.1, h3.0, h3.1, h4.0, h4.1).is_ok(),
        "tag {} collides with H1..H3; choose another fixture",
        tag
    );
    h4
}

/// A client under `client` and a server under `server`, both under `obf`;
/// the server's limiter given `budget` (`None` for the default).
pub(crate) fn pair_under(
    client: &AmneziaConfig,
    server: &AmneziaConfig,
    obf: ObfuscationRanges,
    budget: Option<u64>,
) -> (Tunn, Tunn) {
    let (client, server, _) = keyed_pair_under(client, server, obf, budget);
    (client, server)
}

/// [`pair_under`], also returning the server's static public key -- what a
/// fixture needs for a mac1 that holds at the server.
pub(crate) fn keyed_pair_under(
    client: &AmneziaConfig,
    server: &AmneziaConfig,
    obf: ObfuscationRanges,
    budget: Option<u64>,
) -> (Tunn, Tunn, x25519::PublicKey) {
    let client_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let client_public = x25519::PublicKey::from(&client_secret);
    let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let server_public = x25519::PublicKey::from(&server_secret);
    let client = Tunn::new_with_obfuscation(
        client_secret,
        server_public,
        None,
        None,
        0x0000_1234,
        None,
        obf,
        client.clone(),
    )
    .unwrap();
    let server = Tunn::new_with_obfuscation(
        server_secret,
        client_public,
        None,
        None,
        0x0000_5678,
        budget
            .map(|b| std::sync::Arc::new(super::rate_limiter::RateLimiter::new(&server_public, b))),
        obf,
        server.clone(),
    )
    .unwrap();
    (client, server, server_public)
}
