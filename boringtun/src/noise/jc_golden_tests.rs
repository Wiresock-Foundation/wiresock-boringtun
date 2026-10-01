//! Pre-handshake burst output pinned to fixtures recorded on the unmodified
//! code (before the single-source Jc size range and the capacity preflights):
//! with the same seeds, an adequate buffer must produce byte-identical
//! datagrams -- random, DNS, SIP, STUN and QUIC Jc junk and imitation -- and
//! leave the RNG at the same word position. Every datagram is compared
//! byte-for-byte except a STUN imitation datagram, which carries this
//! process's SOFTWARE value (drawn once per process from `OsRng`, by design)
//! and is compared through [`stun_canonical`]: exact everywhere except the
//! verified spots that depend on it.
#![cfg(feature = "mock-instant")]

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use super::*;
use blake2::{Blake2s256, Digest};
use rand_core::{OsRng, SeedableRng};
use std::time::Duration;

fn golden_configs() -> Vec<(&'static str, u64, AmneziaConfig)> {
    let base = || AmneziaConfig::new(0, 0, 0, 0);
    vec![
        (
            "random",
            0x5101,
            base().with_pre_handshake_junk(3, 40, 900, 0),
        ),
        (
            "dns",
            0x5102,
            base()
                .with_pre_handshake_junk(3, 40, 900, 0)
                .with_protocol_imitation(AmneziaImitationProtocol::Dns, Some("example.com".into())),
        ),
        (
            "sip",
            0x5103,
            base()
                .with_pre_handshake_junk(3, 40, 900, 0)
                .with_protocol_imitation(
                    AmneziaImitationProtocol::Sip,
                    Some("sip.example.com".into()),
                ),
        ),
        (
            "stun",
            0x5104,
            base()
                .with_pre_handshake_junk(3, 40, 900, 0)
                .with_protocol_imitation(AmneziaImitationProtocol::Stun, None),
        ),
        (
            "quic",
            0x5105,
            base()
                .with_pre_handshake_junk(3, 40, 900, 0)
                .with_protocol_imitation(
                    AmneziaImitationProtocol::Quic,
                    Some("example.com".into()),
                ),
        ),
    ]
}

/// Every burst datagram (imitation then Jc) before the initiation, each with
/// whether it came from the pre-generated imitation sequence, and the RNG word
/// position just before the initiation is formatted.
fn burst_outputs(cfg: AmneziaConfig, seed: u64) -> (Vec<(bool, Vec<u8>)>, u128) {
    let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let peer = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(OsRng));
    let pk = x25519_dalek::PublicKey::from(&sk);
    let _ = pk;
    let mut t = Tunn::new_with_amnezia(
        sk,
        peer,
        None,
        None,
        1 << 8,
        None,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        cfg,
    )
    .unwrap();
    t.handshake.rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    let mut big = vec![0u8; 65535];
    let mut out = Vec::new();
    let mut src = Some(vec![0x45u8; 0]);
    for _ in 0..200 {
        let pos = t.handshake.rng.get_word_pos();
        // A Jc datagram decrements the burst's Jc count; an imitation one
        // does not (before the first call there is no burst: the full count).
        let jc_before = t
            .pending_amnezia_junk
            .as_ref()
            .map_or(t.amnezia.pre_handshake_junk.packet_count, |p| p.remaining);
        let r = match src.take() {
            Some(s) => t.encapsulate(&s, &mut big),
            None => t.update_timers(&mut big),
        };
        match r {
            TunnResult::WriteToNetwork(p) => {
                let p = p.to_vec();
                if t.pending_amnezia_junk.is_none() {
                    return (out, pos);
                }
                let jc_after = t.pending_amnezia_junk.as_ref().unwrap().remaining;
                let from_imitation = jc_after == jc_before;
                out.push((from_imitation, p));
            }
            TunnResult::Done => {}
            other => panic!("[R3:GEN-BURST-OUTPUTS:UNEXPECTED] unexpected {:?}", other),
        }
        mock_instant::thread_local::MockClock::advance(Duration::from_secs(1));
    }
    panic!("[R3:GEN-BURST-OUTPUTS:NO-INITIATION] no initiation")
}

/// What a fixture pins of one datagram: its length and BLAKE2s-256 digest.
///
/// Every datagram is pinned byte-for-byte except a STUN imitation datagram,
/// which is pinned through [`stun_canonical`]: exact everywhere except the
/// three spots that depend on this process's SOFTWARE value (drawn once per
/// process from `OsRng` by `stun::host_software`, deliberately not from the
/// seeded RNG), each of which is verified rather than dropped.
fn fixture(name: &str, from_imitation: bool, p: &[u8]) -> (usize, String) {
    if !(name == "stun" && from_imitation) {
        return (p.len(), digest(p));
    }
    let canon = stun_canonical(p)
        .unwrap_or_else(|e| panic!("[R3:GEN-FIXTURE:STUN-STRUCTURE] STUN structure: {}", e));
    (canon.len(), digest(&canon))
}

const STUN_SOFTWARE: u16 = 0x8022;
const STUN_MESSAGE_INTEGRITY: u16 = 0x0008;
const STUN_FINGERPRINT: u16 = 0x8028;

fn stun_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A STUN Binding Request in canonical form, or why it is malformed.
///
/// Kept exactly: message type, magic cookie, transaction id, the attribute
/// type sequence, and every attribute other than the three below (type,
/// length, value and padding).
///
/// Process-variable, verified then replaced by a marker:
/// - header Message Length -- replaced by the length *without* the SOFTWARE
///   attribute (which is the only part whose size varies), checked against
///   the datagram size;
/// - SOFTWARE -- must be present, typed 0x8022, its length must equal the
///   value length, the value must be this process's `host_software()`, and
///   its padding must be zero; the value and its length become `<SOFTWARE>`;
/// - MESSAGE-INTEGRITY -- type 0x0008, length exactly 20; only the 20 HMAC
///   bytes (keyed by the seeded ICE password, but over the SOFTWARE bytes)
///   become `<MI>`;
/// - FINGERPRINT -- type 0x8028, length exactly 4, last attribute, and its
///   value must equal CRC-32(preceding bytes) XOR 0x5354554E; only the 4 CRC
///   bytes become `<FP-OK>`.
fn stun_canonical(p: &[u8]) -> Result<Vec<u8>, String> {
    use super::imitation::stun::{host_software, MAGIC_COOKIE};
    if p.len() < 20 {
        return Err("shorter than the header".into());
    }
    let declared = u16::from_be_bytes([p[2], p[3]]) as usize;
    if declared + 20 != p.len() {
        return Err(format!("length {} vs datagram {}", declared, p.len()));
    }
    let software = host_software().as_bytes();
    let sw_attr = 4 + ((software.len() + 3) & !3);
    let mut out = Vec::new();
    out.extend_from_slice(&p[0..2]);
    out.extend_from_slice(&((declared - sw_attr) as u16).to_be_bytes());
    out.extend_from_slice(&p[4..20]);
    let (mut off, mut seen_sw, mut seen_mi, mut seen_fp) = (20usize, false, false, false);
    while off < p.len() {
        if seen_fp {
            return Err("attribute after FINGERPRINT".into());
        }
        if off + 4 > p.len() {
            return Err("truncated attribute header".into());
        }
        let ty = u16::from_be_bytes([p[off], p[off + 1]]);
        let len = u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize;
        let end = off + 4 + ((len + 3) & !3);
        if end > p.len() {
            return Err(format!("attribute {:#06x} overruns", ty));
        }
        if p[off + 4 + len..end].iter().any(|&b| b != 0) {
            return Err(format!("attribute {:#06x} has nonzero padding", ty));
        }
        out.extend_from_slice(&p[off..off + 2]);
        match ty {
            STUN_SOFTWARE => {
                if seen_sw || off != 20 {
                    return Err("SOFTWARE not the first attribute".into());
                }
                if &p[off + 4..off + 4 + len] != software {
                    return Err("SOFTWARE is not this process's value".into());
                }
                seen_sw = true;
                out.extend_from_slice(b"<SOFTWARE>");
            }
            STUN_MESSAGE_INTEGRITY => {
                if len != 20 || seen_mi {
                    return Err("MESSAGE-INTEGRITY shape".into());
                }
                seen_mi = true;
                out.extend_from_slice(&p[off + 2..off + 4]);
                out.extend_from_slice(b"<MI>");
            }
            STUN_FINGERPRINT => {
                if len != 4 || !seen_mi {
                    return Err("FINGERPRINT shape or order".into());
                }
                let want = stun_crc32(&p[..off]) ^ 0x5354_554e;
                if p[off + 4..off + 8] != want.to_be_bytes() {
                    return Err("FINGERPRINT does not match the bytes before it".into());
                }
                seen_fp = true;
                out.extend_from_slice(&p[off + 2..off + 4]);
                out.extend_from_slice(b"<FP-OK>");
            }
            _ => out.extend_from_slice(&p[off + 2..end]),
        }
        off = end;
    }
    if p[4..8] != MAGIC_COOKIE {
        // Kept exactly in `out` as well; reported here for a clear failure.
        return Err("magic cookie".into());
    }
    if !(seen_sw && seen_mi && seen_fp) {
        return Err("SOFTWARE / MESSAGE-INTEGRITY / FINGERPRINT missing".into());
    }
    Ok(out)
}

fn digest(p: &[u8]) -> String {
    Blake2s256::digest(p)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// (config, [(pinned length, BLAKE2s-256, from the imitation sequence)],
/// RNG word position before the initiation) -- recorded on the unmodified code, identical in eight separate
/// processes.
#[allow(clippy::type_complexity)]
const BASELINE: &[(&str, &[(usize, &str, bool)], u128)] = &[
    (
        "random",
        &[
            (
                272,
                "ad2b5b10da5aee3060ee1848f8c83f870c8216c0e326669dde3984ac47eae013",
                false,
            ),
            (
                59,
                "3d6e1bf241d4d4ce686ec3512c5dcb14fba8dc921aee82dc749f269e67471352",
                false,
            ),
            (
                678,
                "066e84d4fc21cb7bb1930638201e4a3226717df7714818b795e10afc14fb7d5b",
                false,
            ),
        ],
        259,
    ),
    (
        "dns",
        &[
            (
                29,
                "f19d24a908a29d6b62b75de31e8c21088b5ac6e7041489ac3227c3e69f04f87c",
                true,
            ),
            (
                29,
                "f9ffe81957c514611d9f2bf18e3242fefff8dee889b524a03839b88c5add326e",
                true,
            ),
            (
                29,
                "ecddd56215ccae587e9de66d56d44a12fd44cf41c0e9deb955432bb96c774f48",
                true,
            ),
            (
                63,
                "967e53cdbc0d87233bc34f49e7abaf89a9d51ddb487da426f55fc84a3955415e",
                false,
            ),
            (
                200,
                "da5f9f5022dad70757c4f055ba8580320114023c16e6d5e66c6fff5134567460",
                false,
            ),
            (
                103,
                "a121c8aaa0da6049bfa83c353192bb1f9a7e962f7a95486909ab5fa7beb109a8",
                false,
            ),
        ],
        18,
    ),
    (
        "sip",
        &[
            (
                498,
                "907b46a2532a89863641ef92180159e66633d8dfeba39fb4f422974fe298e371",
                true,
            ),
            (
                319,
                "82d9dd3ace9d1b674c823857101c7dafe85d5e2c429490e084989fa99ccf7e4d",
                true,
            ),
            (
                882,
                "455fb601c34a6c06771d95865c879a538791932d8b345681d2649aafa0238251",
                false,
            ),
            (
                547,
                "bf95fa19ec015de3bef10ede074df4b40ea895b56e47cefd70fa60e3fc9081bf",
                false,
            ),
            (
                386,
                "c8f29262a00ae85464fa745cca67f8ac84456e0583f2045a025b322317160e19",
                false,
            ),
        ],
        486,
    ),
    (
        "stun",
        &[
            (
                91,
                "d32d1b2d52bdc19aaf43792899e594c47bd63baa2a52f90fd172fa9564bac65e",
                true,
            ),
            (
                95,
                "d5fe302a407c945131b6c826b210bc60f469345ff3b9b46462640585d3c75f7e",
                true,
            ),
            (
                49,
                "223f88c96bbcc4ebba237afd78e2748ba04faf718dfc7d39155de4887ad3907a",
                false,
            ),
            (
                39,
                "e162f6a222892d1423d5a51b7b65413442f4a4262a4541223b14d529674a19d9",
                false,
            ),
            (
                90,
                "30c0e5be2be755d86c0294c7e47250d135b45a9b240e17cc82ab0aef96f67794",
                false,
            ),
        ],
        240,
    ),
    (
        "quic",
        &[
            (
                1250,
                "6a9496cf212d14411e23eee8d8170aa6ed66c20627e423a7bc79127eb9799832",
                true,
            ),
            (
                1225,
                "c4f168d2bc524b907efe7fb52439e0b352935b4bba2b54b9eaef1492622f9158",
                false,
            ),
            (
                1216,
                "eb2dbed61e5467b42c03cb4fbe064ea53a7c23c827b31eef849c45c0c29b6a65",
                false,
            ),
            (
                1239,
                "de96ad0e5feb64f787475a57ffdfccfc58ae06ed8306be3261a878fb6146fcd8",
                false,
            ),
        ],
        1032,
    ),
];

/// Compare one configuration's burst with its baseline fixture, without
/// panicking on malformed STUN (that is reported as a mismatch).
fn compare(name: &str, got: &[(bool, Vec<u8>)], pos: u128) -> Result<(), String> {
    let (_, want, want_pos) = BASELINE
        .iter()
        .find(|(n, _, _)| *n == name)
        .ok_or("unknown config")?;
    if got.len() != want.len() {
        return Err(format!("{} datagrams, baseline {}", got.len(), want.len()));
    }
    for (i, ((imit, p), (wl, wd, wi))) in got.iter().zip(want.iter()).enumerate() {
        if imit != wi {
            return Err(format!("#{} kind differs", i));
        }
        let (l, d) = if name == "stun" && *imit {
            let c = stun_canonical(p).map_err(|e| format!("#{} {}", i, e))?;
            (c.len(), digest(&c))
        } else {
            (p.len(), digest(p))
        };
        if (l, d.as_str()) != (*wl, *wd) {
            return Err(format!("#{} differs ({} vs {})", i, l, wl));
        }
    }
    if pos != *want_pos {
        return Err("RNG position differs".into());
    }
    Ok(())
}

#[test]
fn adequate_buffer_burst_output_matches_the_baseline_fixtures() {
    let configs = golden_configs();
    assert_eq!(
        configs.len(),
        BASELINE.len(),
        "[R3:GOLD:CONFIGS-LEN-BASELINE-LEN]"
    );
    for (name, seed, cfg) in configs {
        let (got, pos) = burst_outputs(cfg, seed);
        // `fixture` is what the generator printed on the baseline.
        for (imit, p) in &got {
            let _ = fixture(name, *imit, p);
        }
        compare(name, &got, pos)
            .unwrap_or_else(|e| panic!("[R3:GOLD:MATCHES-BASELINE-FIXTURE] {}: {}", name, e));
    }
}

/// A burst as `burst_outputs` returns it: (from the imitation sequence, bytes).
type Burst = Vec<(bool, Vec<u8>)>;

/// Re-sign a STUN datagram's FINGERPRINT after a deliberate edit, so the edit
/// is judged by the deterministic-field comparison, not by the CRC check.
fn refingerprint(p: &mut [u8]) {
    let n = p.len();
    let mut crc = 0xffff_ffffu32;
    for &b in &p[..n - 8] {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    let v = (!crc) ^ 0x5354_554e;
    p[n - 4..].copy_from_slice(&v.to_be_bytes());
}

fn attr_span(p: &[u8], ty: u16) -> (usize, usize) {
    let mut off = 20;
    while off < p.len() {
        let t = u16::from_be_bytes([p[off], p[off + 1]]);
        let len = u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize;
        let end = off + 4 + ((len + 3) & !3);
        if t == ty {
            return (off, end);
        }
        off = end;
    }
    panic!(
        "[R3:G-ATTR-SPAN:ATTRIBUTE-ABSENT] attribute {:#06x} absent",
        ty
    )
}

#[test]
fn the_stun_golden_rejects_every_deterministic_mutation() {
    let (name, seed, cfg) = golden_configs()
        .into_iter()
        .find(|c| c.0 == "stun")
        .unwrap();
    let (got, pos) = burst_outputs(cfg, seed);
    compare(name, &got, pos)
        .expect("[R3:STUNNEG:UNMUTATED-OUTPUT-MATCHES] unmutated output matches");
    let mutate = |f: &dyn Fn(&mut Burst)| {
        let mut m = got.clone();
        f(&mut m);
        compare(name, &m, pos)
    };
    // Message type (Binding Request 0x0001 -> 0x0101), FINGERPRINT re-signed.
    assert!(
        mutate(&|m| {
            m[0].1[0] ^= 0x01;
            refingerprint(&mut m[0].1);
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-M-X01-REFINGERPRINT]"
    );
    // Magic cookie, re-signed.
    assert!(
        mutate(&|m| {
            m[0].1[5] ^= 0x01;
            refingerprint(&mut m[0].1);
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-M-X01-REFINGERPRINT-2]"
    );
    // Transaction id (seeded), re-signed.
    assert!(
        mutate(&|m| {
            m[1].1[19] ^= 0x01;
            refingerprint(&mut m[1].1);
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-M-X01-REFINGERPRINT-3]"
    );
    // Attribute order: PRIORITY (0x0024) and ICE-CONTROLLING (0x802a) swapped,
    // lengths and contents intact, re-signed.
    assert!(
        mutate(&|m| {
            let p = &mut m[0].1;
            let (a0, a1) = attr_span(p, 0x0024);
            let (b0, b1) = attr_span(p, 0x802a);
            assert_eq!(a1, b0, "[R3:STUNNEG:ADJACENT] adjacent");
            let mut swapped = p[b0..b1].to_vec();
            swapped.extend_from_slice(&p[a0..a1]);
            p[a0..b1].copy_from_slice(&swapped);
            refingerprint(p);
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-M-A0-A1]"
    );
    // A deterministic attribute value (PRIORITY), re-signed.
    assert!(
        mutate(&|m| {
            let (a0, _) = attr_span(&m[0].1, 0x0024);
            m[0].1[a0 + 4] ^= 0x01;
            refingerprint(&mut m[0].1);
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-A0-ATTR-SPAN-M]"
    );
    // An edit to a SOFTWARE byte is rejected by the SOFTWARE check (it no
    // longer equals this process's value) -- before the CRC stage; the CRC
    // stage itself is exercised by `the_stun_crc_stage_rejects_a_corrupted_fingerprint`.
    assert!(
        mutate(&|m| m[1].1[25] ^= 0x01).is_err(),
        "[R3:STUNNEG:SOFTWARE-BYTE-EDIT-REJECTED]"
    );
    // Jc length: one byte shorter.
    assert!(
        mutate(&|m| {
            m[2].1.pop();
        })
        .is_err(),
        "[R3:STUNNEG:MUTATE-M-M-POP-IS-ERR]"
    );
    // Jc order: two Jc datagrams swapped.
    assert!(
        mutate(&|m| m.swap(2, 3)).is_err(),
        "[R3:STUNNEG:MUTATE-M-M-SWAP-IS-ERR]"
    );
    // Jc content.
    assert!(
        mutate(&|m| m[4].1[0] ^= 0x01).is_err(),
        "[R3:STUNNEG:MUTATE-M-M-X01-IS-ERR-2]"
    );
    // What IS normalised: the MESSAGE-INTEGRITY bytes (keyed HMAC over the
    // process-variable SOFTWARE). Editing only them (re-signed) still matches.
    assert!(
        mutate(&|m| {
            let (o, _) = attr_span(&m[0].1, 0x0008);
            m[0].1[o + 4] ^= 0x01;
            refingerprint(&mut m[0].1);
        })
        .is_ok(),
        "[R3:STUNNEG:MUTATE-M-O-ATTR-SPAN-M]"
    );
}

/// CRC negative control: an otherwise-valid STUN imitation datagram whose
/// FINGERPRINT value alone is corrupted must be rejected by the FINGERPRINT
/// (CRC-32) verifier -- every preceding check (header, SOFTWARE, the other
/// attributes, MESSAGE-INTEGRITY shape) passes first.
#[test]
fn the_stun_crc_stage_rejects_a_corrupted_fingerprint() {
    let (_, seed, cfg) = golden_configs()
        .into_iter()
        .find(|c| c.0 == "stun")
        .unwrap();
    let (got, _) = burst_outputs(cfg, seed);
    let (imit, valid) = &got[0];
    assert!(*imit, "[R3:CRCNEG:FIRST-DATAGRAM-IS-IMITATION]");
    assert!(
        stun_canonical(valid).is_ok(),
        "[R3:CRCNEG:VALID-DATAGRAM-ACCEPTED]"
    );
    let mut bad = valid.clone();
    let n = bad.len();
    // The last attribute is FINGERPRINT (type 0x8028, length 4); its 4-byte
    // value is the last 4 bytes. Nothing before it is touched.
    assert_eq!(
        &bad[n - 8..n - 4],
        &[0x80, 0x28, 0x00, 0x04],
        "[R3:CRCNEG:FINGERPRINT-IS-LAST]"
    );
    bad[n - 1] ^= 0x01;
    assert_eq!(
        &bad[..n - 4],
        &valid[..n - 4],
        "[R3:CRCNEG:ONLY-CRC-BYTES-CHANGED]"
    );
    let err = stun_canonical(&bad).expect_err("[R3:CRCNEG:CORRUPTED-CRC-REJECTED]");
    assert!(
        err.contains("FINGERPRINT does not match"),
        "[R3:CRCNEG:REJECTED-BY-CRC-STAGE] rejected by another stage: {}",
        err
    );
}
