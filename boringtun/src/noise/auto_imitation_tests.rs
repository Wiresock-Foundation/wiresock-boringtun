// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};
use super::auto_imitation_fixtures::keyed_pair_under;
use super::inbound::fixtures::{bare_ipv4, pair};
use super::*;
use rand_core::OsRng;

fn auto_config() -> AmneziaConfig {
    let protocol: P = "auto".parse().expect("server auto mode must be selectable");
    AmneziaConfig::new(128, 128, 128, 128).with_protocol_imitation(protocol, None)
}

fn network(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected network output, got {:?}", other),
    }
}

fn prelude(protocol: P) -> Vec<u8> {
    AmneziaConfig::default()
        .with_protocol_imitation(protocol, Some("example.com".into()))
        .pre_handshake_imitation_datagrams(&mut OsRng)
        .pop_front()
        .unwrap()
        .1
}

fn shaped(packet: &[u8], protocol: P) {
    match protocol {
        P::Dns => {
            assert_eq!(packet[2], 1);
            assert_eq!(&packet[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
        }
        P::Quic => assert_eq!(packet[0] & 0xc0, 0x40),
        P::Sip => assert!(
            packet.starts_with(b"OPTIONS ")
                || packet.starts_with(b"REGISTER ")
                || packet.starts_with(b"MESSAGE ")
        ),
        P::Stun => assert_eq!(&packet[4..8], &[0x21, 0x12, 0xa4, 0x42]),
        _ => panic!("expected a concrete protocol"),
    }
}

/// [`shaped`] as a predicate.
fn is_shaped(packet: &[u8], protocol: P) -> bool {
    match protocol {
        P::Dns => packet[2] == 1 && packet[4..12] == [0, 1, 0, 0, 0, 0, 0, 1],
        P::Quic => packet[0] & 0xc0 == 0x40,
        P::Sip => {
            packet.starts_with(b"OPTIONS ")
                || packet.starts_with(b"REGISTER ")
                || packet.starts_with(b"MESSAGE ")
        }
        P::Stun => is_stun(packet),
        _ => panic!("expected a concrete protocol"),
    }
}

#[test]
fn auto_imitation_selects_each_client_protocol_before_reply_and_data() {
    for protocol in [P::Dns, P::Quic, P::Sip, P::Stun] {
        let config = AmneziaConfig::new(128, 128, 128, 128)
            .with_protocol_imitation(protocol, None)
            .as_responder();
        let (mut client, mut server) = pair(&config, None);
        server
            .try_set_obfuscation(ObfuscationRanges::default(), auto_config())
            .unwrap();
        let mut buf = [0u8; 2048];
        let _ = server.decapsulate(None, &prelude(protocol), &mut buf);
        let init = network(client.format_handshake_initiation(&mut buf, false));
        let response = network(server.decapsulate(None, &init, &mut buf));
        shaped(&response, protocol);
        let keepalive = network(client.decapsulate(None, &response, &mut buf));
        assert!(matches!(
            server.decapsulate(None, &keepalive, &mut buf),
            TunnResult::Done
        ));
        // A different prelude cannot repin an established peer.
        let _ = server.decapsulate(
            None,
            &prelude(if protocol == P::Dns { P::Stun } else { P::Dns }),
            &mut buf,
        );
        for send_from_server in [true, false] {
            let (sender, receiver) = if send_from_server {
                (&mut server, &mut client)
            } else {
                (&mut client, &mut server)
            };
            let data = network(sender.encapsulate(&bare_ipv4(), &mut buf));
            shaped(&data, protocol);
            match receiver.decapsulate(None, &data, &mut buf) {
                TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, bare_ipv4()),
                other => panic!("data failed: {:?}", other),
            }
        }
    }
}

#[test]
fn auto_imitation_is_responder_only_even_with_junk_configured() {
    let config = auto_config().with_pre_handshake_junk(2, 100, 100, 0);
    let (mut server, _) = pair(&config, None);
    let mut buf = [0u8; 2048];
    let initiation = network(server.format_handshake_initiation(&mut buf, false));
    assert_eq!(initiation.len(), 128 + HANDSHAKE_INIT_SZ);
}

#[test]
fn auto_imitation_forgery_and_short_buffer_do_not_pin_or_consume_the_handshake() {
    let config = auto_config();
    let (mut client, mut server) = pair(&config, None);
    let mut buf = [0u8; 2048];
    let _ = server.decapsulate(None, &prelude(P::Stun), &mut buf);
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let mut forged = init.clone();
    forged[128 + 20] ^= 1;
    assert!(matches!(
        server.decapsulate(None, &forged, &mut buf),
        TunnResult::Err(_)
    ));
    assert_eq!(server.imitation_protocol(), P::None);
    assert!(matches!(
        server.decapsulate(None, &init, &mut [0u8; 219]),
        TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
    ));
    assert_eq!(server.imitation_protocol(), P::None);
    shaped(&network(server.decapsulate(None, &init, &mut buf)), P::Stun);
    assert_eq!(server.imitation_protocol(), P::Stun);
    // A replay with another prelude cannot replace the established choice.
    let _ = server.decapsulate(None, &prelude(P::Dns), &mut buf);
    assert!(matches!(
        server.decapsulate(None, &init, &mut buf),
        TunnResult::Err(_)
    ));
    assert_eq!(server.imitation_protocol(), P::Stun);
}

#[test]
fn auto_imitation_hints_are_source_bound_and_fixed_modes_ignore_them() {
    let (mut client, mut server) = pair(&auto_config(), None);
    let mut buf = [0u8; 2048];
    let _ = server.decapsulate(
        Some("192.0.2.1".parse().unwrap()),
        &prelude(P::Stun),
        &mut buf,
    );
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let _ = network(server.decapsulate(Some("192.0.2.2".parse().unwrap()), &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::None);

    let fixed = auto_config()
        .with_protocol_imitation(P::Dns, None)
        .as_responder();
    let (mut client, mut server) = pair(&fixed, None);
    let _ = server.decapsulate(None, &prelude(P::Stun), &mut buf);
    let init = network(client.format_handshake_initiation(&mut buf, false));
    shaped(&network(server.decapsulate(None, &init, &mut buf)), P::Dns);
}

#[test]
fn auto_imitation_survives_reconfiguration_and_rejects_unsafe_sip() {
    let config = auto_config();
    let (mut client, mut server) = pair(&config, None);
    let mut buf = [0u8; 2048];
    let _ = server.decapsulate(None, &prelude(P::Quic), &mut buf);
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let _ = network(server.decapsulate(None, &init, &mut buf));
    let mut changed = config.clone();
    changed.transport_packet_junk_size = 129;
    server
        .try_set_obfuscation(ObfuscationRanges::default(), changed)
        .unwrap();
    assert_eq!(server.imitation_protocol(), P::Quic);
    server
        .try_set_obfuscation(
            ObfuscationRanges::default(),
            config.clone().with_protocol_imitation(P::Dns, None),
        )
        .unwrap();
    server
        .try_set_obfuscation(ObfuscationRanges::default(), config.clone())
        .unwrap();
    assert_eq!(server.imitation_protocol(), P::None);

    let protected = config.with_header_protection([7; 32]);
    let (mut client, mut server) = pair(&protected, None);
    let _ = server.decapsulate(None, &prelude(P::Sip), &mut buf);
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(None, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::None);
    let keepalive = network(client.decapsulate(None, &response, &mut buf));
    assert!(matches!(
        server.decapsulate(None, &keepalive, &mut buf),
        TunnResult::Done
    ));
}

#[test]
#[cfg(feature = "mock-instant")]
fn auto_imitation_first_hint_wins_but_expires_without_refresh() {
    use mock_instant::thread_local::MockClock;
    for expire in [false, true] {
        let (mut client, mut server) = pair(&auto_config(), None);
        let mut buf = [0u8; 2048];
        let _ = server.decapsulate(None, &prelude(P::Stun), &mut buf);
        MockClock::advance(Duration::from_secs(29));
        let _ = server.decapsulate(None, &prelude(P::Dns), &mut buf);
        if expire {
            MockClock::advance(Duration::from_secs(1));
        }
        let init = network(client.format_handshake_initiation(&mut buf, false));
        let _ = network(server.decapsulate(None, &init, &mut buf));
        assert_eq!(
            server.imitation_protocol(),
            if expire { P::None } else { P::Stun }
        );
    }
}

#[test]
fn auto_imitation_cookie_uses_hint_without_pinning() {
    let (mut client, mut server) = pair(&auto_config(), Some(0));
    let source = Some("192.0.2.1".parse().unwrap());
    let mut buf = [0u8; 2048];
    let _ = server.decapsulate(source, &prelude(P::Stun), &mut buf);
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let cookie = network(server.decapsulate(source, &init, &mut buf));
    shaped(&cookie, P::Stun);
    assert!(cookie.len() <= init.len());
    assert_eq!(server.imitation_protocol(), P::None);
}

/// Run `f` with WARN events captured; returns the number of header-protection
/// nonce warnings it logged, each also checked to name `protocol`.
fn nonce_warnings(protocol: P, f: impl FnOnce()) -> usize {
    let log = warnings(f);
    let warnings: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("protocol imitation weakens AmneziaWG header protection"))
        .collect();
    for line in &warnings {
        assert!(
            line.contains(&format!("protocol=\"{}\"", protocol.as_str()))
                || line.contains(&format!("protocol={}", protocol.as_str())),
            "warning names the learned protocol {:?}: {}",
            protocol,
            line
        );
    }
    warnings.len()
}

/// Run `f` with WARN events captured; returns the number of Auto refusals
/// of SIP by header-protection policy it logged. Separate from
/// [`nonce_warnings`], whose filter would count none of them.
fn policy_refusals(f: impl FnOnce()) -> usize {
    warnings(f)
        .lines()
        .filter(|line| {
            line.contains("auto imitation refused by header-protection policy")
                && (line.contains("protocol=\"sip\"") || line.contains("protocol=sip"))
        })
        .count()
}

/// Run `f` with WARN events captured, and return them.
fn warnings(f: impl FnOnce()) -> String {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || Capture(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let log = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    log
}

/// Deliberately ungated: ordinary Rust library builds (no `device`, no
/// `ffi-bindings`) embed `Tunn` directly, and an auto responder learning DNS
/// or STUN under header protection must warn there too.
#[test]
fn auto_imitation_reports_learned_nonce_warning_in_every_build() {
    for protocol in [P::Dns, P::Stun] {
        // Header protection on before learning: one warning when the mode is
        // learned, none for repeated identical updates afterwards.
        let protected = auto_config().with_header_protection([9; 32]);
        let (mut client, mut server) = pair(&protected, None);
        let mut buf = [0u8; 2048];
        let warnings = nonce_warnings(protocol, || {
            let _ = server.decapsulate(None, &prelude(protocol), &mut buf);
            let init = network(client.format_handshake_initiation(&mut buf, false));
            let _ = network(server.decapsulate(None, &init, &mut buf));
            for _ in 0..2 {
                server
                    .try_set_obfuscation(Default::default(), protected.clone())
                    .unwrap();
            }
        });
        assert_eq!(server.imitation_protocol(), protocol);
        assert_eq!(
            warnings, 1,
            "masking enabled before learning {:?}",
            protocol
        );

        // Header protection enabled by a live update after learning: one
        // warning for the update, none for repeating it.
        let config = auto_config();
        let (mut client, mut server) = pair(&config, None);
        let _ = server.decapsulate(None, &prelude(protocol), &mut buf);
        let init = network(client.format_handshake_initiation(&mut buf, false));
        let _ = network(server.decapsulate(None, &init, &mut buf));
        assert_eq!(server.imitation_protocol(), protocol);
        let protected = config.with_header_protection([9; 32]);
        let warnings = nonce_warnings(protocol, || {
            for _ in 0..3 {
                server
                    .try_set_obfuscation(Default::default(), protected.clone())
                    .unwrap();
            }
        });
        assert_eq!(server.imitation_protocol(), protocol);
        assert_eq!(warnings, 1, "masking enabled after learning {:?}", protocol);

        // Fixed modes keep their door-only reporting: `Tunn` stays silent and
        // the accepting door (UAPI `set=1`, the C constructor) warns once.
        let fixed = AmneziaConfig::new(128, 128, 128, 128)
            .with_protocol_imitation(protocol, None)
            .as_responder();
        let (_, mut server) = pair(&fixed, None);
        let warnings = nonce_warnings(protocol, || {
            for _ in 0..2 {
                server
                    .try_set_obfuscation(
                        Default::default(),
                        fixed.clone().with_header_protection([9; 32]),
                    )
                    .unwrap();
            }
        });
        assert_eq!(warnings, 0, "fixed {:?} warns only at its door", protocol);
    }
}

fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= 8 && packet[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

/// Finish the handshake `response` answers -- the client's keepalive into the
/// server -- then send [`bare_ipv4`] both ways, checking the server's output
/// against `shape`. A learning test passes only if the tunnel it learned for
/// carries plaintext in both directions.
fn confirm_and_exchange(
    client: &mut Tunn,
    server: &mut Tunn,
    src: Option<IpAddr>,
    response: &[u8],
    shape: impl Fn(&[u8]) -> bool,
) {
    let mut buf = [0u8; 2048];
    assert!(shape(response), "response shape");
    let keepalive = network(client.decapsulate(src, response, &mut buf));
    assert!(matches!(
        server.decapsulate(src, &keepalive, &mut buf),
        TunnResult::Done
    ));
    let data = network(client.encapsulate(&bare_ipv4(), &mut buf));
    match server.decapsulate(src, &data, &mut buf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, bare_ipv4()),
        other => panic!("client to server: {:?}", other),
    }
    let data = network(server.encapsulate(&bare_ipv4(), &mut buf));
    assert!(shape(&data), "server transport shape");
    match client.decapsulate(src, &data, &mut buf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, bare_ipv4()),
        other => panic!("server to client: {:?}", other),
    }
}

/// The recorded STUN burst, under the recorded layout: both Binding Requests
/// carry `hIew` at S4 = 36, and under the colliding H4 that makes each a
/// transport reading. The reading fails -- there is no session for it -- and
/// that refusal is no reason to ignore what the datagram plainly is.
#[test]
fn auto_imitation_learns_from_a_prelude_that_fits_a_transport_reading() {
    use super::auto_imitation_fixtures::*;
    use super::imitation::detect::{detect, Probe};
    let prelude = recorded_stun_prelude();
    let src: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
    let server_config = recorded_layout(P::Auto);
    let client_config = recorded_layout(P::Stun).as_responder();

    for (h4, colliding) in [(COLLIDING_H4, true), (CONTROL_H4, false)] {
        let obf = recorded_obf(h4);
        for (i, datagram) in prelude.iter().enumerate() {
            let request = i < 2;
            assert_eq!(
                detect(datagram),
                request.then_some(Probe::Stun),
                "datagram #{}",
                i + 1
            );
            assert_eq!(
                server_config.inbound_candidates(obf, datagram).offsets(),
                if request && colliding {
                    vec![36]
                } else {
                    vec![]
                },
                "datagram #{} under the {} H4",
                i + 1,
                if colliding { "colliding" } else { "control" }
            );
        }

        let (mut client, mut server) = pair_under(&client_config, &server_config, obf, None);
        assert_eq!(server.imitation_protocol(), P::None);
        assert!(!server.has_imitation_hint());
        let mut buf = [0u8; 2048];
        for (i, datagram) in prelude.iter().enumerate() {
            let outcome = server.decapsulate(src, datagram, &mut buf);
            match (i < 2, colliding) {
                (true, true) => assert!(
                    matches!(outcome, TunnResult::Err(WireGuardError::NoCurrentSession)),
                    "#{}: {:?}",
                    i + 1,
                    outcome
                ),
                (true, false) => assert!(matches!(outcome, TunnResult::Done)),
                (false, _) => assert!(
                    matches!(outcome, TunnResult::Err(WireGuardError::InvalidPacket)),
                    "#{}: {:?}",
                    i + 1,
                    outcome
                ),
            }
        }
        assert_eq!(
            server.auto_imitation.hint(src),
            Some(P::Stun),
            "pending evidence before the initiation ({} H4)",
            if colliding { "colliding" } else { "control" }
        );

        let init = network(client.format_handshake_initiation(&mut buf, false));
        assert_eq!(detect(&init), None, "the initiation cannot detect itself");
        // The initiation reading comes first, so it is the one accepted. Its
        // S1 filler is random, and can also fit a transport reading after it.
        assert_eq!(
            server_config
                .inbound_candidates(obf, &init)
                .offsets()
                .first(),
            Some(&110)
        );
        let response = network(server.decapsulate(src, &init, &mut buf));
        assert_eq!(server.imitation_protocol(), P::Stun);
        assert!(!server.has_imitation_hint(), "learning consumes the hint");
        confirm_and_exchange(&mut client, &mut server, src, &response, is_stun);
    }

    // No prelude: nothing to learn from, random padding.
    let obf = recorded_obf(COLLIDING_H4);
    let (mut client, mut server) = pair_under(&client_config, &server_config, obf, None);
    let mut buf = [0u8; 2048];
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(src, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::None);
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| !is_stun(p));
}

fn advance_clock() {
    // A mocked clock stands still, and a responder refuses an initiation
    // whose timestamp does not advance as a replay.
    #[cfg(feature = "mock-instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_millis(1));
}

/// The state every negative case starts from: nothing learned, nothing held.
fn assert_unresolved(server: &Tunn) {
    assert_eq!(server.auto_imitation.learned, None);
    assert_eq!(server.imitation_protocol(), P::None);
    assert!(!server.has_imitation_hint(), "no pending evidence");
}

fn kind(packet: &Packet) -> &'static str {
    match packet {
        Packet::HandshakeInit(_) => "init",
        Packet::HandshakeResponse(_) => "response",
        Packet::PacketCookieReply(_) => "cookie",
        Packet::PacketData(_) => "data",
    }
}

/// Drive `server`'s own receive over `wire` with a trial that records what
/// each reading's authentication said, and return the refusal and the record.
/// Readings refused at the mac1 gate never reach a trial, so are not in it.
fn recorded_refusal(
    server: &Tunn,
    src: Option<IpAddr>,
    wire: &[u8],
    dst: &mut [u8],
) -> (inbound::Refusal, Vec<(&'static str, String)>) {
    let obf = server.handshake.obf;
    let candidates = server.amnezia.inbound_candidates(obf, wire);
    let mut tried = Vec::new();
    let outcome = inbound::receive(
        &server.amnezia,
        obf,
        &server.rate_limiter,
        src.map(Into::into),
        &candidates,
        wire,
        |p| {
            let k = kind(&p);
            match server.authenticate(p, dst) {
                Ok(_) => panic!("the {} reading authenticated", k),
                Err(e) => {
                    tried.push((k, format!("{:?}", e)));
                    Err::<(), _>(e)
                }
            }
        },
    );
    match outcome {
        inbound::Inbound::Refused(refusal) => (refusal, tried),
        _ => panic!("expected a refusal"),
    }
}

fn readings(record: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    record.iter().map(|(k, e)| (*k, e.to_string())).collect()
}

/// A responder with a working session and nothing learned: the client's
/// random-padded initiation is no camouflage, and no prelude came before it.
fn established(amnezia: &AmneziaConfig) -> (Tunn, Tunn, u32, x25519::PublicKey) {
    let (mut client, mut server, server_public) =
        keyed_pair_under(amnezia, amnezia, ObfuscationRanges::default(), None);
    let their_idx = super::inbound::fixtures::handshake(&mut client, &mut server);
    assert_unresolved(&server);
    (client, server, their_idx, server_public)
}

/// Each reading's refusal counts, not just the first: one that is not
/// allowed vetoes the hint however many allowed ones came before it, and the
/// reported error is still the first.
#[test]
fn auto_imitation_eligibility_accumulates_across_candidates() {
    use super::inbound::fixtures::*;
    let amnezia = colliding(None).with_protocol_imitation(P::Auto, None);
    // A transport index in the established session's slot that is not its
    // index: a routing refusal, decided before any cryptography.
    let stale = |their_idx: u32| their_idx.wrapping_add(N_SESSIONS as u32);
    let mut buf = vec![0u8; 2048];

    // Every reading refused with an allowed error: evidence.
    let (_, mut server, their_idx, _) = established(&amnezia);
    let wire = four_candidate_stun(
        &amnezia,
        [0x0bad_0001, 0x0bad_0002, 0x0bad_0003, stale(their_idx)],
    );
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut buf);
    assert_eq!(
        tried,
        readings(&[("cookie", "WrongIndex"), ("data", "WrongIndex")]),
        "init and response fail mac1 before any trial"
    );
    assert!(matches!(refusal.error, WireGuardError::InvalidMac));
    assert!(refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut buf),
        TunnResult::Err(WireGuardError::InvalidMac)
    ));
    assert_eq!(server.auto_imitation.hint(SRC), Some(P::Stun));

    // A response reading whose mac1 holds, into a buffer one byte short of
    // its keepalive: a local failure that verified nothing.
    let (_, mut server, their_idx, server_public) = established(&amnezia);
    let mut wire = four_candidate_stun(&amnezia, [0, 0x0bad_0002, 0, stale(their_idx)]);
    plant(&mut wire, &amnezia, COOKIE_AT, 0xffff_ffff, 0);
    let mac1_at = RESPONSE_AT + HANDSHAKE_RESP_SZ - 32;
    let mac1 = handshake::b2s_keyed_mac_16(
        &handshake::b2s_hash(handshake::LABEL_MAC1, server_public.as_bytes()),
        &wire[RESPONSE_AT..mac1_at],
    );
    wire[mac1_at..mac1_at + 16].copy_from_slice(&mac1);
    assert_detected_readings(&amnezia, &wire, &[INIT_AT, RESPONSE_AT, DATA_AT]);
    assert!(matches!(
        RateLimiter::new(&server_public, 100).gate_handshake(
            SRC.map(Into::into),
            &wire[RESPONSE_AT..],
            0x0bad_0002,
            rate_limiter::CookieDefense::Armed,
            &mut rate_limiter::LoadDecision::default(),
        ),
        rate_limiter::HandshakeGate::Pass
    ));
    let short = DATA_OVERHEAD_SZ + DATA_AT - 1;
    assert_eq!(short, 179);
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut vec![0u8; short]);
    assert_eq!(
        tried,
        readings(&[
            ("response", "DestinationBufferTooSmall"),
            ("data", "WrongIndex")
        ])
    );
    assert!(matches!(refusal.error, WireGuardError::InvalidMac));
    assert!(!refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut vec![0u8; short]),
        TunnResult::Err(WireGuardError::InvalidMac)
    ));
    assert!(!server.has_imitation_hint());

    // A genuine transport into a buffer one byte short of its ciphertext.
    let (mut client, mut server, their_idx, _) = established(&amnezia);
    let colliding_transport = |client: &mut Tunn| {
        let mut wire = network(client.encapsulate(&bare_ipv4(), &mut [0u8; WIRE]));
        assert_eq!(wire.len(), WIRE);
        stun_header(&mut wire);
        plant(&mut wire, &amnezia, INIT_AT, 1, 0x0bad_0001);
        plant(&mut wire, &amnezia, RESPONSE_AT, 2, 0x0bad_0002);
        plant(&mut wire, &amnezia, COOKIE_AT, 3, 0x0bad_0003);
        assert_detected_readings(&amnezia, &wire, &[INIT_AT, RESPONSE_AT, COOKIE_AT, DATA_AT]);
        wire
    };
    let wire = colliding_transport(&mut client);
    let ciphertext = WIRE - DATA_AT - 16;
    assert_eq!(ciphertext, 36);
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut [0u8; 35]);
    assert_eq!(
        tried,
        readings(&[
            ("cookie", "WrongIndex"),
            ("data", "DestinationBufferTooSmall")
        ])
    );
    assert!(matches!(refusal.error, WireGuardError::InvalidMac));
    assert!(!refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut [0u8; 35]),
        TunnResult::Err(WireGuardError::InvalidMac)
    ));
    assert!(!server.has_imitation_hint());
    // The same datagram with room is the transport it is.
    match server.decapsulate(SRC, &wire, &mut buf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, bare_ipv4()),
        other => panic!("genuine transport: {:?}", other),
    }
    assert!(!server.has_imitation_hint());

    // Replay-window refusals: a counter already marked...
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut buf);
    assert_eq!(
        tried,
        readings(&[("cookie", "WrongIndex"), ("data", "DuplicateCounter")])
    );
    assert!(!refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut buf),
        TunnResult::Err(WireGuardError::InvalidMac)
    ));
    assert!(!server.has_imitation_hint());

    // ...and one too old for the 8192-counter window, on the real receiving
    // index.
    for _ in 0..8300 {
        let data = network(client.encapsulate(&bare_ipv4(), &mut buf));
        assert!(matches!(
            server.decapsulate(SRC, &data, &mut [0u8; 2048]),
            TunnResult::WriteToTunnelV4(..)
        ));
    }
    let mut wire = colliding_transport(&mut client);
    assert_eq!(
        u32::from_le_bytes(wire[DATA_AT + 4..DATA_AT + 8].try_into().unwrap()),
        their_idx
    );
    wire[DATA_AT + 8..DATA_AT + 16].copy_from_slice(&0u64.to_le_bytes());
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut buf);
    assert_eq!(
        tried,
        readings(&[("cookie", "WrongIndex"), ("data", "InvalidCounter")])
    );
    assert!(!refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut buf),
        TunnResult::Err(WireGuardError::InvalidMac)
    ));
    assert!(!server.has_imitation_hint());
    assert_eq!(server.imitation_protocol(), P::None);
}

/// An Auto responder holding a working session with a fixed-DNS client and
/// nothing learned, plus the client's genuine DNS-shaped initiation. The
/// server accepted a copy of that initiation with its S1 prefix zeroed --
/// the same handshake, carrying no camouflage -- so a test can replay the
/// genuine one without the setup having already learned DNS from it.
fn unresolved_peer() -> (Tunn, Tunn, Vec<u8>) {
    use super::imitation::detect::{detect, Probe};
    let client_config = AmneziaConfig::new(128, 128, 128, 128)
        .with_protocol_imitation(P::Dns, None)
        .as_responder();
    let (mut client, mut server) = pair(&client_config, None);
    server
        .try_set_obfuscation(ObfuscationRanges::default(), auto_config())
        .unwrap();
    let src = super::inbound::fixtures::SRC;
    let mut buf = [0u8; 2048];
    let init = network(client.format_handshake_initiation(&mut buf, false));
    assert_eq!(detect(&init), Some(Probe::Dns));
    let mut bare = init.clone();
    bare[..128].fill(0);
    assert_eq!(detect(&bare), None);
    assert_eq!(
        bare[128..],
        init[128..],
        "the canonical handshake is unchanged"
    );
    let response = network(server.decapsulate(src, &bare, &mut buf));
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| {
        detect(p).is_none()
    });
    assert_unresolved(&server);
    (client, server, init)
}

/// A replayed initiation is refused for its timestamp, after decryption,
/// and that refusal is no evidence -- whatever shape its prefix has.
#[test]
fn auto_imitation_stale_initiation_is_not_evidence() {
    use super::imitation::detect::{detect, Probe};
    let src = super::inbound::fixtures::SRC;
    let (mut client, mut server, init) = unresolved_peer();
    let mut buf = [0u8; 2048];

    assert_eq!(detect(&init), Some(Probe::Dns));
    assert!(matches!(
        server.decapsulate(src, &init, &mut buf),
        TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
    ));
    assert_unresolved(&server);

    // With header protection off, anyone can rewrite a prefix.
    let mut sip = init.clone();
    let line = b"OPTIONS sip:a@b SIP/2.0\r\n";
    sip[..128].fill(b' ');
    sip[..line.len()].copy_from_slice(line);
    assert_eq!(detect(&sip), Some(Probe::Sip));
    assert_eq!(sip[128..], init[128..]);
    assert!(matches!(
        server.decapsulate(src, &sip, &mut buf),
        TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
    ));
    assert_unresolved(&server);

    // Fresh evidence and a fresh initiation still learn.
    assert!(matches!(
        server.decapsulate(src, &prelude(P::Dns), &mut buf),
        TunnResult::Done
    ));
    assert_eq!(server.auto_imitation.hint(src), Some(P::Dns));
    advance_clock();
    let fresh = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(src, &fresh, &mut buf));
    assert_eq!(server.imitation_protocol(), P::Dns);
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| {
        is_shaped(p, P::Dns)
    });
}

/// A reading that authenticated is accepted, whatever then fails; it never
/// becomes evidence, and what acceptance consumed stays consumed.
#[test]
fn auto_imitation_accepted_packets_never_enter_fallback() {
    use super::imitation::detect::{detect, Probe};
    let src = super::inbound::fixtures::SRC;
    let (mut client, mut server, _) = unresolved_peer();
    let mut buf = [0u8; 2048];

    // A transport whose plaintext is no IP packet: a total length of 10.
    let mut malformed = bare_ipv4();
    malformed[2..4].copy_from_slice(&10u16.to_be_bytes());
    let wire = network(client.encapsulate(&malformed, &mut buf));
    assert_eq!(detect(&wire), Some(Probe::Dns), "a DNS-shaped transport");
    assert!(matches!(
        server.decapsulate(src, &wire, &mut buf),
        TunnResult::Err(WireGuardError::InvalidPacket)
    ));
    assert_unresolved(&server);
    assert!(matches!(
        server.decapsulate(src, &wire, &mut buf),
        TunnResult::Err(WireGuardError::DuplicateCounter)
    ));
    assert_unresolved(&server);

    // An authenticated initiation whose Auto response cannot fit.
    advance_clock();
    let init = network(client.format_handshake_initiation(&mut buf, false));
    assert_eq!(detect(&init), Some(Probe::Dns));
    let short = HANDSHAKE_RESP_SZ + 128 - 1;
    assert_eq!(short, 219);
    assert!(matches!(
        server.decapsulate(src, &init, &mut vec![0u8; short]),
        TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
    ));
    assert_unresolved(&server);
    let response = network(server.decapsulate(src, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::Dns);
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| {
        is_shaped(p, P::Dns)
    });
}

/// A cookie reply or a load refusal is the datagram's disposition, and
/// neither records evidence; a refusal under normal load does.
#[test]
fn auto_imitation_cookie_and_load_dispositions_record_nothing() {
    use super::inbound::fixtures::*;
    let amnezia = colliding(None).with_protocol_imitation(P::Auto, None);
    let obf = ObfuscationRanges::default();
    let mut buf = [0u8; 2048];

    // Starved, with an address to answer: a cookie, shaped by what the
    // datagram is, and nothing kept.
    let (_, mut server, public) = keyed_pair_under(&amnezia, &amnezia, obf, Some(0));
    let wire = stun_gated_initiation(&public);
    assert_initiation_gate_passes(&RateLimiter::new(&public, 100), &wire);
    let cookie = network(server.decapsulate(SRC, &wire, &mut buf));
    assert!(is_stun(&cookie), "the cookie reply imitates the request");
    assert_unresolved(&server);

    // Starved, with no address: `UnderLoad`, and nothing kept.
    let (_, mut server, public) = keyed_pair_under(&amnezia, &amnezia, obf, Some(0));
    let wire = stun_gated_initiation(&public);
    assert!(matches!(
        server.decapsulate(None, &wire, &mut buf),
        TunnResult::Err(WireGuardError::UnderLoad)
    ));
    assert_unresolved(&server);

    // Normal load: Noise refuses the initiation reading, and the rest fail
    // for routing or missing state -- evidence.
    let (_, mut server, public) = keyed_pair_under(&amnezia, &amnezia, obf, None);
    let wire = stun_gated_initiation(&public);
    let (refusal, tried) = recorded_refusal(&server, SRC, &wire, &mut buf);
    assert_eq!(tried.len(), 3, "{:?}", tried);
    assert_eq!(tried[0].0, "init");
    assert!(
        tried[0].1 == "InvalidAeadTag" || tried[0].1 == "WrongKey",
        "{:?}",
        tried
    );
    assert_eq!(
        tried[1..],
        readings(&[("cookie", "UnexpectedPacket"), ("data", "NoCurrentSession")])[..]
    );
    assert!(refusal.allows_imitation_hint);
    assert!(matches!(
        server.decapsulate(SRC, &wire, &mut buf),
        TunnResult::Err(WireGuardError::InvalidAeadTag | WireGuardError::WrongKey)
    ));
    assert_eq!(server.auto_imitation.hint(SRC), Some(P::Stun));
}

/// Evidence from a refused prelude lands in the same one-slot store as any
/// other, under the same rules.
#[test]
fn auto_imitation_core_slot_source_semantics() {
    use super::auto_imitation_fixtures::*;
    let stun = recorded_stun_prelude();
    let config = recorded_layout(P::Auto);
    let obf = recorded_obf(COLLIDING_H4);
    let dns = prelude(P::Dns);
    assert_eq!(config.inbound_candidates(obf, &stun[0]).offsets(), vec![36]);
    assert_eq!(config.inbound_candidates(obf, &stun[1]).offsets(), vec![36]);
    assert_eq!(config.inbound_candidates(obf, &dns).offsets(), vec![]);
    let one: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
    let two: Option<IpAddr> = Some("192.0.2.2".parse().unwrap());
    let client_config = recorded_layout(P::None).as_responder();
    let (mut client, mut server) = pair_under(&client_config, &config, obf, None);
    let mut buf = [0u8; 2048];
    // A routing refusal of the transport reading: `NoCurrentSession` while
    // the server has no session, and `WrongIndex` once the recorded bytes
    // name an occupied slot. Both are allowed refusals.
    let refused = |server: &mut Tunn, src, datagram: &[u8]| {
        let mut buf = [0u8; 2048];
        let outcome = server.decapsulate(src, datagram, &mut buf);
        assert!(
            matches!(
                outcome,
                TunnResult::Err(WireGuardError::NoCurrentSession | WireGuardError::WrongIndex)
            ),
            "{:?}",
            outcome
        );
    };

    // The same source keeps its first live hint.
    refused(&mut server, one, &stun[0]);
    assert!(matches!(
        server.decapsulate(one, &dns, &mut buf),
        TunnResult::Done
    ));
    assert_eq!(server.auto_imitation.hint(one), Some(P::Stun));
    // A different source replaces it, live or not.
    assert!(matches!(
        server.decapsulate(two, &dns, &mut buf),
        TunnResult::Done
    ));
    assert_eq!(server.auto_imitation.hint(one), None);
    assert_eq!(server.auto_imitation.hint(two), Some(P::Dns));
    // `None` is a source of its own...
    refused(&mut server, None, &stun[1]);
    assert_eq!(server.auto_imitation.hint(two), None);
    assert_eq!(server.auto_imitation.hint(None), Some(P::Stun));
    // ...matched only by `None` at selection.
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(one, &init, &mut buf));
    assert!(!is_stun(&response));
    assert_eq!(server.imitation_protocol(), P::None);
    assert_eq!(server.auto_imitation.hint(None), Some(P::Stun));
    network(client.decapsulate(one, &response, &mut buf));
    // And `Some` replaces `None`.
    assert!(matches!(
        server.decapsulate(one, &dns, &mut buf),
        TunnResult::Done
    ));
    assert_eq!(server.auto_imitation.hint(None), None);
    assert_eq!(server.auto_imitation.hint(one), Some(P::Dns));
    refused(&mut server, None, &stun[0]);
    advance_clock();
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(None, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::Stun);
    confirm_and_exchange(&mut client, &mut server, None, &response, is_stun);

    #[cfg(feature = "mock-instant")]
    {
        use mock_instant::thread_local::MockClock;
        let (_, mut server) = pair_under(&client_config, &config, obf, None);
        refused(&mut server, one, &stun[0]);
        MockClock::advance(Duration::from_secs(29));
        assert!(matches!(
            server.decapsulate(one, &dns, &mut buf),
            TunnResult::Done
        ));
        assert_eq!(server.auto_imitation.hint(one), Some(P::Stun));
        MockClock::advance(Duration::from_secs(1));
        assert_eq!(server.auto_imitation.hint(one), None, "expired at 30 s");
        assert!(matches!(
            server.decapsulate(one, &dns, &mut buf),
            TunnResult::Done
        ));
        assert_eq!(server.auto_imitation.hint(one), Some(P::Dns));
        MockClock::advance(Duration::from_secs(30));
        refused(&mut server, one, &stun[1]);
        assert_eq!(server.auto_imitation.hint(one), Some(P::Stun));
    }
}

/// The installer's 247-byte SIP probe (tests/helpers/boringtun-imitation-wire.py,
/// `sip_probe`).
fn installer_sip_probe() -> Vec<u8> {
    let probe = b"OPTIONS sip:probe@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK0123456789\r\n\
Max-Forwards: 70\r\nFrom: <sip:probe@example.com>;tag=1\r\n\
To: <sip:probe@example.com>\r\nCall-ID: 0123456789@example.com\r\n\
CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        .to_vec();
    assert_eq!(probe.len(), 247);
    probe
}

/// The installer's SIP layout, under which the probe's `\r\nVi` at S4 = 37 is
/// a transport tag.
const SIP_S: [u16; 4] = [27, 113, 125, 37];
const SIP_H4: (u32, u32) = (1_767_000_000, 1_866_999_999);

/// Learn `protocol` from `prelude`, which fits a transport reading at S4.
fn learns_colliding(protocol: P, prelude: &[u8], s: [u16; 4], h4: (u32, u32)) {
    use super::auto_imitation_fixtures::*;
    use super::imitation::detect::detect;
    let server_config =
        AmneziaConfig::new(s[0], s[1], s[2], s[3]).with_protocol_imitation(P::Auto, None);
    let client_config = AmneziaConfig::new(s[0], s[1], s[2], s[3])
        .with_protocol_imitation(protocol, None)
        .as_responder();
    let obf = recorded_obf(h4);
    assert_eq!(detect(prelude).map(|p| p.protocol()), Some(protocol));
    assert_eq!(
        server_config.inbound_candidates(obf, prelude).offsets(),
        vec![s[3] as usize],
        "{:?} prelude fits a transport reading",
        protocol
    );
    let (mut client, mut server) = pair_under(&client_config, &server_config, obf, None);
    assert_unresolved(&server);
    let src: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
    let mut buf = [0u8; 2048];
    assert!(matches!(
        server.decapsulate(src, prelude, &mut buf),
        TunnResult::Err(WireGuardError::NoCurrentSession)
    ));
    assert_eq!(server.auto_imitation.hint(src), Some(protocol));
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(src, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), protocol);
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| {
        is_shaped(p, protocol)
    });
}

#[test]
fn auto_imitation_colliding_dns_quic_sip_preludes_are_learned() {
    use super::auto_imitation_fixtures::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    let plain = AmneziaConfig::default();
    let s4 = RECORDED_S[3] as usize;

    let domain = format!("{}.{}.com", "a".repeat(50), "b".repeat(50));
    let dns = AmneziaConfig::default()
        .with_protocol_imitation(P::Dns, Some(domain))
        .pre_handshake_imitation_datagrams(&mut OsRng)
        .pop_front()
        .unwrap()
        .1;
    assert_eq!(dns.len(), 123, "the generated query");
    learns_colliding(P::Dns, &dns, RECORDED_S, colliding_h4_for(&dns, s4, &plain));

    let quic = AmneziaConfig::default()
        .with_protocol_imitation(P::Quic, Some("example.com".into()))
        .pre_handshake_imitation_datagrams(&mut ChaCha8Rng::seed_from_u64(7))
        .pop_front()
        .unwrap()
        .1;
    learns_colliding(
        P::Quic,
        &quic,
        RECORDED_S,
        colliding_h4_for(&quic, s4, &plain),
    );

    learns_colliding(P::Sip, &installer_sip_probe(), SIP_S, SIP_H4);
}

/// Recovered evidence obeys header-protection policy like any other: SIP
/// with S >= 31 under header protection is refused, with one warning.
#[test]
fn auto_imitation_recovered_sip_hint_obeys_header_protection_policy() {
    use super::auto_imitation_fixtures::*;
    let key = [7; 32];
    let layout =
        AmneziaConfig::new(SIP_S[0], SIP_S[1], SIP_S[2], SIP_S[3]).with_header_protection(key);
    let server_config = layout.clone().with_protocol_imitation(P::Auto, None);
    let probe = installer_sip_probe();
    let obf = recorded_obf(colliding_h4_for(&probe, SIP_S[3] as usize, &layout));
    assert_eq!(
        server_config.inbound_candidates(obf, &probe).offsets(),
        vec![SIP_S[3] as usize]
    );
    let (mut client, mut server) = pair_under(&layout, &server_config, obf, None);
    assert_unresolved(&server);
    let src: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
    let mut buf = [0u8; 2048];
    assert!(matches!(
        server.decapsulate(src, &probe, &mut buf),
        TunnResult::Err(WireGuardError::NoCurrentSession)
    ));
    assert_eq!(server.auto_imitation.hint(src), Some(P::Sip));

    let refusals = policy_refusals(|| {
        for _ in 0..3 {
            advance_clock();
            let init = network(client.format_handshake_initiation(&mut buf, false));
            let response = network(server.decapsulate(src, &init, &mut buf));
            assert_eq!(server.imitation_protocol(), P::None);
            assert!(!is_shaped(&response, P::Sip));
            network(client.decapsulate(src, &response, &mut buf));
        }
    });
    assert_eq!(refusals, 1);
}

/// Fixed modes keep their contract: no hints, the configured shape.
#[test]
fn auto_imitation_fallback_leaves_fixed_modes_alone() {
    use super::auto_imitation_fixtures::*;
    let stun = recorded_stun_prelude();
    let config = recorded_layout(P::Dns).as_responder();
    let obf = recorded_obf(COLLIDING_H4);
    assert_eq!(config.inbound_candidates(obf, &stun[0]).offsets(), vec![36]);
    let (mut client, mut server) = pair_under(&config, &config, obf, None);
    let src: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
    let mut buf = [0u8; 2048];
    assert!(matches!(
        server.decapsulate(src, &stun[0], &mut buf),
        TunnResult::Err(WireGuardError::NoCurrentSession)
    ));
    assert!(!server.has_imitation_hint());
    let init = network(client.format_handshake_initiation(&mut buf, false));
    let response = network(server.decapsulate(src, &init, &mut buf));
    assert_eq!(server.imitation_protocol(), P::Dns);
    confirm_and_exchange(&mut client, &mut server, src, &response, |p| {
        is_shaped(p, P::Dns)
    });
}
