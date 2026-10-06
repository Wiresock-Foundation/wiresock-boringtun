// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol as P};
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
