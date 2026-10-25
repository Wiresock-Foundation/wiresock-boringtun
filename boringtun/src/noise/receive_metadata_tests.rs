// SPDX-License-Identifier: BSD-3-Clause

use super::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use super::errors::WireGuardError;
use super::handshake::{b2s_hash, b2s_keyed_mac_16, LABEL_MAC1};
use super::inbound::fixtures::{
    bare_ipv4, colliding, handshake, keyed_pair_with_publics, network, pair,
};
use super::{AuthenticatedPacketKind as Kind, Tunn, TunnResult, HANDSHAKE_RESP_SZ};
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn source() -> Option<SocketAddr> {
    Some("198.51.100.7:40000".parse().unwrap())
}

fn profiles() -> [AmneziaConfig; 4] {
    [
        AmneziaConfig::default(),
        colliding(None),
        colliding(Some([0x5a; 32])),
        colliding(Some([0x5a; 32])).with_random_trailers(true),
    ]
}

fn ipv6() -> Vec<u8> {
    let mut packet = vec![0; 43];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&3u16.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::from(2u128).octets());
    packet[40..].copy_from_slice(&[1, 2, 3]);
    packet
}

fn establish(mine: &mut Tunn, theirs: &mut Tunn) {
    let mut buf = [0; 4096];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeInitiation));
    assert!(kind.unwrap().moves_endpoint());
    let response = network(result);
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeResponse));
    assert!(kind.unwrap().moves_endpoint());
    let keepalive = network(result);
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &keepalive, &mut buf);
    assert_eq!(kind, Some(Kind::Transport));
    assert!(kind.unwrap().moves_endpoint());
    assert!(matches!(result, TunnResult::Done));
}

#[test]
fn authenticated_handshakes_keepalives_and_both_ip_families_have_proof() {
    profiles().iter().for_each(|config| {
        let (mut mine, mut theirs) = pair(config, None);
        establish(&mut mine, &mut theirs);
        let mut buf = [0; 4096];
        [bare_ipv4(), ipv6()].iter().for_each(|packet| {
            let wire = network(mine.encapsulate(packet, &mut buf));
            let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &wire, &mut buf);
            assert_eq!(kind, Some(Kind::Transport));
            match result {
                TunnResult::WriteToTunnelV4(bytes, addr) => {
                    assert_eq!(bytes, packet.as_slice());
                    assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 2));
                }
                TunnResult::WriteToTunnelV6(bytes, addr) => {
                    assert_eq!(bytes, packet.as_slice());
                    assert_eq!(addr, Ipv6Addr::LOCALHOST);
                }
                other => panic!("expected IP output, got {:?}", other),
            }
            let wire = network(theirs.encapsulate(packet, &mut buf));
            let (result, kind) = mine.decapsulate_from_with_metadata(None, &wire, &mut buf);
            assert_eq!(kind, Some(Kind::Transport));
            assert!(matches!(
                result,
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..)
            ));
        });
    });
}

#[test]
fn accepted_cookie_is_distinct_from_the_unauthenticated_cookie_demand() {
    profiles().iter().for_each(|config| {
        let (mut mine, mut theirs) = pair(config, Some(0));
        let mut buf = [0; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
        assert_eq!(kind, None);
        let cookie = network(result);
        let mut bad_cookie = cookie.clone();
        bad_cookie[config.cookie_packet_junk_size as usize + 40] ^= 1;
        let (result, kind) = mine.decapsulate_from_with_metadata(source(), &bad_cookie, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Err(_)));
        let (result, kind) = mine.decapsulate_from_with_metadata(source(), &cookie, &mut buf);
        assert_eq!(kind, Some(Kind::CookieReply));
        assert!(!kind.unwrap().moves_endpoint());
        assert!(matches!(result, TunnResult::Done));
        // A reply is accepted once per handshake message we send; a captured
        // copy is refused and accepted as nothing.
        let (result, kind) = mine.decapsulate_from_with_metadata(source(), &cookie, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(
            result,
            TunnResult::Err(WireGuardError::UnexpectedPacket)
        ));
        let (result, kind) = mine.decapsulate_from_with_metadata(source(), &[0xff], &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Err(_)));
    });
}

#[test]
fn under_load_without_a_source_a_handshake_is_refused_with_no_kind() {
    // With no source there is nothing to bind a cookie to, so none is
    // demanded: the initiation is refused outright.
    profiles().iter().for_each(|config| {
        let (mut mine, mut theirs) = pair(config, Some(0));
        let mut buf = [0; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let (result, kind) = theirs.decapsulate_from_with_metadata(None, &init, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Err(WireGuardError::UnderLoad)));
    });
}

#[test]
fn with_cookies_disabled_a_sourceless_handshake_under_load_is_accepted() {
    // `DisableCookies` skips the load check, so the documented exception to
    // the no-source refusal: the initiation is accepted and answered.
    let config = AmneziaConfig::default().with_disable_cookies(true);
    let (mut mine, mut theirs) = pair(&config, Some(0));
    let mut buf = [0; 4096];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let (result, kind) = theirs.decapsulate_from_with_metadata(None, &init, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeInitiation));
    assert!(matches!(result, TunnResult::WriteToNetwork(_)));
}

#[test]
fn an_initiation_proven_by_its_cookie_is_accepted_under_load() {
    profiles().iter().for_each(|config| {
        let (mut mine, mut theirs) = pair(config, Some(0));
        let mut buf = [0; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
        assert_eq!(kind, None, "a cookie demand accepts nothing");
        let cookie = network(result);
        let (_, kind) = mine.decapsulate_from_with_metadata(source(), &cookie, &mut buf);
        assert_eq!(kind, Some(Kind::CookieReply));
        // The retransmission carries a mac2 under the cookie, bound to the
        // same source, and is admitted although the responder is under load.
        let init = network(mine.format_handshake_initiation(&mut buf, true));
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
        assert_eq!(kind, Some(Kind::HandshakeInitiation));
        assert!(kind.unwrap().moves_endpoint());
        let response = network(result);
        let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
        assert_eq!(kind, Some(Kind::HandshakeResponse));
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
    });
}

#[test]
fn an_acceptance_on_the_legacy_path_is_not_reported_by_the_next_metadata_receive() {
    // The kind is tunnel state between the commit that records it and the
    // end of the metadata receive. A legacy receive records acceptance too;
    // it must not surface in a later metadata receive that accepts nothing.
    let (mut mine, mut theirs) = pair(&AmneziaConfig::default(), None);
    let mut buf = [0; 4096];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    assert!(matches!(
        theirs.decapsulate_from(source(), &init, &mut buf),
        TunnResult::WriteToNetwork(_)
    ));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
    ));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &[0xff], &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Err(_)));
}

#[cfg(feature = "device")]
#[test]
fn an_acceptance_on_the_device_path_is_not_reported_by_the_next_metadata_receive() {
    // The device's anonymous ingress authenticates and commits through
    // `authenticate` and `commit_with_imitation`, which record acceptance too.
    let (mut mine, mut theirs) = pair(&AmneziaConfig::default(), None);
    let mut buf = [0; 4096];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let packet = Tunn::parse_incoming_packet(theirs.handshake.obf, &init).unwrap();
    let packet = theirs.authenticate(packet, &mut buf).unwrap();
    assert!(packet.moves_endpoint());
    assert!(matches!(
        theirs.commit_with_imitation(packet, &init, None, &mut buf),
        TunnResult::WriteToNetwork(_)
    ));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
    ));
}

#[test]
fn authenticated_malformed_plaintext_retains_proof_without_ip_delivery() {
    profiles().iter().for_each(|config| {
        let (mut mine, mut theirs) = pair(config, None);
        handshake(&mut mine, &mut theirs);
        let mut buf = [0; 4096];
        let wire = network(mine.encapsulate(&[0x70; 40], &mut buf));
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &wire, &mut buf);
        assert_eq!(kind, Some(Kind::Transport));
        assert!(matches!(
            result,
            TunnResult::Err(WireGuardError::InvalidPacket)
        ));
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &wire, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(
            result,
            TunnResult::Err(WireGuardError::DuplicateCounter)
        ));
    });
}

#[test]
fn initiation_without_room_for_its_response_has_no_kind_and_stays_retryable() {
    // The room for the response is checked before the initiation is
    // authenticated (AWG-R1-003), so a short buffer consumes nothing in any
    // imitation mode: no kind, and the same initiation is answered on retry.
    [
        AmneziaConfig::default(),
        AmneziaConfig::new(128, 128, 128, 128)
            .with_protocol_imitation(AmneziaImitationProtocol::Auto, None),
    ]
    .iter()
    .for_each(|config| {
        let (mut mine, mut theirs) = pair(config, None);
        let mut buf = [0; 4096];
        let init = network(mine.format_handshake_initiation(&mut buf, false));
        // Below the bare response, and one byte below the prefixed one.
        let tight = HANDSHAKE_RESP_SZ + config.response_packet_junk_size as usize - 1;
        [16, tight].iter().for_each(|&room| {
            let (result, kind) =
                theirs.decapsulate_from_with_metadata(source(), &init, &mut buf[..room]);
            assert_eq!(kind, None);
            assert!(matches!(
                result,
                TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
            ));
        });
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
        assert_eq!(kind, Some(Kind::HandshakeInitiation));
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        // Accepted now, so the same initiation is a replay.
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(
            result,
            TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
        ));
    });
}

#[test]
fn tampered_aead_with_a_valid_mac1_has_no_proof() {
    let (mut mine, mut theirs, _, their_public) =
        keyed_pair_with_publics(&AmneziaConfig::default(), None);
    let mut buf = [0; 2048];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let mut forged = init.clone();
    forged[40] ^= 1; // first byte of encrypted_static
    let mac1 = b2s_keyed_mac_16(
        &b2s_hash(LABEL_MAC1, their_public.as_bytes()),
        &forged[..116],
    );
    forged[116..132].copy_from_slice(&mac1);
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &forged, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::InvalidAeadTag)
    ));
}

#[test]
fn rejected_handshakes_transport_and_replays_never_reuse_previous_proof() {
    // Every refusal here reports no kind. Those that follow an acceptance
    // also show a kind does not carry from one metadata receive to the next;
    // a kind left by another entry point is covered by the
    // `an_acceptance_*_is_not_reported_by_the_next_metadata_receive` tests.
    let (mut mine, mut theirs) = pair(&AmneziaConfig::default(), None);
    let mut buf = [0; 4096];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let mut forged = init.clone();
    forged[116] ^= 1;
    [&init[..10], forged.as_slice()].iter().for_each(|wire| {
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), wire, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Err(_)));
    });
    let (_, mut wrong_peer) = pair(&AmneziaConfig::default(), None);
    let (result, kind) = wrong_peer.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Err(_)));

    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeInitiation));
    let response = network(result);
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &init, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Err(_)));
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeResponse));
    let keepalive = network(result);
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Err(_)));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &keepalive, &mut buf);
    assert_eq!(kind, Some(Kind::Transport));
    assert!(matches!(result, TunnResult::Done));

    let wire = network(mine.encapsulate(&bare_ipv4(), &mut buf));
    let mut wrong_slot = wire.clone();
    wrong_slot[4] ^= 1; // low bit selects a different session slot
    let mut wrong_index = wire.clone();
    wrong_index[4] ^= 0x80; // same slot, different receiver index
    let mut tampered = wire.clone();
    *tampered.last_mut().unwrap() ^= 1;
    [
        &wire[..8],
        wrong_slot.as_slice(),
        wrong_index.as_slice(),
        tampered.as_slice(),
    ]
    .iter()
    .for_each(|wire| {
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), wire, &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Err(_)));
    });
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &wire, &mut buf);
    assert_eq!(kind, Some(Kind::Transport));
    assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &wire, &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::DuplicateCounter)
    ));
}

#[test]
fn valid_response_with_a_short_buffer_has_no_proof() {
    let (mut mine, mut theirs) = pair(&AmneziaConfig::default(), None);
    let mut buf = [0; 2048];
    let init = network(mine.format_handshake_initiation(&mut buf, false));
    let response = network(theirs.decapsulate_from(source(), &init, &mut buf));
    let mut short = [0; 16];
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut short);
    assert_eq!(kind, None);
    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
    ));
    // The capacity check ran before the response AEAD, so the pending
    // initiation is intact and the retry succeeds.
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeResponse));
    assert!(matches!(result, TunnResult::WriteToNetwork(_)));
}

#[test]
fn metadata_receive_refuses_empty_datagrams_but_legacy_receive_drains() {
    let (mut mine, mut theirs) = pair(&AmneziaConfig::default(), None);
    let mut buf = [0; 4096];
    let init = network(mine.encapsulate(&bare_ipv4(), &mut buf));
    let response = network(theirs.decapsulate_from(source(), &init, &mut buf));
    let (result, kind) = mine.decapsulate_from_with_metadata(source(), &response, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeResponse));
    let keepalive = network(result);
    assert!(matches!(
        theirs.decapsulate_from(source(), &keepalive, &mut buf),
        TunnResult::Done
    ));
    // The metadata receiver refuses the empty network datagram and leaves the
    // queued packet where it is.
    let (result, kind) = mine.decapsulate_from_with_metadata(None, &[], &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Done));
    // The legacy wrapper keeps its documented drain contract.
    let queued = network(mine.decapsulate_from(None, &[], &mut buf));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &queued, &mut buf);
    assert_eq!(kind, Some(Kind::Transport));
    assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
    let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &[], &mut buf);
    assert_eq!(kind, None);
    assert!(matches!(result, TunnResult::Done));
    assert!(matches!(theirs.update_timers(&mut buf), TunnResult::Done));
    let (_, kind) = theirs.decapsulate_from_with_metadata(None, &[], &mut buf);
    assert_eq!(kind, None);
}

#[test]
fn imitation_observation_is_not_authentication() {
    let config = AmneziaConfig::new(128, 128, 128, 128)
        .with_protocol_imitation(AmneziaImitationProtocol::Auto, None);
    let prelude = super::auto_imitation_fixtures::recorded_stun_prelude();
    // On a fresh tunnel, and on one whose last commit accepted an initiation
    // through the legacy receive, so a recorded kind is there to leak.
    [false, true].iter().for_each(|&after_acceptance| {
        let (mut mine, mut theirs) = pair(&config, None);
        let mut buf = [0; 2048];
        if after_acceptance {
            // An initiation's random S1 prefix can, rarely, read as a probe
            // (QUIC, say), and accepting it would then teach Auto that
            // protocol and leave no hint to observe. Use one that reads as
            // none, so the test does not depend on chance.
            let init = loop {
                let init = network(mine.format_handshake_initiation(&mut buf, true));
                if super::imitation::detect::detect(&init).is_none() {
                    break init;
                }
            };
            assert!(matches!(
                theirs.decapsulate_from(source(), &init, &mut buf),
                TunnResult::WriteToNetwork(_)
            ));
        }
        let (result, kind) = theirs.decapsulate_from_with_metadata(source(), &prelude[0], &mut buf);
        assert_eq!(kind, None);
        assert!(matches!(result, TunnResult::Done));
        assert!(theirs.has_imitation_hint());
    });
}

#[derive(Debug, PartialEq)]
enum ActionShape {
    Done,
    Error(std::mem::Discriminant<WireGuardError>),
    Network(usize, u32),
    Ipv4(Vec<u8>, Ipv4Addr),
    Ipv6(Vec<u8>, Ipv6Addr),
}

fn shape(result: TunnResult) -> ActionShape {
    match result {
        TunnResult::Done => ActionShape::Done,
        TunnResult::Err(error) => ActionShape::Error(std::mem::discriminant(&error)),
        TunnResult::WriteToNetwork(bytes) => ActionShape::Network(
            bytes.len(),
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        ),
        TunnResult::WriteToTunnelV4(bytes, addr) => ActionShape::Ipv4(bytes.to_vec(), addr),
        TunnResult::WriteToTunnelV6(bytes, addr) => ActionShape::Ipv6(bytes.to_vec(), addr),
    }
}

#[test]
fn legacy_receive_actions_match_metadata_receive_on_fresh_equivalent_states() {
    // Guards against future divergence between the two entry points; the
    // empty-input exception is covered by
    // `metadata_receive_refuses_empty_datagrams_but_legacy_receive_drains`.
    let config = AmneziaConfig::default();
    let (mut old_mine, mut old_theirs) = pair(&config, None);
    let (mut new_mine, mut new_theirs) = pair(&config, None);
    let mut buf = [0; 4096];
    let old_init = network(old_mine.format_handshake_initiation(&mut buf, false));
    let new_init = network(new_mine.format_handshake_initiation(&mut buf, false));
    let old_response = network(old_theirs.decapsulate_from(source(), &old_init, &mut buf));
    let (new_result, kind) =
        new_theirs.decapsulate_from_with_metadata(source(), &new_init, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeInitiation));
    let new_response = network(new_result);
    assert_eq!(
        shape(TunnResult::WriteToNetwork(&mut old_response.clone())),
        shape(TunnResult::WriteToNetwork(&mut new_response.clone()))
    );
    let old_keepalive = network(old_mine.decapsulate_from(source(), &old_response, &mut buf));
    let (new_result, kind) =
        new_mine.decapsulate_from_with_metadata(source(), &new_response, &mut buf);
    assert_eq!(kind, Some(Kind::HandshakeResponse));
    let new_keepalive = network(new_result);
    assert_eq!(
        shape(old_theirs.decapsulate(None, &old_keepalive, &mut buf)),
        ActionShape::Done
    );
    let (result, kind) = new_theirs.decapsulate_from_with_metadata(None, &new_keepalive, &mut buf);
    assert_eq!(kind, Some(Kind::Transport));
    assert_eq!(shape(result), ActionShape::Done);
    [bare_ipv4(), ipv6(), vec![0x70; 40]]
        .iter()
        .for_each(|packet| {
            let old_wire = network(old_mine.encapsulate(packet, &mut buf));
            let new_wire = network(new_mine.encapsulate(packet, &mut buf));
            let old = shape(old_theirs.decapsulate_from(source(), &old_wire, &mut buf));
            let (result, kind) =
                new_theirs.decapsulate_from_with_metadata(source(), &new_wire, &mut buf);
            assert_eq!(kind, Some(Kind::Transport));
            assert_eq!(shape(result), old);
        });
    let old = shape(old_theirs.decapsulate(None, &[0xff], &mut buf));
    let (result, kind) = new_theirs.decapsulate_from_with_metadata(None, &[0xff], &mut buf);
    assert_eq!(kind, None);
    assert_eq!(shape(result), old);
}
