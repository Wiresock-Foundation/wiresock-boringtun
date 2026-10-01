// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// The C and JNI layers report an error by its discriminant (`size = e as _`),
/// so every value is spelled out and none may change; a new variant takes the
/// next unused number.
#[derive(Debug)]
pub enum WireGuardError {
    DestinationBufferTooSmall = 0,
    IncorrectPacketLength = 1,
    UnexpectedPacket = 2,
    WrongPacketType = 3,
    WrongIndex = 4,
    WrongKey = 5,
    InvalidTai64nTimestamp = 6,
    WrongTai64nTimestamp = 7,
    InvalidMac = 8,
    InvalidAeadTag = 9,
    InvalidCounter = 10,
    DuplicateCounter = 11,
    InvalidPacket = 12,
    NoCurrentSession = 13,
    LockFailed = 14,
    ConnectionExpired = 15,
    UnderLoad = 16,
    /// A new application packet was refused because the queue of packets
    /// waiting for a handshake is full; the packet was not accepted.
    PacketQueueFull = 17,
}
