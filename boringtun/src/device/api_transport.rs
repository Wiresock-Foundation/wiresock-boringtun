// Copyright (c) 2026 Vadim Smirnov (doing business as WireSock). All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Bounded UAPI stream transport. No socket operation waits while a device
//! guard is held. Only complete frames reach the existing configuration parser.

use super::{api_get, api_set};
use crate::device::dev_lock::LockReadGuard;
use crate::device::{Action, Device, Error};
use parking_lot::Mutex;
use std::io::{self, Cursor, Read, Write};
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

pub(super) const MAX_REQUEST: usize = 1024 * 1024;
pub(super) const MAX_RESPONSE: usize = 4 * 1024 * 1024;
pub(super) const MAX_CONNECTIONS: usize = 32;
pub(super) const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);
const IO_BUDGET: usize = 64 * 1024;
const WATCHDOG_PERIOD: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Response {
    bytes: Vec<u8>,
    overflow: bool,
}

impl Write for Response {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.overflow || bytes.len() > MAX_RESPONSE - self.bytes.len() {
            self.overflow = true;
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Connection {
    stream: UnixStream,
    inherited: bool,
    input: Vec<u8>,
    scanned: usize,
    output: Response,
    written: usize,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
    close_after_write: bool,
    expired: bool,
}

impl Connection {
    fn new(stream: UnixStream, inherited: bool) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            inherited,
            input: Vec::new(),
            scanned: 0,
            output: Response::default(),
            written: 0,
            // Accepted clients have a deadline even before their first byte.
            // An inherited supervisor may remain idle between transactions.
            read_deadline: (!inherited).then(|| Instant::now() + TRANSACTION_TIMEOUT),
            write_deadline: None,
            close_after_write: !inherited,
            expired: false,
        })
    }

    fn timed_out(&self, now: Instant) -> bool {
        self.write_deadline
            .or(self.read_deadline)
            .is_some_and(|end| now >= end)
    }

    fn frame_end(&mut self) -> Option<usize> {
        let found = self.input[self.scanned..]
            .windows(2)
            .position(|w| w == b"\n\n")
            .map(|n| self.scanned + n + 2);
        self.scanned = self.input.len().saturating_sub(1);
        found
    }

    fn respond(&mut self, status: i32, now: Instant) -> Action {
        let _ = write!(self.output, "errno={}\n\n", status);
        if self.output.overflow {
            self.output = Response::default();
            let _ = write!(self.output, "errno={}\n\n", libc::EOVERFLOW);
        }
        self.write_deadline = Some(now + TRANSACTION_TIMEOUT);
        Action::WaitForWrite
    }

    fn process_frame(&mut self, end: usize, d: &mut LockReadGuard<Device>, now: Instant) -> Action {
        let frame: Vec<u8> = self.input.drain(..end).collect();
        self.scanned = 0;
        if self.input.is_empty() {
            self.read_deadline = None;
        }
        let status = if frame == b"get=1\n\n" {
            api_get(&mut self.output, d)
        } else if frame.starts_with(b"set=1\n") {
            // The parser may partially apply a complete transaction before a
            // configuration error. Framing adds no rollback promise.
            api_set(&mut Cursor::new(&frame[6..]), d)
        } else {
            libc::EIO
        };
        self.respond(status, now)
    }

    fn step(&mut self, d: &mut LockReadGuard<Device>) -> Action {
        let now = Instant::now();
        if self.expired || self.timed_out(now) {
            return Action::Close;
        }

        if !self.output.bytes.is_empty() {
            let end = (self.written + IO_BUDGET).min(self.output.bytes.len());
            match self.stream.write(&self.output.bytes[self.written..end]) {
                Ok(0) => return Action::Close,
                Ok(n) => self.written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Action::WaitForWrite
                }
                Err(_) => return Action::Close,
            }
            if self.written != self.output.bytes.len() {
                return Action::WaitForWrite;
            }
            self.output = Response::default();
            self.written = 0;
            self.write_deadline = None;
            if self.close_after_write {
                return Action::Close;
            }
        }

        // After flushing one reply, buffered commands are processed even when
        // the socket has no unread bytes. At most one command per dispatch.
        if let Some(end) = self.frame_end() {
            return self.process_frame(end, d, now);
        }
        if self.input.len() == MAX_REQUEST {
            self.input.clear();
            self.close_after_write = true; // The remainder cannot be resynchronized safely.
            return self.respond(libc::E2BIG, now);
        }

        let mut bytes = [0u8; IO_BUDGET];
        let room = (MAX_REQUEST - self.input.len()).min(bytes.len());
        match self.stream.read(&mut bytes[..room]) {
            // An incomplete frame is never applied, including at EOF.
            Ok(0) => return Action::Close,
            Ok(n) => {
                self.read_deadline.get_or_insert(now + TRANSACTION_TIMEOUT);
                self.input.extend_from_slice(&bytes[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Action::WaitForRead
            }
            Err(_) => return Action::Close,
        }
        if let Some(end) = self.frame_end() {
            self.process_frame(end, d, now)
        } else if self.input.len() == MAX_REQUEST {
            self.input.clear();
            self.close_after_write = true;
            self.respond(libc::E2BIG, now)
        } else {
            Action::WaitForRead
        }
    }
}

type Connections = Arc<Mutex<Vec<Weak<Mutex<Connection>>>>>;

fn watchdog(d: &Device) -> Result<Connections, Error> {
    let connections: Connections = Arc::new(Mutex::new(Vec::new()));
    let watched = Arc::clone(&connections);
    d.queue.new_periodic_event(
        Box::new(move |_, _| {
            let now = Instant::now();
            // Never wait for a connection whose handler may be upgrading the
            // device lock. Shutdown wakes its own poll event; only that event
            // cancels itself, so no live EventGuard can be freed by the watchdog.
            watched.lock().retain(|weak| {
                if let Some(connection) = weak.upgrade() {
                    if let Some(mut c) = connection.try_lock() {
                        if !c.expired && c.timed_out(now) {
                            c.expired = true;
                            let _ = c.stream.shutdown(Shutdown::Both);
                        }
                    }
                    true
                } else {
                    false
                }
            });
            Action::Continue
        }),
        WATCHDOG_PERIOD,
    )?;
    Ok(connections)
}

fn register(
    d: &Device,
    connections: &Connections,
    stream: UnixStream,
    inherited: bool,
) -> Result<(), Error> {
    let connection = Arc::new(Mutex::new(Connection::new(stream, inherited)?));
    let fd = connection.lock().stream.as_raw_fd();
    // Only the accept handler adds entries; it and the watchdog never acquire
    // the device write lock while holding the registry mutex.
    connections.lock().push(Arc::downgrade(&connection));
    d.queue.new_stream_event(
        fd,
        Box::new(move |d, _| {
            let Some(mut c) = connection.try_lock() else {
                return Action::Continue;
            };
            let action = c.step(d);
            if matches!(action, Action::Close) && c.inherited {
                d.trigger_exit();
            }
            action
        }),
    )?;
    Ok(())
}

pub(super) fn register_inherited(d: &Device, stream: UnixStream) -> Result<(), Error> {
    let connections = watchdog(d)?;
    register(d, &connections, stream, true)
}

pub(super) fn register_listener(d: &Device, listener: UnixListener) -> Result<(), Error> {
    listener.set_nonblocking(true)?;
    let connections = watchdog(d)?;
    d.queue.new_event(
        listener.as_raw_fd(),
        Box::new(move |d, _| {
            // One accept per event; the level-triggered listener remains ready.
            if let Ok((stream, _)) = listener.accept() {
                let full = {
                    let mut entries = connections.lock();
                    entries.retain(|weak| weak.strong_count() > 0);
                    entries.len() >= MAX_CONNECTIONS
                };
                if !full {
                    if let Err(e) = register(d, &connections, stream, false) {
                        tracing::warn!(message = "Could not register UAPI connection", error = ?e);
                    }
                }
            }
            Action::Continue
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_limit_refuses_overflow_without_releasing_a_partial_dump() {
        let mut response = Response::default();
        response.write_all(&vec![b'x'; MAX_RESPONSE]).unwrap();
        assert_eq!(response.bytes.len(), MAX_RESPONSE);
        assert_eq!(
            response.write(b"x").unwrap_err().raw_os_error(),
            Some(libc::EOVERFLOW)
        );
        assert_eq!(response.bytes.len(), MAX_RESPONSE);
        let (stream, _client) = UnixStream::pair().unwrap();
        let mut connection = Connection::new(stream, true).unwrap();
        connection.output = response;
        assert!(matches!(
            connection.respond(0, Instant::now()),
            Action::WaitForWrite
        ));
        assert_eq!(
            connection.output.bytes,
            format!("errno={}\n\n", libc::EOVERFLOW).as_bytes()
        );
    }
}
