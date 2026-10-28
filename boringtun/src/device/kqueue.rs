// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use parking_lot::Mutex;
use std::io;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A return type for the EventPoll::wait() function
pub enum WaitResult<'a, H> {
    /// Event triggered normally
    Ok(EventGuard<'a, H>),
    /// Event triggered due to End of File conditions
    EoF(EventGuard<'a, H>),
    /// There was an error
    Error(String),
}

/// Implements a registry of pollable events
pub struct EventPoll<H: Sized> {
    events: Mutex<Vec<Option<Box<Event<H>>>>>, // Events with a file descriptor
    custom: Mutex<Vec<Option<Box<Event<H>>>>>, // Other events (i.e. timers & notifiers)
    signals: Mutex<Vec<Option<Box<Event<H>>>>>, // Signal handlers
    kqueue: RawFd,                             // The OS kqueue
    #[cfg(test)]
    fail_next_stream_read: AtomicBool,
}

/// A type that hold a reference to a triggered Event
/// While an EventGuard exists for a given Event, it will not be triggered by any other thread
/// Once the EventGuard goes out of scope, the underlying Event will be re-enabled
pub struct EventGuard<'a, H> {
    kqueue: RawFd,
    event: &'a Event<H>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an EventPoll
pub struct EventRef {
    trigger: RawFd,
}

#[derive(PartialEq)]
enum EventKind {
    FD,
    Notifier,
    Signal,
    Timer,
}

// A single event
struct Event<H> {
    event: kevent, // The kqueue event description
    handler: H,    // The associated data
    kind: EventKind,
    drain_eof: bool,
    write_interest: AtomicBool,
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        unsafe { close(self.kqueue) };
    }
}

unsafe impl<H> Send for EventPoll<H> {}
unsafe impl<H> Sync for EventPoll<H> {}

impl<H: Send + Sync> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<EventPoll<H>, Error> {
        let kqueue = match unsafe { kqueue() } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            kqueue => kqueue,
        };

        Ok(EventPoll {
            events: Mutex::new(vec![]),
            custom: Mutex::new(vec![]),
            signals: Mutex::new(vec![]),
            kqueue,
            #[cfg(test)]
            fail_next_stream_read: AtomicBool::new(false),
        })
    }

    /// Test-only live registration count, including timers and notifiers.
    #[cfg(test)]
    pub(crate) fn registered_count(&self) -> usize {
        self.events.lock().iter().flatten().count()
            + self.custom.lock().iter().flatten().count()
            + self.signals.lock().iter().flatten().count()
    }

    /// Add and enable a new event with the factory.
    /// The event is triggered when a Read operation on the provided trigger becomes available
    /// If the trigger fd is closed, the event won't be triggered anymore, but it's data won't be
    /// automatically released.
    /// The safe way to delete an event, is using the cancel method of an EventGuard.
    /// If the same trigger is used with multiple events in the same EventPoll, the last added
    /// event overrides all previous events. In case the same trigger is used with multiple polls,
    /// each event will be triggered independently.
    /// The event will keep triggering until a Read operation is no longer possible on the trigger.
    /// When triggered, one of the threads waiting on the poll will receive the handler via an
    /// appropriate EventGuard. It is guaranteed that only a single thread can have a reference to
    /// the handler at any given time.
    pub fn new_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        self.new_read_event(trigger, handler, false)
    }

    pub fn new_stream_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        self.new_read_event(trigger, handler, true)
    }

    fn new_read_event(
        &self,
        trigger: RawFd,
        handler: H,
        drain_eof: bool,
    ) -> Result<EventRef, Error> {
        // Create an event descriptor
        let flags = EV_ENABLE | EV_DISPATCH;

        let ev = Event {
            event: kevent {
                ident: trigger as _,
                filter: EVFILT_READ,
                flags,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::FD,
            drain_eof,
            write_interest: AtomicBool::new(false),
        };

        self.register_event(ev)
    }

    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef, Error> {
        // The periodic event in BSD uses EVFILT_TIMER
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_TIMER,
                flags: EV_ENABLE | EV_DISPATCH,
                fflags: NOTE_NSECONDS,
                data: period
                    .as_secs()
                    .checked_mul(1_000_000_000)
                    .unwrap()
                    .checked_add(u64::from(period.subsec_nanos()))
                    .unwrap() as _,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Timer,
            drain_eof: false,
            write_interest: AtomicBool::new(false),
        };

        self.register_event(ev)
    }

    pub fn new_notifier(&self, handler: H) -> Result<EventRef, Error> {
        // The notifier in BSD uses EVFILT_USER for notifications.
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_USER,
                flags: EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Notifier,
            drain_eof: false,
            write_interest: AtomicBool::new(false),
        };

        self.register_event(ev)
    }

    /// Add and enable a new signal handler
    pub fn new_signal_event(&self, signal: c_int, handler: H) -> Result<EventRef, Error> {
        let ev = Event {
            event: kevent {
                ident: signal as _,
                filter: EVFILT_SIGNAL,
                flags: EV_ENABLE | EV_DISPATCH,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Signal,
            drain_eof: false,
            write_interest: AtomicBool::new(false),
        };

        self.register_event(ev)
    }

    /// Wait until one of the registered events becomes triggered. Once an event
    /// is triggered, a single caller thread gets the handler for that event.
    /// In case a notifier is triggered, all waiting threads will receive the same
    /// handler.
    pub fn wait(&'_ self) -> WaitResult<'_, H> {
        let mut event = kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: null_mut(),
        };

        if unsafe { kevent(self.kqueue, null(), 0, &mut event, 1, null()) } == -1 {
            return WaitResult::Error(io::Error::last_os_error().to_string());
        }

        let event_data = unsafe { (event.udata as *mut Event<H>).as_ref().unwrap() };

        let guard = EventGuard {
            kqueue: self.kqueue,
            event: event_data,
            poll: self,
        };

        if event.flags & EV_EOF != 0 && !event_data.drain_eof {
            WaitResult::EoF(guard)
        } else {
            WaitResult::Ok(guard)
        }
    }

    // Register an event with this poll.
    fn register_event(&self, ev: Event<H>) -> Result<EventRef, Error> {
        // Both handlers this can destroy -- the one being displaced, and on the
        // error path the one being rejected -- leave the lock scope before they
        // are dropped. `H` is a type parameter and `EventPoll` makes no promise
        // about what its `Drop` runs; one that reached back into this poll would
        // hang the worker, because `parking_lot::Mutex` is not reentrant.
        // Binding inside the block is not enough: the guard is a *named* local
        // declared first, and locals drop in reverse declaration order, so
        // anything declared after it dies while it is still held. Handing the
        // box out of the block is what works. Mirrors `epoll.rs`.
        let (trigger, displaced) = {
            let mut events = match ev.kind {
                EventKind::FD => self.events.lock(),
                EventKind::Timer | EventKind::Notifier => self.custom.lock(),
                EventKind::Signal => self.signals.lock(),
            };

            let (trigger, index) = match ev.kind {
                EventKind::FD | EventKind::Signal => {
                    (ev.event.ident as RawFd, ev.event.ident as usize)
                }
                EventKind::Timer | EventKind::Notifier => {
                    (-(events.len() as RawFd) - 1, events.len())
                } // Custom events get negative identifiers, hopefully we will never have more than 2^31 events of each type
            };

            // Expand events vector if needed
            while events.len() <= index {
                // Resize the vector to be able to fit the new index
                // We trust the OS to allocate file descriptors in a sane order
                events.push(None); // resize doesn't work because Clone is not satisfied
            }

            // Streams own their descriptor. Refuse replacement rather than
            // disturbing an existing two-filter registration during rollback.
            if ev.drain_eof && events[index].is_some() {
                drop(events);
                return Err(Error::EventQueue(io::Error::from_raw_os_error(EEXIST)));
            }

            let mut ev = Box::new(ev);
            // The inner event points back to the wrapper
            ev.event.ident = trigger as _;
            ev.event.udata = ev.as_mut() as *mut Event<H> as _;

            // Reserve WRITE while registering the stream, before READ can
            // dispatch. Later switches only enable an existing filter and
            // cannot strand a connection on a failed allocation in Drop.
            if ev.drain_eof {
                let mut write = ev.event;
                write.filter = EVFILT_WRITE;
                write.flags = EV_ADD | EV_DISABLE | EV_DISPATCH;
                if unsafe { kevent(self.kqueue, &write, 1, null_mut(), 0, null()) } == -1 {
                    let err = io::Error::last_os_error();
                    drop(events);
                    return Err(Error::EventQueue(err));
                }
            }

            let mut kev = ev.event;
            kev.flags |= EV_ADD;

            #[cfg(test)]
            let queue = if ev.drain_eof && self.fail_next_stream_read.swap(false, Ordering::Relaxed)
            {
                -1
            } else {
                self.kqueue
            };
            #[cfg(not(test))]
            let queue = self.kqueue;
            if unsafe { kevent(queue, &kev, 1, null_mut(), 0, null()) } == -1 {
                // errno before the unlock, and the unlock before `ev` drops.
                let err = io::Error::last_os_error();
                if ev.drain_eof {
                    let mut write = ev.event;
                    write.filter = EVFILT_WRITE;
                    write.flags = EV_DELETE;
                    unsafe { kevent(self.kqueue, &write, 1, null_mut(), 0, null()) };
                }
                drop(events);
                return Err(Error::EventQueue(err));
            }

            // No `EV_DELETE` here, though upstream had one. `EV_ADD` above has
            // already replaced this registration: kqueue(2) says "A kevent is
            // identified by the (ident, filter) pair" and "Re-adding an existing
            // event will modify the parameters of the original event, and not
            // result in a duplicate entry". The displaced entry and the new one
            // share both halves of that key -- `index == ident` for `FD` and
            // `Signal`, `EVFILT_READ` for everything in `self.events`,
            // `EVFILT_SIGNAL` for everything in `self.signals`, and
            // `Timer`/`Notifier` cannot displace at all because their index is
            // always `events.len()`. So the delete named the registration
            // installed one statement earlier and stranded the new handler in
            // the vector, unable to trigger.
            //
            // Not moved above the `EV_ADD` instead: there a failed add would
            // leave the caller with neither registration. As it stands a failed
            // add leaves the previous one intact.
            //
            // Defensive rather than live: this branch needs `events[fd]` to be
            // occupied when a new socket is handed the same fd number, and
            // every handler owns the trigger it is indexed by, so the number
            // cannot be re-issued while the entry exists.
            let displaced = events[index].take();
            if displaced.as_ref().is_some_and(|old| old.drain_eof) {
                // A normal READ event can replace a stream. READ was replaced
                // above, but its reserved WRITE filter must leave with it.
                let mut write = kev;
                write.filter = EVFILT_WRITE;
                write.flags = EV_DELETE;
                unsafe { kevent(self.kqueue, &write, 1, null_mut(), 0, null()) };
            }

            if ev.kind == EventKind::Signal {
                // Mask the signal if successfully added to kqueue
                unsafe { signal(trigger, SIG_IGN) };
            }

            events[index] = Some(ev);

            (trigger, displaced)
        };
        drop(displaced);

        Ok(EventRef { trigger })
    }

    pub fn trigger_notification(&self, notification_event: &EventRef) {
        let events = self.custom.lock();
        let ev_index = -notification_event.trigger - 1; // Custom events have negative index from -1

        let event_ref = &(*events)[ev_index as usize];
        let event_data = event_ref.as_ref().expect("Expected an event");

        if event_data.kind != EventKind::Notifier {
            panic!("Can only trigger a notification event");
        }

        let mut kev = event_data.event;
        kev.fflags = NOTE_TRIGGER;

        unsafe { kevent(self.kqueue, &kev, 1, null_mut(), 0, null()) };
    }

    pub fn stop_notification(&self, notification_event: &EventRef) {
        let events = self.custom.lock();
        let ev_index = -notification_event.trigger - 1; // Custom events have negative index from -1

        let event_ref = &(*events)[ev_index as usize];
        let event_data = event_ref.as_ref().expect("Expected an event");

        if event_data.kind != EventKind::Notifier {
            panic!("Can only stop a notification event");
        }

        let mut kev = event_data.event;
        kev.flags = EV_DISABLE;
        kev.fflags = 0;

        unsafe { kevent(self.kqueue, &kev, 1, null_mut(), 0, null()) };
    }
}

impl<H> EventPoll<H> {
    /// Disable and remove the event and associated handler, using the fd (or,
    /// negative, the custom-event index) that was used to register it.
    ///
    /// # Safety
    ///
    /// The handler is freed here, so the caller must guarantee that no
    /// dispatch of this event is in progress or can begin -- that no
    /// `EventGuard` for it is live, nor a `wait` about to hand one out.
    /// Stopping the event loop guarantees that; so does any external
    /// quiescence mechanism that keeps every waiting thread from dispatching
    /// until this call returns. Otherwise the handler may be freed while in
    /// use.
    ///
    /// `index` must be one this poll registered and has not cleared since:
    /// every such index lies inside its table.
    pub unsafe fn clear_event_by_fd(&self, index: RawFd) {
        // Same shape as `register_event`: the handler leaves the lock scope
        // before it is destroyed. See the note there.
        let cleared = {
            let (mut events, index) = if index >= 0 {
                (self.events.lock(), index as usize)
            } else {
                (self.custom.lock(), (-index - 1) as usize)
            };

            let mut cleared = events[index].take();
            if let Some(event) = cleared.as_mut() {
                // Properly remove any previous event first
                event.event.flags = EV_DELETE;
                kevent(self.kqueue, &event.event, 1, null_mut(), 0, null());
                if event.drain_eof {
                    event.event.filter = EVFILT_WRITE;
                    kevent(self.kqueue, &event.event, 1, null_mut(), 0, null());
                }
            }
            cleared
        };
        drop(cleared);
    }
}

impl<'a, H> Deref for EventGuard<'a, H> {
    type Target = H;
    fn deref(&self) -> &H {
        &self.event.handler
    }
}

impl<'a, H> Drop for EventGuard<'a, H> {
    fn drop(&mut self) {
        let mut event = self.event.event;
        if self.event.drain_eof {
            let desired = if self.event.write_interest.load(Ordering::Relaxed) {
                EVFILT_WRITE
            } else {
                EVFILT_READ
            };
            // EV_DISPATCH already disabled the filter that fired. The other
            // filter was reserved disabled at registration; enabling exactly
            // one keeps ownership exclusive without a fresh EV_ADD allocation.
            event.filter = desired;
        }
        unsafe {
            // Re-enable the event once EventGuard goes out of scope
            kevent(self.kqueue, &event, 1, null_mut(), 0, null());
        }
    }
}

impl<'a, H> EventGuard<'a, H> {
    pub fn notify_writable(&mut self, enabled: bool) {
        self.event.write_interest.store(enabled, Ordering::Relaxed);
    }

    /// Cancel and remove the event represented by this guard
    pub fn cancel(self) {
        unsafe { self.poll.clear_event_by_fd(self.event.event.ident as RawFd) };
        std::mem::forget(self); // Don't call the regular drop that would enable the event
    }

    /// Stub: only used for Linux-specific features.
    pub fn fd(&self) -> i32 {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    // Bounded version of wait for these socket-only tests, so a broken rearm
    // reports a failure rather than hanging the macOS test job.
    fn ready<H>(poll: &EventPoll<H>) -> (EventGuard<'_, H>, i16) {
        let mut event = unsafe { std::mem::zeroed::<kevent>() };
        let timeout = timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { kevent(poll.kqueue, null(), 0, &mut event, 1, &timeout) },
            1
        );
        (
            EventGuard {
                kqueue: poll.kqueue,
                event: unsafe { &*(event.udata as *const Event<H>) },
                poll,
            },
            event.filter,
        )
    }

    fn filter_is_absent(queue: RawFd, fd: RawFd, filter: i16) -> bool {
        let mut event = unsafe { std::mem::zeroed::<kevent>() };
        event.ident = fd as _;
        event.filter = filter;
        event.flags = EV_ENABLE;
        (unsafe { kevent(queue, &event, 1, null_mut(), 0, null()) }) == -1
            && io::Error::last_os_error().raw_os_error() == Some(ENOENT)
    }

    #[test]
    fn stream_filters_switch_exclusively_and_cancel_together() {
        let poll = EventPoll::new().unwrap();
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        poll.new_stream_event(server.as_raw_fd(), ()).unwrap();
        for _ in 0..4 {
            client.write_all(b"r").unwrap();
            let (mut event, filter) = ready(&poll);
            assert_eq!(filter, EVFILT_READ);
            assert_eq!(server.read(&mut [0; 1]).unwrap(), 1);
            event.notify_writable(true);
            drop(event);
            let (mut event, filter) = ready(&poll);
            assert_eq!(filter, EVFILT_WRITE);
            server.write_all(b"w").unwrap();
            event.notify_writable(false);
            drop(event);
            assert_eq!(client.read(&mut [0; 1]).unwrap(), 1);
        }
        client.write_all(b"r").unwrap();
        ready(&poll).0.cancel();
        for filter in [EVFILT_READ, EVFILT_WRITE] {
            assert!(filter_is_absent(poll.kqueue, server.as_raw_fd(), filter));
        }
    }

    #[test]
    fn failed_stream_registration_rolls_back_its_reserved_write_filter() {
        let poll = EventPoll::new().unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        let marker = Arc::new(());
        poll.fail_next_stream_read.store(true, Ordering::Relaxed);
        assert!(poll
            .new_stream_event(server.as_raw_fd(), Arc::clone(&marker))
            .is_err());
        assert_eq!(Arc::strong_count(&marker), 1);
        for filter in [EVFILT_READ, EVFILT_WRITE] {
            assert!(filter_is_absent(poll.kqueue, server.as_raw_fd(), filter));
        }
        poll.new_stream_event(server.as_raw_fd(), marker).unwrap();
    }
}
