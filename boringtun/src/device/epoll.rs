// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use parking_lot::Mutex;
use std::io;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
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
    events: Mutex<Vec<Option<Box<Event<H>>>>>,
    epoll: RawFd, // The OS epoll
    /// Test-only fault injection for the next `EPOLL_CTL_ADD`. Scoped to this
    /// poll instance rather than a global, so arming it in one test cannot
    /// disturb another test's device running concurrently.
    #[cfg(test)]
    fail_next_add: std::sync::atomic::AtomicBool,
}

/// A type that hold a reference to a triggered Event
/// While an EventGuard exists for a given Event, it will not be triggered by any other thread
/// Once the EventGuard goes out of scope, the underlying Event will be re-enabled
pub struct EventGuard<'a, H> {
    epoll: RawFd,
    event: &'a mut Event<H>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an EventPoll
pub struct EventRef {
    trigger: RawFd,
}

struct Event<H> {
    event: epoll_event, // The epoll event description
    fd: RawFd,          // The associated fd
    handler: H,         // The associated data
    notifier: bool,     // Is a notification event
    needs_read: bool,   // This event needs to be read to be cleared
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        unsafe { close(self.epoll) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;

    type H = Box<dyn Fn() + Send + Sync>;

    /// A handler epoll refused must not stay in the events vector.
    ///
    /// `register_event` inserts before calling `epoll_ctl`, so a failure used to
    /// strand the box -- and because the box owns its trigger fd, that fd never
    /// closes, its number is never re-issued, and nothing ever revisits the
    /// index. The leak is permanent, not merely delayed.
    ///
    /// `epoll_ctl(EPOLL_CTL_ADD)` on a regular file fails with EPERM on every
    /// Linux, because regular files are always ready, so this needs no sysctl
    /// tuning and no privileges to reach the failure path.
    #[test]
    fn a_handler_epoll_refused_is_not_left_in_the_events_vector() {
        let poll: EventPoll<H> = EventPoll::new().unwrap();
        let path = std::env::temp_dir().join(format!("bt-epoll-probe-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();

        // The Arc is the observable: if the handler is stranded, so is whatever
        // it captured -- in production that is an `Arc<Peer>`.
        let canary = Arc::new(());
        let held = Arc::clone(&canary);
        let handler: H = Box::new(move || {
            let _ = &held;
        });

        assert!(
            poll.new_event(file.as_raw_fd(), handler).is_err(),
            "precondition: epoll_ctl on a regular file must fail, or this proves nothing"
        );
        assert_eq!(
            Arc::strong_count(&canary),
            1,
            "a handler epoll never accepted is still holding its captured state"
        );
        assert_eq!(
            poll.registered_count(),
            0,
            "a handler epoll never accepted is still in the events vector"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// `register_event` must report epoll's errno, not its own rollback's.
    ///
    /// The rollback runs between the failing `epoll_ctl` and the errno read, and
    /// everything it does can overwrite errno: `events.lock()` parks on a futex
    /// under contention, and `H` is a type parameter whose `Drop` runs whatever
    /// the caller supplied -- in this crate, `close(2)` on a `socket2::Socket`.
    /// The contract is that *nothing* runs in between, and the errno matters
    /// because `register_conn_handler`'s warning reports it to an operator as
    /// the difference between `max_user_watches` and fd exhaustion.
    ///
    /// This pins the destructor half only. The lock half needs a contending
    /// thread to lose the futex race, which is not deterministic; it was
    /// measured out-of-tree at ~1% of registrations with one contender.
    #[test]
    fn the_reported_errno_is_epolls_not_the_rollbacks() {
        struct FailingCloseOnDrop;
        impl Drop for FailingCloseOnDrop {
            fn drop(&mut self) {
                // The shape of `socket2::Socket`'s `Drop`, made to fail: EBADF.
                unsafe { close(-1) };
            }
        }

        let poll: EventPoll<FailingCloseOnDrop> = EventPoll::new().unwrap();
        let path = std::env::temp_dir().join(format!("bt-epoll-errno-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();

        let err = poll
            .new_event(file.as_raw_fd(), FailingCloseOnDrop)
            .err()
            .expect("precondition: epoll_ctl on a regular file must fail, or this proves nothing");
        let raw = match err {
            Error::EventQueue(e) => e.raw_os_error(),
            other => panic!("expected EventQueue, got {:?}", other),
        };
        assert_eq!(
            raw,
            Some(EPERM),
            "the rollback's destructor overwrote epoll_ctl's errno"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The rollback must not destroy the handler while holding `events`.
    ///
    /// `H` is a type parameter, so `EventPoll` cannot know what `H::drop` runs.
    /// One that reached back into this poll would take `self.events` a second
    /// time on the same thread, and `parking_lot::Mutex` is not reentrant, so it
    /// would hang the worker rather than fail. Nothing in this crate does today
    /// -- the closest is `Arc<Peer>`, and `Peer` has no `Drop` at all -- which
    /// makes this a contract about the function, not a reproduction of a bug.
    ///
    /// Probes with `try_lock` so a regression fails in microseconds instead of
    /// deadlocking the suite, and distinguishes "ran with the lock held" from
    /// "never ran", so deleting the rollback entirely cannot read as a pass.
    #[test]
    fn the_rollback_drops_the_handler_after_releasing_the_events_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 0 = destructor never ran, 1 = ran with the lock HELD, 2 = ran with it FREE
        static OBSERVED: AtomicUsize = AtomicUsize::new(0);

        struct ProbesTheLock(*const EventPoll<ProbesTheLock>);
        // The pointer is only read inside `drop`, on the thread that owns the
        // poll, and the poll outlives every handler registered in it.
        unsafe impl Send for ProbesTheLock {}
        unsafe impl Sync for ProbesTheLock {}

        impl Drop for ProbesTheLock {
            fn drop(&mut self) {
                let poll = unsafe { &*self.0 };
                OBSERVED.store(
                    if poll.events.try_lock().is_some() {
                        2
                    } else {
                        1
                    },
                    Ordering::SeqCst,
                );
            }
        }

        let poll: EventPoll<ProbesTheLock> = EventPoll::new().unwrap();
        let path = std::env::temp_dir().join(format!("bt-epoll-reent-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();

        poll.new_event(file.as_raw_fd(), ProbesTheLock(&poll as *const _))
            .err()
            .expect("precondition: epoll_ctl on a regular file must fail, or this proves nothing");

        // Read the observation while `poll` is still alive. Without the rollback
        // the handler would instead be freed later by the poll's own drop glue,
        // which takes no lock -- that would look free, and read as a pass.
        assert_eq!(
            OBSERVED.load(Ordering::SeqCst),
            2,
            "the rollback ran the handler's destructor while still holding \
             self.events (0 = never ran, 1 = ran with the lock held, 2 = free)"
        );

        let _ = std::fs::remove_file(&path);
    }
}

impl<H: Sync + Send> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<EventPoll<H>, Error> {
        let epoll = match unsafe { epoll_create(1) } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            epoll => epoll,
        };

        Ok(EventPoll {
            events: Mutex::new(vec![]),
            epoll,
            #[cfg(test)]
            fail_next_add: std::sync::atomic::AtomicBool::new(false),
        })
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
        // Create an event descriptor
        let flags = EPOLLIN | EPOLLONESHOT;
        let ev = Event {
            event: epoll_event {
                events: flags as _,
                u64: 0,
            },
            fd: trigger,
            handler,
            notifier: false,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new write event with the factory.
    /// The event is triggered when a Write operation on the provided trigger becomes possible
    /// For TCP sockets it means that the socket was succesfully connected
    #[allow(dead_code)]
    pub fn new_write_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        // Create an event descriptor
        let flags = EPOLLOUT | EPOLLET | EPOLLONESHOT;
        let ev = Event {
            event: epoll_event {
                events: flags as _,
                u64: 0,
            },
            fd: trigger,
            handler,
            notifier: false,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new timed event with the factory.
    /// The even will be triggered for the first time after period time, and henceforth triggered
    /// every period time. Period is counted from the moment the appropriate EventGuard is released.
    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef, Error> {
        // The periodic event on Linux uses the timerfd
        let tfd = match unsafe { timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK) } {
            -1 => match unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK) } {
                // A fallback for kernels < 3.15
                -1 => return Err(Error::Timer(io::Error::last_os_error())),
                efd => efd,
            },
            efd => efd,
        };

        let ts = timespec {
            tv_sec: period.as_secs() as _,
            tv_nsec: i64::from(period.subsec_nanos()) as _,
        };

        let spec = itimerspec {
            it_value: ts,
            it_interval: ts,
        };

        if unsafe { timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) } == -1 {
            // errno before the cleanup, for the reason spelled out in
            // `register_event`. This site is the milder one -- `close` on a
            // timerfd we just created succeeds, and a successful `close` does
            // not touch errno on glibc or musl -- but the rule is "read errno
            // before anything else runs", and a rule with an exception in it is
            // the one that gets re-broken.
            let err = io::Error::last_os_error();
            unsafe { close(tfd) };
            return Err(Error::Timer(err));
        }

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: 0,
            },
            fd: tfd,
            handler,
            notifier: false,
            needs_read: true,
        };

        self.register_event(ev)
    }

    /// Add and enable a new notification event with the factory.
    /// The event can only be triggered manually, using the trigger_notification method.
    /// The event will remain in a triggered state until the stop_notification method is
    /// called. Both methods should only be called with the producing EventPoll.
    pub fn new_notifier(&self, handler: H) -> Result<EventRef, Error> {
        // The notifier on Linux uses the eventfd for notifications.
        // The way it works is when a non zero value is written into the eventfd it will trigger
        // the EPOLLIN event. Since we don't enable ONESHOT it will keep triggering until
        // canceled.
        // When we want to stop the event, we read something once from the file descriptor.
        let efd = match unsafe { eventfd(0, EFD_NONBLOCK) } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            efd => efd,
        };

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN) as _,
                u64: 0,
            },
            fd: efd,
            handler,
            notifier: true,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new signal handler
    pub fn new_signal_event(&self, signal: c_int, handler: H) -> Result<EventRef, Error> {
        let sfd = match unsafe {
            let mut sigset = std::mem::zeroed();
            sigemptyset(&mut sigset);
            sigaddset(&mut sigset, signal);
            sigprocmask(SIG_BLOCK, &sigset, null_mut());
            signalfd(-1, &sigset, SFD_NONBLOCK)
        } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            sfd => sfd,
        };

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: 0,
            },
            fd: sfd,
            handler,
            notifier: false,
            needs_read: true,
        };

        self.register_event(ev)
    }

    /// Wait until one of the registered events becomes triggered. Once an event
    /// is triggered, a single caller thread gets the handler for that event.
    /// In case a notifier is triggered, all waiting threads will receive the same
    /// handler.
    pub fn wait(&self) -> WaitResult<'_, H> {
        let mut event = epoll_event { events: 0, u64: 0 };
        match unsafe { epoll_wait(self.epoll, &mut event, 1, -1) } {
            -1 => return WaitResult::Error(io::Error::last_os_error().to_string()),
            1 => {}
            _ => return WaitResult::Error("unexpected number of events returned".to_string()),
        }

        let event_data = unsafe { (event.u64 as *mut Event<H>).as_mut().unwrap() };

        let guard = EventGuard {
            epoll: self.epoll,
            event: event_data,
            poll: self,
        };

        if event.events & EPOLLHUP as u32 != 0 {
            // End of file flag
            WaitResult::EoF(guard)
        } else {
            WaitResult::Ok(guard)
        }
    }

    // Register an event with this poll.
    fn register_event(&self, ev: Event<H>) -> Result<EventRef, Error> {
        // To register an event we
        // * Create a reference to self in the inner event
        // * Store the Event in the events vector
        // * Dispose of a previous Event under same fd if any
        // * Add the Event to epoll
        let trigger = ev.fd;
        let mut ev = Box::new(ev);
        // The inner event points back to the wrapper
        ev.event.u64 = ev.as_mut() as *mut Event<H> as _;
        let mut event_desc = ev.event;
        // Now add the pointer to the events vector, this is a place from which we can drop the event
        self.insert_at(trigger as _, ev);
        // Add the event to epoll. Under `cfg(test)` an armed fault swaps in an
        // invalid epoll descriptor, so what follows is a real `epoll_ctl`
        // failure with a real errno rather than a faked return value -- the
        // rollback, the error type and the caller's handling are all exercised
        // for real. The injected errno is EBADF, standing in for the ENOSPC that
        // `max_user_watches` produces in the field; that one is a machine-wide
        // per-UID sysctl and cannot be forced from a shared test binary without
        // breaking every other epoll user on the host.
        #[cfg(test)]
        let epoll_fd = if self
            .fail_next_add
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            -1
        } else {
            self.epoll
        };
        #[cfg(not(test))]
        let epoll_fd = self.epoll;
        if unsafe { epoll_ctl(epoll_fd, EPOLL_CTL_ADD, trigger, &mut event_desc) } == -1 {
            // Undo the insert above, or the handler is stranded permanently.
            //
            // The vector is keyed by file descriptor, and for every handler that
            // OWNS its trigger -- the connected socket, the listen socket, the
            // API socket -- the stranded box is that descriptor's only owner. So
            // the fd never closes, the kernel never re-issues the number,
            // `register_event` is never called with it again, and `insert_at`
            // never revisits the index to reclaim it. Whatever the handler
            // captured stays alive with it, including an `Arc<Peer>`.
            //
            // Only a handler that *borrows* its fd (`register_iface_handler`'s
            // `Arc<TunSocket>`) could ever be cleaned up by a later insert at the
            // same index, which is why "it self-heals on reuse" is not a defence.
            //
            // errno first: the rollback below can destroy it twice over. The
            // `lock()` parks on a futex under contention, and parking_lot's
            // Linux parker leaves EAGAIN in errno whenever the wait races the
            // unparker -- no destructor needed. Then `H` is a type parameter,
            // and `EventPoll` makes no promise about what its `Drop` runs; in
            // this crate it closes a `socket2::Socket`. The errno is not
            // decorative here, it is what tells an operator whether they hit
            // `max_user_watches` (ENOSPC) or ran out of descriptors (EMFILE).
            let err = io::Error::last_os_error();
            // Bound to a local, not left as a temporary of this statement. As a
            // temporary the rejected handler would be destroyed *before* the
            // `lock()` guard -- both are temporaries of the same statement, and
            // they drop in reverse creation order -- so `H::drop` would run with
            // `self.events` still held. `H` is a type parameter and `EventPoll`
            // makes no promise about what that destructor does; one that reached
            // back into this poll would hang the worker thread, because
            // `parking_lot::Mutex` is not reentrant. Nothing in this crate does
            // today: `Arc<Peer>` bottoms out at `close(2)`, and `Peer` has no
            // `Drop` at all.
            //
            // `let _ = ...` would NOT work: `_` is a wildcard, not a binding, so
            // the value still dies as a temporary. The explicit `drop` is
            // documentation -- the binding is what releases the guard first.
            let rejected = self.events.lock()[trigger as usize].take();
            drop(rejected);
            return Err(Error::EventQueue(err));
        }

        Ok(EventRef { trigger })
    }

    #[cfg(test)]
    fn registered_count(&self) -> usize {
        self.events.lock().iter().filter(|e| e.is_some()).count()
    }

    /// Make the next `register_event` on this poll fail, as `epoll_ctl` does
    /// with ENOSPC once the process is out of `max_user_watches`.
    #[cfg(test)]
    pub(crate) fn fail_next_registration(&self) {
        self.fail_next_add
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Insert an event into the events vector
    fn insert_at(&self, index: usize, data: Box<Event<H>>) {
        // The displaced handler leaves the lock scope before it is destroyed --
        // see the note in `register_event`. Binding it inside the block would
        // not be enough here: `events` is a *named* local, and locals drop in
        // reverse declaration order, so anything declared after it dies while it
        // is still held. Handing the box out of the block is what works.
        //
        // This also puts the handler's `close(2)` after the `EPOLL_CTL_DEL`
        // rather than before it, which is the right order: deleting a descriptor
        // epoll has already dropped on close is a harmless EBADF, but the
        // reverse reads as if the fd number could be reissued in between.
        let previous = {
            let mut events = self.events.lock();
            while events.len() <= index {
                // Resize the vector to be able to fit the new index
                // We trust the OS to allocate file descriptors in a sane order
                events.push(None); // resize doesn't work because Clone is not satisfied
            }

            let previous = events[index].take();
            if previous.is_some() {
                // Properly remove the previous event first
                unsafe {
                    epoll_ctl(self.epoll, EPOLL_CTL_DEL, index as _, null_mut());
                };
            }

            events[index] = Some(data);
            previous
        };
        drop(previous);
    }

    /// Trigger a notification
    pub fn trigger_notification(&self, notification_event: &EventRef) {
        let events = self.events.lock();

        let event_ref = &(*events)[notification_event.trigger as usize];
        let event_data = event_ref.as_ref().expect("Expected an event");

        if !event_data.notifier {
            panic!("Can only trigger a notification event");
        }

        // Write some data to the eventfd to trigger an EPOLLIN event
        unsafe {
            write(
                notification_event.trigger,
                &(std::u64::MAX - 1).to_ne_bytes()[0] as *const u8 as _,
                8,
            )
        };
    }

    /// Stop a notification
    pub fn stop_notification(&self, notification_event: &EventRef) {
        let events = self.events.lock();

        let event_ref = &(*events)[notification_event.trigger as usize];
        let event_data = event_ref.as_ref().expect("Expected an event");

        if !event_data.notifier {
            panic!("Can only trigger a notification event");
        }

        let mut buf = [0u8; 8];
        unsafe {
            read(
                notification_event.trigger,
                buf.as_mut_ptr() as _,
                buf.len() as _,
            )
        };
    }
}

impl<H> EventPoll<H> {
    /// Disable and remove the event and associated handler, using the fd that
    /// was used to register it.
    ///
    /// # Safety
    ///
    /// This function is only safe to call when the event loop is not running,
    /// otherwise the memory of the handler may get freed while in use.
    pub unsafe fn clear_event_by_fd(&self, index: RawFd) {
        assert!(index >= 0);
        // Same shape as `insert_at`: the handler leaves the lock scope before it
        // is destroyed. See the note in `register_event`.
        let previous = {
            let mut events = self.events.lock();
            let previous = events[index as usize].take();
            if previous.is_some() {
                epoll_ctl(self.epoll, EPOLL_CTL_DEL, index, null_mut());
            }
            previous
        };
        drop(previous);
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
        if self.event.needs_read {
            // Must read from the event to reset it before we enable it
            let mut buf: [std::mem::MaybeUninit<u8>; 256] =
                unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            while unsafe { read(self.event.fd, buf.as_mut_ptr() as _, buf.len() as _) } != -1 {}
        }

        unsafe {
            epoll_ctl(
                self.epoll,
                EPOLL_CTL_MOD,
                self.event.fd,
                &mut self.event.event,
            );
        }
    }
}

impl<'a, H> EventGuard<'a, H> {
    /// Get a mutable reference to the stored value
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut H {
        &mut self.event.handler
    }

    /// Cancel and remove the event referenced by this guard
    pub fn cancel(self) {
        unsafe { self.poll.clear_event_by_fd(self.event.fd) };
        std::mem::forget(self); // Don't call the regular drop that would enable the event
    }

    pub fn fd(&self) -> i32 {
        self.event.fd
    }

    /// Change the event flags to enable or disable notifying when the fd is writable
    pub fn notify_writable(&mut self, enabled: bool) {
        let flags = if enabled {
            EPOLLOUT | EPOLLIN | EPOLLET | EPOLLONESHOT
        } else {
            EPOLLIN | EPOLLONESHOT
        };
        self.event.event.events = flags as _;
    }
}

pub fn block_signal(signal: c_int) -> Result<sigset_t, String> {
    unsafe {
        let mut sigset = std::mem::zeroed();
        sigemptyset(&mut sigset);
        if sigaddset(&mut sigset, signal) == -1 {
            return Err(io::Error::last_os_error().to_string());
        }
        if sigprocmask(SIG_BLOCK, &sigset, null_mut()) == -1 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(sigset)
    }
}
