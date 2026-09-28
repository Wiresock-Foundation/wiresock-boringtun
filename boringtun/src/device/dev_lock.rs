// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use std::ops::Deref;

/// A special type of read/write lock, that makes the following assumptions:
/// a) Read access is frequent, and has to be very fast, so we want to hold it indefinitely
/// b) Write access is very rare (think less than once per second) and can be a bit slower
/// c) A thread that holds a read lock, can ask for an upgrade to a write lock, cooperatively asking other threads to yield their locks
pub struct Lock<T: ?Sized> {
    wants_write: (Mutex<bool>, Condvar),
    inner: RwLock<T>, // Although parking lot lock is upgradable, it does not allow a two staged mark + lock upgrade
}

impl<T> Lock<T> {
    /// New lock
    pub fn new(user_data: T) -> Lock<T> {
        Lock {
            wants_write: (Mutex::new(false), Condvar::new()),
            inner: RwLock::new(user_data),
        }
    }
}

impl<T: ?Sized> Lock<T> {
    /// Acquire a read lock
    pub fn read(&self) -> LockReadGuard<T> {
        let (ref lock, ref cvar) = &self.wants_write;
        let mut wants_write = lock.lock();
        while *wants_write {
            // We have a writer and we want to wait for it to go away
            cvar.wait(&mut wants_write);
        }

        LockReadGuard {
            wants_write: &self.wants_write,
            inner: self.inner.read(),
        }
    }
}

pub struct LockReadGuard<'a, T: 'a + ?Sized> {
    wants_write: &'a (Mutex<bool>, Condvar),
    inner: RwLockReadGuard<'a, T>,
}

impl<'a, T: ?Sized> LockReadGuard<'a, T> {
    /// Perform a closure on a mutable reference of the inner locked value.
    ///
    /// # Parameters
    ///
    /// `prep_func` - A closure that will run once, after the lock marks its intention to write,
    /// this can be used to tell other threads to yield their read locks temporarily. It will be passed
    /// an immutable reference to the inner value.
    ///
    /// `mut_func` - A closure that will run once write access is gained. It iwll be passed a mutable reference
    /// to the inner value.
    ///
    /// # Panics
    ///
    /// A panic in either closure propagates to the caller unchanged, and the
    /// lock stays usable: the write lock is released, this guard's read lock
    /// is re-acquired, and the write intent is lowered with every waiter
    /// woken, so later readers and writers proceed. What the closure had
    /// already done to the value stays done -- recovering the lock is not
    /// rolling the data back.
    pub fn try_writeable<U, P: FnOnce(&T), F: FnOnce(&mut T) -> U>(
        &mut self,
        prep_func: P,
        mut_func: F,
    ) -> Option<U> {
        // First tell everyone that we want to write now, this will prevent any new reader from starting until we are done.
        let intent = {
            let state = self.wants_write;
            let (lock, cvar) = state;
            let mut wants_write = lock.lock();

            RwLockReadGuard::unlocked(&mut self.inner, move || {
                while *wants_write {
                    // We have a writer and we want to wait for it to go away
                    cvar.wait(&mut wants_write);
                }

                *wants_write = true;
                // Owned from the moment it is raised: nothing that can
                // unwind lies between the store above and this.
                WriteIntent { state }
            })
        };

        // Second stage is to run the prep function
        prep_func(&*self.inner);

        let lock = RwLockReadGuard::rwlock(&self.inner);

        // Third stage is to perform our op under a write lock
        let ret = Some(RwLockReadGuard::unlocked(&mut self.inner, move || {
            // There is no race here because wants_write blocks other threads
            let mut write_access = lock.write();
            mut_func(&mut *write_access)
        }));

        // Finally signal other threads -- only now, with the write lock
        // released and this guard's read lock back.
        drop(intent);

        ret
    }
}

/// The write intent one `try_writeable` call has raised. Dropping it lowers
/// the intent and wakes every thread waiting on it, so it is lowered exactly
/// once however the call ends: on return, or when a closure panics.
///
/// Without this, a panic in `prep_func` or `mut_func` unwound past the
/// lowering and left `wants_write` set for good: every later `Lock::read` and
/// `try_writeable` waited for a writer that no longer existed, freezing the
/// device -- one worker's panic became a hang of all of them.
struct WriteIntent<'a> {
    state: &'a (Mutex<bool>, Condvar),
}

impl Drop for WriteIntent<'_> {
    fn drop(&mut self) {
        // parking_lot locks are never poisoned, so this cannot panic even
        // while unwinding.
        let (lock, cvar) = self.state;
        let mut wants_write = lock.lock();
        *wants_write = false;
        cvar.notify_all();
    }
}

impl<'a, T: ?Sized> Deref for LockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    /// A fail-safe, not a synchronisation: everything here finishes in
    /// milliseconds, and this only bounds how long a frozen lock takes to be
    /// reported as a failure instead of hanging the run.
    const HANG: Duration = Duration::from_secs(10);

    fn intent_raised<T>(lock: &Lock<T>) -> bool {
        *lock.wants_write.0.lock()
    }

    /// How many threads are parked on the intent's condvar, waiting for a
    /// writer to finish. Counted without waking any (a filter that skips every
    /// thread): waking one to count it would itself be the wake-up under test.
    /// parking_lot's condvar parks on its own address, and has no spurious
    /// wake-ups, so a thread counted here stays parked until notified.
    fn parked_on_intent<T>(lock: &Lock<T>) -> usize {
        let key = &lock.wants_write.1 as *const Condvar as usize;
        let mut parked = 0;
        // SAFETY: the key is this test's own condvar, and neither closure
        // unparks anything or calls into parking_lot.
        unsafe {
            parking_lot_core::unpark_filter(
                key,
                |_| {
                    parked += 1;
                    parking_lot_core::FilterOp::Skip
                },
                |_| parking_lot_core::DEFAULT_UNPARK_TOKEN,
            );
        }
        parked
    }

    fn wait_until_parked<T>(lock: &Lock<T>, n: usize) {
        let deadline = Instant::now() + HANG;
        while parked_on_intent(lock) < n {
            assert!(Instant::now() < deadline, "no thread parked on the intent");
            thread::yield_now();
        }
    }

    /// Run `f` on a thread of its own and return what it returns -- failing,
    /// not hanging, if it is still blocked after `HANG`.
    fn within<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(HANG) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                panic!("{} is still blocked: the lock is frozen", what)
            }
            Err(RecvTimeoutError::Disconnected) => panic!("{} panicked", what),
        }
    }

    fn message(payload: &(dyn std::any::Any + Send)) -> &str {
        payload
            .downcast_ref::<&str>()
            .copied()
            .unwrap_or("<not a &str>")
    }

    /// A later reader and a later writer, each on a thread of its own, both
    /// get through; returns what the writer saw before incrementing.
    fn still_usable(lock: &Arc<Lock<u32>>) -> u32 {
        let l = Arc::clone(lock);
        let read = within("a later Lock::read", move || *l.read());
        let l = Arc::clone(lock);
        let wrote = within("a later try_writeable", move || {
            l.read().try_writeable(
                |_| {},
                |v| {
                    *v += 1;
                    *v - 1
                },
            )
        });
        assert_eq!(wrote, Some(read));
        read
    }

    // `catch_unwind` needs `AssertUnwindSafe` below because the closure
    // borrows the read guard mutably. That is the point, not an oversight:
    // these tests look at the lock after a closure has unwound through it.

    #[test]
    fn a_panic_in_prep_func_propagates_and_releases_the_intent() {
        let lock = Arc::new(Lock::new(1u32));
        let mut guard = lock.read();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            guard.try_writeable(|_| panic!("in prep_func"), |v| *v += 1)
        }))
        .unwrap_err();

        assert_eq!(
            message(&*panic),
            "in prep_func",
            "the panic propagates as is"
        );
        assert!(!intent_raised(&lock), "the intent is lowered");
        assert_eq!(
            *guard, 1,
            "mut_func never ran; the caller's guard still reads"
        );
        drop(guard);
        assert_eq!(still_usable(&lock), 1);
        assert_eq!(*lock.read(), 2);
    }

    #[test]
    fn a_panic_in_mut_func_propagates_and_releases_the_write_lock_and_intent() {
        let lock = Arc::new(Lock::new(1u32));
        let mut guard = lock.read();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            guard.try_writeable(
                |_| {},
                |v| {
                    *v = 7;
                    panic!("in mut_func")
                },
            )
        }))
        .unwrap_err();

        assert_eq!(
            message(&*panic),
            "in mut_func",
            "the panic propagates as is"
        );
        assert!(!intent_raised(&lock), "the intent is lowered");
        // `RwLockReadGuard::unlocked` re-acquires the read lock on unwind too.
        assert!(lock.inner.is_locked() && !lock.inner.is_locked_exclusive());
        assert_eq!(*guard, 7, "the guard reads again; the partial write stays");
        drop(guard);
        assert!(!lock.inner.is_locked());
        assert_eq!(still_usable(&lock), 7);
        assert_eq!(*lock.read(), 8);
    }

    /// B holds its read lock before A raises its intent, then asks to write
    /// itself and parks until A is done. A panics instead of finishing: B must
    /// still be woken, get the intent and write.
    #[test]
    fn a_writer_parked_on_an_intent_that_unwinds_is_woken() {
        let lock = Arc::new(Lock::new(0u32));
        let both_reading = Arc::new(Barrier::new(2));
        let (raised_tx, raised_rx) = mpsc::channel();
        let (panic_tx, panic_rx) = mpsc::channel::<()>();

        let a = {
            let (lock, both_reading) = (Arc::clone(&lock), Arc::clone(&both_reading));
            thread::spawn(move || {
                let mut guard = lock.read();
                both_reading.wait();
                guard.try_writeable(
                    |_| {
                        raised_tx.send(()).unwrap();
                        panic_rx.recv().unwrap();
                        panic!("in A's prep_func")
                    },
                    |_| unreachable!("A never gets past prep_func"),
                );
            })
        };
        let (done_tx, done_rx) = mpsc::channel();
        let b = {
            let lock = Arc::clone(&lock);
            thread::spawn(move || {
                let mut guard = lock.read();
                both_reading.wait();
                raised_rx.recv().unwrap();
                let wrote = guard.try_writeable(
                    |_| {},
                    |v| {
                        *v += 1;
                        *v
                    },
                );
                done_tx.send(wrote).unwrap();
            })
        };

        wait_until_parked(&lock, 1); // B, on A's intent
        panic_tx.send(()).unwrap();

        let wrote = done_rx
            .recv_timeout(HANG)
            .expect("B is still parked on the intent A's panic left behind");
        assert_eq!(wrote, Some(1));
        assert_eq!(message(&*a.join().unwrap_err()), "in A's prep_func");
        b.join().unwrap();
        assert!(!intent_raised(&lock));
        assert_eq!(*lock.read(), 1);
    }

    /// C calls `Lock::read` while A's intent is raised, and parks. A panics:
    /// C must still be woken and get its read lock.
    #[test]
    fn a_reader_parked_on_an_intent_that_unwinds_is_woken() {
        let lock = Arc::new(Lock::new(5u32));
        let (raised_tx, raised_rx) = mpsc::channel();
        let (panic_tx, panic_rx) = mpsc::channel::<()>();

        let a = {
            let lock = Arc::clone(&lock);
            thread::spawn(move || {
                let mut guard = lock.read();
                guard.try_writeable(
                    |_| {
                        raised_tx.send(()).unwrap();
                        panic_rx.recv().unwrap();
                        panic!("in A's prep_func")
                    },
                    |_| unreachable!("A never gets past prep_func"),
                );
            })
        };
        raised_rx.recv().unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        let c = {
            let lock = Arc::clone(&lock);
            thread::spawn(move || done_tx.send(*lock.read()).unwrap())
        };

        wait_until_parked(&lock, 1); // C, on A's intent
        panic_tx.send(()).unwrap();

        let read = done_rx
            .recv_timeout(HANG)
            .expect("C is still parked on the intent A's panic left behind");
        assert_eq!(read, 5);
        assert_eq!(message(&*a.join().unwrap_err()), "in A's prep_func");
        c.join().unwrap();
        assert!(!intent_raised(&lock));
    }

    /// Readers, writers, and writers that unwind out of either closure, all at
    /// once. Every writer checks it holds the only intent. `resume_unwind`
    /// unwinds exactly like a panic but skips the panic hook, so thousands of
    /// them do not flood the test output.
    #[test]
    fn readers_and_writers_survive_writers_that_unwind() {
        const THREADS: usize = 6;
        const ITERATIONS: usize = 1000;
        let lock = Arc::new(Lock::new(0u64));
        let [unwound, completed, reads, without_intent] =
            [(); 4].map(|_| Arc::new(AtomicUsize::new(0)));

        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let (lock, unwound, completed, reads, without_intent) = (
                    Arc::clone(&lock),
                    Arc::clone(&unwound),
                    Arc::clone(&completed),
                    Arc::clone(&reads),
                    Arc::clone(&without_intent),
                );
                thread::spawn(move || {
                    for i in 0..ITERATIONS {
                        let mut guard = lock.read();
                        let _ = *guard;
                        reads.fetch_add(1, Ordering::Relaxed);
                        // Counted, not asserted: an assertion here would be
                        // caught along with the unwinds below.
                        let exclusive = |v: &mut u64| {
                            if !intent_raised(&lock) {
                                without_intent.fetch_add(1, Ordering::Relaxed);
                            }
                            *v += 1;
                        };
                        match (t + i) % 4 {
                            0 => {}
                            1 => {
                                guard.try_writeable(|_| {}, exclusive);
                                completed.fetch_add(1, Ordering::Relaxed);
                            }
                            2 => {
                                let r = catch_unwind(AssertUnwindSafe(|| {
                                    guard.try_writeable(|_| resume_unwind(Box::new(())), exclusive)
                                }));
                                assert!(r.is_err());
                                unwound.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                let r = catch_unwind(AssertUnwindSafe(|| {
                                    guard.try_writeable(
                                        |_| {},
                                        |v| {
                                            exclusive(v);
                                            resume_unwind(Box::new(()))
                                        },
                                    )
                                }));
                                assert!(r.is_err());
                                unwound.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                })
            })
            .collect();

        let deadline = Instant::now() + HANG * 6;
        for t in threads {
            while !t.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "the lock froze under unwinding writers"
                );
                thread::yield_now();
            }
            t.join().unwrap();
        }

        let (unwound, completed) = (
            unwound.load(Ordering::Relaxed),
            completed.load(Ordering::Relaxed),
        );
        // Every completed write, and every write that unwound after its
        // increment (half of the unwinding ones), counted once.
        let mut_unwinds = (0..THREADS)
            .map(|t| (0..ITERATIONS).filter(|i| (t + i) % 4 == 3).count())
            .sum::<usize>();
        assert_eq!(*lock.read(), (completed + mut_unwinds) as u64);
        assert_eq!(
            without_intent.load(Ordering::Relaxed),
            0,
            "a writer without the intent"
        );
        assert!(!intent_raised(&lock));
        eprintln!(
            "stress: {} threads x {} iterations: {} reads, {} writes completed, {} unwound ({} in prep_func, {} in mut_func), 0 hangs",
            THREADS,
            ITERATIONS,
            reads.load(Ordering::Relaxed),
            completed,
            unwound,
            unwound - mut_unwinds,
            mut_unwinds
        );
    }
}
