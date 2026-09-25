//! Precise sleeping for the client's timer thread and `bench` pacing
//! (SPEC §6.1): wait until a deadline or until another thread calls
//! [`Waiter::wake`]. On Windows this is a high-resolution waitable timer
//! (`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`) plus an event; elsewhere a
//! condition variable, whose timeouts are already precise on Linux.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub use imp::Waiter;

/// Most lead [`Waiter::wait_until`] applies.
const MAX_LEAD: Duration = Duration::from_millis(2);

impl Waiter {
    /// Sleeps until about `deadline`, or until woken; returns whether it
    /// was woken. Starts early by the timer's typical overshoot, learned
    /// from previous waits, so it is on time on average instead of always
    /// late (Windows high-resolution timers overshoot by ~0.5ms).
    pub fn wait_until(&self, deadline: Instant) -> bool {
        let now = Instant::now();
        let Some(left) = deadline.checked_duration_since(now) else {
            return self.wait(Duration::ZERO);
        };
        let lead = self.lead();
        let req = left.saturating_sub(lead);
        let woken = self.wait(req);
        if !woken && !req.is_zero() {
            let late = now.elapsed().saturating_sub(req).min(MAX_LEAD);
            let old = lead.as_nanos() as i64;
            let new = old + (late.as_nanos() as i64 - old) / 8;
            self.lead_ns().store(new.max(0) as u64, Ordering::Relaxed);
        }
        woken
    }

    /// Current overshoot estimate.
    pub fn lead(&self) -> Duration {
        Duration::from_nanos(self.lead_ns().load(Ordering::Relaxed))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateEventW, CreateWaitableTimerExW, INFINITE,
        SetEvent, SetWaitableTimer, TIMER_ALL_ACCESS, WaitForMultipleObjects, WaitForSingleObject,
    };

    pub struct Waiter {
        timer: HANDLE,
        event: HANDLE,
        high_res: bool,
        lead_ns: AtomicU64,
    }

    // SAFETY: kernel object handles may be used from any thread.
    unsafe impl Send for Waiter {}
    unsafe impl Sync for Waiter {}

    impl Waiter {
        pub fn new() -> io::Result<Self> {
            // SAFETY: plain object creation; null names and attributes.
            unsafe {
                let mut high_res = true;
                let mut timer = CreateWaitableTimerExW(
                    std::ptr::null(),
                    std::ptr::null(),
                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                    TIMER_ALL_ACCESS,
                );
                if timer.is_null() {
                    // Before Windows 10 1803.
                    high_res = false;
                    timer = CreateWaitableTimerExW(
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        TIMER_ALL_ACCESS,
                    );
                }
                if timer.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let event = CreateEventW(std::ptr::null(), 0, 0, std::ptr::null());
                if event.is_null() {
                    let e = io::Error::last_os_error();
                    CloseHandle(timer);
                    return Err(e);
                }
                Ok(Self {
                    timer,
                    event,
                    high_res,
                    lead_ns: AtomicU64::new(0),
                })
            }
        }

        pub fn is_high_resolution(&self) -> bool {
            self.high_res
        }

        pub(super) fn lead_ns(&self) -> &AtomicU64 {
            &self.lead_ns
        }

        /// Sleeps for `dur` or until woken; returns whether it was woken.
        pub fn wait(&self, dur: Duration) -> bool {
            // SAFETY: handles are valid for the lifetime of `self`.
            unsafe {
                if dur.is_zero() {
                    return WaitForSingleObject(self.event, 0) == WAIT_OBJECT_0;
                }
                // Negative = relative, in 100 ns units.
                let due = -((dur.as_nanos() / 100).clamp(1, i64::MAX as u128) as i64);
                if SetWaitableTimer(self.timer, &due, 0, None, std::ptr::null(), 0) == 0 {
                    std::thread::sleep(dur);
                    return false;
                }
                let handles = [self.event, self.timer];
                WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) == WAIT_OBJECT_0
            }
        }

        pub fn wake(&self) {
            // SAFETY: valid event handle.
            unsafe {
                SetEvent(self.event);
            }
        }
    }

    impl Drop for Waiter {
        fn drop(&mut self) {
            // SAFETY: handles owned by `self`, closed once.
            unsafe {
                CloseHandle(self.timer);
                CloseHandle(self.event);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::sync::{Condvar, Mutex};

    pub struct Waiter {
        woken: Mutex<bool>,
        cv: Condvar,
        lead_ns: AtomicU64,
    }

    impl Waiter {
        pub fn new() -> io::Result<Self> {
            Ok(Self {
                woken: Mutex::new(false),
                cv: Condvar::new(),
                lead_ns: AtomicU64::new(0),
            })
        }

        pub fn is_high_resolution(&self) -> bool {
            true
        }

        pub(super) fn lead_ns(&self) -> &AtomicU64 {
            &self.lead_ns
        }

        /// Sleeps for `dur` or until woken; returns whether it was woken.
        pub fn wait(&self, dur: Duration) -> bool {
            let mut woken = self.woken.lock().unwrap_or_else(|e| e.into_inner());
            if !*woken && !dur.is_zero() {
                woken = self
                    .cv
                    .wait_timeout(woken, dur)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            std::mem::replace(&mut *woken, false)
        }

        pub fn wake(&self) {
            *self.woken.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.cv.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn sleeps_about_the_requested_time() {
        let w = Waiter::new().unwrap();
        let t = Instant::now();
        assert!(!w.wait(Duration::from_millis(3)));
        let el = t.elapsed();
        assert!(el >= Duration::from_micros(2500), "{el:?}");
    }

    #[test]
    fn wake_interrupts_and_is_not_lost() {
        let w = Arc::new(Waiter::new().unwrap());
        // A wake before the wait makes the next wait return at once.
        w.wake();
        let t = Instant::now();
        assert!(w.wait(Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_secs(1));

        let w2 = Arc::clone(&w);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            w2.wake();
        });
        let t = Instant::now();
        assert!(w.wait(Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_secs(1));
        h.join().unwrap();
    }

    /// Overshoot of short sleeps; run with
    /// `cargo test -p skyblock-sys --release -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn overshoot() {
        let w = Waiter::new().unwrap();
        for target_us in [500u64, 1000, 2000, 5000] {
            let mut over: Vec<u64> = (0..200)
                .map(|_| {
                    let t = Instant::now();
                    w.wait(Duration::from_micros(target_us));
                    (t.elapsed().as_micros() as u64).saturating_sub(target_us)
                })
                .collect();
            over.sort_unstable();
            println!(
                "wait {target_us}us (high_res={}): overshoot p50 {}us p99 {}us max {}us",
                w.is_high_resolution(),
                over[100],
                over[198],
                over[199]
            );
        }
        for target_us in [1000u64, 2000] {
            let mut err: Vec<i64> = (0..400)
                .map(|_| {
                    let t = Instant::now();
                    w.wait_until(t + Duration::from_micros(target_us));
                    t.elapsed().as_micros() as i64 - target_us as i64
                })
                .skip(100)
                .collect();
            err.sort_unstable();
            println!(
                "wait_until {target_us}us: error p1 {}us p50 {}us p99 {}us (lead {:?})",
                err[3],
                err[150],
                err[297],
                w.lead()
            );
        }
    }
}
