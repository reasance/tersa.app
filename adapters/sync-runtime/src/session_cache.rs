// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One cached Gmail session per account, reused until shortly before its
//! access token expires.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use tersa_application::mailbox::AccountId;

/// The two clocks a cached token is checked against. The monotonic clock
/// stops while the machine sleeps, but Google expires tokens by wall-clock
/// time, so an entry is valid only while both say so.
pub(crate) trait CacheClock {
    fn monotonic(&self) -> Instant;
    fn wall(&self) -> SystemTime;
}

/// The system clocks.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemCacheClock;

impl CacheClock for SystemCacheClock {
    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Where a session came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Origin {
    /// Reused from the cache.
    Cached,
    /// Refreshed for this call, or by the refresh it waited for.
    Fresh,
}

struct Entry<T> {
    value: T,
    monotonic: Instant,
    wall: SystemTime,
}

/// One account's refresh turn. The mutex holds the error of the last refresh
/// when it failed, and `finished` counts completed refreshes, so a caller can
/// tell whether one ended while it waited.
struct Gate<E> {
    turn: tokio::sync::Mutex<Option<E>>,
    finished: AtomicU64,
}

impl<E> Default for Gate<E> {
    fn default() -> Self {
        Self {
            turn: tokio::sync::Mutex::new(None),
            finished: AtomicU64::new(0),
        }
    }
}

pub(crate) struct SessionCache<T, E, C> {
    clock: C,
    /// How long before its expiry a token is replaced.
    margin: Duration,
    entries: Mutex<HashMap<AccountId, Entry<T>>>,
    /// One refresh at a time per account, so concurrent misses share it.
    refreshing: Mutex<HashMap<AccountId, Arc<Gate<E>>>>,
}

impl<T: Clone, E: Clone, C: CacheClock> SessionCache<T, E, C> {
    pub(crate) fn new(clock: C, margin: Duration) -> Self {
        Self {
            clock,
            margin,
            entries: Mutex::new(HashMap::new()),
            refreshing: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, account: &AccountId) -> Option<T> {
        let entries = lock(&self.entries);
        let entry = entries.get(account)?;
        (self.clock.monotonic() < entry.monotonic && self.clock.wall() < entry.wall)
            .then(|| entry.value.clone())
    }

    /// The cached value, or a new one from `refresh`, which returns it with
    /// its token's lifetime. Concurrent misses for one account wait for a
    /// single refresh and share its result, failure included, so a token
    /// endpoint that cannot be reached is not asked once per caller. A failed
    /// refresh caches nothing; the next caller tries again.
    pub(crate) async fn get_or_refresh<F, Fut>(
        &self,
        account: &AccountId,
        refresh: F,
    ) -> Result<(T, Origin), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Duration), E>>,
    {
        if let Some(value) = self.get(account) {
            return Ok((value, Origin::Cached));
        }
        let gate = Arc::clone(lock(&self.refreshing).entry(account.clone()).or_default());
        let seen = gate.finished.load(Ordering::SeqCst);
        let mut turn = gate.turn.lock().await;
        let refreshed_meanwhile = gate.finished.load(Ordering::SeqCst) != seen;
        if let Some(value) = self.get(account) {
            // A token refreshed while this caller waited is as new as the
            // leader's: a rejection is not retried with yet another one.
            let origin = if refreshed_meanwhile {
                Origin::Fresh
            } else {
                Origin::Cached
            };
            return Ok((value, origin));
        }
        if refreshed_meanwhile && let Some(error) = turn.as_ref() {
            return Err(error.clone());
        }
        // The token's lifetime starts no earlier than this request.
        let monotonic = self.clock.monotonic();
        let wall = self.clock.wall();
        // A refresh dropped half-way counts as not finished: the next caller
        // in line runs its own.
        let refreshed = refresh().await;
        gate.finished.fetch_add(1, Ordering::SeqCst);
        let (value, lifetime) = match refreshed {
            Ok(refreshed) => {
                *turn = None;
                refreshed
            }
            Err(error) => {
                *turn = Some(error.clone());
                return Err(error);
            }
        };
        let lifetime = lifetime.saturating_sub(self.margin);
        lock(&self.entries).insert(
            account.clone(),
            Entry {
                value: value.clone(),
                monotonic: monotonic.checked_add(lifetime).unwrap_or(monotonic),
                wall: wall.checked_add(lifetime).unwrap_or(wall),
            },
        );
        Ok((value, Origin::Fresh))
    }

    /// Forgets the account's session if `rejected` says it is the one that
    /// failed. A newer session another caller refreshed in the meantime stays.
    pub(crate) fn forget_if(&self, account: &AccountId, rejected: impl Fn(&T) -> bool) {
        let mut entries = lock(&self.entries);
        if entries
            .get(account)
            .is_some_and(|entry| rejected(&entry.value))
        {
            entries.remove(account);
        }
    }

    /// Forgets the account's session, whichever it is.
    pub(crate) fn forget(&self, account: &AccountId) {
        lock(&self.entries).remove(account);
    }
}

/// The maps hold no invariant a panic could break; recover them.
fn lock<V>(mutex: &Mutex<V>) -> MutexGuard<'_, V> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    use tersa_application::mailbox::AccountId;

    use super::{CacheClock, Origin, SessionCache};

    const HOUR: Duration = Duration::from_secs(3600);
    const MARGIN: Duration = Duration::from_secs(60);

    /// Clocks that move only when a test says so.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<(Instant, SystemTime)>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new((Instant::now(), SystemTime::now()))))
        }

        fn advance(&self, monotonic: Duration, wall: Duration) {
            let mut now = self.0.lock().unwrap();
            now.0 += monotonic;
            now.1 += wall;
        }
    }

    impl CacheClock for TestClock {
        fn monotonic(&self) -> Instant {
            self.0.lock().unwrap().0
        }

        fn wall(&self) -> SystemTime {
            self.0.lock().unwrap().1
        }
    }

    fn account(name: &str) -> AccountId {
        AccountId::new(name).unwrap()
    }

    fn run<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Hands out 1, 2, 3, … with a one-hour token and counts the calls.
    fn issue(count: &Cell<u32>) -> impl Future<Output = Result<(u32, Duration), &'static str>> {
        count.set(count.get() + 1);
        std::future::ready(Ok((count.get(), HOUR)))
    }

    #[test]
    fn a_session_is_reused_until_the_margin_before_expiry() {
        let clock = TestClock::new();
        let cache = SessionCache::new(clock.clone(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Fresh))
            );
            let almost = HOUR - MARGIN - Duration::from_secs(1);
            clock.advance(almost, almost);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Cached))
            );
            clock.advance(Duration::from_secs(1), Duration::ZERO);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
            assert_eq!(
                cache
                    .get_or_refresh(&account("acct_b"), || issue(&count))
                    .await,
                Ok((3, Origin::Fresh)),
                "accounts never share a session"
            );
        });
    }

    #[test]
    fn a_wall_clock_jump_expires_the_session() {
        // The machine slept: wall time moved, monotonic time did not.
        let clock = TestClock::new();
        let cache = SessionCache::new(clock.clone(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            clock.advance(Duration::from_secs(5), 2 * HOUR);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
        });
    }

    #[test]
    fn a_forgotten_session_is_refreshed() {
        let cache = SessionCache::new(TestClock::new(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            cache.forget(&first);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Fresh))
            );
        });
    }

    #[test]
    fn a_failed_refresh_caches_nothing() {
        let cache = SessionCache::new(TestClock::new(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            assert_eq!(
                cache
                    .get_or_refresh(&first, || async { Err::<(u32, Duration), _>("offline") })
                    .await,
                Err("offline")
            );
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((1, Origin::Fresh))
            );
        });
    }

    #[test]
    fn only_the_rejected_session_is_forgotten() {
        let cache = SessionCache::new(TestClock::new(), MARGIN);
        let count = Cell::new(0);
        let first = account("acct_a");
        run(async {
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            // Another caller already replaced session 1 with session 2.
            cache.forget(&first);
            cache
                .get_or_refresh(&first, || issue(&count))
                .await
                .unwrap();
            cache.forget_if(&first, |cached| *cached == 1);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((2, Origin::Cached)),
                "a late rejection of session 1 keeps session 2"
            );
            cache.forget_if(&first, |cached| *cached == 2);
            assert_eq!(
                cache.get_or_refresh(&first, || issue(&count)).await,
                Ok((3, Origin::Fresh))
            );
        });
    }

    #[test]
    fn callers_waiting_on_a_failed_refresh_share_its_error() {
        let cache = Rc::new(SessionCache::new(TestClock::new(), MARGIN));
        let attempts = Rc::new(Cell::new(0));
        let results = run(tokio::task::LocalSet::new().run_until(async {
            let callers: Vec<_> = (0..3)
                .map(|_| {
                    let cache = Rc::clone(&cache);
                    let attempts = Rc::clone(&attempts);
                    tokio::task::spawn_local(async move {
                        cache
                            .get_or_refresh(&account("acct_a"), || async move {
                                attempts.set(attempts.get() + 1);
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                Err::<(u32, Duration), _>("offline")
                            })
                            .await
                    })
                })
                .collect();
            let mut results = Vec::new();
            for caller in callers {
                results.push(caller.await.unwrap());
            }
            results
        }));
        assert_eq!(attempts.get(), 1, "one refresh for all three callers");
        assert_eq!(results, [Err("offline"), Err("offline"), Err("offline")]);
        let count = Cell::new(0);
        assert_eq!(
            run(cache.get_or_refresh(&account("acct_a"), || issue(&count))),
            Ok((1, Origin::Fresh)),
            "a later caller tries again"
        );
    }

    #[test]
    fn a_dropped_refresh_lets_the_next_caller_try() {
        let cache = Rc::new(SessionCache::new(TestClock::new(), MARGIN));
        let count = Rc::new(Cell::new(0));
        let result = run(tokio::task::LocalSet::new().run_until(async {
            let leader = {
                let cache = Rc::clone(&cache);
                tokio::task::spawn_local(async move {
                    cache
                        .get_or_refresh(&account("acct_a"), || async {
                            std::future::pending::<Result<(u32, Duration), &str>>().await
                        })
                        .await
                })
            };
            let waiter = {
                let cache = Rc::clone(&cache);
                let count = Rc::clone(&count);
                tokio::task::spawn_local(async move {
                    cache
                        .get_or_refresh(&account("acct_a"), || issue(&count))
                        .await
                })
            };
            tokio::task::yield_now().await;
            leader.abort();
            waiter.await.unwrap()
        }));
        assert_eq!(result, Ok((1, Origin::Fresh)));
    }

    #[test]
    fn concurrent_misses_share_one_refresh() {
        let cache = Rc::new(SessionCache::new(TestClock::new(), MARGIN));
        let count = Rc::new(Cell::new(0));
        let results = run(tokio::task::LocalSet::new().run_until(async {
            let callers: Vec<_> = (0..3)
                .map(|_| {
                    let cache = Rc::clone(&cache);
                    let count = Rc::clone(&count);
                    tokio::task::spawn_local(async move {
                        cache
                            .get_or_refresh(&account("acct_a"), || async move {
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                issue(&count).await
                            })
                            .await
                    })
                })
                .collect();
            let mut results = Vec::new();
            for caller in callers {
                results.push(caller.await.unwrap());
            }
            results
        }));
        assert_eq!(count.get(), 1);
        assert_eq!(
            results,
            [
                Ok((1, Origin::Fresh)),
                Ok((1, Origin::Fresh)),
                Ok((1, Origin::Fresh))
            ],
            "waiters got the token just refreshed, not an old one"
        );
    }
}
