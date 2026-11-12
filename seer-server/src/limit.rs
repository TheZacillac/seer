//! Per-route, per-caller rate limiting.
//!
//! Each route has a cost class; the class's per-minute limit comes from
//! `seer_core::contract`, the numbers seer-api also uses. An anonymous
//! caller is counted per route and client address, a keyed caller per route
//! at a multiple of the limit. The algorithm is GCRA (the `governor`
//! crate): a full minute's allowance may be used in a burst, and it refills
//! evenly afterwards.
//!
//! Memory is bounded: idle entries are swept ([`Limits::sweep`]), IPv6
//! callers are counted by /64 ([`bucket`]), and past a cap of tracked
//! callers anonymous requests are refused rather than tracked.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use seer_core::contract::CostClass;

/// Most anonymous callers tracked per cost class before new ones are
/// refused. Entries idle for a minute are swept, so a real audience stays
/// far below this; only a flood of distinct addresses reaches it.
const MAX_TRACKED: usize = 100_000;

/// The wait reported when a request is refused without consulting a
/// bucket (the tracking cap, or a cost class with no limiter).
const REFUSED: Duration = Duration::from_secs(60);

/// Who a request is counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// An anonymous caller, by client address.
    Anonymous(IpAddr),
    /// The holder of the API key.
    Keyed,
}

/// The rate limiters: one per cost class and tier.
pub struct Limits {
    anonymous: HashMap<CostClass, DefaultKeyedRateLimiter<(&'static str, IpAddr)>>,
    keyed: HashMap<CostClass, DefaultKeyedRateLimiter<&'static str>>,
    clock: DefaultClock,
    cap: usize,
}

impl Limits {
    /// Limiters for every cost class. Keyed callers get `keyed_multiplier`
    /// times each class's limit.
    pub fn new(keyed_multiplier: u32) -> Self {
        Self::with_cap(keyed_multiplier, MAX_TRACKED)
    }

    /// [`new`](Self::new) with a chosen cap on tracked anonymous callers
    /// per cost class.
    pub(crate) fn with_cap(keyed_multiplier: u32, cap: usize) -> Self {
        let mut anonymous = HashMap::new();
        let mut keyed = HashMap::new();
        for class in CostClass::ALL {
            let limit = class.per_minute();
            anonymous.insert(class, RateLimiter::keyed(quota(limit)));
            keyed.insert(
                class,
                RateLimiter::keyed(quota(limit.saturating_mul(keyed_multiplier))),
            );
        }
        Self {
            anonymous,
            keyed,
            clock: DefaultClock::default(),
            cap,
        }
    }

    /// Counts one request to `route` (cost class `cost`) against `subject`.
    /// `Err` is how long until the limiter would admit another.
    pub fn check(
        &self,
        route: &'static str,
        cost: CostClass,
        subject: Subject,
    ) -> Result<(), Duration> {
        let verdict = match subject {
            Subject::Anonymous(ip) => {
                let Some(limiter) = self.anonymous.get(&cost) else {
                    return Err(REFUSED);
                };
                // Fail closed at the cap: refusing is bounded, tracking a
                // flood of distinct addresses is not.
                if limiter.len() >= self.cap {
                    limiter.retain_recent();
                    if limiter.len() >= self.cap {
                        return Err(REFUSED);
                    }
                }
                limiter.check_key(&(route, bucket(ip)))
            }
            Subject::Keyed => {
                let Some(limiter) = self.keyed.get(&cost) else {
                    return Err(REFUSED);
                };
                limiter.check_key(&route)
            }
        };
        verdict.map_err(|not_until| not_until.wait_time_from(self.clock.now()))
    }

    /// Forgets callers whose allowance has fully refilled. Call it
    /// periodically; `check` also does when the cap is reached.
    pub fn sweep(&self) {
        for limiter in self.anonymous.values() {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
        for limiter in self.keyed.values() {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }

    /// Anonymous callers currently tracked, over all cost classes.
    pub fn tracked(&self) -> usize {
        self.anonymous.values().map(|limiter| limiter.len()).sum()
    }
}

/// `per_minute` requests a minute, with a full minute's burst.
fn quota(per_minute: u32) -> Quota {
    Quota::per_minute(NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::MIN))
}

/// The address a caller is counted under. An IPv6 caller is counted by
/// /64: a single subscriber usually holds a whole /64, so counting each
/// address would let one caller mint as many buckets as they like. An
/// IPv4-mapped IPv6 address is the IPv4 caller it stands for.
pub fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// How many consecutive requests are admitted before the first refusal.
    fn admitted(limits: &Limits, route: &'static str, cost: CostClass, subject: Subject) -> u32 {
        let mut count = 0;
        while limits.check(route, cost, subject).is_ok() {
            count += 1;
            assert!(count < 100_000, "never refused");
        }
        count
    }

    #[test]
    fn an_anonymous_caller_gets_the_classes_limit_then_a_wait() {
        let limits = Limits::new(10);
        let caller = Subject::Anonymous(ip("203.0.113.7"));
        for class in CostClass::ALL {
            assert_eq!(admitted(&limits, "/a", class, caller), class.per_minute());
            let wait = limits.check("/a", class, caller).unwrap_err();
            assert!(
                wait > Duration::ZERO && wait <= Duration::from_secs(60),
                "{class:?}: {wait:?}"
            );
        }
    }

    #[test]
    fn a_keyed_caller_gets_the_multiple() {
        let limits = Limits::new(3);
        assert_eq!(
            admitted(&limits, "/a", CostClass::Heavy, Subject::Keyed),
            CostClass::Heavy.per_minute() * 3
        );
    }

    #[test]
    fn callers_and_routes_are_counted_separately() {
        let limits = Limits::new(10);
        let first = Subject::Anonymous(ip("203.0.113.7"));
        let second = Subject::Anonymous(ip("203.0.113.8"));
        let limit = CostClass::Heavy.per_minute();
        assert_eq!(admitted(&limits, "/a", CostClass::Heavy, first), limit);
        // Another address, another route and the keyed tier are untouched.
        assert_eq!(admitted(&limits, "/a", CostClass::Heavy, second), limit);
        assert_eq!(admitted(&limits, "/b", CostClass::Heavy, first), limit);
        assert!(limits.check("/a", CostClass::Heavy, Subject::Keyed).is_ok());
    }

    #[test]
    fn ipv6_callers_share_a_slash_64_bucket() {
        assert_eq!(
            bucket(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            ip("2001:db8:1:2::")
        );
        assert_eq!(bucket(ip("203.0.113.7")), ip("203.0.113.7"));
        // An IPv4-mapped address is the IPv4 caller it stands for.
        assert_eq!(bucket(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));

        let limits = Limits::new(10);
        let limit = CostClass::Heavy.per_minute();
        let one = Subject::Anonymous(ip("2001:db8:1:2::1"));
        let neighbour = Subject::Anonymous(ip("2001:db8:1:2:ffff::9"));
        let elsewhere = Subject::Anonymous(ip("2001:db8:1:3::1"));
        assert_eq!(admitted(&limits, "/a", CostClass::Heavy, one), limit);
        assert!(limits.check("/a", CostClass::Heavy, neighbour).is_err());
        assert!(limits.check("/a", CostClass::Heavy, elsewhere).is_ok());
    }

    #[test]
    fn tracking_is_capped_and_fails_closed() {
        let limits = Limits::with_cap(10, 50);
        for n in 0..50u32 {
            let caller = Subject::Anonymous(IpAddr::from(n.to_be_bytes()));
            assert!(limits.check("/a", CostClass::Light, caller).is_ok(), "{n}");
        }
        assert_eq!(limits.tracked(), 50);
        // At the cap a new caller is refused, not tracked.
        let newcomer = Subject::Anonymous(ip("203.0.113.200"));
        assert!(limits.check("/a", CostClass::Light, newcomer).is_err());
        assert_eq!(limits.tracked(), 50);
        // Keyed callers are not subject to the anonymous cap.
        assert!(limits.check("/a", CostClass::Light, Subject::Keyed).is_ok());
    }

    #[test]
    fn sweeping_keeps_callers_who_are_still_limited() {
        let limits = Limits::new(10);
        let caller = Subject::Anonymous(ip("203.0.113.7"));
        admitted(&limits, "/a", CostClass::Heavy, caller);
        limits.sweep();
        assert_eq!(limits.tracked(), 1);
        assert!(limits.check("/a", CostClass::Heavy, caller).is_err());
    }
}
