//! Date arithmetic shared by every "days until expiry" readout.

use chrono::{DateTime, Utc};

/// Whole days from `now` until `when`, where any instant already in the past
/// is at least `-1`.
///
/// `TimeDelta::num_days` truncates toward zero, so a certificate or
/// registration that expired five hours ago read as `0` ("expires in 0
/// days!") and slipped past every `< 0` expired check. Plain flooring fixes
/// the sign but overstates the age ("expired 2 days ago" at 25 hours), so
/// whole elapsed days are kept and only the sub-day past case becomes `-1`.
pub(crate) fn days_until(when: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    let days = (when - now).num_days();
    if days == 0 && when < now {
        -1
    } else {
        days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_instants_are_negative_without_overstating_age() {
        let now: DateTime<Utc> = "2026-01-10T12:00:00Z".parse().unwrap();
        let h = chrono::Duration::hours;
        assert_eq!(days_until(now - chrono::Duration::seconds(1), now), -1);
        assert_eq!(days_until(now - h(5), now), -1);
        assert_eq!(days_until(now - h(24), now), -1);
        assert_eq!(days_until(now - h(25), now), -1);
        assert_eq!(days_until(now - h(49), now), -2);
        assert_eq!(days_until(now, now), 0);
        assert_eq!(days_until(now + h(5), now), 0);
        assert_eq!(days_until(now + h(24), now), 1);
        assert_eq!(days_until(now + h(71), now), 2);
    }
}
