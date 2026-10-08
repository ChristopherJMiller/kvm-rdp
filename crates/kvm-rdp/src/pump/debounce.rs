//! §6.6 display suppression: IronRDP exposes it as a polled flag clients
//! pulse; only edges held for `suppress_debounce` count.
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    On,
    Off,
}

pub struct Debounce {
    hold: Duration,
    stable: bool,
    raw: bool,
    since: Option<Instant>,
}

impl Debounce {
    #[must_use]
    pub fn new(hold: Duration) -> Debounce {
        Debounce {
            hold,
            stable: false,
            raw: false,
            since: None,
        }
    }

    pub fn sample(&mut self, now: Instant, raw: bool) -> Option<Edge> {
        if raw != self.raw {
            self.raw = raw;
            self.since = Some(now);
        }
        if raw == self.stable {
            self.since = None;
            return None;
        }
        let since = *self.since.get_or_insert(now);
        if now.saturating_duration_since(since) >= self.hold {
            self.stable = raw;
            self.since = None;
            return Some(if raw { Edge::On } else { Edge::Off });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;

    /// §6.6: only edges held for `suppress_debounce` count.
    #[test]
    fn only_held_edges_count() {
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut d = Debounce::new(Duration::from_secs(1));
        assert_eq!(d.sample(at(0), true), None);
        assert_eq!(d.sample(at(500), false), None, "a short pulse");
        assert_eq!(d.sample(at(2000), false), None);
        assert_eq!(d.sample(at(2000), true), None);
        assert_eq!(d.sample(at(2999), true), None);
        assert_eq!(d.sample(at(3000), true), Some(Edge::On));
        assert_eq!(d.sample(at(3500), true), None);
        assert_eq!(d.sample(at(4000), false), None);
        assert_eq!(d.sample(at(5000), false), Some(Edge::Off));
    }
}
