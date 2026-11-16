//! §10.2's shaped link as the client reads through it (pre-flight E62): a
//! link of `bps` bits per second. Each PDU holds the link for len·8/bps, so
//! an IDR serialises as on a real link, and a change of rate starts the
//! link afresh.
use std::time::{Duration, Instant};

/// How late a read may start after the link fell free and still be charged
/// from that instant. tokio's timer fires on whole milliseconds, and
/// IronRDP sends EGFX in 1600-byte channel chunks — at 20 Mbit/s a PDU
/// holds the link 0.65 ms, under one tick — so charging each PDU from its
/// own late wake read a "20 Mbit/s" link at 7 Mbit/s and a 5 Mbit/s one at
/// 3.4 (PE13). Past it, the link was idle and starts afresh: an idle link
/// banks at most this much credit (12.5 KB at 20 Mbit/s).
pub const WAKE_SLACK: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy)]
pub struct Link {
    bps: Option<u64>,
    free: Instant,
}

impl Link {
    /// Unshaped: every read is open.
    #[must_use]
    pub fn new(now: Instant) -> Link {
        Link {
            bps: None,
            free: now,
        }
    }

    /// A change of rate starts the link afresh; the same rate changes
    /// nothing.
    pub fn set_rate(&mut self, now: Instant, bps: Option<u64>) {
        if bps != self.bps {
            self.bps = bps;
            self.free = now;
        }
    }

    /// While a PDU still holds the link, when it falls free; `None` when
    /// the next read may go.
    #[must_use]
    pub fn busy_until(&self, now: Instant) -> Option<Instant> {
        (self.bps.is_some() && now < self.free).then_some(self.free)
    }

    /// A PDU of `len` bytes read at `now` holds the link for len·8/bps —
    /// from when the link fell free, if that was at most `WAKE_SLACK` ago
    /// (the PDU waited for it), else from `now` (the link was idle).
    pub fn read(&mut self, now: Instant, len: usize) {
        let Some(bps) = self.bps.filter(|b| *b > 0) else {
            return;
        };
        let start = if now.saturating_duration_since(self.free) <= WAKE_SLACK {
            self.free
        } else {
            now
        };
        self.free = start + Duration::from_secs_f64(len as f64 * 8.0 / bps as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IronRDP's channel chunks: a 1600-byte chunk in its PDU.
    const PDU: usize = 1615;

    /// Reads `n` PDUs back to back, each woken `late` after the link fell
    /// free (tokio's timer fires on whole milliseconds), from `t0`;
    /// returns when the last PDU's hold ends.
    fn saturate(link: &mut Link, t0: Instant, n: usize, late: Duration) -> Instant {
        let mut now = t0;
        for _ in 0..n {
            if let Some(free) = link.busy_until(now) {
                now = free + late;
            }
            link.read(now, PDU);
        }
        link.busy_until(now).unwrap_or(now)
    }

    /// PE13: at 1615-byte PDUs a 20 Mbit/s PDU holds the link 0.65 ms,
    /// under one tick of tokio's timer. Charged from each late wake, the
    /// link read at 7 Mbit/s, and at 5 Mbit/s at 3.4; a saturated link must
    /// read at its own rate, whatever the wake's lateness within a tick.
    #[test]
    fn a_saturated_link_reads_at_its_rate_whatever_the_wake() {
        for mbit in [20u64, 5] {
            let t0 = Instant::now();
            let mut link = Link::new(t0);
            link.set_rate(t0, Some(mbit * 1_000_000));
            let n = 10_000;
            let end = saturate(&mut link, t0, n, Duration::from_micros(1500));
            let secs = end.duration_since(t0).as_secs_f64();
            let rate = (n * PDU) as f64 * 8.0 / secs / 1e6;
            assert!(
                (rate - mbit as f64).abs() <= mbit as f64 * 0.01,
                "{mbit} Mbit/s read at {rate:.2}"
            );
        }
    }

    /// No credit beyond the wake's slack: a PDU after an idle second holds
    /// the link from its own arrival, and a change of rate starts afresh.
    #[test]
    fn an_idle_link_banks_no_credit() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let mut link = Link::new(t0);
        assert_eq!(link.busy_until(t0), None, "unshaped");
        link.read(t0, PDU);
        assert_eq!(link.busy_until(t0), None, "unshaped reads hold nothing");
        link.set_rate(t0, Some(8_000_000));
        link.read(t0, 1000); // 1 ms
        assert_eq!(link.busy_until(t0), Some(ms(1)));
        link.read(ms(1000), 1000);
        assert_eq!(link.busy_until(ms(1000)), Some(ms(1001)));
        // At the slack's edge a read is charged from the link's free
        // instant; just past it, from its own.
        link.read(ms(1001) + WAKE_SLACK, 1000);
        assert_eq!(link.busy_until(ms(1001)), Some(ms(1002)));
        let late = ms(1002) + WAKE_SLACK + Duration::from_micros(1);
        link.read(late, 1000);
        let held = late + Duration::from_millis(1);
        assert_eq!(link.busy_until(late), Some(held));
        link.set_rate(late, Some(8_000_000));
        assert_eq!(link.busy_until(late), Some(held), "the same rate");
        link.set_rate(late, Some(4_000_000));
        assert_eq!(link.busy_until(late), None, "a new rate starts afresh");
    }
}
