//! Percentiles, and the soak's numbers, schedule and verdict (§10.1).
use crate::report::Report;
use serde::Serialize;

/// The nearest-rank `p`th percentile (0 < p ≤ 100) of `xs`, in any order.
#[must_use]
pub fn percentile(xs: &[f64], p: f64) -> Option<f64> {
    if xs.is_empty() || !(p > 0.0 && p <= 100.0) {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    // p·n first: p/100 can round up past an exact rank (PE12 review m3).
    let rank = (p * v.len() as f64 / 100.0).ceil() as usize;
    v.get(rank.clamp(1, v.len()) - 1).copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    pub n: usize,
    pub p50: f64,
    pub p99: f64,
    pub max: f64,
}

#[must_use]
pub fn summarize(xs: &[f64]) -> Option<Summary> {
    Some(Summary {
        n: xs.len(),
        p50: percentile(xs, 50.0)?,
        p99: percentile(xs, 99.0)?,
        max: percentile(xs, 100.0)?,
    })
}

/// The least-squares slope of `(x, y)`; `None` without two distinct x.
#[must_use]
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let (sx, sy) = points
        .iter()
        .fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let (num, den) = points.iter().fold((0.0, 0.0), |(a, b), (x, y)| {
        (a + (x - mx) * (y - my), b + (x - mx) * (x - mx))
    });
    (den > 0.0).then(|| num / den)
}

/// §10.1's steady window for a run of `minutes`: from minute 5, or from
/// the run's twelfth when that is earlier (a short run keeps its last
/// 11/12). The one place this is computed: the window, and the warm-up
/// cycles before it, both read it.
#[must_use]
pub fn soak_window_from(minutes: f64) -> f64 {
    (minutes / 12.0).min(5.0)
}

/// The soak's churn schedule over a run of `minutes`, a cycle every
/// `every` minutes, as `(start minute, warm-up)` in time order (a warm-up
/// first at a tie). Two warm-up cycles come before the steady window, at
/// from/5 and 3·from/5 — minutes 1 and 3 of the hour — so the allocator's
/// warm-up to the churn's high-water mark (two cycles: one of each resize
/// order) lands before it (PE15 review m1). §10.1's own cycles are
/// unchanged: from `every` on, every `every`, while under the run (5, 10,
/// …, 55). With `every` ≤ 0 there are none but the warm-ups.
#[must_use]
pub fn churn_starts(minutes: f64, every: f64) -> Vec<(f64, bool)> {
    let from = soak_window_from(minutes);
    let mut starts = vec![(from / 5.0, true), (3.0 * from / 5.0, true)];
    if every > 0.0 {
        starts.extend(
            (1u32..)
                .map(|k| (f64::from(k) * every, false))
                .take_while(|(m, _)| *m < minutes),
        );
    }
    // Stable: a warm-up stays ahead of a window cycle at the same minute.
    starts.sort_by(|a, b| a.0.total_cmp(&b.0));
    starts
}

/// The run length from which the soak checks §10.1's bounds: the hour's
/// (PE15 review m4). A shorter run's window still holds the churn's
/// warm-up, which reads as slope.
pub const SOAK_CHECKED_FROM_MINUTES: f64 = 60.0;

/// §10.1's memory soak, read from its `VmRSS` samples.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SoakMemory {
    /// The steady window's first minute: §10.1's 5, or a run's twelfth when
    /// that is earlier (a short run keeps its last 11/12).
    pub from: f64,
    /// Samples in the steady window.
    pub n: usize,
    /// The window's least-squares RSS slope, MiB/h.
    pub per_hour: f64,
    /// The window's max − min, MiB.
    pub range: f64,
    /// The window's median RSS, MiB: what the memory limit is sized from.
    pub steady: f64,
    /// The largest sample, the start-up's included, MiB.
    pub peak: f64,
    /// The deployment design's memory limit (its §4.2): the steady RSS +
    /// `backlog_limit` (4 MiB) + 16 MiB (§10.1's stalled-client bound),
    /// + 50 %, MiB.
    pub limit: f64,
}

/// The soak's numbers from `(minutes, MiB)` samples over a run of
/// `minutes`; `None` with under two samples in the steady window.
#[must_use]
pub fn soak_memory(samples: &[(f64, f64)], minutes: f64) -> Option<SoakMemory> {
    const BACKLOG_LIMIT_MIB: f64 = 4.0;
    const STALLED_CLIENT_MIB: f64 = 16.0;
    let from = soak_window_from(minutes);
    let window: Vec<(f64, f64)> = samples
        .iter()
        .copied()
        .filter(|(m, _)| *m >= from)
        .collect();
    let mib: Vec<f64> = window.iter().map(|(_, y)| *y).collect();
    let per_hour = slope(&window)? * 60.0;
    let max = mib.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let min = mib.iter().copied().fold(f64::INFINITY, f64::min);
    let steady = percentile(&mib, 50.0)?;
    Some(SoakMemory {
        from,
        n: window.len(),
        per_hour,
        range: max - min,
        steady,
        peak: samples
            .iter()
            .map(|(_, y)| *y)
            .fold(f64::NEG_INFINITY, f64::max),
        limit: (steady + BACKLOG_LIMIT_MIB + STALLED_CLIENT_MIB) * 1.5,
    })
}

impl SoakMemory {
    /// Into `r`, for a run of `minutes`: §10.1's bounds — strict, "slope
    /// < 2 MiB/h and max − min < 16 MiB" (PE15 review m2) — checked over an
    /// hour or more, and below that reported as numbers with the short-soak
    /// note; and in every run, what sizes the memory limit.
    pub fn report(&self, r: &mut Report, minutes: f64) {
        const SLOPE: &str = "RSS slope, MiB/h (minutes 5 on)";
        const RANGE: &str = "RSS max − min, MiB (minutes 5 on)";
        r.number("steady window from minute", self.from);
        if minutes >= SOAK_CHECKED_FROM_MINUTES {
            r.under(SLOPE, self.per_hour, 2.0);
            r.under(RANGE, self.range, 16.0);
        } else {
            r.number(SLOPE, self.per_hour);
            r.number(RANGE, self.range);
            r.note(
                "short soak: slope and range are reported, not checked — §10.1's bounds are \
                 the hour's (under 60 minutes the window still reads the churn's warm-up)",
            );
        }
        r.number("steady RSS MiB", self.steady);
        r.number("peak RSS MiB", self.peak);
        r.number("memory limit MiB (RSS + 4 + 16, + 50 %)", self.limit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Report, Thresholds};

    #[test]
    fn percentiles_are_nearest_rank_in_any_order() {
        let xs: Vec<f64> = (1..=100).rev().map(f64::from).collect();
        assert_eq!(percentile(&xs, 50.0), Some(50.0));
        assert_eq!(percentile(&xs, 99.0), Some(99.0));
        assert_eq!(percentile(&xs, 100.0), Some(100.0));
        assert_eq!(percentile(&[7.0], 99.0), Some(7.0));
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&xs, 0.0), None);
        let s = summarize(&xs).unwrap();
        assert_eq!((s.n, s.p50, s.p99, s.max), (100, 50.0, 99.0, 100.0));
    }

    /// PE12 review m3: the rank is p·n/100 rounded up. Dividing p by 100
    /// first rounds some ranks just past an integer (0.07 · 100 is
    /// 7.000000000000001), so p7 of 1..=100 read 8.
    #[test]
    fn a_rank_is_exact_for_every_p() {
        let xs: Vec<f64> = (1..=100).map(f64::from).collect();
        for p in [7, 14, 28, 55, 56] {
            assert_eq!(percentile(&xs, f64::from(p)), Some(f64::from(p)), "p{p}");
        }
        assert_eq!(
            percentile(&[1.0, 2.0, 3.0], 50.0),
            Some(2.0),
            "rank 1.5 → 2"
        );
    }

    /// §10.1's soak: minutes 5 to the end of an hour; a short run's last
    /// 11/12. Samples before the window — the start-up's climb — move none
    /// of the slope, the range, the steady RSS or the limit.
    #[test]
    fn the_soak_reads_minutes_five_on_or_a_short_runs_last_eleven_twelfths() {
        // An hour: 0 → 100 MiB over minutes 0–5, then 100 MiB flat.
        let hour: Vec<(f64, f64)> = (0..=360)
            .map(|i| {
                let m = f64::from(i) / 6.0;
                (m, if m < 5.0 { 20.0 * m } else { 100.0 })
            })
            .collect();
        let s = soak_memory(&hour, 60.0).unwrap();
        assert_eq!(s.from, 5.0);
        assert_eq!(s.n, 331, "minutes 5 to 60, every 10 s, both ends");
        assert_eq!(
            (s.per_hour, s.range, s.steady, s.peak),
            (0.0, 0.0, 100.0, 100.0)
        );
        // The deployment design's limit (§4.2): RSS + backlog_limit + 16, + 50 %.
        assert_eq!(s.limit, (100.0 + 4.0 + 16.0) * 1.5);
        // Three minutes: from 0.25 (15 s), and a climb in the first 15 s
        // is outside it.
        let short: Vec<(f64, f64)> = (0..=18)
            .map(|i| {
                let m = f64::from(i) / 6.0;
                (m, if m < 0.25 { 50.0 } else { 80.0 })
            })
            .collect();
        let s = soak_memory(&short, 3.0).unwrap();
        assert_eq!((s.from, s.n, s.range, s.steady), (0.25, 17, 0.0, 80.0));
    }

    /// The slope is per hour, the range is max − min, the steady RSS is
    /// the window's median, and the peak is any sample's (the start-up's
    /// too).
    #[test]
    fn the_soak_slope_is_mib_per_hour_and_the_steady_rss_its_median() {
        // 1 MiB over minutes 5–35: 2 MiB/h, §10.1's bound exactly.
        let mut pts: Vec<(f64, f64)> = (30..=210)
            .map(|i| {
                let m = f64::from(i) / 6.0;
                (m, 200.0 + (m - 5.0) / 30.0)
            })
            .collect();
        pts.insert(0, (0.0, 300.0));
        let s = soak_memory(&pts, 60.0).unwrap();
        assert!((s.per_hour - 2.0).abs() < 1e-9, "{}", s.per_hour);
        assert!((s.range - 1.0).abs() < 1e-9, "{}", s.range);
        assert!((s.steady - 200.5).abs() < 1e-9, "{}", s.steady);
        assert_eq!(s.peak, 300.0);
        assert!((s.limit - (200.5 + 20.0) * 1.5).abs() < 1e-9);
        // Under two samples in the window: nothing to read.
        assert_eq!(soak_memory(&[(0.0, 1.0), (6.0, 2.0)], 60.0), None);
        assert_eq!(soak_memory(&[], 3.0), None);
    }

    fn close(a: &[(f64, bool)], b: &[(f64, bool)]) -> bool {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|((x, p), (y, q))| (x - y).abs() < 1e-9 && p == q)
    }

    /// PE15 review m1: two warm-up churn cycles before the steady window,
    /// at from/5 and 3·from/5 — minutes 1 and 3 of the hour — then §10.1's
    /// cycles, unchanged: every `every` from `every` on, while under the
    /// run (5, 10, …, 55). `(start minute, warm-up)`, in order.
    #[test]
    fn two_warm_up_cycles_come_before_the_window_and_the_hours_cycles_are_unchanged() {
        assert_eq!(soak_window_from(60.0), 5.0);
        assert_eq!(soak_window_from(120.0), 5.0);
        assert_eq!(soak_window_from(3.0), 0.25);
        let mut hour = vec![(1.0, true), (3.0, true)];
        hour.extend((1..=11).map(|k| (5.0 * f64::from(k), false)));
        assert!(
            close(&churn_starts(60.0, 5.0), &hour),
            "{:?}",
            churn_starts(60.0, 5.0)
        );
        // Ten minutes, every two: the window starts at 10/12.
        let from = 10.0 / 12.0;
        let ten = [
            (from / 5.0, true),
            (3.0 * from / 5.0, true),
            (2.0, false),
            (4.0, false),
            (6.0, false),
            (8.0, false),
        ];
        assert!(
            close(&churn_starts(10.0, 2.0), &ten),
            "{:?}",
            churn_starts(10.0, 2.0)
        );
        // A churn as fast as the warm-ups: in time order, a warm-up first.
        let fast = churn_starts(60.0, 1.0);
        assert!(close(
            &fast[..5],
            &[
                (1.0, true),
                (1.0, false),
                (2.0, false),
                (3.0, true),
                (3.0, false)
            ]
        ));
        assert_eq!(fast.len(), 2 + 59);
        // No churn period: the warm-ups only, never an endless schedule.
        assert!(close(&churn_starts(60.0, 0.0), &[(1.0, true), (3.0, true)]));
    }

    fn memory(per_hour: f64, range: f64) -> SoakMemory {
        SoakMemory {
            from: 5.0,
            n: 331,
            per_hour,
            range,
            steady: 16.0,
            peak: 16.5,
            limit: (16.0 + 20.0) * 1.5,
        }
    }

    /// PE15 review m2 and m4: §10.1's bounds are strict (`<`) and the
    /// hour's — a run of 60 minutes or more checks them; any shorter run
    /// reports them as numbers with the short-soak note.
    #[test]
    fn the_soak_checks_its_strict_bounds_at_the_hour_only() {
        let verdicts = |r: &Report| r.checks.iter().map(|c| c.pass).collect::<Vec<_>>();
        let mut r = Report::new("soak", Thresholds::Strict);
        memory(1.999, 15.99).report(&mut r, 60.0);
        assert_eq!(verdicts(&r), [true, true]);
        assert!(r.notes.is_empty(), "{:?}", r.notes);
        let mut r = Report::new("soak", Thresholds::Ci);
        memory(2.0, 16.0).report(&mut r, 90.0);
        assert_eq!(verdicts(&r), [false, false], "at the bound fails");
        assert_eq!(
            r.checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            [
                "RSS slope, MiB/h (minutes 5 on)",
                "RSS max − min, MiB (minutes 5 on)"
            ]
        );
        for short in [59.99, 30.0, 3.0] {
            let mut r = Report::new("soak", Thresholds::Strict);
            memory(70.0, 2.5).report(&mut r, short);
            assert!(r.checks.is_empty(), "{short} min: {:?}", r.checks);
            assert_eq!(r.numbers["RSS slope, MiB/h (minutes 5 on)"], 70.0);
            assert_eq!(r.numbers["RSS max − min, MiB (minutes 5 on)"], 2.5);
            assert!(
                r.notes.iter().any(|n| n.starts_with("short soak")),
                "{:?}",
                r.notes
            );
        }
        // Every run carries what sizes the memory limit.
        let mut r = Report::new("soak", Thresholds::Strict);
        memory(0.5, 1.0).report(&mut r, 60.0);
        for k in [
            "steady window from minute",
            "steady RSS MiB",
            "peak RSS MiB",
            "memory limit MiB (RSS + 4 + 16, + 50 %)",
        ] {
            assert!(r.numbers.contains_key(k), "{k}");
        }
    }

    #[test]
    fn the_slope_of_a_line_is_its_gradient() {
        let pts: Vec<(f64, f64)> = (0..10)
            .map(|i| (f64::from(i), 2.0 * f64::from(i) + 1.0))
            .collect();
        assert!((slope(&pts).unwrap() - 2.0).abs() < 1e-9);
        assert_eq!(slope(&[(1.0, 1.0)]), None);
        assert_eq!(slope(&[(1.0, 1.0), (1.0, 2.0)]), None, "no spread in x");
    }
}
