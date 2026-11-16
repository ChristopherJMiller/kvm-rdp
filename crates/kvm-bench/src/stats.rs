//! Percentiles and the soak's slope (§10.1).
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
    let from = (minutes / 12.0).min(5.0);
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

#[cfg(test)]
mod tests {
    use super::*;

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
