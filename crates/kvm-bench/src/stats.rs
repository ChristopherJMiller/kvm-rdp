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
