//! Nearest-rank percentile over a set of latency samples (§12 Leg A).

use std::time::Duration;

/// Nearest-rank percentile: the smallest sample with at least `p`% of
/// samples ≤ it. `None` for an empty slice or `p > 100`; panic-free and
/// checked throughout (no `as` casts, no indexing, no unchecked
/// arithmetic).
#[must_use]
pub fn percentile(samples: &[Duration], p: u32) -> Option<Duration> {
    if samples.is_empty() || p > 100 {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = u64::try_from(sorted.len()).ok()?;
    // rank = ceil(p/100 * n), at least 1.
    let rank = u64::from(p).checked_mul(n)?.div_ceil(100).max(1);
    let idx = usize::try_from(rank.checked_sub(1)?).ok()?;
    sorted.get(idx).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ms(v: &[u64]) -> Vec<Duration> {
        v.iter().map(|&x| Duration::from_millis(x)).collect()
    }

    #[test]
    fn nearest_rank_percentiles() {
        let s = ms(&[500, 100, 300, 200, 400]);
        assert_eq!(percentile(&s, 50), Some(Duration::from_millis(300)));
        assert_eq!(percentile(&s, 95), Some(Duration::from_millis(500)));
        assert_eq!(percentile(&s, 0), Some(Duration::from_millis(100)));
        assert_eq!(percentile(&s, 100), Some(Duration::from_millis(500)));
    }

    #[test]
    fn empty_or_out_of_range_is_none() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&ms(&[1]), 101), None);
    }
}
