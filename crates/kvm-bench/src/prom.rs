//! One `/metrics` scrape — §4.5's Prometheus text as the bridge renders it.
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scrape(pub BTreeMap<String, f64>);

impl Scrape {
    /// Every `series value` line; comments and unparsable lines skipped.
    #[must_use]
    pub fn parse(text: &str) -> Scrape {
        Scrape(
            text.lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| {
                    let (series, value) = l.rsplit_once(' ')?;
                    Some((series.to_owned(), value.trim().parse().ok()?))
                })
                .collect(),
        )
    }

    /// A series' value; 0 when absent — a family renders a label only once
    /// it is counted, and a counter starts at 0.
    #[must_use]
    pub fn get(&self, series: &str) -> f64 {
        self.0.get(series).copied().unwrap_or(0.0)
    }

    #[must_use]
    pub fn has(&self, series: &str) -> bool {
        self.0.contains_key(series)
    }

    #[must_use]
    pub fn delta(&self, earlier: &Scrape, series: &str) -> f64 {
        self.get(series) - earlier.get(series)
    }

    /// Of a histogram's observations between `earlier` and this scrape, the
    /// fraction at or under `le` (written as the bridge renders it, "0.005").
    #[must_use]
    pub fn fraction_le(&self, earlier: &Scrape, histogram: &str, le: &str) -> Option<f64> {
        let count = self.delta(earlier, &format!("{histogram}_count"));
        let under = self.delta(earlier, &format!("{histogram}_bucket{{le=\"{le}\"}}"));
        (count > 0.0).then(|| under / count)
    }

    /// A labelled counter's moves between `earlier` and now: label value → delta.
    #[must_use]
    pub fn family_delta(
        &self,
        earlier: &Scrape,
        family: &str,
        label: &str,
    ) -> BTreeMap<String, f64> {
        let prefix = format!("{family}{{{label}=\"");
        self.0
            .keys()
            .filter_map(|k| {
                let v = k.strip_prefix(&prefix)?.strip_suffix("\"}")?;
                let d = self.delta(earlier, k);
                (d != 0.0).then(|| (v.to_owned(), d))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "# HELP kvm_rdp_sessions_total s\n# TYPE kvm_rdp_sessions_total counter\n\
        kvm_rdp_sessions_total 1\nkvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 2\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 90\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"+Inf\"} 100\n\
        kvm_rdp_enqueue_latency_seconds_count 100\nkvm_rdp_egfx_in_flight 7\n";
    const TWO: &str = "kvm_rdp_sessions_total 1\nkvm_rdp_frames_dropped_total{reason=\"soft_gate\"} 5\n\
        kvm_rdp_frames_dropped_total{reason=\"paused\"} 1\n\
        kvm_rdp_enqueue_latency_seconds_bucket{le=\"0.005\"} 289\n\
        kvm_rdp_enqueue_latency_seconds_count 300\n";

    #[test]
    fn a_scrape_parses_its_series_and_skips_comments() {
        let s = Scrape::parse(ONE);
        assert_eq!(s.get("kvm_rdp_sessions_total"), 1.0);
        assert_eq!(s.get("kvm_rdp_egfx_in_flight"), 7.0);
        assert_eq!(s.get("kvm_rdp_absent_total"), 0.0);
        assert!(!s.has("kvm_rdp_absent_total"));
        assert_eq!(
            s.get("kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"),
            2.0
        );
    }

    #[test]
    fn deltas_fractions_and_families_are_between_two_scrapes() {
        let (a, b) = (Scrape::parse(ONE), Scrape::parse(TWO));
        assert_eq!(
            b.delta(&a, "kvm_rdp_frames_dropped_total{reason=\"soft_gate\"}"),
            3.0
        );
        let f = b
            .fraction_le(&a, "kvm_rdp_enqueue_latency_seconds", "0.005")
            .unwrap();
        assert!((f - 199.0 / 200.0).abs() < 1e-9);
        assert_eq!(
            a.fraction_le(&a, "kvm_rdp_enqueue_latency_seconds", "0.005"),
            None
        );
        let d = b.family_delta(&a, "kvm_rdp_frames_dropped_total", "reason");
        assert_eq!(d.get("soft_gate"), Some(&3.0));
        assert_eq!(d.get("paused"), Some(&1.0));
    }
}
