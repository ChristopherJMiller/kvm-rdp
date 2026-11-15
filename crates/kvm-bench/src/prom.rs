//! One `/metrics` scrape — §4.5's Prometheus text as the bridge renders it.
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scrape(pub BTreeMap<String, f64>);

impl Scrape {
    /// Every `series value [timestamp]` line; comments, blank lines and
    /// unparsable lines skipped.
    #[must_use]
    pub fn parse(text: &str) -> Scrape {
        Scrape(text.lines().filter_map(sample).collect())
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

/// One sample line of the text format (PE12 review m4): blanks around it
/// ignored, `#` first is a comment, then the series, its value and an
/// optional integer timestamp. A label value may hold blanks and braces;
/// the value and the timestamp hold neither, so a label set ends at the
/// line's last `}`.
fn sample(line: &str) -> Option<(String, f64)> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    let end = match line.find('{') {
        Some(_) => line.rfind('}')? + 1,
        None => line.find(char::is_whitespace)?,
    };
    let (series, rest) = line.split_at(end);
    let mut fields = rest.split_whitespace();
    let value = fields.next()?.parse().ok()?;
    match (fields.next(), fields.next()) {
        (None, _) => {}
        (Some(ts), None) if ts.parse::<i64>().is_ok() => {}
        _ => return None,
    }
    Some((series.to_owned(), value))
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

    /// PE12 review m4: the text format's other forms — a timestamp after
    /// the value, blanks around a line, an indented comment, a label value
    /// holding a blank or a brace — and nothing else: a comment whose last
    /// word is a number, a line with no value or too many fields.
    #[test]
    fn a_scrape_reads_every_form_of_a_sample_line() {
        let s = Scrape::parse(
            &[
                "h 3 1700000000",
                "trailing 4 ",
                "\t indented 5",
                "  # HELP kvm_rdp_x 6",
                "# HELP kvm_rdp_y 7",
                "#tight 8",
                "f{reason=\"a b\"} 2",
                "g{path=\"}\",le=\"+Inf\"} +Inf 1700000000",
                "no_value",
                "too many 1 2",
                "",
            ]
            .join("\n"),
        );
        let want: BTreeMap<String, f64> = [
            ("h", 3.0),
            ("trailing", 4.0),
            ("indented", 5.0),
            ("f{reason=\"a b\"}", 2.0),
            ("g{path=\"}\",le=\"+Inf\"}", f64::INFINITY),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        assert_eq!(s.0, want);
    }

    /// PE12 review m4: a family's labels that did not move are left out.
    #[test]
    fn a_family_delta_leaves_out_what_did_not_move() {
        let a = Scrape::parse("f{reason=\"x\"} 1\nf{reason=\"y\"} 4\n");
        let b = Scrape::parse("f{reason=\"x\"} 1\nf{reason=\"y\"} 6\n");
        let d = b.family_delta(&a, "f", "reason");
        assert_eq!(d.into_iter().collect::<Vec<_>>(), [("y".to_owned(), 2.0)]);
    }
}
