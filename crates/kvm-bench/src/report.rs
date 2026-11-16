//! A scenario's report, and §10.2's thresholds: absolute (`strict`) on a
//! dedicated runner, 10× looser (`ci`) per PR.
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Thresholds {
    Strict,
    Ci,
}

impl Thresholds {
    /// §10.2: "CI runs the harness with loose thresholds that catch 10×
    /// regressions."
    #[must_use]
    pub fn factor(self) -> f64 {
        match self {
            Thresholds::Strict => 1.0,
            Thresholds::Ci => 10.0,
        }
    }

    /// DE10: a stalled-client timing bound loosens 1.5× under `ci`.
    #[must_use]
    pub fn timing_factor(self) -> f64 {
        match self {
            Thresholds::Strict => 1.0,
            Thresholds::Ci => 1.5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub value: f64,
    pub bound: String,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub scenario: String,
    pub thresholds: Thresholds,
    pub checks: Vec<Check>,
    pub numbers: BTreeMap<String, f64>,
    pub notes: Vec<String>,
    /// Named `(x, y)` series a failure is read from (the soak's RSS by
    /// minute, PE15 review I1). Absent from the JSON while empty, so a
    /// report without one is byte for byte what it always was.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub series: BTreeMap<String, Vec<(f64, f64)>>,
}

impl Report {
    #[must_use]
    pub fn new(scenario: &str, thresholds: Thresholds) -> Report {
        Report {
            scenario: scenario.to_owned(),
            thresholds,
            checks: Vec::new(),
            numbers: BTreeMap::new(),
            notes: Vec::new(),
            series: BTreeMap::new(),
        }
    }

    fn push(&mut self, name: &str, value: f64, bound: String, pass: bool) {
        self.checks.push(Check {
            name: name.to_owned(),
            value,
            bound,
            pass,
        });
    }

    /// A §10.1 performance bound, loosened by `factor`.
    pub fn perf_at_most(&mut self, name: &str, value: f64, bound: f64) {
        let b = bound * self.thresholds.factor();
        self.push(name, value, format!("<= {b}"), value <= b);
    }

    /// A stalled-client timing bound, loosened by `timing_factor` (DE10).
    pub fn timing_at_most(&mut self, name: &str, value: f64, bound: f64) {
        let b = bound * self.thresholds.timing_factor();
        self.push(name, value, format!("<= {b}"), value <= b);
    }

    /// Exact bounds no threshold loosens: delivery, bitrate, uniqueness, survival.
    pub fn at_most(&mut self, name: &str, value: f64, bound: f64) {
        self.push(name, value, format!("<= {bound}"), value <= bound);
    }

    /// A strict bound no threshold loosens: §10.1's soak, "slope < 2 MiB/h".
    pub fn under(&mut self, name: &str, value: f64, bound: f64) {
        self.push(name, value, format!("< {bound}"), value < bound);
    }

    pub fn at_least(&mut self, name: &str, value: f64, bound: f64) {
        self.push(name, value, format!(">= {bound}"), value >= bound);
    }

    pub fn within(&mut self, name: &str, value: f64, target: f64, fraction: f64) {
        let pass = (value - target).abs() <= target * fraction;
        self.push(
            name,
            value,
            format!("{target} ± {}%", fraction * 100.0),
            pass,
        );
    }

    pub fn holds(&mut self, name: &str, ok: bool) {
        self.push(name, if ok { 1.0 } else { 0.0 }, "true".to_owned(), ok);
    }

    pub fn series(&mut self, name: &str, points: Vec<(f64, f64)>) {
        self.series.insert(name.to_owned(), points);
    }

    pub fn number(&mut self, name: &str, value: f64) {
        self.numbers.insert(name.to_owned(), value);
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_loosens_performance_bounds_tenfold_and_timing_bounds_by_half() {
        let mut r = Report::new("t", Thresholds::Ci);
        r.perf_at_most("cpu percent", 40.0, 5.0);
        r.timing_at_most("ended within s", 20.0, 15.5);
        r.at_most("unmatched fraction", 0.5, 0.01);
        assert_eq!(
            r.checks.iter().map(|c| c.pass).collect::<Vec<_>>(),
            [true, true, false]
        );
        assert!(!r.passed());
        let mut s = Report::new("t", Thresholds::Strict);
        s.perf_at_most("cpu percent", 4.0, 5.0);
        s.within("bitrate", 8.4e6, 8e6, 0.10);
        s.at_least("fraction under 5 ms", 0.995, 0.99);
        s.holds("alive", true);
        s.number("p50 ms", 1.5);
        assert!(s.passed());
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains("\"thresholds\":\"strict\"") && json.contains("\"p50 ms\":1.5"),
            "{json}"
        );
    }

    /// A report's JSON, as every scenario wrote it before series existed:
    /// a report with none must stay byte for byte what it was (PE15 fix
    /// round 1).
    #[test]
    fn a_report_without_series_is_the_json_it_always_was() {
        let mut r = Report::new("t", Thresholds::Ci);
        r.at_most("x", 1.0, 2.0);
        r.number("n", 1.5);
        r.note("a");
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"scenario":"t","thresholds":"ci","checks":[{"name":"x","value":1.0,"bound":"<= 2","pass":true}],"numbers":{"n":1.5},"notes":["a"]}"#
        );
    }

    /// A series (the soak's RSS by minute, PE15 review I1) is in the JSON,
    /// as `[x, y]` pairs under `series`, once there is one — and the key is
    /// absent while there is none.
    #[test]
    fn a_series_is_in_the_json_only_when_there_is_one() {
        let mut r = Report::new("t", Thresholds::Strict);
        let empty = serde_json::to_string(&r).unwrap();
        assert!(!empty.contains("series"), "{empty}");
        r.series("VmRSS MiB by minute", vec![(0.0, 14.0), (0.25, 14.5)]);
        r.series("churn cycle starts (minute, cycle)", Vec::new());
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.ends_with(
                r#""notes":[],"series":{"VmRSS MiB by minute":[[0.0,14.0],[0.25,14.5]],"churn cycle starts (minute, cycle)":[]}}"#
            ),
            "{json}"
        );
    }

    /// §10.1's soak bounds are strict ("slope < 2 MiB/h"): `under` fails at
    /// its bound, where `at_most` passes.
    #[test]
    fn a_strict_bound_fails_at_its_value() {
        let mut r = Report::new("t", Thresholds::Strict);
        r.under("slope", 1.9999, 2.0);
        r.under("slope", 2.0, 2.0);
        r.under("slope", 2.0001, 2.0);
        assert_eq!(
            r.checks.iter().map(|c| c.pass).collect::<Vec<_>>(),
            [true, false, false]
        );
        assert_eq!(r.checks[0].bound, "< 2");
        // Thresholds never loosen it.
        let mut c = Report::new("t", Thresholds::Ci);
        c.under("slope", 2.5, 2.0);
        assert!(!c.passed());
    }

    /// PE12 review I2: the thresholds decide every verdict, so each bound
    /// is pinned at its value — a check passes there and fails just past
    /// it — under both thresholds: strict is §10.1's own numbers, ci's
    /// timing is 1.5× (DE10 forbids 10×) and its performance 10×.
    #[test]
    fn every_bound_passes_at_its_value_and_fails_past_it() {
        let verdicts = |r: &Report| r.checks.iter().map(|c| c.pass).collect::<Vec<_>>();
        let mut c = Report::new("t", Thresholds::Ci);
        c.timing_at_most("x", 23.25, 15.5);
        c.timing_at_most("x", 23.26, 15.5);
        c.perf_at_most("x", 50.0, 5.0);
        c.perf_at_most("x", 50.01, 5.0);
        assert_eq!(verdicts(&c), [true, false, true, false]);
        let mut s = Report::new("t", Thresholds::Strict);
        s.perf_at_most("x", 5.0, 5.0);
        s.perf_at_most("x", 5.0001, 5.0);
        s.timing_at_most("x", 15.5, 15.5);
        s.timing_at_most("x", 15.51, 15.5);
        s.at_most("x", 0.01, 0.01);
        s.at_most("x", 0.0101, 0.01);
        s.at_least("x", 0.99, 0.99);
        s.at_least("x", 0.9899, 0.99);
        s.within("x", 7.5, 10.0, 0.25);
        s.within("x", 12.5, 10.0, 0.25);
        s.within("x", 7.49, 10.0, 0.25);
        s.within("x", 12.51, 10.0, 0.25);
        assert_eq!(
            verdicts(&s),
            [
                true, false, true, false, true, false, true, false, true, true, false, false
            ]
        );
    }
}
