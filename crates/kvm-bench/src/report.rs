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
