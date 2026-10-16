//! kvm-bench's pure half (spec §10.2; Plan E design decision 12): the
//! statistics, the `/metrics` parser, a scenario's report and its
//! thresholds, and the frame and input matchers. The binary does the IO.
pub mod frames;
pub mod prom;
pub mod report;
pub mod stats;
