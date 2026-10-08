//! Plan C's input handler is a counting stub (DC7): every event is counted
//! and dropped, never logged (§4.5: no keystrokes). Plan D replaces it with
//! §7's scancode/US-layout mapping and mouse scaling.
use crate::metrics::Metrics;
use ironrdp_server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
use std::sync::Arc;

pub struct InputStub {
    metrics: Arc<Metrics>,
}

impl InputStub {
    #[must_use]
    pub fn new(metrics: Arc<Metrics>) -> InputStub {
        InputStub { metrics }
    }
}

impl RdpServerInputHandler for InputStub {
    fn keyboard(&mut self, _event: KeyboardEvent) {
        self.metrics.input_events_ignored.inc();
    }

    fn mouse(&mut self, _event: MouseEvent) {
        self.metrics.input_events_ignored.inc();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;

    #[test]
    fn input_events_are_counted_and_dropped() {
        let m = Arc::new(Metrics::default());
        let mut h = InputStub::new(m.clone());
        h.keyboard(KeyboardEvent::Pressed {
            code: 0x1E,
            extended: false,
        });
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        assert_eq!(m.input_events_ignored.get(), 2);
    }
}
