use ironrdp_server::{
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServerDisplay,
    RdpServerDisplayUpdates, RdpServerInputHandler, ServerResult,
};

pub struct SpikeDisplay {
    pub w: u16,
    pub h: u16,
}

struct Pending;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Pending {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // Frames are pushed proactively via the gfx handle; never via updates().
        let () = core::future::pending().await;
        unreachable!()
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for SpikeDisplay {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: self.w,
            height: self.h,
        }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Pending))
    }
}

/// Logs every input event — this IS the Leg B key-matrix capture.
pub struct SpikeInput;

impl RdpServerInputHandler for SpikeInput {
    fn keyboard(&mut self, e: KeyboardEvent) {
        tracing::info!(event = ?e, "LEGB_INPUT keyboard");
    }
    fn mouse(&mut self, e: MouseEvent) {
        tracing::debug!(event = ?e, "LEGB_INPUT mouse");
    }
}
