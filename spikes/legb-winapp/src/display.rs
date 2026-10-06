use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ironrdp_server::{
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServerDisplay,
    RdpServerDisplayUpdates, RdpServerInputHandler, ServerResult,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Shared between the display handler and the ship loop.
#[derive(Clone)]
pub struct DisplayCtl {
    size: Arc<Mutex<(u16, u16)>>,
    tx: Arc<Mutex<Option<UnboundedSender<DisplayUpdate>>>>,
    updates_calls: Arc<AtomicU64>,
}

impl DisplayCtl {
    pub fn new(w: u16, h: u16) -> Self {
        Self {
            size: Arc::new(Mutex::new((w, h))),
            tx: Arc::new(Mutex::new(None)),
            updates_calls: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn set_size(&self, w: u16, h: u16) {
        *self.size.lock().expect("size") = (w, h);
    }
    /// Emit DisplayUpdate::Resize on the current updates stream. False if none yet.
    pub fn send_resize(&self, w: u16, h: u16) -> bool {
        self.tx.lock().expect("tx").as_ref().is_some_and(|tx| {
            tx.send(DisplayUpdate::Resize(DesktopSize {
                width: w,
                height: h,
            }))
            .is_ok()
        })
    }
    /// IronRDP calls updates() once per (re)activation; a bump = reactivation complete.
    pub fn updates_calls(&self) -> u64 {
        self.updates_calls.load(Ordering::SeqCst)
    }
}

pub struct SpikeDisplay {
    pub ctl: DisplayCtl,
}

struct ChanUpdates(UnboundedReceiver<DisplayUpdate>);

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for ChanUpdates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // recv() is cancellation-safe, as the trait requires.
        Ok(self.0.recv().await)
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for SpikeDisplay {
    async fn size(&mut self) -> DesktopSize {
        let (width, height) = *self.ctl.size.lock().expect("size");
        DesktopSize { width, height }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        let (tx, rx) = unbounded_channel();
        *self.ctl.tx.lock().expect("tx") = Some(tx);
        let n = self.ctl.updates_calls.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::info!(
            updates_calls = n,
            "LEGB_DISPLAY updates() (activation/reactivation)"
        );
        Ok(Box::new(ChanUpdates(rx)))
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
