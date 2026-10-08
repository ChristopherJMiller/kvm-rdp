//! `RdpServerDisplay` (§5.1, §6.4): `size()` is the last-known KVM
//! resolution (`video.default_size` until the first SPS), and `updates()`
//! — called on every activation and reactivation — hands IronRDP a fresh
//! stream whose sender the shell uses for `DisplayUpdate::Resize`. A stream
//! never ends: IronRDP reads `Ok(None)` as a disconnect. Every lock here is
//! held only to read or replace a value, never across a send or an await.
use crate::msg::RdpInput;
use ironrdp_server::{
    DesktopSize, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult,
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::mpsc;

pub struct DisplayShared {
    size: Mutex<(u16, u16)>,
    surface: Mutex<Option<(u16, u16)>>,
    updates: Mutex<Option<mpsc::UnboundedSender<DisplayUpdate>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl DisplayShared {
    #[must_use]
    pub fn new(size: (u16, u16)) -> Arc<DisplayShared> {
        Arc::new(DisplayShared {
            size: Mutex::new(size),
            surface: Mutex::new(None),
            updates: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        *lock(&self.size)
    }

    pub fn set_size(&self, size: (u16, u16)) {
        *lock(&self.size) = size;
    }

    /// The surface mouse scaling uses (§6.4 Setup; Plan D reads it).
    #[must_use]
    pub fn surface(&self) -> Option<(u16, u16)> {
        *lock(&self.surface)
    }

    pub fn set_surface(&self, surface: (u16, u16)) {
        *lock(&self.surface) = Some(surface);
    }

    /// `DisplayUpdate::Resize` on the current stream; `false` if none.
    pub fn resize(&self, width: u16, height: u16) -> bool {
        let tx = lock(&self.updates).clone();
        tx.is_some_and(|tx| {
            tx.send(DisplayUpdate::Resize(DesktopSize { width, height }))
                .is_ok()
        })
    }
}

pub struct BridgeDisplay {
    shared: Arc<DisplayShared>,
    tx: mpsc::UnboundedSender<RdpInput>,
}

impl BridgeDisplay {
    #[must_use]
    pub fn new(shared: Arc<DisplayShared>, tx: mpsc::UnboundedSender<RdpInput>) -> BridgeDisplay {
        BridgeDisplay { shared, tx }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for BridgeDisplay {
    async fn size(&mut self) -> DesktopSize {
        let (width, height) = self.shared.size();
        DesktopSize { width, height }
    }

    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        let (tx, rx) = mpsc::unbounded_channel();
        *lock(&self.shared.updates) = Some(tx);
        let _ = self.tx.send(RdpInput::Updates);
        Ok(Box::new(Updates { rx }))
    }
}

struct Updates {
    rx: mpsc::UnboundedReceiver<DisplayUpdate>,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        match self.rx.recv().await {
            Some(u) => Ok(Some(u)),
            // Replaced by a later `updates()`: this stream's connection is
            // gone or reactivating. Never report the end (a disconnect).
            None => std::future::pending().await,
        }
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
    use std::time::Duration;

    /// §6.4: `size()` is the shared last-known size; `updates()` replaces
    /// the stream and announces itself; a Resize reaches the current stream
    /// only; a replaced stream pends rather than ending (`Ok(None)` would be
    /// a disconnect). Every wait is bounded (P6): a stream that is not
    /// replaced fails the test instead of hanging it.
    #[tokio::test(flavor = "current_thread")]
    async fn updates_replace_the_stream_and_resize_reaches_the_current_one() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shared = DisplayShared::new((1920, 1080));
        let mut d = BridgeDisplay::new(shared.clone(), tx);
        assert_eq!(
            d.size().await,
            DesktopSize {
                width: 1920,
                height: 1080
            }
        );
        assert!(!shared.resize(640, 360), "no stream yet");
        let mut first = d.updates().await.unwrap();
        assert!(matches!(rx.try_recv(), Ok(RdpInput::Updates)));
        assert!(shared.resize(640, 360));
        match tokio::time::timeout(Duration::from_secs(5), first.next_update())
            .await
            .expect("no Resize on the current stream")
            .unwrap()
        {
            Some(DisplayUpdate::Resize(s)) => assert_eq!((s.width, s.height), (640, 360)),
            other => panic!("{other:?}"),
        }
        shared.set_size((640, 360));
        assert_eq!(
            d.size().await,
            DesktopSize {
                width: 640,
                height: 360
            }
        );
        let mut second = d.updates().await.unwrap();
        assert!(shared.resize(854, 480));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), second.next_update())
                .await
                .expect("no Resize on the replacing stream")
                .unwrap(),
            Some(DisplayUpdate::Resize(_))
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), first.next_update())
                .await
                .is_err()
        );
        shared.set_surface((854, 480));
        assert_eq!(shared.surface(), Some((854, 480)));
    }
}
