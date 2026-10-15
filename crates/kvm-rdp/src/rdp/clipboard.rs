//! Clipboard paste (§8), server side: IronRDP's `CliprdrServer` with a
//! backend that advertises nothing, records only whether Unicode text is
//! offered, and hands a format-data response to the input shell. One
//! backend per connection, tagged with its slot as the GFX handle is
//! (§4.3): `build_cliprdr_backend` mints the slot and records it as the
//! latest, `on_connection_info` binds it into the session's `SessionStart`,
//! and the pump shell drops a word from any other slot or from an ended
//! generation. One way only: nothing reads the Mac's clipboard, and no
//! request from the client is answered.
//!
//! The client is untrusted (§9.3). IronRDP reassembles a response before
//! the backend sees it (§8 accepts that bound); the backend checks its
//! length against `paste.max_bytes` before it copies a byte. Over the cap
//! the session ends (`clipboard_oversize`, through `RdpInput::Fatal`) and
//! the backend says nothing more. A failed response is `ClipboardFailed`.
//! A response the bridge never asked for reaches the input core like any
//! other (the backend cannot tell them apart), which types one only when it
//! answers the Pending paste's own request, and discards and counts any
//! other (DD4; PD9 carry 3). A list that names CF_UNICODETEXT as its file list offers no text
//! (IronRDP would take the answer as a file list, past the cap). The data
//! is never logged or Debug-formatted (§9.2).
//!
//! A backend bounds its own forwarding (PD8 review m2), so a flood of
//! format lists or responses never depends on IronRDP's pacing to stay
//! bounded on the unbounded pump channel: at most one availability word
//! (an `Offer`, which reads the latest list when the shell takes it) and
//! one answer word (text or a failure, carrying an `Answer`) are in flight
//! per connection. An answer that comes while one is in flight is dropped
//! and counted on the word in flight (`Answer::lost`), so the input core's
//! request count stays true. A word frees its place when dropped —
//! consumed, or dropped by the shell as another slot's.
//!
//! The callbacks run inside IronRDP's channel processing on the RDP
//! thread: they only push to the pump's channel and take the backend's own
//! `Flow` lock — a leaf, released before any send (a failed send drops its
//! word, whose `Drop` takes it) — and never call into IronRDP.
use crate::msg::{Cause, Gen, Generations, RdpInput};
use crate::pump::Input;
use ironrdp_cliprdr::backend::{CliprdrBackend, CliprdrBackendFactory};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest,
    FormatDataResponse, LockDataId,
};
use ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tokio::sync::mpsc::UnboundedSender;

/// The latest connection's CLIPRDR backend slot.
pub type ClipSlot = Arc<Mutex<Option<u64>>>;

/// IronRDP's `ServerEvent` sender. It exists only once `RdpServer::new`
/// has run (it calls `set_sender` on this factory, server.rs:1647–1648),
/// after `ServerParts` is built, so the input shell reads it from this
/// shared cell (D9a).
pub type ServerEvents = Arc<OnceLock<UnboundedSender<ServerEvent>>>;

/// `on_connection_info`: take the slot of the backend built for this
/// connection (IronRDP builds it in `attach_channels`, beside the GFX
/// handle, before that connection's `on_connection_info`).
#[must_use]
pub fn take_latest_clip(slot: &ClipSlot) -> Option<u64> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// One backend's words in flight on the pump channel (PD8 review m2).
#[derive(Default)]
struct Flow {
    /// The latest format list offered Unicode text (D18).
    text: bool,
    /// An availability word is on the pump channel.
    offer_queued: bool,
    /// An answer word (text or a failure) is on the pump channel.
    answer_queued: bool,
    /// Answers dropped while it was (saturating).
    lost: u32,
}

type FlowCell = Arc<Mutex<Flow>>;

fn flow(f: &FlowCell) -> std::sync::MutexGuard<'_, Flow> {
    f.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An availability word's place: `text` reads the latest format list's
/// offer, so a list that came while the word waited is not lost. Dropping
/// it frees the place for the next list's word.
pub struct Offer(FlowCell);

impl Offer {
    /// Whether the latest format list offers Unicode text.
    #[must_use]
    pub fn text(&self) -> bool {
        flow(&self.0).text
    }

    /// A word with no backend behind it (the shell's tests).
    #[cfg(test)]
    pub(crate) fn detached(text: bool) -> Offer {
        Offer(Arc::new(Mutex::new(Flow {
            text,
            ..Flow::default()
        })))
    }
}

impl Drop for Offer {
    fn drop(&mut self) {
        flow(&self.0).offer_queued = false;
    }
}

/// An answer word's place: `lost` counts the answers the backend dropped
/// while this one was in flight — answers all the same, which the input
/// core must count. Dropping it frees the place and the count.
pub struct Answer(FlowCell);

impl Answer {
    /// Answers dropped behind this one, so far.
    #[must_use]
    pub fn lost(&self) -> u32 {
        flow(&self.0).lost
    }

    /// A word with no backend behind it (the shell's tests).
    #[cfg(test)]
    pub(crate) fn detached() -> Answer {
        Answer(Arc::new(Mutex::new(Flow::default())))
    }
}

impl Drop for Answer {
    fn drop(&mut self) {
        let mut f = flow(&self.0);
        f.answer_queued = false;
        f.lost = 0;
    }
}

/// What the pump shell steps for an `RdpInput::Fatal` from its current
/// link's clip slot, given that link's generation — as
/// `rdp::gfx::closed_channel_input` is for EGFX. While the generation is
/// current, the session closes with `cause`. Once `on_disconnected` has
/// ended it (its `SessionStop` still queued behind this word), the client
/// has gone already: `None`, or the pump would count a
/// `clipboard_oversize` disconnect that never happens (D17).
#[must_use]
pub fn fatal_input(gens: &Generations, generation: Gen, cause: Cause) -> Option<Input> {
    gens.is_current(generation)
        .then_some(Input::UpstreamFatal(cause))
}

pub struct ClipFactory {
    slot_src: Arc<AtomicU64>,
    latest: ClipSlot,
    to_pump: UnboundedSender<RdpInput>,
    max_bytes: usize,
    events: ServerEvents,
}

impl ClipFactory {
    #[must_use]
    pub fn new(
        slot_src: Arc<AtomicU64>,
        latest: ClipSlot,
        to_pump: UnboundedSender<RdpInput>,
        max_bytes: usize,
        events: ServerEvents,
    ) -> ClipFactory {
        ClipFactory {
            slot_src,
            latest,
            to_pump,
            max_bytes,
            events,
        }
    }
}

impl ServerEventSender for ClipFactory {
    /// Called once, inside `RdpServer::new`: keep the sender for the input
    /// shell's `SendInitiatePaste` (Task 4.1). A second call keeps the
    /// first.
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        let _ = self.events.set(sender);
    }
}

impl CliprdrBackendFactory for ClipFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        let slot = self
            .slot_src
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
            .max(1);
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(slot);
        Box::new(ClipBackend {
            slot,
            to_pump: self.to_pump.clone(),
            max_bytes: self.max_bytes,
            ended: false,
            flow: FlowCell::default(),
        })
    }
}

impl CliprdrServerFactory for ClipFactory {}

struct ClipBackend {
    slot: u64,
    to_pump: UnboundedSender<RdpInput>,
    max_bytes: usize,
    /// It sent its `Fatal`: the session is ending, and nothing more from
    /// this connection's clipboard goes anywhere.
    ended: bool,
    /// Its words in flight (PD8 review m2).
    flow: FlowCell,
}

impl ClipBackend {
    /// The answer word's place, if it is free; otherwise this answer is
    /// dropped and counted on the word in flight. The lock is released
    /// before the caller sends.
    fn answer_place(&self) -> Option<Answer> {
        let mut f = flow(&self.flow);
        if f.answer_queued {
            f.lost = f.lost.saturating_add(1);
            return None;
        }
        f.answer_queued = true;
        f.lost = 0;
        Some(Answer(self.flow.clone()))
    }
}

// `CliprdrBackend: AsAny + Debug + Send`, and `AsAny` has no blanket impl
// (ironrdp-core as_any.rs) — D1c.
ironrdp_core::impl_as_any!(ClipBackend);

impl std::fmt::Debug for ClipBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never clipboard contents (§9.2). This backend holds none, but a
        // derive would become a leak the day a field did.
        f.debug_struct("ClipBackend")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        "." // The client role's; no file transfer (§8 non-goals).
    }

    /// §8: the server advertises no clipboard capabilities of its own.
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    /// Only a client is asked for its format list (a hostile client's
    /// Monitor Ready lands here): the server offers nothing.
    fn on_request_format_list(&mut self) {}

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    /// The client announced its formats: record only whether Unicode text
    /// — the one format the bridge requests — is there (D18). A client
    /// that offers only ANSI text gets a `no_text` refusal at once, not a
    /// wait that ends in `modifier_wait`.
    ///
    /// Not when the list's first format *named* `FileGroupDescriptorW` has
    /// CF_UNICODETEXT's id (PD8 review I2). IronRDP takes that first name
    /// as the client's file list whatever its id (ironrdp-cliprdr
    /// lib.rs:810–821) and parses the answer to a request for it as a file
    /// list, bypassing `on_format_data_response` and with it §8's cap; a
    /// benign client never names a standard format. `formats` is the very
    /// list IronRDP reads, in its order, so the two cannot disagree.
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        if self.ended {
            return;
        }
        let file_list = formats
            .iter()
            .find(|f| {
                f.name()
                    .is_some_and(|n| n.value() == ClipboardFormatName::FILE_LIST.value())
            })
            .map(ClipboardFormat::id);
        let text = file_list != Some(ClipboardFormatId::CF_UNICODETEXT)
            && formats
                .iter()
                .any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT);
        // Coalesced (m2): a word already in flight reads this list's offer
        // when the shell takes it.
        let queue = {
            let mut f = flow(&self.flow);
            f.text = text;
            !std::mem::replace(&mut f.offer_queued, true)
        };
        if queue {
            let _ = self.to_pump.send(RdpInput::ClipboardAvailable {
                slot: self.slot,
                offer: Offer(self.flow.clone()),
            });
        }
    }

    /// The client asks for the server's clipboard: never answered (§8, one
    /// way).
    fn on_format_data_request(&mut self, _request: FormatDataRequest) {}

    /// A response to the bridge's request — or one nobody asked for, which
    /// IronRDP forwards just the same. Its length is checked before a byte
    /// is copied: over `paste.max_bytes` → fatal `clipboard_oversize`
    /// (§8), counted once by the pump's `close` (D17); the backend counts
    /// nothing and says nothing more. A CB_RESPONSE_FAIL — the client's, or
    /// IronRDP's own for a request it could not send — types nothing: it
    /// is `ClipboardFailed`, so the paste waiting on it can end at once
    /// (PD8 review (b)). At most one answer is in flight (m2): one that
    /// comes meanwhile is dropped, before a byte is copied, and counted on
    /// the word in flight; an oversize one is still the `Fatal`, checked
    /// first. Never logged.
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if self.ended {
            return;
        }
        if response.is_error() {
            if let Some(answer) = self.answer_place() {
                let _ = self.to_pump.send(RdpInput::ClipboardFailed {
                    slot: self.slot,
                    answer,
                });
            }
            return;
        }
        let data = response.data();
        if data.len() > self.max_bytes {
            self.ended = true;
            let _ = self.to_pump.send(RdpInput::Fatal {
                slot: self.slot,
                cause: Cause::ClipboardOversize,
            });
            return;
        }
        if let Some(answer) = self.answer_place() {
            let _ = self.to_pump.send(RdpInput::ClipboardText {
                slot: self.slot,
                bytes: data.to_vec(),
                answer,
            });
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}

    /// IronRDP parsed an answer as a file list (a client that named
    /// CF_UNICODETEXT its `FileGroupDescriptorW` after the bridge asked —
    /// PD8's residual) and never calls `on_format_data_response` for it. It
    /// is an answer all the same: forwarded as one with no text, so the
    /// input core's request count stays true (PD9 review I2). Nothing of
    /// the list is kept.
    fn on_remote_file_list(&mut self, _files: &[FileDescriptor], _clip_data_id: Option<u32>) {
        if self.ended {
            return;
        }
        if let Some(answer) = self.answer_place() {
            let _ = self.to_pump.send(RdpInput::ClipboardFailed {
                slot: self.slot,
                answer,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::input::{Ctx, Event, InputCore, Out, PasteOutcome};
    use ironrdp_cliprdr::backend::ClipboardMessage;
    use ironrdp_cliprdr::pdu::{
        ClipboardPdu, FileContentsFlags, FileDescriptor, OwnedFormatDataResponse, PackedFileList,
    };
    use ironrdp_cliprdr::{Cliprdr, CliprdrClient, CliprdrServer};
    use ironrdp_svc::{StaticVirtualChannel, SvcMessage};
    use kvm_proto::hid::HidFrame;
    use kvm_proto::keymap::Chord;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc::UnboundedReceiver;

    fn factory_with(
        max_bytes: usize,
    ) -> (
        ClipFactory,
        ClipSlot,
        UnboundedReceiver<RdpInput>,
        ServerEvents,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let latest = ClipSlot::default();
        let events = ServerEvents::default();
        let f = ClipFactory::new(
            Arc::new(AtomicU64::new(0)),
            latest.clone(),
            tx,
            max_bytes,
            events.clone(),
        );
        (f, latest, rx, events)
    }

    fn factory() -> (ClipFactory, ClipSlot, UnboundedReceiver<RdpInput>) {
        let (f, slot, rx, _) = factory_with(64 * 1024);
        (f, slot, rx)
    }

    /// The next word, if it is `slot`'s availability: the offer it reads.
    /// (The word is dropped here, freeing its place.)
    fn offered(rx: &mut UnboundedReceiver<RdpInput>, slot: u64) -> Option<bool> {
        match rx.try_recv() {
            Ok(RdpInput::ClipboardAvailable { slot: s, offer }) if s == slot => Some(offer.text()),
            _ => None,
        }
    }

    fn utf16z(s: &str) -> Vec<u8> {
        let mut b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        b.extend([0, 0]);
        b
    }

    /// The backend advertises nothing of its own (§8: the server advertises
    /// no clipboard capabilities).
    #[test]
    fn the_backend_advertises_no_capabilities() {
        let (f, _slot, _rx) = factory();
        let b = f.build_cliprdr_backend();
        assert!(b.client_capabilities().is_empty());
    }

    /// `build_cliprdr_backend` mints a slot and records it as the latest,
    /// as the GFX factory does; the backend tags its inputs with it. Only
    /// CF_UNICODETEXT — the one format the bridge requests — is text (D18).
    #[test]
    fn a_backend_mints_and_records_its_slot() {
        let (f, slot, mut rx) = factory();
        let mut b = f.build_cliprdr_backend();
        assert_eq!(take_latest_clip(&slot), Some(1));
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert_eq!(offered(&mut rx, 1), Some(true));
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_BITMAP)]);
        assert_eq!(offered(&mut rx, 1), Some(false));
        b.on_remote_copy(&[
            ClipboardFormat::new(ClipboardFormatId::CF_TEXT),
            ClipboardFormat::new(ClipboardFormatId::CF_OEMTEXT),
        ]);
        assert_eq!(offered(&mut rx, 1), Some(false));
        // A second connection's backend gets the next slot, and is latest.
        let mut b2 = f.build_cliprdr_backend();
        assert_eq!(take_latest_clip(&slot), Some(2));
        assert_eq!(take_latest_clip(&slot), None, "taken once");
        b2.on_remote_copy(&[]);
        assert_eq!(offered(&mut rx, 2), Some(false));
    }

    /// D9a: IronRDP hands the factory its `ServerEvent` sender; the input
    /// shell reads it from the shared cell. Set once: a second sender does
    /// not replace the first.
    #[test]
    fn set_sender_fills_the_shared_cell_once() {
        let (mut f, _slot, _rx, events) = factory_with(64);
        assert!(events.get().is_none());
        let (tx, _erx) = tokio::sync::mpsc::unbounded_channel();
        f.set_sender(tx.clone());
        assert!(events.get().is_some());
        let (other, _orx) = tokio::sync::mpsc::unbounded_channel();
        f.set_sender(other);
        assert!(events.get().unwrap().same_channel(&tx));
    }

    /// A text response under the cap becomes `ClipboardText`; an oversize
    /// one becomes `Fatal(ClipboardOversize)` (§8), and the data is never
    /// Debug-formatted (§9.2: assert by construction — no Debug call here).
    /// An error response types nothing: it becomes `ClipboardFailed`, so
    /// the paste waiting on it can end at once (PD8 review (b); Task 4.1
    /// acts on it). (Its order differs from the brief's: a backend says
    /// nothing after its `Fatal`, so the error response comes first.)
    #[test]
    fn a_response_routes_text_or_a_fatal_oversize() {
        let (f, _slot, mut rx, _) = factory_with(8);
        let mut b = f.build_cliprdr_backend();
        b.on_format_data_response(FormatDataResponse::new_unicode_string("hi"));
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardText { slot: 1, bytes, .. }) if bytes == utf16z("hi"))
        );
        // An error response types nothing; it is reported as a failure.
        b.on_format_data_response(FormatDataResponse::new_error());
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::ClipboardFailed { slot: 1, .. })
        ));
        assert!(rx.try_recv().is_err());
        b.on_format_data_response(FormatDataResponse::new_unicode_string("far too long"));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::Fatal {
                slot: 1,
                cause: Cause::ClipboardOversize
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    /// §8's cap is `paste.max_bytes` after reassembly: exactly that many
    /// bytes are text, one more ends the session. The length is checked
    /// before a byte is copied.
    #[test]
    fn exactly_max_bytes_is_text_and_one_byte_more_is_fatal() {
        let (f, _slot, mut rx, _) = factory_with(6);
        let mut b = f.build_cliprdr_backend();
        b.on_format_data_response(FormatDataResponse::new_data(utf16z("hi")));
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardText { slot: 1, bytes, .. }) if bytes == utf16z("hi"))
        );
        b.on_format_data_response(FormatDataResponse::new_data(vec![0x41; 7]));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::Fatal {
                slot: 1,
                cause: Cause::ClipboardOversize
            })
        ));
    }

    /// A hostile client can repeat its oversize response: the session ends
    /// once — one `Fatal` — and the backend says nothing more, so no text
    /// reaches a paste while the session closes.
    #[test]
    fn after_its_fatal_a_backend_sends_nothing_more() {
        let (f, _slot, mut rx, _) = factory_with(4);
        let mut b = f.build_cliprdr_backend();
        b.on_format_data_response(FormatDataResponse::new_data(vec![0; 5]));
        assert!(matches!(rx.try_recv(), Ok(RdpInput::Fatal { slot: 1, .. })));
        b.on_format_data_response(FormatDataResponse::new_data(vec![0; 5]));
        b.on_format_data_response(FormatDataResponse::new_data(vec![0x41, 0]));
        b.on_format_data_response(FormatDataResponse::new_error());
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert!(rx.try_recv().is_err());
    }

    /// §8 is one way: what the client asks of the server's clipboard (data,
    /// file contents, a lock) is never answered, and the channel's own life
    /// (ready, capabilities, a format list request) sends nothing.
    #[test]
    fn the_backend_answers_no_request_and_offers_nothing() {
        let (f, _slot, mut rx) = factory();
        let mut b = f.build_cliprdr_backend();
        b.on_ready();
        b.on_request_format_list();
        b.on_process_negotiated_capabilities(ClipboardGeneralCapabilityFlags::all());
        b.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        });
        b.on_file_contents_request(FileContentsRequest {
            stream_id: 1,
            index: 0,
            flags: FileContentsFlags::RANGE,
            position: 0,
            requested_size: 1 << 20,
            data_id: None,
        });
        b.on_file_contents_response(FileContentsResponse::new_error(1));
        b.on_lock(LockDataId(1));
        b.on_unlock(LockDataId(1));
        b.on_format_list_response(true);
        assert!(rx.try_recv().is_err());
        // The backend's Debug names its slot and nothing else.
        assert_eq!(format!("{b:?}"), "ClipBackend { slot: 1, .. }");
    }

    // ---- A real CLIPRDR exchange: IronRDP's client against IronRDP's
    // server hosting the bridge's backend, through the SVC chunking and
    // reassembly the server runs (1 600-byte chunks).

    /// What the client end saw and was asked.
    #[derive(Default)]
    struct ClientState {
        /// What the client's backend asked its event loop to do, in order.
        queued: Vec<ClipboardMessage>,
        /// Its answer to a data request (`None`: CB_RESPONSE_FAIL).
        answer: Option<Vec<u8>>,
        /// It never answers a data request (a client that stopped).
        silent: bool,
        /// Data requests the server sent.
        asked: usize,
        /// Format lists the server offered (§8: never).
        offered: usize,
        /// The capabilities negotiated with the server.
        negotiated: Option<ClipboardGeneralCapabilityFlags>,
    }

    /// The client end, as a real client runs it: its backend announces
    /// CF_UNICODETEXT when the server's Monitor Ready asks for its format
    /// list (D9b: from `on_request_format_list`; `on_ready` comes only
    /// after the server's `FormatListResponse`), and answers a data request
    /// with `answer`.
    struct ClientClip(Arc<Mutex<ClientState>>);

    ironrdp_core::impl_as_any!(ClientClip);

    impl std::fmt::Debug for ClientClip {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ClientClip")
        }
    }

    impl ClientClip {
        fn state(&self) -> std::sync::MutexGuard<'_, ClientState> {
            self.0.lock().unwrap()
        }
    }

    impl CliprdrBackend for ClientClip {
        fn temporary_directory(&self) -> &str {
            "."
        }
        fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
            ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
                | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
        }
        fn on_ready(&mut self) {}
        fn on_request_format_list(&mut self) {
            self.state()
                .queued
                .push(ClipboardMessage::SendInitiateCopy(vec![
                    ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
                ]));
        }
        fn on_process_negotiated_capabilities(&mut self, c: ClipboardGeneralCapabilityFlags) {
            self.state().negotiated = Some(c);
        }
        fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {
            self.state().offered += 1;
        }
        fn on_format_data_request(&mut self, _: FormatDataRequest) {
            let mut s = self.state();
            s.asked += 1;
            if s.silent {
                return;
            }
            let r = match &s.answer {
                Some(b) => OwnedFormatDataResponse::new_data(b.clone()),
                None => OwnedFormatDataResponse::new_error(),
            };
            s.queued.push(ClipboardMessage::SendFormatData(r));
        }
        fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
        fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
        fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
        fn on_lock(&mut self, _: LockDataId) {}
        fn on_unlock(&mut self, _: LockDataId) {}
    }

    struct Wire {
        server: StaticVirtualChannel,
        client: StaticVirtualChannel,
        state: Arc<Mutex<ClientState>>,
    }

    /// Chunk `msgs` as IronRDP writes them and hand every chunk to `to`;
    /// its replies.
    fn deliver(to: &mut StaticVirtualChannel, msgs: Vec<SvcMessage>) -> Vec<SvcMessage> {
        let mut replies = Vec::new();
        for chunk in StaticVirtualChannel::chunkify(msgs).unwrap() {
            replies.extend(to.process(chunk.filled()).unwrap());
        }
        replies
    }

    impl Wire {
        /// Both ends of one connection's channel, started: the server's
        /// capabilities and Monitor Ready, the client's capabilities,
        /// temporary directory and format list, the server's response.
        fn start(f: &ClipFactory, answer: Option<Vec<u8>>) -> Wire {
            let state = Arc::new(Mutex::new(ClientState {
                answer,
                ..ClientState::default()
            }));
            let server: CliprdrServer = Cliprdr::new(f.build_cliprdr_backend());
            let client: CliprdrClient = Cliprdr::new(Box::new(ClientClip(state.clone())));
            let mut w = Wire {
                server: StaticVirtualChannel::new(server),
                client: StaticVirtualChannel::new(client),
                state,
            };
            let s = w.server.start().unwrap();
            let c = w.client.start().unwrap();
            w.settle(s, c);
            w
        }

        /// The client's event loop carrying out what its backend queued.
        fn client_does(&mut self, m: ClipboardMessage) -> Vec<SvcMessage> {
            let c = self
                .client
                .channel_processor_downcast_mut::<CliprdrClient>()
                .unwrap();
            match m {
                ClipboardMessage::SendInitiateCopy(formats) => {
                    c.initiate_copy(&formats).unwrap().into()
                }
                ClipboardMessage::SendFormatData(r) => c.submit_format_data(r).unwrap().into(),
                other => panic!("the test client never sends {other:?}"),
            }
        }

        /// Run the exchange until both ends are quiet (bounded).
        fn settle(&mut self, mut to_client: Vec<SvcMessage>, mut to_server: Vec<SvcMessage>) {
            for _ in 0..64 {
                if !to_client.is_empty() {
                    let msgs = std::mem::take(&mut to_client);
                    to_server.extend(deliver(&mut self.client, msgs));
                }
                let queued = std::mem::take(&mut self.state.lock().unwrap().queued);
                for m in queued {
                    to_server.extend(self.client_does(m));
                }
                if !to_server.is_empty() {
                    let msgs = std::mem::take(&mut to_server);
                    to_client.extend(deliver(&mut self.server, msgs));
                }
                if to_client.is_empty()
                    && to_server.is_empty()
                    && self.state.lock().unwrap().queued.is_empty()
                {
                    return;
                }
            }
            panic!("the CLIPRDR exchange never settled");
        }

        /// What IronRDP's server does with the bridge's request,
        /// `ServerEvent::Clipboard(SendInitiatePaste(CF_UNICODETEXT))`
        /// (server.rs:3412; Task 4.1 sends it).
        fn request_text(&mut self) {
            let msgs = self
                .server
                .channel_processor_downcast_mut::<CliprdrServer>()
                .unwrap()
                .initiate_paste(ClipboardFormatId::CF_UNICODETEXT)
                .unwrap()
                .into();
            self.settle(msgs, Vec::new());
        }

        /// The client sends a format data response nobody asked for.
        fn unasked(&mut self, bytes: Vec<u8>) {
            let msgs = self.client_does(ClipboardMessage::SendFormatData(
                OwnedFormatDataResponse::new_data(bytes),
            ));
            self.settle(Vec::new(), msgs);
        }

        /// A raw PDU straight to the server, as a hostile client may send.
        fn raw(&mut self, pdu: ClipboardPdu<'static>) {
            self.settle(Vec::new(), vec![SvcMessage::from(pdu)]);
        }
    }

    /// §8 steps 1 and 3 on the wire: a real client's format list reaches
    /// the bridge as `ClipboardAvailable(true)`; the bridge's request
    /// reaches the client once, and its CF_UNICODETEXT answer comes back
    /// as `ClipboardText`, NUL terminator and all (D4: the core drops it).
    /// The server advertises no capability of its own — nothing the client
    /// offers is negotiated — and never offers its own clipboard (one way).
    #[test]
    fn a_real_client_offers_text_and_answers_the_bridges_request() {
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, Some(utf16z("hi")));
        assert_eq!(offered(&mut rx, 1), Some(true));
        assert!(rx.try_recv().is_err());
        w.request_text();
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardText { slot: 1, bytes, .. }) if bytes == utf16z("hi"))
        );
        let s = w.state.lock().unwrap();
        assert_eq!(s.asked, 1);
        assert_eq!(s.offered, 0, "the server offered a clipboard");
        // The client offered file streams and locking; the bridge adds no
        // capability, so neither is negotiated. Long format names are
        // IronRDP's own format-list encoding, which every CLIPRDR end it
        // builds advertises (ironrdp-cliprdr lib.rs:603), not a clipboard
        // feature.
        assert_eq!(
            s.negotiated,
            Some(ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES)
        );
    }

    /// §8: an answer over `paste.max_bytes` once IronRDP has reassembled
    /// its chunks ends the session (`clipboard_oversize`); an unasked one
    /// too. A CB_RESPONSE_FAIL answer types nothing: `ClipboardFailed`.
    #[test]
    fn an_oversize_answer_reassembled_from_chunks_is_fatal() {
        let (f, _slot, mut rx, _) = factory_with(64 * 1024);
        let mut w = Wire::start(&f, Some(vec![0x41; 64 * 1024 + 1]));
        let _ = rx.try_recv(); // its availability
        w.request_text();
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::Fatal {
                slot: 1,
                cause: Cause::ClipboardOversize
            })
        ));
        let mut w = Wire::start(&f, None);
        let _ = rx.try_recv();
        w.request_text();
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardFailed { slot: 2, .. })),
            "a CB_RESPONSE_FAIL answer was not reported as a failure"
        );
        assert!(rx.try_recv().is_err());
        w.unasked(vec![0x41; 64 * 1024 + 1]);
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::Fatal {
                slot: 2,
                cause: Cause::ClipboardOversize
            })
        ));
    }

    /// PD8 review (b): the failures IronRDP synthesizes itself reach the
    /// pump too. A client that stops answering fills IronRDP's 64 pending
    /// requests; the 65th is never sent, and IronRDP fails it to the
    /// backend at once (ironrdp-cliprdr lib.rs:942–951) — a
    /// `ClipboardFailed`, not a paste that waits out `modifier_wait`.
    #[test]
    fn ironrdps_own_failure_for_an_unanswered_request_reaches_the_pump() {
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, None);
        let _ = rx.try_recv(); // its availability
        w.state.lock().unwrap().silent = true;
        for _ in 0..64 {
            w.request_text();
        }
        assert_eq!(w.state.lock().unwrap().asked, 64);
        assert!(rx.try_recv().is_err(), "nothing answered yet");
        w.request_text();
        assert_eq!(w.state.lock().unwrap().asked, 64, "the 65th went out");
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::ClipboardFailed { slot: 1, .. })
        ));
        assert!(rx.try_recv().is_err());
    }

    /// PD8 review I2: IronRDP takes the first format *named*
    /// `FileGroupDescriptorW` as the client's file list (ironrdp-cliprdr
    /// lib.rs:810–821), whatever its id, and parses the answer to a request
    /// for that id as a file list — never through `on_format_data_response`,
    /// so §8's cap would never fire. A list whose first such name sits on
    /// CF_UNICODETEXT therefore offers no text: the core refuses `no_text`
    /// and never asks. Any other arrangement leaves CF_UNICODETEXT IronRDP's
    /// plain format, and is text as before. The names cross the real wire,
    /// so the unnamed control proves they arrive.
    #[test]
    fn unicode_text_named_as_the_file_list_is_not_text() {
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, Some(utf16z("x")));
        let _ = rx.try_recv();
        let text = || ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT);
        let named = |id| ClipboardFormat::new(id).with_name(ClipboardFormatName::FILE_LIST);
        let other = ClipboardFormatId::new(0xC0FF);
        let cases = [
            (vec![named(ClipboardFormatId::CF_UNICODETEXT)], false),
            (
                vec![named(ClipboardFormatId::CF_UNICODETEXT), text()],
                false,
            ),
            (
                vec![text(), named(ClipboardFormatId::CF_UNICODETEXT)],
                false,
            ),
            (vec![named(other), text()], true),
            (
                vec![named(other), named(ClipboardFormatId::CF_UNICODETEXT)],
                true,
            ),
            (vec![text()], true),
        ];
        for (i, (formats, want)) in cases.into_iter().enumerate() {
            let msgs = w.client_does(ClipboardMessage::SendInitiateCopy(formats));
            w.settle(Vec::new(), msgs);
            assert!(
                matches!(rx.try_recv(), Ok(RdpInput::ClipboardAvailable { slot: 1, offer }) if offer.text() == want),
                "case {i}: want text = {want}"
            );
        }
        assert!(rx.try_recv().is_err());
    }

    /// What a hostile client may send the server besides its answer — a
    /// Monitor Ready, a request for the server's data, locks, a file
    /// contents request — reaches nothing: no input for the pump, no
    /// format list or data offered back. Format lists are coalesced into
    /// one `ClipboardAvailable` in flight (a bool; nothing of a list is
    /// kept).
    #[test]
    fn hostile_cliprdr_traffic_reaches_nothing() {
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, Some(utf16z("x")));
        let _ = rx.try_recv();
        w.raw(ClipboardPdu::MonitorReady);
        w.raw(ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        }));
        for id in 0..200 {
            w.raw(ClipboardPdu::LockData(LockDataId(id)));
        }
        w.raw(ClipboardPdu::UnlockData(LockDataId(3)));
        w.raw(ClipboardPdu::FileContentsRequest(FileContentsRequest {
            stream_id: 7,
            index: 0,
            flags: FileContentsFlags::RANGE,
            position: 0,
            requested_size: u32::MAX,
            data_id: None,
        }));
        assert!(rx.try_recv().is_err(), "hostile traffic reached the pump");
        assert_eq!(w.state.lock().unwrap().offered, 0);
        for i in 0..200u32 {
            let formats = if i % 2 == 0 {
                vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
            } else {
                vec![ClipboardFormat::new(ClipboardFormatId::new(0xC000 + i))]
            };
            let msgs = w.client_does(ClipboardMessage::SendInitiateCopy(formats));
            w.settle(Vec::new(), msgs);
        }
        // Coalesced (PD9 carry 3, m2): one word in flight, reading the
        // latest list — the 200th, which offered no text.
        assert_eq!(offered(&mut rx, 1), Some(false));
        assert!(rx.try_recv().is_err());
    }

    /// PD9 carry 3 (PD8 review m2): a flood of format lists never queues
    /// more than one availability word, whatever IronRDP's pacing — and
    /// that word reports the latest list when the shell reads it. Once the
    /// shell has taken it (or dropped it as another slot's), the next list
    /// sends a word again.
    #[test]
    fn a_format_list_flood_queues_one_word_with_the_latest_offer() {
        let (f, _slot, mut rx) = factory();
        let mut b = f.build_cliprdr_backend();
        for i in 0..10_000u32 {
            let id = if i % 2 == 0 {
                ClipboardFormatId::CF_UNICODETEXT
            } else {
                ClipboardFormatId::CF_BITMAP
            };
            b.on_remote_copy(&[ClipboardFormat::new(id)]);
        }
        let Ok(RdpInput::ClipboardAvailable { slot: 1, offer }) = rx.try_recv() else {
            panic!("no availability word");
        };
        assert!(rx.try_recv().is_err(), "more than one word queued");
        assert!(!offer.text(), "not the latest list (the last had no text)");
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert!(offer.text(), "the queued word reads the latest list");
        assert!(rx.try_recv().is_err());
        drop(offer);
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_BITMAP)]);
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardAvailable { slot: 1, offer }) if !offer.text())
        );
    }

    /// PD9 carry 3 (PD8 review m2): at most one answer — a text response or
    /// a failure — is in flight on the pump channel per connection; the
    /// rest are dropped and counted on the word in flight (`lost`), so the
    /// shell's request count stays true. An oversize response is still the
    /// session's end, in flight or not (§8).
    #[test]
    fn a_response_flood_queues_one_answer_and_counts_the_rest() {
        let (f, _slot, mut rx, _) = factory_with(64);
        let mut b = f.build_cliprdr_backend();
        for _ in 0..1_000 {
            b.on_format_data_response(FormatDataResponse::new_unicode_string("hi"));
            b.on_format_data_response(FormatDataResponse::new_error());
        }
        let Ok(RdpInput::ClipboardText {
            slot: 1,
            bytes,
            answer,
        }) = rx.try_recv()
        else {
            panic!("no answer word");
        };
        assert_eq!(bytes, utf16z("hi"));
        assert!(rx.try_recv().is_err(), "more than one answer queued");
        assert_eq!(answer.lost(), 1_999);
        drop(answer);
        b.on_format_data_response(FormatDataResponse::new_error());
        let Ok(RdpInput::ClipboardFailed { slot: 1, answer }) = rx.try_recv() else {
            panic!("no failure word");
        };
        assert_eq!(answer.lost(), 0, "a freed place starts a fresh count");
        b.on_format_data_response(FormatDataResponse::new_unicode_string("hi"));
        assert_eq!(answer.lost(), 1);
        b.on_format_data_response(FormatDataResponse::new_data(vec![0; 65]));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::Fatal {
                slot: 1,
                cause: Cause::ClipboardOversize
            })
        ));
        assert!(rx.try_recv().is_err());
        assert_eq!(answer.lost(), 1, "the oversize answer is the Fatal");
    }

    /// The places are per connection: one backend's word in flight never
    /// holds another's back, and a word dropped with the pump's channel
    /// (the shell gone) frees its place without a deadlock — `send`'s
    /// error drops it inside the callback, after the backend's own lock.
    #[test]
    fn places_are_per_connection_and_a_closed_channel_frees_them() {
        let (f, _slot, mut rx) = factory();
        let mut b1 = f.build_cliprdr_backend();
        let mut b2 = f.build_cliprdr_backend();
        b1.on_format_data_response(FormatDataResponse::new_unicode_string("a"));
        b2.on_format_data_response(FormatDataResponse::new_unicode_string("b"));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::ClipboardText { slot: 1, .. })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::ClipboardText { slot: 2, .. })
        ));
        drop(rx);
        for _ in 0..3 {
            b1.on_format_data_response(FormatDataResponse::new_unicode_string("a"));
            b1.on_format_data_response(FormatDataResponse::new_error());
            b1.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        }
    }

    /// PD9 fix round 1, I2 (b): a file list IronRDP parsed out of an answer
    /// (`on_remote_file_list`) is an answer to the bridge's request all the
    /// same — forwarded as `ClipboardFailed` (no text), through the answer
    /// word's place, so the input core's request count stays true.
    #[test]
    fn a_file_list_answer_is_an_answer_with_no_text() {
        let (f, _slot, mut rx) = factory();
        let mut b = f.build_cliprdr_backend();
        b.on_remote_file_list(&[], None);
        let Ok(RdpInput::ClipboardFailed { slot: 1, answer }) = rx.try_recv() else {
            panic!("the file list was not forwarded as an answer");
        };
        b.on_remote_file_list(&[], Some(3));
        assert!(rx.try_recv().is_err(), "a second word in flight");
        assert_eq!(answer.lost(), 1);
    }

    /// I2 (b) on the wire, the PD8 residual: the client names CF_UNICODETEXT
    /// as its `FileGroupDescriptorW` between the chord and the request, so
    /// IronRDP takes the bridge's request for a file list and parses the
    /// answer as one (never `on_format_data_response`). The backend still
    /// reports it: one answer, no text.
    #[test]
    fn a_spoofed_file_list_answer_still_counts_as_an_answer() {
        let list = PackedFileList {
            files: vec![FileDescriptor::new("a.txt").with_file_size(1)],
        };
        let bytes = OwnedFormatDataResponse::new_file_list(&list)
            .unwrap()
            .data()
            .to_vec();
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, Some(bytes));
        assert_eq!(offered(&mut rx, 1), Some(true));
        let spoof = vec![
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)
                .with_name(ClipboardFormatName::FILE_LIST),
        ];
        let msgs = w.client_does(ClipboardMessage::SendInitiateCopy(spoof));
        w.settle(Vec::new(), msgs);
        assert_eq!(offered(&mut rx, 1), Some(false));
        w.request_text();
        assert!(
            matches!(rx.try_recv(), Ok(RdpInput::ClipboardFailed { slot: 1, .. })),
            "the spoofed answer reached nothing"
        );
        assert!(rx.try_recv().is_err());
    }

    fn ctx(now: Instant) -> Ctx {
        Ctx {
            now,
            epoch: 0,
            generation: 1,
            surface: (1920, 1080),
            mac_remap: false,
            key_repeat_timeout: Duration::from_secs(10),
            modifier_idle_timeout: Duration::from_secs(30),
            chord: Chord::parse("ctrl+option+shift+v").unwrap(),
            pace: Duration::ZERO,
            modifier_wait: Duration::from_secs(5),
            multiline_refuse: false,
            max_chars: 4096,
            queue_room: 8,
        }
    }

    /// The pump's input as Task 4.1 hands it to the input core: this
    /// slot's clipboard words only.
    fn as_event(i: RdpInput, slot: u64) -> Option<Event> {
        match i {
            RdpInput::ClipboardAvailable { slot: s, offer } if s == slot => {
                Some(Event::ClipboardAvailable(offer.text()))
            }
            RdpInput::ClipboardText { slot: s, bytes, .. } if s == slot => {
                Some(Event::ClipboardText(bytes))
            }
            _ => None,
        }
    }

    /// Step every clipboard word the backend has sent into `core`.
    fn feed(core: &mut InputCore, rx: &mut UnboundedReceiver<RdpInput>, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        while let Ok(i) = rx.try_recv() {
            if let Some(e) = as_event(i, 1) {
                core.step(&ctx(now), e, &mut out);
            }
        }
        out
    }

    /// The keyboard usages the outs pressed, in order.
    fn typed(out: &[Out]) -> Vec<u8> {
        out.iter()
            .filter_map(|o| match o {
                Out::Push {
                    frame: HidFrame::Keyboard { keys, .. },
                    ..
                } if keys[0] != 0 => Some(keys[0]),
                _ => None,
            })
            .collect()
    }

    /// The request/response path that feeds paste (§8, DD4), a real
    /// client's bytes into the real core: a response types only for the
    /// paste that asked for it. One sent before any chord types nothing;
    /// one sent while the asking paste already has its text does not
    /// replace it; one after the paste ended types nothing. The answer's
    /// NUL terminator is never typed as a Return (D4).
    #[test]
    fn a_response_types_only_for_the_paste_that_asked() {
        let (f, _slot, mut rx) = factory();
        let mut w = Wire::start(&f, Some(utf16z("hi")));
        let mut core = InputCore::new();
        let _ = core.on_generation(1);
        let mut now = Instant::now();
        let mut out = feed(&mut core, &mut rx, now); // the format list: text
        w.unasked(utf16z("zz"));
        assert!(
            typed(&feed(&mut core, &mut rx, now)).is_empty(),
            "unasked text typed"
        );

        for code in [0x1D, 0x38, 0x2A, 0x2F] {
            core.step(
                &ctx(now),
                Event::KeyPressed {
                    code,
                    extended: false,
                },
                &mut out,
            );
        }
        assert!(out.iter().any(|o| matches!(o, Out::RequestClipboard)));
        w.request_text(); // what Task 4.1 does with `Out::RequestClipboard`
        assert_eq!(w.state.lock().unwrap().asked, 1);
        out.extend(feed(&mut core, &mut rx, now));
        w.unasked(utf16z("zz")); // the paste has its text already
        out.extend(feed(&mut core, &mut rx, now));
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            core.step(
                &ctx(now),
                Event::KeyReleased {
                    code,
                    extended: false,
                },
                &mut out,
            );
        }
        let ended = |out: &[Out]| {
            out.iter()
                .filter(|o| matches!(o, Out::Paste(p) if *p != PasteOutcome::Started))
                .count()
        };
        // Pace 0 and room for 8 may type it all in the last release's step.
        for _ in 0..16 {
            if ended(&out) > 0 {
                break;
            }
            now += Duration::from_millis(1);
            core.step(&ctx(now), Event::Tick, &mut out);
        }
        assert!(
            out.iter().any(|o| matches!(
                o,
                Out::Paste(PasteOutcome::Done {
                    typed: 2,
                    skipped: 0
                })
            )),
            "the paste did not type its two characters: {out:?}"
        );
        assert_eq!(ended(&out), 1);
        // h = 0x0B, i = 0x0C; never z (0x1D) or Return (0x28).
        assert_eq!(typed(&out), [0x0B, 0x0C]);
        w.unasked(utf16z("zz")); // a late answer
        assert!(
            typed(&feed(&mut core, &mut rx, now)).is_empty(),
            "a late answer typed"
        );
    }
}
