//! What the RDP side, the pump and the KVM actor say to each other (§4.3),
//! and the generation that tags every word of it: `on_connection_info`
//! begins one, `on_disconnected` ends it before returning, and anything
//! carrying another generation is dropped (DC4).
use ironrdp_pdu::rdp::server_error_info::ProtocolIndependentCode;
use ironrdp_server::{ConnectionAbortHandle, ErrorInfo, GfxServerHandle};
use kvm_proto::video::{AccessUnit, ParamClass, ParamSets};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub type Gen = u64;

#[derive(Debug, Default)]
pub struct Generations {
    current: AtomicU64,
    next: AtomicU64,
}

impl Generations {
    /// A new, never-reused generation, made current.
    pub fn begin(&self) -> Gen {
        let g = self
            .next
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
            .max(1);
        self.current.store(g, Ordering::SeqCst);
        g
    }
    /// Invalidate the current generation; returns it.
    pub fn end(&self) -> Option<Gen> {
        let g = self.current.swap(0, Ordering::SeqCst);
        (g != 0).then_some(g)
    }
    #[must_use]
    pub fn current(&self) -> Option<Gen> {
        let g = self.current.load(Ordering::SeqCst);
        (g != 0).then_some(g)
    }
    #[must_use]
    pub fn is_current(&self, g: Gen) -> bool {
        g != 0 && self.current.load(Ordering::SeqCst) == g
    }
}

/// Why the bridge ends a session (§6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Shutdown,
    KvmUnreachable,
    StreamCorrupt,
    StreamIncompatible,
    NoAvc420,
    ClientStalled,
    ClipboardOversize,
    KvmAuthFailed,
    KvmCertMismatch,
}

impl Cause {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Cause::Shutdown => "shutdown",
            Cause::KvmUnreachable => "kvm_unreachable",
            Cause::StreamCorrupt => "stream_corrupt",
            Cause::StreamIncompatible => "stream_incompatible",
            Cause::NoAvc420 => "no_avc420",
            Cause::ClientStalled => "client_stalled",
            Cause::ClipboardOversize => "clipboard_oversize",
            Cause::KvmAuthFailed => "kvm_auth_failed",
            Cause::KvmCertMismatch => "kvm_cert_mismatch",
        }
    }

    /// MS-RDPBCGR 2.2.5.1.1 server-initiated codes, so clients do not
    /// auto-reconnect into a loop (§6.9).
    #[must_use]
    pub fn error_info(self) -> ErrorInfo {
        use ProtocolIndependentCode as P;
        ErrorInfo::ProtocolIndependentCode(match self {
            Cause::Shutdown => P::RpcInitiatedDisconnect,
            Cause::KvmAuthFailed | Cause::KvmCertMismatch => P::ServerInsufficientPrivileges,
            Cause::KvmUnreachable
            | Cause::StreamCorrupt
            | Cause::StreamIncompatible
            | Cause::NoAvc420
            | Cause::ClientStalled
            | Cause::ClipboardOversize => P::ServerDeniedConnection,
        })
    }
}

/// Why an FLV connection opened (§4.3 `FlvOpened`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlvOrigin {
    /// The first Setup's `OpenFlv`.
    First,
    /// A reconnect after the FLV was lost (§6.9 transient).
    Transient,
    /// A `ReconnectFlv` (make-before-break).
    Commanded,
}

impl FlvOrigin {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            FlvOrigin::First => "first",
            FlvOrigin::Transient => "transient",
            FlvOrigin::Commanded => "commanded",
        }
    }
}

/// One admitted access unit on its way to the pump.
#[derive(Debug, Clone)]
pub struct KvmAu {
    pub au: AccessUnit,
    /// An earlier AU was dropped on a full channel: a flow cause (DC12).
    pub after_drop: bool,
    /// When its tag was parsed (the enqueue-latency start, §10.1).
    pub received: Instant,
}

/// KVM → pump, on the one ordered, bounded stream (§4.3).
#[derive(Debug)]
pub enum KvmEvent {
    FlvOpened {
        generation: Gen,
        origin: FlvOrigin,
    },
    SpsChanged {
        generation: Gen,
        class: ParamClass,
        params: ParamSets,
    },
    Au {
        generation: Gen,
        au: KvmAu,
    },
    UpstreamFatal {
        generation: Gen,
        cause: Cause,
    },
}

impl KvmEvent {
    #[must_use]
    pub fn generation(&self) -> Gen {
        match self {
            KvmEvent::FlvOpened { generation, .. }
            | KvmEvent::SpsChanged { generation, .. }
            | KvmEvent::Au { generation, .. }
            | KvmEvent::UpstreamFatal { generation, .. } => *generation,
        }
    }
}

/// RDP side and pump → the KVM actor (unbounded: lifecycle and
/// rate-limited IDR commands only).
#[derive(Debug)]
pub enum KvmCommand {
    Start {
        generation: Gen,
    },
    Stop {
        generation: Gen,
        done: Option<oneshot::Sender<()>>,
    },
    OpenFlv {
        generation: Gen,
    },
    RequestIdr {
        generation: Gen,
    },
    ReconnectFlv {
        generation: Gen,
    },
    /// Write any pending release-all now (shutdown, §5.2).
    FlushHid {
        done: oneshot::Sender<()>,
    },
    /// Close everything (never a logout) and stop the actor.
    Shutdown {
        done: oneshot::Sender<()>,
    },
}

/// IronRDP's callbacks → the pump (unbounded: they run under the GFX lock
/// and may only push, §4.3). `slot` names the GFX handle — or, for the
/// clipboard's words, the CLIPRDR backend — a callback came from; a stale
/// slot is dropped.
pub enum RdpInput {
    SessionStart {
        generation: Gen,
        slot: u64,
        gfx: GfxServerHandle,
        counter: Arc<AtomicU64>,
        abort: ConnectionAbortHandle,
        /// This connection's CLIPRDR backend (`rdp::clipboard`), bound with
        /// its GFX handle; `None` if none was built.
        clip_slot: Option<u64>,
    },
    SessionStop {
        generation: Gen,
    },
    CapsAdvertised {
        slot: u64,
        sets: Vec<String>,
    },
    OnReady {
        slot: u64,
        version: u32,
    },
    FrameAck {
        slot: u64,
        frame_id: u32,
        queue_depth: u32,
    },
    /// The slot's EGFX channel closed (`GraphicsPipelineHandler::on_close`;
    /// PC11 n2). A client's mid-session DVC Close and every connection's
    /// teardown both run it; the shell tells them apart with
    /// `rdp::gfx::closed_channel_input`.
    GfxClosed {
        slot: u64,
    },
    /// The client's format list said whether CF_UNICODETEXT is on its
    /// clipboard (§8 step 1, D18): the input core's availability (D9c).
    ClipboardAvailable {
        slot: u64,
        text: bool,
    },
    /// A clipboard response's CF_UNICODETEXT bytes, at most
    /// `paste.max_bytes` (§8). As sensitive as a password: never logged,
    /// never Debug-formatted (§9.2) — this enum's `Debug` names the variant
    /// only.
    ClipboardText {
        slot: u64,
        bytes: Vec<u8>,
    },
    /// The slot's session must end with `cause` (`clipboard_oversize`,
    /// §8): the shell steps it as `Input::UpstreamFatal` for its current
    /// generation only, and the pump's `close` counts it (D17).
    Fatal {
        slot: u64,
        cause: Cause,
    },
    /// `RdpServerDisplay::updates()` ran: an activation or reactivation.
    Updates,
    /// Close the live session with cause `shutdown` (§5.2).
    Shutdown {
        done: oneshot::Sender<()>,
    },
    /// Test hook: block the RDP runtime (L2 `/livez`).
    #[doc(hidden)]
    Stall(Duration),
    /// Test hook (PC15 review m5): the pump shell panics, as a bug would.
    #[cfg(test)]
    InjectedPanic,
}

impl std::fmt::Debug for RdpInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RdpInput::SessionStart { .. } => "SessionStart",
            RdpInput::SessionStop { .. } => "SessionStop",
            RdpInput::CapsAdvertised { .. } => "CapsAdvertised",
            RdpInput::OnReady { .. } => "OnReady",
            RdpInput::FrameAck { .. } => "FrameAck",
            RdpInput::GfxClosed { .. } => "GfxClosed",
            RdpInput::ClipboardAvailable { .. } => "ClipboardAvailable",
            RdpInput::ClipboardText { .. } => "ClipboardText",
            RdpInput::Fatal { .. } => "Fatal",
            RdpInput::Updates => "Updates",
            RdpInput::Shutdown { .. } => "Shutdown",
            RdpInput::Stall(_) => "Stall",
            #[cfg(test)]
            RdpInput::InjectedPanic => "InjectedPanic",
        };
        f.write_str(name)
    }
}

/// The KVM→pump channel's capacity: at least the hard cap (§4.3, DC14).
#[must_use]
pub fn kvm_stream_capacity(hard_cap_frames: u32) -> usize {
    usize::try_from(hard_cap_frames)
        .unwrap_or(4096)
        .saturating_add(8)
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
    use ironrdp_pdu::rdp::server_error_info::ProtocolIndependentCode as P;

    const ALL: [Cause; 9] = [
        Cause::Shutdown,
        Cause::KvmUnreachable,
        Cause::StreamCorrupt,
        Cause::StreamIncompatible,
        Cause::NoAvc420,
        Cause::ClientStalled,
        Cause::ClipboardOversize,
        Cause::KvmAuthFailed,
        Cause::KvmCertMismatch,
    ];

    /// §6.9's ErrorInfo table, one row per cause.
    #[test]
    fn every_cause_maps_to_its_errorinfo() {
        for c in ALL {
            let code = c.error_info();
            let ok = match c {
                Cause::Shutdown => matches!(
                    code,
                    ErrorInfo::ProtocolIndependentCode(P::RpcInitiatedDisconnect)
                ),
                Cause::KvmAuthFailed | Cause::KvmCertMismatch => {
                    matches!(
                        code,
                        ErrorInfo::ProtocolIndependentCode(P::ServerInsufficientPrivileges)
                    )
                }
                _ => matches!(
                    code,
                    ErrorInfo::ProtocolIndependentCode(P::ServerDeniedConnection)
                ),
            };
            assert!(ok, "{c:?} → {code:?}");
        }
        let mut labels: Vec<_> = ALL.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL.len());
    }

    #[test]
    fn generations_begin_end_and_never_reuse() {
        let g = Generations::default();
        assert_eq!(g.current(), None);
        let a = g.begin();
        assert!(a != 0 && g.is_current(a));
        assert_eq!(g.end(), Some(a));
        assert!(!g.is_current(a) && g.end().is_none());
        let b = g.begin();
        assert!(b > a && g.is_current(b) && !g.is_current(0));
    }

    #[test]
    fn the_kvm_stream_holds_at_least_the_hard_cap() {
        assert_eq!(kvm_stream_capacity(60), 68);
    }
}
