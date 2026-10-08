//! The pump's vocabulary (§4.3): what the core is told, what it orders.
use crate::config::{Config, IdrPolicy};
use crate::hid::ReleaseTrigger;
use crate::msg::{Cause, FlvOrigin, Gen, KvmAu};
use ironrdp_dvc::DvcMessage;
use kvm_proto::video::{ParamClass, ParamSets};
use std::time::{Duration, Instant};

/// §6.6's gates and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowConfig {
    pub soft_gate: Duration,
    pub backlog_limit: u64,
    pub standing_delay_limit: Duration,
    pub first_ack_grace: Duration,
    pub stall_timeout: Duration,
}

/// §6.5's IDR acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdrConfig {
    pub policy: IdrPolicy,
    pub side_timeout: Duration,
    pub wait_max: Duration,
    pub interval_setup: Duration,
    pub interval_flow: Duration,
}

#[derive(Debug, Clone)]
pub struct PumpConfig {
    /// IronRDP's `max_frames_in_flight`, set at every Setup (§6.6).
    pub hard_cap: u32,
    pub flow: FlowConfig,
    pub idr: IdrConfig,
    pub rtt_probe_interval: Duration,
    pub burst_chunk: u32,
    pub avc420_timeout: Duration,
    pub suppress_debounce: Duration,
    pub disconnect_watchdog: Duration,
    pub region_qp: u8,
}

impl PumpConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> PumpConfig {
        let v = &c.video;
        PumpConfig {
            hard_cap: v.hard_cap_frames(),
            flow: FlowConfig {
                soft_gate: v.soft_gate,
                backlog_limit: v.backlog_limit,
                standing_delay_limit: v.standing_delay_limit,
                first_ack_grace: v.first_ack_grace,
                stall_timeout: v.stall_timeout,
            },
            idr: IdrConfig {
                policy: v.idr_policy,
                side_timeout: v.idr_side_timeout,
                wait_max: v.idr_wait_max,
                interval_setup: v.flv_reconnect_interval_setup,
                interval_flow: v.flv_reconnect_interval_flow,
            },
            rtt_probe_interval: v.rtt_probe_interval,
            burst_chunk: v.burst_chunk,
            avc420_timeout: v.avc420_timeout,
            suppress_debounce: v.suppress_debounce,
            disconnect_watchdog: v.disconnect_watchdog,
            region_qp: v.region_qp,
        }
    }
}

/// §6.4's states; `Idle` means "no generation".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    WaitReady,
    NeedIdr,
    Live,
    WaitReactivation,
    Paused,
    Closing,
}

/// One input to `Pump::step` (§4.3's list, with `Shutdown`).
#[derive(Debug)]
pub enum Input {
    SessionStart {
        generation: Gen,
        size: (u16, u16),
    },
    SessionStop {
        generation: Gen,
    },
    OnReady {
        avc420: bool,
    },
    ReactivationComplete,
    FrameAck {
        frame_id: u32,
        queue_depth: u32,
    },
    Tick,
    /// The display-suppressed flag, sampled (§6.6).
    Suppress(bool),
    SpsChanged {
        class: ParamClass,
        params: ParamSets,
    },
    FlvOpened {
        origin: FlvOrigin,
    },
    Au(KvmAu),
    UpstreamFatal(Cause),
    /// §5.2: close with cause `shutdown` and this watchdog (DC13).
    Shutdown {
        watchdog: Duration,
    },
    /// This generation's write-progress counter (§6.6 backlog gate).
    Backlog {
        written: u64,
    },
    /// The auto-detect RTT handle (ms; `u32::MAX` = no answer).
    Rtt(u32),
}

/// One `ServerEvent::Egfx` worth of drained EGFX PDUs.
pub struct DvcBatch {
    pub channel_id: u32,
    pub messages: Vec<DvcMessage>,
    /// Σ `DvcMessage::size()` (§4.2 patch 2's weight).
    pub weight: u64,
    /// AVC420 frames in the batch (the slate counts, Setup PDUs do not).
    pub frames: u32,
    /// The earliest receive time of a KVM AU in the batch (§10.1).
    pub received: Option<Instant>,
    /// A burst chunk: yield after sending so input interleaves (§6.5).
    pub yield_after: bool,
}

impl std::fmt::Debug for DvcBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DvcBatch")
            .field("channel_id", &self.channel_id)
            .field("messages", &self.messages.len())
            .field("weight", &self.weight)
            .field("frames", &self.frames)
            .field("yield_after", &self.yield_after)
            .finish()
    }
}

/// What the shell carries out (§4.3's list).
#[derive(Debug)]
pub enum Command {
    SendDvc(DvcBatch),
    DisplayResize {
        width: u16,
        height: u16,
    },
    /// Mouse scaling switches to this surface (§6.4, Plan D).
    SurfaceSize {
        width: u16,
        height: u16,
    },
    ReleaseAll(ReleaseTrigger),
    OpenFlv,
    RequestIdr,
    ReconnectFlv,
    /// A deferred IDR request was cancelled (metrics only, DC11).
    CancelIdrRequest,
    ProbeRtt,
    Disconnect(Cause),
    /// The disconnect watchdog fired: stop the KVM side, abort (§6.9).
    Abort,
}

impl Command {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Command::SendDvc(_) => "SendDvc",
            Command::DisplayResize { .. } => "DisplayResize",
            Command::SurfaceSize { .. } => "SurfaceSize",
            Command::ReleaseAll(_) => "ReleaseAll",
            Command::OpenFlv => "OpenFlv",
            Command::RequestIdr => "RequestIdr",
            Command::ReconnectFlv => "ReconnectFlv",
            Command::CancelIdrRequest => "CancelIdrRequest",
            Command::ProbeRtt => "ProbeRtt",
            Command::Disconnect(_) => "Disconnect",
            Command::Abort => "Abort",
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

    #[test]
    fn command_kinds_are_distinct() {
        let all = [
            Command::DisplayResize {
                width: 1,
                height: 1,
            },
            Command::SurfaceSize {
                width: 1,
                height: 1,
            },
            Command::ReleaseAll(ReleaseTrigger::Closing),
            Command::OpenFlv,
            Command::RequestIdr,
            Command::ReconnectFlv,
            Command::CancelIdrRequest,
            Command::ProbeRtt,
            Command::Disconnect(Cause::Shutdown),
            Command::Abort,
            Command::SendDvc(DvcBatch {
                channel_id: 1,
                messages: Vec::new(),
                weight: 0,
                frames: 0,
                received: None,
                yield_after: false,
            }),
        ];
        let mut k: Vec<_> = all.iter().map(Command::kind).collect();
        k.sort_unstable();
        k.dedup();
        assert_eq!(k.len(), all.len());
    }

    #[test]
    fn a_batch_debug_never_dumps_its_payload() {
        let b = DvcBatch {
            channel_id: 7,
            messages: Vec::new(),
            weight: 99,
            frames: 1,
            received: None,
            yield_after: true,
        };
        let s = format!("{b:?}");
        assert!(s.contains("weight: 99") && s.contains("messages: 0"), "{s}");
    }
}
