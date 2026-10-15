//! The §5.1 lifecycle as IronRDP's `ConnectionHandler`. `on_accept` runs
//! before anything else (the accept rate; refuse once shutdown began,
//! DC13); `on_connection_info` — once per connection, after NLA — mints
//! the generation, binds it to this connection's GFX handle, CLIPRDR
//! backend and abort handle, and starts the KVM side; `on_disconnected`
//! ends the generation before it returns. Under Preempt the evicted
//! session's `on_disconnected` runs before the winner's
//! `on_connection_info`. Nothing here calls into IronRDP with a lock held:
//! the GFX and clipboard slots' locks are released before the abort handle
//! or a channel is touched.
use crate::hid::{HidControl, ReleaseTrigger};
use crate::metrics::Metrics;
use crate::msg::{Generations, KvmCommand, RdpInput};
use crate::rdp::accept::{AcceptRate, Handshakes};
use crate::rdp::clipboard::{ClipSlot, take_latest_clip};
use crate::rdp::gfx::{GfxSlot, take_latest};
use ironrdp_server::{ConnectionHandler, ConnectionInfo, PostConnectionAction, ServerError};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

pub struct Lifecycle {
    pub gens: Arc<Generations>,
    /// Cleared when shutdown begins (§5.2, DC13).
    pub accepting: Arc<AtomicBool>,
    pub rate: AcceptRate,
    pub gfx: GfxSlot,
    /// The latest CLIPRDR backend's slot (`rdp::clipboard::ClipFactory`).
    pub clip: ClipSlot,
    pub hid: Arc<HidControl>,
    pub metrics: Arc<Metrics>,
    pub to_pump: UnboundedSender<RdpInput>,
    pub to_kvm: UnboundedSender<KvmCommand>,
    /// Connections admitted and not yet in a session or gone (DC21, m4).
    pub handshakes: Arc<Handshakes>,
}

impl ConnectionHandler for Lifecycle {
    fn on_accept(&mut self, _peer: SocketAddr) -> bool {
        if !self.accepting.load(Ordering::SeqCst) {
            self.metrics.accept_refused.inc();
            return false;
        }
        let now = Instant::now();
        if !self.rate.admit(now) {
            self.metrics.accept_refused.inc();
            // One line now, then at most one per interval (m8).
            if let Some(refused) = self.rate.refusal_report(now) {
                tracing::warn!(
                    refused,
                    "security.accept_rate exceeded; refusing connections"
                );
            }
            return false;
        }
        // DC21 (m4): a client from here until its session begins or it goes.
        self.handshakes.admit(now);
        true
    }

    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        let abort = info.abort_handle();
        if !self.accepting.load(Ordering::SeqCst) {
            // Finished NLA after shutdown began — a Preempt winner, or a
            // fresh connection accepted just before: never start the KVM
            // side. Dropped without ErrorInfo (P32, DC13): the exiting
            // bridge cannot serve its auto-reconnect; the restarted one can.
            abort.abort();
            return;
        }
        let Some((slot, gfx)) = take_latest(&self.gfx) else {
            tracing::error!("no EGFX handle was built for this connection; aborting it");
            abort.abort();
            return;
        };
        // Built beside the GFX handle in `attach_channels`, so it is this
        // connection's (§4.3): its words reach the session only under it.
        let clip_slot = take_latest_clip(&self.clip);
        let generation = self.gens.begin();
        // After `begin`: the certificate watcher reads the handshakes first,
        // so it never sees this client in neither (DC21, m4). An aborted
        // connection (above) is finished by `on_disconnected` instead.
        self.handshakes.finish();
        self.metrics.sessions.inc();
        self.hid.release_all(ReleaseTrigger::SessionStart);
        let counter = Arc::new(AtomicU64::new(0));
        let _ = self.to_pump.send(RdpInput::SessionStart {
            generation,
            slot,
            gfx,
            counter,
            abort,
            clip_slot,
        });
        let _ = self.to_kvm.send(KvmCommand::Start { generation });
        tracing::info!(generation, "session start");
    }

    fn on_disconnected(
        &mut self,
        _peer: SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        if let Some(generation) = self.gens.end() {
            self.hid.release_all(ReleaseTrigger::SessionEnd);
            let _ = self.to_pump.send(RdpInput::SessionStop { generation });
            let _ = self.to_kvm.send(KvmCommand::Stop {
                generation,
                done: None,
            });
            tracing::info!(
                generation,
                secs = duration.as_secs(),
                error = error.is_some(),
                "session end"
            );
        } else {
            // It went before a session began: NLA failed, it was aborted,
            // or the peer left mid-handshake (DC21, m4).
            self.handshakes.finish();
        }
        PostConnectionAction::Continue
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
    use crate::msg::Cause;
    use crate::pump::rig::{census_caps, cfg};
    use crate::pump::{Command, Input, Pump, State};
    use crate::rdp::accept::HANDSHAKE_GRACE;
    use crate::rdp::clipboard::{ClipFactory, ServerEvents};
    use crate::rdp::gfx::{GfxFactory, closed_channel_input};
    use ironrdp_cliprdr::backend::CliprdrBackendFactory as _;
    use ironrdp_core::encode_vec;
    use ironrdp_dvc::DvcProcessor as _;
    use ironrdp_egfx::pdu::{
        CapabilitiesAdvertisePdu, FrameAcknowledgePdu, GfxPdu, QoeFrameAcknowledgePdu, QueueDepth,
    };
    use ironrdp_pdu::gcc::KeyboardType;
    use ironrdp_server::{GfxServerFactory as _, GfxServerHandle};
    use tokio::sync::mpsc;

    struct Rig {
        h: Lifecycle,
        factory: GfxFactory,
        /// The clipboard factory, over `h.clip` and the pump's channel.
        clips: ClipFactory,
        pump: mpsc::UnboundedReceiver<RdpInput>,
        kvm: mpsc::UnboundedReceiver<KvmCommand>,
        metrics: Arc<Metrics>,
        hid: Arc<HidControl>,
        gens: Arc<Generations>,
        accepting: Arc<AtomicBool>,
        handshakes: Arc<Handshakes>,
    }

    fn rig(rate: u32) -> Rig {
        let handshakes = Arc::new(Handshakes::new(HANDSHAKE_GRACE));
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(16, metrics.clone()));
        let gens = Arc::new(Generations::default());
        let accepting = Arc::new(AtomicBool::new(true));
        let latest = GfxSlot::default();
        let (ptx, pump) = mpsc::unbounded_channel();
        let (ktx, kvm) = mpsc::unbounded_channel();
        let factory = GfxFactory::new(latest.clone(), ptx.clone(), 60, metrics.clone());
        let clip = ClipSlot::default();
        let clips = clip_factory(&clip, &ptx);
        let h = Lifecycle {
            gens: gens.clone(),
            accepting: accepting.clone(),
            rate: AcceptRate::new(rate, Duration::from_secs(60)),
            gfx: latest,
            clip,
            hid: hid.clone(),
            metrics: metrics.clone(),
            to_pump: ptx,
            to_kvm: ktx,
            handshakes: handshakes.clone(),
        };
        Rig {
            h,
            factory,
            clips,
            pump,
            kvm,
            metrics,
            hid,
            gens,
            accepting,
            handshakes,
        }
    }

    /// A clipboard factory recording into `latest`, pushing to `to_pump`.
    fn clip_factory(latest: &ClipSlot, to_pump: &UnboundedSender<RdpInput>) -> ClipFactory {
        ClipFactory::new(
            Arc::new(AtomicU64::new(0)),
            latest.clone(),
            to_pump.clone(),
            64 << 10,
            ServerEvents::default(),
        )
    }

    fn info() -> ConnectionInfo {
        ConnectionInfo::new(0x409, KeyboardType::IBM_ENHANCED, String::new())
    }

    fn peer() -> SocketAddr {
        "127.0.0.2:50000".parse().unwrap()
    }

    fn advertise() -> Vec<u8> {
        encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(
            census_caps(),
        )))
        .unwrap()
    }

    /// One pump step under the GFX lock, released before returning (the
    /// shell's discipline: IronRDP's bridge takes the same lock).
    fn step(pump: &mut Pump, gfx: &GfxServerHandle, input: Input) -> Vec<Command> {
        let mut g = gfx.lock().unwrap();
        pump.step(&mut g, Instant::now(), input)
    }

    /// Counts WARN events on this thread.
    struct Warnings(Arc<std::sync::atomic::AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(&self, e: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            if *e.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn warnings_during(f: impl FnOnce()) -> usize {
        use tracing_subscriber::layer::SubscriberExt as _;
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sub = tracing_subscriber::registry().with(Warnings(n.clone()));
        tracing::subscriber::with_default(sub, f);
        n.load(Ordering::SeqCst)
    }

    /// m8: a TCP flood is not a log flood. Every refusal is counted; the
    /// warning is one line now and then at most one per
    /// `REFUSAL_LOG_INTERVAL` (the loop takes milliseconds).
    #[test]
    fn a_refused_flood_is_counted_in_full_and_logged_in_a_line_or_two() {
        let mut r = rig(2);
        let lines = warnings_during(|| {
            for _ in 0..1000 {
                r.h.on_accept(peer());
            }
        });
        assert_eq!(r.metrics.accept_refused.get(), 998);
        assert!(
            (1..=2).contains(&lines),
            "{lines} warning lines for 998 refusals"
        );
    }

    /// §5.1, DC4: the generation is minted, bound to the GFX handle built
    /// for this connection (the latest), and handed to the pump
    /// (`SessionStart`, with that handle) and to the KVM side (`Start`);
    /// release-all runs first (session start). The order of the two sends
    /// is not observable here — they are two channels (m3). The code sends
    /// `SessionStart` first; that no KVM event overtakes its session's
    /// start rests on the shell's `biased` select and its sharing the RDP
    /// thread with this callback (DC4, Task 5.3).
    #[test]
    fn connection_info_begins_a_generation_bound_to_the_latest_gfx_handle() {
        let mut r = rig(30);
        let (_, first) = r.factory.build_server_with_handle().unwrap();
        let (_, second) = r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart {
            generation,
            slot,
            gfx,
            ..
        }) = r.pump.try_recv()
        else {
            panic!("no SessionStart")
        };
        assert_eq!((generation, slot), (1, 2));
        assert!(Arc::ptr_eq(&gfx, &second) && !Arc::ptr_eq(&gfx, &first));
        assert!(matches!(
            r.kvm.try_recv(),
            Ok(KvmCommand::Start { generation: 1 })
        ));
        assert_eq!(r.gens.current(), Some(1));
        assert_eq!(r.metrics.sessions.get(), 1);
        assert_eq!(r.metrics.release_all.get("session_start"), 1);
        assert_eq!(r.hid.epoch(), 1);
    }

    /// §4.3, design decision 8: the CLIPRDR backend built for this
    /// connection — the latest, as for the GFX handle — is bound into its
    /// `SessionStart`, and taken: a connection that had none built gets
    /// none, never an earlier connection's.
    #[test]
    fn connection_info_binds_the_latest_clipboard_backend() {
        let mut r = rig(30);
        r.factory.build_server_with_handle().unwrap();
        let _first = r.clips.build_cliprdr_backend();
        let _second = r.clips.build_cliprdr_backend();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart { clip_slot, .. }) = r.pump.try_recv() else {
            panic!("no SessionStart")
        };
        assert_eq!(clip_slot, Some(2));
        r.h.on_disconnected(peer(), Duration::from_secs(1), None);
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::SessionStop { generation: 1 })
        ));
        r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart {
            generation: 2,
            clip_slot,
            ..
        }) = r.pump.try_recv()
        else {
            panic!("no second SessionStart")
        };
        assert_eq!(clip_slot, None, "an earlier connection's backend was bound");
    }

    /// §4.3: `on_disconnected` invalidates the generation before it returns.
    #[test]
    fn disconnect_ends_the_generation_before_returning() {
        let mut r = rig(30);
        r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let _ = (r.pump.try_recv(), r.kvm.try_recv());
        let action = r.h.on_disconnected(peer(), Duration::from_secs(3), None);
        assert_eq!(action, PostConnectionAction::Continue);
        assert_eq!(r.gens.current(), None);
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::SessionStop { generation: 1 })
        ));
        assert!(matches!(
            r.kvm.try_recv(),
            Ok(KvmCommand::Stop {
                generation: 1,
                done: None
            })
        ));
        assert_eq!(r.metrics.release_all.get("session_end"), 1);
        // A connection that never authenticated touches nothing.
        r.h.on_disconnected(peer(), Duration::ZERO, None);
        assert!(r.pump.try_recv().is_err() && r.kvm.try_recv().is_err());
    }

    #[test]
    fn accept_refuses_over_the_rate_and_once_shutdown_begins() {
        let mut r = rig(2);
        assert!(r.h.on_accept(peer()) && r.h.on_accept(peer()));
        assert!(!r.h.on_accept(peer()));
        assert_eq!(r.metrics.accept_refused.get(), 1);
        let mut r = rig(30);
        r.accepting.store(false, Ordering::SeqCst);
        assert!(!r.h.on_accept(peer()));
        assert_eq!(r.metrics.accept_refused.get(), 1);
    }

    /// §5.1 "No KVM traffic before auth": what IronRDP runs before NLA has
    /// validated the credentials — `on_accept`, the channel factory's
    /// `build_server_with_handle` — starts nothing; only
    /// `on_connection_info`, after authentication, does.
    #[test]
    fn nothing_starts_before_authentication() {
        let mut r = rig(30);
        assert!(r.h.on_accept(peer()));
        r.factory.build_server_with_handle().unwrap();
        assert!(r.pump.try_recv().is_err() && r.kvm.try_recv().is_err());
        assert_eq!(r.gens.current(), None);
        assert_eq!((r.metrics.sessions.get(), r.hid.epoch()), (0, 0));
    }

    /// DC13: a connection that wins after shutdown began starts nothing.
    #[test]
    fn a_late_winner_during_shutdown_starts_nothing() {
        let mut r = rig(30);
        r.factory.build_server_with_handle().unwrap();
        r.accepting.store(false, Ordering::SeqCst);
        r.h.on_connection_info(&info());
        assert!(r.pump.try_recv().is_err() && r.kvm.try_recv().is_err());
        assert_eq!(r.gens.current(), None);
    }

    fn in_flight(r: &Rig) -> usize {
        r.handshakes.in_flight(Instant::now())
    }

    /// DC21 (PC15 review m4): a connection is in flight from `on_accept`
    /// until its session begins (`on_connection_info`) or it goes before one
    /// did (`on_disconnected` with no generation) — never counted twice.
    #[test]
    fn a_connection_is_in_flight_from_accept_until_its_session_or_its_end() {
        let mut r = rig(30);
        assert!(r.h.on_accept(peer()));
        assert_eq!(in_flight(&r), 1, "admitted: handshaking");
        r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        assert_eq!(in_flight(&r), 0, "its session began");
        assert!(r.h.on_accept(peer()), "a Preempt candidate");
        r.h.on_disconnected(peer(), Duration::from_secs(5), None);
        assert_eq!(in_flight(&r), 1, "the session's end is not the candidate's");
        r.h.on_disconnected(peer(), Duration::ZERO, None);
        assert_eq!(in_flight(&r), 0, "the candidate failed NLA");
        assert!(!rig_refusing(&mut r));
        assert_eq!(in_flight(&r), 0, "a refused connection is never in flight");
    }

    fn rig_refusing(r: &mut Rig) -> bool {
        r.accepting.store(false, Ordering::SeqCst);
        let admitted = r.h.on_accept(peer());
        r.accepting.store(true, Ordering::SeqCst);
        admitted
    }

    /// DC13 with DC21: a connection aborted in `on_connection_info` (it
    /// finished NLA after stop-accepting) stays in flight until IronRDP
    /// reports its end — not counted finished twice.
    #[test]
    fn an_aborted_connection_is_in_flight_until_it_ends() {
        let mut r = rig(30);
        assert!(r.h.on_accept(peer()));
        r.factory.build_server_with_handle().unwrap();
        r.accepting.store(false, Ordering::SeqCst);
        r.h.on_connection_info(&info());
        assert_eq!(in_flight(&r), 1);
        r.h.on_disconnected(peer(), Duration::ZERO, None);
        assert_eq!(in_flight(&r), 0);
    }

    /// §4.3: the callbacks run with the GFX mutex held and never lock the
    /// handle. Driven through IronRDP's own bridge (which holds the lock
    /// around `process`) on another thread: a relock would deadlock it.
    #[test]
    fn gfx_callbacks_only_push_their_slot_and_never_relock() {
        let mut r = rig(30);
        let (mut bridge, _handle) = r.factory.build_server_with_handle().unwrap();
        let advertise = advertise();
        let ack = encode_vec(&GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::Unavailable,
            frame_id: 9,
            total_frames_decoded: 1,
        }))
        .unwrap();
        let qoe = encode_vec(&GfxPdu::QoeFrameAcknowledge(QoeFrameAcknowledgePdu {
            frame_id: 9,
            timestamp: 0,
            time_diff_se: 1,
            time_diff_dr: 4,
        }))
        .unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            bridge.start(7).unwrap();
            bridge.process(7, &advertise).unwrap();
            bridge.process(7, &ack).unwrap();
            bridge.process(7, &qoe).unwrap();
            bridge.close(7);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a callback relocked the GFX handle");
        let Ok(RdpInput::CapsAdvertised { slot: 1, sets }) = r.pump.try_recv() else {
            panic!("no CapsAdvertised")
        };
        assert_eq!(sets, ["00080004:02000000", "00080105:12000000"]);
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::OnReady {
                slot: 1,
                version: 0x8_0105
            })
        ));
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::FrameAck {
                slot: 1,
                frame_id: 9,
                queue_depth: 0
            })
        ));
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::GfxClosed { slot: 1 })
        ));
        assert_eq!(r.metrics.qoe_decode.count(), 1, "QoE decode time (§10.4)");
        // The decode-and-render field (`time_diff_dr`, 4 ms), not the
        // encode one (`time_diff_se`, 1 ms) (m7).
        let text = r.metrics.render();
        assert!(
            text.lines()
                .any(|l| l == "kvm_rdp_egfx_qoe_decode_seconds_sum 0.004"),
            "{}",
            text.lines()
                .filter(|l| l.contains("qoe"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// PC11 n2: a client that closes its EGFX channel mid-session reaches
    /// the pump at once, not at its next Setup. `on_close` pushes the slot,
    /// the shell steps `closed_channel_input`, and the core closes with the
    /// cause a refused Setup gets (m7, `no_avc420`) — from NeedIdr, where
    /// nothing else would notice until the next resize or flow window.
    #[test]
    fn a_mid_session_egfx_close_reaches_the_pump_at_once() {
        let mut r = rig(30);
        let (mut bridge, _) = r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart {
            generation,
            slot,
            gfx,
            ..
        }) = r.pump.try_recv()
        else {
            panic!("no SessionStart")
        };
        let mut pump = Pump::new(cfg(), r.metrics.clone());
        step(
            &mut pump,
            &gfx,
            Input::SessionStart {
                generation,
                size: (640, 360),
            },
        );
        bridge.start(7).unwrap();
        bridge.process(7, &advertise()).unwrap();
        while let Ok(i) = r.pump.try_recv() {
            assert!(
                matches!(
                    i,
                    RdpInput::CapsAdvertised { .. } | RdpInput::OnReady { .. }
                ),
                "{i:?}"
            );
        }
        let out = step(&mut pump, &gfx, Input::OnReady { avc420: true });
        assert!(out.iter().any(|c| matches!(c, Command::OpenFlv)));
        assert_eq!(pump.state(), State::NeedIdr);

        bridge.close(7); // the client's DVC Close PDU
        let Ok(RdpInput::GfxClosed { slot: closed }) = r.pump.try_recv() else {
            panic!("the EGFX close never reached the pump")
        };
        assert_eq!(closed, slot);
        let input =
            closed_channel_input(&r.gens, generation).expect("a live session's close is a cause");
        let out = step(&mut pump, &gfx, input);
        assert_eq!(pump.state(), State::Closing);
        let causes: Vec<_> = out
            .iter()
            .filter_map(|c| match c {
                Command::Disconnect(cause) => Some(*cause),
                _ => None,
            })
            .collect();
        assert_eq!(causes, [Cause::NoAvc420]);
        assert_eq!(r.metrics.disconnects.get("no_avc420"), 1);
    }

    /// IronRDP drops a connection's channels — running `on_close` — just
    /// before `on_disconnected`, with no await between on its normal paths
    /// (`RdpServer::run`, `run_connection_with`; the one accepted window is
    /// on `closed_channel_input`). That close is every session's, not a
    /// cause: by the time the pump reads it the generation has ended.
    #[test]
    fn the_close_every_teardown_runs_is_not_a_cause() {
        let mut r = rig(30);
        let (mut bridge, _) = r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        let Ok(RdpInput::SessionStart { generation, .. }) = r.pump.try_recv() else {
            panic!("no SessionStart")
        };
        bridge.start(7).unwrap();
        bridge.close(7);
        r.h.on_disconnected(peer(), Duration::from_secs(1), None);
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::GfxClosed { slot: 1 })
        ));
        assert!(matches!(
            r.pump.try_recv(),
            Ok(RdpInput::SessionStop { generation: 1 })
        ));
        assert!(
            closed_channel_input(&r.gens, generation).is_none(),
            "a teardown's close closed the session"
        );
        // Nor is the evicted session's, once the Preempt winner is current.
        r.factory.build_server_with_handle().unwrap();
        r.h.on_connection_info(&info());
        assert!(closed_channel_input(&r.gens, generation).is_none());
        assert!(closed_channel_input(&r.gens, generation + 1).is_some());
    }

    /// m2: the two `abort()` calls in `on_connection_info`, observed through
    /// a real connection. `ConnectionInfo::new`'s handle is inert, so these
    /// drive a real IronRDP client through TLS and NLA into a real
    /// `RdpServer` built as the bridge builds it (`with_hybrid` and our
    /// `TlsIdentity`). Loopback only; every wait is bounded.
    mod real_client {
        use super::*;
        use crate::rdp::display::{BridgeDisplay, DisplayShared};
        use crate::rdp::input::InputStub;
        use crate::rdp::tls;
        use ironrdp_pdu::gcc;
        use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
        use ironrdp_server::{Credentials, RdpServer, ServerResult};
        use std::future::Future;
        use tokio::net::{TcpListener, TcpStream};

        const USER: &str = "kvm";
        /// Test-only, never a deployed secret (≥ 22 characters, §9.1).
        const PASSWORD: &str = "l1-test-only-nla-password";
        /// A served connection that outlives this is not being aborted.
        const SERVE_BOUND: Duration = Duration::from_secs(5);

        fn client_config() -> ironrdp_connector::Config {
            ironrdp_connector::Config {
                desktop_size: ironrdp_connector::DesktopSize {
                    width: 1024,
                    height: 768,
                },
                monitor_layout: None,
                desktop_scale_factor: 0,
                enable_tls: true,
                enable_credssp: true,
                enable_standard_rdp_security: false,
                credentials: ironrdp_connector::Credentials::UsernamePassword {
                    username: USER.into(),
                    password: PASSWORD.into(),
                },
                domain: None,
                client_build: 0,
                client_name: "kvm-rdp-l1".into(),
                keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
                keyboard_subtype: 0,
                keyboard_functional_keys_count: 12,
                keyboard_layout: 0,
                connection_type: gcc::ConnectionType::Lan,
                ime_file_name: String::new(),
                bitmap: None,
                dig_product_id: String::new(),
                client_dir: String::new(),
                alternate_shell: String::new(),
                work_dir: String::new(),
                remote_application_mode: false,
                rail_support_level: RailSupportLevel::SUPPORTED,
                platform: MajorPlatformType::UNIX,
                hardware_id: None,
                request_data: None,
                autologon: false,
                enable_audio_playback: false,
                enable_audio_capture: false,
                performance_flags: Default::default(),
                license_cache: None,
                timezone_info: Default::default(),
                compression_type: None,
                enable_server_pointer: false,
                pointer_software_rendering: true,
                multitransport_flags: None,
                support_dyn_vc_gfx_protocol: false,
            }
        }

        /// Connect through TLS and NLA and hold the transport open whatever
        /// the outcome: an aborted connection fails `connect_finalize`, but
        /// the server must not be able to end by the client leaving.
        async fn connect_and_hold(
            addr: std::net::SocketAddr,
        ) -> Option<ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>> {
            let tcp = TcpStream::connect(addr).await.ok()?;
            let client_addr = tcp.local_addr().ok()?;
            let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
            let mut connector =
                ironrdp_connector::ClientConnector::new(client_config(), client_addr);
            let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
                .await
                .ok()?;
            let (tls, cert) = ironrdp_tls::upgrade_with_certificate_validation(
                framed.into_inner_no_leftover(),
                "localhost",
                ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate,
            )
            .await
            .ok()?;
            let upgraded = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
            let mut framed = ironrdp_tokio::TokioFramed::new(tls);
            let key = ironrdp_tls::extract_tls_server_public_key(&cert)?.to_owned();
            let _ = ironrdp_async::connect_finalize(
                upgraded,
                connector,
                &mut framed,
                &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
                "localhost".into(),
                key,
                None,
            )
            .await;
            Some(framed)
        }

        /// Serve one real client with `lifecycle` (and `gfx` and `clip`, if
        /// any) while `watch` runs. `Some(result)` when the server ended
        /// within `SERVE_BOUND` although the client held the connection
        /// open — an abort — and `None` when it was still serving.
        async fn serve_one(
            lifecycle: Lifecycle,
            gfx: Option<GfxFactory>,
            clip: Option<ClipFactory>,
            watch: impl Future<Output = ()>,
        ) -> Option<ServerResult<()>> {
            tls::install_crypto_provider();
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let id = tls::from_pem(
                ck.cert.pem().as_bytes(),
                ck.key_pair.serialize_pem().as_bytes(),
            )
            .unwrap();
            let (display_tx, _display_rx) = mpsc::unbounded_channel();
            let metrics = lifecycle.metrics.clone();
            let mut server = RdpServer::builder()
                .with_addr(([127, 0, 0, 1], 0))
                .with_hybrid(id.acceptor, id.public_key)
                .with_input_handler(InputStub::new(metrics))
                .with_display_handler(BridgeDisplay::new(
                    DisplayShared::new((1024, 768)),
                    display_tx,
                ))
                .with_connection_handler(Some(Box::new(lifecycle)))
                .with_gfx_factory(
                    gfx.map(|g| -> Box<dyn ironrdp_server::GfxServerFactory> { Box::new(g) }),
                )
                .with_cliprdr_factory(
                    clip.map(|c| -> Box<dyn ironrdp_server::CliprdrServerFactory> { Box::new(c) }),
                )
                .build();
            server.set_credentials(Some(Credentials {
                username: USER.into(),
                password: PASSWORD.into(),
                domain: None,
            }));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let serve = async {
                let (stream, _) = tokio::time::timeout(SERVE_BOUND, listener.accept())
                    .await
                    .expect("the client never connected")
                    .unwrap();
                // `run_connection` skips `on_accept` (only `run()`'s accept
                // loop calls it): the connection was admitted before.
                tokio::time::timeout(SERVE_BOUND, server.run_connection(stream))
                    .await
                    .ok()
            };
            let client = tokio::time::timeout(SERVE_BOUND, connect_and_hold(addr));
            let (served, held, ()) = tokio::join!(serve, client, watch);
            drop(held);
            served
        }

        /// The lifecycle under test, its receivers, and the shared state.
        fn lifecycle() -> (
            Lifecycle,
            mpsc::UnboundedReceiver<RdpInput>,
            mpsc::UnboundedReceiver<KvmCommand>,
            Arc<Generations>,
        ) {
            let r = rig(30);
            (r.h, r.pump, r.kvm, r.gens)
        }

        /// K8 / P32: a connection that finishes NLA after stop-accepting is
        /// aborted, and nothing starts. Without the abort it would sit with
        /// no KVM side and need its own `Quit`.
        #[tokio::test(flavor = "current_thread")]
        async fn a_connection_finishing_nla_after_stop_accepting_is_aborted() {
            let (h, mut pump, mut kvm, gens) = lifecycle();
            h.accepting.store(false, Ordering::SeqCst);
            let gfx = GfxFactory::new(h.gfx.clone(), h.to_pump.clone(), 60, h.metrics.clone());
            let served = serve_one(h, Some(gfx), None, async {}).await;
            assert!(
                matches!(served, Some(Ok(()))),
                "the connection was not aborted (still served after {SERVE_BOUND:?}, or failed before NLA)"
            );
            assert!(pump.try_recv().is_err() && kvm.try_recv().is_err());
            assert_eq!(gens.current(), None);
        }

        /// K9: a connection for which no EGFX handle was built is aborted
        /// rather than left with no pump.
        #[tokio::test(flavor = "current_thread")]
        async fn a_connection_without_an_egfx_handle_is_aborted() {
            let (h, mut pump, mut kvm, gens) = lifecycle();
            let served = serve_one(h, None, None, async {}).await;
            assert!(
                matches!(served, Some(Ok(()))),
                "the connection was not aborted (still served after {SERVE_BOUND:?}, or failed before NLA)"
            );
            assert!(pump.try_recv().is_err() && kvm.try_recv().is_err());
            assert_eq!(gens.current(), None);
        }

        /// The control: the same rig with a GFX factory and `accepting`
        /// starts a session after NLA (§5.1) — so the two cases above reach
        /// `on_connection_info` — and its `SessionStart` carries this
        /// connection's real abort handle, which ends it. With the
        /// clipboard factory installed as the bridge installs it, IronRDP
        /// has built this connection's backend by then (`attach_channels`),
        /// so the session is bound to its slot (design decision 8).
        #[tokio::test(flavor = "current_thread")]
        async fn a_real_client_through_nla_starts_a_session_with_a_live_abort_handle() {
            let (h, mut pump, mut kvm, gens) = lifecycle();
            let gfx = GfxFactory::new(h.gfx.clone(), h.to_pump.clone(), 60, h.metrics.clone());
            let clip = clip_factory(&h.clip, &h.to_pump);
            let mut started = None;
            let watch = async {
                if let Ok(Some(RdpInput::SessionStart {
                    generation,
                    slot,
                    abort,
                    clip_slot,
                    ..
                })) = tokio::time::timeout(SERVE_BOUND, pump.recv()).await
                {
                    started = Some((generation, slot, gens.current(), clip_slot));
                    abort.abort();
                }
            };
            let served = serve_one(h, Some(gfx), Some(clip), watch).await;
            assert_eq!(
                started,
                Some((1, 1, Some(1), Some(1))),
                "no session started after NLA, or not bound to its clipboard backend"
            );
            assert!(
                matches!(served, Some(Ok(()))),
                "the session's abort handle did not end it"
            );
            assert!(matches!(
                kvm.try_recv(),
                Ok(KvmCommand::Start { generation: 1 })
            ));
        }
    }
}
