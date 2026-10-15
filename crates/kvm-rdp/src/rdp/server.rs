//! The `RdpServer` (§5.1, §9.1): NLA only — `with_hybrid` over our own
//! rustls config and the certificate's CredSSP key; the builder's other
//! security modes (`with_tls`, `with_no_security`) are never called — with
//! Preempt, the callbacks of Task 5.2 (the connection handler installed:
//! without one IronRDP admits every connection), the suppression and RTT
//! handles the shell samples, auto-detect enabled (§6.6), and CLIPRDR for
//! paste (§8).
use crate::config::Secret;
use crate::rdp::clipboard::ClipFactory;
use crate::rdp::display::BridgeDisplay;
use crate::rdp::gfx::GfxFactory;
use crate::rdp::handler::Lifecycle;
use crate::rdp::input::InputHandler;
use crate::rdp::tls::TlsIdentity;
use ironrdp_server::{ConnectionPolicy, Credentials, RdpServer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32};

pub struct ServerParts {
    pub listen: SocketAddr,
    pub tls: TlsIdentity,
    pub username: String,
    pub password: Secret,
    pub input: InputHandler,
    pub display: BridgeDisplay,
    pub gfx: GfxFactory,
    /// Concrete, as `gfx` is: `CliprdrServerFactory` has no `Send`
    /// supertrait, and these parts move to the RDP thread (D1d). Boxed
    /// only in `build`, on that thread.
    pub cliprdr: ClipFactory,
    pub lifecycle: Lifecycle,
    pub suppressed: Arc<AtomicBool>,
    pub rtt: Arc<AtomicU32>,
}

/// Build the server on the RDP runtime's thread (`RdpServer` is `!Send`).
#[must_use]
pub fn build(p: ServerParts) -> RdpServer {
    let TlsIdentity {
        acceptor,
        public_key,
        ..
    } = p.tls;
    let mut server = RdpServer::builder()
        .with_addr(p.listen)
        .with_hybrid(acceptor, public_key)
        .with_input_handler(p.input)
        .with_display_handler(p.display)
        .with_gfx_factory(Some(Box::new(p.gfx)))
        .with_cliprdr_factory(Some(Box::new(p.cliprdr)))
        .with_connection_policy(ConnectionPolicy::Preempt)
        .with_connection_handler(Some(Box::new(p.lifecycle)))
        .with_display_suppressed_handle(p.suppressed)
        .with_autodetect_rtt_handle(p.rtt)
        .build();
    // CredSSP compares the account name exactly and ignores the domain.
    server.set_credentials(Some(Credentials {
        username: p.username,
        password: p.password.expose().to_owned(),
        domain: None,
    }));
    server.enable_autodetect();
    server
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::hid::HidControl;
    use crate::metrics::Metrics;
    use crate::msg::Generations;
    use crate::rdp::accept::{AcceptRate, HANDSHAKE_GRACE, Handshakes};
    use crate::rdp::clipboard::{ClipSlot, ServerEvents};
    use crate::rdp::display::DisplayShared;
    use crate::rdp::gfx::GfxSlot;
    use crate::rdp::input::{InputDeps, InputRuntimeConfig, InputShared};
    use crate::rdp::tls;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// PD8 review m1, D9a in production: the `ServerEvents` cell handed to
    /// the clipboard factory — the bridge's own, which Task 4.1's input
    /// shell reads — holds this server's `event_sender()` once `build`
    /// returns (IronRDP's `set_sender`, inside `RdpServer::new`), not some
    /// other channel and not nothing.
    #[test]
    fn build_fills_the_bridges_own_server_event_cell() {
        tls::install_crypto_provider();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let identity = tls::from_pem(
            ck.cert.pem().as_bytes(),
            ck.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let metrics = Arc::new(Metrics::default());
        let (to_pump, _rdp_inputs) = mpsc::unbounded_channel();
        let (to_kvm, _kvm_cmds) = mpsc::unbounded_channel();
        let gfx_slot = GfxSlot::default();
        let clip_slot = ClipSlot::default();
        let events = ServerEvents::default();
        let input = Arc::new(InputShared::new(InputDeps {
            hid: Arc::new(HidControl::new(16, metrics.clone())),
            display: DisplayShared::new((1024, 768)),
            events: events.clone(),
            gens: Arc::new(Generations::default()),
            metrics: metrics.clone(),
            cfg: InputRuntimeConfig::test(),
        }));
        let parts = ServerParts {
            listen: ([127, 0, 0, 1], 0).into(),
            tls: identity,
            username: "kvm".to_owned(),
            password: Secret::new("l1-test-only-nla-password"),
            input: InputHandler::new(input.clone()),
            display: BridgeDisplay::new(DisplayShared::new((1024, 768)), to_pump.clone()),
            gfx: GfxFactory::new(gfx_slot.clone(), to_pump.clone(), 60, metrics.clone()),
            cliprdr: ClipFactory::new(
                Arc::new(AtomicU64::new(0)),
                clip_slot.clone(),
                to_pump.clone(),
                64 << 10,
                events.clone(),
            ),
            lifecycle: Lifecycle {
                gens: Arc::new(Generations::default()),
                accepting: Arc::new(AtomicBool::new(true)),
                rate: AcceptRate::new(30, Duration::from_secs(60)),
                gfx: gfx_slot,
                clip: clip_slot,
                hid: Arc::new(HidControl::new(16, metrics.clone())),
                metrics,
                to_pump,
                to_kvm,
                handshakes: Arc::new(Handshakes::new(HANDSHAKE_GRACE)),
            },
            suppressed: Arc::new(AtomicBool::new(false)),
            rtt: Arc::new(AtomicU32::new(u32::MAX)),
        };
        assert!(events.get().is_none());
        let server = build(parts);
        let sender = events
            .get()
            .expect("server::build left the bridge's ServerEvents cell empty");
        assert!(sender.same_channel(server.event_sender()));
        // Task 4.1: the input shell sends its paste requests on that cell.
        assert!(
            input
                .events_for_test()
                .get()
                .is_some_and(|s| s.same_channel(server.event_sender()))
        );
    }
}
