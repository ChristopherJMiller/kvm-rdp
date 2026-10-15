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
use crate::rdp::input::InputStub;
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
    pub input: InputStub,
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
