//! §11.3 Resolution change, by each of §6.4's three signals.
use crate::client::{Ev, Opts, nal_types, pictures, timeline};
use crate::harness::{P360, P480, T, env, main_360p, sized, source};
use kvm_proto::h264::{parse_sps, split_annex_b};
use kvm_sim::ResizeSignal;

/// DeactivateAll; no EGFX PDU until the reactivated Demand Active; the old
/// surface deleted (IronRDP keeps the connection's `GraphicsPipelineServer`
/// across a reactivation, and `resize_with_monitors` deletes every surface
/// before its ResetGraphics — §11.2's "no DeleteSurface" is the
/// re-advertise rule); ResetGraphics and CreateSurface at the new size; the
/// first KVM AU after is an IDR whose SPS has the new size; login count
/// unchanged; and a second resize in the same session works.
async fn resize_by(signal: ResizeSignal) {
    let env = env(main_360p(), sized).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 5).await;
    for (fixture, (w, h)) in [(P480, (854u16, 480u16)), (P360, (640, 360))] {
        let n = c.with_log(<[Ev]>::len);
        env.sim.switch_source(source(fixture), signal);
        // P44: an EGFX PDU between DeactivateAll and the Demand Active fails
        // the client's reactivation (it reads only activation PDUs then): it
        // surfaces as Ev::Closed("reactivation: …"). So does a connection
        // that ends mid-reactivation. A close — or a disconnect — ends the
        // wait as well, and the assert names it at once instead of after T.
        let ended = |x: &Ev| matches!(x, Ev::Closed(_) | Ev::Terminated(_));
        let evs = c
            .wait_for(T, |e| {
                let new = &e[n..];
                let reactivated = new.iter().position(|x| matches!(x, Ev::Reactivated(..)));
                new.iter().any(ended)
                    || reactivated.is_some_and(|r| !pictures(&new[r..]).is_empty())
            })
            .await;
        let new = &evs[n..];
        assert!(
            !new.iter().any(ended),
            "{signal:?}: {:?} ({:?})",
            timeline(new),
            new.iter().find(|x| ended(x))
        );
        let d = new
            .iter()
            .position(|x| matches!(x, Ev::DeactivateAll))
            .unwrap();
        let r = new
            .iter()
            .position(|x| matches!(x, Ev::Reactivated(..)))
            .unwrap();
        let t = timeline(&new[d..]);
        let want = [
            format!("reactivated {w}x{h}"),
            "delete".to_owned(),
            format!("reset {w}x{h}"),
            format!("surface {w}x{h}"),
            "map".to_owned(),
        ];
        assert_eq!(t[1..6], want, "{signal:?}: {t:?}");
        let first = &pictures(&new[r..])[0];
        assert_eq!(nal_types(&first.annex_b), [7, 8, 5], "{signal:?}");
        let sps = parse_sps(split_annex_b(&first.annex_b).next().unwrap()).unwrap();
        assert_eq!(
            (sps.width, sps.height),
            (u32::from(w), u32::from(h)),
            "{signal:?}"
        );
    }
    assert_eq!(env.logins(), 1, "{signal:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_sequence_header_resizes_twice() {
    resize_by(ResizeSignal::SequenceHeader).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_band_sps_resizes_twice() {
    resize_by(ResizeSignal::InBandSps).await;
}

/// The ES3's observed preset change: the FLV closes; the new one opens at
/// the new size (§6.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_flv_close_at_a_new_size_resizes_twice() {
    resize_by(ResizeSignal::CloseFlv).await;
}
