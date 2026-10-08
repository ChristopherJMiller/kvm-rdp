//! §11.3 Video oracle (once per `idr_policy`), Side IDR, the POC-0
//! stranding check (§6.8), NO SIGNAL.
//!
//! The oracle is independent of the bridge (§11.1): a received picture is
//! identified by its first slice NAL — byte-identical to one fixture frame,
//! whose index is the frame's barcode — and compared with the
//! `source_index` kvm-sim logged for each AU it sent on the FLV that
//! carried the pictures.
//!
//! The two side-IDR cases run on the long-GOP fixture (IDRs at 0 and 300 of
//! 330 frames). The main FLV's subscription restarts the GOP at 300, and the
//! source wraps to frame 0 a second later. The cases re-advertise only after
//! that second IDR and after the 1 s setup window, so the next periodic IDR
//! is about 9 s away and the only IDR in the window is the one the side FLV
//! (or the fallback's new FLV) forces (P2).
use crate::client::{Client, Ev, Opts, Picture, confirmed, nal_types, pictures, terminated};
use crate::harness::{
    ES3_FIXTURE, Env, LONGGOP, T, assert_run, barcodes, env, es3, flv_opens, index_of, ms, sent_on,
    sized, source, until, within,
};
use kvm_proto::h264::{parse_sps, split_annex_b};
use kvm_rdp::config::IdrPolicy;
use kvm_sim::{Pacing, SimConfig, SimEvent, Timestamps};
use std::time::{Duration, Instant};

/// §11.3, once per `idr_policy` (P9): a re-advertise once the session is
/// past the FLV's 1 s setup window is a Setup cause each policy serves its
/// own way, at once — `side` with a side FLV, `reconnect` with a second main
/// FLV, `wait` with the ES3 fixture's next periodic IDR (≤ 2 s). From the
/// re-advertise's confirm on, the client's pictures are exactly kvm-sim's
/// AUs on the FLV that carried them, in order; each matches §6.3's
/// composition (IDR: SPS, PPS, slice; P: slice); EGFX frame ids are
/// consecutive; the first is an IDR carrying SPS/PPS.
///
/// Deviation from P9's ruling (unsized, served at the connect-time
/// resize): there, a reactivation that completes before the FLV's first
/// IDR lets that IDR resolve the NeedIdr and cancel the deferred request,
/// so no policy ran in 3 of 10 runs (`side` and `reconnect` saw one FLV).
/// How long the oracle waits for kvm-sim's log to catch up with what the
/// client already shows.
const CATCH_UP: Duration = Duration::from_secs(2);

async fn oracle(policy: IdrPolicy) {
    let env = env(es3(), move |c| {
        sized(c);
        c.video.idr_policy = policy;
    })
    .await;
    let c = env.client(Opts::new(2));
    // 45 pictures: 1.5 s after the FLV's first IDR, past its setup window.
    c.wait_for(T, |e| pictures(e).len() >= 45).await;
    let n = c.with_log(<[Ev]>::len);
    c.readvertise();
    let evs = c
        .wait_for(T, |e| {
            confirmed(e, n).is_some_and(|k| pictures(&e[k..]).len() >= 60)
        })
        .await;
    let pics = pictures(&evs[confirmed(&evs, n).unwrap()..]);
    assert_eq!(nal_types(&pics[0].annex_b), [7, 8, 5], "{policy:?}");
    for p in &pics {
        let t = nal_types(&p.annex_b);
        assert!(t == [7, 8, 5] || t == [1], "{policy:?}: {t:?}");
    }
    for w in pics.windows(2) {
        assert_eq!(w[1].frame_id, w[0].frame_id.wrapping_add(1), "{policy:?}");
    }
    // The policy acted within milliseconds of the confirm, 60 pictures ago:
    // short bounded waits, then asserts that name the policy (m3), so a
    // policy served the wrong way fails fast and says which.
    let expected = if policy == IdrPolicy::Wait { 1 } else { 2 };
    let log = env
        .sim
        .wait_for(CATCH_UP, |l| flv_opens(l).len() >= expected)
        .await
        .unwrap_or_else(|l| l);
    let opens = flv_opens(&log);
    assert_eq!(opens.len(), expected, "{policy:?}: FLV opens");
    if policy == IdrPolicy::Side {
        let closed = env
            .sim
            .wait_for(CATCH_UP, |l| {
                l.contains(&SimEvent::FlvClose { conn: opens[1] })
            })
            .await;
        assert!(closed.is_ok(), "{policy:?}: the side FLV never closed");
    }
    let main = if policy == IdrPolicy::Reconnect {
        opens[1]
    } else {
        opens[0]
    };
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    // kvm-sim logs an AU once its write returned: wait for the last ones.
    let log = env
        .sim
        .wait_for(CATCH_UP, |l| sent_on(l, main).len() >= got.len())
        .await
        .unwrap_or_else(|l| l);
    assert_run(&got, &sent_on(&log, main), &format!("{policy:?}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_side() {
    oracle(IdrPolicy::Side).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_reconnect() {
    oracle(IdrPolicy::Reconnect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_video_oracle_holds_under_wait() {
    oracle(IdrPolicy::Wait).await;
}

/// The long-GOP fixture at the ES3's pacing, sized, `idr_side_timeout` set,
/// streaming past the wrap-around IDR (the 31st picture) and the 1 s setup
/// window: the next periodic IDR is ≈9 s away and a re-advertise is not
/// deferred (P2).
async fn longgop(side_timeout: Duration) -> (Env, Client) {
    let env = env(SimConfig::es3(source(LONGGOP)), move |c| {
        sized(c);
        c.video.idr_side_timeout = side_timeout;
    })
    .await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| {
        let p = pictures(e);
        p.len() >= 45
            && p.iter()
                .filter(|p| nal_types(&p.annex_b) == [7, 8, 5])
                .count()
                >= 2
    })
    .await;
    (env, c)
}

/// §11.3 Side IDR (kvm-sim's shared encoder, `side`): a re-advertise → one
/// extra FLV, closed by the bridge after its first tag; the main FLV never
/// closes; the first KVM AU after the re-advertise is the IDR the side open
/// forced into the main FLV — not a periodic one (none for ≈9 s after the
/// wrap on this fixture) — and it resolves NeedIdr, so no fallback follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_readvertise_takes_one_side_flv_and_never_closes_the_main_one() {
    let side_timeout = ms(500);
    let (env, c) = longgop(side_timeout).await;
    let main = flv_opens(&env.sim.events())[0];
    let n = c.with_log(<[Ev]>::len);
    let t0 = Instant::now();
    c.readvertise();
    // P8: anchored at the re-advertise's confirm, not at `n`.
    let evs = c
        .wait_for(T, |e| {
            confirmed(e, n).is_some_and(|k| pictures(&e[k..]).len() >= 3)
        })
        .await;
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "picture after {:?}: a periodic IDR, not the side one",
        t0.elapsed()
    );
    let log = env
        .sim
        .wait_for(T, |l| {
            flv_opens(l).len() == 2
                && l.contains(&SimEvent::FlvClose {
                    conn: flv_opens(l)[1],
                })
        })
        .await
        .unwrap();
    let side = flv_opens(&log)[1];
    let after = pictures(&evs[confirmed(&evs, n).unwrap()..]);
    assert_eq!(
        nal_types(&after[0].annex_b),
        [7, 8, 5],
        "the first KVM AU after the re-advertise"
    );
    let side_open = log
        .iter()
        .position(|e| *e == SimEvent::FlvOpen { conn: side })
        .unwrap();
    let forced = log[side_open..]
        .iter()
        .find_map(|e| match e {
            SimEvent::FlvAu {
                conn,
                idr: true,
                source_index,
                ..
            } if *conn == main => Some(*source_index),
            _ => None,
        })
        .expect("no forced IDR on the main FLV after the side open");
    assert_eq!(forced, 300, "the side open restarts the GOP at frame 300");
    assert_eq!(
        index_of(&barcodes(LONGGOP), &after[0].annex_b),
        forced,
        "the client's IDR is the forced one"
    );
    // Past `idr_side_timeout`: no fallback FLV, and the main FLV stays open.
    let quiet = env
        .sim
        .wait_for(side_timeout * 3, |l| {
            flv_opens(l).len() > 2 || l.contains(&SimEvent::FlvClose { conn: main })
        })
        .await;
    assert!(
        quiet.is_err(),
        "a fallback FLV opened, or the main FLV closed"
    );
    // P43, as the bridge sees it: the side FLV ended `Ok` — the demuxer
    // gave it a tag and the bridge closed it there. Its first tag is the
    // sequence header kvm-sim writes on open, so it usually closes before
    // kvm-sim writes it an AU (not asserted: a frame can race the close).
    // One left to time out is a counted side failure. L2 cannot tell a
    // close at the first tag from one at the HTTP 200 (m4); L1 pins "reads
    // to its first tag" (`kvm::video` `a_side_flv_with_no_tag_is_abandoned_at_the_side_timeout`).
    assert_eq!(
        env.metrics().idr_side_failures.total(),
        0,
        "the side FLV closed before its first tag"
    );
    assert_eq!(
        env.metrics().idr_side_fallbacks.get(),
        0,
        "the side IDR did not resolve NeedIdr"
    );
    assert_eq!(env.metrics().idr_requests.get("side"), 1);
    assert_eq!(env.logins(), 1);
}

/// §11.3: with side connections refused, exactly one make-before-break
/// `ReconnectFlv` after `idr_side_timeout` — on its setup window's clock, so
/// ≈1 s after the request — and no re-login. No periodic IDR can resolve
/// NeedIdr first on this fixture (P2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_side_flvs_fall_back_to_one_make_before_break_reconnect() {
    let side_timeout = ms(500);
    let (env, c) = longgop(side_timeout).await;
    let main = flv_opens(&env.sim.events())[0];
    env.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
    let t0 = Instant::now();
    c.readvertise();
    assert!(until(T, || env.metrics().idr_side_fallbacks.get() == 1).await);
    within(t0.elapsed(), side_timeout);
    let log = env
        .sim
        .wait_for(T, |l| {
            flv_opens(l).len() == 2 && l.contains(&SimEvent::FlvClose { conn: main })
        })
        .await
        .unwrap();
    let pos = |e: &SimEvent| log.iter().position(|x| x == e).unwrap();
    let new = flv_opens(&log)[1];
    assert!(
        pos(&SimEvent::FlvOpen { conn: new }) < pos(&SimEvent::FlvClose { conn: main }),
        "make-before-break"
    );
    assert_eq!(
        log.iter()
            .filter(|e| matches!(e, SimEvent::FlvRefused { .. }))
            .count(),
        1
    );
    assert_eq!(env.metrics().idr_requests.get("reconnect"), 1);
    assert_eq!(env.logins(), 1, "no re-login");
    let n = pictures(&c.events()).len();
    c.wait_for(T, |e| pictures(e).len() >= n + 10).await;
}

/// §6.8 row 4 — the POC-0 stranding check (Plan A's ledger, §12's Leg B
/// deviation): on the ES3-shaped POC-type-0 fixture, after each batch the
/// last AU kvm-sim shipped reaches the client with nothing after it to push
/// it out, and nothing else arrives; every AU sent is shown, in order. The
/// SPS the client decodes with carries (a) the raised level, (b) the true
/// VUI and (c) `bitstream_restriction` with no reordering. Whether a real
/// decoder (Windows App) holds frames stays an acceptance item (§12, L5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_au_shipped_reaches_the_client_and_its_sps_is_rewritten() {
    let mut sim = es3();
    sim.pacing = Pacing::Manual;
    sim.timestamps = Timestamps::WallClock;
    let env = env(sim, sized).await;
    let c = env.client(Opts::new(2));
    // Manual pacing writes only to FLVs already open: wait for the FLV.
    assert!(until(T, || env.sim.stats().flv_open == 1).await, "no FLV");
    let main = flv_opens(&env.sim.events())[0];
    let map = barcodes(ES3_FIXTURE);
    let mut total = 0;
    for batch in [1u32, 4, 1, 7, 1] {
        env.sim.advance(batch);
        total += usize::try_from(batch).unwrap();
        let log = env
            .sim
            .wait_for(T, |l| sent_on(l, main).len() >= total)
            .await
            .unwrap();
        let last = *sent_on(&log, main).last().unwrap();
        let evs = c
            .wait_for(T, |e| {
                pictures(e)
                    .last()
                    .is_some_and(|p| index_of(&map, &p.annex_b) == last)
            })
            .await;
        let n = pictures(&evs).len();
        c.never(ms(300), |e| pictures(e).len() != n).await;
    }
    let pics = pictures(&c.events());
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    assert_eq!(
        got,
        sent_on(&env.sim.events(), main),
        "every AU shown, in order, none withheld"
    );
    let sps = parse_sps(split_annex_b(&pics[0].annex_b).next().unwrap()).unwrap();
    assert_eq!(sps.pic_order_cnt_type, 0, "the ES3-shaped POC-0 fixture");
    assert_eq!(
        (sps.max_num_reorder_frames, sps.max_dec_frame_buffering),
        (Some(0), Some(sps.num_ref_frames.max(1))),
        "(c) bitstream_restriction: 0 and 1 on the ES3"
    );
    assert_eq!(
        (
            sps.video_full_range_flag,
            sps.colour_primaries,
            sps.matrix_coefficients
        ),
        (Some(false), Some(1), Some(1)),
        "(b) VUI: limited range, BT.709"
    );
    // (a) 640×360 at 30 fps: 920 MBs > level 2.1's MaxFS 792; level 3 is the
    // lowest with MaxFS ≥ 920 and MaxMBPS ≥ 27 600 (the ES3's 1080p30 → 40).
    assert_eq!(sps.level_idc, 30, "(a) level");
}

/// The ES3 whenever the Mac sleeps (rev 6.1 kvm-sim): NO SIGNAL — every
/// frame an IDR, alternating between GOP starts, each with its SPS/PPS, at
/// several times the bitrate. §6.3's composition, the gates and the oracle
/// hold through it with no NeedIdr and no disconnect, and P frames resume
/// when the signal returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_signal_is_all_idr_and_p_frames_resume_when_it_ends() {
    let env = env(es3(), sized).await;
    let c = env.client(Opts::new(2));
    c.wait_for(T, |e| pictures(e).len() >= 10).await;
    let awaiting = env.metrics().frames_dropped.get("awaiting_idr");
    let n = pictures(&c.events()).len();
    env.sim.set_signal(false);
    let idr = |p: &Picture| nal_types(&p.annex_b) == [7, 8, 5];
    let evs = c
        .wait_for(T, |e| {
            pictures(e)[n..].iter().filter(|p| idr(p)).count() >= 31
        })
        .await;
    let pics = pictures(&evs);
    let first = n + pics[n..].iter().position(idr).unwrap();
    assert!(
        pics[first..first + 30].iter().all(idr),
        "NO SIGNAL: every picture an IDR with SPS/PPS"
    );
    for w in pics.windows(2) {
        assert_eq!(
            w[1].frame_id,
            w[0].frame_id.wrapping_add(1),
            "a frame was dropped"
        );
    }
    let map = barcodes(ES3_FIXTURE);
    let got: Vec<usize> = pics.iter().map(|p| index_of(&map, &p.annex_b)).collect();
    let main = flv_opens(&env.sim.events())[0];
    let log = env
        .sim
        .wait_for(T, |l| sent_on(l, main).len() >= got.len())
        .await
        .unwrap();
    assert_run(&got, &sent_on(&log, main), "through NO SIGNAL");
    assert_eq!(
        env.metrics().frames_dropped.get("awaiting_idr"),
        awaiting,
        "NO SIGNAL caused a NeedIdr"
    );
    env.sim.set_signal(true);
    let m = pictures(&c.events()).len();
    c.wait_for(T, |e| {
        pictures(e)[m..]
            .iter()
            .any(|p| nal_types(&p.annex_b) == [1])
    })
    .await;
    assert!(terminated(&c.events()).is_none());
    assert_eq!(env.metrics().disconnects.total(), 0);
}
