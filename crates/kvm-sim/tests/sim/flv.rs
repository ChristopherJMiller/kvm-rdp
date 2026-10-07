use crate::support::{FlvClient, T, es3_sim, flv_raw_request, login, sim_with, target};
use kvm_proto::flv::{FrameType, TagBody, VideoBody};
use kvm_proto::video::{AdmissionConfig, ParamClass, VideoAdmission};
use kvm_sim::{KvmSim, Pacing, Profile, ResizeSignal, SimConfig, SimEvent, Source, Timestamps};
use std::time::{Duration, Instant};

fn nal_types(body: &TagBody) -> Vec<u8> {
    match body {
        TagBody::Video(VideoBody::Nalus { nals, .. }) => {
            nals.iter().map(|n| n.unit_type().unwrap()).collect()
        }
        _ => vec![],
    }
}

#[tokio::test]
async fn es3_tag_shape_on_the_wire_and_the_bridge_admits_it() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(3);
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    let seq = c.next().await.unwrap().unwrap();
    match &seq.body {
        TagBody::Video(VideoBody::SequenceHeader(cfg)) => {
            assert_eq!(cfg.length_size_minus_one, 3); // AVCC length size 4
            assert_eq!(cfg.sps.len(), 1);
            assert_eq!(cfg.pps.len(), 1);
            // Padded like the device's own (census.md: sps_hex …08 00,
            // pps_hex …12 00 00).
            assert!(cfg.sps[0].ends_with(&[0]) && cfg.pps[0].ends_with(&[0, 0]));
        }
        other => panic!("{other:?}"),
    }
    let params = adm.admit(seq, Instant::now()).unwrap().params.unwrap();
    assert_eq!(params.class, ParamClass::Initial);
    assert_eq!(params.params.summary.level_idc, 30); // mislabelled 21 → rewritten
    // Admission trims the padding (D2).
    assert!(!params.params.sps.ends_with(&[0]) && !params.params.pps[0].ends_with(&[0]));
    for (i, want) in [(0u32, vec![5u8]), (33, vec![1]), (66, vec![1])] {
        let tag = c.next().await.unwrap().unwrap();
        assert_eq!(tag.timestamp, i);
        assert_eq!(nal_types(&tag.body), want, "only NAL types 1 and 5 (ES3)");
        if let TagBody::Video(VideoBody::Nalus {
            composition_time,
            frame_type,
            ..
        }) = &tag.body
        {
            assert_eq!(*composition_time, 16);
            assert_eq!(*frame_type == FrameType::Key, want == [5]);
        }
        let au = adm.admit(tag, Instant::now()).unwrap().au.unwrap();
        assert_eq!(au.idr, want == [5]);
    }
}

#[tokio::test]
async fn a_new_connection_forces_an_idr_into_every_open_stream() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut a = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(10);
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
            .count()
            == 10
    })
    .await
    .unwrap();
    let b = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(2);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 14
        })
        .await
        .unwrap();
    let aus: Vec<(u64, u64, bool)> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { conn, seq, idr, .. } => Some((*conn, *seq, *idr)),
            _ => None,
        })
        .collect();
    // The 11th frame (seq 10) is an IDR on both streams: off the 60-frame cadence.
    assert!(
        aus.iter()
            .filter(|(_, s, _)| *s == 10)
            .all(|(_, _, idr)| *idr)
    );
    assert_eq!(aus.iter().filter(|(_, s, _)| *s == 10).count(), 2);
    for _ in 0..11 {
        a.next().await.unwrap().unwrap();
    }
    let tag = a.next().await.unwrap().unwrap();
    assert!(matches!(
        tag.body,
        TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            ..
        })
    ));
    // The forced IDR restarted the GOP: the next IDR comes 60 frames later
    // (seq 70), not on the old cadence (seq 60).
    drop(b);
    sim.advance(60);
    let mut keys = vec![];
    for seq in 11..72 {
        let tag = a.next().await.unwrap().unwrap();
        if matches!(
            tag.body,
            TagBody::Video(VideoBody::Nalus {
                frame_type: FrameType::Key,
                ..
            })
        ) {
            keys.push(seq);
        }
    }
    assert_eq!(keys, [70]);
}

#[tokio::test]
async fn gop_is_sixty_frames_and_no_signal_is_all_intra() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let _c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(121);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 121
        })
        .await
        .unwrap();
    let idrs: Vec<u64> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { seq, idr: true, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(idrs, [0, 60, 120]);
    sim.set_signal(false);
    sim.advance(5);
    let ev = sim
        .wait_for(T, |e| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
                .count()
                == 126
        })
        .await
        .unwrap();
    let last: Vec<bool> = ev
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { idr, .. } => Some(*idr),
            _ => None,
        })
        .skip(121)
        .collect();
    assert_eq!(last, [true; 5]);
}

#[tokio::test]
async fn bad_tokens_and_refused_side_connections() {
    let sim = es3_sim(Pacing::Manual).await;
    assert_eq!(FlvClient::open(&sim, "0.123").await.err(), Some(403));
    let token = login(&sim).await;
    sim.set_policy(|p| p.refuse_concurrent_flv = 1);
    let _first = FlvClient::open(&sim, &token).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter().any(|e| matches!(e, SimEvent::FlvOpen { .. }))
    })
    .await
    .unwrap();
    assert_eq!(FlvClient::open(&sim, &token).await.err(), Some(503));
    assert!(sim.events().contains(&SimEvent::FlvRefused { status: 503 }));
    // The refusal is spent: a make-before-break reconnect is served (P3 —
    // §11.3's side-IDR reconnect is itself a second concurrent FLV).
    let _second = FlvClient::open(&sim, &token).await.unwrap();
    sim.wait_for(T, |e| {
        e.iter()
            .filter(|e| matches!(e, SimEvent::FlvOpen { .. }))
            .count()
            == 2
    })
    .await
    .unwrap();
}

async fn main_sim() -> KvmSim {
    let mut cfg = SimConfig::es3(Source::fixture("360p30_main_full.h264").unwrap());
    cfg.pacing = Pacing::Manual;
    cfg.profile = Profile {
        aud: true,
        ..Profile::es3()
    };
    KvmSim::start(cfg).await.unwrap()
}

#[tokio::test]
async fn resolution_change_by_each_signal() {
    for signal in [
        ResizeSignal::SequenceHeader,
        ResizeSignal::InBandSps,
        ResizeSignal::CloseFlv,
    ] {
        let sim = main_sim().await;
        let token = login(&sim).await;
        let mut c = FlvClient::open(&sim, &token).await.unwrap();
        let mut adm = VideoAdmission::new(AdmissionConfig::default());
        adm.flv_opened();
        sim.advance(2);
        for _ in 0..3 {
            adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
                .unwrap();
        }
        sim.switch_source(Source::fixture("480p30_main_full.h264").unwrap(), signal);
        sim.advance(1);
        let mut classes = vec![];
        if signal == ResizeSignal::CloseFlv {
            assert!(c.next().await.unwrap().is_none(), "the FLV closes");
            c = FlvClient::open(&sim, &token).await.unwrap();
            adm.flv_opened();
            sim.advance(1);
        }
        while classes.is_empty() {
            let a = adm
                .admit(c.next().await.unwrap().unwrap(), Instant::now())
                .unwrap();
            if let Some(p) = a.params {
                assert_eq!(
                    (p.params.summary.width, p.params.summary.height),
                    (854, 480)
                );
                classes.push(p.class);
            }
        }
        let want = if signal == ResizeSignal::CloseFlv {
            ParamClass::Initial
        } else {
            ParamClass::Resize
        };
        assert_eq!(classes, [want], "{signal:?}");
    }
}

#[tokio::test]
async fn no_signal_card_admits_without_a_params_change() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    sim.advance(3);
    for _ in 0..4 {
        adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
    }
    sim.set_signal(false); // display sleep: every frame an IDR, same SPS
    sim.advance(6);
    for _ in 0..6 {
        let a = adm
            .admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
        assert_eq!(a.params, None);
        assert!(a.au.unwrap().idr);
    }
    sim.set_signal(true); // wake: the encoder restarts at an IDR
    sim.advance(2);
    let a = adm
        .admit(c.next().await.unwrap().unwrap(), Instant::now())
        .unwrap();
    assert!(a.au.unwrap().idr);
    let a = adm
        .admit(c.next().await.unwrap().unwrap(), Instant::now())
        .unwrap();
    assert!(!a.au.unwrap().idr);
}

#[tokio::test]
async fn a_viewer_that_stops_reading_does_not_stall_the_others() {
    // A 64 KiB send buffer: the stalled viewer's writer blocks after a few
    // dozen frames, so its 512-frame queue overflows well before 2000.
    let sim = sim_with(|c| {
        c.pacing = Pacing::Manual;
        c.video_send_buffer = Some(64 * 1024);
    })
    .await;
    let token = login(&sim).await;
    let mut reader = FlvClient::open(&sim, &token).await.unwrap();
    let _stalled = FlvClient::open(&sim, &token).await.unwrap(); // never read
    reader.next().await.unwrap().unwrap(); // sequence header
    // ~5 MB of video: the viewer that never reads blocks its writer and
    // overflows its queue — the reading one must not notice.
    for _ in 0..20 {
        sim.advance(100);
        for _ in 0..100 {
            reader
                .next()
                .await
                .unwrap()
                .expect("the reading viewer keeps getting tags");
        }
    }
    let events = sim.events();
    let reader_conn = events
        .iter()
        .find_map(|e| match e {
            SimEvent::FlvOpen { conn } => Some(*conn),
            _ => None,
        })
        .unwrap();
    let reader_seqs: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvAu { conn, seq, .. } if *conn == reader_conn => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(
        sim.stats().frames_dropped > 0,
        "the stalled viewer's queue never overflowed"
    );
    assert_eq!(reader_seqs, (0..2000).collect::<Vec<u64>>());
}

#[tokio::test]
async fn a_second_login_leaves_the_first_token_valid() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let _b = login(&sim).await;
    assert!(FlvClient::open(&sim, &a).await.is_ok());
}

#[tokio::test]
async fn logout_is_global_but_open_streams_survive() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    let b = login(&sim).await;
    let mut open = FlvClient::open(&sim, &a).await.unwrap();
    kvm_probe::kvm::logout(&target(&sim), Some(sim.spki_sha256()), &b)
        .await
        .unwrap();
    // Every token died, including the one that did not log out …
    assert_eq!(FlvClient::open(&sim, &a).await.err(), Some(403));
    // … but the FLV opened before the logout keeps streaming.
    sim.advance(2);
    assert!(open.next().await.unwrap().is_some()); // sequence header
    assert!(open.next().await.unwrap().is_some()); // IDR
    assert_eq!(sim.stats().logouts, 1);
}

#[tokio::test]
async fn expired_tokens_are_refused_without_a_logout() {
    let sim = es3_sim(Pacing::Manual).await;
    let a = login(&sim).await;
    sim.expire_tokens();
    assert_eq!(FlvClient::open(&sim, &a).await.err(), Some(403));
    assert_eq!(sim.stats().logouts, 0);
}

#[tokio::test]
async fn a_policy_status_refuses_the_stream() {
    // HTTP 5xx, and the 401 a second consecutive auth failure (§11.3) needs.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    for status in [503u16, 401] {
        sim.set_policy(|p| p.flv_status = Some(status));
        assert_eq!(FlvClient::open(&sim, &token).await.err(), Some(status));
        assert!(sim.events().contains(&SimEvent::FlvRefused { status }));
    }
    sim.set_policy(|p| p.flv_status = None);
    assert!(FlvClient::open(&sim, &token).await.is_ok());
}

#[tokio::test]
async fn sim_tx_follows_the_send_order_and_a_reader_never_blocks_a_write() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(30);
    for _ in 0..31 {
        c.next().await.unwrap().unwrap();
    }
    let sent: Vec<(Instant, u64)> = sim
        .stamped_events()
        .into_iter()
        .filter_map(|(at, e)| match e {
            SimEvent::FlvAu { seq, .. } => Some((at, seq)),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent.iter().map(|s| s.1).collect::<Vec<u64>>(),
        (0..30).collect::<Vec<u64>>()
    );
    assert!(
        sent.windows(2).all(|w| w[0].0 <= w[1].0),
        "sim_tx in send order"
    );
    assert_eq!(sim.stats().frames_sent, 30);
    // §10.2: no FLV write blocks for 100 ms (kvm-bench asserts it under load).
    let block = sim.stats().max_flv_write_block;
    assert!(
        block > Duration::ZERO && block < Duration::from_millis(100),
        "{block:?}"
    );
}

/// I1 (fix round 1): a viewer whose queue filled because its client
/// stopped reading is evicted by `Encoder::broadcast` on a control item,
/// but its `av.flv` connection must close *promptly* — not only once the
/// client resumes and drains the already-queued backlog. Same stall setup
/// as `a_viewer_that_stops_reading_does_not_stall_the_others` (a 64 KiB
/// send buffer, so the never-reading viewer's writer genuinely blocks on
/// the socket, not just falls behind at the mpsc layer). Bounded by
/// `wait_for`'s own timeout: this fails fast (never hangs) whether it
/// passes or not.
#[tokio::test]
async fn an_evicted_full_queue_viewer_closes_promptly_while_its_client_stays_stalled() {
    let sim = sim_with(|c| {
        c.pacing = Pacing::Manual;
        c.video_send_buffer = Some(64 * 1024);
    })
    .await;
    let token = login(&sim).await;
    let mut reader = FlvClient::open(&sim, &token).await.unwrap();
    let _stalled = FlvClient::open(&sim, &token).await.unwrap(); // never read again
    let stalled_conn = sim
        .events()
        .iter()
        .filter_map(|e| match e {
            SimEvent::FlvOpen { conn } => Some(*conn),
            _ => None,
        })
        .nth(1)
        .expect("the stalled viewer opened");
    reader.next().await.unwrap().unwrap(); // sequence header
    for _ in 0..20 {
        sim.advance(100);
        for _ in 0..100 {
            reader
                .next()
                .await
                .unwrap()
                .expect("the reading viewer keeps getting tags");
        }
    }
    assert!(
        sim.stats().frames_dropped > 0,
        "the stalled viewer's queue never overflowed"
    );
    // A control item evicts the full queue (Task 8.2's `broadcast`); its
    // FLV connection must close promptly even though its client is still
    // not reading — not only once it resumes and drains what was already
    // queued (the bug I1 found: no FlvClose for 3s+, then hundreds of
    // stale tags on resume). PB17/n2: a source switch is the control item
    // here, not `Fault::Close` — Task 8.5 makes `Fault::Close` close every
    // open viewer (the reader too), which this test's `flv_open == 1`
    // assertion does not expect; a `Params` item still evicts the full
    // queue the same way (`Encoder::broadcast`) without touching the
    // reader beyond a harmless new sequence header.
    let other = Source::fixture("480p30_main_full.h264").unwrap();
    sim.switch_source(other, ResizeSignal::SequenceHeader);
    let ev = sim
        .wait_for(Duration::from_millis(500), |e| {
            e.iter()
                .any(|e| matches!(e, SimEvent::FlvClose { conn } if *conn == stalled_conn))
        })
        .await
        .expect("the stalled viewer's FlvClose never arrived within 500ms");
    assert!(
        ev.iter()
            .any(|e| matches!(e, SimEvent::FlvClose { conn } if *conn == stalled_conn))
    );
    assert_eq!(
        sim.stats().flv_open,
        1,
        "only the reader is still open once the stalled viewer closes"
    );
}

/// m1 (fix round 1): §6.9 classes `result: 403` as an auth failure (P2), so
/// only an actual 403 may carry it — every other refusal's body is empty.
#[tokio::test]
async fn refusal_bodies_carry_result_403_only_on_an_actual_403() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;

    // 403: a bogus-but-well-formed token (query == cookie, but not live).
    let (status, body) = flv_raw_request(&sim, "/av.flv?token=0.bogus", Some("0.bogus")).await;
    assert_eq!(status, 403);
    assert_eq!(body, b"{\"result\":403}");

    // 404: the wrong path.
    let (status, body) = flv_raw_request(&sim, "/nope?token=x", Some("x")).await;
    assert_eq!(status, 404);
    assert!(body.is_empty(), "{body:?}");

    // 503 (`Policy::flv_status`) and 401 (§11.3's second consecutive auth
    // failure): neither is `result: 403`, even though 401 is itself an
    // auth status.
    for want in [503u16, 401] {
        sim.set_policy(|p| p.flv_status = Some(want));
        let path = format!("/av.flv?token={token}");
        let (status, body) = flv_raw_request(&sim, &path, Some(&token)).await;
        assert_eq!(status, want);
        assert!(body.is_empty(), "{want}: {body:?}");
    }
}

/// m2 (fix round 1): the "both required, equal and live" token rule
/// (flv.rs's `token_ok`) pinned for a missing cookie, a missing query
/// token, and a query that disagrees with a live cookie — only the bogus-
/// but-equal case (`bad_tokens_and_refused_side_connections`) was tested
/// before.
#[tokio::test]
async fn a_missing_or_mismatched_token_is_refused() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;

    // No Cookie header at all.
    let (status, _) = flv_raw_request(&sim, &format!("/av.flv?token={token}"), None).await;
    assert_eq!(status, 403);

    // No `token` query parameter.
    let (status, _) = flv_raw_request(&sim, "/av.flv", Some(&token)).await;
    assert_eq!(status, 403);

    // A live cookie, but the query token names a different (also live) one.
    let other = login(&sim).await;
    let (status, _) = flv_raw_request(&sim, &format!("/av.flv?token={token}"), Some(&other)).await;
    assert_eq!(status, 403);
}

/// Final review I2: what `Pacing::Manual` hands admission, by timestamp
/// mode, read end to end and admitted on receipt as the bridge will. The
/// default frame-count stamps step 33 ms per frame whatever the clock does,
/// so one `advance` batch is nearly all `burst` — the source-burst path of
/// §6.5/§6.6, not the live one. Wall-clock stamps never run ahead of real
/// time, so no AU is a burst and a Manual-paced test reaches the soft gate.
/// Multi-threaded, so the reader keeps up with the writer as the bridge's
/// KVM actor would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_pacing_bursts_with_frame_count_stamps_and_never_with_wall_clock_ones() {
    const FRAMES: u32 = 30;
    for stamps in [Timestamps::FrameCount, Timestamps::WallClock] {
        let sim = sim_with(|c| {
            c.pacing = Pacing::Manual;
            c.timestamps = stamps;
        })
        .await;
        let token = login(&sim).await;
        let mut c = FlvClient::open(&sim, &token).await.unwrap();
        sim.advance(FRAMES);
        let mut adm = VideoAdmission::new(AdmissionConfig::default());
        adm.flv_opened();
        let (mut stamped, mut bursts) = (Vec::new(), 0);
        while stamped.len() < FRAMES as usize {
            let tag = c.next().await.unwrap().unwrap();
            let ts = tag.timestamp;
            if let Some(au) = adm.admit(tag, Instant::now()).unwrap().au {
                stamped.push(ts);
                bursts += usize::from(au.burst);
            }
        }
        match stamps {
            Timestamps::FrameCount => {
                let cadence: Vec<u32> = (0..FRAMES).map(|k| k * 1000 / 30).collect();
                assert_eq!(stamped, cadence);
                // AU k is 33·k ms ahead of the first; past 100 ms of real
                // time it is a burst. Every AU from the 11th on is, unless
                // reading ten tags took over 233 ms (the review: 282/290).
                assert!(bursts >= 20, "{bursts} of {FRAMES} bursts");
            }
            Timestamps::WallClock => {
                assert!(stamped.windows(2).all(|w| w[0] <= w[1]), "{stamped:?}");
                assert!(stamped[29] - stamped[0] < 500, "{stamped:?}");
                assert_eq!(bursts, 0, "{stamped:?}");
            }
        }
    }
}
