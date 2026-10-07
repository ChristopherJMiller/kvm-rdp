use crate::support::{FlvClient, T, es3_sim, login, sim_with, target};
use kvm_proto::flv::{FrameType, TagBody, VideoBody};
use kvm_proto::video::{AdmissionConfig, ParamClass, VideoAdmission};
use kvm_sim::{KvmSim, Pacing, Profile, ResizeSignal, SimConfig, SimEvent, Source};
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
