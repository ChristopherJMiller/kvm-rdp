//! kvm-probe, the census tool proven against the real ES3, measures kvm-sim
//! the way it measured the device (`census.md`, Leg A — stream).
use crate::support::{FlvClient, T, es3_sim, login, target};
use kvm_probe::capture::{StopAt, run};
use kvm_probe::captures::CaptureDir;
use kvm_probe::fingerprint::observe;
use kvm_probe::kvm::{KvmError, connect_to};
use kvm_probe::record::TagRecord;
use kvm_probe::report::summarize;
use kvm_proto::flv::{TagBody, VideoBody};
use kvm_sim::{Fault, KvmSim, Pacing, Profile, SimConfig, SimEvent, Source};

fn coded_aus(e: &[SimEvent]) -> usize {
    e.iter()
        .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
        .count()
}

#[tokio::test]
async fn census_capture_sees_the_es3_profile() {
    // Manual pacing: once kvm-probe's FLV is open, kvm-sim sends exactly 130
    // frames (two whole GOPs and the start of a third) and then closes it, so
    // what is captured never depends on how loaded the host is.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stop = StopAt {
        max_bytes: 8 << 20,
        max_duration: T,
    };
    let drive = async {
        sim.wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::FlvOpen { .. }))
        })
        .await
        .unwrap();
        sim.advance(130);
        sim.wait_for(T, |e| coded_aus(e) == 130).await.unwrap();
        sim.inject(Fault::Close);
    };
    let kvm = target(&sim);
    let capture = run(
        &kvm,
        Some(sim.spki_sha256()),
        &token,
        &dir,
        "sim.flv",
        &mut jsonl,
        stop,
    );
    let (stats, ()) = tokio::join!(capture, drive);
    assert_eq!(stats.unwrap().parse_errors, 0);
    let records: Vec<TagRecord> = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let s = summarize(&records);
    assert_eq!(s.codecs, [7]);
    assert_eq!(
        (
            s.multi_picture_tags,
            s.continuation_tags,
            s.non_vcl_picture_tags,
            s.bad_header_nals
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(s.gop_len, Some(60));
    // Like the real ES3, the SPS as sent is refused by h264-reader (level),
    // and both parameter sets end in zero bytes (census.md sps_hex, pps_hex).
    assert!(s.sps[0].summary.is_err());
    assert!(s.sps[0].hex.ends_with("00") && s.pps_hex[0].ends_with("0000"));
    let coded: Vec<&TagRecord> = records
        .iter()
        .filter(|r| r.avc_packet_type == Some(1))
        .collect();
    assert_eq!(coded.len(), 130);
    for r in coded {
        assert_eq!(r.composition_time, 16);
        assert!(r.nal_types.iter().all(|t| matches!(t, 1 | 5)));
    }
    assert_eq!(sim.stats().logouts, 0);
}

#[tokio::test]
async fn first_idr_and_websocket_open_work_and_send_nothing() {
    // Real-time pacing at 120 fps: the first-IDR trial waits on frames.
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    cfg.profile = Profile {
        fps: 120,
        ..Profile::es3()
    };
    let sim = KvmSim::start(cfg).await.unwrap();
    let token = login(&sim).await;
    let latency =
        kvm_probe::trial::first_idr_latency(&target(&sim), Some(sim.spki_sha256()), &token, T)
            .await
            .unwrap();
    assert!(latency < T);
    kvm_probe::wsprobe::open_control_websocket(&target(&sim), Some(sim.spki_sha256()), &token)
        .await
        .unwrap();
    let ev = sim
        .wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::WsClose { .. }))
        })
        .await
        .unwrap();
    assert!(!ev.iter().any(|e| matches!(e, SimEvent::Hid { .. })));
}

/// PC7 W10's knob: `rotate_certificate` gives every new TLS connection, on
/// all three ports, a fresh self-signed certificate — another SPKI on
/// each call — so a client pinned to the first fails its handshake with
/// kvm-probe's pin error, as the bridge's pin does. A connection open
/// before the swap keeps the certificate it was served, and
/// `spki_sha256()` stays the first certificate's (the pin a test
/// configured).
#[tokio::test]
async fn a_rotated_certificate_fails_the_old_pin_on_new_connections_only() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let kvm = target(&sim);
    let p = sim.ports();
    let old = sim.spki_sha256().to_owned();
    for port in [p.web, p.video, p.control] {
        assert_eq!(observe(&kvm, port).await.unwrap(), old, "port {port}");
    }
    let mut open = FlvClient::open(&sim, &token).await.unwrap();
    sim.rotate_certificate().unwrap();
    let new = observe(&kvm, p.web).await.unwrap();
    assert_ne!(new, old, "the rotated certificate has the old SPKI");
    for port in [p.web, p.video, p.control] {
        assert_eq!(observe(&kvm, port).await.unwrap(), new, "port {port}");
        match connect_to(&kvm, port, Some(&old)).await {
            Err(KvmError::Tls(e)) => assert!(e.contains("kvm_cert_mismatch"), "port {port}: {e}"),
            Err(e) => panic!("port {port}: not a pin failure: {e:?}"),
            Ok(_) => panic!("port {port}: the old pin still matched"),
        }
    }
    assert_eq!(sim.spki_sha256(), old, "the configured pin moved");
    // The new certificate serves: a login pinned to it.
    kvm_probe::kvm::login(&kvm, Some(&new), sim.password(), 0, "UTC")
        .await
        .unwrap();
    // The FLV opened before the swap streams on: the sequence header, then
    // the frames encoded after it.
    sim.advance(2);
    for _ in 0..3 {
        open.next().await.unwrap().expect("the open FLV closed");
    }
    sim.rotate_certificate().unwrap();
    let newer = observe(&kvm, p.web).await.unwrap();
    assert!(newer != new && newer != old, "not a fresh SPKI");
    assert_eq!(sim.stats().logouts, 0);
}

/// Every coded AU's NALs, in order, until `n` of them have come.
async fn coded(c: &mut FlvClient, n: usize) -> Vec<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while out.len() < n {
        let tag = c.next().await.unwrap().expect("the FLV closed");
        if let TagBody::Video(VideoBody::Nalus { nals, .. }) = tag.body {
            out.push(nals.iter().map(|n| n.bytes.to_vec()).collect());
        }
    }
    out
}

/// PC17 m1's knob: with `alter_candidate_frame = Some(3)`, the next FLV
/// opened while another is open (a `ReconnectFlv` candidate) changes one
/// byte inside the first slice of its third frame (counting from 1 at its
/// first IDR) — the same length, header and every other byte and AU as the
/// other viewers get — and that open spends it. An FLV opened alone before
/// it, and one opened after it, are untouched. kvm-sim logs the altered AU
/// with its own frame id.
#[tokio::test]
async fn alter_candidate_frame_changes_one_byte_of_one_concurrent_au() {
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    sim.set_policy(|p| p.alter_candidate_frame = Some(3));
    let mut alone = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(5);
    sim.wait_for(T, |e| coded_aus(e) == 5).await.unwrap();
    let mut candidate = FlvClient::open(&sim, &token).await.unwrap();
    let mut after = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(6);
    let log = sim
        .wait_for(T, |e| coded_aus(e) == 5 + 3 * 6)
        .await
        .unwrap();
    let all = coded(&mut alone, 11).await;
    let cand = coded(&mut candidate, 6).await;
    let later = coded(&mut after, 6).await;
    // The two later opens forced the IDR their streams start at (seq 5).
    let shared = &all[5..];
    assert_eq!(
        later, shared,
        "the FLV opened after the candidate was altered"
    );
    for k in [0, 1, 3, 4, 5] {
        assert_eq!(cand[k], shared[k], "candidate AU {k}");
    }
    let (got, want) = (&cand[2], &shared[2]);
    assert_eq!(got.len(), want.len());
    assert_eq!(got[1..], want[1..], "a NAL past the first slice changed");
    let (slice, orig) = (&got[0], &want[0]);
    assert!(matches!(orig[0] & 0x1F, 1 | 5), "the first NAL is a slice");
    assert_eq!(slice.len(), orig.len());
    let changed: Vec<usize> = (0..slice.len()).filter(|i| slice[*i] != orig[*i]).collect();
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(
        changed[0] > 0 && changed[0] < slice.len() - 1,
        "the change is not inside the slice: byte {} of {}",
        changed[0],
        slice.len()
    );
    // The log: the same seqs on every viewer, one frame id apart.
    let ids = |conn_at: usize| -> Vec<(u64, u64)> {
        let conn = log
            .iter()
            .filter_map(|e| match e {
                SimEvent::FlvOpen { conn } => Some(*conn),
                _ => None,
            })
            .nth(conn_at)
            .unwrap();
        log.iter()
            .filter_map(|e| match e {
                SimEvent::FlvAu {
                    conn: on,
                    seq,
                    frame_id,
                    ..
                } if *on == conn => Some((*seq, *frame_id)),
                _ => None,
            })
            .collect()
    };
    let (a, b, c) = (ids(0), ids(1), ids(2));
    assert_eq!(c, a[5..]);
    for (k, (x, y)) in b.iter().zip(&a[5..]).enumerate() {
        assert_eq!(x.0, y.0, "seq of candidate AU {k}");
        assert_eq!(x.1 != y.1, k == 2, "frame id of candidate AU {k}");
    }
}
