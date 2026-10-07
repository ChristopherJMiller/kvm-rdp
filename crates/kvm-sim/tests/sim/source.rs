use kvm_sim::Source;

#[test]
fn es3like_fixture_splits_into_120_frames_in_two_gops() {
    let s = Source::fixture("360p30_es3like_poc0.h264").unwrap();
    assert_eq!(s.frames.len(), 120);
    assert_eq!(s.gop_starts, [0, 60]);
    assert_eq!(s.sps[0] & 0x1F, 7);
    assert_eq!(s.pps[0] & 0x1F, 8);
    assert!(s.frames.iter().all(|f| {
        f.nals
            .iter()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .count()
            == 1
    }));
    assert_eq!(
        (
            s.next_gop_start(0),
            s.next_gop_start(59),
            s.next_gop_start(60)
        ),
        (60, 60, 0)
    );
}

#[test]
fn multi_slice_access_units_stay_whole() {
    let s = Source::fixture("360p30_main_slices.h264").unwrap();
    assert_eq!(s.frames.len(), 90);
    assert!(s.frames.iter().any(|f| {
        f.nals
            .iter()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .count()
            > 3
    }));
    assert_eq!(s.gop_starts, [0, 30, 60]);
}

#[test]
fn a_stream_must_start_with_an_idr() {
    let data = std::fs::read(kvm_sim::fixtures_dir().join("360p30_main_full.h264")).unwrap();
    // Drop everything up to the second access unit delimiter: a P frame first.
    let second_aud = data
        .windows(5)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 0, 1, 0x09])
        .nth(1)
        .unwrap()
        .0;
    assert!(matches!(
        Source::from_annex_b("cut", &data[second_aud..]),
        Err(kvm_sim::SourceError::NotIdrFirst)
    ));
}
