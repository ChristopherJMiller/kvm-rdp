//! Every one-shot fault reaches the bridge's admission as exactly its §6.9
//! refusal (kvm-proto is the oracle).
use crate::support::{FlvClient, es3_sim, login};
use kvm_proto::flv::FlvError;
use kvm_proto::h264::picture::SliceRefusal;
use kvm_proto::h264::sanitize::NalRefusal;
use kvm_proto::video::{AdmissionConfig, AdmissionError, Framing, Incompatible, VideoAdmission};
use kvm_sim::{Fault, Pacing, SimEvent};
use std::time::{Duration, Instant};

/// How a stream ended for the bridge's admission.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Refused(AdmissionError),
    EndOfSequence,
    Eof,
}

/// Stream an IDR and a P frame, inject `fault`, stream two more, and return
/// the first refusal (or the end of the stream).
async fn first_refusal(fault: Option<Fault>, skip_sequence_header: bool) -> Outcome {
    let sim = es3_sim(Pacing::Manual).await;
    sim.set_policy(|p| p.skip_sequence_header = skip_sequence_header);
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    let mut adm = VideoAdmission::new(AdmissionConfig::default());
    adm.flv_opened();
    sim.advance(2);
    let skip = if skip_sequence_header { 0 } else { 3 };
    for _ in 0..skip {
        adm.admit(c.next().await.unwrap().unwrap(), Instant::now())
            .unwrap();
    }
    if let Some(f) = fault {
        sim.inject(f);
    }
    sim.advance(2);
    loop {
        let tag = match c.next().await {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::Eof,
            Err(e) => return Outcome::Refused(AdmissionError::from(e)),
        };
        match adm.admit(tag, Instant::now()) {
            Ok(a) if a.end_of_sequence => return Outcome::EndOfSequence,
            Ok(_) => {}
            Err(e) => return Outcome::Refused(e),
        }
    }
}

#[tokio::test]
async fn each_fault_is_its_own_section_6_9_refusal() {
    use Outcome::{EndOfSequence, Eof, Refused};
    let flv = |e: FlvError| Refused(AdmissionError::from(e));
    let framing = |f: Framing| Refused(AdmissionError::Framing(f));
    let incompatible = |i: Incompatible| Refused(AdmissionError::Incompatible(i));
    let cases = [
        (Fault::OversizeTag, flv(FlvError::OversizeTag)),
        (Fault::BadPrevTagSize, flv(FlvError::BadPrevTagSize)),
        (Fault::EncryptedTag, flv(FlvError::EncryptedTag)),
        (Fault::BadStreamId, flv(FlvError::BadStreamId)),
        (Fault::HevcCodecId, incompatible(Incompatible::Codec(12))),
        (
            Fault::EnhancedHevc,
            incompatible(Incompatible::Enhanced(*b"hvc1")),
        ),
        (
            Fault::CompositionTime(17),
            incompatible(Incompatible::CompositionTime { first: 16, now: 17 }),
        ),
        (Fault::TwoPictures, framing(Framing::NotOnePicture)),
        (
            Fault::BSlice,
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(1))),
        ),
        (
            Fault::StartCodeInNal,
            framing(Framing::Nal(NalRefusal::StartCode)),
        ),
        (
            Fault::ForbiddenBit,
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
        ),
        (Fault::TooManyNals, flv(FlvError::TooManyNals)),
        (Fault::EndOfSequence, EndOfSequence),
        (Fault::Close, Eof),
    ];
    for (fault, want) in cases {
        assert_eq!(first_refusal(Some(fault), false).await, want, "{fault:?}");
    }
    assert_eq!(
        first_refusal(None, true).await,
        flv(FlvError::NalBeforeSequenceHeader)
    );
}

#[tokio::test]
async fn silence_keeps_the_flv_open_and_sends_nothing() {
    // §11.3's `flv_idle_timeout` case: no byte and no EOF.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let mut c = FlvClient::open(&sim, &token).await.unwrap();
    sim.advance(2);
    for _ in 0..3 {
        c.next().await.unwrap().unwrap(); // sequence header, IDR, P
    }
    sim.inject(Fault::Silence);
    sim.advance(3);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), c.next())
            .await
            .is_err(),
        "nothing arrives and the connection stays open"
    );
    assert_eq!(sim.stats().flv_open, 1);
    let aus = sim
        .events()
        .iter()
        .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
        .count();
    assert_eq!(aus, 2);
}
