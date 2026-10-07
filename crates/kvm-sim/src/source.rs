//! A video source for the simulated encoder: a committed Annex-B fixture
//! split into access units (trusted input — never a KVM capture).
use bytes::Bytes;
use kvm_proto::h264::split_annex_b;
use std::path::{Path, PathBuf};

/// One access unit of the source, NALs without start codes, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Index of this frame in the source (the fixture's barcode counter).
    pub index: usize,
    pub idr: bool,
    pub nals: Vec<Bytes>,
}

/// A looping stream of frames plus the parameter sets for its sequence header.
#[derive(Debug, Clone)]
pub struct Source {
    pub name: String,
    pub sps: Bytes,
    pub pps: Bytes,
    pub frames: Vec<Frame>,
    /// Indices into `frames` of every IDR (GOP starts), ascending.
    pub gop_starts: Vec<usize>,
}

#[derive(Debug)]
pub enum SourceError {
    Io(std::io::Error),
    NoParameterSets,
    /// The stream is empty or does not start with an IDR.
    NotIdrFirst,
}

/// The low 5 bits of a NAL's header byte (its type), or 0 for an empty NAL.
///
/// Shared with `encoder.rs` (P7): both filter and classify source NALs by
/// type, and the integration tests cannot reach a crate-internal module, so
/// this copy is the single definition for the library side.
pub(crate) fn nal_type(n: &[u8]) -> u8 {
    n.first().map_or(0, |b| b & 0x1F)
}

/// The committed `fixtures/` directory of this repository.
#[must_use]
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

impl Source {
    /// Load `fixtures/<name>`.
    pub fn fixture(name: &str) -> Result<Source, SourceError> {
        let data = std::fs::read(fixtures_dir().join(name)).map_err(SourceError::Io)?;
        Source::from_annex_b(name, &data)
    }

    /// Split an Annex-B stream into access units (H.264 7.4.1.2.3): once the
    /// current AU has a slice, an SEI, SPS, PPS, AUD or type 14–18 NAL, or a
    /// slice with `first_mb_in_slice == 0`, starts the next one.
    pub fn from_annex_b(name: &str, data: &[u8]) -> Result<Source, SourceError> {
        let mut sps = None;
        let mut pps = None;
        let mut aus: Vec<Vec<Bytes>> = Vec::new();
        let mut current: Vec<Bytes> = Vec::new();
        let mut has_vcl = false;
        for nal in split_annex_b(data) {
            let t = nal_type(nal);
            let starts_picture = matches!(t, 1 | 5)
                && kvm_proto::h264::parse_slice_header_prefix(nal)
                    .is_ok_and(|p| p.first_mb_in_slice == 0);
            if has_vcl && (matches!(t, 6..=9 | 14..=18) || starts_picture) {
                aus.push(std::mem::take(&mut current));
                has_vcl = false;
            }
            match t {
                7 if sps.is_none() => sps = Some(Bytes::copy_from_slice(nal)),
                8 if pps.is_none() => pps = Some(Bytes::copy_from_slice(nal)),
                _ => {}
            }
            has_vcl |= matches!(t, 1 | 5);
            current.push(Bytes::copy_from_slice(nal));
        }
        if has_vcl {
            aus.push(current);
        }
        let frames: Vec<Frame> = aus
            .into_iter()
            .enumerate()
            .map(|(index, nals)| Frame {
                index,
                idr: nals.iter().any(|n| nal_type(n) == 5),
                nals,
            })
            .collect();
        if !frames.first().is_some_and(|f| f.idr) {
            return Err(SourceError::NotIdrFirst);
        }
        let gop_starts = frames.iter().filter(|f| f.idr).map(|f| f.index).collect();
        Ok(Source {
            name: name.to_owned(),
            sps: sps.ok_or(SourceError::NoParameterSets)?,
            pps: pps.ok_or(SourceError::NoParameterSets)?,
            frames,
            gop_starts,
        })
    }

    /// The first GOP start after `index`, wrapping to the first.
    #[must_use]
    pub fn next_gop_start(&self, index: usize) -> usize {
        self.gop_starts
            .iter()
            .copied()
            .find(|&s| s > index)
            .unwrap_or(0)
    }
}
