//! The parameter-set state of one KVM session (§6.1): the active rewritten
//! SPS, the admitted PPSs, the pins, and the class of each change the pump
//! must hear about as `SpsChanged`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::pps::check_pps;
use crate::h264::rewrite::{RewriteConfig, RewriteFields, RewrittenSps, rewrite_sps};
use crate::h264::{
    SpsChange, SpsIncompatibleReason, SpsLimits, SpsPins, SpsSummary, check_sps_limits,
    classify_sps_change,
};
use crate::video::error::{AdmissionError, Framing, Incompatible, framing, incompatible};
use bytes::Bytes;
use h264_reader::Context;
use h264_reader::nal::sps::SeqParameterSet;

/// §6.1's classes for the pump (`SpsChanged{class}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamClass {
    /// The first parameter sets after an FLV open (no comparison).
    Initial,
    /// Dimensions or level changed.
    Resize,
    /// Anything else changed, including a PPS alone.
    Other,
}

/// The parameter sets the pump caches and sends before every IDR (§6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSets {
    /// The rewritten SPS NAL.
    pub sps: Bytes,
    /// Every admitted PPS NAL, by ascending `pic_parameter_set_id`.
    pub pps: Vec<Bytes>,
    pub summary: SpsSummary,
}

/// `SpsChanged`: the class, the new sets, and which rewrites applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamsChange {
    pub class: ParamClass,
    pub params: ParamSets,
    pub rewrites: RewriteFields,
}

/// The sets as they were before a tag, to tell whether it changed them.
pub(crate) type Snapshot = (Option<Bytes>, Vec<Bytes>);

pub(crate) struct ParamState {
    limits: SpsLimits,
    rewrite: RewriteConfig,
    max_pps: usize,
    pins: Option<SpsPins>,
    sps: Option<(Bytes, RewrittenSps)>,
    /// `(pic_parameter_set_id, trimmed NAL)`, ascending by id.
    pps: Vec<(u8, Bytes)>,
    /// h264-reader context holding exactly the active SPS and the PPSs.
    ctx: Context,
    initial_pending: bool,
}

impl ParamState {
    pub(crate) fn new(limits: SpsLimits, rewrite: RewriteConfig, max_pps: usize) -> Self {
        ParamState {
            limits,
            rewrite,
            max_pps,
            pins: None,
            sps: None,
            pps: Vec::new(),
            ctx: Context::new(),
            initial_pending: true,
        }
    }

    /// A new FLV connection: its first sets are `Initial`. Pins persist.
    pub(crate) fn flv_opened(&mut self) {
        self.initial_pending = true;
    }

    pub(crate) fn ctx(&self) -> &Context {
        &self.ctx
    }

    pub(crate) fn active_sps(&self) -> Option<&SeqParameterSet> {
        self.sps.as_ref().map(|(_, r)| &r.parsed)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        (
            self.sps.as_ref().map(|(b, _)| b.clone()),
            self.pps.iter().map(|(_, b)| b.clone()).collect(),
        )
    }

    /// A sequence header replaces every PPS: they leave the cache and the
    /// h264-reader context, which keeps only the active SPS (so a slice can
    /// never parse against a PPS the reported sets no longer list).
    pub(crate) fn clear_pps(&mut self) {
        self.pps.clear();
        let mut ctx = Context::new();
        if let Some((_, r)) = &self.sps {
            ctx.put_seq_param_set(r.parsed.clone());
        }
        self.ctx = ctx;
    }

    /// Rewrite, check and adopt one SPS (§6.8 then §6.1); returns its class
    /// for this tag, `None` when it is byte-identical to the active one.
    pub(crate) fn take_sps(&mut self, nal: &[u8]) -> Result<Option<ParamClass>, AdmissionError> {
        let r =
            rewrite_sps(nal, &self.rewrite).map_err(|e| incompatible(Incompatible::Rewrite(e)))?;
        check_sps_limits(&r.summary, &self.limits).map_err(|v| {
            incompatible(Incompatible::Sps(SpsIncompatibleReason::OutsideLimits(v)))
        })?;
        match self.pins {
            Some(p) => p.check(&r.summary).map_err(|f| {
                incompatible(Incompatible::Sps(
                    SpsIncompatibleReason::PinnedFieldChanged(f),
                ))
            })?,
            None => self.pins = Some(SpsPins::of(&r.summary)),
        }
        let class = match &self.sps {
            _ if self.initial_pending => Some(ParamClass::Initial),
            None => Some(ParamClass::Initial),
            // D4: a byte-identical repeat (in-band sets with every IDR) is no change.
            Some((old, _)) if old.as_ref() == r.nal.as_slice() => None,
            // Any other change goes through kvm-proto's one §6.1 classifier.
            Some((_, old)) => {
                match classify_sps_change(Some(&old.summary), &r.summary, &self.limits) {
                    SpsChange::Initial => Some(ParamClass::Initial),
                    SpsChange::Resize => Some(ParamClass::Resize),
                    SpsChange::Other => Some(ParamClass::Other),
                    SpsChange::Incompatible(reason) => {
                        return Err(incompatible(Incompatible::Sps(reason)));
                    }
                }
            }
        };
        // The context holds only the active SPS; each cached PPS is checked
        // again against it and dropped if it no longer passes.
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed.clone());
        let mut kept = Vec::with_capacity(self.pps.len());
        for (id, b) in core::mem::take(&mut self.pps) {
            if let Ok(p) = check_pps(&ctx, &b) {
                ctx.put_pic_param_set(p);
                kept.push((id, b));
            }
        }
        self.pps = kept;
        self.ctx = ctx;
        self.sps = Some((Bytes::copy_from_slice(&r.nal), r));
        Ok(class)
    }

    /// Check and adopt one PPS against the active SPS.
    pub(crate) fn take_pps(&mut self, nal: &Bytes) -> Result<(), AdmissionError> {
        let pps = check_pps(&self.ctx, nal).map_err(|e| incompatible(Incompatible::Pps(e)))?;
        let id = pps.pic_parameter_set_id.id();
        // `Bytes::clone()` would share `nal`'s backing allocation — the
        // demuxer's whole tag buffer (up to the 4 MiB tag cap, §6.2) — for
        // as long as this PPS stays cached. A PPS is tens of bytes, so copy
        // it out instead: up to `max_pps` cached copies cost nothing next
        // to one shared 4 MiB tag buffer kept alive per cached id (fix
        // round 1, m5).
        match self.pps.binary_search_by_key(&id, |(i, _)| *i) {
            Ok(at) => {
                if let Some(slot) = self.pps.get_mut(at) {
                    slot.1 = Bytes::copy_from_slice(nal);
                }
            }
            Err(at) => {
                if self.pps.len() >= self.max_pps {
                    return Err(framing(Framing::TooManyPps));
                }
                self.pps.insert(at, (id, Bytes::copy_from_slice(nal)));
            }
        }
        self.ctx.put_pic_param_set(pps);
        Ok(())
    }

    /// The change a tag made, if any: `class` from its SPSs, or `Other` when
    /// only the PPSs differ from `before`.
    pub(crate) fn change(
        &mut self,
        class: Option<ParamClass>,
        before: Snapshot,
    ) -> Option<ParamsChange> {
        let (sps, r) = self.sps.as_ref()?;
        let pps: Vec<Bytes> = self.pps.iter().map(|(_, b)| b.clone()).collect();
        let class = match class {
            Some(c) => c,
            None if before.0.as_ref() != Some(sps) || before.1 != pps => ParamClass::Other,
            None => return None,
        };
        let change = ParamsChange {
            class,
            params: ParamSets {
                sps: sps.clone(),
                pps,
                summary: r.summary.clone(),
            },
            rewrites: r.changed,
        };
        if class == ParamClass::Initial {
            self.initial_pending = false;
        }
        Some(change)
    }
}

/// Initial beats Resize beats Other beats nothing.
pub(crate) fn strongest(a: Option<ParamClass>, b: Option<ParamClass>) -> Option<ParamClass> {
    let rank = |c: Option<ParamClass>| match c {
        None => 0,
        Some(ParamClass::Other) => 1,
        Some(ParamClass::Resize) => 2,
        Some(ParamClass::Initial) => 3,
    };
    if rank(b) > rank(a) { b } else { a }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use crate::h264::rewrite::RewriteError;
    use crate::h264::sps_syntax::SpsSyntaxError;
    use crate::h264::test_support::{PpsCfg, SpsCfg};
    use crate::h264::{PinnedField, SpsLimitViolation};

    /// The ES3's own SPS and PPS (`census.md` `sps_hex`, `pps_hex`, the
    /// PPS's trailing zeros trimmed as `check_nal` does).
    const ES3_SPS: [u8; 17] = [
        0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14,
        0x08, 0x00,
    ];
    const ES3_PPS: [u8; 4] = [0x68, 0xce, 0x31, 0x12];

    fn state() -> ParamState {
        ParamState::new(SpsLimits::default(), RewriteConfig::ES3, 16)
    }

    fn baseline(width_mbs_minus1: u32, height_minus1: u32) -> Vec<u8> {
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = width_mbs_minus1;
        c.pic_height_in_map_units_minus1 = height_minus1;
        c.crop = None;
        c.build()
    }

    fn tag(st: &mut ParamState, sps: &[&[u8]], pps: &[&[u8]]) -> Option<ParamsChange> {
        let before = st.snapshot();
        let mut class = None;
        for s in sps {
            class = strongest(class, st.take_sps(s).unwrap());
        }
        for p in pps {
            st.take_pps(&Bytes::copy_from_slice(p)).unwrap();
        }
        st.change(class, before)
    }

    #[test]
    fn es3_sets_are_initial_rewritten_then_silent_when_repeated() {
        let mut st = state();
        let c = tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]).unwrap();
        assert_eq!(c.class, ParamClass::Initial);
        assert_eq!(c.params.summary.level_idc, 40);
        assert_eq!(c.params.pps, [Bytes::from_static(&ES3_PPS)]);
        assert!(c.rewrites.level && c.rewrites.vui && c.rewrites.restriction);
        assert_eq!(tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]), None);
        st.flv_opened();
        assert_eq!(
            tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]).unwrap().class,
            ParamClass::Initial
        );
    }

    #[test]
    fn size_change_is_resize_and_other_changes_are_other() {
        let mut st = state();
        tag(&mut st, &[&baseline(39, 22)], &[&PpsCfg::default().build()]);
        let r = tag(&mut st, &[&baseline(52, 29)], &[]).unwrap();
        assert_eq!(r.class, ParamClass::Resize);
        assert_eq!(
            (r.params.summary.width, r.params.summary.height),
            (848, 480)
        );
        // A PPS alone changing is Other.
        let pps = PpsCfg {
            chroma_qp_index_offset: 2,
            ..PpsCfg::default()
        };
        assert_eq!(
            tag(&mut st, &[], &[&pps.build()]).unwrap().class,
            ParamClass::Other
        );
        // The SPS changing only outside dimensions/level is Other.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = 52;
        c.pic_height_in_map_units_minus1 = 29;
        c.crop = None;
        c.log2_max_frame_num_minus4 = 2;
        assert_eq!(
            tag(&mut st, &[&c.build()], &[]).unwrap().class,
            ParamClass::Other
        );
    }

    #[test]
    fn pinned_fields_and_limits_refuse() {
        let mut st = state();
        tag(&mut st, &[&ES3_SPS], &[&ES3_PPS]);
        let main = SpsCfg::main_1080p().build(); // profile 77
        // The pins outlive an FLV reconnect (§6.1) …
        st.flv_opened();
        assert_eq!(
            st.take_sps(&main),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::PinnedFieldChanged(PinnedField::ProfileIdc)
            )))
        );
        // … and only a new session (`Start`) resets them.
        assert_eq!(state().take_sps(&main), Ok(Some(ParamClass::Initial)));
        let mut two_refs = SpsCfg::main_1080p();
        two_refs.profile_idc = 66;
        two_refs.max_num_ref_frames = 2;
        assert_eq!(
            state().take_sps(&two_refs.build()),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::TooManyRefFrames(2))
            )))
        );
    }

    #[test]
    fn section_6_1s_largest_size_needs_level_5_2_and_is_refused() {
        // 4096×2304 is 36 864 MBs: at 30 fps that is past level 5.1's MaxMBPS,
        // so the rewrite raises the level to 5.2 and the §6.1 level limit
        // refuses it (D9). Level 5.1 at 30 fps admits 32 768 MBs: 4096×2048.
        assert_eq!(
            state().take_sps(&baseline(255, 143)),
            Err(incompatible(Incompatible::Sps(
                SpsIncompatibleReason::OutsideLimits(SpsLimitViolation::Level(52))
            )))
        );
        assert_eq!(
            state().take_sps(&baseline(255, 127)),
            Ok(Some(ParamClass::Initial))
        );
    }

    #[test]
    fn an_sps_the_rewriter_cannot_read_is_stream_incompatible() {
        // seq_parameter_set_id 32 is outside H.264's range: the rewriter
        // refuses to read it, and there is no pass-through (§6.8).
        let mut w = crate::bits::BitWriter::new();
        w.write_u8(66);
        w.write_u8(0);
        w.write_u8(30);
        w.write_ue(32);
        w.write_trailing_bits();
        let mut nal = vec![0x67];
        crate::bits::escape_rbsp_into(&w.into_rbsp(), &mut nal);
        assert_eq!(
            state().take_sps(&nal),
            Err(incompatible(Incompatible::Rewrite(
                RewriteError::Unreadable(SpsSyntaxError::OutOfRange("seq_parameter_set_id"))
            )))
        );
    }

    #[test]
    fn an_unrecognized_level_is_stream_incompatible() {
        // RB3: the rewriter refuses a `level_idc` that names no Table A-1
        // level and is not level 1b (`RewriteError::UnknownLevel`);
        // admission classifies it as `stream_incompatible`, the same as any
        // other rewrite failure.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.level_idc = 0;
        c.crop = None;
        assert_eq!(
            state().take_sps(&c.build()),
            Err(incompatible(Incompatible::Rewrite(
                RewriteError::UnknownLevel(0)
            )))
        );
    }

    #[test]
    fn a_new_sps_drops_ppss_that_no_longer_parse() {
        let mut st = state();
        tag(&mut st, &[&baseline(39, 22)], &[&PpsCfg::default().build()]);
        // The PPS names SPS id 0; the new SPS has id 1, so the PPS goes.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = 39;
        c.pic_height_in_map_units_minus1 = 22;
        c.crop = None;
        c.seq_parameter_set_id = 1;
        let ch = tag(&mut st, &[&c.build()], &[]).unwrap();
        assert_eq!(ch.class, ParamClass::Other);
        assert!(ch.params.pps.is_empty());
    }

    #[test]
    fn more_than_sixteen_pps_ids_is_a_framing_violation() {
        let mut st = state();
        tag(&mut st, &[&ES3_SPS], &[]);
        for id in 0..16 {
            st.take_pps(&Bytes::from(
                PpsCfg {
                    pps_id: id,
                    ..PpsCfg::default()
                }
                .build(),
            ))
            .unwrap();
        }
        let seventeenth = Bytes::from(
            PpsCfg {
                pps_id: 16,
                ..PpsCfg::default()
            }
            .build(),
        );
        assert_eq!(st.take_pps(&seventeenth), Err(framing(Framing::TooManyPps)));
        // Replacing an existing id is fine.
        st.take_pps(&Bytes::from(
            PpsCfg {
                pps_id: 3,
                ..PpsCfg::default()
            }
            .build(),
        ))
        .unwrap();
    }

    /// A PPS refusal is `stream_incompatible`, not a transient framing
    /// violation (§6.9's "slice/PPS check fails" row), and the context a PPS
    /// is checked against holds only the *active* SPS: once a new SPS
    /// supersedes it, a PPS naming the old id is refused, not silently
    /// admitted against stale state (fix round 1, I1).
    #[test]
    fn a_refused_pps_is_stream_incompatible_and_needs_the_active_sps() {
        use crate::h264::pps::PpsRefusal;
        let mut st = state();
        tag(&mut st, &[&baseline(39, 22)], &[]);
        let groups = PpsCfg {
            slice_groups: true,
            ..PpsCfg::default()
        };
        assert_eq!(
            st.take_pps(&Bytes::from(groups.build())),
            Err(incompatible(Incompatible::Pps(PpsRefusal::SliceGroups)))
        );
        // After the active SPS becomes id 1, a PPS naming id 0 is refused.
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_width_in_mbs_minus1 = 39;
        c.pic_height_in_map_units_minus1 = 22;
        c.crop = None;
        c.seq_parameter_set_id = 1;
        tag(&mut st, &[&c.build()], &[]);
        assert_eq!(
            st.take_pps(&Bytes::from(PpsCfg::default().build())),
            Err(incompatible(Incompatible::Pps(PpsRefusal::UnknownSps(0))))
        );
    }

    /// Initial beats Resize beats Other beats nothing (fix round 1, m4): the
    /// test helper above only ever calls `strongest(None, x)`, so a rank
    /// swap between `Resize` and `Other` would pass every other test.
    #[test]
    fn strongest_ranks_initial_over_resize_over_other() {
        use ParamClass::{Initial, Other, Resize};
        assert_eq!(strongest(Some(Resize), Some(Other)), Some(Resize));
        assert_eq!(strongest(Some(Other), Some(Initial)), Some(Initial));
        assert_eq!(strongest(Some(Resize), None), Some(Resize));
    }
}
