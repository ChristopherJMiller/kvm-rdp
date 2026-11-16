//! Fixture tool (trusted input only — never run on a KVM capture): turn an
//! x264 Baseline stream with POC type 2 into an ES3-shaped stream (§11.5):
//! POC type 0 with `pic_order_cnt_lsb = 2 × frame_num` inserted into every
//! slice header, no `bitstream_restriction`, and the ES3's mislabels — a
//! level below the coded size (2.1 for 640×360), constraint flags 0, and a
//! VUI claiming full-range BT.601 (5/6/5). Slice data is copied bit for
//! bit, so the decoded frames are unchanged (gen-fixtures checks the md5).
//!
//! `rewrite` instead applies kvm-proto's §6.8 rewrite (`RewriteConfig::ES3`)
//! to every SPS, so gen-fixtures can show ffmpeg what the bridge would send.
//!
//! `slate` turns x264's one-IDR 1080p Baseline encode into the §6.4 slate,
//! carrying the parameter sets the client gets for the ES3's own stream:
//! the census SPS put through the bridge's §6.8 rewrite (`rewrite_sps` with
//! `RewriteConfig::ES3`, the bridge's default) and the census PPS, both byte
//! for byte — Windows App on macOS appears not to switch decoder
//! mid-surface (gen-fixtures has the story). x264's PPS must already equal the census
//! PPS, so the slice data is copied bit for bit; only the IDR's slice header
//! changes: `frame_num` written at the census width, a zero
//! `pic_order_cnt_lsb` inserted.
//!
//! Usage: `cargo run -p kvm-proto --example es3_fixture -- es3ify|rewrite|slate IN OUT`
use kvm_proto::bits::{BitReader, BitWriter, escape_rbsp_into, unescape_rbsp};
use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
use kvm_proto::h264::split_annex_b;
use kvm_proto::h264::sps_syntax::{ColourDescription, PocSyntax, SpsSyntax, VideoSignalType};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let [_, mode, input, output] = args.as_slice() else {
        return Err("usage: es3_fixture es3ify|rewrite|slate IN.h264 OUT.h264".into());
    };
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let out = match mode.as_str() {
        "es3ify" => transform(&data)?,
        "rewrite" => rewrite(&data)?,
        "slate" => slate(&data)?,
        other => return Err(format!("unknown mode {other}")),
    };
    std::fs::write(output, out).map_err(|e| format!("{output}: {e}"))
}

/// `census.md` `sps_hex` (trailing zero byte included) and `pps_hex` as §6.2
/// trims it: the ES3's parameter sets as sent.
const CENSUS_SPS: [u8; 17] = [
    0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14, 0x08,
    0x00,
];
const CENSUS_PPS: [u8; 4] = [0x68, 0xce, 0x31, 0x12];

fn slate(data: &[u8]) -> Result<Vec<u8>, String> {
    let sent = rewrite_sps(&CENSUS_SPS, &RewriteConfig::ES3).map_err(|e| format!("{e:?}"))?;
    let es3 = &sent.syntax;
    let PocSyntax::Type0 {
        log2_max_pic_order_cnt_lsb_minus4,
    } = es3.poc
    else {
        return Err("the census SPS is not POC type 0".into());
    };
    let out_widths = (
        es3.log2_max_frame_num_minus4 + 4,
        log2_max_pic_order_cnt_lsb_minus4 + 4,
    );
    // The slice data is copied, so the coded picture must be the census's:
    // the same macroblocks and cropping.
    let geometry = |s: &SpsSyntax| {
        (
            s.pic_width_in_mbs_minus1,
            s.pic_height_in_map_units_minus1,
            s.frame_mbs_only_flag,
            s.frame_cropping,
        )
    };
    let mut in_fn: Option<u32> = None;
    let (mut pps_seen, mut idrs) = (false, 0);
    let mut out = Vec::with_capacity(data.len() + 64);
    for nal in split_annex_b(data) {
        let new = match nal[0] & 0x1F {
            7 => {
                let s = SpsSyntax::parse(nal).map_err(|e| format!("SPS: {e:?}"))?;
                if s.profile_idc != 66 || s.poc != PocSyntax::Type2 {
                    return Err(format!(
                        "want a Baseline POC type 2 SPS, got {} {:?}",
                        s.profile_idc, s.poc
                    ));
                }
                if geometry(&s) != geometry(es3) {
                    return Err(format!(
                        "x264's geometry {:?} is not the census's {:?}",
                        geometry(&s),
                        geometry(es3)
                    ));
                }
                in_fn = Some(s.log2_max_frame_num_minus4 + 4);
                sent.nal.clone()
            }
            8 => {
                // Byte-identical, so every PPS field the slice data depends
                // on (CAVLC, pic_init_qp, chroma_qp_index_offset, deblocking
                // control) is the one x264 encoded with.
                if nal != CENSUS_PPS {
                    return Err(format!("x264's PPS {nal:02x?} is not the census's"));
                }
                pps_seen = true;
                nal.to_vec()
            }
            5 => {
                idrs += 1;
                retarget_idr_header(nal, in_fn.ok_or("slice before SPS")?, out_widths)?
            }
            1 => return Err("the slate is one IDR; x264 sent a non-IDR slice".into()),
            _ => nal.to_vec(),
        };
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&new);
    }
    if in_fn.is_none() || !pps_seen || idrs != 1 {
        return Err("want one in-band SPS, one PPS and one IDR slice".into());
    }
    Ok(out)
}

/// An IDR slice header from x264's SPS (POC type 2) to the census's: the
/// zero `frame_num` at the census width, then `idr_pic_id`, then a zero
/// `pic_order_cnt_lsb`, the rest copied bit for bit (CAVLC with no
/// `delta_pic_order_cnt_bottom`: the census PPS has neither CABAC nor
/// `bottom_field_pic_order_in_frame_present_flag`).
fn retarget_idr_header(
    nal: &[u8],
    in_fn: u32,
    (out_fn, out_lsb): Widths,
) -> Result<Vec<u8>, String> {
    let bits = |e| format!("slice: {e:?}");
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let stop = r.stop_bit_position().ok_or("slice without a stop bit")?;
    let mut w = BitWriter::new();
    for _ in 0..3 {
        w.write_ue(r.read_ue().map_err(bits)?); // first_mb_in_slice, slice_type, pps_id
    }
    if r.read_bits(in_fn).map_err(bits)? != 0 {
        return Err("an IDR's frame_num is not 0".into());
    }
    w.write_bits(0, out_fn); // frame_num
    w.write_ue(r.read_ue().map_err(bits)?); // idr_pic_id
    w.write_bits(0, out_lsb); // pic_order_cnt_lsb
    while r.position() < stop {
        w.write_bit(r.read_bit().map_err(bits)?);
    }
    w.write_trailing_bits();
    let mut out = vec![nal[0]];
    escape_rbsp_into(&w.into_rbsp(), &mut out);
    Ok(out)
}

fn rewrite(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    for nal in split_annex_b(data) {
        out.extend_from_slice(&[0, 0, 0, 1]);
        if nal[0] & 0x1F == 7 {
            let r = rewrite_sps(nal, &RewriteConfig::ES3).map_err(|e| format!("{e:?}"))?;
            out.extend_from_slice(&r.nal);
        } else {
            out.extend_from_slice(nal);
        }
    }
    Ok(out)
}

/// `(log2_max_frame_num, log2_max_pic_order_cnt_lsb)` of the stream's SPS.
type Widths = (u32, u32);

fn transform(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut widths: Option<Widths> = None;
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);
    for nal in split_annex_b(data) {
        let nal_type = nal[0] & 0x1F;
        let new = match nal_type {
            7 => {
                let (sps, w) = es3_sps(nal)?;
                widths = Some(w);
                sps
            }
            8 => {
                check_pps(nal)?;
                nal.to_vec()
            }
            1 | 5 => insert_poc_lsb(nal, widths.ok_or("slice before SPS")?)?,
            _ => nal.to_vec(),
        };
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&new);
    }
    Ok(out)
}

fn es3_sps(nal: &[u8]) -> Result<(Vec<u8>, Widths), String> {
    let mut s = SpsSyntax::parse(nal).map_err(|e| format!("SPS: {e:?}"))?;
    if s.poc != PocSyntax::Type2 || s.profile_idc != 66 {
        return Err(format!(
            "want Baseline POC type 2, got {} {:?}",
            s.profile_idc, s.poc
        ));
    }
    let log2_fn = s.log2_max_frame_num_minus4 + 4;
    let log2_lsb = log2_fn + 1; // 2 × frame_num never wraps before frame_num does
    s.poc = PocSyntax::Type0 {
        log2_max_pic_order_cnt_lsb_minus4: log2_lsb - 4,
    };
    s.level_idc = 21; // MaxFS 792 < 920 MBs: mislabelled like the ES3 (§6.8)
    s.constraint_flags = 0;
    let vui = s.vui.get_or_insert_with(Default::default);
    vui.video_signal_type = Some(VideoSignalType {
        video_format: 5,
        video_full_range_flag: true,
        colour_description: Some(ColourDescription {
            colour_primaries: 5,
            transfer_characteristics: 6,
            matrix_coefficients: 5,
        }),
    });
    vui.bitstream_restriction = None;
    Ok((s.to_nal(), (log2_fn, log2_lsb)))
}

/// The slice-header rewrite below copies everything after the inserted
/// field bit for bit, which is only right for CAVLC slices with no
/// `delta_pic_order_cnt_bottom`.
fn check_pps(nal: &[u8]) -> Result<(), String> {
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let bits = |e| format!("PPS: {e:?}");
    r.read_ue().map_err(bits)?; // pic_parameter_set_id
    r.read_ue().map_err(bits)?; // seq_parameter_set_id
    let cabac = r.read_bit().map_err(bits)?;
    let bottom_field_poc = r.read_bit().map_err(bits)?;
    if cabac || bottom_field_poc {
        return Err("want a CAVLC PPS without bottom_field_pic_order_in_frame_present_flag".into());
    }
    Ok(())
}

fn insert_poc_lsb(nal: &[u8], (log2_fn, log2_lsb): Widths) -> Result<Vec<u8>, String> {
    let bits = |e| format!("slice: {e:?}");
    let rbsp = unescape_rbsp(&nal[1..]);
    let mut r = BitReader::new(&rbsp);
    let stop = r.stop_bit_position().ok_or("slice without a stop bit")?;
    let mut w = BitWriter::new();
    for _ in 0..3 {
        w.write_ue(r.read_ue().map_err(bits)?); // first_mb_in_slice, slice_type, pps_id
    }
    let frame_num = r.read_bits(log2_fn).map_err(bits)?;
    w.write_bits(u64::from(frame_num), log2_fn);
    if nal[0] & 0x1F == 5 {
        w.write_ue(r.read_ue().map_err(bits)?); // idr_pic_id
    }
    let lsb = (2 * u64::from(frame_num)) % (1u64 << log2_lsb);
    w.write_bits(lsb, log2_lsb); // pic_order_cnt_lsb
    while r.position() < stop {
        w.write_bit(r.read_bit().map_err(bits)?);
    }
    w.write_trailing_bits();
    let mut out = vec![nal[0]];
    escape_rbsp_into(&w.into_rbsp(), &mut out);
    Ok(out)
}
