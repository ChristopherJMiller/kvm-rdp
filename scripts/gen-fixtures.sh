#!/usr/bin/env bash
# Synthetic H.264 fixtures for kvm-rdp (spec §11.5). Deterministic for a pinned
# ffmpeg/x264 (flake.lock): encoder -threads 1, sliced-threads=0, fixed GOP,
# scenecut=0. Never fed from the real KVM.
#   scripts/gen-fixtures.sh            fixtures/*.h264|.flv + *.manifest.json (committed)
#   scripts/gen-fixtures.sh es3like    only fixtures/360p30_es3like_poc0.h264 (+ manifest)
#   scripts/gen-fixtures.sh slate      only fixtures/slate_1080p.h264 (+ manifest)
#   scripts/gen-fixtures.sh large      fixtures/large/*.h264 (gitignored; spikes, benches)
#   scripts/gen-fixtures.sh bench      ${CARGO_TARGET_DIR:-target}/bench-streams/*.h264 (kvm-bench's
#                                      §10.2 streams; -threads 4, not deterministic, never committed)
#   scripts/gen-fixtures.sh clean      rm -rf fixtures/large
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-committed}
FF=(nice -n 19 ffmpeg -hide_banner -nostdin -loglevel error -y)
FP=(nice -n 19 ffprobe -v error)
# Decode-only runs (md5, trace_headers): §13 caps ffmpeg at 4 threads. Encodes
# keep their own `-threads 1` (determinism), so FF itself is unchanged.
DEC=("${FF[@]}" -threads 4)

# 16-bit frame-counter barcode across the top: block k is white when bit k of
# the frame number n is set. $1/$2 = block width/height.
barcode() {
  local f="drawbox=x=0:y=0:w=iw:h=$2:color=black:t=fill" k
  for k in $(seq 0 15); do
    f="$f,drawbox=x=$((k * $1)):y=0:w=$1:h=$2:color=white:t=fill:enable='eq(mod(floor(n/$((1 << k))),2),1)'"
  done
  printf '%s' "$f"
}

# enc OUT WxH FRAMES PROFILE LEVEL RANGE(pc|tv) KEYINT BITRATE REPEAT_HEADERS BLOCK_W BLOCK_H [EXTRA_X264]
enc() {
  local out=$1 size=$2 frames=$3 profile=$4 level=$5 range=$6 keyint=$7 br=$8 rh=$9 bw=${10} bh=${11} extra=${12:-}
  "${FF[@]}" -f lavfi -i "testsrc2=size=${size}:rate=30" \
    -vf "$(barcode "$bw" "$bh"),scale=out_color_matrix=bt709:out_range=${range},format=yuv420p" \
    -frames:v "$frames" -an -c:v libx264 -preset veryfast -tune zerolatency \
    -profile:v "$profile" -level:v "$level" -bf 0 -threads 1 \
    -x264-params "sliced-threads=0:keyint=${keyint}:min-keyint=${keyint}:scenecut=0:aud=1:repeat-headers=${rh}:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=${range}${extra}" \
    -b:v "$br" -maxrate "$br" -bufsize "$br" -f h264 "$out"
}

# Whether a stream has an in-band SPS (nal_unit_type 7): a byte-level scan for
# a 3-byte start code followed by an SPS header byte (any of the 4 nal_ref_idc
# values: 0x07/0x27/0x47/0x67). Only presence (0 vs not 0) is used; a 4-byte
# start code ends in the same 3 bytes. Not ffmpeg's trace_headers, whose
# extradata handling logs SPS lines that do not match the real NAL count.
sps_count() {
  grep -c -aP '\x00\x00\x01[\x07\x27\x47\x67]' "$1" 2>/dev/null || true
}

# First value of a trace_headers field, or null when the field is absent.
tv() { awk -v k=" $2 " 'index($0, k) { print $NF; found = 1; exit } END { if (!found) print "null" }' <<<"$1"; }

manifest() { # $1 = fixture path, $2 = configured keyint
  local f=$1 keyint=$2 probe trace frames keys slices
  probe=$("${FP[@]}" -count_frames -select_streams v:0 \
    -show_entries stream=width,height,nb_read_frames -of json "$f")
  trace=$("${FF[@]}" -loglevel trace -i "$f" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  frames=$(jq '.streams[0].nb_read_frames | tonumber' <<<"$probe")
  keys=$("${FP[@]}" -select_streams v:0 -show_entries frame=key_frame -of csv=p=0 "$f" | grep -c '^1' || true)
  slices=$(grep -c ' first_mb_in_slice ' <<<"$trace" || true)
  jq -n \
    --arg name "$(basename "$f")" \
    --arg sha "$(sha256sum "$f" | cut -d' ' -f1)" \
    --argjson bytes "$(stat -c %s "$f")" \
    --argjson probe "$probe" \
    --argjson profile "$(tv "$trace" profile_idc)" \
    --argjson level "$(tv "$trace" level_idc)" \
    --argjson poc "$(tv "$trace" pic_order_cnt_type)" \
    --argjson full "$(tv "$trace" video_full_range_flag)" \
    --argjson br "$(tv "$trace" bitstream_restriction_flag)" \
    --argjson colour_primaries "$(tv "$trace" colour_primaries)" \
    --argjson matrix_coefficients "$(tv "$trace" matrix_coefficients)" \
    --argjson frames "$frames" --argjson keys "$keys" --argjson keyint "$keyint" \
    --argjson slices "$slices" \
    '{name: $name, sha256: $sha, bytes: $bytes,
      width: $probe.streams[0].width, height: $probe.streams[0].height,
      profile_idc: $profile, level_idc: $level, pic_order_cnt_type: $poc,
      video_full_range_flag: $full, bitstream_restriction_flag: $br,
      colour_primaries: $colour_primaries, matrix_coefficients: $matrix_coefficients,
      frames: $frames, key_frames: $keys, keyint: $keyint,
      slices_per_au: (if $frames > 0 then ($slices / $frames | floor) else 0 end)}' \
    > "${f}.manifest.json"
}

committed() {
  mkdir -p fixtures
  local d=fixtures
  #   OUT                                  SIZE     FRAMES PROFILE  LEVEL RANGE KEYINT BR    RH BW BH  EXTRA
  enc $d/360p30_baseline_full.h264         640x360  90     baseline 3.1   pc    30     600k  1  40 32
  enc $d/360p30_main_full.h264             640x360  90     main     3.1   pc    30     600k  1  40 32
  enc $d/360p30_main_norepeat.h264         640x360  90     main     3.1   pc    30     600k  0  40 32
  # R7: x264 with repeat-headers=0 emits NO in-band SPS/PPS at all in this
  # devshell's ffmpeg/x264 (verified empirically) — not even once, at the
  # very start of the stream — so the fixture above has zero SPS for
  # parse_sps to find. When that happens, splice in exactly one SPS+PPS pair
  # taken from the sibling 360p30_main_full stream, which uses identical
  # encoder params (same size/profile/level/keyint/range, differing only in
  # repeat-headers), prepended once ahead of the repeat-headers=0 payload.
  if [ "$(sps_count "$d/360p30_main_norepeat.h264")" -eq 0 ]; then
    local sps_pps
    sps_pps=$(mktemp)
    "${FF[@]}" -i "$d/360p30_main_full.h264" -frames:v 1 -c copy \
      -bsf:v "filter_units=pass_types=7-8" -f h264 "$sps_pps"
    cat "$sps_pps" "$d/360p30_main_norepeat.h264" > "${d}/360p30_main_norepeat.h264.tmp"
    mv "${d}/360p30_main_norepeat.h264.tmp" "$d/360p30_main_norepeat.h264"
    rm -f "$sps_pps"
  fi
  enc $d/360p30_main_longgop.h264          640x360  330    main     3.1   pc    300    300k  1  40 32
  enc $d/360p30_main_slices.h264           640x360  90     main     3.1   pc    30     600k  1  40 32  ":slice-max-size=250"
  enc $d/360p30_main_limited.h264          640x360  90     main     3.1   tv    30     600k  1  40 32
  enc $d/480p30_main_full.h264             854x480  90     main     3.1   pc    30     800k  1  40 32
  # Colour A/B twin: identical slices, only the SPS VUI range flag flipped.
  "${FF[@]}" -i $d/360p30_main_limited.h264 -c copy \
    -bsf:v h264_metadata=video_full_range_flag=1 -f h264 $d/360p30_main_limited_flagfull.h264
  # Demux oracle: the main stream muxed by ffmpeg's own FLV muxer.
  "${FF[@]}" -i $d/360p30_main_full.h264 -c copy -f flv $d/360p30_main_full.flv

  manifest $d/360p30_baseline_full.h264 30
  manifest $d/360p30_main_full.h264 30
  manifest $d/360p30_main_norepeat.h264 30
  manifest $d/360p30_main_longgop.h264 300
  manifest $d/360p30_main_slices.h264 30
  manifest $d/360p30_main_limited.h264 30
  manifest $d/360p30_main_limited_flagfull.h264 30
  manifest $d/480p30_main_full.h264 30
  manifest $d/360p30_main_full.flv 30
  slate
  es3like
}

es3_fixture() { cargo run -q -p kvm-proto --example es3_fixture -- "$@"; }

# check_sps_trace HEX FIELD=VALUE...: ffmpeg's trace_headers, an independent
# reader, must see every listed field of the Annex-B SPS HEX at its value.
check_sps_trace() {
  local hex=$1 f trace kv got
  shift
  f=$(mktemp)
  printf '%b' "$(printf '00000001%s' "$hex" | sed 's/../\\x&/g')" > "$f"
  trace=$("${DEC[@]}" -loglevel trace -f h264 -i "$f" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  rm -f "$f"
  for kv in "$@"; do
    got=$(tv "$trace" "${kv%%=*}")
    if [ "$got" != "${kv#*=}" ]; then
      echo "gen-fixtures: SPS $hex: ${kv%%=*} is $got, want ${kv#*=}" >&2
      return 1
    fi
  done
}

# The ES3-shaped POC-type-0 fixture (spec §11.5; Plan B deviation D6): an x264
# Baseline POC-type-2 encode of limited-range BT.709 pixels (what Leg A
# measured on the ES3's) with the ES3's GOP (keyint 60, ref 1), turned by
# kvm-proto's es3_fixture example into POC type 0 (pic_order_cnt_lsb =
# 2 × frame_num) carrying the ES3's mislabels — so the §6.8 VUI rewrite makes
# its VUI true, as it does the ES3's. Checked four ways: trace_headers reads
# the L0 goldens of kvm-proto Task 2.4 (census.md's sps_hex rewritten) with
# the fields that task claims; the decode is unchanged; kvm-proto's full §6.8
# rewrite of the fixture reads back in trace_headers as level 30,
# limited-range BT.709 and bitstream_restriction 0/1, with the decode still
# unchanged; and ffmpeg's own h264_metadata level+VUI rewrite of its SPS is
# recorded in the manifest, which kvm-proto's tests compare byte for byte
# with the bridge's.
es3like() {
  local d=fixtures work md5_src trace kv got hex
  check_sps_trace 67420028965403c0112f2cd40404041b41008540 level_idc=40 \
    video_full_range_flag=0 colour_primaries=1 transfer_characteristics=1 \
    matrix_coefficients=1 bitstream_restriction_flag=1 max_num_reorder_frames=0 \
    max_dec_frame_buffering=1 pic_order_cnt_type=0
  check_sps_trace 67420028965403c0112f2cd404040408 level_idc=40 video_full_range_flag=0 \
    colour_primaries=1 transfer_characteristics=1 matrix_coefficients=1 \
    bitstream_restriction_flag=0
  work=$(mktemp -d)
  enc "$work/src.h264" 640x360 120 baseline 3.0 tv 60 600k 1 40 32 ":ref=1"
  es3_fixture es3ify "$work/src.h264" $d/360p30_es3like_poc0.h264
  md5_src=$("${DEC[@]}" -i "$work/src.h264" -fps_mode passthrough -f md5 -)
  if [ "$("${DEC[@]}" -i $d/360p30_es3like_poc0.h264 -fps_mode passthrough -f md5 -)" != "$md5_src" ]; then
    echo "es3like: decoded frames differ from the x264 source" >&2
    rm -rf "$work"
    return 1
  fi
  es3_fixture rewrite $d/360p30_es3like_poc0.h264 "$work/rewritten.h264"
  trace=$("${DEC[@]}" -loglevel trace -i "$work/rewritten.h264" -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  for kv in level_idc=30 video_full_range_flag=0 colour_primaries=1 transfer_characteristics=1 \
    matrix_coefficients=1 bitstream_restriction_flag=1 max_num_reorder_frames=0 \
    max_dec_frame_buffering=1 pic_order_cnt_type=0; do
    got=$(tv "$trace" "${kv%%=*}")
    if [ "$got" != "${kv#*=}" ]; then
      echo "es3like: rewritten SPS ${kv%%=*} is $got, want ${kv#*=}" >&2
      rm -rf "$work"
      return 1
    fi
  done
  if [ "$("${DEC[@]}" -i "$work/rewritten.h264" -fps_mode passthrough -f md5 -)" != "$md5_src" ]; then
    echo "es3like: the rewrite changed the decoded frames" >&2
    rm -rf "$work"
    return 1
  fi
  "${FF[@]}" -i $d/360p30_es3like_poc0.h264 -frames:v 1 -c copy \
    -bsf:v "h264_metadata=level=3:video_full_range_flag=0:colour_primaries=1:transfer_characteristics=1:matrix_coefficients=1,filter_units=pass_types=7" \
    -f h264 "$work/meta.h264"
  hex=$(od -An -tx1 -v "$work/meta.h264" | tr -d ' \n' | sed 's/^00000001//')
  manifest $d/360p30_es3like_poc0.h264 60
  jq --arg h "$hex" '. + {ffmpeg_level_vui_sps_hex: $h}' \
    $d/360p30_es3like_poc0.h264.manifest.json > "$work/manifest.json"
  mv "$work/manifest.json" $d/360p30_es3like_poc0.h264.manifest.json
  rm -rf "$work"
}

# The "Connecting to KVM…" slate (spec §6.4): one 1080p IDR, sent on the
# surface the KVM's stream then plays on. Its SPS and PPS are byte for byte
# what the client gets for the ES3's stream: census.md's SPS through the
# bridge's own §6.8 rewrite, and census.md's PPS. That is Baseline (66) with
# the ES3's constraint flags (all 0, so not flagged Constrained Baseline),
# level 40, CAVLC, POC type 0, log2_max_frame_num 8, one reference frame,
# 1920×1088 cropped to 1080, limited-range BT.709 (1/1/1), no timing info,
# bitstream_restriction 0/1.
#
# Why (2026-11-16, the first Windows App session, on macOS): the slate
# stayed on screen for good while Windows App acked the KVM's frames and
# reported them decoded. The slate was then x264 Main, CABAC, full range,
# POC type 2, and the KVM's stream is Baseline CAVLC POC type 0 on the same
# surface. Windows App on macOS most likely keeps the decoder it set up from
# the surface's first SPS/PPS rather than switching it mid-surface;
# FreeRDP's software decoder (OpenH264 in L3) follows in-band SPS/PPS
# changes, which is why no test caught it. The slate must therefore not
# differ from the KVM's parameter sets: if the ES3's SPS or PPS changes
# (census.md), update the census constants in es3_fixture and kvm-rdp's
# slate test, then regenerate.
#
# How: x264 encodes Baseline with the census PPS's fields (ref=1;
# stitchable=1 for pic_init_qp 26; chroma-qp-offset=4) at limited range,
# then kvm-proto's es3_fixture `slate` swaps in the rewritten census SPS
# (refusing unless x264's PPS is the census's byte for byte) and retargets
# the IDR's slice header (frame_num at the census width, a zero
# pic_order_cnt_lsb). It copies the slice data bit for bit, so the decode
# stays identical (checked below). x264's SEI stays in the file, where it
# records the encoder settings; Slate::from_annex_b drops it (§6.3's
# allowlist).
slate() {
  local d=fixtures work md5_src trace kv got sps pps
  work=$(mktemp -d)
  "${FF[@]}" -f lavfi -i "color=c=0x202020:size=1920x1080:rate=30" \
    -vf "drawtext=fontfile=${KVM_RDP_FONT}:text='Connecting to KVM...':fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2,scale=out_color_matrix=bt709:out_range=tv,format=yuv420p" \
    -frames:v 1 -an -c:v libx264 -preset veryfast -profile:v baseline -level:v 4.0 -threads 1 \
    -x264-params "sliced-threads=0:keyint=1:min-keyint=1:scenecut=0:aud=1:repeat-headers=1:ref=1:stitchable=1:chroma-qp-offset=4:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=tv" \
    -f h264 "$work/x264.h264"
  es3_fixture slate "$work/x264.h264" $d/slate_1080p.h264
  md5_src=$("${DEC[@]}" -i "$work/x264.h264" -fps_mode passthrough -f md5 -)
  if [ "$("${DEC[@]}" -i $d/slate_1080p.h264 -fps_mode passthrough -f md5 -)" != "$md5_src" ]; then
    echo "slate: the decoded frame differs from the x264 source" >&2
    rm -rf "$work"
    return 1
  fi
  # ffmpeg's trace_headers, an independent reader, sees the KVM's shape.
  trace=$("${DEC[@]}" -loglevel trace -i $d/slate_1080p.h264 -c copy -bsf:v trace_headers -f null - 2>&1 || true)
  for kv in profile_idc=66 constraint_set0_flag=0 constraint_set1_flag=0 level_idc=40 \
    log2_max_frame_num_minus4=4 pic_order_cnt_type=0 log2_max_pic_order_cnt_lsb_minus4=4 \
    max_num_ref_frames=1 frame_mbs_only_flag=1 frame_crop_bottom_offset=4 \
    video_full_range_flag=0 colour_primaries=1 transfer_characteristics=1 matrix_coefficients=1 \
    timing_info_present_flag=0 bitstream_restriction_flag=1 max_num_reorder_frames=0 \
    max_dec_frame_buffering=1 entropy_coding_mode_flag=0 pic_init_qp_minus26=0 \
    chroma_qp_index_offset=4 frame_num=0 pic_order_cnt_lsb=0; do
    got=$(tv "$trace" "${kv%%=*}")
    if [ "$got" != "${kv#*=}" ]; then
      echo "slate: ${kv%%=*} is $got, want ${kv#*=}" >&2
      rm -rf "$work"
      return 1
    fi
  done
  manifest $d/slate_1080p.h264 1
  # The parameter sets as hex, for review; kvm-rdp's slate tests compare
  # them with the bridge's rewrite of census.md's.
  "${FF[@]}" -i $d/slate_1080p.h264 -c copy -bsf:v "filter_units=pass_types=7" -f h264 "$work/sps.h264"
  "${FF[@]}" -i $d/slate_1080p.h264 -c copy -bsf:v "filter_units=pass_types=8" -f h264 "$work/pps.h264"
  sps=$(od -An -tx1 -v "$work/sps.h264" | tr -d ' \n' | sed 's/^00000001//')
  pps=$(od -An -tx1 -v "$work/pps.h264" | tr -d ' \n' | sed 's/^00000001//')
  jq --arg s "$sps" --arg p "$pps" '. + {sps_hex: $s, pps_hex: $p}' \
    $d/slate_1080p.h264.manifest.json > "$work/manifest.json"
  mv "$work/manifest.json" $d/slate_1080p.h264.manifest.json
  rm -rf "$work"
}

large() {
  mkdir -p fixtures/large
  local d=fixtures/large
  enc $d/1080p30_main_full.h264      1920x1080 300 main 4.0 pc 30 4M 1 120 64
  enc $d/720p30_main_full.h264       1280x720  300 main 4.0 pc 30 2500k 1 80 48
  enc $d/1080p30_main_limited.h264   1920x1080 300 main 4.0 tv 30 4M 1 120 64
  "${FF[@]}" -i $d/1080p30_main_limited.h264 -c copy \
    -bsf:v h264_metadata=video_full_range_flag=1 -f h264 $d/1080p30_main_limited_flagfull.h264
}

# §10.2's bench streams (Plan E Task 5.1, DE10): testsrc2 under full-frame
# noise at 8 Mbit/s capped (no filler), the barcode drawn over the noise,
# an IDR every second, 20 s each — loops of at least 10 s — into the shared
# target dir. -threads 4 (§13), so not deterministic: nothing pins their
# bytes, and kvm-bench checks what it needs (unique FrameIds, the bitrate).
# sliced-threads=0, as every other fixture: -tune zerolatency with -threads 4
# would cut each AU into four slices, which no ES3 stream does; and
# -filter_threads 4, or the lavfi graph takes one thread per CPU (§13).
# Baseline, as the ES3 sends (census.md; PE12 review m7): Main's weighted
# prediction made admission's slice-header parse allocate per P frame
# (h264-reader's pred_weight_table), which no ES3 stream does.
bench_enc() { # OUT SIZE FPS BLOCK_W BLOCK_H SOURCE NOISE — SOURCE ends in = or : (its options follow)
  "${FF[@]}" -filter_threads 4 -f lavfi -i "${6}size=$2:rate=$3" \
    -vf "$7,$(barcode "$4" "$5"),scale=out_color_matrix=bt709:out_range=pc,format=yuv420p" \
    -t 20 -an -c:v libx264 -preset veryfast -tune zerolatency -profile:v baseline -level:v 4.2 \
    -bf 0 -threads 4 \
    -x264-params "sliced-threads=0:keyint=$3:min-keyint=$3:scenecut=0:aud=1:repeat-headers=1:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=pc" \
    -b:v 8M -maxrate 8M -bufsize 8M -f h264 "$1"
}
bench() {
  local d=${CARGO_TARGET_DIR:-target}/bench-streams
  mkdir -p "$d"
  # 30 and 60 fps at two resolutions (§10.2; 720p for resize churn).
  bench_enc "$d/bench_1080p30.h264" 1920x1080 30 120 64 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_1080p60.h264" 1920x1080 60 120 64 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_720p30.h264" 1280x720 30 80 48 "testsrc2=" "noise=alls=60:allf=t"
  bench_enc "$d/bench_720p60.h264" 1280x720 60 80 48 "testsrc2=" "noise=alls=60:allf=t"
  # Idle → motion (§10.2): 10 s of a still grey screen (only the barcode
  # changes), then 10 s of noise.
  bench_enc "$d/idle_motion_1080p30.h264" 1920x1080 30 120 64 "color=c=0x404040:" \
    "noise=alls=60:allf=t:enable='gte(t,10)'"
}

case "$MODE" in
  committed) committed ;;
  es3like) es3like ;;
  slate) slate ;;
  large) large ;;
  bench) bench ;;
  clean) rm -rf fixtures/large ;;
  *) echo "usage: $0 [committed|es3like|slate|large|bench|clean]" >&2; exit 2 ;;
esac
