#!/usr/bin/env bash
# Synthetic H.264 fixtures for kvm-rdp (spec §11.5). Deterministic for a pinned
# ffmpeg/x264 (flake.lock): encoder -threads 1, sliced-threads=0, fixed GOP,
# scenecut=0. Never fed from the real KVM.
#   scripts/gen-fixtures.sh            fixtures/*.h264|.flv + *.manifest.json (committed)
#   scripts/gen-fixtures.sh large      fixtures/large/*.h264 (gitignored; spikes, benches)
#   scripts/gen-fixtures.sh clean      rm -rf fixtures/large
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-committed}
FF=(nice -n 19 ffmpeg -hide_banner -nostdin -loglevel error -y)
FP=(nice -n 19 ffprobe -v error)

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

# Count in-band SPS (nal_unit_type 7) NALs by scanning for Annex-B start codes
# directly. NOT implemented via ffmpeg's trace_headers bsf: empirically, its
# logging (via the auto-inserted extract_extradata bsf plus the internal h264
# parser) does not scale 1:1 with the real NAL count — a stream with exactly
# one real in-band SPS logged either 1 or 2 "nal_unit_type: 7" trace lines
# depending on what else was in the stream, and a stream with 3 real SPS
# logged 4 — so it cannot be trusted as a count. A byte-level scan for the
# start-code + SPS header byte (forbidden_zero_bit=0, nal_unit_type=7, any of
# the 4 possible nal_ref_idc values: 0x07/0x27/0x47/0x67) is exact.
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
    local sps_pps=$(mktemp)
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
  # "Connecting to KVM…" slate: one 1080p IDR (spec §6.4).
  "${FF[@]}" -f lavfi -i "color=c=0x202020:size=1920x1080:rate=30" \
    -vf "drawtext=fontfile=${KVM_RDP_FONT}:text='Connecting to KVM...':fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2,scale=out_color_matrix=bt709:out_range=pc,format=yuv420p" \
    -frames:v 1 -an -c:v libx264 -preset veryfast -profile:v main -level:v 4.0 -threads 1 \
    -x264-params "sliced-threads=0:keyint=1:min-keyint=1:scenecut=0:aud=1:repeat-headers=1:colorprim=bt709:transfer=bt709:colormatrix=bt709:range=pc" \
    -f h264 $d/slate_1080p.h264

  manifest $d/360p30_baseline_full.h264 30
  manifest $d/360p30_main_full.h264 30
  manifest $d/360p30_main_norepeat.h264 30
  manifest $d/360p30_main_longgop.h264 300
  manifest $d/360p30_main_slices.h264 30
  manifest $d/360p30_main_limited.h264 30
  manifest $d/360p30_main_limited_flagfull.h264 30
  manifest $d/480p30_main_full.h264 30
  manifest $d/360p30_main_full.flv 30
  manifest $d/slate_1080p.h264 1
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

case "$MODE" in
  committed) committed ;;
  large) large ;;
  clean) rm -rf fixtures/large ;;
  *) echo "usage: $0 [committed|large|clean]" >&2; exit 2 ;;
esac
