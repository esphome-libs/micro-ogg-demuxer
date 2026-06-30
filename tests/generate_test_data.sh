#!/bin/bash

# Regenerate the checked-in real-world Ogg fixture used by the end-to-end test.
#
# Most of the test suite builds Ogg pages programmatically (see ogg_page_builder.h),
# which gives precise control over framing edge cases. This script produces the
# single real fixture decoded by an independent encoder (oggenc), so the suite
# also validates the demuxer against real-world output.
#
# Requires ffmpeg (to synthesize a WAV) and oggenc from vorbis-tools (to encode).
# The fixture is committed to the repo; you only need to run this if it changes.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/data"
mkdir -p "${DATA_DIR}"

TMP_WAV="$(mktemp -t micro_ogg_sine.XXXXXX.wav)"
trap 'rm -f "${TMP_WAV}"' EXIT

# 0.5 s, mono, 44.1 kHz, 440 Hz sine tone.
ffmpeg -hide_banner -loglevel error -f lavfi \
    -i "sine=frequency=440:duration=0.5:sample_rate=44100" \
    -ac 1 -f wav "${TMP_WAV}" -y

# --serial 1 keeps the bitstream serial fixed so the committed file is stable.
oggenc -Q --serial 1 -q 1 -o "${DATA_DIR}/sine_mono_44100.ogg" "${TMP_WAV}"

echo "Regenerated ${DATA_DIR}/sine_mono_44100.ogg"
