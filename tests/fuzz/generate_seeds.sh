#!/usr/bin/env bash
# Generate the Ogg fuzzer seed corpus.
#
# Builds the ogg_seed_gen helper (via the fuzz CMake project) and runs it to
# populate seeds_ogg/ with a spread of valid and edge-case Ogg streams. Each
# seed carries a neutral config tail so the whole stream survives the harness's
# tail-consumption (see fuzz_ogg_demux.cpp and the README).
#
# Seeds are byte-exact streams built with the same page builder the unit tests
# use, so no ffmpeg/oggenc is required.
#
# Point $CLANGXX at a Clang before running:
#   export CLANGXX=$(brew --prefix llvm)/bin/clang++   # macOS / Homebrew LLVM
#   export CLANGXX=clang++                             # Linux / system clang

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

clangxx="${CLANGXX:-clang++}"
out="seeds_ogg"

echo "[seed] configuring build-seeds/ with $clangxx"
cmake -B build-seeds -DCMAKE_CXX_COMPILER="$clangxx" . >/dev/null

echo "[seed] building ogg_seed_gen"
cmake --build build-seeds --target ogg_seed_gen >/dev/null

mkdir -p "$out"
./build-seeds/ogg_seed_gen "$out"

echo
echo "[seed] wrote $(find "$out" -type f | wc -l | tr -d ' ') seeds to $out/"
echo "[seed] seed the running corpus with: mkdir -p corpus_ogg && cp $out/* corpus_ogg/"
