# microOggDemuxer fuzzer

libFuzzer harness for the Ogg container demuxer.

`fuzz_ogg_demux` drives `micro_ogg::OggDemuxer` with raw bytes. The demuxer is a
pure parser of untrusted input: capture-pattern matching, segment-table lacing
math, header accumulation into a fixed staging buffer, zero-copy pointer
arithmetic into the caller's buffer, dynamic buffer growth, packet skipping, and
CRC.

## What each input exercises

Every input drives the demuxer three ways over one shared payload:

1. **Mode-equivalence (differential) pass:** The whole payload is fed to a
   `get_next_packet()` demuxer and a `get_next_data()` (streaming) demuxer under
   identical lossless config (CRC off, buffer large enough that nothing is
   skipped). Both strip the same Ogg framing, so the concatenated packet
   payloads must agree and so must the packet boundary offsets (the cumulative
   payload position at each packet end). The boundary comparison is what catches
   merge/split bugs: fusing two packets leaves the concatenated bytes unchanged,
   so only the boundary sequence exposes it. This is the
   `streaming_matches_packet_mode` unit-test equivalence, checked continuously
   on mutated input. Only shared prefixes are compared: on a malformed tail the
   two modes may recover to different depths, which is not a bug.
2. **Packet-mode driven pass:** `get_next_packet()` over a growing input window,
   with config taken from the tail: CRC on/off, a small vs. large `max_buffer_size`
   (small stresses the oversized-packet skip path), an optional fault-injecting
   allocator, and an optional `reset()`-and-replay.
3. **Streaming-mode driven pass:** `get_next_data()` over a growing window.

The growing window means a partial page that outgrows one chunk is retried with
more contiguous bytes, so the whole payload is processed rather than stalling at
the first straddling packet.

## Structural oracle

On every call in every pass the harness asserts invariants that must hold
regardless of input (a violation aborts, surfacing like a sanitizer finding):

- the result code is one of the documented `OggDemuxResult` values;
- `bytes_consumed` never exceeds the bytes offered;
- a returned packet is never longer than the whole input, and non-empty packet
  data is never null;
- in streaming mode, the returned body pointer + length lies wholly within
  the offered window (get_next_data never buffers, so it must be a zero-copy
  slice of the caller's bytes).

On every `OGG_OK` the returned packet bytes are read in full, so a bad zero-copy
pointer or length trips ASan even when no named invariant catches it.

## Configuration tail

A cfg byte and a region of chunk-control bytes are consumed from the tail of
the input via `FuzzedDataProvider` (integral reads come off the back), so the
payload prefix stays an intact Ogg stream. The cfg byte's bits select CRC
(bit 0), a small max buffer to force the skip path (bit 1), a fault-injecting
allocator (bit 2), a `reset()`-and-replay (bit 3), a zero `min_buffer_size` that
makes the ctor apply its default (bit 4), a `max_buffer_size` below the minimum
that the ctor clamps (bit 5), and a one-sided allocator the ctor must reject
(bit 6). The control bytes drive the input window sizes. An exhausted provider
reads 0, i.e. neutral defaults. Seeds from `generate_seeds.sh` append a tail so a
whole `.ogg` stream survives these reads while libFuzzer still has a mutable
region to flip options.

## Requirements

- A Clang with the libFuzzer runtime.
  - **macOS:** `brew install llvm`; Apple's stock clang omits the libFuzzer
    runtime, so the Homebrew build is required for the libFuzzer target. (The
    standalone target below builds with Apple clang.)
  - **Linux:** the system `clang++` already ships libFuzzer.

Seed generation needs no external tools; seeds are built byte-exact with the
same page builder the unit tests use.

Point `$CLANGXX` at the right Clang:

```sh
export CLANGXX=$(brew --prefix llvm)/bin/clang++   # macOS / Homebrew LLVM
export CLANGXX=clang++                             # Linux / system clang
```

## Build

```sh
cd tests/fuzz
cmake -B build-libfuzzer -DCMAKE_CXX_COMPILER="$CLANGXX" .
cmake --build build-libfuzzer
```

For crash reproducers and the standalone torture battery (no libFuzzer runtime):

```sh
cmake -B build-standalone -DFUZZ_USE_LIBFUZZER=OFF -DCMAKE_CXX_COMPILER="$CLANGXX" .
cmake --build build-standalone
./build-standalone/fuzz_ogg_demux path/to/crashing.ogg   # reproduce a crash file
./build-standalone/fuzz_ogg_demux                        # parameterless torture battery
./build-standalone/fuzz_ogg_demux -mutate seeds_ogg/multi_page   # quick local mutation loop
```

The torture battery (no args) runs empty input, a lone/truncated capture
pattern, a header claiming a huge segment count with no body, all-`0xFF` and
all-zero runs around the staging-buffer and page boundaries, and random blobs
salted with `OggS`. `FUZZ_ITERATIONS` sets the random-blob and mutation counts.

## Seed corpus

```sh
./generate_seeds.sh           # creates seeds_ogg/
mkdir -p corpus_ogg
cp seeds_ogg/* corpus_ogg/
```

`generate_seeds.sh` spans single/multi-packet pages, multi-segment packets,
exact-multiple-of-255 packets, zero-length packets, packets spanning two and
several pages, a wide page with a long segment table, a multi-page
BOS/middle/EOS stream, and oversized packets (single-page and spanning) whose
cfg tail pre-sets the small buffer so the skip path is seeded directly.
`seeds_ogg/` and `corpus_ogg/` are local-only and gitignored; regenerate any
time.

### Merging an external corpus

Any pile of `.ogg` files (Vorbis, Opus, FLAC-in-Ogg all share identical
container framing) can be merged as generic seed material:

```sh
# point $OGGDIR at any directory of .ogg files
./build-libfuzzer/fuzz_ogg_demux -merge=1 -max_len=65536 corpus_ogg/ "$OGGDIR/"
```

`-merge=1` keeps only inputs that add new coverage against this harness.

## Run

```sh
./build-libfuzzer/fuzz_ogg_demux -dict=ogg.dict corpus_ogg/
```

Useful flags: `-max_total_time=60`, `-jobs=4`, `-workers=4`, `-max_len=65536`,
`-rss_limit_mb=4096`.

## Corpus coverage

```sh
./coverage.sh           # per-function report on stdout
./coverage.sh --html    # also write cov-html/ for line-by-line browsing
```

The script builds a separate `build-cov/` with clang source-based coverage
instrumentation, replays `corpus_ogg/` once via libFuzzer's `-runs=0` mode, and
renders the report with `llvm-cov`.

## When a crash is found

1. libFuzzer drops `crash-<sha>` in the current directory.
2. Minimize: `./build-libfuzzer/fuzz_ogg_demux -minimize_crash=1 -runs=10000 crash-<sha>`.
3. Reproduce under the standalone binary for cleaner stack traces:
   `./build-standalone/fuzz_ogg_demux crash-<sha>`.
4. Keep the reproducer in `crashes/` and replay after demuxer changes for
   regression cover:

   ```sh
   ./build-libfuzzer/fuzz_ogg_demux -runs=0 crashes/
   ```

   Crash inputs are otherwise local-only (the repo-wide `crash-*` gitignore
   pattern keeps them out of the tree); commit a real reproducer deliberately.
