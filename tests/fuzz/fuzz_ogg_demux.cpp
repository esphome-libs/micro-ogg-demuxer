// Copyright 2026 Kevin Ahrendt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fuzz harness for micro_ogg::OggDemuxer.
//
// A demuxer is a pure parser of untrusted bytes: capture-pattern matching,
// segment-table lacing math, header accumulation into a fixed staging buffer,
// zero-copy pointer arithmetic into the caller's input, dynamic buffer growth,
// packet skipping, and CRC. Every one of those is driven directly by the input,
// so libFuzzer's coverage feedback plus ASan/UBSan is a natural fit. Unlike a
// fixed-point codec, there are no intentional-overflow paths, so the full UBSan
// set runs with no suppressions.
//
// Each input drives the demuxer four ways, sharing one payload:
//
//   1. Differential pass. Feed the whole payload to a packet-mode demuxer, a
//      streaming-mode demuxer, and a demuxer that switches modes only at packet
//      boundaries, all with identical lossless config (CRC off, buffer large
//      enough that nothing is skipped). All strip the same framing, so the
//      concatenated packet payloads must agree over their shared prefix, AND the
//      packet boundary offsets must agree over their shared prefix. The boundary
//      comparison is what catches merge/split bugs: a demuxer that fuses two
//      packets (e.g. by swallowing a 255-multiple packet's zero-length lacing
//      terminator) still produces identical concatenated bytes, so only the
//      boundary sequence exposes it. This is the get_next_packet()/
//      get_next_data() equivalence the unit test streaming_matches_packet_mode
//      asserts, plus the boundary-switch case, checked continuously on mutated
//      input. (Only shared prefixes are compared: on a malformed tail the modes
//      may recover to different depths.)
//
//   2. Packet-mode driven pass. get_next_packet() over a growing input window,
//      with config taken from the tail (CRC on/off, small vs. large max buffer
//      to exercise the skip path, and an optional fault-injecting allocator).
//
//   3. Streaming-mode driven pass. get_next_data() over a growing window.
//
//   4. Interleaved pass. One demuxer with the two entry points interleaved per
//      the control bytes, requesting switches regardless of boundary so the
//      mode-switch guard is hit mid-assembly and mid-skip. A switch rejected
//      mid-packet must return OGG_INVALID_MODE_SWITCH and consume nothing; the
//      pass then retries in the current mode and must still make progress,
//      exercising the documented recover-in-original-mode guarantee.
//
// A structural oracle runs on every call in every pass (see check_oracle): the
// demuxer never reports consuming more than it was offered, never returns a
// packet longer than the whole input, and, in streaming mode, never returns a
// body pointer outside the offered window. Returned packet bytes are always
// touched, so a bad zero-copy pointer or length trips ASan even when no
// invariant names it. A violation aborts, surfacing like any sanitizer finding.
//
// A configuration byte and a region of chunk-control bytes are consumed from the
// TAIL of the input via FuzzedDataProvider, so the front stays an intact Ogg
// payload.
//
// Two build modes:
//   1. libFuzzer:  compile with -fsanitize=fuzzer,address,undefined, which
//      exposes LLVMFuzzerTestOneInput. Use with a corpus directory:
//          ./fuzz_ogg_demux corpus_ogg/
//   2. Standalone: compile with FUZZ_STANDALONE defined. Takes file paths on
//      argv for crash reproduction, or with no args runs a torture battery.

#include "micro_ogg/ogg_demuxer.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <vector>

using micro_ogg::OggDemuxer;
using micro_ogg::OggDemuxerConfig;
using micro_ogg::OggDemuxResult;
using micro_ogg::OggDemuxState;

namespace {

// Bound on the chunk-control bytes pulled from the tail. Cycling over them
// drives the streaming window sizes while the front payload stays intact.
constexpr size_t MAX_CONTROL_BYTES = 64;

// Bound the per-pass work so libFuzzer keeps a high exec rate. A pathological
// input (tiny windows over a large payload) would otherwise run one call per
// byte; the cap processes only a prefix, which coverage feedback tolerates.
constexpr int MAX_ITERATIONS = 100000;

// ==============================================================================
// Fault-injecting allocator
// ==============================================================================
// File-scope because the demuxer's allocator hooks are plain C function pointers
// with no user-data argument, so the fail point lives in globals. Fails the Nth
// allocation to exercise OGG_ALLOCATION_FAILED and the realloc-failure path,
// mirroring the initial_allocation_failure and realloc_failure_during_assembly
// unit tests.
size_t g_alloc_calls = 0;
size_t g_alloc_fail_at = 0;  // 0 disables injection
bool g_alloc_active = false;

void* fault_alloc(size_t size) {
    if (g_alloc_active && ++g_alloc_calls == g_alloc_fail_at) {
        return nullptr;
    }
    return std::malloc(size);
}

void* fault_realloc(void* ptr, size_t size) {
    if (g_alloc_active && ++g_alloc_calls == g_alloc_fail_at) {
        // Contract: return nullptr WITHOUT freeing the original.
        return nullptr;
    }
    return std::realloc(ptr, size);
}

void fault_free(void* ptr) {
    std::free(ptr);
}

// True if `r` is one of the documented result codes.
bool is_valid_result(OggDemuxResult r) {
    switch (r) {
        case micro_ogg::OGG_OK:
        case micro_ogg::OGG_NEED_MORE_DATA:
        case micro_ogg::OGG_PACKET_SKIPPED:
        case micro_ogg::OGG_INVALID_CAPTURE:
        case micro_ogg::OGG_INVALID_VERSION:
        case micro_ogg::OGG_CRC_FAILED:
        case micro_ogg::OGG_STREAM_SEQUENCE_ERROR:
        case micro_ogg::OGG_STREAM_BOS_ERROR:
        case micro_ogg::OGG_STREAM_EOS_ERROR:
        case micro_ogg::OGG_STREAM_SERIAL_MISMATCH:
        case micro_ogg::OGG_STREAM_CONTINUATION_ERROR:
        case micro_ogg::OGG_ALLOCATION_FAILED:
        case micro_ogg::OGG_INVALID_MODE_SWITCH:
        case micro_ogg::OGG_INVALID_INPUT:
            return true;
    }
    return false;
}

// Read every byte of the packet so a bad zero-copy pointer or length trips ASan
// even when no explicit invariant catches it. volatile sink defeats DCE.
void touch_packet(const micro_ogg::OggPacket& p) {
    if (p.length == 0 || p.data == nullptr) {
        return;
    }
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < p.length; i++) {
        sink = static_cast<uint8_t>(sink ^ p.data[i]);
    }
    (void)sink;
}

// Structural invariants that must hold on every call in either mode. `streaming`
// selects the extra streaming-only bound (the returned body pointer must lie
// inside the offered window, since get_next_data never buffers). A violation
// aborts so sanitizers surface it.
void check_oracle(const OggDemuxState& st, const uint8_t* input, size_t offered,
                  size_t payload_size, bool streaming) {
    if (!is_valid_result(st.result)) {
        std::abort();
    }
    // Never claim to consume more input than was offered.
    if (st.bytes_consumed > offered) {
        std::abort();
    }
    // A rejected mode switch is documented to consume no input and leave state
    // untouched, so the caller can recover by continuing in the original mode.
    if (st.result == micro_ogg::OGG_INVALID_MODE_SWITCH && st.bytes_consumed != 0) {
        std::abort();
    }
    if (st.result != micro_ogg::OGG_OK) {
        return;
    }
    // A single packet can never exceed the whole input.
    if (st.packet.length > payload_size) {
        std::abort();
    }
    if (st.packet.length > 0 && st.packet.data == nullptr) {
        std::abort();
    }
    if (st.packet.length > 0) {
        // A zero-copy return points into the offered window; when it does, the
        // slice must not run past the window end. Without this, a pointer/length
        // bug whose overrun happens to stay inside the same allocation would slip
        // past ASan. A buffered return points into the internal buffer, outside
        // the window, and is bounded by payload_size above instead.
        // std::less gives a well-defined total order across allocations, so this
        // stays defined even when packet.data points into the internal buffer (a
        // different object than the input window); the builtin relational
        // operators are only specified for pointers into the same object.
        std::less<const uint8_t*> ptr_less;
        const uint8_t* window_end = input + offered;
        const bool points_into_window =
            !ptr_less(st.packet.data, input) && ptr_less(st.packet.data, window_end);
        if (points_into_window && ptr_less(window_end, st.packet.data + st.packet.length)) {
            std::abort();
        }
        // Streaming mode never buffers: the slice must always be a zero-copy view
        // inside the window.
        if (streaming && !points_into_window) {
            std::abort();
        }
    }
    touch_packet(st.packet);
}

// Feed `payload` to get_next_packet() over a growing input window, appending
// each complete packet's payload bytes to `out`. Mirrors the caller loop the
// unit tests use, but widens the window on a stall so the whole payload is
// processed rather than stopping at the first packet that outgrows one chunk.
//
// `boundaries` (optional) records the cumulative payload-byte offset at which
// each packet ends. Zero-length packets are excluded: packet mode surfaces
// genuine empty packets but streaming mode does not, so only nonzero packet
// ends are comparable across modes.
void run_packet_pass(OggDemuxer& d, const std::vector<uint8_t>& payload,
                     const std::vector<uint8_t>& ctrl, std::vector<uint8_t>* out,
                     std::vector<size_t>* boundaries) {
    size_t off = 0;
    size_t ctrl_idx = 0;
    size_t window_extra = 0;
    size_t total_payload_bytes = 0;
    int iterations = 0;

    while (off < payload.size() && iterations++ < MAX_ITERATIONS) {
        const uint8_t b = ctrl[ctrl_idx++ % ctrl.size()];
        const size_t chunk = 1 + (static_cast<size_t>(b) * 31);  // 1..7906 bytes
        const size_t remaining = payload.size() - off;
        const size_t win = std::min(chunk + window_extra, remaining);
        const uint8_t* ptr = payload.data() + off;

        OggDemuxState st = d.get_next_packet(ptr, win);
        check_oracle(st, ptr, win, payload.size(), /*streaming=*/false);

        if (st.result == micro_ogg::OGG_OK) {
            // Exercise the codec-wrapper accessors on a live packet. Their values
            // feed a volatile sink so the reads are not optimized away.
            volatile bool sink = d.current_page_has_continued_flag();
            sink = d.previous_page_ended_with_continued_packet();
            (void)sink;
            if (out != nullptr && st.packet.length > 0) {
                out->insert(out->end(), st.packet.data, st.packet.data + st.packet.length);
            }
            total_payload_bytes += st.packet.length;
            if (boundaries != nullptr && st.packet.length > 0) {
                boundaries->push_back(total_payload_bytes);
            }
            off += st.bytes_consumed;
            window_extra = 0;
        } else if (st.result == micro_ogg::OGG_PACKET_SKIPPED) {
            off += st.bytes_consumed;
            window_extra = 0;
        } else if (st.result == micro_ogg::OGG_NEED_MORE_DATA) {
            off += st.bytes_consumed;
            if (st.bytes_consumed == 0) {
                if (win == remaining) {
                    break;  // whole tail offered and still starved: end of stream
                }
                window_extra += chunk;  // widen so the next call sees more
            } else {
                window_extra = 0;
            }
        } else {
            break;  // fatal / format error
        }
    }

    // EOF drain: offer a zero-length window the way a caller flushes at end of
    // stream. When the payload ended mid-packet the demuxer is still assembling,
    // and a zero-length offer drives the assembler's input_len == 0 path. No
    // packet is emitted (it returns NEED_MORE_DATA), so `out` is unperturbed and
    // the differential comparison is unaffected.
    for (int flush = 0; flush < 2; flush++) {
        const uint8_t* ptr = payload.data() + std::min(off, payload.size());
        OggDemuxState st = d.get_next_packet(ptr, 0);
        check_oracle(st, ptr, 0, payload.size(), /*streaming=*/false);
        if (st.result != micro_ogg::OGG_NEED_MORE_DATA) {
            break;
        }
    }
}

// Feed `payload` to get_next_data() over a growing window, appending each body
// slice to `out`. Same growing-window strategy as run_packet_pass.
//
// `boundaries` (optional) records the cumulative payload-byte offset of each
// chunk with is_end_of_packet set. A zero-length end-of-packet (the terminator
// of a 255-multiple packet leading a continuation page) marks the end of the
// bytes already accumulated, so it records the same offset packet mode does.
void run_data_pass(OggDemuxer& d, const std::vector<uint8_t>& payload,
                   const std::vector<uint8_t>& ctrl, std::vector<uint8_t>* out,
                   std::vector<size_t>* boundaries) {
    size_t off = 0;
    size_t ctrl_idx = 0;
    size_t window_extra = 0;
    size_t total_payload_bytes = 0;
    int iterations = 0;

    while (off < payload.size() && iterations++ < MAX_ITERATIONS) {
        const uint8_t b = ctrl[ctrl_idx++ % ctrl.size()];
        const size_t chunk = 1 + (static_cast<size_t>(b) * 31);
        const size_t remaining = payload.size() - off;
        const size_t win = std::min(chunk + window_extra, remaining);
        const uint8_t* ptr = payload.data() + off;

        OggDemuxState st = d.get_next_data(ptr, win);
        check_oracle(st, ptr, win, payload.size(), /*streaming=*/true);

        if (st.result == micro_ogg::OGG_OK) {
            if (out != nullptr && st.packet.length > 0) {
                out->insert(out->end(), st.packet.data, st.packet.data + st.packet.length);
            }
            total_payload_bytes += st.packet.length;
            if (boundaries != nullptr && st.packet.is_end_of_packet) {
                boundaries->push_back(total_payload_bytes);
            }
            off += st.bytes_consumed;
            window_extra = 0;
        } else if (st.result == micro_ogg::OGG_NEED_MORE_DATA) {
            off += st.bytes_consumed;
            if (st.bytes_consumed == 0) {
                if (win == remaining) {
                    break;
                }
                window_extra += chunk;
            } else {
                window_extra = 0;
            }
        } else {
            break;
        }
    }
}

// Drive ONE demuxer, switching between get_next_packet() and get_next_data()
// only at packet boundaries -- the points the README documents as safe (after a
// returned packet or a streaming chunk with is_end_of_packet). `at_boundary`
// tracks those points conservatively: mid-packet (NEED_MORE_DATA) is never
// treated as safe. Legal switching is lossless, so the reconstructed bytes must
// match a single-mode traversal (the caller compares), and a switch at a tracked
// boundary must never be rejected (asserted here).
void run_interleaved_lossless(OggDemuxer& d, const std::vector<uint8_t>& payload,
                              const std::vector<uint8_t>& ctrl, std::vector<uint8_t>* out,
                              std::vector<size_t>* boundaries) {
    size_t off = 0;
    size_t ctrl_idx = 0;
    size_t window_extra = 0;
    size_t total_payload_bytes = 0;
    int iterations = 0;
    bool streaming = (ctrl[0] & 0x01) != 0;
    bool at_boundary = true;  // a fresh demuxer sits between packets

    while (off < payload.size() && iterations++ < MAX_ITERATIONS) {
        const uint8_t b = ctrl[ctrl_idx++ % ctrl.size()];
        if (at_boundary && (b & 0x80)) {
            streaming = !streaming;  // only ever switch where we know it is safe
        }
        const size_t chunk = 1 + (static_cast<size_t>(b & 0x7F) * 31);
        const size_t remaining = payload.size() - off;
        const size_t win = std::min(chunk + window_extra, remaining);
        const uint8_t* ptr = payload.data() + off;

        OggDemuxState st = streaming ? d.get_next_data(ptr, win) : d.get_next_packet(ptr, win);
        check_oracle(st, ptr, win, payload.size(), streaming);

        // Switching only at tracked boundaries must never trip the guard.
        if (st.result == micro_ogg::OGG_INVALID_MODE_SWITCH) {
            std::abort();
        }

        if (st.result == micro_ogg::OGG_OK) {
            if (out != nullptr && st.packet.length > 0) {
                out->insert(out->end(), st.packet.data, st.packet.data + st.packet.length);
            }
            total_payload_bytes += st.packet.length;
            // Mode switches happen only at boundaries, so every packet is
            // consumed wholly in one mode; record its end per that mode's rule.
            const bool packet_ended =
                streaming ? st.packet.is_end_of_packet : (st.packet.length > 0);
            if (boundaries != nullptr && packet_ended) {
                boundaries->push_back(total_payload_bytes);
            }
            off += st.bytes_consumed;
            window_extra = 0;
            at_boundary = streaming ? st.packet.is_end_of_packet : true;
        } else if (st.result == micro_ogg::OGG_PACKET_SKIPPED) {
            off += st.bytes_consumed;
            window_extra = 0;
            at_boundary = true;
        } else if (st.result == micro_ogg::OGG_NEED_MORE_DATA) {
            off += st.bytes_consumed;
            at_boundary = false;  // conservatively mid-packet until the next boundary
            if (st.bytes_consumed == 0) {
                if (win == remaining) {
                    break;
                }
                window_extra += chunk;
            } else {
                window_extra = 0;
            }
        } else {
            break;
        }
    }
}

// Adversarial counterpart to run_interleaved_lossless: request mode switches per
// the control bytes regardless of boundary, so the guard is hit on live state,
// including mid-assembly and mid-skip. A switch rejected mid-packet returns
// OGG_INVALID_MODE_SWITCH and consumes nothing (the oracle enforces zero bytes);
// we then retry the same window in the mode we are already in, which must succeed
// on intact state, so the traversal still advances. Run under the fuzzed config
// so the guard meets CRC, the skip path, and allocation faults.
void run_interleaved_pass(OggDemuxer& d, const std::vector<uint8_t>& payload,
                          const std::vector<uint8_t>& ctrl) {
    size_t off = 0;
    size_t ctrl_idx = 0;
    size_t window_extra = 0;
    int iterations = 0;
    bool streaming = (ctrl[0] & 0x01) != 0;

    while (off < payload.size() && iterations++ < MAX_ITERATIONS) {
        const uint8_t b = ctrl[ctrl_idx++ % ctrl.size()];
        const bool want_streaming = (b & 0x80) ? !streaming : streaming;
        const size_t chunk = 1 + (static_cast<size_t>(b & 0x7F) * 31);
        const size_t remaining = payload.size() - off;
        const size_t win = std::min(chunk + window_extra, remaining);
        const uint8_t* ptr = payload.data() + off;

        OggDemuxState st = want_streaming ? d.get_next_data(ptr, win) : d.get_next_packet(ptr, win);
        check_oracle(st, ptr, win, payload.size(), want_streaming);

        if (st.result == micro_ogg::OGG_INVALID_MODE_SWITCH) {
            // Mid-packet switch rejected: retry the same window in the current mode
            // so we keep making progress. This only succeeds if state is intact.
            st = streaming ? d.get_next_data(ptr, win) : d.get_next_packet(ptr, win);
            check_oracle(st, ptr, win, payload.size(), streaming);
        } else {
            streaming = want_streaming;  // switch (if any) accepted
        }

        if (st.result == micro_ogg::OGG_OK || st.result == micro_ogg::OGG_PACKET_SKIPPED) {
            off += st.bytes_consumed;
            window_extra = 0;
        } else if (st.result == micro_ogg::OGG_NEED_MORE_DATA) {
            off += st.bytes_consumed;
            if (st.bytes_consumed == 0) {
                if (win == remaining) {
                    break;
                }
                window_extra += chunk;
            } else {
                window_extra = 0;
            }
        } else {
            break;
        }
    }
}

// Compare two boundary-offset sequences over their shared prefix (the modes may
// recover to different depths on a malformed tail, exactly like the byte
// comparison). A mismatch means one traversal merged or split a packet. Abort.
void check_same_boundaries(const std::vector<size_t>& a, const std::vector<size_t>& b) {
    const size_t shared = std::min(a.size(), b.size());
    if (!std::equal(a.begin(), a.begin() + static_cast<ptrdiff_t>(shared), b.begin())) {
        std::abort();
    }
}

// Differential oracle: with lossless config (CRC off, buffer big enough that no
// packet is skipped) both modes strip identical framing, so over their shared
// prefixes the concatenated packet payloads must agree (a mismatch means a byte
// was read, dropped, or duplicated wrong) AND the packet boundary offsets must
// agree (a mismatch means a packet was merged or split -- invisible to the byte
// comparison, since fusing two packets leaves the concatenation unchanged).
// Abort on either.
void check_equivalence(const std::vector<uint8_t>& payload, const std::vector<uint8_t>& ctrl) {
    OggDemuxerConfig cfg;
    cfg.enable_crc = false;
    cfg.min_buffer_size = 64;
    // Large enough that no packet is skipped, so packet mode buffers everything
    // streaming mode offers. +4096 covers the empty-payload case.
    cfg.max_buffer_size = payload.size() + 4096;

    std::vector<uint8_t> packet_bytes;
    std::vector<uint8_t> data_bytes;
    std::vector<uint8_t> mixed_bytes;
    std::vector<size_t> packet_bounds;
    std::vector<size_t> data_bounds;
    std::vector<size_t> mixed_bounds;
    {
        OggDemuxer d(cfg);
        run_packet_pass(d, payload, ctrl, &packet_bytes, &packet_bounds);
    }
    {
        OggDemuxer d(cfg);
        run_data_pass(d, payload, ctrl, &data_bytes, &data_bounds);
    }
    {
        // A demuxer switched between modes only at packet boundaries strips the
        // same framing, so it must reconstruct the same bytes as pure packet mode.
        OggDemuxer d(cfg);
        run_interleaved_lossless(d, payload, ctrl, &mixed_bytes, &mixed_bounds);
    }

    const size_t shared = std::min(packet_bytes.size(), data_bytes.size());
    if (shared > 0 && std::memcmp(packet_bytes.data(), data_bytes.data(), shared) != 0) {
        std::abort();
    }
    const size_t shared_mixed = std::min(packet_bytes.size(), mixed_bytes.size());
    if (shared_mixed > 0 &&
        std::memcmp(packet_bytes.data(), mixed_bytes.data(), shared_mixed) != 0) {
        std::abort();
    }

    check_same_boundaries(packet_bounds, data_bounds);
    check_same_boundaries(packet_bounds, mixed_bounds);
}

}  // namespace

// NOLINTNEXTLINE(readability-identifier-naming): fixed libFuzzer entry point name
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Split the input into a payload prefix and a config/control tail. Integral
    // reads come off the BACK of the buffer, so the payload prefix stays an
    // intact Ogg stream: only the trailing cfg/control bytes are peeled off. The
    // same parsing runs in both build modes, so a libFuzzer crash file replays
    // identically under the standalone binary.
    FuzzedDataProvider fdp(data, size);
    const uint8_t cfg_byte = fdp.ConsumeIntegral<uint8_t>();
    size_t ctrl_len = std::min(MAX_CONTROL_BYTES, fdp.remaining_bytes() / 8);
    std::vector<uint8_t> ctrl;
    ctrl.reserve(ctrl_len);
    for (size_t i = 0; i < ctrl_len; i++) {
        ctrl.push_back(fdp.ConsumeIntegral<uint8_t>());
    }
    std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();

    if (ctrl.empty()) {
        ctrl.push_back(0x08);  // neutral default window (249 bytes)
    }
    if (payload.empty()) {
        return 0;
    }

    // Probe the null-input guard (a non-zero length with a null pointer) in both
    // entry points. Both are documented to return OGG_INVALID_INPUT without
    // touching state, so this cannot allocate or read through the null pointer.
    {
        OggDemuxer probe;
        check_oracle(probe.get_next_packet(nullptr, 8), nullptr, 8, payload.size(),
                     /*streaming=*/false);
        check_oracle(probe.get_next_data(nullptr, 8), nullptr, 8, payload.size(),
                     /*streaming=*/true);
    }

    // Decode the config byte.
    const bool enable_crc = (cfg_byte & 0x01) != 0;
    const bool small_buffer = (cfg_byte & 0x02) != 0;  // stress the skip path
    const bool inject_faults = (cfg_byte & 0x04) != 0;
    const bool replay = (cfg_byte & 0x08) != 0;
    const bool zero_min = (cfg_byte & 0x10) != 0;  // exercise the min_buffer default
    const bool tiny_max = (cfg_byte & 0x20) != 0;  // exercise the max < min clamp
    // A one-sided allocator (alloc without free) must be rejected by the ctor,
    // which then falls back to malloc/free. Mutually exclusive with fault
    // injection, which needs the full trio installed.
    const bool one_sided_alloc = (cfg_byte & 0x40) != 0 && !inject_faults;
    // A control byte seeds which allocation fails, so libFuzzer can walk the
    // fail point across the allocation sequence.
    const size_t fail_at = 1 + (static_cast<size_t>(ctrl[0]) % 16);

    // Pass 1: mode equivalence on lossless config (no fault injection).
    check_equivalence(payload, ctrl);

    // Passes 2 and 3: each mode driven with the fuzzed config.
    OggDemuxerConfig cfg;
    cfg.enable_crc = enable_crc;
    cfg.min_buffer_size = zero_min ? 0 : 64;  // 0 makes the ctor apply its default
    if (tiny_max) {
        cfg.max_buffer_size = 8;  // below min: the ctor clamps it up to min
    } else {
        cfg.max_buffer_size = small_buffer ? 512 : (payload.size() + 4096);
    }
    if (one_sided_alloc) {
        cfg.alloc = &fault_alloc;  // realloc/free left null: the ctor discards the set
    } else if (inject_faults) {
        cfg.alloc = &fault_alloc;
        cfg.realloc = &fault_realloc;
        cfg.free = &fault_free;
    }

    g_alloc_active = inject_faults;
    g_alloc_calls = 0;
    g_alloc_fail_at = inject_faults ? fail_at : 0;

    {
        OggDemuxer d(cfg);
        run_packet_pass(d, payload, ctrl, nullptr, nullptr);
        if (replay) {
            // Re-stream across a reset() to drive the reuse path (state reset,
            // buffer retained) that a single pass never exercises.
            d.reset();
            run_packet_pass(d, payload, ctrl, nullptr, nullptr);
        }
    }

    g_alloc_calls = 0;  // streaming mode allocates nothing, but reset the counter
    {
        OggDemuxer d(cfg);
        run_data_pass(d, payload, ctrl, nullptr, nullptr);
    }

    // Pass 4: adversarial interleaving under the fuzzed config. Requests mode
    // switches regardless of boundary so the guard is exercised mid-assembly and
    // mid-skip (the class of bug the switch enforcement was added for), meeting
    // CRC, the skip path, and allocation faults.
    g_alloc_calls = 0;
    {
        OggDemuxer d(cfg);
        run_interleaved_pass(d, payload, ctrl);
    }

    g_alloc_active = false;
    g_alloc_fail_at = 0;
    return 0;
}

#ifdef FUZZ_STANDALONE

namespace {

std::vector<uint8_t> read_file(const char* path) {
    std::vector<uint8_t> out;
    FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return out;
    }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n > 0) {
        out.resize(static_cast<size_t>(n));
        size_t got = std::fread(out.data(), 1, out.size(), f);
        out.resize(got);
    }
    std::fclose(f);
    return out;
}

uint32_t lcg_next(uint32_t& state) {
    state = state * 1664525U + 1013904223U;
    return state;
}

// A random blob salted with the "OggS" capture pattern at aligned-ish offsets so
// the page-header parser and segment-table walk engage on otherwise-random data.
std::vector<uint8_t> build_random_blob(uint32_t seed, size_t len) {
    std::vector<uint8_t> buf(len);
    uint32_t state = seed;
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(lcg_next(state) >> 24);
    }
    for (size_t i = 0; i + 4 < buf.size(); i += 64 + (seed % 200)) {
        buf[i] = 'O';
        buf[i + 1] = 'g';
        buf[i + 2] = 'g';
        buf[i + 3] = 'S';
        buf[i + 4] = 0;  // stream structure version 0
    }
    return buf;
}

void mutate_in_place(std::vector<uint8_t>& buf, uint32_t& rng_state) {
    if (buf.empty()) {
        return;
    }
    int n = 1 + static_cast<int>((lcg_next(rng_state) >> 24) & 0x07);
    for (int i = 0; i < n; i++) {
        uint32_t r = lcg_next(rng_state);
        size_t pos = r % buf.size();
        uint32_t kind = (r >> 24) & 0x07;
        switch (kind) {
            case 0:
            case 1:
                buf[pos] ^= static_cast<uint8_t>(1U << ((r >> 8) & 0x07));
                break;
            case 2:
            case 3:
                buf[pos] = static_cast<uint8_t>(r >> 16);
                break;
            case 4: {
                static const uint8_t interesting[] = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE, 255, 254};
                buf[pos] = interesting[(r >> 16) & 0x07];
                break;
            }
            case 5: {
                size_t run = 1 + ((r >> 16) & 0x0F);
                for (size_t k = 0; k < run && pos + k < buf.size(); k++) {
                    buf[pos + k] = 255;  // build 255-lacing runs (spanning packets)
                }
                break;
            }
            case 6:
                buf[pos] = static_cast<uint8_t>(buf[pos] + 1);
                break;
            default:
                buf[pos] = static_cast<uint8_t>(buf[pos] - 1);
                break;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    // Mutation mode: "./fuzz_ogg_demux -mutate <seedfile>"
    if (argc >= 3 && std::strcmp(argv[1], "-mutate") == 0) {
        std::vector<uint8_t> seed = read_file(argv[2]);
        if (seed.empty()) {
            std::fprintf(stderr, "[fuzz] seed file %s is empty or missing\n", argv[2]);
            return 1;
        }
        const char* iter_env = std::getenv("FUZZ_ITERATIONS");
        const int iters = iter_env != nullptr ? std::atoi(iter_env) : 2000;
        std::printf("[fuzz] mutation mode: seed=%s (%zu bytes), %d iterations\n", argv[2],
                    seed.size(), iters);

        uint32_t rng_state = 0xC0FFEEU;
        std::vector<uint8_t> scratch;

        LLVMFuzzerTestOneInput(seed.data(), seed.size());
        for (int i = 0; i < iters; i++) {
            scratch = seed;
            mutate_in_place(scratch, rng_state);
            LLVMFuzzerTestOneInput(scratch.data(), scratch.size());
            if ((i + 1) % 500 == 0) {
                std::printf("[fuzz] %d/%d mutated iterations ok\n", i + 1, iters);
            }
        }
        std::printf("[fuzz] mutation fuzzing complete, no sanitizer failures\n");
        return 0;
    }

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            std::vector<uint8_t> data = read_file(argv[i]);
            std::printf("[fuzz] %s (%zu bytes)\n", argv[i], data.size());
            LLVMFuzzerTestOneInput(data.data(), data.size());
        }
        std::printf("[fuzz] %d file(s) processed cleanly\n", argc - 1);
        return 0;
    }

    std::printf("[fuzz] standalone torture mode\n");

    // Empty / tiny inputs.
    {
        const uint8_t nothing[1] = {0};
        LLVMFuzzerTestOneInput(nothing, 0);
        LLVMFuzzerTestOneInput(nothing, 1);
    }

    // A lone / truncated capture pattern: the parser must wait, not over-read.
    {
        const uint8_t cap[4] = {'O', 'g', 'g', 'S'};
        LLVMFuzzerTestOneInput(cap, sizeof(cap));
    }
    // "OggS" + version + a huge segment count, but no segment table or body:
    // exercises the header-accumulation starve path.
    {
        const uint8_t hdr[27] = {'O', 'g', 'g', 'S', 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
                                 0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0xFF};
        LLVMFuzzerTestOneInput(hdr, sizeof(hdr));
    }

    // All-0xFF and all-zero runs around the staging-buffer and page boundaries.
    for (size_t len : {2U, 27U, 28U, 282U, 283U, 4096U}) {
        std::vector<uint8_t> ones(len, 0xFF);
        LLVMFuzzerTestOneInput(ones.data(), ones.size());
        std::vector<uint8_t> zeros(len, 0x00);
        LLVMFuzzerTestOneInput(zeros.data(), zeros.size());
    }

    // Random blobs salted with "OggS".
    const char* iter_env = std::getenv("FUZZ_ITERATIONS");
    const int kIterations = iter_env != nullptr ? std::atoi(iter_env) : 200;
    for (int i = 0; i < kIterations; i++) {
        size_t len = 512 + (static_cast<size_t>(i) * 37) % (32 * 1024);
        std::vector<uint8_t> blob = build_random_blob(static_cast<uint32_t>(i) * 2654435761U, len);
        LLVMFuzzerTestOneInput(blob.data(), blob.size());
        if ((i + 1) % 200 == 0) {
            std::printf("[fuzz] %d/%d random iterations ok\n", i + 1, kIterations);
        }
    }

    std::printf("[fuzz] standalone torture complete, no sanitizer failures\n");
    return 0;
}

#endif  // FUZZ_STANDALONE
