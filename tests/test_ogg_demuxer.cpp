// Copyright 2025 Kevin Ahrendt
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

// Unit tests for the microOggDemuxer.
//
// Test input is built by the page builder in ogg_page_builder.h, which lets each
// RFC 3533 framing case be constructed exactly. One real oggenc-produced file
// (tests/data/sine_mono_44100.ogg) provides an end-to-end check against an
// independent encoder.
//
// The runner follows the sibling repos (micro-vorbis, micro-mp3): a hand-rolled
// CHECK/CHECK_EQ harness, one static bool test_*() per case, and a TESTS[] table
// driven from main(). argv[1] is the data directory; argv[2] is an optional
// single-test filter.

#include "ogg_page_builder.h"

#include <micro_ogg/ogg_demuxer.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace micro_ogg;

// ============================================================================
// Assertion macros (same CHECK/CHECK_EQ style as the sibling test suites)
// ============================================================================

// Abort the current test on the first failed condition, reporting the line.
#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::printf("    CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return false;                                                     \
        }                                                                     \
    } while (0)

// Like CHECK(a == b) but reports both operands' values on failure.
#define CHECK_EQ(a, b)                                                  \
    do {                                                                \
        const long long _va = static_cast<long long>(a);                \
        const long long _vb = static_cast<long long>(b);                \
        if (_va != _vb) {                                               \
            std::printf("    CHECK_EQ failed: %s == %s (%lld vs %lld) " \
                        "(line %d)\n",                                  \
                        #a, #b, _va, _vb, __LINE__);                    \
            return false;                                               \
        }                                                               \
    } while (0)

// ============================================================================
// Demux drivers
// ============================================================================

struct CollectedPacket {
    std::vector<uint8_t> data;
    int64_t granule = 0;
    bool is_bos = false;
    bool is_eos = false;
    bool is_last_on_page = false;
    bool zero_copy = false;  // payload pointed into the presented input window
};

struct DriveResult {
    std::vector<CollectedPacket> packets;
    OggDemuxResult final_result = OGG_NEED_MORE_DATA;
    int skipped = 0;
    bool errored = false;  // a negative (error) result code was returned
    bool stalled = false;  // driver made no progress (guards against hangs)
    bool saw_bos = false;
    bool saw_eos = false;
};

// Feed `stream` to get_next_packet() in windows of at most `chunk` bytes,
// advancing by bytes_consumed each call. chunk == SIZE_MAX feeds whole buffers.
static DriveResult drive_packets(OggDemuxer& d, const std::vector<uint8_t>& stream, size_t chunk) {
    DriveResult r;
    size_t offset = 0;
    const size_t limit = stream.size() * 16 + 4096;
    size_t iters = 0;

    while (offset < stream.size()) {
        if (++iters > limit) {
            r.stalled = true;
            break;
        }
        const size_t avail = stream.size() - offset;
        const size_t win = chunk < avail ? chunk : avail;
        const uint8_t* ptr = stream.data() + offset;

        OggDemuxState st = d.get_next_packet(ptr, win);
        r.final_result = st.result;

        if (st.result == OGG_OK) {
            CollectedPacket cp;
            cp.data.assign(st.packet.data, st.packet.data + st.packet.length);
            cp.granule = st.packet.granule_position;
            cp.is_bos = st.packet.is_bos;
            cp.is_eos = st.packet.is_eos;
            cp.is_last_on_page = st.packet.is_last_on_page;
            cp.zero_copy =
                (st.packet.data >= ptr && st.packet.data + st.packet.length <= ptr + win);
            r.saw_bos = r.saw_bos || cp.is_bos;
            r.saw_eos = r.saw_eos || cp.is_eos;
            r.packets.push_back(std::move(cp));
            offset += st.bytes_consumed;
        } else if (st.result == OGG_NEED_MORE_DATA) {
            offset += st.bytes_consumed;
            if (st.bytes_consumed == 0) {
                if (win == avail) {
                    break;  // all available bytes were offered; stream ends here
                }
                r.stalled = true;  // demuxer needed more than the window held
                break;
            }
        } else if (st.result == OGG_PACKET_SKIPPED) {
            r.skipped++;
            offset += st.bytes_consumed;
        } else {
            r.errored = true;
            break;
        }
    }
    return r;
}

// Feed `stream` to get_next_data() (streaming mode), reassembling the body
// chunks into whole packets at is_end_of_packet boundaries.
static DriveResult drive_data(OggDemuxer& d, const std::vector<uint8_t>& stream, size_t chunk) {
    DriveResult r;
    size_t offset = 0;
    const size_t limit = stream.size() * 16 + 4096;
    size_t iters = 0;
    CollectedPacket cur;

    while (offset < stream.size()) {
        if (++iters > limit) {
            r.stalled = true;
            break;
        }
        const size_t avail = stream.size() - offset;
        const size_t win = chunk < avail ? chunk : avail;
        const uint8_t* ptr = stream.data() + offset;

        OggDemuxState st = d.get_next_data(ptr, win);
        r.final_result = st.result;

        if (st.result == OGG_OK) {
            const uint8_t* body = st.packet.data;
            // A packet may arrive over several chunks; it is zero-copy only if every
            // chunk's full slice lay inside the offered window.
            const bool in_window = (body >= ptr && body + st.packet.length <= ptr + win);
            cur.zero_copy = cur.data.empty() ? in_window : (cur.zero_copy && in_window);
            cur.data.insert(cur.data.end(), body, body + st.packet.length);
            r.saw_bos = r.saw_bos || st.packet.is_bos;
            r.saw_eos = r.saw_eos || st.packet.is_eos;
            if (st.packet.is_end_of_packet) {
                cur.granule = st.packet.granule_position;
                cur.is_eos = st.packet.is_eos;
                cur.is_last_on_page = st.packet.is_last_on_page;
                r.packets.push_back(std::move(cur));
                cur = CollectedPacket();
            }
            offset += st.bytes_consumed;
        } else if (st.result == OGG_NEED_MORE_DATA) {
            offset += st.bytes_consumed;
            if (st.bytes_consumed == 0) {
                if (win == avail) {
                    break;
                }
                r.stalled = true;
                break;
            }
        } else {
            r.errored = true;
            break;
        }
    }
    return r;
}

// Compare two packet sequences by payload only.
static bool same_payloads(const std::vector<CollectedPacket>& a,
                          const std::vector<CollectedPacket>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i].data != b[i].data) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Fixture loading and allocator instrumentation
// ============================================================================

static std::string g_data_dir;

static std::vector<uint8_t> read_file(const std::string& name) {
    std::ifstream f(g_data_dir + "/" + name, std::ios::binary);
    if (!f) {
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

// Allocator callbacks that count calls, used to assert which allocator the
// demuxer uses and how often.
static size_t g_alloc_count = 0;
static size_t g_realloc_count = 0;
static size_t g_free_count = 0;

static void reset_alloc_counts() {
    g_alloc_count = 0;
    g_realloc_count = 0;
    g_free_count = 0;
}

static void* counting_alloc(size_t s) {
    g_alloc_count++;
    return std::malloc(s);
}
static void* counting_realloc(void* p, size_t s) {
    g_realloc_count++;
    return std::realloc(p, s);
}
static void counting_free(void* p) {
    if (p) {
        g_free_count++;
    }
    std::free(p);
}

// Allocator callbacks that always fail, used to test allocation-failure paths.
static void* failing_alloc(size_t) {
    return nullptr;
}
static void* failing_realloc(void*, size_t) {
    return nullptr;
}

// ============================================================================
// Tests: core packet extraction
// ============================================================================

// A single small packet on one BOS+EOS page is returned zero-copy with the
// correct payload and stream flags.
static bool test_single_packet_zero_copy() {
    std::vector<uint8_t> payload = make_pattern(7, 50);
    std::vector<uint8_t> stream =
        page_with_packets({payload}, 1, 0, 999, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.packets[0].data == payload);
    CHECK(r.packets[0].is_bos);
    CHECK(r.packets[0].is_eos);
    CHECK(r.packets[0].is_last_on_page);
    CHECK(r.packets[0].zero_copy);
    CHECK_EQ(r.packets[0].granule, 999);
    return true;
}

// Several packets on one page: payloads, per-packet flags, and last-on-page all
// resolve correctly, and every packet is zero-copy.
static bool test_multiple_packets_one_page() {
    std::vector<uint8_t> a = make_pattern(1, 30);
    std::vector<uint8_t> b = make_pattern(2, 40);
    std::vector<uint8_t> c = make_pattern(3, 50);
    std::vector<uint8_t> stream =
        page_with_packets({a, b, c}, 1, 0, 4242, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 3);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == b);
    CHECK(r.packets[2].data == c);
    CHECK(r.packets[0].is_bos);
    CHECK(!r.packets[1].is_bos);
    CHECK(!r.packets[2].is_bos);
    CHECK(!r.packets[0].is_last_on_page);
    CHECK(!r.packets[1].is_last_on_page);
    CHECK(r.packets[2].is_last_on_page);
    CHECK(r.packets[2].is_eos);
    CHECK(r.packets[0].zero_copy && r.packets[1].zero_copy && r.packets[2].zero_copy);
    return true;
}

// A packet larger than 255 bytes (multiple lacing values) is reassembled
// contiguously within the page and still returned zero-copy.
static bool test_multi_segment_packet() {
    std::vector<uint8_t> payload = make_pattern(9, 600);  // lacing 255, 255, 90
    std::vector<uint8_t> stream =
        page_with_packets({payload}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK_EQ(r.packets[0].data.size(), 600);
    CHECK(r.packets[0].data == payload);
    CHECK(r.packets[0].zero_copy);
    return true;
}

// A packet whose size is an exact multiple of 255 needs a terminating 0 lacing
// value. Verify both 255 and 510 are extracted at the right boundaries.
static bool test_packet_exact_multiple_of_255() {
    std::vector<uint8_t> a = make_pattern(4, 255);  // lacing 255, 0
    std::vector<uint8_t> b = make_pattern(5, 510);  // lacing 255, 255, 0
    std::vector<uint8_t> stream =
        page_with_packets({a, b}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 2);
    CHECK_EQ(r.packets[0].data.size(), 255);
    CHECK_EQ(r.packets[1].data.size(), 510);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == b);
    return true;
}

// A zero-length packet (lacing value 0) between two packets is surfaced as an
// empty OGG_OK packet.
static bool test_zero_length_packet() {
    std::vector<uint8_t> a = make_pattern(1, 20);
    std::vector<uint8_t> empty;
    std::vector<uint8_t> c = make_pattern(2, 20);
    std::vector<uint8_t> stream =
        page_with_packets({a, empty, c}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 3);
    CHECK(r.packets[0].data == a);
    CHECK_EQ(r.packets[1].data.size(), 0);
    CHECK(r.packets[2].data == c);
    CHECK(r.packets[2].is_last_on_page);
    return true;
}

// An empty page (segment_count == 0) between data pages yields no packet and the
// stream continues.
static bool test_empty_page_skipped() {
    std::vector<uint8_t> a = make_pattern(1, 10);
    std::vector<uint8_t> c = make_pattern(2, 10);

    std::vector<uint8_t> stream;
    append_bytes(stream, page_with_packets({a}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    PageSpec empty;
    empty.serial = 1;
    empty.sequence = 1;
    append_bytes(stream, make_page(empty));
    append_bytes(stream, page_with_packets({c}, 1, 2, 0, OGG_END_OF_STREAM));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 2);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == c);
    return true;
}

// ============================================================================
// Tests: packets spanning page boundaries
// ============================================================================

// A packet that spans two pages is reassembled into the internal buffer (not
// zero-copy) with its full payload and the completing page's granule and EOS.
static bool test_packet_spanning_two_pages() {
    std::vector<uint8_t> payload = make_pattern(11, 300);

    std::vector<uint8_t> stream;
    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    p0.segments = {255};  // 255 bytes, packet continues
    p0.body.assign(payload.begin(), payload.begin() + 255);
    append_bytes(stream, make_page(p0));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.granule = 7777;
    p1.header_type = OGG_CONTINUED_PACKET | OGG_END_OF_STREAM;
    append_packet_lacing(p1.segments, 45);  // remaining 45 bytes terminate the packet
    p1.body.assign(payload.begin() + 255, payload.end());
    append_bytes(stream, make_page(p1));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.packets[0].data == payload);
    CHECK(!r.packets[0].zero_copy);
    CHECK(r.packets[0].is_eos);
    CHECK(r.packets[0].is_last_on_page);
    CHECK_EQ(r.packets[0].granule, 7777);
    CHECK(d.current_page_has_continued_flag());
    return true;
}

// A packet spanning three pages (two continuation boundaries) reassembles fully.
static bool test_packet_spanning_three_pages() {
    std::vector<uint8_t> payload = make_pattern(13, 540);

    std::vector<uint8_t> stream;
    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    p0.segments = {255};
    p0.body.assign(payload.begin(), payload.begin() + 255);
    append_bytes(stream, make_page(p0));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.header_type = OGG_CONTINUED_PACKET;
    p1.segments = {255};
    p1.body.assign(payload.begin() + 255, payload.begin() + 510);
    append_bytes(stream, make_page(p1));

    PageSpec p2;
    p2.serial = 1;
    p2.sequence = 2;
    p2.header_type = OGG_CONTINUED_PACKET | OGG_END_OF_STREAM;
    append_packet_lacing(p2.segments, 30);
    p2.body.assign(payload.begin() + 510, payload.end());
    append_bytes(stream, make_page(p2));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.packets[0].data == payload);
    CHECK(!r.packets[0].zero_copy);
    CHECK(r.packets[0].is_eos);
    return true;
}

// Feeding the same stream as one buffer and in small windows must produce
// identical packets. Small windows force packets to span input boundaries,
// which exercises the assembly path instead of zero-copy.
static bool test_chunked_input_invariance() {
    std::vector<uint8_t> a = make_pattern(1, 40);
    std::vector<uint8_t> b = make_pattern(2, 355);
    std::vector<uint8_t> c = make_pattern(3, 20);
    std::vector<uint8_t> dpkt = make_pattern(4, 70);

    // Paginate so packet B spans the page boundary.
    std::vector<uint8_t> stream;
    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    append_packet_lacing(p0.segments, a.size());
    p0.segments.push_back(255);  // first 255 bytes of B, continues
    append_bytes(p0.body, a);
    p0.body.insert(p0.body.end(), b.begin(), b.begin() + 255);
    append_bytes(stream, make_page(p0));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.header_type = OGG_CONTINUED_PACKET;
    append_packet_lacing(p1.segments, b.size() - 255);  // 100 bytes finish B
    append_packet_lacing(p1.segments, c.size());
    p1.body.insert(p1.body.end(), b.begin() + 255, b.end());
    append_bytes(p1.body, c);
    append_bytes(stream, make_page(p1));

    append_bytes(stream, page_with_packets({dpkt}, 1, 2, 5555, OGG_END_OF_STREAM));

    OggDemuxer ref_demux;
    DriveResult ref = drive_packets(ref_demux, stream, SIZE_MAX);
    CHECK(!ref.errored);
    CHECK_EQ(ref.packets.size(), 4);
    CHECK(ref.packets[0].data == a);
    CHECK(ref.packets[1].data == b);
    CHECK(ref.packets[2].data == c);
    CHECK(ref.packets[3].data == dpkt);
    CHECK(!ref.packets[1].zero_copy);  // B spans pages, so it is buffered

    for (size_t chunk : {static_cast<size_t>(1), static_cast<size_t>(3), static_cast<size_t>(7),
                         static_cast<size_t>(64)}) {
        OggDemuxer d;
        DriveResult r = drive_packets(d, stream, chunk);
        CHECK(!r.errored);
        CHECK(!r.stalled);
        CHECK(same_payloads(ref.packets, r.packets));
        CHECK_EQ(r.packets[3].granule, 5555);
    }
    return true;
}

// ============================================================================
// Tests: streaming mode (get_next_data)
// ============================================================================

// Streaming mode delivers raw body bytes capped at packet boundaries, flags BOS
// and EOS, and marks is_end_of_packet at each packet boundary.
static bool test_streaming_mode_basic() {
    std::vector<uint8_t> a = make_pattern(1, 30);
    std::vector<uint8_t> b = make_pattern(2, 40);
    std::vector<uint8_t> stream =
        page_with_packets({a, b}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult r = drive_data(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 2);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == b);
    CHECK(r.packets[0].zero_copy && r.packets[1].zero_copy);  // streaming is always zero-copy
    CHECK(r.saw_bos);
    CHECK(r.saw_eos);
    return true;
}

// Streaming mode reconstructs the same packet payloads as packet mode, including
// across a page-spanning packet.
static bool test_streaming_matches_packet_mode() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(21, 1000, body);

    OggDemuxer packet_demux;
    DriveResult pkt = drive_packets(packet_demux, stream, SIZE_MAX);

    OggDemuxer data_demux;
    DriveResult dat = drive_data(data_demux, stream, SIZE_MAX);

    CHECK(!pkt.errored);
    CHECK(!dat.errored);
    CHECK_EQ(pkt.packets.size(), 1);
    CHECK(pkt.packets[0].data == body);
    CHECK(same_payloads(pkt.packets, dat.packets));
    return true;
}

// Streaming mode performs no heap allocation: the internal packet buffer is
// never created, so its capacity stays zero and no allocator call is made.
static bool test_streaming_no_heap_allocation() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(22, 1200, body);

    reset_alloc_counts();
    OggDemuxerConfig cfg;
    cfg.alloc = counting_alloc;
    cfg.realloc = counting_realloc;
    cfg.free = counting_free;
    OggDemuxer d(cfg);
    DriveResult r = drive_data(d, stream, 13);

    CHECK(!r.errored);
    CHECK_EQ(g_alloc_count, 0);
    CHECK_EQ(g_realloc_count, 0);
#ifdef MICRO_OGG_DEMUXER_DEBUG
    size_t current = 1, peak = 1;
    d.get_buffer_stats(current, peak);
    CHECK_EQ(current, 0);
#endif
    return true;
}

// Streaming mode skips zero-length packets at the start of, between, and at the
// end of a page, reconstructing only the non-empty packets. Driven at several
// chunk sizes so both get_next_data body-offering paths run: a single window
// that carries the header and body together, and body-only windows that arrive
// after the header was consumed.
static bool test_streaming_zero_length_packets() {
    std::vector<uint8_t> a = make_pattern(1, 20);
    std::vector<uint8_t> c = make_pattern(2, 20);
    std::vector<uint8_t> empty;
    std::vector<uint8_t> stream = page_with_packets({empty, a, empty, c, empty}, 1, 0, 0,
                                                    OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    for (size_t chunk : {SIZE_MAX, static_cast<size_t>(1), static_cast<size_t>(5),
                         static_cast<size_t>(13), static_cast<size_t>(64)}) {
        OggDemuxer d;
        DriveResult r = drive_data(d, stream, chunk);

        CHECK(!r.errored);
        CHECK(!r.stalled);
        CHECK_EQ(r.packets.size(), 2);
        CHECK(r.packets[0].data == a);
        CHECK(r.packets[1].data == c);
        CHECK(r.packets[1].is_last_on_page);
        CHECK(r.saw_bos);
        CHECK(r.saw_eos);
    }
    return true;
}

// ============================================================================
// Tests: zero-copy accounting
// ============================================================================

// Single-page packets are returned zero-copy; a page-spanning packet is
// buffered. Checked by the payload pointer range and, in debug builds, the
// statistics counters.
static bool test_zero_copy_vs_buffered() {
    std::vector<uint8_t> a = make_pattern(1, 40);
    std::vector<uint8_t> b = make_pattern(2, 50);
    std::vector<uint8_t> spanning = make_pattern(3, 300);

    std::vector<uint8_t> stream;
    append_bytes(stream, page_with_packets({a, b}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.segments = {255};
    p1.body.assign(spanning.begin(), spanning.begin() + 255);
    append_bytes(stream, make_page(p1));

    PageSpec p2;
    p2.serial = 1;
    p2.sequence = 2;
    p2.header_type = OGG_CONTINUED_PACKET | OGG_END_OF_STREAM;
    append_packet_lacing(p2.segments, 45);
    p2.body.assign(spanning.begin() + 255, spanning.end());
    append_bytes(stream, make_page(p2));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 3);
    CHECK(r.packets[0].zero_copy);
    CHECK(r.packets[1].zero_copy);
    CHECK(!r.packets[2].zero_copy);
    CHECK(r.packets[2].data == spanning);
#ifdef MICRO_OGG_DEMUXER_DEBUG
    size_t zero_copy = 0, buffered = 0;
    d.get_stats(zero_copy, buffered);
    CHECK_EQ(zero_copy, 2);
    CHECK_EQ(buffered, 1);
#endif
    return true;
}

// ============================================================================
// Tests: oversized packet skipping and buffer growth
// ============================================================================

// A packet exceeding max_buffer_size that must be buffered is skipped
// (OGG_PACKET_SKIPPED) while neighboring packets still decode.
static bool test_oversized_packet_skipped() {
    std::vector<uint8_t> a = make_pattern(1, 20);
    std::vector<uint8_t> big = make_pattern(2, 5000);
    std::vector<uint8_t> c = make_pattern(3, 20);
    std::vector<uint8_t> stream =
        page_with_packets({a, big, c}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxerConfig cfg;
    cfg.min_buffer_size = 64;
    cfg.max_buffer_size = 128;
    OggDemuxer d(cfg);
    // Small windows prevent zero-copy, forcing the packet through the buffer
    // where the size limit applies.
    DriveResult r = drive_packets(d, stream, 64);

    CHECK(!r.errored);
    CHECK(!r.stalled);
    CHECK_EQ(r.skipped, 1);
    CHECK_EQ(r.packets.size(), 2);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == c);
    return true;
}

// An oversized packet that also spans pages is skipped across the boundary, and
// a following packet still decodes.
static bool test_oversized_spanning_packet_skipped() {
    std::vector<uint8_t> a = make_pattern(1, 20);
    std::vector<uint8_t> big = make_pattern(2, 560);
    std::vector<uint8_t> c = make_pattern(3, 20);

    std::vector<uint8_t> stream;
    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    append_packet_lacing(p0.segments, a.size());
    p0.segments.push_back(255);  // first 255 of big, continues
    append_bytes(p0.body, a);
    p0.body.insert(p0.body.end(), big.begin(), big.begin() + 255);
    append_bytes(stream, make_page(p0));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.header_type = OGG_CONTINUED_PACKET;
    p1.segments = {255};  // next 255 of big, still continues
    p1.body.insert(p1.body.end(), big.begin() + 255, big.begin() + 510);
    append_bytes(stream, make_page(p1));

    PageSpec p2;
    p2.serial = 1;
    p2.sequence = 2;
    p2.header_type = OGG_CONTINUED_PACKET | OGG_END_OF_STREAM;
    append_packet_lacing(p2.segments, 50);  // last 50 of big
    append_packet_lacing(p2.segments, c.size());
    p2.body.insert(p2.body.end(), big.begin() + 510, big.end());
    append_bytes(p2.body, c);
    append_bytes(stream, make_page(p2));

    OggDemuxerConfig cfg;
    cfg.min_buffer_size = 64;
    cfg.max_buffer_size = 256;
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK(!r.stalled);
    CHECK_EQ(r.skipped, 1);
    CHECK_EQ(r.packets.size(), 2);
    CHECK(r.packets[0].data == a);
    CHECK(r.packets[1].data == c);
    return true;
}

// A buffered packet larger than min_buffer_size (but within max) triggers buffer
// growth and is returned intact.
static bool test_buffer_grows_for_large_packet() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(31, 1000, body);

    OggDemuxerConfig cfg;
    cfg.min_buffer_size = 64;
    cfg.max_buffer_size = 8192;
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.packets[0].data == body);
    CHECK(!r.packets[0].zero_copy);
#ifdef MICRO_OGG_DEMUXER_DEBUG
    size_t current = 0, peak = 0;
    d.get_buffer_stats(current, peak);
    CHECK(peak >= 1000);
    CHECK(peak > 64);
#endif
    return true;
}

// ============================================================================
// Tests: custom allocators
// ============================================================================

// The custom alloc/realloc/free callbacks are used for the internal buffer:
// alloc on first use, realloc on growth, free on destruction.
static bool test_custom_allocator_used() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(41, 1000, body);

    reset_alloc_counts();
    {
        OggDemuxerConfig cfg;
        cfg.min_buffer_size = 64;
        cfg.max_buffer_size = 8192;
        cfg.alloc = counting_alloc;
        cfg.realloc = counting_realloc;
        cfg.free = counting_free;
        OggDemuxer d(cfg);
        DriveResult r = drive_packets(d, stream, SIZE_MAX);
        CHECK(!r.errored);
        CHECK_EQ(r.packets.size(), 1);
        CHECK(r.packets[0].data == body);
        CHECK(g_alloc_count >= 1);
        CHECK(g_realloc_count >= 1);
    }
    CHECK(g_free_count >= 1);  // destructor freed the buffer
    return true;
}

// A failing allocator surfaces OGG_ALLOCATION_FAILED on the first call (lazy
// buffer allocation) rather than crashing.
static bool test_initial_allocation_failure() {
    std::vector<uint8_t> stream = make_pattern(1, 64);  // contents irrelevant

    OggDemuxerConfig cfg;
    cfg.alloc = failing_alloc;
    cfg.realloc = failing_realloc;
    cfg.free = counting_free;
    OggDemuxer d(cfg);

    OggDemuxState st = d.get_next_packet(stream.data(), stream.size());
    CHECK_EQ(st.result, OGG_ALLOCATION_FAILED);
    return true;
}

// A realloc that fails during buffer growth surfaces OGG_ALLOCATION_FAILED.
static bool test_realloc_failure_during_assembly() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(51, 1000, body);

    OggDemuxerConfig cfg;
    cfg.min_buffer_size = 64;
    cfg.max_buffer_size = 8192;
    cfg.alloc = counting_alloc;
    cfg.realloc = failing_realloc;  // initial alloc succeeds, growth fails
    cfg.free = counting_free;
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_ALLOCATION_FAILED);
    return true;
}

// ============================================================================
// Tests: CRC validation
// ============================================================================

// With CRC enabled, pages carrying correct checksums validate and decode.
static bool test_crc_accepts_valid_pages() {
    std::vector<uint8_t> body;
    std::vector<uint8_t> stream = spanning_packet_stream(61, 900, body);

    OggDemuxerConfig cfg;
    cfg.enable_crc = true;
    cfg.max_buffer_size = 8192;
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.packets[0].data == body);
    return true;
}

// With CRC enabled, a corrupted body byte is detected when the page completes.
static bool test_crc_detects_corruption() {
    std::vector<uint8_t> a = make_pattern(1, 50);
    std::vector<uint8_t> b = make_pattern(2, 50);
    std::vector<uint8_t> stream =
        page_with_packets({a, b}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);
    stream.back() ^= 0xff;  // corrupt the last body byte so the page CRC no longer matches

    OggDemuxerConfig cfg;
    cfg.enable_crc = true;
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    // The first packet is returned before validation (a documented limitation),
    // but the page's final packet reports the CRC failure.
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_CRC_FAILED);
    return true;
}

// ============================================================================
// Tests: RFC 3533 stream-consistency error paths
// ============================================================================

static bool test_invalid_capture_pattern() {
    std::vector<uint8_t> bad(40, 0x00);  // not "OggS"
    OggDemuxer d;
    OggDemuxState st = d.get_next_packet(bad.data(), bad.size());
    CHECK_EQ(st.result, OGG_INVALID_CAPTURE);
    return true;
}

static bool test_invalid_version() {
    PageSpec spec;
    spec.header_type = OGG_BEGINNING_OF_STREAM;
    append_packet_lacing(spec.segments, 10);
    spec.body = make_pattern(1, 10);
    std::vector<uint8_t> page = make_page(spec);
    page[4] = 0x01;  // unsupported version; the version is checked before the CRC

    OggDemuxer d;
    OggDemuxState st = d.get_next_packet(page.data(), page.size());
    CHECK_EQ(st.result, OGG_INVALID_VERSION);
    return true;
}

static bool test_missing_bos_flag() {
    std::vector<uint8_t> stream = page_with_packets({make_pattern(1, 10)}, 1, 0, 0, 0);
    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_BOS_ERROR);
    return true;
}

static bool test_unexpected_bos_flag() {
    std::vector<uint8_t> stream;
    append_bytes(stream,
                 page_with_packets({make_pattern(1, 10)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    append_bytes(stream,
                 page_with_packets({make_pattern(2, 10)}, 1, 1, 0, OGG_BEGINNING_OF_STREAM));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK_EQ(r.packets.size(), 1);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_BOS_ERROR);
    return true;
}

static bool test_serial_mismatch() {
    std::vector<uint8_t> stream;
    append_bytes(stream,
                 page_with_packets({make_pattern(1, 10)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    append_bytes(stream, page_with_packets({make_pattern(2, 10)}, 2, 1, 0, 0));  // different serial

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_SERIAL_MISMATCH);
    return true;
}

static bool test_page_sequence_error() {
    std::vector<uint8_t> stream;
    append_bytes(stream,
                 page_with_packets({make_pattern(1, 10)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    append_bytes(stream, page_with_packets({make_pattern(2, 10)}, 1, 5, 0, 0));  // skips sequences

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_SEQUENCE_ERROR);
    return true;
}

static bool test_continuation_flag_mismatch() {
    std::vector<uint8_t> stream;
    append_bytes(stream,
                 page_with_packets({make_pattern(1, 10)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    // Page claims a continued packet, but page 0 ended on a packet boundary.
    append_bytes(stream, page_with_packets({make_pattern(2, 10)}, 1, 1, 0, OGG_CONTINUED_PACKET));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_CONTINUATION_ERROR);
    return true;
}

static bool test_eos_with_continued_packet() {
    std::vector<uint8_t> stream;
    append_bytes(stream,
                 page_with_packets({make_pattern(1, 10)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
    // An EOS page whose last lacing value is 255 (packet continues) violates RFC 3533.
    PageSpec eos;
    eos.serial = 1;
    eos.sequence = 1;
    eos.header_type = OGG_END_OF_STREAM;
    eos.segments = {255};
    eos.body = make_pattern(2, 255);
    append_bytes(stream, make_page(eos));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);
    CHECK(r.errored);
    CHECK_EQ(r.final_result, OGG_STREAM_EOS_ERROR);
    return true;
}

// ============================================================================
// Tests: granule, reset, and input guards
// ============================================================================

// Only the last packet completing on a page carries the page granule; earlier
// packets report the invalid sentinel (-1).
static bool test_granule_position_propagation() {
    std::vector<uint8_t> a = make_pattern(1, 30);
    std::vector<uint8_t> b = make_pattern(2, 40);
    std::vector<uint8_t> c = make_pattern(3, 50);

    std::vector<uint8_t> stream;
    append_bytes(stream, page_with_packets({a, b}, 1, 0, 12345, OGG_BEGINNING_OF_STREAM));
    append_bytes(stream, page_with_packets({c}, 1, 1, 67890, OGG_END_OF_STREAM));

    OggDemuxer d;
    DriveResult r = drive_packets(d, stream, SIZE_MAX);

    CHECK(!r.errored);
    CHECK_EQ(r.packets.size(), 3);
    CHECK_EQ(r.packets[0].granule, -1);  // not last on page
    CHECK_EQ(r.packets[1].granule, 12345);
    CHECK_EQ(r.packets[2].granule, 67890);
    return true;
}

// reset() clears stream state: the same stream re-decodes identically, and once
// a stream has finished a new BOS stream is rejected until reset() is called.
static bool test_reset_reuse() {
    std::vector<uint8_t> stream = page_with_packets({make_pattern(1, 60)}, 1, 0, 1,
                                                    OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;
    DriveResult first = drive_packets(d, stream, SIZE_MAX);
    CHECK(!first.errored);
    CHECK_EQ(first.packets.size(), 1);

    // Without reset, a second BOS stream is rejected (stream already initialized).
    DriveResult no_reset = drive_packets(d, stream, SIZE_MAX);
    CHECK(no_reset.errored);

    d.reset();
    DriveResult second = drive_packets(d, stream, SIZE_MAX);
    CHECK(!second.errored);
    CHECK(same_payloads(first.packets, second.packets));
    return true;
}

// Null and empty inputs are handled without crashing.
static bool test_null_and_empty_input() {
    OggDemuxer d;
    uint8_t dummy = 0;

    OggDemuxState a = d.get_next_packet(nullptr, 10);
    CHECK_EQ(a.result, OGG_INVALID_CAPTURE);
    CHECK_EQ(a.bytes_consumed, 0);

    OggDemuxState b = d.get_next_packet(&dummy, 0);
    CHECK_EQ(b.result, OGG_NEED_MORE_DATA);

    OggDemuxState c = d.get_next_data(nullptr, 10);
    CHECK_EQ(c.result, OGG_INVALID_CAPTURE);

    OggDemuxState e = d.get_next_data(&dummy, 0);
    CHECK_EQ(e.result, OGG_NEED_MORE_DATA);
    return true;
}

// ============================================================================
// Tests: real-world fixture
// ============================================================================

// Demux a real oggenc-produced Ogg/Vorbis file with CRC enabled. This checks the
// demuxer (and the library's CRC table) against output from an independent
// encoder, including a setup header that spans pages.
static bool test_real_ogg_file_end_to_end() {
    std::vector<uint8_t> file = read_file("sine_mono_44100.ogg");
    CHECK(!file.empty());

    OggDemuxerConfig cfg;
    cfg.enable_crc = true;
    cfg.max_buffer_size = 16384;  // hold the Vorbis setup header
    OggDemuxer d(cfg);
    DriveResult r = drive_packets(d, file, SIZE_MAX);

    CHECK(!r.errored);
    CHECK(!r.stalled);
    CHECK(r.packets.size() >= 3);  // Vorbis has 3 header packets plus audio
    CHECK(r.packets.front().is_bos);
    CHECK(r.packets.back().is_eos);

    // The first packet is the Vorbis identification header: 0x01 "vorbis".
    const std::vector<uint8_t>& id = r.packets.front().data;
    CHECK(id.size() >= 7);
    const uint8_t vorbis_magic[7] = {0x01, 'v', 'o', 'r', 'b', 'i', 's'};
    CHECK(std::memcmp(id.data(), vorbis_magic, 7) == 0);

    // Chunked feeding of the real file yields the same packets.
    OggDemuxer d2(cfg);
    DriveResult chunked = drive_packets(d2, file, 17);
    CHECK(!chunked.errored);
    CHECK(same_payloads(r.packets, chunked.packets));
    return true;
}

// ============================================================================
// Tests: consumption-mode switching (get_next_packet <-> get_next_data)
// ============================================================================

// The two consumption modes may be interleaved, but only at a packet boundary.
// This is the metadata-parser pattern: read one packet with get_next_packet(),
// then stream the next with get_next_data() without buffering it.
static bool test_mode_switch_at_boundary_allowed() {
    std::vector<uint8_t> a = make_pattern(1, 30);
    std::vector<uint8_t> b = make_pattern(2, 40);
    std::vector<uint8_t> stream =
        page_with_packets({a, b}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

    OggDemuxer d;

    // Packet mode: first packet, zero-copy. Leaves the cursor at a packet
    // boundary mid-page (the second packet has not started).
    OggDemuxState s1 = d.get_next_packet(stream.data(), stream.size());
    CHECK_EQ(s1.result, OGG_OK);
    CHECK_EQ(s1.packet.length, a.size());
    CHECK(std::vector<uint8_t>(s1.packet.data, s1.packet.data + s1.packet.length) == a);
    CHECK(!s1.packet.is_last_on_page);

    // Switch to streaming mode AT the boundary: allowed, returns the second packet.
    const uint8_t* rest = stream.data() + s1.bytes_consumed;
    const size_t rest_len = stream.size() - s1.bytes_consumed;
    OggDemuxState s2 = d.get_next_data(rest, rest_len);
    CHECK_EQ(s2.result, OGG_OK);
    CHECK_EQ(s2.packet.length, b.size());
    CHECK(s2.packet.is_end_of_packet);
    CHECK(std::vector<uint8_t>(s2.packet.data, s2.packet.data + s2.packet.length) == b);
    return true;
}

// Switching modes in the middle of a packet is rejected with
// OGG_INVALID_MODE_SWITCH and does not mutate state (bytes_consumed == 0).
static bool test_mode_switch_mid_packet_rejected() {
    // (a) get_next_data() consumed only part of a packet -> get_next_packet() rejected.
    {
        std::vector<uint8_t> p = make_pattern(1, 200);
        std::vector<uint8_t> stream =
            page_with_packets({p}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

        OggDemuxer d;
        // Header (27 + one lacing byte) plus 50 of 200 body bytes: mid-packet.
        OggDemuxState s1 = d.get_next_data(stream.data(), 27 + 1 + 50);
        CHECK_EQ(s1.result, OGG_OK);
        CHECK(!s1.packet.is_end_of_packet);

        OggDemuxState s2 = d.get_next_packet(stream.data(), stream.size());
        CHECK_EQ(s2.result, OGG_INVALID_MODE_SWITCH);
        CHECK_EQ(s2.bytes_consumed, 0);
    }

    // (b) get_next_packet() buffering a packet across input windows -> get_next_data() rejected.
    {
        std::vector<uint8_t> p = make_pattern(3, 500);
        std::vector<uint8_t> stream =
            page_with_packets({p}, 1, 0, 0, OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);

        OggDemuxer d;
        // A header-sized first window parses the header only (no zero-copy return,
        // since the full packet is not present).
        OggDemuxState h = d.get_next_packet(stream.data(), 100);
        CHECK_EQ(h.result, OGG_NEED_MORE_DATA);
        const size_t off = h.bytes_consumed;
        // A short body window starts assembly but cannot complete the packet.
        OggDemuxState s1 = d.get_next_packet(stream.data() + off, 100);
        CHECK_EQ(s1.result, OGG_NEED_MORE_DATA);

        OggDemuxState s2 = d.get_next_data(stream.data() + off, stream.size() - off);
        CHECK_EQ(s2.result, OGG_INVALID_MODE_SWITCH);
        CHECK_EQ(s2.bytes_consumed, 0);
    }
    return true;
}

// A skip that spans a page boundary keeps a packet in flight across the page
// header. Switching to streaming mode while the skip is pending is rejected,
// rather than corrupting the skip byte count.
static bool test_mode_switch_mid_skip_rejected() {
    OggDemuxerConfig cfg;
    cfg.min_buffer_size = 1;
    cfg.max_buffer_size = 1;  // force skip mode for any packet larger than 1 byte

    OggDemuxer d(cfg);

    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    p0.segments = {255};  // last lacing 255: packet continues onto the next page
    p0.body = make_pattern(1, 255);
    std::vector<uint8_t> page0 = make_page(p0);

    OggDemuxState s = d.get_next_packet(page0.data(), page0.size());  // parse header
    CHECK_EQ(s.result, OGG_NEED_MORE_DATA);
    const size_t off = s.bytes_consumed;
    s = d.get_next_packet(page0.data() + off, page0.size() - off);  // skip the 255 body bytes
    CHECK_EQ(s.result, OGG_NEED_MORE_DATA);

    // Page 1 continues (and completes) the skipped packet. A get_next_data() call
    // while the skip is still in flight must be rejected.
    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.header_type = OGG_CONTINUED_PACKET;
    p1.segments = {255, 10};
    p1.body = make_pattern(2, 265);
    std::vector<uint8_t> page1 = make_page(p1);

    OggDemuxState sd = d.get_next_data(page1.data(), page1.size());
    CHECK_EQ(sd.result, OGG_INVALID_MODE_SWITCH);
    CHECK_EQ(sd.bytes_consumed, 0);
    return true;
}

// ============================================================================
// Runner
// ============================================================================

struct TestCase {
    const char* name;
    bool (*fn)();
};

static const TestCase TESTS[] = {
    {"single_packet_zero_copy", test_single_packet_zero_copy},
    {"multiple_packets_one_page", test_multiple_packets_one_page},
    {"multi_segment_packet", test_multi_segment_packet},
    {"packet_exact_multiple_of_255", test_packet_exact_multiple_of_255},
    {"zero_length_packet", test_zero_length_packet},
    {"empty_page_skipped", test_empty_page_skipped},
    {"packet_spanning_two_pages", test_packet_spanning_two_pages},
    {"packet_spanning_three_pages", test_packet_spanning_three_pages},
    {"chunked_input_invariance", test_chunked_input_invariance},
    {"streaming_mode_basic", test_streaming_mode_basic},
    {"streaming_matches_packet_mode", test_streaming_matches_packet_mode},
    {"streaming_no_heap_allocation", test_streaming_no_heap_allocation},
    {"streaming_zero_length_packets", test_streaming_zero_length_packets},
    {"zero_copy_vs_buffered", test_zero_copy_vs_buffered},
    {"oversized_packet_skipped", test_oversized_packet_skipped},
    {"oversized_spanning_packet_skipped", test_oversized_spanning_packet_skipped},
    {"buffer_grows_for_large_packet", test_buffer_grows_for_large_packet},
    {"custom_allocator_used", test_custom_allocator_used},
    {"initial_allocation_failure", test_initial_allocation_failure},
    {"realloc_failure_during_assembly", test_realloc_failure_during_assembly},
    {"crc_accepts_valid_pages", test_crc_accepts_valid_pages},
    {"crc_detects_corruption", test_crc_detects_corruption},
    {"invalid_capture_pattern", test_invalid_capture_pattern},
    {"invalid_version", test_invalid_version},
    {"missing_bos_flag", test_missing_bos_flag},
    {"unexpected_bos_flag", test_unexpected_bos_flag},
    {"serial_mismatch", test_serial_mismatch},
    {"page_sequence_error", test_page_sequence_error},
    {"continuation_flag_mismatch", test_continuation_flag_mismatch},
    {"eos_with_continued_packet", test_eos_with_continued_packet},
    {"granule_position_propagation", test_granule_position_propagation},
    {"reset_reuse", test_reset_reuse},
    {"null_and_empty_input", test_null_and_empty_input},
    {"real_ogg_file_end_to_end", test_real_ogg_file_end_to_end},
    {"mode_switch_at_boundary_allowed", test_mode_switch_at_boundary_allowed},
    {"mode_switch_mid_packet_rejected", test_mode_switch_mid_packet_rejected},
    {"mode_switch_mid_skip_rejected", test_mode_switch_mid_skip_rejected},
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <data_dir> [test_name]\n", argv[0]);
        return 2;
    }
    g_data_dir = argv[1];
    const char* filter = (argc > 2) ? argv[2] : nullptr;

    int ran = 0;
    int failed = 0;
    for (const TestCase& t : TESTS) {
        if (filter && std::strcmp(filter, t.name) != 0) {
            continue;
        }
        ran++;
        std::printf("[ RUN  ] %s\n", t.name);
        const bool ok = t.fn();
        std::printf("[ %s ] %s\n", ok ? "PASS" : "FAIL", t.name);
        if (!ok) {
            failed++;
        }
    }
    std::printf("%d/%d tests passed\n", ran - failed, ran);
    return failed == 0 ? 0 : 1;
}
