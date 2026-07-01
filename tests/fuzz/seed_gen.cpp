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

// Seed generator for the Ogg demuxer fuzzer. Emits a spread of framing shapes,
// built with the same byte-exact page builder the unit tests use, so libFuzzer
// starts from valid, structurally varied streams instead of noise.
// Each seed gets a neutral config tail appended (see below) so the whole Ogg
// stream survives the harness's tail-consumption.
//
// Usage: ogg_seed_gen <output-dir>

#include "ogg_page_builder.h"

#include <micro_ogg/ogg_demuxer.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using micro_ogg::OGG_BEGINNING_OF_STREAM;
using micro_ogg::OGG_END_OF_STREAM;

namespace {

// The harness peels a cfg byte plus up to 64 control bytes off the TAIL of each
// input (FuzzedDataProvider reads from the back). Appending a neutral tail here
// keeps the whole Ogg stream intact as decoder payload while still leaving
// libFuzzer a mutable region to flip options. 65 bytes = 64 control + 1 cfg.
// `cfg` pre-selects harness options for seeds that need a specific mode (e.g.
// bit 1 = small buffer, to drive the oversized-packet skip path).
void append_config_tail(std::vector<uint8_t>& stream, uint8_t cfg) {
    for (int i = 0; i < 64; i++) {
        stream.push_back(0x08);  // 249-byte windows
    }
    stream.push_back(cfg);
}

void write_seed(const std::string& dir, const std::string& name, std::vector<uint8_t> stream,
                uint8_t cfg = 0x00) {
    append_config_tail(stream, cfg);
    std::string path = dir + "/" + name;
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) {
        std::fprintf(stderr, "[seed] cannot open %s\n", path.c_str());
        return;
    }
    std::fwrite(stream.data(), 1, stream.size(), f);
    std::fclose(f);
    std::printf("[seed] %s (%zu bytes)\n", name.c_str(), stream.size());
}

// One self-contained BOS|EOS page holding the given packets.
std::vector<uint8_t> one_page_stream(const std::vector<std::vector<uint8_t>>& packets) {
    return page_with_packets(packets, /*serial=*/1, /*sequence=*/0, /*granule=*/0,
                             OGG_BEGINNING_OF_STREAM | OGG_END_OF_STREAM);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
        return 1;
    }
    const std::string dir = argv[1];

    // A single small packet (zero-copy path).
    write_seed(dir, "single_packet", one_page_stream({make_pattern(1, 100)}));

    // Several packets on one page.
    write_seed(dir, "multi_packet",
               one_page_stream({make_pattern(1, 40), make_pattern(2, 80), make_pattern(3, 12)}));

    // A multi-segment packet (crosses the 255-byte lacing boundary).
    write_seed(dir, "multi_segment", one_page_stream({make_pattern(4, 700)}));

    // A packet that is an exact multiple of 255 (terminating 0 lacing value).
    write_seed(dir, "exact_multiple_255", one_page_stream({make_pattern(5, 510)}));

    // A zero-length packet alongside a normal one.
    write_seed(dir, "zero_length_packet",
               one_page_stream({std::vector<uint8_t>{}, make_pattern(6, 50)}));

    // A packet spanning two pages (BOS -> CONTINUED|EOS).
    {
        std::vector<uint8_t> body;
        write_seed(dir, "spanning_two_pages", spanning_packet_stream(7, 600, body));
    }

    // A larger spanning packet, several pages of 255-runs.
    {
        std::vector<uint8_t> body;
        write_seed(dir, "spanning_large", spanning_packet_stream(8, 4000, body));
    }

    // A wide page: many small packets, exercising a long segment table.
    {
        std::vector<std::vector<uint8_t>> packets;
        for (uint32_t i = 0; i < 40; i++) {
            packets.push_back(make_pattern(100 + i, 20 + (i % 7)));
        }
        write_seed(dir, "wide_page", one_page_stream(packets));
    }

    // A multi-page stream: BOS page, a middle page, an EOS page (distinct
    // sequence numbers), so stream-consistency validation runs across pages.
    {
        std::vector<uint8_t> stream;
        append_bytes(stream,
                     page_with_packets({make_pattern(10, 60)}, 1, 0, 0, OGG_BEGINNING_OF_STREAM));
        append_bytes(stream, page_with_packets({make_pattern(11, 90)}, 1, 1, 1000, 0));
        append_bytes(stream,
                     page_with_packets({make_pattern(12, 30)}, 1, 2, 2000, OGG_END_OF_STREAM));
        write_seed(dir, "multi_page", std::move(stream));
    }

    // Oversized-packet seeds carry cfg bit 1 (small buffer, max = 512) so the
    // driven pass skips packets larger than the buffer instead of assembling
    // them, bootstrapping the skip path on a fresh (seed-only) corpus.
    constexpr uint8_t CFG_SMALL_BUFFER = 0x02;

    // A single oversized packet on one page: skipped whole, completing at the
    // page boundary (OGG_PACKET_SKIPPED with is_last_on_page set).
    write_seed(dir, "oversized_single_page", one_page_stream({make_pattern(20, 900)}),
               CFG_SMALL_BUFFER);

    // An oversized packet spanning two pages: skipped across the boundary,
    // exercising the skip-and-continue path (finalize the finished page, resume
    // skipping on the next).
    {
        std::vector<uint8_t> body;
        write_seed(dir, "oversized_spanning", spanning_packet_stream(21, 1400, body),
                   CFG_SMALL_BUFFER);
    }

    std::printf("[seed] done\n");
    return 0;
}
