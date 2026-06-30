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

#include "ogg_page_builder.h"

#include <micro_ogg/ogg_demuxer.h>

#include <cstddef>
#include <cstdint>
#include <vector>

using micro_ogg::OGG_BEGINNING_OF_STREAM;
using micro_ogg::OGG_CONTINUED_PACKET;
using micro_ogg::OGG_END_OF_STREAM;

namespace {

void put_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void put_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}

// Ogg CRC32: polynomial 0x04C11DB7, no input/output reflection, init 0, no final
// XOR. The table is derived from the polynomial here rather than copied from the
// library, so a page the demuxer accepts also confirms the library's table.
uint32_t g_crc_table[256];
bool g_crc_table_ready = false;

void ensure_crc_table() {
    if (g_crc_table_ready) {
        return;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t r = i << 24;
        for (int j = 0; j < 8; j++) {
            r = (r & 0x80000000U) ? ((r << 1) ^ 0x04C11DB7U) : (r << 1);
        }
        g_crc_table[i] = r;
    }
    g_crc_table_ready = true;
}

uint32_t ogg_crc32(const uint8_t* data, size_t len) {
    ensure_crc_table();
    uint32_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ g_crc_table[((crc >> 24) & 0xff) ^ data[i]];
    }
    return crc;
}

}  // namespace

std::vector<uint8_t> make_pattern(uint32_t seed, size_t size) {
    std::vector<uint8_t> v(size);
    for (size_t i = 0; i < size; i++) {
        v[i] = static_cast<uint8_t>(static_cast<size_t>(seed) * 131U + i * 7U + (i >> 3));
    }
    return v;
}

void append_packet_lacing(std::vector<uint8_t>& segs, size_t size) {
    while (size >= 255) {
        segs.push_back(255);
        size -= 255;
    }
    segs.push_back(static_cast<uint8_t>(size));
}

std::vector<uint8_t> make_page(const PageSpec& spec) {
    std::vector<uint8_t> page(27, 0);
    page[0] = 'O';
    page[1] = 'g';
    page[2] = 'g';
    page[3] = 'S';
    page[4] = 0;  // stream structure version
    page[5] = spec.header_type;
    put_le64(&page[6], spec.granule);
    put_le32(&page[14], spec.serial);
    put_le32(&page[18], spec.sequence);
    put_le32(&page[22], 0);  // checksum field zeroed while computing the CRC
    page[26] = static_cast<uint8_t>(spec.segments.size());
    page.insert(page.end(), spec.segments.begin(), spec.segments.end());
    page.insert(page.end(), spec.body.begin(), spec.body.end());
    put_le32(&page[22], ogg_crc32(page.data(), page.size()));
    return page;
}

std::vector<uint8_t> page_with_packets(const std::vector<std::vector<uint8_t>>& packets,
                                       uint32_t serial, uint32_t sequence, uint64_t granule,
                                       uint8_t header_type) {
    PageSpec spec;
    spec.serial = serial;
    spec.sequence = sequence;
    spec.granule = granule;
    spec.header_type = header_type;
    for (const auto& p : packets) {
        append_packet_lacing(spec.segments, p.size());
        spec.body.insert(spec.body.end(), p.begin(), p.end());
    }
    return make_page(spec);
}

void append_bytes(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

std::vector<uint8_t> spanning_packet_stream(uint32_t seed, size_t total,
                                            std::vector<uint8_t>& expected_body) {
    expected_body = make_pattern(seed, total);

    // Split the packet so the first page holds a whole number of 255-byte
    // lacing values (last value 255 => the packet continues) and stays below
    // half the total.
    size_t first = 255;
    while (first + 255 < total) {
        first += 255;
        if (first >= total / 2) {
            break;
        }
    }
    if (first >= total) {
        first = 255;
    }
    const size_t second = total - first;

    std::vector<uint8_t> stream;

    PageSpec p0;
    p0.serial = 1;
    p0.sequence = 0;
    p0.header_type = OGG_BEGINNING_OF_STREAM;
    for (size_t s = 0; s < first; s += 255) {
        p0.segments.push_back(255);  // no terminating value: the run continues
    }
    p0.body.assign(expected_body.begin(), expected_body.begin() + first);
    append_bytes(stream, make_page(p0));

    PageSpec p1;
    p1.serial = 1;
    p1.sequence = 1;
    p1.header_type = OGG_CONTINUED_PACKET | OGG_END_OF_STREAM;
    append_packet_lacing(p1.segments, second);
    p1.body.assign(expected_body.begin() + first, expected_body.end());
    append_bytes(stream, make_page(p1));

    return stream;
}
