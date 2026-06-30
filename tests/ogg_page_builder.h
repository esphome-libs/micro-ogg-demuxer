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

// Helpers for constructing Ogg bitstreams used as test input. Pages are built
// byte for byte with correct lacing and CRC, so each RFC 3533 framing case can
// be expressed directly, including cases a real encoder does not emit (oversized
// packets, malformed framing, corrupted checksums).

#ifndef MICRO_OGG_TESTS_OGG_PAGE_BUILDER_H
#define MICRO_OGG_TESTS_OGG_PAGE_BUILDER_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Fields of one Ogg page. make_page() fills in the segment count and CRC.
struct PageSpec {
    uint32_t serial = 1;
    uint32_t sequence = 0;
    uint64_t granule = 0;
    uint8_t header_type = 0;        // OGG_* header flags from the public header
    std::vector<uint8_t> segments;  // lacing values
    std::vector<uint8_t> body;      // page body bytes
};

// Fills `size` bytes with a deterministic, position-dependent pattern so payload
// content and packet boundaries can be compared exactly. `seed` distinguishes
// otherwise-identical packets.
std::vector<uint8_t> make_pattern(uint32_t seed, size_t size);

// Appends the lacing values for one complete packet of `size` bytes. A size that
// is an exact multiple of 255 gets a terminating 0 lacing value, per RFC 3533.
void append_packet_lacing(std::vector<uint8_t>& segs, size_t size);

// Serializes one page (27-byte header, segment table, body) with a valid CRC.
std::vector<uint8_t> make_page(const PageSpec& spec);

// Builds one page holding the given complete packets, computing lacing for each.
std::vector<uint8_t> page_with_packets(const std::vector<std::vector<uint8_t>>& packets,
                                       uint32_t serial, uint32_t sequence, uint64_t granule,
                                       uint8_t header_type);

// Appends the bytes of `src` to `dst`.
void append_bytes(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src);

// Builds a two-page stream in which one `total`-byte packet spans the page
// boundary. The first page (BOS) holds a multiple-of-255 prefix so its last
// lacing value is 255; the second page (CONTINUED | EOS) completes the packet.
// `expected_body` receives the full packet payload for comparison.
// `total` must be greater than 255, since a spanning packet needs a 255-byte
// (or larger) prefix on the first page plus a remainder on the second.
std::vector<uint8_t> spanning_packet_stream(uint32_t seed, size_t total,
                                            std::vector<uint8_t>& expected_body);

#endif  // MICRO_OGG_TESTS_OGG_PAGE_BUILDER_H
