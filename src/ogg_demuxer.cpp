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

/* microOggDemuxer - Lightweight Ogg Container Demuxer
 * Implements RFC 3533 Ogg page demuxing with zero-copy optimization.
 * See ogg_demuxer.h for detailed architecture documentation.
 */

#include <micro_ogg/ogg_demuxer.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace micro_ogg {

// Ogg container constants (RFC 3533). Page geometry (OGG_PAGE_HEADER_SIZE,
// OGG_MAX_HEADER_SIZE) lives in the public header, where the staging buffer
// is declared.
constexpr size_t OGG_SEGMENT_COUNT_OFFSET = 26;  // Offset to segment_count field
constexpr int64_t OGG_INVALID_GRANULE_POSITION =
    -1;                                        // RFC 3533 sentinel: no packet finishes on page
constexpr uint8_t OGG_MAX_LACING_VALUE = 255;  // Lacing value indicating packet continues

// Ogg page header field offsets (RFC 3533)
constexpr size_t OGG_GRANULE_OFFSET = 6;    // Offset to granule_position field
constexpr size_t OGG_SERIAL_OFFSET = 14;    // Offset to stream_serial field
constexpr size_t OGG_SEQUENCE_OFFSET = 18;  // Offset to page_sequence field
constexpr size_t OGG_CHECKSUM_OFFSET = 22;  // Offset to checksum field

// Little-endian helpers
static inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

static inline uint64_t read_le64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

// Reinterpret a 64-bit pattern as signed. Ogg granule positions are signed
// (RFC 3533 uses -1 as a sentinel), but converting an out-of-range uint64_t
// to int64_t is implementation-defined, so reinterpret the bits instead.
static inline int64_t bitcast_i64(uint64_t v) {
    int64_t out = 0;
    std::memcpy(&out, &v, sizeof(out));
    return out;
}

// CRC-32 lookup table (Ogg/Ethernet polynomial 0x04C11DB7)
static const uint32_t CRC_LOOKUP[256] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
    0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
    0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
    0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
    0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
    0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
    0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
    0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
    0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
    0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
    0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
    0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
    0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
    0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
    0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
    0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
    0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
    0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
    0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
    0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4};

static uint32_t calculate_crc32(const uint8_t* buffer, size_t size, uint32_t crc) {
    while (size >= 8) {
        crc ^= (static_cast<uint32_t>(buffer[0]) << 24) | (static_cast<uint32_t>(buffer[1]) << 16) |
               (static_cast<uint32_t>(buffer[2]) << 8) | buffer[3];
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);

        crc ^= (static_cast<uint32_t>(buffer[4]) << 24) | (static_cast<uint32_t>(buffer[5]) << 16) |
               (static_cast<uint32_t>(buffer[6]) << 8) | buffer[7];
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);
        crc = CRC_LOOKUP[(crc >> 24) & 0xff] ^ (crc << 8);

        buffer += 8;
        size -= 8;
    }

    while (size != 0) {
        crc = (crc << 8) ^ CRC_LOOKUP[((crc >> 24) & 0xff) ^ *buffer++];
        --size;
    }

    return crc;
}

OggDemuxer::OggDemuxer(const OggDemuxerConfig& config)
    : config_(config),
      max_buffer_size_(config.max_buffer_size),
      min_buffer_size_(config.min_buffer_size),
      enable_crc_(config.enable_crc) {
    // Validate and fix buffer size configuration
    if (min_buffer_size_ == 0) {
        min_buffer_size_ = 1024;  // Safe default
    }
    if (max_buffer_size_ < min_buffer_size_) {
        max_buffer_size_ = min_buffer_size_;
    }

    // Fix inconsistent allocator configuration. The callbacks only compose as a
    // full set (buffer growth realloc's a pointer that came from alloc), so if
    // any of the trio is missing, fall back to all standard functions.
    bool has_alloc = (config_.alloc != nullptr);
    bool has_realloc = (config_.realloc != nullptr);
    bool has_free = (config_.free != nullptr);
    if (has_alloc != has_free || has_alloc != has_realloc) {
        config_.alloc = nullptr;
        config_.realloc = nullptr;
        config_.free = nullptr;
    }

    reset();
}

OggDemuxer::~OggDemuxer() {
    // Use configured free function or standard free
    if (config_.free) {
        if (internal_buffer_) {
            config_.free(internal_buffer_);
        }
    } else {
        if (internal_buffer_) {
            std::free(internal_buffer_);
        }
    }
}

// ==============================================================================
// PUBLIC API: Streaming Mode
// ==============================================================================

OggDemuxState OggDemuxer::get_next_data(const uint8_t* input, size_t input_len) {
    OggDemuxState state{};

    if (input_len > 0 && !input) {
        state.result = OGG_INVALID_INPUT;
        state.bytes_consumed = 0;
        state.packet.length = 0;
        state.packet.is_bos = false;
        state.packet.is_eos = false;
        state.packet.is_last_on_page = false;
        state.packet.granule_position = OGG_INVALID_GRANULE_POSITION;
        return state;
    }

    // Reject interleaving with get_next_packet() unless at a packet boundary
    if (!enforce_mode(ConsumptionMode::DATA, state)) {
        return state;
    }

    state.bytes_consumed = 0;
    state.packet.length = 0;
    state.packet.data = nullptr;
    state.packet.is_bos = false;
    state.packet.is_eos = false;
    state.packet.is_last_on_page = false;
    state.packet.is_end_of_packet = false;
    state.packet.granule_position = OGG_INVALID_GRANULE_POSITION;

    // Header states: parse header without zero-copy packet optimization
    if (state_ == STATE_EXPECT_PAGE_HEADER || state_ == STATE_ACCUMULATING_PAGE_HEADER) {
        InternalResult result = handle_page_header(input, input_len, state, false);
        if (result != InternalResult::OK) {
            return state;
        }
        // Header parsed, now in STATE_PROCESSING_SEGMENTS. Offer any input bytes
        // left after the header as body data.
        size_t header_bytes = state.bytes_consumed;
        size_t remaining_len = (header_bytes < input_len) ? (input_len - header_bytes) : 0;

        if (remaining_len == 0) {
            state.result = OGG_NEED_MORE_DATA;
            return state;
        }

        offer_body_data(input + header_bytes, remaining_len, header_bytes, state);
        return state;
    }

    // STATE_PROCESSING_SEGMENTS: offer body bytes as zero-copy pointer
    if (state_ == STATE_PROCESSING_SEGMENTS) {
        offer_body_data(input, input_len, 0, state);
        return state;
    }

    state.result = OGG_NEED_MORE_DATA;
    return state;
}

void OggDemuxer::offer_body_data(const uint8_t* body, size_t body_len, size_t header_bytes,
                                 OggDemuxState& state) {
    // No span in flight: rest the cursor on the next packet's span. Zero-size
    // spans are resolved here rather than offered: a zero-size span at the start
    // of a continuation page is the terminator of the packet continued from the
    // previous page (its total size is a multiple of 255), reported as a
    // zero-length end-of-packet so the boundary is not lost; any other zero-size
    // span is a genuine zero-length packet, which carries no body bytes in
    // streaming mode and is stepped over silently.
    if (!span_active_) {
        while (current_segment_index_ < current_page_.segment_count) {
            begin_packet_span();
            if (span_remaining_ > 0) {
                break;
            }
            if (current_segment_index_ == 0 && previous_page_ended_with_continued_packet_) {
                close_packet_span();

                state.packet.data = body;
                state.packet.length = 0;
                state.packet.granule_position = granule_position_;
                state.packet.is_bos = current_packet_is_bos_;
                state.packet.is_eos = (current_page_.header_type & OGG_END_OF_STREAM) != 0;
                state.packet.is_end_of_packet = true;
                state.packet.is_last_on_page =
                    (current_segment_index_ >= current_page_.segment_count);
                state.bytes_consumed = header_bytes;
                current_packet_is_bos_ = false;

                // If the terminator was the only segment, the page is now fully consumed.
                if (current_segment_index_ >= current_page_.segment_count) {
                    OggDemuxResult page_result = finalize_page();
                    if (page_result != OGG_OK) {
                        state.result = page_result;
                        return;
                    }
                }
                state.result = OGG_OK;
                return;
            }
            close_packet_span();  // genuine zero-length packet
        }

        // Fully consumed page: transition back to header parsing
        if (current_segment_index_ >= current_page_.segment_count) {
            OggDemuxResult page_result = finalize_page();
            state.result = (page_result == OGG_OK) ? OGG_NEED_MORE_DATA : page_result;
            return;
        }
    }

    // Cap at the span (packet boundary) so we don't bleed into the next packet
    size_t to_offer = std::min(body_len, span_remaining_);

    if (to_offer == 0) {
        state.result = OGG_NEED_MORE_DATA;
        return;
    }

    state.packet.data = body;
    state.packet.length = to_offer;
    state.packet.granule_position = granule_position_;
    state.packet.is_bos = current_packet_is_bos_;
    state.packet.is_eos = (current_page_.header_type & OGG_END_OF_STREAM) != 0;
    state.packet.is_end_of_packet = current_span_.complete && (to_offer == span_remaining_);

    // Auto-advance: accumulate CRC, update span tracking
    if (enable_crc_) {
        incremental_crc_ = calculate_crc32(body, to_offer, incremental_crc_);
    }
    page_body_bytes_consumed_ += to_offer;
    span_remaining_ -= to_offer;
    if (span_remaining_ == 0) {
        close_packet_span();
    } else {
        span_active_ = true;
    }
    current_packet_is_bos_ = false;

    state.packet.is_last_on_page = (page_body_bytes_consumed_ >= page_body_size_);
    state.bytes_consumed = header_bytes + to_offer;

    // Finalize page if fully consumed
    if (page_body_bytes_consumed_ >= page_body_size_) {
        OggDemuxResult page_result = finalize_page();
        if (page_result != OGG_OK) {
            state.result = page_result;
            return;
        }
    }

    state.result = OGG_OK;
}

// ==============================================================================
// PUBLIC API: Packet Demuxing
// ==============================================================================

OggDemuxState OggDemuxer::get_next_packet(const uint8_t* input, size_t input_len) {
    OggDemuxState state{};

    // Validate input parameters
    if (input_len > 0 && !input) {
        state.result = OGG_INVALID_INPUT;
        state.bytes_consumed = 0;
        state.packet.length = 0;
        state.packet.is_bos = false;
        state.packet.is_eos = false;
        state.packet.is_last_on_page = false;
        state.packet.granule_position = OGG_INVALID_GRANULE_POSITION;
        return state;
    }

    // Reject interleaving with get_next_data() unless at a packet boundary
    if (!enforce_mode(ConsumptionMode::PACKET, state)) {
        return state;
    }

    // Lazy allocation: allocate buffers on first use
    if (!ensure_buffers_allocated(state)) {
        return state;
    }

    state.bytes_consumed = 0;
    state.packet.length = 0;
    state.packet.is_bos = false;
    state.packet.is_eos = false;
    state.packet.is_last_on_page = false;
    state.packet.granule_position = OGG_INVALID_GRANULE_POSITION;

    // ==========================================================================
    // PHASE A: PAGE HEADER PARSING
    // ==========================================================================
    if (state_ == STATE_EXPECT_PAGE_HEADER || state_ == STATE_ACCUMULATING_PAGE_HEADER) {
        // Either a packet was returned (zero-copy fast path), an error was set,
        // or the header was consumed and the body arrives on the next call.
        handle_page_header(input, input_len, state);
        return state;
    }

    // ==========================================================================
    // PHASE B: PACKET EXTRACTION (STATE_PROCESSING_SEGMENTS)
    // ==========================================================================
    // ===== Case 0: Skipping Packet (Too Large to Buffer) =====
    if (skipping_packet_) {
        handle_skipping_packet(input, input_len, state);
        return state;
    }

    // ===== Case 1: Assembling Packet (Greedy Buffering) =====
    if (assembling_packet_) {
        handle_assembling_packet(input, input_len, state);
        return state;
    }

    // ===== Case 2: Zero-Copy Mode =====
    handle_zero_copy_path(input, input_len, state);
    return state;
}

// ==============================================================================
// PUBLIC API: State Management
// ==============================================================================

void OggDemuxer::reset() {
    state_ = STATE_EXPECT_PAGE_HEADER;
    page_header_staging_size_ = 0;
    current_segment_index_ = 0;
    page_body_bytes_consumed_ = 0;
    page_body_size_ = 0;
    packet_assembly_size_ = 0;
    assembling_packet_ = false;
    skipping_packet_ = false;
    current_span_ = PacketInfo{};
    span_remaining_ = 0;
    span_active_ = false;
    previous_page_ended_with_continued_packet_ = false;
    granule_position_ = 0;
    stream_serial_ = 0;
    expected_page_sequence_ = 0;
    stream_initialized_ = false;
    current_packet_is_bos_ = false;
    bos_flag_used_ = false;
    incremental_crc_ = 0;
    active_mode_ = ConsumptionMode::UNSET;
#ifdef MICRO_OGG_DEMUXER_DEBUG
    zero_copy_packets_ = 0;
    buffered_packets_ = 0;
#endif
}

bool OggDemuxer::current_page_has_continued_flag() const {
    return (current_page_.header_type & OGG_CONTINUED_PACKET) != 0;
}

bool OggDemuxer::previous_page_ended_with_continued_packet() const {
    return previous_page_ended_with_continued_packet_;
}

// ==============================================================================
// PRIVATE HELPERS: Page Header Parsing
// ==============================================================================

OggDemuxResult OggDemuxer::parse_page_header(const uint8_t* data, size_t data_len,
                                             OggPageHeader& header, size_t& header_size) {
    // Minimum header size: 27 bytes + segment_count
    if (data_len < OGG_PAGE_HEADER_SIZE) {
        return OGG_NEED_MORE_DATA;
    }

    // Check capture pattern "OggS"
    if (data[0] != 'O' || data[1] != 'g' || data[2] != 'g' || data[3] != 'S') {
        return OGG_INVALID_CAPTURE;
    }

    // Check version
    if (data[4] != 0x00) {
        return OGG_INVALID_VERSION;
    }

    // Parse header fields (capture pattern and version are already validated above)
    header.header_type = data[5];
    header.granule_position = bitcast_i64(read_le64(data + OGG_GRANULE_OFFSET));
    header.stream_serial = read_le32(data + OGG_SERIAL_OFFSET);
    header.page_sequence = read_le32(data + OGG_SEQUENCE_OFFSET);
    header.checksum = read_le32(data + OGG_CHECKSUM_OFFSET);
    header.segment_count = data[OGG_SEGMENT_COUNT_OFFSET];

    // Total header size = 27 + segment_count
    header_size = OGG_PAGE_HEADER_SIZE + header.segment_count;

    // Check if we have enough data for complete header
    if (data_len < header_size) {
        return OGG_NEED_MORE_DATA;
    }

    return OGG_OK;
}

OggDemuxResult OggDemuxer::validate_page_crc() const {
    if (incremental_crc_ != current_page_.checksum) {
        return OGG_CRC_FAILED;
    }
    return OGG_OK;
}

void OggDemuxer::seed_page_crc(const uint8_t* header_data, size_t header_size) {
    if (!enable_crc_) {
        return;
    }

    // The CRC is computed over the full header in page_header_staging_. The
    // segment table is already there; copy the rest of the header if it is not.
    if (page_header_staging_size_ == 0) {
        std::memcpy(page_header_staging_, header_data, header_size);
    }

    // The checksum field is zeroed for the computation, then restored
    uint8_t saved_crc[4];
    std::memcpy(saved_crc, page_header_staging_ + OGG_CHECKSUM_OFFSET, 4);
    std::memset(page_header_staging_ + OGG_CHECKSUM_OFFSET, 0, 4);
    incremental_crc_ = calculate_crc32(page_header_staging_, header_size, 0);
    std::memcpy(page_header_staging_ + OGG_CHECKSUM_OFFSET, saved_crc, 4);
}

bool OggDemuxer::ensure_buffers_allocated(OggDemuxState& state) {
    if (!internal_buffer_) {
        internal_buffer_capacity_ = min_buffer_size_;
        void* ptr = config_.alloc ? config_.alloc(internal_buffer_capacity_)
                                  : std::malloc(internal_buffer_capacity_);

        if (!ptr) {
            state.result = OGG_ALLOCATION_FAILED;
            return false;
        }
        internal_buffer_ = static_cast<uint8_t*>(ptr);
#ifdef MICRO_OGG_DEMUXER_DEBUG
        // Track initial allocation
        peak_buffer_capacity_ = internal_buffer_capacity_;
#endif
    }

    return true;
}

bool OggDemuxer::between_packets() const {
    // A packet is partially consumed while assembling, skipping, or while a
    // streaming span is open.
    if (assembling_packet_ || skipping_packet_ || span_active_) {
        return false;
    }

    // Between pages: a boundary unless a packet continues onto the next page.
    if (state_ != STATE_PROCESSING_SEGMENTS) {
        return !previous_page_ended_with_continued_packet_;
    }

    // Within a page the cursor always rests at the start of the next packet's
    // span. That is a boundary unless the page opens with a continuation whose
    // closing span has not been consumed yet (cursor still at segment 0).
    if (current_segment_index_ == 0) {
        return !previous_page_ended_with_continued_packet_;
    }
    return true;
}

bool OggDemuxer::enforce_mode(ConsumptionMode requested, OggDemuxState& state) {
    if (active_mode_ != ConsumptionMode::UNSET && active_mode_ != requested && !between_packets()) {
        state.result = OGG_INVALID_MODE_SWITCH;
        state.bytes_consumed = 0;
        state.packet.length = 0;
        state.packet.granule_position = OGG_INVALID_GRANULE_POSITION;
        return false;
    }
    active_mode_ = requested;
    return true;
}

void OggDemuxer::handle_skipping_packet(const uint8_t* input, size_t input_len,
                                        OggDemuxState& state) {
    // No span in flight: the skip is resuming on a new page. Open the span of
    // the packet's bytes on this page. A zero-size span (the packet's
    // zero-length terminator leading the page) completes the skip immediately.
    if (!span_active_) {
        begin_packet_span();
        span_active_ = true;
    }

    // Skip bytes without buffering until the span is consumed
    size_t to_skip = std::min(input_len, span_remaining_);

    if (to_skip > 0) {
        span_remaining_ -= to_skip;
        page_body_bytes_consumed_ += to_skip;
        state.bytes_consumed = to_skip;

        // Update CRC (we still need to validate the page)
        if (enable_crc_) {
            incremental_crc_ = calculate_crc32(input, to_skip, incremental_crc_);
        }
    }

    if (span_remaining_ > 0) {
        state.result = OGG_NEED_MORE_DATA;
        return;
    }

    // The packet's bytes on this page are consumed
    close_packet_span();

    if (!current_span_.complete) {
        // Packet continues onto the next page: finalize this page, keep skipping
        OggDemuxResult page_result = finalize_page();
        state.result = (page_result == OGG_OK) ? OGG_NEED_MORE_DATA : page_result;
        return;
    }

    // Packet complete - exit skip mode
    skipping_packet_ = false;

    bool is_last = (current_segment_index_ >= current_page_.segment_count);
    if (is_last) {
        OggDemuxResult page_result = finalize_page();
        if (page_result != OGG_OK) {
            state.result = page_result;
            return;
        }
    }

    // Set output parameter for skipped packet
    state.packet.is_last_on_page = is_last;
    state.result = OGG_PACKET_SKIPPED;
}

void OggDemuxer::return_assembled_packet(size_t bytes_consumed, OggDemuxState& state) {
    state.packet.data = internal_buffer_;
    state.packet.length = packet_assembly_size_;
#ifdef MICRO_OGG_DEMUXER_DEBUG
    buffered_packets_++;
#endif

    // Set flags
    state.packet.is_bos = current_packet_is_bos_;
    current_packet_is_bos_ = false;

    bool is_last = (current_segment_index_ >= current_page_.segment_count);
    state.packet.is_last_on_page = is_last;
    state.packet.is_end_of_packet = true;
    state.packet.granule_position = is_last ? granule_position_ : OGG_INVALID_GRANULE_POSITION;

    // Reset assembly state
    assembling_packet_ = false;
    packet_assembly_size_ = 0;

    state.bytes_consumed = bytes_consumed;

    // Check if page complete
    if (is_last) {
        OggDemuxResult page_result = finalize_page();
        if (page_result != OGG_OK) {
            state.result = page_result;
            return;
        }
        if (current_page_.header_type & OGG_END_OF_STREAM) {
            state.packet.is_eos = true;
        }
    }

    state.result = OGG_OK;
}

bool OggDemuxer::current_page_ends_with_continued_packet() const {
    return current_page_.segment_count > 0 &&
           segment_table_[current_page_.segment_count - 1] == OGG_MAX_LACING_VALUE;
}

OggDemuxResult OggDemuxer::finalize_page() {
    if (enable_crc_ && validate_page_crc() != OGG_OK) {
        return OGG_CRC_FAILED;
    }

    previous_page_ended_with_continued_packet_ = current_page_ends_with_continued_packet();

    state_ = STATE_EXPECT_PAGE_HEADER;
    return OGG_OK;
}

OggDemuxer::InternalResult OggDemuxer::accumulate_header(const uint8_t* input, size_t input_len,
                                                         size_t& bytes_added,
                                                         OggDemuxState& state) {
    size_t staged_bytes = page_header_staging_size_;
    bytes_added = 0;

    // Step 1: Ensure we have at least 27 bytes to read segment_count
    if (staged_bytes < OGG_PAGE_HEADER_SIZE) {
        size_t needed = OGG_PAGE_HEADER_SIZE - staged_bytes;
        size_t to_copy = std::min(input_len, needed);

        if (to_copy > 0) {
            std::memcpy(page_header_staging_ + staged_bytes, input, to_copy);
            bytes_added = to_copy;
            staged_bytes += to_copy;
            page_header_staging_size_ = staged_bytes;
        }

        if (staged_bytes < OGG_PAGE_HEADER_SIZE) {
            state.bytes_consumed = bytes_added;
            state.result = OGG_NEED_MORE_DATA;
            return InternalResult::NEED_MORE_DATA;
        }
    }

    // Step 2: Now we can read segment_count, calculate full header size
    uint8_t segment_count = page_header_staging_[OGG_SEGMENT_COUNT_OFFSET];
    size_t full_header_size = OGG_PAGE_HEADER_SIZE + segment_count;

    if (staged_bytes < full_header_size) {
        size_t needed = full_header_size - staged_bytes;
        size_t available_in_input = (input_len > bytes_added) ? (input_len - bytes_added) : 0;
        size_t to_copy = std::min(available_in_input, needed);

        if (to_copy > 0) {
            std::memcpy(page_header_staging_ + staged_bytes, input + bytes_added, to_copy);
            bytes_added += to_copy;
            staged_bytes += to_copy;
            page_header_staging_size_ = staged_bytes;
        }

        if (staged_bytes < full_header_size) {
            state.bytes_consumed = bytes_added;
            state.result = OGG_NEED_MORE_DATA;
            return InternalResult::NEED_MORE_DATA;
        }
    }

    return InternalResult::OK;
}

bool OggDemuxer::validate_stream_consistency(OggDemuxState& state) {
    // RFC 3533 validation - page sequence
    if (!stream_initialized_) {
        if (!(current_page_.header_type & OGG_BEGINNING_OF_STREAM)) {
            state.result = OGG_STREAM_BOS_ERROR;
            return false;
        }
        stream_serial_ = current_page_.stream_serial;
        expected_page_sequence_ = current_page_.page_sequence;
        stream_initialized_ = true;
    } else {
        // RFC 3533: BOS flag can only appear on the first page
        if (current_page_.header_type & OGG_BEGINNING_OF_STREAM) {
            state.result = OGG_STREAM_BOS_ERROR;
            return false;
        }
        if (current_page_.stream_serial != stream_serial_) {
            state.result = OGG_STREAM_SERIAL_MISMATCH;
            return false;
        }
        if (current_page_.page_sequence != expected_page_sequence_) {
            state.result = OGG_STREAM_SEQUENCE_ERROR;
            return false;
        }
    }
    expected_page_sequence_++;

    // RFC 3533 Section 6: Validate continued packet flag consistency
    // A page's continued flag must agree with whether the previous page left a
    // packet open (its last segment was 255). The check runs on every page: on the
    // first page previous_page_ended_with_continued_packet_ is false (its reset
    // state), which correctly models "no previous page". A well-formed BOS page
    // (continued unset) passes, and a BOS page that falsely claims a continuation
    // is rejected. Deriving the first-page case from this state rather than from
    // page_sequence also means a stream whose sequence wraps through 0 (a crafted
    // first page at 0xFFFFFFFF) cannot make a later page masquerade as the first.
    bool has_continued_flag = (current_page_.header_type & OGG_CONTINUED_PACKET) != 0;
    if (has_continued_flag != previous_page_ended_with_continued_packet_) {
        state.result = OGG_STREAM_CONTINUATION_ERROR;
        return false;
    }

    // RFC 3533 validation - EOS flag with continued packet
    if ((current_page_.header_type & OGG_END_OF_STREAM) &&
        current_page_ends_with_continued_packet()) {
        state.result = OGG_STREAM_EOS_ERROR;
        return false;
    }

    return true;
}

void OggDemuxer::handle_assembling_packet(const uint8_t* input, size_t input_len,
                                          OggDemuxState& state) {
    // No span in flight: the assembly is resuming on a new page. Open the span
    // of the packet's bytes on this page.
    if (!span_active_) {
        begin_packet_span();
        span_active_ = true;
    }

    // A zero-size span means the packet ends with no more body bytes: its
    // zero-length lacing terminator leads this page (the packet size is a
    // multiple of 255). Flush the assembled packet before any page bookkeeping;
    // on a terminator-only page, finalizing first would merge this packet with
    // the next one.
    if (span_remaining_ == 0) {
        close_packet_span();
        return_assembled_packet(0, state);
        return;
    }

    size_t to_consume = std::min(input_len, span_remaining_);
    if (to_consume == 0) {
        state.result = OGG_NEED_MORE_DATA;
        return;
    }

    // Ensure buffer can hold new data
    GrowBufferResult grow_result = grow_buffer(packet_assembly_size_ + to_consume);
    if (grow_result != GROW_OK) {
        if (grow_result == GROW_EXCEEDS_MAX) {
            // Too large to buffer: discard what was assembled and skip the rest
            // of the span (and any continuation) without copying.
            skipping_packet_ = true;
            assembling_packet_ = false;
            packet_assembly_size_ = 0;
            handle_skipping_packet(input, input_len, state);
            return;
        }
        state.result = OGG_ALLOCATION_FAILED;
        return;
    }

    // Copy to buffer and update state
    std::memcpy(internal_buffer_ + packet_assembly_size_, input, to_consume);
    packet_assembly_size_ += to_consume;
    page_body_bytes_consumed_ += to_consume;
    span_remaining_ -= to_consume;
    state.bytes_consumed = to_consume;

    if (enable_crc_) {
        incremental_crc_ = calculate_crc32(input, to_consume, incremental_crc_);
    }

    if (span_remaining_ > 0) {
        state.result = OGG_NEED_MORE_DATA;
        return;
    }

    close_packet_span();

    // Packet complete on this page: flush it
    if (current_span_.complete) {
        return_assembled_packet(to_consume, state);
        return;
    }

    // Packet continues onto the next page: finalize this page, keep assembling
    OggDemuxResult page_result = finalize_page();
    state.result = (page_result == OGG_OK) ? OGG_NEED_MORE_DATA : page_result;
}

OggDemuxer::InternalResult OggDemuxer::handle_page_header(const uint8_t* input, size_t input_len,
                                                          OggDemuxState& state,
                                                          bool attempt_packet_zero_copy) {
    const uint8_t* header_data = nullptr;
    size_t header_data_len = 0;
    size_t staged_bytes = page_header_staging_size_;
    size_t bytes_added_to_staging = 0;

    // Combine staged data (if any) with new input
    if (staged_bytes > 0) {
        InternalResult acc_result =
            accumulate_header(input, input_len, bytes_added_to_staging, state);
        if (acc_result != InternalResult::OK) {
            return acc_result;
        }
        header_data = page_header_staging_;
        header_data_len = page_header_staging_size_;
    } else {
        header_data = input;
        header_data_len = input_len;
    }

    // Try to parse header
    size_t header_size = 0;
    OggDemuxResult result =
        parse_page_header(header_data, header_data_len, current_page_, header_size);

    if (result == OGG_NEED_MORE_DATA) {
        if (page_header_staging_size_ == 0 && input_len > 0) {
            size_t to_stage = std::min(input_len, OGG_MAX_HEADER_SIZE);
            std::memcpy(page_header_staging_, input, to_stage);
            page_header_staging_size_ = to_stage;
            state.bytes_consumed = to_stage;
        }
        state_ = STATE_ACCUMULATING_PAGE_HEADER;
        state.result = OGG_NEED_MORE_DATA;
        return InternalResult::NEED_MORE_DATA;
    }

    if (result != OGG_OK) {
        state.result = result;
        return InternalResult::PACKET_READY;
    }

    // Header parsed successfully - copy segment table if from input
    if (header_data != page_header_staging_) {
        std::memcpy(segment_table_, header_data + OGG_PAGE_HEADER_SIZE,
                    current_page_.segment_count);
    }

    // Cache page body size; bounded to 65025 (255 x 255) by the uint8_t segment table
    page_body_size_ = calculate_body_size(segment_table_, current_page_.segment_count);

    granule_position_ = current_page_.granule_position;

    // Validate stream consistency (BOS, serial, sequence, EOS)
    if (!validate_stream_consistency(state)) {
        return InternalResult::PACKET_READY;
    }

    // Handle empty page
    if (current_page_.segment_count == 0) {
        seed_page_crc(header_data, header_size);

        if (enable_crc_ && validate_page_crc() != OGG_OK) {
            state.result = OGG_CRC_FAILED;
            return InternalResult::PACKET_READY;
        }

        state.bytes_consumed = (bytes_added_to_staging > 0) ? bytes_added_to_staging : header_size;
        page_header_staging_size_ = 0;
        state_ = STATE_EXPECT_PAGE_HEADER;
        state.result = OGG_NEED_MORE_DATA;
        return InternalResult::NEED_MORE_DATA;
    }

    // Non-empty page: initialize for packet extraction. Spans are per-page and
    // open lazily in the consumption paths, so none is active yet.
    seed_page_crc(header_data, header_size);

    current_segment_index_ = 0;
    page_body_bytes_consumed_ = 0;
    span_active_ = false;

    current_packet_is_bos_ =
        ((current_page_.header_type & OGG_BEGINNING_OF_STREAM) != 0) && !bos_flag_used_;
    if (current_packet_is_bos_) {
        bos_flag_used_ = true;
    }

    // Check for zero-copy opportunity. This is skipped while a packet is being assembled or
    // skipped: on a continued page the first segments belong to that in-progress packet, so
    // returning them as a standalone packet would be incorrect.
    size_t bytes_from_input_for_header = (staged_bytes == 0) ? header_size : bytes_added_to_staging;
    size_t remaining_in_input =
        (bytes_from_input_for_header < input_len) ? (input_len - bytes_from_input_for_header) : 0;

    if (attempt_packet_zero_copy && remaining_in_input > 0 && !assembling_packet_ &&
        !skipping_packet_) {
        PacketInfo first_packet = scan_for_next_packet(0);
        if (first_packet.complete && remaining_in_input >= first_packet.size) {
            const uint8_t* body_start = input + bytes_from_input_for_header;
            handle_zero_copy_return(body_start, first_packet, bytes_from_input_for_header, state);
            page_header_staging_size_ = 0;
            return InternalResult::PACKET_READY;
        }
    }

    state.bytes_consumed = (bytes_added_to_staging > 0) ? bytes_added_to_staging : header_size;
    page_header_staging_size_ = 0;
    state_ = STATE_PROCESSING_SEGMENTS;
    state.result = OGG_NEED_MORE_DATA;
    return InternalResult::OK;
}

void OggDemuxer::handle_zero_copy_path(const uint8_t* input, size_t input_len,
                                       OggDemuxState& state) {
    // Scan segment table to find next packet size
    PacketInfo next_packet = scan_for_next_packet(current_segment_index_);

    // Check if we have enough data and packet is complete
    if (next_packet.complete && input_len >= next_packet.size) {
        // Zero-copy return
        handle_zero_copy_return(input, next_packet, 0, state);
        return;
    }

    if (input_len == 0) {
        state.result = OGG_NEED_MORE_DATA;
        return;
    }

    // Packet spans the input window or the page: open its span and assemble it.
    current_span_ = next_packet;
    span_remaining_ = next_packet.size;
    span_active_ = true;
    assembling_packet_ = true;
    handle_assembling_packet(input, input_len, state);
}

// ==============================================================================
// PRIVATE HELPERS: Segment and Packet Navigation
// ==============================================================================

size_t OggDemuxer::calculate_body_size(const uint8_t* segment_table, uint8_t segment_count) {
    size_t total = 0;
    for (uint8_t i = 0; i < segment_count; i++) {
        total += segment_table[i];
    }
    return total;
}

void OggDemuxer::begin_packet_span() {
    current_span_ = scan_for_next_packet(current_segment_index_);
    span_remaining_ = current_span_.size;
}

void OggDemuxer::close_packet_span() {
    // The span's segment count includes any trailing zero-length lacing
    // terminator (packet size a multiple of 255), so the cursor lands on the
    // next packet's first segment -- never mid-frame on a consumed terminator.
    current_segment_index_ += current_span_.segment_count;
    span_active_ = false;
}

OggDemuxer::PacketInfo OggDemuxer::scan_for_next_packet(uint8_t start_segment_index) const {
    PacketInfo info = {0, false, 0};

    for (uint8_t i = start_segment_index; i < current_page_.segment_count; i++) {
        info.size += segment_table_[i];
        info.segment_count++;
        if (segment_table_[i] < OGG_MAX_LACING_VALUE) {
            info.complete = true;
            break;
        }
    }

    return info;
}

// ==============================================================================
// PRIVATE HELPERS: Zero-Copy Optimization and Buffer Management
// ==============================================================================

void OggDemuxer::handle_zero_copy_return(const uint8_t* packet_ptr, const PacketInfo& packet_info,
                                         size_t additional_bytes_consumed, OggDemuxState& state) {
    // Set packet output parameters
    state.packet.data = packet_ptr;
    state.packet.length = packet_info.size;
    state.bytes_consumed = additional_bytes_consumed + packet_info.size;

#ifdef MICRO_OGG_DEMUXER_DEBUG
    zero_copy_packets_++;  // Stats: zero-copy packet
#endif

    // Update segment tracking
    current_segment_index_ += packet_info.segment_count;
    page_body_bytes_consumed_ += packet_info.size;

    // Update CRC
    if (enable_crc_) {
        incremental_crc_ =
            calculate_crc32(state.packet.data, state.packet.length, incremental_crc_);
    }

    // Set flags
    state.packet.is_bos = current_packet_is_bos_;
    current_packet_is_bos_ = false;

    bool is_last = (current_segment_index_ >= current_page_.segment_count);
    state.packet.is_last_on_page = is_last;
    state.packet.is_end_of_packet = true;
    state.packet.granule_position = is_last ? granule_position_ : OGG_INVALID_GRANULE_POSITION;

    // Check if page complete
    if (is_last) {
        OggDemuxResult page_result = finalize_page();
        if (page_result != OGG_OK) {
            state.result = page_result;
            return;
        }
        if (current_page_.header_type & OGG_END_OF_STREAM) {
            state.packet.is_eos = true;
        }
    } else {
        state_ = STATE_PROCESSING_SEGMENTS;
    }

    state.result = OGG_OK;
}

OggDemuxer::GrowBufferResult OggDemuxer::grow_buffer(size_t needed_size) {
    // Check if we need to grow
    if (needed_size <= internal_buffer_capacity_) {
        return GROW_OK;  // Already large enough
    }

    // Check if needed size exceeds maximum
    if (needed_size > max_buffer_size_) {
        return GROW_EXCEEDS_MAX;
    }

    // Calculate new capacity: double current size or use needed size, whichever is larger
    size_t new_capacity = internal_buffer_capacity_ * 2;
    if (new_capacity < needed_size) {
        new_capacity = needed_size;
    }

    // Cap at maximum buffer size
    if (new_capacity > max_buffer_size_) {
        new_capacity = max_buffer_size_;
    }

    // Reallocate buffer using configured allocator
    void* new_buffer = config_.realloc ? config_.realloc(internal_buffer_, new_capacity)
                                       : std::realloc(internal_buffer_, new_capacity);

    if (!new_buffer) {
        return GROW_ALLOCATION_FAILED;
    }

    internal_buffer_ = static_cast<uint8_t*>(new_buffer);
    internal_buffer_capacity_ = new_capacity;

#ifdef MICRO_OGG_DEMUXER_DEBUG
    // Track peak capacity reached
    if (new_capacity > peak_buffer_capacity_) {
        peak_buffer_capacity_ = new_capacity;
    }
#endif

    return GROW_OK;
}

}  // namespace micro_ogg
