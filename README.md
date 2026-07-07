# microOggDemuxer - Lightweight Ogg Container Demuxer

[![CI](https://github.com/esphome-libs/micro-ogg-demuxer/actions/workflows/ci.yml/badge.svg)](https://github.com/esphome-libs/micro-ogg-demuxer/actions/workflows/ci.yml)

A streaming Ogg container demuxer for embedded systems. Extracts codec packets from RFC 3533 Ogg pages delivered in arbitrarily sized chunks, with zero-copy packet output. The demuxer handles the container only; the extracted packets are handed to a separate decoder (Opus, Vorbis, FLAC, or any other codec carried in the container).

[![A project from the Open Home Foundation](https://www.openhomefoundation.org/badges/ohf-project.png)](https://www.openhomefoundation.org/)

## Features

- **Streaming input**: Feed the stream in chunks of any size; the demuxer consumes what it can and reports how many bytes it took
- **Zero-copy packets**: Packets that fit within the caller's input buffer are returned as pointers into it; internal buffering happens only when a packet spans page or chunk boundaries
- **Raw streaming mode**: `get_next_data()` strips Ogg framing and returns body bytes directly, with no packet assembly and no heap allocation
- **Bounded memory**: The packet assembly buffer starts at 1 KB and grows to a configurable cap; boundary-spanning packets that exceed the cap are skipped rather than buffered
- **Optional CRC validation**: Page CRC32 checking, off by default (see [CRC Validation](#crc-validation))
- **Custom allocators**: All dynamic memory routes through optional user callbacks
- **Embedded-friendly**: C++11, no external dependencies (no libogg), no exceptions or RTTI, no platform-specific code

## Quick Start

### As a Git Submodule

```bash
git submodule add https://github.com/esphome-libs/micro-ogg-demuxer.git lib/micro-ogg-demuxer
```

```cmake
add_subdirectory(lib/micro-ogg-demuxer)
target_link_libraries(your_target PRIVATE micro_ogg_demuxer)
```

### Basic Example

```cpp
#include <micro_ogg/ogg_demuxer.h>

using namespace micro_ogg;

OggDemuxer demuxer;

while (have_data()) {
    size_t len = 0;
    const uint8_t* buf = get_chunk(&len);

    while (len > 0) {
        OggDemuxState state = demuxer.get_next_packet(buf, len);

        if (state.result == OGG_OK) {
            // Pass the packet to the decoder
            decode(state.packet.data, state.packet.length);
        } else if (state.result < 0) {
            handle_error(state.result);
            return;
        }

        buf += state.bytes_consumed;
        len -= state.bytes_consumed;
    }
}
```

## API Reference

### Main Methods

| Method | Description |
| ------ | ----------- |
| `get_next_packet(input, input_len)` | Demux input and return an `OggDemuxState` with the result code, bytes consumed, and the next complete packet |
| `get_next_data(input, input_len)` | Return raw body bytes as a zero-copy pointer capped at the packet boundary (see [Streaming Mode](#streaming-mode)) |
| `reset()` | Return to the initial state to accept a new stream; internal buffers are kept, not freed |
| `current_page_has_continued_flag()` | `true` when the current page carries the continued-packet flag; for codec wrappers that enforce framing rules |
| `previous_page_ended_with_continued_packet()` | `true` when the previous page ended mid-packet (final lacing value 255) |

### Streaming Mode

`get_next_data()` skips packet assembly and internal buffering entirely: it strips the Ogg framing and returns raw body bytes as a zero-copy pointer into the input, capped at the current packet boundary. Segment tracking, CRC accumulation, and page finalization happen automatically, and no heap allocation is performed (only the inline header staging buffer is used). Use it to stream arbitrarily large packets, or to feed a decoder that does its own reassembly.

```cpp
OggDemuxer demuxer;

while (len > 0) {
    OggDemuxState state = demuxer.get_next_data(input, len);

    if (state.result == OGG_OK) {
        // Use packet.data before advancing input (it points into the input buffer)
        decoder.decode(state.packet.data, state.packet.length);
    }

    input += state.bytes_consumed;
    len -= state.bytes_consumed;
}
```

- `bytes_consumed` covers both header and body bytes; advance the input pointer by this amount
- `packet.is_end_of_packet` is `true` when the returned data reaches a packet boundary

The two methods share demuxer state and may be mixed, but only at a packet boundary: after `get_next_packet()` returns a packet (`OGG_OK` or `OGG_PACKET_SKIPPED`), or after `get_next_data()` returns a chunk with `is_end_of_packet == true`. For example, stream a large comment/artwork packet with `get_next_data()` to inspect it without buffering, then decode the following audio packets with `get_next_packet()`. A mid-packet switch returns `OGG_INVALID_MODE_SWITCH` and consumes no input, so the caller can continue in the original mode; single-mode use never triggers this.

### Result Codes

Non-negative codes are success or informational; negative codes are errors. Check `state.result < 0` for errors.

| Code | Value | Meaning |
| ---- | ----- | ------- |
| `OGG_OK` | 0 | Packet extracted; `state.packet` is valid |
| `OGG_NEED_MORE_DATA` | 1 | Call again with more input |
| `OGG_PACKET_SKIPPED` | 2 | A boundary-spanning packet exceeded `max_buffer_size` and was skipped |
| `OGG_INVALID_CAPTURE` | -1 | "OggS" capture pattern not found |
| `OGG_INVALID_VERSION` | -2 | Unsupported Ogg version |
| `OGG_CRC_FAILED` | -3 | Page CRC32 mismatch (only with `enable_crc`) |
| `OGG_STREAM_SEQUENCE_ERROR` | -4 | Page sequence number gap (lost or reordered page) |
| `OGG_STREAM_BOS_ERROR` | -5 | Beginning-of-stream flag violation |
| `OGG_STREAM_EOS_ERROR` | -6 | End-of-stream flag violation (EOS page ends mid-packet) |
| `OGG_STREAM_SERIAL_MISMATCH` | -7 | Page from a different logical stream (chained file); `reset()` to accept the new stream |
| `OGG_STREAM_CONTINUATION_ERROR` | -8 | Continued-packet flag inconsistent with the previous page |
| `OGG_ALLOCATION_FAILED` | -9 | Memory allocation failed |
| `OGG_INVALID_MODE_SWITCH` | -10 | `get_next_packet()` and `get_next_data()` mixed mid-packet; no input consumed |
| `OGG_INVALID_INPUT` | -11 | Null input pointer with a non-zero input length (caller bug) |

### OggPacket

| Field | Description |
| ----- | ----------- |
| `data`, `length` | Packet payload; points into the input buffer (zero-copy) or the internal assembly buffer, valid only until the next demuxer call |
| `granule_position` | Granule position from the page header; meaning is codec-specific |
| `is_bos` | Packet begins the logical bitstream |
| `is_eos` | Packet ends the logical bitstream |
| `is_last_on_page` | Last packet completing on the current page (the page boundary marker for [CRC buffering](#crc-validation)) |
| `is_end_of_packet` | Returned data reaches a packet boundary (streaming mode) |

## Configuration

`OggDemuxerConfig` is passed to the constructor; defaults are used when omitted.

| Field | Default | Description |
| ----- | ------- | ----------- |
| `min_buffer_size` | 1024 | Initial packet assembly buffer size in bytes |
| `max_buffer_size` | 8192 | Assembly buffer cap; only limits packets that span pages or input chunks, zero-copy packets can be any size |
| `enable_crc` | false | Page CRC32 validation (see [CRC Validation](#crc-validation)) |
| `alloc`, `realloc`, `free` | `nullptr` | Custom allocator callbacks; standard `malloc`/`realloc`/`free` when unset |

```cpp
OggDemuxerConfig config;
config.max_buffer_size = 32768;
config.alloc = my_alloc;    // e.g., heap_caps_malloc into PSRAM
config.realloc = my_realloc;
config.free = my_free;

OggDemuxer demuxer(config);
```

## CRC Validation

CRC validation is disabled by default because it fits poorly with the zero-copy design. The page CRC32 covers the whole page, but packets are returned as soon as they are complete, so validation can only run once the final packet of the page is ready. If the check fails, that final packet returns `OGG_CRC_FAILED`, but the page's earlier packets were already returned with `OGG_OK` and may have been processed.

Enable CRC only when corruption detection matters more than immediate processing, such as in a validation tool or a player that can defer processing to page boundaries. For strict validation, copy each packet (the `data` pointer is only valid until the next call), hold the copies until `is_last_on_page`, then process the page's packets on success or discard them all on `OGG_CRC_FAILED`:

```cpp
std::vector<std::vector<uint8_t>> page_packets;

while (len > 0) {
    OggDemuxState state = demuxer.get_next_packet(input, len);

    if (state.result == OGG_OK) {
        page_packets.emplace_back(state.packet.data, state.packet.data + state.packet.length);

        if (state.packet.is_last_on_page) {
            // Page complete and CRC valid: process all packets from this page
            for (auto& pkt : page_packets) {
                decode(pkt.data(), pkt.size());
            }
            page_packets.clear();
        }
    } else if (state.result == OGG_CRC_FAILED) {
        // CRC failed on the last packet: discard the whole page
        page_packets.clear();
    }

    input += state.bytes_consumed;
    len -= state.bytes_consumed;
}
```

## Memory Usage

The constructor allocates nothing; the demuxer object itself is roughly 500 bytes (64-bit host, smaller on 32-bit targets), including the inline 282-byte header staging buffer.

| Buffer | Size | Lifetime |
| ------ | ---- | -------- |
| Header staging | 282 bytes | Inline member (no heap); accumulates the page header and segment table |
| Packet assembly buffer | `min_buffer_size` growing to at most `max_buffer_size` | Allocated lazily on the first `get_next_packet()` call; `get_next_data()` never allocates; survives `reset()` |

Zero-copy applies whenever a complete packet sits inside the caller's input buffer without spanning a page or chunk boundary, so larger input chunks raise the zero-copy rate. As a reference point: with a 4 KB input buffer and Ogg Opus audio, roughly 95-99% of packets are returned zero-copy.

## Testing

```bash
cmake -B tests/build -DENABLE_SANITIZERS=ON -DENABLE_WERROR=ON tests
cmake --build tests/build
ctest --test-dir tests/build --output-on-failure
```

The suite is a standalone CMake project in `tests/` with no third-party test framework. Most fixtures are Ogg pages constructed programmatically so the RFC 3533 framing cases can be exercised precisely: 255-byte lacing runs, packets spanning pages and buffers, zero-length packets, oversized-packet skipping, zero-copy versus buffered returns, and the stream-validation error codes. One real `oggenc`-produced file provides an end-to-end check against an independent encoder; regenerate it with `tests/generate_test_data.sh` (requires `ffmpeg` and `oggenc`) only when the fixture set needs to change. A libFuzzer harness with an ASan/UBSan torture battery lives in `tests/fuzz/`.

## Known Limitations

- **Single logical bitstream only**: Multiplexed (grouped) streams are not demuxed; callers must filter pages by serial number externally. A new serial in a chained file returns `OGG_STREAM_SERIAL_MISMATCH`; call `reset()` to continue with the next stream
- **Sequential access**: No seeking; input is consumed as a forward-only stream
- **Boundary-spanning packet cap**: Packets that must be internally buffered and exceed `max_buffer_size` are skipped (`OGG_PACKET_SKIPPED`); raise the cap, deliver them whole for zero-copy, or stream them with `get_next_data()`
- **Deferred CRC validation**: Page CRC is checked only when the page's final packet is ready (see [CRC Validation](#crc-validation))
- **Thread safety**: Instances are not thread-safe; use one demuxer per stream and per thread

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Links

- [RFC 3533: The Ogg Encapsulation Format](https://www.rfc-editor.org/rfc/rfc3533)
- [Ogg container format](https://xiph.org/ogg/)
- [microM4aDemuxer](https://github.com/esphome-libs/micro-m4a-demuxer), the MP4/M4A container sibling of this library
- [Open Home Foundation](https://www.openhomefoundation.org/)
