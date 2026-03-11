# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Project Overview

microOggDemuxer is a lightweight, platform-agnostic Ogg container demuxer for embedded systems. It implements RFC 3533 Ogg page demuxing with zero-copy optimization.

## Architecture

**Single-file library**: The entire demuxer is in two files:

- `include/micro_ogg/ogg_demuxer.h` - Public API and data structures
- `src/ogg_demuxer.cpp` - Implementation

**State machine design**: The `OggDemuxer` class uses a three-state machine:

- `STATE_EXPECT_PAGE_HEADER` - Waiting for new Ogg page
- `STATE_ACCUMULATING_PAGE_HEADER` - Buffering partial header
- `STATE_PROCESSING_SEGMENTS` - Extracting packets from page body

**Zero-copy optimization**: Packets are returned as zero-copy pointers when they fit entirely within the input buffer. Internal buffering only occurs when packets span page or input buffer boundaries.

**Two usage modes**:

- `get_next_packet()` - Assembles complete Ogg packets, buffering internally when packets span pages/buffers
- `get_next_data()` - Streaming mode that skips internal buffering entirely. Returns raw body data as zero-copy pointers capped at packet boundaries; segment tracking, CRC, and page finalization are automatic

**Memory model**:

- `page_header_staging_` (282 bytes) - Inline fixed buffer for header accumulation (no heap allocation)
- `internal_buffer_` - Dynamic buffer that grows from `min_buffer_size` to `max_buffer_size` (lazily allocated on first `get_next_packet()` call)
- Custom allocators supported via `OggDemuxerConfig` (applies to `internal_buffer_` only)

## Key Design Constraints

- C++11 compatible
- No external dependencies (no libogg, no platform-specific code)
- No exceptions or RTTI
- Single logical bitstream Ogg files only (for multiplexed files, callers must filter pages by serial number externally)
- Thread-unsafe by design (one instance per thread)

## Debug Mode

Define `MICRO_OGG_DEMUXER_DEBUG` to enable statistics tracking (`get_stats()`, `get_buffer_stats()`, `get_debug_state()`).
