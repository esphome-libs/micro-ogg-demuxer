cmake_minimum_required(VERSION 3.16)
project(micro_ogg_demuxer_tests CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# script/clang-tidy.sh can lint the tests against this build's compile DB
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_WERROR "Treat warnings as errors" OFF)

if(ENABLE_SANITIZERS)
    set(SANITIZER_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# Build the demuxer from source as a host library. MICRO_OGG_DEMUXER_DEBUG is
# enabled PUBLIC so both the library and the test share one class layout and the
# test can read the zero-copy / buffer statistics.
if(NOT TARGET micro_ogg_demuxer)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. micro-ogg-demuxer-build)
endif()
target_compile_definitions(micro_ogg_demuxer PUBLIC MICRO_OGG_DEMUXER_DEBUG)

add_executable(test_ogg_demuxer
    test_ogg_demuxer.cpp
    ogg_page_builder.cpp
)
target_link_libraries(test_ogg_demuxer PRIVATE micro_ogg_demuxer)
target_compile_options(test_ogg_demuxer PRIVATE
    -Wall
    -Wextra
    $<$<BOOL:${ENABLE_WERROR}>:-Werror>
)

# Test fixtures are checked in; regenerate with generate_test_data.sh if the
# fixture set needs to change (requires ffmpeg and oggenc).
set(TEST_DATA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/data)
foreach(fixture sine_mono_44100.ogg)
    if(NOT EXISTS ${TEST_DATA_DIR}/${fixture})
        message(FATAL_ERROR "Test fixture missing: ${fixture}; run generate_test_data.sh first")
    endif()
endforeach()

enable_testing()

set(DEMUXER_TESTS
    single_packet_zero_copy
    multiple_packets_one_page
    multi_segment_packet
    packet_exact_multiple_of_255
    zero_length_packet
    empty_page_skipped
    packet_spanning_two_pages
    packet_spanning_three_pages
    chunked_input_invariance
    streaming_mode_basic
    streaming_matches_packet_mode
    streaming_no_heap_allocation
    streaming_zero_length_packets
    zero_copy_vs_buffered
    oversized_packet_skipped
    oversized_spanning_packet_skipped
    buffer_grows_for_large_packet
    custom_allocator_used
    initial_allocation_failure
    realloc_failure_during_assembly
    crc_accepts_valid_pages
    crc_detects_corruption
    invalid_capture_pattern
    invalid_version
    missing_bos_flag
    unexpected_bos_flag
    serial_mismatch
    page_sequence_error
    continuation_flag_mismatch
    eos_with_continued_packet
    granule_position_propagation
    reset_reuse
    null_and_empty_input
    real_ogg_file_end_to_end
    mode_switch_at_boundary_allowed
    mode_switch_after_255_multiple_packet
    mode_switch_mid_packet_rejected
    mode_switch_mid_skip_rejected
)

foreach(test_name IN LISTS DEMUXER_TESTS)
    add_test(NAME ${test_name}
             COMMAND test_ogg_demuxer ${TEST_DATA_DIR} ${test_name})
endforeach()
