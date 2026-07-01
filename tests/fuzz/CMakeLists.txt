cmake_minimum_required(VERSION 3.16)
project(micro_ogg_fuzz CXX)

# C++17 for the harness: libFuzzer's FuzzedDataProvider.h requires it. The
# demuxer library stays C++11 (its own target sets that); only the harness TU is
# built at this standard.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# libFuzzer is the default. Apple clang ships without libclang_rt.fuzzer, so
# point CMAKE_CXX_COMPILER at Homebrew LLVM (e.g. /opt/homebrew/opt/llvm/bin/clang++).
# Pass -DFUZZ_USE_LIBFUZZER=OFF for the standalone harness instead.
option(FUZZ_USE_LIBFUZZER "Build as a libFuzzer target" ON)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzing requires Clang. Set CMAKE_CXX_COMPILER to clang++.")
endif()

# Full ASan + UBSan, no suppressions: the demuxer is a plain byte parser with no
# intentional-overflow paths (unlike a fixed-point codec), so every UBSan check
# is meaningful here. -fno-sanitize-recover=all makes any finding abort so the
# CI torture battery fails loudly.
set(FUZZ_FLAGS "-g -fno-omit-frame-pointer -fsanitize=address,undefined")
set(FUZZ_FLAGS "${FUZZ_FLAGS} -fno-sanitize-recover=all")

if(FUZZ_USE_LIBFUZZER)
    set(FUZZ_FLAGS "${FUZZ_FLAGS} -fsanitize=fuzzer-no-link")
endif()

set(CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS} ${FUZZ_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FUZZ_FLAGS}")

# Convention borrowed from Chromium/OpenSSL: a build flag for code to disable
# per-error logging that malformed inputs would otherwise flood. The demuxer
# carries no such logging today, so this is purely a guard for any future
# addition; clang does not define it automatically.
add_compile_definitions(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)

# On macOS with Homebrew LLVM, link against LLVM's libc++ so the sanitizer
# runtime and the C++ library agree.
if(APPLE)
    get_filename_component(LLVM_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(LLVM_PREFIX  "${LLVM_BIN_DIR}" DIRECTORY)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${LLVM_PREFIX}/lib/c++ -Wl,-rpath,${LLVM_PREFIX}/lib/c++")
endif()

# Build micro-ogg-demuxer as a host library (same pattern as tests/CMakeLists.txt).
if(NOT TARGET micro_ogg_demuxer)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. micro-ogg-demuxer-build)
endif()

# --- Ogg demuxer fuzzer ------------------------------------------------------
add_executable(fuzz_ogg_demux fuzz_ogg_demux.cpp)
target_link_libraries(fuzz_ogg_demux PRIVATE micro_ogg_demuxer)

if(FUZZ_USE_LIBFUZZER)
    target_compile_options(fuzz_ogg_demux PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_ogg_demux    PRIVATE -fsanitize=fuzzer)
else()
    target_compile_definitions(fuzz_ogg_demux PRIVATE FUZZ_STANDALONE=1)
endif()

# --- Seed generator ----------------------------------------------------------
# Emits a spread of valid and edge-case Ogg streams into a directory, built on
# the same page builder the unit tests use. Not a fuzz target itself, so it is
# built without the fuzzer instrumentation link.
add_executable(ogg_seed_gen seed_gen.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../ogg_page_builder.cpp)
target_include_directories(ogg_seed_gen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(ogg_seed_gen PRIVATE micro_ogg_demuxer)
