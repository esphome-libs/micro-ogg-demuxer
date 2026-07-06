cmake_minimum_required(VERSION 3.16)

# Guard against double-inclusion when used as submodule
if(TARGET micro_ogg_demuxer)
    return()
endif()

project(micro_ogg_demuxer VERSION 1.2.1 LANGUAGES CXX)

add_library(micro_ogg_demuxer STATIC
    src/ogg_demuxer.cpp
)

target_include_directories(micro_ogg_demuxer
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(micro_ogg_demuxer PRIVATE cxx_std_11)

option(ENABLE_WERROR "Treat warnings as errors" OFF)

# Strict warnings for the library itself (parent projects that vendor this as
# a submodule compile it through this block too, so it must stay clean).
target_compile_options(micro_ogg_demuxer PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough
    # Any function not declared in a header must be static; keeps
    # -Wunused-function able to see dead internal functions. Clang and GCC
    # spell the C++ variant of this check differently.
    $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wmissing-prototypes>
    $<$<CXX_COMPILER_ID:GNU>:-Wmissing-declarations>
    # Require static_cast/reinterpret_cast over C-style casts
    -Wold-style-cast
    $<$<BOOL:${ENABLE_WERROR}>:-Werror>
)
