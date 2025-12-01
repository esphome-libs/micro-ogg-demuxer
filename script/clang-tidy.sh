#!/bin/bash

# Run clang-tidy on source files
# Requires a compile_commands.json in the build directory

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${ROOT_DIR}/build"

# Find clang-tidy
CLANG_TIDY=""
for name in clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15; do
    if command -v "$name" &> /dev/null; then
        CLANG_TIDY="$name"
        break
    fi
done

# Check Homebrew LLVM paths on macOS
if [ -z "$CLANG_TIDY" ]; then
    for path in /opt/homebrew/opt/llvm/bin/clang-tidy /usr/local/opt/llvm/bin/clang-tidy; do
        if [ -x "$path" ]; then
            CLANG_TIDY="$path"
            break
        fi
    done
fi

if [ -z "$CLANG_TIDY" ]; then
    echo "Error: clang-tidy not found"
    exit 1
fi

# Check for compile_commands.json
if [ ! -f "${BUILD_DIR}/compile_commands.json" ]; then
    echo "Error: compile_commands.json not found in ${BUILD_DIR}"
    echo "Run: cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .."
    exit 1
fi

SOURCES="${ROOT_DIR}/src/ogg_demuxer.cpp"

# Parse arguments
FIX_FLAG=""
if [ "$1" = "--fix" ]; then
    FIX_FLAG="--fix"
fi

echo "Running clang-tidy..."
$CLANG_TIDY -p "$BUILD_DIR" $FIX_FLAG $SOURCES
