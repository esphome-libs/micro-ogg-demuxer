#!/bin/bash

# Run cppcheck whole-program analysis on first-party sources
#
# Complements clang-tidy: cppcheck sees every first-party source in one pass,
# so its unusedFunction check can flag functions with no caller anywhere in
# the project -- something a per-translation-unit tool cannot do. The scan
# includes tests/ so public API entry points have visible callers; anything
# unusedFunction still flags is dead beyond the API surface.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if ! command -v cppcheck &> /dev/null; then
    echo "Error: cppcheck not found (brew install cppcheck / apt-get install cppcheck)"
    exit 1
fi

cd "$ROOT_DIR"

# Suppressions:
#   useStlAlgorithm -- raw loops are often clearer; stylistic nag
#   missingInclude* -- system headers are not resolvable here; cppcheck
#       analyzes without them
cppcheck \
    --enable=warning,style,unusedFunction \
    --std=c++14 \
    --inline-suppr \
    --quiet \
    --error-exitcode=1 \
    --suppress=missingIncludeSystem \
    --suppress=missingInclude \
    --suppress=useStlAlgorithm \
    -i build \
    -i tests/build \
    -i tests/fuzz/build \
    -I include \
    -I src \
    -I tests \
    src/ogg_demuxer.cpp \
    tests

echo "cppcheck passed"
