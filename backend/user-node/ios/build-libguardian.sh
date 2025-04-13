#!/bin/zsh

set -eu -o pipefail

# Determine the directory where this script resides.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBS_DIR="${SCRIPT_DIR}/build/libguardian/libs"
OUTPUT_DIR="${SCRIPT_DIR}/libs"

# Include the "common functions" file
. "${SCRIPT_DIR}/utils.sh"

build_single() {
	local TARGET="${1}-apple-ios"
	local PLATFORM="$2"

	cd "${REPO_DIR}/backend/user-node"
	env RUSTFLAGS="-L ${REPO_DIR}/backend/user-node/ios/libs/" \
	cargo build \
		--locked --lib --release \
		--target "${TARGET}"

	# Copy over the built libraries.
	mkdir -p "${LIBS_DIR}"
	cp "${REPO_DIR}/target/${TARGET}/release/libnode.a" "${LIBS_DIR}/libguardian-${PLATFORM}.a"
}

build_all() {
	rm -rf "${LIBS_DIR}"
	build_single "aarch64" "arm64-iphoneos"
	build_single "x86_64" "x86_64-iphonesimulator"
}

build_all
combine_library "${LIBS_DIR}" "${OUTPUT_DIR}/libguardian.a"
