#!/bin/zsh
set -eu -o pipefail

# Determine the directory where this script resides.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/libs"

MAIN_DIR="${SCRIPT_DIR}/build/libgmp"
SOURCE_DIR="${MAIN_DIR}/source"
BUILD_DIR="${MAIN_DIR}/build"
LIBS_DIR="${MAIN_DIR}/libs"

# GMP version
VERSION="6.2.1"

# Include the "common functions" file
. "${SCRIPT_DIR}/utils.sh"

function download_gmp() {
	if [[ ! -d "${SOURCE_DIR}" ]]; then
		mkdir -p "${SOURCE_DIR}"
	fi
	cd "${SOURCE_DIR}"

	# Download the GNU MP archive if it hasn't been downloaded yet.
	if [[ ! -f "gmp-${VERSION}.tar.lz" ]]; then
		curl --remote-name "https://ftp.gnu.org/gnu/gmp/gmp-${VERSION}.tar.lz"
	fi
	# Extract it, if it hasn't been extracted yet.
	if [[ ! -d "gmp-${VERSION}" ]]; then
		tar xf "gmp-${VERSION}.tar.lz"
	fi
}

build_genprogs() {
	# If an older build directory exists, remove it first.
	if [[ -d "${BUILD_DIR}/gmp-native" ]]; then
		rm -rf "${BUILD_DIR}/gmp-native"
	fi

	# Create the build directory by copying the source directory.
	mkdir -p "${BUILD_DIR}"
	cp -a "${SOURCE_DIR}/gmp-${VERSION}" "${BUILD_DIR}/gmp-native"
	cd "${BUILD_DIR}/gmp-native"

	./configure

	# Build *only* the "gen-STUFF" helper programs.
	for PROG in gen-*.c; do
		PROG="$(basename "${PROG}" ".c")"
		make "${PROG}"
	done
}

copy_genprogs() {
	local ARCH="$1"
	local PLATFORM="$2"
	local CALLER_DIR="$(pwd)"

	cd "${BUILD_DIR}/gmp-native/"
	for PROG in gen-*.c; do
		PROG="$(basename "${PROG}" ".c")"
		cp "${PROG}" "${BUILD_DIR}/gmp-${ARCH}-${PLATFORM}/${PROG}"
	done

	cd "${CALLER_DIR}"
}

build_single() {
	local ARCH="$1"
	local PLATFORM="$2"

	# If an older build directory exists, remove it first.
	if [[ -d "${BUILD_DIR}/gmp-${ARCH}-${PLATFORM}" ]]; then
		rm -rf "${BUILD_DIR}/gmp-${ARCH}-${PLATFORM}"
	fi

	# Create the build directory by copying the source directory.
	mkdir -p "${BUILD_DIR}"
	cp -a "${SOURCE_DIR}/gmp-${VERSION}" "${BUILD_DIR}/gmp-${ARCH}-${PLATFORM}"
	cd "${BUILD_DIR}/gmp-${ARCH}-${PLATFORM}"

	# Perform the build.
	configure_build "${ARCH}" "${PLATFORM}"
	copy_genprogs "${ARCH}" "${PLATFORM}"
	make -j $(nproc)

	# Copy over the built libraries.
	mkdir -p "${LIBS_DIR}"
	cp .libs/libgmp.a "${LIBS_DIR}/libgmp-${ARCH}-${PLATFORM}.a"
}

build_all() {
	rm -rf "${LIBS_DIR}"

	# Build the helper gen-STUFF programs.
	build_genprogs

	# Disabled since Rust does not support these yet.
	# build_single "armv7" "iphoneos"
	# build_single "armv7s" "iphoneos"

	build_single "arm64" "iphoneos"
	build_single "x86_64" "iphonesimulator"
}

download_gmp
build_all
combine_library "${LIBS_DIR}" "${OUTPUT_DIR}/libgmp.a"
