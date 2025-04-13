#!/bin/zsh

set -eu -o pipefail

# Determine the directory where this script resides.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/libs"

MAIN_DIR="${SCRIPT_DIR}/build/libsqlite3"
SOURCE_DIR="${MAIN_DIR}/source"
BUILD_DIR="${MAIN_DIR}/build"
LIBS_DIR="${MAIN_DIR}/libs"

# GMP version
VERSION="3340000"

# Include the "common functions" file
. "${SCRIPT_DIR}/utils.sh"

function download_sqlite() {
	if [[ ! -d "${SOURCE_DIR}" ]]; then
		mkdir -p "${SOURCE_DIR}"
	fi
	cd "${SOURCE_DIR}"

	# Download the SQLite archive if it hasn't been downloaded yet.
	if [[ ! -f "sqlite-autoconf-${VERSION}.tar.gz" ]]; then
		curl --remote-name "https://sqlite.org/2020/sqlite-autoconf-${VERSION}.tar.gz"
	fi
	# Extract it, if it hasn't been extracted yet.
	if [[ ! -d "sqlite-autoconf-${VERSION}" ]]; then
		tar xf "sqlite-autoconf-${VERSION}.tar.gz"
	fi
}

build_single() {
	local ARCH="$1"
	local PLATFORM="$2"

	# If an older build directory exists, remove it first.
	if [[ -d "${BUILD_DIR}/sqlite-${ARCH}-${PLATFORM}" ]]; then
		rm -rf "${BUILD_DIR}/sqlite-${ARCH}-${PLATFORM}"
	fi

	# Create the build directory by copying the source directory.
	mkdir -p "${BUILD_DIR}"
	cp -a "${SOURCE_DIR}/sqlite-autoconf-${VERSION}" "${BUILD_DIR}/sqlite-${ARCH}-${PLATFORM}"
	cd "${BUILD_DIR}/sqlite-${ARCH}-${PLATFORM}"

	# The SQLite source package contains code for building the library, but also for the SQLite interactive shell.
	# This shell fails to build for iOS. I looked at the configure script for a way to disable building the shell,
	# but couldn't find anything, so here's a dirty workaround - replace the shell with a minimal C program.
	echo 'int main(void){return 0;}' > shell.c

	# Perform the build.
	configure_build "${ARCH}" "${PLATFORM}"
	make -j $(nproc)

	# Copy over the built libraries.
	mkdir -p "${LIBS_DIR}"
	cp .libs/libsqlite3.a "${LIBS_DIR}/libsqlite3-${ARCH}-${PLATFORM}.a"
}

build_all() {
	rm -rf "${LIBS_DIR}"

	# Disabled since Rust does not support these yet.
	# build_single "armv7" "iphoneos"
	# build_single "armv7s" "iphoneos"

	build_single "arm64" "iphoneos"
	build_single "x86_64" "iphonesimulator"
}

download_sqlite
build_all
combine_library "${LIBS_DIR}" "${OUTPUT_DIR}/libsqlite3.a"
