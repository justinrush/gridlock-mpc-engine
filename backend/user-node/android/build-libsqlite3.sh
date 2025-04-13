#!/bin/bash

set -eu -o pipefail

# Check command-line arguments.
RELEASE=0
while [[ "$#" -gt 0 ]]; do
	if [[ "$1" == "--release" ]]; then
		RELEASE=1
		shift 1
	elif [[ "$1" == "--help" ]]; then
		echo "Usage: build-libsqlite3.sh [--release]"
		exit 0
	else
		echo "build-libsqlite3.sh: Unrecognized option \"$1\"" >&2
		exit 1
	fi
done

# Determine the directory where this bash script resides.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build/"
LIBS_DIR="${SCRIPT_DIR}/libs"

# Create the directories.
mkdir -p "${BUILD_DIR}"
mkdir -p "${LIBS_DIR}/aarch64" "${LIBS_DIR}/armv7" "${LIBS_DIR}/x86_64"

# cd to the build directory and do our stuff.
cd "${BUILD_DIR}"

# Download the SQLite archive
VERSION="3340000"
curl --remote-name "https://sqlite.org/2020/sqlite-autoconf-${VERSION}.tar.gz"

# Unpack the archive and cd into the extracted directory.
tar xzf "sqlite-autoconf-${VERSION}.tar.gz"
pushd "sqlite-autoconf-${VERSION}"

# Set up CFLAGS/CXXFLAGS for either a release or a debug build.
if [[ "${RELEASE}" -eq 0 ]]; then
	export CFLAGS="-Og -ggdb"
	export CXXFLAGS="${CFLAGS}"
fi

# Build for aarch64.
if [[ ! -f "${LIBS_DIR}/aarch64/libsqlite3.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-aarch64.sh"

	./configure \
		--host=aarch64-linux-android \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libsqlite3.so "${LIBS_DIR}/aarch64/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/aarch64/libsqlite3.so"
	fi

	make distclean
fi

# Build for armv7.
if [[ ! -f "${LIBS_DIR}/armv7/libsqlite3.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-armv7.sh"

	./configure \
		--host=armv7a-linux-androideabi \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libsqlite3.so "${LIBS_DIR}/armv7/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/armv7/libsqlite3.so"
	fi

	make distclean
fi

# Build for x86_64.
if [[ ! -f "${LIBS_DIR}/x86_64/libsqlite3.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-x86_64.sh"

	./configure \
		--host=x86_64-linux-android \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libsqlite3.so "${LIBS_DIR}/x86_64/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/x86_64/libsqlite3.so"
	fi

	make distclean
fi
