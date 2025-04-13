#!/bin/bash

set -eu -o pipefail

# Check command-line arguments.
RELEASE=0
while [[ "$#" -gt 0 ]]; do
	if [[ "$1" == "--release" ]]; then
		RELEASE=1
		shift 1
	elif [[ "$1" == "--help" ]]; then
		echo "Usage: build-libgmp.sh [--release]"
		exit 0
	else
		echo "build-libgmp.sh: Unrecognized option \"$1\"" >&2
		exit 1
	fi
done

# Determine the directory where this bash script resides.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
LIBS_DIR="${SCRIPT_DIR}/libs"

# Create the directories.
mkdir -p "${BUILD_DIR}"
mkdir -p "${LIBS_DIR}/aarch64" "${LIBS_DIR}/armv7" "${LIBS_DIR}/x86_64"

# cd to the build directory and do our stuff.
cd "${BUILD_DIR}"

# Download the GNU MP archive
VERSION="6.2.1"
curl --remote-name "https://gmplib.org/download/gmp/gmp-${VERSION}.tar.lz"

# Unpack the archive and cd into the extracted directory.
tar xlf "gmp-${VERSION}.tar.lz"
pushd "gmp-${VERSION}"

# Set up CFLAGS/CXXFLAGS for either a release or a debug build.
if [[ "${RELEASE}" -eq 0 ]]; then
	export CFLAGS="-Og -ggdb"
	export CXXFLAGS="${CFLAGS}"
fi

# Build for aarch64.
if [[ ! -f "${LIBS_DIR}/aarch64/libgmp.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-aarch64.sh"

	./configure \
		--host=aarch64-linux-android \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libgmp.so "${LIBS_DIR}/aarch64/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/aarch64/libgmp.so"
	fi

	make distclean
fi

# Build for armv7.
if [[ ! -f "${LIBS_DIR}/armv7/libgmp.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-armv7.sh"

	./configure \
		--host=armv7a-linux-androideabi \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libgmp.so "${LIBS_DIR}/armv7/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/armv7/libgmp.so"
	fi

	make distclean
fi

# Build for x86_64.
if [[ ! -f "${LIBS_DIR}/x86_64/libgmp.so" ]]; then
	source "${SCRIPT_DIR}/toolchain-x86_64.sh"

	./configure \
		--host=x86_64-linux-android \
		--enable-shared --disable-static \
		--with-pic
	make -j $(nproc)

	cp -av .libs/libgmp.so "${LIBS_DIR}/x86_64/"
	if [[ "${RELEASE}" -eq 1 ]]; then
		"${STRIP}" --verbose "${LIBS_DIR}/x86_64/libgmp.so"
	fi

	make distclean
fi
