#!/bin/bash

set -eu -o pipefail

# Determine toolchain location.
if [[ ! -z "${ANDROID_NDK_ROOT+isset}" ]]; then
	NDK_DIR="${ANDROID_NDK_ROOT}"
elif [[ ! -z "${ANDROID_NDK_HOME+isset}" ]]; then
	NDK_DIR="${ANDROID_NDK_HOME}"
else
	echo "Both \$ANDROID_NDK_ROOT and \$ANDROID_NDK_HOME are unset - unable to find toolchain" >&2
	exit 1
fi
TOOLCHAIN="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64"

# Set env variables for aarch64.
export CC="${TOOLCHAIN}/bin/aarch64-linux-android${ANDROID_API}-clang"
export CXX="${TOOLCHAIN}/bin/aarch64-linux-android${ANDROID_API}-clang++"

NDK_VERSION="$(cat "${NDK_DIR}/source.properties" | grep --only-matching '^Pkg\.Revision = [0-9]*' | tr --delete --complement '[0-9]')"
if [[ "${NDK_VERSION}" -ge 22 ]]; then
	# New toolchain for NDK >= 22
	export AR="${TOOLCHAIN}/bin/llvm-ar"
	export AS="${CC}"
	export LD="${TOOLCHAIN}/bin/ld"
	export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
	export STRIP="${TOOLCHAIN}/bin/llvm-strip"
else
	# Fallback for NDK < 22
	export AR="${TOOLCHAIN}/bin/aarch64-linux-android-ar"
	export AS="${TOOLCHAIN}/bin/aarch64-linux-android-as"
	export LD="${TOOLCHAIN}/bin/aarch64-linux-android-ld"
	export RANLIB="${TOOLCHAIN}/bin/aarch64-linux-android-ranlib"
	export STRIP="${TOOLCHAIN}/bin/aarch64-linux-android-strip"
fi
