#!/bin/bash

# Halt and catch fire when
# - any command returns an error (-e)
# - any part of a pipe returns an error (-o pipefail)
# - an uninitialized variable is used (-u)
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

if [[ $OSTYPE == 'darwin'* ]]; then
  TOOLCHAIN="${NDK_DIR}/toolchains/llvm/prebuilt/darwin-x86_64"
else
  TOOLCHAIN="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64"
fi

# Check command-line arguments.
BUILD_MODE="debug"
while [[ "$#" -gt 0 ]]; do
	if [[ "$1" == "--release" ]]; then
		BUILD_MODE="release"
		shift 1
	elif [[ "$1" == "--help" ]]; then
		echo "Usage: build-libnode.sh [--release]"
		exit 0
	else
		echo "build-libnode.sh: Unrecognized option \"$1\"" >&2
		exit 1
	fi
done

# cd to the directory this script is located in.
cd "$(dirname "${BASH_SOURCE[0]}")"
# Calculate some paths to make referencing them easier.
LIBS_DIR="$(pwd)/libs"
REPO_DIR="$(git rev-parse --show-toplevel)"
NODE_DIR="${REPO_DIR}/backend/user-node"

# cd over to the node directory and build the Guardian Node for each target.
# We need to be in the node directory, since we're using cargo with --features.
cd "${NODE_DIR}"

# Put this in a variable so we don't repeat ourselves
CARGO_FLAGS="--locked --lib"
if [[ "${BUILD_MODE}" == "release" ]]; then
	CARGO_FLAGS="${CARGO_FLAGS} --release"
fi

# The toolchain variables are based on what cargo-apk uses for building.
# See: https://github.com/rust-windowing/android-ndk-rs/blob/master/ndk-build/src/cargo.rs
#
# The RUSTFLAGS variable sets up the linking path (tells rustc where to look for dependencies).
if [[ -z "${DISABLE_AARCH64+isset}" ]]; then
	env \
		AR_aarch64-linux-android="${TOOLCHAIN}/bin/llvm-ar" \
		CC_aarch64-linux-android="${TOOLCHAIN}/bin/aarch64-linux-android${ANDROID_API}-clang" \
		CXX_aarch64-linux-android="${TOOLCHAIN}/bin/aarch64-linux-android${ANDROID_API}-clang++" \
		CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${TOOLCHAIN}/bin/aarch64-linux-android${ANDROID_API}-clang" \
		RUSTFLAGS="-L ${LIBS_DIR}/aarch64/" \
		~/.cargo/bin/cargo build ${CARGO_FLAGS} --target=aarch64-linux-android

	cp -av "${REPO_DIR}/target/aarch64-linux-android/${BUILD_MODE}/libnode.so" "${LIBS_DIR}/aarch64/"
fi

if [[ -z "${DISABLE_ARMV7+isset}" ]]; then
	env \
		AR_armv7-linux-androideabi="${TOOLCHAIN}/bin/llvm-ar" \
		CC_armv7-linux-androideabi="${TOOLCHAIN}/bin/armv7a-linux-androideabi${ANDROID_API}-clang" \
		CXX_armv7-linux-androideabi="${TOOLCHAIN}/bin/armv7a-linux-androideabi${ANDROID_API}-clang++" \
		CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${TOOLCHAIN}/bin/armv7a-linux-androideabi${ANDROID_API}-clang" \
		RUSTFLAGS="-L ${LIBS_DIR}/armv7/" \
		~/.cargo/bin/cargo build ${CARGO_FLAGS} --target=armv7-linux-androideabi

	cp -av "${REPO_DIR}/target/armv7-linux-androideabi/${BUILD_MODE}/libnode.so" "${LIBS_DIR}/armv7/"
fi


if [[ -z "${DISABLE_X86_64+isset}" ]]; then
	env \
		AR_x86_64-linux-android="${TOOLCHAIN}/bin/llvm-ar" \
		CC_x86_64-linux-android="${TOOLCHAIN}/bin/x86_64-linux-android${ANDROID_API}-clang" \
		CXX_x86_64-linux-android="${TOOLCHAIN}/bin/x86_64-linux-android${ANDROID_API}-clang++" \
		CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${TOOLCHAIN}/bin/x86_64-linux-android${ANDROID_API}-clang" \
		RUSTFLAGS="-L ${LIBS_DIR}/x86_64/" \
		~/.cargo/bin/cargo build ${CARGO_FLAGS} --target=x86_64-linux-android

	cp -av "${REPO_DIR}/target/x86_64-linux-android/${BUILD_MODE}/libnode.so" "${LIBS_DIR}/x86_64/"
fi
