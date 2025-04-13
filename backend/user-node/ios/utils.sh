# Dev-tools directory.
PLATFORM_DIR="/Applications/Xcode.app/Contents/Developer/Platforms"
TOOLCHAIN_DIR="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain"

# Minimum versions we're interested in.
IOS_VERSION_MIN=7.0
OSX_VERSION_MIN=10.0

# Determine repository top dir.
REPO_DIR="$(git rev-parse --show-toplevel)"

nproc() {
	sysctl -n hw.ncpu
}

configure_build() {
	local ARCH="$1"
	local PLATFORM="$2"

	local SDK_PATH="$(xcrun --sdk "${PLATFORM}" --show-sdk-path)"
	local FLAGS="-O2 -fembed-bitcode -arch ${ARCH} --sysroot=${SDK_PATH} -miphoneos-version-min=${IOS_VERSION_MIN}"
	./configure \
		CC="$(xcrun --sdk "${PLATFORM}" -f clang)" \
		CXX="$(xcrun --sdk "${PLATFORM}" -f clang++)" \
		CFLAGS="${FLAGS}" \
		CXXFLAGS="${FLAGS}" \
		--prefix="${TOOLCHAIN_DIR}/usr/local" \
		--host="arm-apple-darwin" \
		--disable-shared --enable-static --disable-assembly
}

combine_library() {
	local FILES_DIR="$1"
	local DEST_FILE="$2"

	mkdir -p "$(dirname "${DEST_FILE}")"
	lipo -create "${FILES_DIR}"/*.a -output "${DEST_FILE}"
}
