#!/bin/bash

set -eu -o pipefail

# Determine the directory where this bash script resides.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBS_DIR="${SCRIPT_DIR}/libs"

# Check arguments
if [[ "$#" -ne 1 ]] || [[ "$1" == "--help" ]]; then
	echo "zip-library.sh: Prepare a built library for upload to S3"
	echo "Usage: zip-library.sh LIBNAME"
	exit 10
fi

# Check if library is compiled
for ARCH in aarch64 armv7 x86_64; do
	if [[ ! -f "${LIBS_DIR}/${ARCH}/${1}.so" ]]; then
		echo "zip-library.sh: \"${ARCH}/${1}.so\" not found!"
		exit 20
	fi
done

cd "${SCRIPT_DIR}"
tar --create --gzip --file "${1}.tar.gz" libs/{aarch64,armv7,x86_64}/"${1}.so"
