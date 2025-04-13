#!/bin/bash

set -eu -o pipefail

# Determine the directory where this bash script resides.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBS_DIR="${SCRIPT_DIR}/libs"

# Check arguments
if [[ "$#" -ne 1 ]] || [[ "$1" == "--help" ]]; then
	echo "zip-library.sh: Prepare a built library for upload"
	echo "Usage: zip-library.sh LIBNAME"
	exit 10
fi

# Check if library is compiled
if [[ ! -f "${LIBS_DIR}/${1}.a" ]]; then
	echo "zip-library.sh: ${1}.a not found!"
	exit 20
fi

cd "${SCRIPT_DIR}"
tar --create --gzip --file "${1}.tar.gz" "libs/${1}.a"