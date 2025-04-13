#!/bin/bash

set -eu -o pipefail

# cd to the directory where this bash script resides.
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ "$#" -lt 1 ]]; then
	echo "download-libgmp.sh: You need to specify which build to download" >&2
	echo "                    Use --debug or --release" >&2
	exit 1
fi

if [[ "$1" == "--debug" ]]; then
	FILE="libgmp-debug.tar.gz"
elif [[ "$1" == "--release" ]]; then
	FILE="libgmp-release.tar.gz"
else
	echo "download-libgmp.sh: Unrecognized option \"${1}\"" >&2
	echo "Valid options are --debug and --release." >&2
	exit 2
fi

REGION="eu-west-2"
BUCKET="downloads.gridlock.network"
URL="https://s3.${REGION}.amazonaws.com/${BUCKET}/android-libs/${FILE}"
curl "${URL}" | tar --extract --gunzip --verbose
