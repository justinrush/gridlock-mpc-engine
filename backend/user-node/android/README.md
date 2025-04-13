# Android library build scripts

This directory contains scripts for building the Gridlock Node library,
and its dependencies, for Android.

## Building the Node library

The Node library is the heart of Gridlock, allowing user devices to generate and store
key shares, and sign transactions.

### Requirements

To build the Guardian Node library, you will need the following:

- Android SDK installed
- Android NDK installed (r25b or newer)
- An `ANDROID_NDK_ROOT` environment variable, pointing at the NDK's location
- An `ANDROID_API` environment variable, specifying which [Android API level](https://en.wikipedia.org/wiki/Android_version_history#Overview)
  you want to target. Recommended value is 29.
- Rust cross-compilers for Android

To install cross-compilers, you need to install Rust via [rustup](https://rust-lang.github.io/rustup/installation/other.html).
Once that's done, run the following:

```
~/.cargo/bin/rustup target add aarch64-linux-android
~/.cargo/bin/rustup target add armv7-linux-androideabi
~/.cargo/bin/rustup target add x86_64-linux-android
```

### Instructions

Before you continue, please take a moment to decide if you want _debug_, or _release_ version libraries.

**NOTE**: On Android, external libraries are required to properly build the Guardian Node library.
The recommended, fast-forward workflow is to use pre-built external libraries.
If you want to build everything from scratch, omit Step 1 and refer to the "Building external libraries"
section instead.

1. Use the `download-libgmp.sh` and `download-libsqlite3.sh` scripts to download pre-built external libraries.
   Pass either `--debug` or `--release` to each script, depending on your choice.
2. Use the `build-libnode.sh` script to build the Guardian Node library.
   Pass `--release` to the script to perform _release_ build (when omitted, results in a _debug_ build).

When finished, a `libs/` directory should appear. Inside, there should be `aarch64`, `armv7` and `x86_64`
subdirectories. In each of these, a version of `libnode.so` for the specified platform should be found.

## Building external libraries

There are some external libraries used in the project, which need to be built as well.

### Requirements

To build the external libraries that Gridlock Node depends on, you will also need:

- gcc
- gzip
- lzip
- make
- m4

### Instructions

1. Take a moment to decide if you want _debug_, or _release_ version libraries.
2. Use the `build-libgmp.sh` script to build the GNU Multiple Precision Arithmetic Library.
   Pass `--release` to the script to perform _release_ build (when omitted, results in a _debug_ build).
3. Use the `build-libsqlite3.sh` script to build the SQLite3 library.
   Pass `--release` to the script to perform _release_ build (when omitted, results in a _debug_ build).

When finished, a `libs/` directory should appear. Inside, there should be `aarch64`, `armv7` and `x86_64`
subdirectories. In each of these, a version of `libgmp.so` and `libsqlite3` for the specified platform
should be found.

A `build/` directory will also be created. That directory is used only for the build process and can be
safely removed.

## Pre-built libraries and S3

The `downloads.gridlock.network` S3 bucket holds pre-built versions of the external libraries,
as well as the latest versions of the Guardian Node libraries. Should you ever find yourself
needing to update the external libraries, follow the steps described in the "Building external libraries"
section, and then use the `zip-library.sh` script to prepare an archive for each library.
Afterwards, use your preferred method to upload the `tar.gz` files and replace old builds.
