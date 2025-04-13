# iOS library build scripts

This directory contains scripts for building the Gridlock Node library,
and its dependencies, for iOS.

## Building the Node library

The Node library is the heart of Gridlock, allowing user devices to generate and store
key shares, and sign transactions.

### Requirements

To build the Guardian Node library, you will need the Rust cross-compilers for iOS.

To install cross-compilers, you need to install Rust via [rustup](https://rust-lang.github.io/rustup/installation/other.html).
Once that's done, run the following:

```
~/.cargo/bin/rustup target add aarch64-apple-ios
~/.cargo/bin/rustup target add x86_64-apple-ios
```

### Instructions

For iOS, we always create a _release_ version of the Guardian Node library.
This is because until recently, _debug_ builds of Rust code caused errors
when building the iOS app with Xcode.

To build, simply invoke the `build-libguardian.sh` script.

When finished, a `libs/` directory should appear. Inside, you should find the `libguardian.a` file.
This is a fat file (LIPO archive), meaning it contains a version of Guardian Node library
for each supported platform.

## Building external libraries

To build external libraries, use `build-libgmp.sh` and `build-libsqlite3.sh` scripts.

When any of these finishes, a `libs/` directory should appear.
Inside, you should find the `libgmp.a` and/or `libsqlite3.a` file.
Each of these is a fat file (LIPO archive), meaning it contains a version of Guardian Node library
for each supported platform.

A `build/` directory will also be created. That directory is used only for the build process and can be
safely removed.

## Pre-built libraries and S3

The `downloads.gridlock.network` S3 bucket holds pre-built versions of the external libraries,
as well as the latest versions of the Guardian Node libraries. Should you ever find yourself
needing to update the external libraries, follow the steps described in the "Building external libraries"
section, and then use your preferred method to upload the `.a` files and replace old builds.
