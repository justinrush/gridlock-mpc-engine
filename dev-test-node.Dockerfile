# syntax=docker/dockerfile:1
FROM ubuntu:22.04 AS cargofiles
COPY . cargofiles
RUN find cargofiles -type f -not \( -name 'Cargo.toml' -or -name 'Cargo.lock' \) -delete


FROM rust:1.70 AS builder

# Copy cargo Cargo.toml and Cargo.lock files. Pertain folder structure
ENV HOME=/home/root
COPY --from=cargofiles cargofiles $HOME/app
COPY backend/test $HOME/app/backend/test

# Build with cache
WORKDIR $HOME/app
ENV PROFILE=debug
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo test --lib -p test --no-run
RUN --mount=type=cache,target=/home/root/app/target \
    find /home/root/app/target/$PROFILE/deps/ -regex '.*test-[0-9a-z]*$' \
    | xargs -t -I % mv % /home/root/test


FROM ubuntu:22.04 AS runner
ENV BIN=test
COPY --from=builder /home/root/$BIN /usr/local/bin/app
ENV RUST_TEST_THREADS=1
ENTRYPOINT ["/usr/local/bin/app"]