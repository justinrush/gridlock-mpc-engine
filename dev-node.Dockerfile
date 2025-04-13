# syntax=docker/dockerfile:1
FROM ubuntu:22.04 AS cargofiles
COPY . cargofiles
RUN find cargofiles -type f -not \( -name 'Cargo.toml' -or -name 'Cargo.lock' \) -delete


FROM rust:1.75 AS builder

# Copy cargo Cargo.toml and Cargo.lock files. Pertain folder structure
ENV HOME=/home/root
COPY --from=cargofiles cargofiles $HOME/app
COPY backend/node $HOME/app/backend/node
COPY backend/shared $HOME/app/backend/shared
COPY backend/server-node $HOME/app/backend/server-node

# Build with cache
WORKDIR $HOME/app
ENV BIN=guardian-node
ENV PROFILE=debug
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo build --bin $BIN
RUN --mount=type=cache,target=/home/root/app/target \
    cp /home/root/app/target/$PROFILE/$BIN /home/root/$BIN


FROM ubuntu:22.04 AS runner
ENV BIN=guardian-node
ENV VERSION=0.0.0
LABEL gridlocknetwork.$BIN.version=$VERSION
COPY --from=builder /home/root/$BIN /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]