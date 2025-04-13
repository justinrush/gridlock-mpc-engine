# For testing run

# RUSTFLAGS="-Awarnings" cargo run --bin guardian-node

.

.

.

.

.

.

old content below, unread and unreviewed
.

.

.

.

.

.

# MVP

MVP Gridlock implementation.

## Doc files

See additional developer documentation at:

- <.github/workflows/README_CI.md>
- <.github/workflows/README_CD.md>
- <webhook/README.md>
- [Servers](servers.md)
- [NATS](nats.md)

## Building the project

Building the backend requires the following dependencies:

- GCC
- GMP
- OpenSSL
- pkg-config
- Rust compiler

To get the Rust compiler, visit [rustup.rs](https://rustup.rs/).

To install the rest of the dependencies, on Ubuntu/Debian, you can use the following command:

```bash
apt install -y build-essential libgmp-dev libpq-dev libssl-dev pkg-config
```

## Development usage

The development environment is containerized and runs in Docker, using Compose.
On Ubuntu/Debian, you can install these using the following command:

```bash
apt install -y docker docker-compose
```

# This script will build the backend code and then build all the containers and run them:

```bash
make dev-nodes
```

## Production usage

To set up this project on a production server with webhook CD run the following commands on your production server:

```bash
# defaults
cp .env.tmpl .env
# insert your production environment details
nano .env

# login to the Docker registry
source .env
docker login "$DOCKER_REGISTRY" -u "$DOCKER_USERNAME" --password "$DOCKER_PASSWORD"

# deploy application
docker-compose -f docker-compose.yml -f docker-compose.prod.yml -p mvp build --pull
docker-compose -f docker-compose.yml -f docker-compose.prod.yml -p mvp up -d --remove-orphans

# deploy webhook
docker-compose -f docker-compose.webhook.yml -p mvp-webhook build --pull
docker-compose -f docker-compose.webhook.yml -p mvp-webhook up -d --remove-orphans
```
