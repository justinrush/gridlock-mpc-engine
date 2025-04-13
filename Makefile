.EXPORT_ALL_VARIABLES:
DOCKER_BUILDKIT=1
NODE_DB=/var/lib/gridlock/node/node.db
STORAGE_DIR=./backend/test/data
HTTP_PORT=80
HTTPS_PORT=443
ARG := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))


# Setup dev environment for manual local testing
dev_nodes:
	docker build -t "node" -f dev-node.Dockerfile --build-arg NODE_VERSION=$NODE_VERSION .
	docker build -t "message-logging" -f dev-message-logging.Dockerfile .
	docker build -t "key-info" -f dev-key-info.Dockerfile .
	docker compose -p gridlock up --remove-orphans

test:
	cargo test --lib -p test

test_single:
	cargo test --lib $(ARG)

# Run integration auto tests against dev environment
dev_nodes_test:
	set -o pipefail
	docker build -t "node" -f dev-node.Dockerfile --build-arg NODE_VERSION=$NODE_VERSION .
	docker build -t "test-node" -f dev-test-node.Dockerfile .
	docker build -t "key-info" -f dev-key-info.Dockerfile .
	docker compose -f docker-compose.yml -f docker-compose.test.yml -p gridlock up --remove-orphans --exit-code-from tests | grep "tests\|node\|key-info"
	git add --all ./backend/test/data
	git restore --source=HEAD --staged --worktree -- ./backend/test/data


# Run compatibility integration auto tests against dev environment
# Run with old version of first node other nodes of current version
# Then run current version of first node and other nodes of older version
dev_nodes_test_compatibility:
	docker build -t "node" -f dev-node.Dockerfile --build-arg NODE_VERSION=$NODE_VERSION .
	docker build -t "test-node" -f dev-test-node.Dockerfile .
	docker pull ghcr.io/gridlocknetwork/mvp/app:master
	docker compose -f docker-compose.yml -f docker-compose.test.yml -f docker-compose.test.compatibility-1.yml -p gridlock-comp1 up --remove-orphans --exit-code-from tests
	docker compose -f docker-compose.yml -f docker-compose.test.yml -f docker-compose.test.compatibility-2.yml -p gridlock-comp2 up --remove-orphans --exit-code-from tests
	git add --all ./backend/test/data
	git restore --source=HEAD --staged --worktree -- ./backend/test/data


# Listen to local nats messages
listen_nats_local:
	cargo run --bin listener -- -c local


# Listen to staging nats messages
listen_nats_staging:
	cargo run --bin listener -- -c staging


# Run 2 partner nodes with connection to staging NATs
# set $STORAGE_DIR env variable to path
# to directory for nodes keys storage.
# Nodes will be mounted on to it.
partner_nodes_stage:
	NATS_ADDRESS='nats://stagingnats.gridlock.network:4222' \
	docker compose -f docker-compose.partner.yml -p gridlock-partner up --remove-orphans


# Run 2 partner nodes with connection to production NATs
# set $STORAGE_DIR env variable to path
# to directory for nodes keys storage.
# Nodes will be mounted on to it.
partner_nodes_prod:
	NATS_ADDRESS='nats://app.gridlock.network:4222' \
	docker compose -f docker-compose.partner.yml -p gridlock-partner up --remove-orphans


# Run 2 partner nodes with connection to local NATs
# set $STORAGE_DIR env variable to path
# to directory for nodes keys storage.
# Nodes will be mounted on to it.
partner_nodes_local:
	NATS_ADDRESS='nats://host.docker.internal:4222' \
	docker compose -f docker-compose.partner.yml -p gridlock-partner up --remove-orphans