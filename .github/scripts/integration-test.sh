export HTTP_PORT=80
export HTTPS_PORT=443
export STORAGE_DIR=./backend/test/data
export NODE_DB=/var/lib/gridlock/node/node.db

set -o pipefail
docker compose -f docker-compose.yml -f docker-compose.test.yml -p gridlock up --remove-orphans  --exit-code-from tests | grep tests
