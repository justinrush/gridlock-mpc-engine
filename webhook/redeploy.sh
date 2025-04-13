#!/bin/sh
set -e

cd /app

# Try to extract branch name from .env
BRANCH_NAME=$(grep -e '^BRANCH=' .env | head -n1 | sed -e 's/^BRANCH=//')

git fetch
git reset --hard "origin/${BRANCH_NAME}"

docker login "$DOCKER_REGISTRY" -u "$DOCKER_USERNAME" --password "$DOCKER_PASSWORD"

docker-compose -f docker-compose.yml -f docker-compose.prod.yml -p mvp pull
docker-compose -f docker-compose.yml -f docker-compose.prod.yml -p mvp build --pull
docker-compose -f docker-compose.yml -f docker-compose.prod.yml -p mvp up -d --remove-orphans

docker system prune --force --all
