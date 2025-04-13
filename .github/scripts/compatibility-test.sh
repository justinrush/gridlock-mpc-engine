#!/bin/bash
set -e

test_compatibility () {
  export HTTP_PORT=80
  export HTTPS_PORT=443
  export STORAGE_DIR=./backend/test/data
  export NODE_DB=/var/lib/gridlock/node/node.db

  set -o pipefail
  docker compose -f docker-compose.yml -f docker-compose.test.yml -f docker-compose.test.compatibility-1.yml -p gridlock-comp1 up --remove-orphans --exit-code-from tests | grep tests
  docker compose -f docker-compose.yml -f docker-compose.test.yml -f docker-compose.test.compatibility-2.yml -p gridlock-comp2 up --remove-orphans --exit-code-from tests | grep tests
}


NODE_VERSION=$NODE_VERSION
if [[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
then
  echo "Current gridlock node version is - NODE_VERSION: $NODE_VERSION"
  NODE_VERSION_ARR=( ${NODE_VERSION//./ } )
  MAJOR_VERSION=${NODE_VERSION_ARR[0]}
  echo "MAJOR_VERSION: $MAJOR_VERSION"
  MINOR_VERSION=${NODE_VERSION_ARR[1]}
else
  echo "Node version env hasn't set - NODE_VERSION"
  exit 1
fi


RELEASE_NODE_VERSION=$(docker image inspect ghcr.io/gridlocknetwork/mvp/app:master | jq -r '.[0].Config.Labels."gridlocknetwork.guardian-node.version"')
if [[ "$RELEASE_NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
then
  echo "Release gridlock node version fetched - RELEASE_NODE_VERSION: $RELEASE_NODE_VERSION"
  RELEASE_NODE_VERSION_ARR=( ${RELEASE_NODE_VERSION//./ } )
  RELEASE_MAJOR_VERSION=${RELEASE_NODE_VERSION_ARR[0]}
  echo "RELEASE_MAJOR_VERSION: $RELEASE_MAJOR_VERSION"
  RELEASE_MINOR_VERSION=${RELEASE_NODE_VERSION_ARR[1]}
else
  echo "Release version not found - Test compatibility"
  test_compatibility
  exit 0
fi


if [ "$MAJOR_VERSION" == "0" ] && [ "$RELEASE_MAJOR_VERSION" == "0" ]
then
  if [ "$MINOR_VERSION" == "$RELEASE_MINOR_VERSION" ]
    then
      test_compatibility
    else
      echo "Skipping compatibility test - Minor version are different"
  fi
elif [ "$MAJOR_VERSION" == "$RELEASE_MAJOR_VERSION" ]
then
  test_compatibility
else
  echo "Skipping compatibility test - Major versions are different"
fi
