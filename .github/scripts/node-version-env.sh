#!/bin/bash

NODE_VERSION=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "node") | .version')
USER_NODE_VERSION=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "user-node") | .version')
SERVER_NODE_VERSION=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "server-node") | .version')

if [ $NODE_VERSION == $USER_NODE_VERSION ] && [ $NODE_VERSION == $SERVER_NODE_VERSION ];
then
  export NODE_VERSION
  echo "Gridlock node version is: $NODE_VERSION"
else
  echo "Node versions don't match - NODE_VERSION: $NODE_VERSION, USER_NODE_VERSION: $USER_NODE_VERSION, SERVER_NODE_VERSION: $SERVER_NODE_VERSION"
  return 1
fi
