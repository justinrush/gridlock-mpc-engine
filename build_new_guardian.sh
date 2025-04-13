#!/bin/bash
set -e

# Function to increment version number
increment_version() {
    local version=$1
    local major=$(echo $version | cut -d. -f1)
    local minor=$(echo $version | cut -d. -f2)
    local patch=$(echo $version | cut -d. -f3)
    echo "$major.$minor.$((patch + 1))"
}

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep -m 1 'version = ' backend/node/Cargo.toml | cut -d'"' -f2)
echo "Current version: $CURRENT_VERSION"

# Increment version
NEW_VERSION=$(increment_version $CURRENT_VERSION)
echo "New version: $NEW_VERSION"

# Update Cargo.toml with new version
sed -i '' "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" backend/node/Cargo.toml

# Build Docker image with both new version and latest tag
docker build -t guardian-node:$NEW_VERSION -t guardian-node:latest .

echo "Successfully built guardian-node:$NEW_VERSION and guardian-node:latest"