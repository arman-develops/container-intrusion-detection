#!/bin/bash
set -e

# Build script for Container IDS base image

VERSION="${VERSION:-1.0.0}"
REGISTRY="${REGISTRY:-localhost:5000}"
IMAGE_NAME="container-ids-base"

echo "========================================="
echo "Building Container IDS Base Image"
echo "========================================="
echo "Version: $VERSION"
echo "Registry: $REGISTRY"
echo "Image: $IMAGE_NAME"
echo "========================================="

# Ensure we're in the repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "Building from: $REPO_ROOT"

# Build the image
echo "Building Docker image..."
docker build \
    --build-arg VERSION="$VERSION" \
    --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    -t "$IMAGE_NAME:$VERSION" \
    -t "$IMAGE_NAME:latest" \
    -f packages/base-image/Dockerfile \
    .

echo "✓ Image built successfully"

# Tag for registry
if [ "$REGISTRY" != "localhost:5000" ]; then
    echo "Tagging for registry: $REGISTRY"
    docker tag "$IMAGE_NAME:$VERSION" "$REGISTRY/$IMAGE_NAME:$VERSION"
    docker tag "$IMAGE_NAME:latest" "$REGISTRY/$IMAGE_NAME:latest"
fi

echo "========================================="
echo "Build Complete!"
echo "========================================="
echo "Local tags:"
echo "  - $IMAGE_NAME:$VERSION"
echo "  - $IMAGE_NAME:latest"

if [ "$REGISTRY" != "localhost:5000" ]; then
    echo "Registry tags:"
    echo "  - $REGISTRY/$IMAGE_NAME:$VERSION"
    echo "  - $REGISTRY/$IMAGE_NAME:latest"
fi

echo "========================================="
echo ""
echo "To push to registry:"
echo "  docker push $REGISTRY/$IMAGE_NAME:$VERSION"
echo "  docker push $REGISTRY/$IMAGE_NAME:latest"
echo ""
echo "To test locally:"
echo "  docker run -it --rm \\"
echo "    -e AGENT_API_KEY=test-key \\"
echo "    -e RABBITMQ_URL=amqp://guest:guest@localhost:5672/ \\"
echo "    $IMAGE_NAME:latest"
echo ""