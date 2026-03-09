#!/bin/bash
set -e

# Build script for Container IDS Agent

VERSION="${VERSION:-1.0.0}"
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "========================================="
echo "Building Container IDS Agent"
echo "========================================="
echo "Version:    $VERSION"
echo "Build Date: $BUILD_DATE"
echo "Git Commit: $GIT_COMMIT"
echo "========================================="

# Change to agent directory
cd packages/agent

# Generate eBPF bytecode (if you have .bpf.c files)
echo "Generating eBPF programs..."
go generate ./...

# Build for Linux AMD64
echo "Building for linux/amd64..."
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.buildTime=${BUILD_DATE} \
        -X main.gitCommit=${GIT_COMMIT}" \
    -o ../../dist/agent-linux-amd64 \
    ./cmd/agent

# Build for Linux ARM64 (optional)
echo "Building for linux/arm64..."
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc go build \
    -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.buildTime=${BUILD_DATE} \
        -X main.gitCommit=${GIT_COMMIT}" \
    -o ../../dist/agent-linux-arm64 \
    ./cmd/agent \
    2>/dev/null || echo "Skipped ARM64 build (cross-compiler not available)"

cd ../..

# Create checksums
echo "Creating checksums..."
cd dist
sha256sum agent-linux-* > checksums.txt
cd ..

# Display results
echo "========================================="
echo "Build Complete!"
echo "========================================="
ls -lh dist/
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Test the binary: ./dist/agent-linux-amd64 --version"
echo "2. Create GitHub release with these files"
echo "3. Update Dockerfile to download from release"
echo ""