#!/usr/bin/env bash
# Reclaim Docker disk space after interop runs.
#
# - Removes stopped containers (interop leaves client/server/sim behind)
# - Removes the entire Docker build cache (interop-runner and the
#   quic-zig-interop image build both generate multi-GB caches)
# - Removes dangling (untagged) images
#
# Keeps tagged images we still use: quic-zig-interop:latest,
# martenseemann/quic-go-interop:latest, martenseemann/quic-network-simulator:latest.
# Rebuild with `docker build -t quic-zig-interop:latest -f interop/runner/Dockerfile .`
# if a rebuild is needed.

set -euo pipefail

echo "=== before ==="
docker system df

echo
echo "=== stopped containers ==="
docker container prune -f

echo
echo "=== build cache (all, including referenced) ==="
docker builder prune -af

echo
echo "=== dangling images ==="
docker image prune -f

echo
echo "=== after ==="
docker system df
