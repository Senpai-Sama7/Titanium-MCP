#!/usr/bin/env bash
set -euo pipefail
REGISTRY=${1:-your.registry}
IMAGE=${2:-titanium-operator:latest}

docker build -t ${REGISTRY}/${IMAGE} .
docker push ${REGISTRY}/${IMAGE}
