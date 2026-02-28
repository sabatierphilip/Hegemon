#!/usr/bin/env bash
set -euo pipefail

docker build -t sentinel-containment .
docker run --rm -p 5000:5000 --env-file .env sentinel-containment
