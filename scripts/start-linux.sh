#!/usr/bin/env bash
set -euo pipefail
command -v docker >/dev/null || { echo "Docker is required for the one-command setup."; exit 1; }
docker compose up --build
