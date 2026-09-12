#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENVIRONMENT="${1:-dev}"
ENV_FILE_PATH="${ENV_FILE:-.env}"

fail() {
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

pass() {
    printf '[PASS] %s\n' "$1"
}

required_files=(
    .env.example
    docker-compose.yml
    docker-compose.dev.yml
    docker-compose.prod.yml
    backend/Dockerfile
    backend/Dockerfile.dev
    backend/main.py
    backend/requirements.txt
    frontend/Dockerfile
    frontend/Dockerfile.dev
    frontend/nginx.conf
    frontend/package.json
    frontend/pnpm-lock.yaml
)

for file in "${required_files[@]}"; do
    [[ -f "$file" ]] || fail "Missing required file: $file"
done
pass "Required project files are present"

command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not available"
pass "Docker Compose v2 is available"

[[ -f "$ENV_FILE_PATH" ]] || fail "Missing $ENV_FILE_PATH. Run ./deploy.sh init first"

compose_args=(-f docker-compose.yml)
case "$ENVIRONMENT" in
    dev)
        compose_args+=(-f docker-compose.dev.yml)
        ;;
    prod)
        compose_args+=(-f docker-compose.prod.yml)
        ;;
    *)
        fail "Unknown environment: $ENVIRONMENT"
        ;;
esac

docker compose --env-file "$ENV_FILE_PATH" "${compose_args[@]}" config --quiet
pass "$ENVIRONMENT Compose configuration is valid"

bash -n deploy.sh verify-setup.sh
pass "Shell scripts are syntactically valid"

printf '\nSetup verification completed successfully.\n'
