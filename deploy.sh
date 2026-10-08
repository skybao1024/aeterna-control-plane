#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BASE_FILE="docker-compose.yml"
DEV_FILE="docker-compose.dev.yml"
PROD_FILE="docker-compose.prod.yml"
ENV_FILE_PATH="${ENV_FILE:-.env}"

print_info() {
    printf '[INFO] %s\n' "$1"
}

print_error() {
    printf '[ERROR] %s\n' "$1" >&2
}

usage() {
    cat <<'EOF'
Usage: ./deploy.sh <command> [service]

Commands:
  init                 Create .env from .env.example when it is missing
  dev                  Build and start the development environment
  prod                 Build and start the production-like environment
  release <commit>     Deploy prebuilt images with a backup and migrations
  stop                 Stop all services without deleting persistent data
  restart [dev|prod]   Restart an environment (defaults to dev)
  logs [service]       Follow logs for all services or one service
  status               Show service status
  migrate              Run Alembic migrations in the backend container
  mcp-setup            Provision the local AI read-only PostgreSQL role
  mcp-serve            Serve the project PostgreSQL MCP over stdio
  monitoring           Start Flower for the current Compose project
  config [dev|prod]    Validate and print the merged Compose configuration

Set AETERNA_USE_AWS_PROFILES=1 to include docker-compose.aws.yml for external
AWS SDK profiles. AWS_CONFIG_DIRECTORY must point outside this repository.
Set AETERNA_USE_SMALL_HOST=1 to limit process counts and memory on a small host.
CI can set AETERNA_SKIP_BUILD=1 after loading the required development images.
EOF
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        print_error "Docker is not installed."
        exit 1
    fi

    if ! docker compose version >/dev/null 2>&1; then
        print_error "Docker Compose v2 is not available."
        exit 1
    fi
}

ensure_env() {
    if [[ -f "$ENV_FILE_PATH" ]]; then
        return
    fi

    if [[ "$ENV_FILE_PATH" != ".env" ]]; then
        print_error "Environment file not found: $ENV_FILE_PATH"
        exit 1
    fi

    cp .env.example .env
    print_info "Created .env from .env.example. Review it before a production deployment."
}

get_config_value() {
    local key="$1"
    local default_value="$2"
    local value="${!key:-}"

    if [[ -z "$value" && -f "$ENV_FILE_PATH" ]]; then
        value="$(awk -v key="$key" '
            index($0, key "=") == 1 { value = substr($0, length(key) + 2) }
            END { print value }
        ' "$ENV_FILE_PATH")"
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
    fi

    printf '%s' "${value:-$default_value}"
}

set_compose_args() {
    local environment="${1:-dev}"
    COMPOSE_ARGS=(-f "$BASE_FILE")

    case "$environment" in
        dev)
            COMPOSE_ARGS+=(-f "$DEV_FILE")
            ;;
        prod)
            COMPOSE_ARGS+=(-f "$PROD_FILE")
            ;;
        *)
            print_error "Unknown environment: $environment"
            exit 1
            ;;
    esac

    if [[ "${AETERNA_USE_AWS_PROFILES:-0}" == "1" ]]; then
        COMPOSE_ARGS+=(-f docker-compose.aws.yml)
    fi
    if [[ "${AETERNA_USE_SMALL_HOST:-0}" == "1" ]]; then
        COMPOSE_ARGS+=(-f docker-compose.small.yml)
    fi
    if [[ "${AETERNA_USE_RELEASE_IMAGES:-0}" == "1" ]]; then
        COMPOSE_ARGS+=(-f docker-compose.release.yml)
    fi
}

compose() {
    docker compose --env-file "$ENV_FILE_PATH" "${COMPOSE_ARGS[@]}" "$@"
}

start_environment() {
    local environment="$1"
    ensure_env
    set_compose_args "$environment"

    print_info "Building and starting the $environment environment..."
    local build_option=--build
    if [[ "${AETERNA_SKIP_BUILD:-0}" == "1" ]]; then
        build_option=--no-build
    fi
    compose up -d "$build_option" --remove-orphans --wait --wait-timeout 180

    print_info "Applying database migrations..."
    compose exec -T backend alembic upgrade head

    print_info "Environment is ready."
    if [[ "$environment" == "dev" ]]; then
        print_info "Frontend: http://localhost:$(get_config_value FRONTEND_DEV_PORT 3000)"
    else
        print_info "Frontend: http://localhost:$(get_config_value FRONTEND_PORT 8080)"
    fi
    print_info "Backend: http://localhost:$(get_config_value API_PORT 8001)"
    print_info "API docs: http://localhost:$(get_config_value API_PORT 8001)/client/docs"
}

release_environment() {
    local revision="${1:-}"
    if [[ ! "$revision" =~ ^[a-f0-9]{40}$ ]]; then
        print_error "Release must identify a full commit SHA."
        exit 1
    fi
    if [[ ! -f "$ENV_FILE_PATH" || "${AETERNA_USE_AWS_PROFILES:-0}" != "1" ]]; then
        print_error "Release requires existing production configuration and AWS profiles."
        exit 1
    fi
    : "${AETERNA_IDENTITY_KMS_REGION:?Set the public KMS region}"
    : "${AETERNA_IDENTITY_KMS_KEY_ARN:?Set the public KMS key ARN}"
    : "${AETERNA_BACKUP_DIRECTORY:?Set the external backup directory}"

    export IMAGE_TAG="$revision"
    export AETERNA_USE_RELEASE_IMAGES=1
    export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aeterna-control-plane}"
    set_compose_args prod
    compose config --quiet

    local database_existed=0
    if docker volume inspect "${COMPOSE_PROJECT_NAME}_postgres-data" >/dev/null 2>&1; then
        database_existed=1
    fi
    print_info "Starting persistent services..."
    compose up -d --no-build --wait --wait-timeout 180 postgres redis

    print_info "Pausing application traffic and scheduled work..."
    compose stop celery-beat celery-worker frontend backend

    local backup_directory
    backup_directory="$(mktemp -d "$AETERNA_BACKUP_DIRECTORY/$(date -u +%Y%m%dT%H%M%SZ)-$revision.XXXXXXXX")"
    chmod 700 "$backup_directory"
    print_info "Backing up PostgreSQL before migrations..."
    compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' \
        > "$backup_directory/database.dump"
    chmod 600 "$backup_directory/database.dump"

    if ! compose run --rm --no-deps --entrypoint sh backend \
        -c 'test -s /app/identity-keys/envelope.json'; then
        if [[ "$database_existed" == "1" ]]; then
            print_error "Existing database has no identity envelope. Restore its original envelope."
            exit 1
        fi
        print_info "Initializing the identity envelope for this new database..."
        AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-identity-provisioner \
        AETERNA_AWS_PROFILE=aeterna-identity-provisioner \
            compose --profile identity-setup run --rm --no-deps identity-setup \
                --region "$AETERNA_IDENTITY_KMS_REGION" \
                --key-arn "$AETERNA_IDENTITY_KMS_KEY_ARN" --environment production
    fi

    compose run --rm --no-deps --user 0:0 --entrypoint sh \
        -v "$backup_directory:/backup" backend \
        -c 'cp /app/identity-keys/envelope.json /backup/envelope.json && chmod 600 /backup/envelope.json'
    print_info "Applying migrations before starting the application..."
    compose run --rm --no-deps backend alembic upgrade head
    compose up -d --no-build --pull never --remove-orphans --wait --wait-timeout 300
    print_info "Release is healthy. Backup retained at $backup_directory."
}

main() {
    local command="${1:-}"

    case "$command" in
        dev|prod|release|stop|restart|logs|status|migrate|mcp-setup|mcp-serve|monitoring|config)
            require_docker
            ;;
    esac

    case "$command" in
        init)
            ensure_env
            ;;
        dev|prod)
            start_environment "$command"
            ;;
        release)
            release_environment "${2:-}"
            ;;
        stop)
            ensure_env
            set_compose_args dev
            compose --profile monitoring down --remove-orphans
            ;;
        restart)
            local environment="${2:-dev}"
            ensure_env
            set_compose_args "$environment"
            compose restart
            ;;
        logs)
            ensure_env
            set_compose_args dev
            if [[ -n "${2:-}" ]]; then
                compose logs --follow "$2"
            else
                compose logs --follow
            fi
            ;;
        status)
            ensure_env
            set_compose_args dev
            compose --profile monitoring ps
            ;;
        migrate)
            ensure_env
            set_compose_args dev
            compose exec -T backend alembic upgrade head
            ;;
        mcp-setup)
            ensure_env
            set_compose_args dev
            compose exec -T backend python scripts/setup_postgres_mcp_role.py
            ;;
        mcp-serve)
            if [[ ! -f "$ENV_FILE_PATH" ]]; then
                print_error "Environment file not found: $ENV_FILE_PATH"
                exit 1
            fi
            set_compose_args dev
            exec docker compose --env-file "$ENV_FILE_PATH" \
                "${COMPOSE_ARGS[@]}" exec -T backend python scripts/postgres_mcp.py
            ;;
        monitoring)
            ensure_env
            set_compose_args dev
            compose --profile monitoring up -d flower
            print_info "Flower: http://localhost:$(get_config_value FLOWER_PORT 5556)"
            ;;
        config)
            ensure_env
            set_compose_args "${2:-dev}"
            compose config
            ;;
        *)
            usage
            [[ -n "$command" ]] && exit 1
            ;;
    esac
}

main "$@"
