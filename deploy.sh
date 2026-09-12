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
  stop                 Stop all services without deleting persistent data
  restart [dev|prod]   Restart an environment (defaults to dev)
  logs [service]       Follow logs for all services or one service
  status               Show service status
  migrate              Run Alembic migrations in the backend container
  mcp-setup            Provision the local AI read-only PostgreSQL role
  mcp-serve            Serve the project PostgreSQL MCP over stdio
  monitoring           Start Flower for the current Compose project
  config [dev|prod]    Validate and print the merged Compose configuration
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
}

compose() {
    docker compose --env-file "$ENV_FILE_PATH" "${COMPOSE_ARGS[@]}" "$@"
}

start_environment() {
    local environment="$1"
    ensure_env
    set_compose_args "$environment"

    print_info "Building and starting the $environment environment..."
    compose up -d --build --remove-orphans --wait --wait-timeout 180

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

main() {
    local command="${1:-}"

    case "$command" in
        dev|prod|stop|restart|logs|status|migrate|mcp-setup|mcp-serve|monitoring|config)
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
