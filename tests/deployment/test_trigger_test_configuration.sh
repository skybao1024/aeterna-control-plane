#!/usr/bin/env bash
# Run from the repository root. Resolves only synthetic settings, never runtime secrets.
set -Eeuo pipefail
repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository"
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/aeterna-trigger-release-test.XXXXXXXX")"
trap 'rm -rf "$test_directory"' EXIT
umask 077
configuration="$test_directory/synthetic.env.example"
cat > "$configuration" <<'SETTINGS'
POSTGRES_USER=synthetic
POSTGRES_DB=synthetic
POSTGRES_PASSWORD=synthetic-postgres-password
REDIS_PASSWORD=synthetic-redis-password
SECRET_KEY=synthetic-only-jwt-key
ENV=production
SETTINGS
export ENV_FILE="$configuration"
export IMAGE_TAG=0123456789012345678901234567890123456789
export AWS_CONFIG_DIRECTORY="$test_directory/synthetic-aws"
export AETERNA_AWS_PROFILE=synthetic-runtime
mkdir -p "$AWS_CONFIG_DIRECTORY"

# Execute only the actual new release child's data-only public-control helper.
# The test child checks that the previous wrapper did not export the control.
printf '%s\n' 'set -Eeuo pipefail' \
    'print_error() { printf "%s\n" "$1" >&2; }' > "$test_directory/public-control.sh"
awk '
    /^configure_trigger_test_notice_origin\(\) \{/ { capture=1 }
    capture { print }
    capture && /^}$/ { capture=0; found++ }
    END { if (found != 1) exit 1 }
' deploy.sh >> "$test_directory/public-control.sh"
printf '%s\n' '[[ -z ${AETERNA_TRIGGER_TEST_NOTICE_ORIGIN+x} ]]' \
    'configure_trigger_test_notice_origin "$1"' \
    'printf "%s" "$AETERNA_TRIGGER_TEST_NOTICE_ORIGIN"' >> "$test_directory/public-control.sh"

for setting in unset empty quoted-empty quoted-custom single-quoted-custom; do
    public_configuration="$test_directory/public-deployment.conf"
    case "$setting" in
        unset)
            : > "$public_configuration"
            expected=https://api.aeternarelay.com
            old_value=
            ;;
        empty)
            printf 'AETERNA_TRIGGER_TEST_NOTICE_ORIGIN=\n' > "$public_configuration"
            expected=
            old_value=
            ;;
        quoted-empty)
            printf 'AETERNA_TRIGGER_TEST_NOTICE_ORIGIN=""\n' > "$public_configuration"
            expected=
            old_value=
            ;;
        quoted-custom)
            printf 'export AETERNA_TRIGGER_TEST_NOTICE_ORIGIN="https://api.example.test"\n' > "$public_configuration"
            expected=https://api.example.test
            old_value=https://api.example.test
            ;;
        single-quoted-custom)
            printf "AETERNA_TRIGGER_TEST_NOTICE_ORIGIN='https://api.example.test'\n" > "$public_configuration"
            expected=https://api.example.test
            old_value=https://api.example.test
            ;;
    esac
    # Reproduce assigned-but-unexported values in the installed previous wrapper.
    origin="$(bash -c '
        unset AETERNA_TRIGGER_TEST_NOTICE_ORIGIN
        if [[ "$3" != unset ]]; then
            AETERNA_TRIGGER_TEST_NOTICE_ORIGIN="$4"
            export -n AETERNA_TRIGGER_TEST_NOTICE_ORIGIN
        fi
        bash "$1" "$2"
    ' synthetic-prior-wrapper "$test_directory/public-control.sh" "$public_configuration" "$setting" "$old_value")"
    [[ "$origin" == "$expected" ]]
    export AETERNA_TRIGGER_TEST_NOTICE_ORIGIN="$origin"
    docker compose --env-file "$configuration" \
        -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.aws.yml \
        -f docker-compose.small.yml -f docker-compose.release.yml \
        config > "$test_directory/resolved.yaml"
    awk -v expected="$expected" '
        /^  [a-zA-Z0-9_-]+:/ { service=$1; sub(/:$/, "", service) }
        /^      AETERNA_TRIGGER_TEST_NOTICE_ORIGIN:/ &&
            (service == "backend" || service == "celery-worker" || service == "celery-beat") {
            value=$2; gsub(/^"|"$/, "", value)
            if (value != expected) exit 1
            found++
        }
        END { if (found != 3) exit 1 }
    ' "$test_directory/resolved.yaml"
done
unset AETERNA_TRIGGER_TEST_NOTICE_ORIGIN
marker="$test_directory/injection-executed"
printf 'AETERNA_TRIGGER_TEST_NOTICE_ORIGIN="$(touch %s)"\n' "$marker" > "$public_configuration"
if bash "$test_directory/public-control.sh" "$public_configuration" \
    > "$test_directory/injection-output.log" 2>&1; then
    exit 1
fi
[[ ! -e "$marker" ]]
printf 'Five first-upgrade trigger-test configurations and injection rejection passed.\n'
