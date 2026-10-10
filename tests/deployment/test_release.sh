#!/usr/bin/env bash
# Run from the repository root. Uses isolated fake Docker state, never secrets.
set -Eeuo pipefail
repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/aeterna-release-test.XXXXXXXX")"
trap 'rm -rf "$test_directory"' EXIT
mkdir -p "$test_directory/bin" "$test_directory/backups"
touch "$test_directory/runtime.env.example"

cat > "$test_directory/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -eu
printf '%s | profile=%s directory=%s\n' "$*" "${AETERNA_AWS_PROFILE:-}" "${AWS_CONFIG_DIRECTORY:-}" >> "$TEST_COMMAND_LOG"
if [[ "$1" == "volume" ]]; then
    [[ "${TEST_DATABASE_EXISTS:-0}" == "1" ]]
    exit
fi
if [[ "$*" == *'test -s /app/identity-keys/envelope.json'* ]]; then
    [[ "${TEST_ENVELOPE_EXISTS:-0}" == "1" || -f "$TEST_ENVELOPE_STATE" ]]
    exit
fi
if [[ "$*" == *'identity-setup --region'* ]]; then
    touch "$TEST_ENVELOPE_STATE"
fi
if [[ "$*" == *'pg_dump'* ]]; then
    [[ "${TEST_BACKUP_FAILURE:-0}" == "0" ]] || exit 1
    printf 'synthetic database backup\n'
fi
if [[ "$*" == *'alembic upgrade head'* ]]; then
    [[ "${TEST_MIGRATION_FAILURE:-0}" == "0" ]] || exit 1
fi
if [[ "$*" == *'python -m scripts.diagnose_recovery_configuration'* ]]; then
    printf '{"diagnostic_version":1,"status":"%s"}\n' \
        "${TEST_DIAGNOSTIC_STATUS:-recovery_configured_not_probed}"
    exit "${TEST_DIAGNOSTIC_EXIT:-0}"
fi
MOCK
chmod 700 "$test_directory/bin/docker"

export PATH="$test_directory/bin:$PATH"
export ENV_FILE="$test_directory/runtime.env.example"
export AETERNA_USE_AWS_PROFILES=1 AETERNA_USE_SMALL_HOST=1
export AETERNA_IDENTITY_KMS_REGION=ap-southeast-1
export AETERNA_IDENTITY_KMS_KEY_ARN=arn:aws:kms:ap-southeast-1:000000000000:key/00000000-0000-0000-0000-000000000001
export AETERNA_BACKUP_DIRECTORY="$test_directory/backups"
export AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-runtime AETERNA_AWS_PROFILE=aeterna-runtime
export TEST_COMMAND_LOG="$test_directory/commands.log"
export TEST_ENVELOPE_STATE="$test_directory/envelope-created"
revision=0123456789012345678901234567890123456789

reset_case() {
    : > "$TEST_COMMAND_LOG"
    rm -f "$TEST_ENVELOPE_STATE"
    export TEST_DATABASE_EXISTS=0 TEST_ENVELOPE_EXISTS=0
    export TEST_BACKUP_FAILURE=0 TEST_MIGRATION_FAILURE=0
    export TEST_DIAGNOSTIC_EXIT=0
    export TEST_DIAGNOSTIC_STATUS=recovery_configured_not_probed
}

reset_case
bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1
awk '/ stop celery-beat/ { stop=NR } /pg_dump/ { backup=NR } /cp \/app\/identity-keys/ { envelope=NR } /alembic upgrade head/ { migration=NR } /--pull never/ { start=NR } END { exit !(stop && stop < backup && backup < envelope && envelope < migration && migration < start) }' "$TEST_COMMAND_LOG"
awk '/identity-setup --region/ && /profile=aeterna-identity-provisioner directory=\/etc\/aeterna\/aws-identity-provisioner/ { found=1 } END { exit !found }' "$TEST_COMMAND_LOG"
grep -q '"status":"recovery_configured_not_probed"' \
    "$test_directory/release-status/$revision.json"

reset_case
export TEST_DATABASE_EXISTS=1 TEST_ENVELOPE_EXISTS=1
bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1
awk '/identity-setup --region/ { exit 1 }' "$TEST_COMMAND_LOG"

reset_case
export TEST_DATABASE_EXISTS=1
if bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1; then
    exit 1
fi
awk '/identity-setup --region|alembic upgrade head|--pull never/ { exit 1 }' "$TEST_COMMAND_LOG"

reset_case
export TEST_BACKUP_FAILURE=1
if bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1; then
    exit 1
fi
awk '/identity-setup --region|alembic upgrade head|--pull never/ { exit 1 }' "$TEST_COMMAND_LOG"

reset_case
export TEST_ENVELOPE_EXISTS=1 TEST_MIGRATION_FAILURE=1
if bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1; then
    exit 1
fi
awk '/--pull never/ { exit 1 }' "$TEST_COMMAND_LOG"

reset_case
export TEST_ENVELOPE_EXISTS=1 TEST_DIAGNOSTIC_EXIT=1
export TEST_DIAGNOSTIC_STATUS=recovery_provider_disabled
bash "$repository/deploy.sh" release "$revision" > "$test_directory/result.log" 2>&1
grep -q '"status":"recovery_provider_disabled"' \
    "$test_directory/release-status/$revision.json"

reset_case
if bash "$repository/deploy.sh" release invalid > "$test_directory/result.log" 2>&1; then
    exit 1
fi
awk '/ volume inspect| up | stop | run / { exit 1 }' "$TEST_COMMAND_LOG"
printf 'Seven release safety checks passed.\n'
