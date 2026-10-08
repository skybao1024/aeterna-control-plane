#!/usr/bin/env bash
# Install as /usr/local/sbin/aeterna-release, owned by root and mode 0755.
# Accepts a full commit SHA; CI uploads an immutable image/config bundle first.
set -Eeuo pipefail
umask 077

revision="${1:-}"
[[ "$#" == "1" && "$revision" =~ ^[a-f0-9]{40}$ ]] || exit 2
[[ "$EUID" == "0" ]] || exit 2

root=/srv/aeterna-control-plane
incoming="$root/incoming/$revision"
release="$root/releases/$revision"
phase=preflight
trap 'printf "Deployment failed during %s. Inspect the private server log locally.\n" "$phase" >&2' ERR

exec 9>/var/lock/aeterna-control-plane-release.lock
flock -w 30 9
[[ -d "$incoming" && ! -L "$incoming" ]]
for name in images.tar.gz release.tar.gz checksums.txt; do
    [[ -f "$incoming/$name" && ! -L "$incoming/$name" ]]
done

install -d -o root -g root -m 700 "$root/releases" "$root/backups" /var/log/aeterna-control-plane
private_log="/var/log/aeterna-control-plane/$revision-$(date -u +%Y%m%dT%H%M%SZ).log"
touch "$private_log"
chmod 600 "$private_log"

phase=checksum-verification
(
    cd "$incoming"
    awk 'NF != 2 || $1 !~ /^[a-f0-9]+$/ || length($1) != 64 || ($2 != "images.tar.gz" && $2 != "release.tar.gz") { exit 1 } END { if (NR != 2) exit 1 }' checksums.txt
    sha256sum --check --strict checksums.txt
) >> "$private_log" 2>&1

phase=archive-validation
tar -tzf "$incoming/release.tar.gz" | LC_ALL=C sort > "$root/expected-release-files.actual"
printf '%s\n' deploy.sh docker-compose.yml docker-compose.prod.yml docker-compose.aws.yml \
    docker-compose.small.yml docker-compose.release.yml | LC_ALL=C sort \
    > "$root/expected-release-files.expected"
cmp "$root/expected-release-files.actual" "$root/expected-release-files.expected" >> "$private_log" 2>&1
tar -tvzf "$incoming/release.tar.gz" | awk '$1 !~ /^-/ { exit 1 }'

phase=image-loading
docker load -i "$incoming/images.tar.gz" >> "$private_log" 2>&1
docker image inspect --format '{{.Os}}/{{.Architecture}}' \
    "aeterna-control-plane-backend:$revision" \
    "aeterna-control-plane-frontend:$revision" | \
    awk '$0 != "linux/amd64" { exit 1 } END { if (NR != 2) exit 1 }'

if [[ ! -e "$release" ]]; then
    install -d -o root -g root -m 700 "$release"
    tar -xzf "$incoming/release.tar.gz" --no-same-owner --no-same-permissions -C "$release"
    chmod 700 "$release/deploy.sh"
fi
[[ -d "$release" && ! -L "$release" ]]

# This is a root-owned file containing public controls only, never credentials.
source /etc/aeterna/deployment.conf
export ENV_FILE=/etc/aeterna/runtime.env
export COMPOSE_PROJECT_NAME=aeterna-control-plane
export AETERNA_USE_AWS_PROFILES=1
export AETERNA_USE_SMALL_HOST=1
export AETERNA_BACKUP_DIRECTORY="$root/backups"
export AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-runtime
export AETERNA_AWS_PROFILE=aeterna-runtime
export AETERNA_IDENTITY_KMS_REGION AETERNA_IDENTITY_KMS_KEY_ARN

phase=service-release
"$release/deploy.sh" release "$revision" >> "$private_log" 2>&1

phase=health-verification
curl --fail --silent --show-error --max-time 15 \
    http://127.0.0.1:8001/api/v1/config/health > /dev/null
curl --fail --silent --show-error --max-time 15 http://127.0.0.1:8080/health > /dev/null
ln -sfn "$release" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
# Retain installed images and root-owned release directories for reviewed rollback.
rm -f "$incoming/images.tar.gz" "$incoming/release.tar.gz" "$incoming/checksums.txt"
rmdir "$incoming"
printf 'Release %s is healthy.\n' "$revision"
