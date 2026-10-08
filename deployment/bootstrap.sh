#!/usr/bin/env bash
# Run as root on the production host after installing Docker and Compose.
# Working directory: this deployment directory, uploaded over the operator SSH.
# Arguments: a CI public-key file, KMS region, and the public identity key ARN.
# Existing runtime secrets, certificates, accounts, and unrelated sites are preserved.
set -Eeuo pipefail
umask 077
[[ "$EUID" == "0" && "$#" == "3" ]] || exit 2
directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
public_key="$1"
region="$2"
key_arn="$3"
[[ "$region" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]]
[[ "$key_arn" =~ ^arn:aws:kms:$region:[0-9]{12}:key/[a-f0-9-]{36}$ ]]
[[ -f "$public_key" && ! -L "$public_key" ]]
ssh-keygen -l -f "$public_key" > /dev/null
docker compose version > /dev/null
bootstrap_log="$(mktemp /root/aeterna-control-bootstrap.XXXXXXXX.log)"
trap 'printf "Server bootstrap failed. Inspect its private server log locally.\n" >&2' ERR

if [[ "${AETERNA_ENABLE_CI_SSH:-0}" == "1" ]]; then
if ! command -v sudo > /dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y sudo >> "$bootstrap_log" 2>&1
fi
if ! id aeterna-control-ci > /dev/null 2>&1; then
    useradd --system --create-home --user-group --shell /bin/bash aeterna-control-ci
fi
install -d -o root -g root -m 755 /srv/aeterna-control-plane
install -d -o aeterna-control-ci -g aeterna-control-ci -m 700 /srv/aeterna-control-plane/incoming
install -d -o root -g root -m 700 /srv/aeterna-control-plane/releases /srv/aeterna-control-plane/backups
install -d -o aeterna-control-ci -g aeterna-control-ci -m 700 /home/aeterna-control-ci/.ssh
if [[ ! -e /home/aeterna-control-ci/.ssh/authorized_keys ]]; then
    { printf 'restrict '; cat "$public_key"; } > /home/aeterna-control-ci/.ssh/authorized_keys
    chown aeterna-control-ci:aeterna-control-ci /home/aeterna-control-ci/.ssh/authorized_keys
    chmod 600 /home/aeterna-control-ci/.ssh/authorized_keys
fi
install -o root -g root -m 755 "$directory/ssh-release.sh" /usr/local/sbin/aeterna-release
printf '%s\n' 'aeterna-control-ci ALL=(root) NOPASSWD: /usr/local/sbin/aeterna-release *' \
    > /etc/sudoers.d/aeterna-control-ci
chmod 440 /etc/sudoers.d/aeterna-control-ci
visudo -cf /etc/sudoers.d/aeterna-control-ci >> "$bootstrap_log" 2>&1
else
    install -d -o root -g root -m 755 /srv/aeterna-control-plane
    install -d -o root -g root -m 700 /srv/aeterna-control-plane/incoming \
        /srv/aeterna-control-plane/releases /srv/aeterna-control-plane/backups
    install -o root -g root -m 755 "$directory/ssh-release.sh" /usr/local/sbin/aeterna-release
fi

install -d -o root -g root -m 755 /etc/aeterna
if [[ ! -e /etc/aeterna/deployment.conf ]]; then
    printf 'AETERNA_IDENTITY_KMS_REGION=%s\nAETERNA_IDENTITY_KMS_KEY_ARN=%s\n' \
        "$region" "$key_arn" > /etc/aeterna/deployment.conf
    chmod 644 /etc/aeterna/deployment.conf
fi
if [[ ! -e /etc/aeterna/runtime.env ]]; then
    (
        set -o noclobber
        {
            printf '%s\n' 'COMPOSE_PROJECT_NAME=aeterna-control-plane' 'ENV=production' \
                'PROJECT_NAME=Aeterna Control Plane' 'BIND_ADDRESS=127.0.0.1' \
                'API_PORT=8001' 'FRONTEND_PORT=8080' 'FRONTEND_URL=https://console.aeternarelay.com' \
                'VITE_API_BASE_URL=/api' 'POSTGRES_USER=app' 'POSTGRES_DB=app' \
                'POSTGRES_HOST=postgres' 'POSTGRES_PORT=5432' 'POSTGRES_SSL_REQUIRE=false' \
                'REDIS_HOST=redis' 'REDIS_PORT=6379' 'CELERY_LOG_LEVEL=info'
            for name in POSTGRES_PASSWORD REDIS_PASSWORD SECRET_KEY; do
                printf '%s=' "$name"
                openssl rand -hex 32
            done
            printf '%s\n' 'AETERNA_IDENTITY_KEY_PROVIDER=aws-kms' 'AETERNA_IDENTITY_KMS_ENABLED=true' \
                "AETERNA_IDENTITY_KMS_REGION=$region" "AETERNA_IDENTITY_KMS_KEY_ARN=$key_arn" \
                'AETERNA_IDENTITY_KMS_ENVELOPE_PATH=/app/identity-keys/envelope.json' \
                'AETERNA_PII_KEY_V1=' 'AETERNA_LOOKUP_KEY_V1=' 'AETERNA_OTP_KEY_V1=' \
                'AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-runtime' 'AETERNA_AWS_PROFILE=aeterna-runtime' \
                'AETERNA_EMAIL_PROVIDER=disabled' 'AETERNA_EMAIL_PRODUCTION_ENABLED=false' \
                'AETERNA_RECOVERY_KEY_PROVIDER=disabled' 'AETERNA_RECOVERY_KMS_ENABLED=false'
        } > /etc/aeterna/runtime.env
    )
fi
[[ -f /etc/aeterna/runtime.env && ! -L /etc/aeterna/runtime.env ]]
chmod 600 /etc/aeterna/runtime.env

if [[ ! -e /etc/nginx/sites-available/aeterna-control-plane ]]; then
    install -d -o root -g root -m 755 /var/www/aeterna-control-acme
    install -o root -g root -m 644 "$directory/nginx-http.conf" /etc/nginx/sites-available/aeterna-control-plane
    ln -s /etc/nginx/sites-available/aeterna-control-plane /etc/nginx/sites-enabled/aeterna-control-plane
    nginx -t >> "$bootstrap_log" 2>&1
    systemctl reload nginx
fi
if [[ ! -d /etc/letsencrypt/live/aeterna-control-plane ]]; then
    certbot certonly --webroot -w /var/www/aeterna-control-acme \
        --cert-name aeterna-control-plane -d api.aeternarelay.com -d console.aeternarelay.com \
        --non-interactive --agree-tos --register-unsafely-without-email >> "$bootstrap_log" 2>&1
fi
install -o root -g root -m 644 "$directory/nginx.conf" /etc/nginx/sites-available/aeterna-control-plane
nginx -t >> "$bootstrap_log" 2>&1
systemctl reload nginx
systemctl enable --now certbot.timer >> "$bootstrap_log" 2>&1
printf 'Production server, private configuration, release wrapper, and HTTPS ingress prepared.\n'
