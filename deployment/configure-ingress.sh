#!/usr/bin/env bash
# Run as root on the production host from the uploaded deployment directory.
# Requires Nginx, Certbot, and all three DNS records pointing to this host.
# Updates only this project's ingress and certificate; accepts no arguments.
set -Eeuo pipefail
umask 077
[[ "$EUID" == "0" && "$#" == "0" ]] || exit 2
directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
site=/etc/nginx/sites-available/aeterna-control-plane
enabled=/etc/nginx/sites-enabled/aeterna-control-plane
temporary=/etc/nginx/sites-enabled/aeterna-control-plane-claim-acme
certificate=/etc/letsencrypt/live/aeterna-control-plane/fullchain.pem
operation="$(mktemp -d /root/aeterna-ingress.XXXXXXXX)"
log="$operation/operation.log"
previous=0
changed=0
temporary_created=0

if [[ -e "$site" ]]; then
    [[ -f "$site" && ! -L "$site" ]]
    cp -p "$site" "$operation/previous.conf"
    previous=1
fi
[[ ! -e "$enabled" || ( -L "$enabled" && "$(readlink "$enabled")" == "$site" ) ]]
[[ ! -e "$temporary" && ! -L "$temporary" ]]

cleanup() {
    local status="$?"
    local reload_needed=0
    if [[ "$temporary_created" == "1" ]]; then
        rm -f "$temporary"
        reload_needed=1
    fi
    if [[ "$status" != "0" && "$changed" == "1" ]]; then
        if [[ "$previous" == "1" ]]; then
            install -o root -g root -m 644 "$operation/previous.conf" "$site"
        else
            rm -f "$site" "$enabled"
        fi
        reload_needed=1
    fi
    if [[ "$status" != "0" && "$reload_needed" == "1" ]]; then
        if nginx -t >> "$log" 2>&1; then
            systemctl reload nginx >> "$log" 2>&1 || true
        fi
    fi
    if [[ "$status" != "0" ]]; then
        printf 'Ingress update failed. Inspect the private host log at %s.\n' "$log" >&2
    else
        rm -rf "$operation"
    fi
}
trap cleanup EXIT

install -d -o root -g root -m 755 /var/www/aeterna-control-acme
if [[ "$previous" == "0" ]]; then
    changed=1
    install -o root -g root -m 644 "$directory/nginx-http.conf" "$site"
    ln -s "$site" "$enabled"
fi

certificate_ready=1
for domain in api.aeternarelay.com console.aeternarelay.com claim.aeternarelay.com; do
    if [[ ! -f "$certificate" ]] || ! openssl x509 -in "$certificate" \
        -noout -checkhost "$domain" > /dev/null 2>&1; then
        certificate_ready=0
    fi
done
if [[ "$certificate_ready" == "0" ]]; then
    if [[ "$previous" == "1" ]]; then
        # Keep the existing API and console HTTPS servers active during ACME.
        cat > "$temporary" <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name claim.aeternarelay.com;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/aeterna-control-acme;
        default_type text/plain;
    }
    location / { return 503; }
}
NGINX
        temporary_created=1
    fi
    nginx -t >> "$log" 2>&1
    systemctl reload nginx >> "$log" 2>&1
    certbot certonly --webroot -w /var/www/aeterna-control-acme \
        --cert-name aeterna-control-plane --expand \
        -d api.aeternarelay.com -d console.aeternarelay.com -d claim.aeternarelay.com \
        --non-interactive --agree-tos --register-unsafely-without-email >> "$log" 2>&1
fi

if [[ "$temporary_created" == "1" ]]; then
    rm -f "$temporary"
    temporary_created=0
fi
changed=1
install -o root -g root -m 644 "$directory/nginx.conf" "$site"
if [[ ! -e "$enabled" ]]; then
    ln -s "$site" "$enabled"
fi
nginx -t >> "$log" 2>&1
systemctl reload nginx >> "$log" 2>&1
systemctl enable --now certbot.timer >> "$log" 2>&1
printf 'API, operations console, and trusted contact HTTPS ingress prepared.\n'
