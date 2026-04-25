#!/usr/bin/env bash
# migrate-nginx-vhosts.sh — migrate V1 nginx vhosts to the canonical V2 conf.d-v2/ format.
#
# For each active instance where a V2 systemd service exists on this server:
#   1. Detect type (node vs phpfpm) from /etc/systemd/system/dnsfox-{type}-{id}.service
#   2. Extract port (Node.js) or PHP-FPM socket username (PHP)
#   3. Choose SSL cert: Let's Encrypt > /etc/ssl/dnsfox/{domain}/ > wildcard
#   4. Write /etc/nginx/conf.d-v2/dnsfox-{siteID}.conf using the canonical V2 template
#   5. Remove stale domain-named configs from conf.d-v2/ (legacy naming)
#   6. Remove V1 symlink from sites-enabled/ if present
#   7. Run nginx -t and reload
#
# Usage:
#   sudo ./migrate-nginx-vhosts.sh             # live run
#   sudo ./migrate-nginx-vhosts.sh --dry-run   # preview only, no changes
#   sudo ./migrate-nginx-vhosts.sh --site UUID # migrate a single site
#   sudo ./migrate-nginx-vhosts.sh --verbose   # show extra detail

set -euo pipefail

DRY_RUN=false
VERBOSE=false
SINGLE_SITE=""

usage() {
  echo "Usage: $0 [--dry-run] [--verbose] [--site SITE_ID]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --verbose) VERBOSE=true; shift ;;
    --site)    SINGLE_SITE="${2:?--site requires a value}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (nginx configs require elevated write access)" >&2
  exit 1
fi

log()     { echo "[$(date '+%H:%M:%S')] $*"; }
verbose() { "$VERBOSE" && echo "         $*" || true; }

# Write a file unless --dry-run; always shows the target path.
write_file() {
  local path="$1"
  local content="$2"
  if "$DRY_RUN"; then
    echo "    [dry-run] write → $path"
  else
    echo "$content" > "$path"
  fi
}

remove_file() {
  local path="$1"
  if "$DRY_RUN"; then
    echo "    [dry-run] remove → $path"
  else
    rm -f "$path"
  fi
}

# ── Constants ────────────────────────────────────────────────────────────────

V2_CONF_DIR="/etc/nginx/conf.d-v2"
V1_SITES_ENABLED="/etc/nginx/sites-enabled"
V1_SITES_AVAILABLE="/etc/nginx/sites-available"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/dnsfox"

# PGPASSWORD must be supplied by the caller (not committed to git).
# Example: PGPASSWORD=$(grep DATABASE_URL /home/ubuntu/dnsfox-platform/.env | grep -oP '(?<=:)[^@]+(?=@)')
: "${PGPASSWORD:?Set PGPASSWORD before running this script (see /home/ubuntu/dnsfox-platform/.env)}"
export PGPASSWORD
DB_CONN="-h 127.0.0.1 -p 5432 -U dnsfox_user -d dnsfox"

# ── SSL cert resolution ───────────────────────────────────────────────────────

# ssl_cert_for DOMAIN → sets global CERT_FILE and CERT_KEY
ssl_cert_for() {
  local domain="$1"
  if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]]; then
    CERT_FILE="/etc/letsencrypt/live/${domain}/fullchain.pem"
    CERT_KEY="/etc/letsencrypt/live/${domain}/privkey.pem"
    verbose "SSL: Let's Encrypt /etc/letsencrypt/live/${domain}/"
  elif [[ -f "/etc/ssl/dnsfox/${domain}/fullchain.pem" ]]; then
    CERT_FILE="/etc/ssl/dnsfox/${domain}/fullchain.pem"
    CERT_KEY="/etc/ssl/dnsfox/${domain}/privkey.pem"
    verbose "SSL: DNSFox stored /etc/ssl/dnsfox/${domain}/"
  else
    CERT_FILE="/etc/ssl/dnsfox/wildcard-sites/fullchain.pem"
    CERT_KEY="/etc/ssl/dnsfox/wildcard-sites/privkey.pem"
    verbose "SSL: wildcard fallback"
  fi
}

# ── Config generators ─────────────────────────────────────────────────────────

# Nginx variables are escaped as \$var so bash does not expand them.
# Bash variables (site_id, domain, etc.) are expanded normally.

gen_nodejs_conf() {
  local site_id="$1" server_names="$2" ssl_cert="$3" ssl_key="$4" port="$5"
  cat <<NGINX
# DNSFox v2 — Node.js proxy vhost (migrated from V1)
# Do not edit manually — managed by Warden

server {
    listen 80;
    listen [::]:80;
    server_name ${server_names};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${server_names};

    ssl_certificate     ${ssl_cert};
    ssl_certificate_key ${ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log ${LOG_DIR}/nginx-${site_id}-access.log;
    error_log  ${LOG_DIR}/nginx-${site_id}-error.log;

    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
    }

    location /_dba/ {
        proxy_pass http://127.0.0.1:9200;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_read_timeout 300s;
        access_log off;
    }

    location ~ /\. {
        deny all;
    }
}
NGINX
}

gen_php_conf() {
  local site_id="$1" server_names="$2" ssl_cert="$3" ssl_key="$4" username="$5" docroot="$6"
  cat <<NGINX
# DNSFox v2 — PHP/WordPress vhost (migrated from V1)
# Do not edit manually — managed by Warden

server {
    listen 80;
    listen [::]:80;
    server_name ${server_names};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${server_names};

    ssl_certificate     ${ssl_cert};
    ssl_certificate_key ${ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;

    root ${docroot};
    index index.php index.html;

    client_max_body_size 64M;
    client_body_timeout 300s;

    access_log ${LOG_DIR}/nginx-${site_id}-access.log;
    error_log  ${LOG_DIR}/nginx-${site_id}-error.log;

    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/${username}.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTPS on;
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_buffer_size 32k;
        fastcgi_buffers 16 16k;
        fastcgi_busy_buffers_size 64k;
        include fastcgi_params;
        set \$skip_cache 0;
        if (\$request_method = POST)                                       { set \$skip_cache 1; }
        if (\$request_uri ~* "^(/cart|/checkout|/my-account)")            { set \$skip_cache 1; }
        fastcgi_cache V2_SITES;
        fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
        fastcgi_cache_valid 200 301 302 60m;
        fastcgi_cache_valid 404 1m;
        fastcgi_cache_lock on;
        fastcgi_cache_use_stale error timeout invalid_header http_500 http_503;
        fastcgi_cache_bypass \$skip_cache
                             \$cookie_wordpress_logged_in
                             \$cookie_wordpress_sec
                             \$cookie_comment_author
                             \$cookie_woocommerce_cart_hash
                             \$cookie_woocommerce_items_in_cart
                             \$cookie_wp_woocommerce_session;
        fastcgi_no_cache    \$skip_cache
                             \$cookie_wordpress_logged_in
                             \$cookie_wordpress_sec
                             \$cookie_comment_author
                             \$cookie_woocommerce_cart_hash
                             \$cookie_woocommerce_items_in_cart
                             \$cookie_wp_woocommerce_session;
        add_header X-Cache-Status \$upstream_cache_status always;
    }

    location /_dba/ {
        proxy_pass http://127.0.0.1:9200;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_read_timeout 300s;
        access_log off;
    }

    # Cache purge — localhost only. Warden handles actual file removal via PurgeCache().
    location ~ ^/_purge(/.*)?\$ {
        allow 127.0.0.1;
        deny all;
        return 200 "PURGED\n";
        add_header Content-Type text/plain;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
        access_log off;
    }

    location ~ /\. {
        deny all;
    }

    location ~* \.(env|log|sql|bak|credentials)\$ {
        deny all;
    }
}
NGINX
}

# ── Main loop ─────────────────────────────────────────────────────────────────

log "DNSFox V1→V2 nginx vhost migration${DRY_RUN:+ (DRY RUN)}"
log "Reading active instances from DB..."

if [[ -n "$SINGLE_SITE" ]] && \
   [[ ! "$SINGLE_SITE" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "ERROR: --site must be a valid UUID (lowercase hex, e.g. a1b2c3d4-...)" >&2
  exit 1
fi

QUERY="SELECT id, domain, subdomain FROM instances WHERE status NOT IN ('deleted','suspended')"
if [[ -n "$SINGLE_SITE" ]]; then
  QUERY+=" AND id = '${SINGLE_SITE}'"
fi
QUERY+=" ORDER BY domain"

mapfile -t ROWS < <(
  psql $DB_CONN -t -A -F'|' -c "$QUERY" 2>/dev/null \
  | grep -v '^$'
)

if [[ ${#ROWS[@]} -eq 0 ]]; then
  log "No instances found — nothing to do."
  exit 0
fi

log "Found ${#ROWS[@]} instance(s) to evaluate."
echo

MIGRATED=0
SKIPPED=0
ERRORS=0

for row in "${ROWS[@]}"; do
  IFS='|' read -r site_id domain subdomain <<< "$row"

  log "[$domain] site_id=${site_id}"

  # Username matches SiteUsername() in Go: "site_" + first 15 chars of UUID
  username="site_${site_id:0:15}"

  v2_conf="${V2_CONF_DIR}/dnsfox-${site_id}.conf"
  old_domain_conf="${V2_CONF_DIR}/${domain}.conf"
  v1_enabled="${V1_SITES_ENABLED}/${domain}"

  # ── Detect V2 service type ──────────────────────────────────────────────

  node_svc="${SYSTEMD_DIR}/dnsfox-node-${site_id}.service"
  php_svc="${SYSTEMD_DIR}/dnsfox-phpfpm-${site_id}.service"

  site_type=""
  node_port=""
  php_socket_user=""

  if [[ -f "$node_svc" ]]; then
    site_type="nodejs"
    node_port=$(grep -oP '(?<=Environment=PORT=)\d+' "$node_svc" | head -1)
    if [[ -z "$node_port" ]]; then
      log "  ERROR: dnsfox-node-${site_id}.service has no PORT environment variable"
      ((ERRORS++)) || true
      continue
    fi
    verbose "type=nodejs port=${node_port}"

  elif [[ -f "$php_svc" ]]; then
    site_type="php"
    php_socket_user="$username"
    verbose "type=php socket=/run/php/${username}.sock"

  else
    log "  SKIP: no V2 systemd service found — needs service migration first"
    # Warn if a stale domain-named conf.d-v2 file exists without a running service.
    # Nginx is loading it, but there's nothing to proxy/fastcgi to.
    if [[ -f "${V2_CONF_DIR}/${domain}.conf" ]]; then
      log "  WARNING: stale ${V2_CONF_DIR}/${domain}.conf exists with no V2 service behind it"
    fi
    ((SKIPPED++)) || true
    continue
  fi

  # ── SSL cert ────────────────────────────────────────────────────────────

  ssl_cert_for "$domain"

  # ── server_name list ────────────────────────────────────────────────────
  # Include www.{domain} for custom domains; append internal subdomain if set.

  if [[ "$domain" == *".sites.dnsfox.com" || "$domain" == *".dwarf.host" ]]; then
    server_names="$domain"
  else
    server_names="$domain www.$domain"
  fi
  if [[ -n "$subdomain" ]]; then
    server_names="$server_names $subdomain"
  fi
  verbose "server_name: $server_names"

  # ── Generate config ─────────────────────────────────────────────────────

  "$DRY_RUN" && verbose "Would write → $v2_conf" || true
  if ! "$DRY_RUN"; then
    mkdir -p "$LOG_DIR"
    mkdir -p "$V2_CONF_DIR"
  fi

  if [[ "$site_type" == "nodejs" ]]; then
    conf_content=$(gen_nodejs_conf "$site_id" "$server_names" "$CERT_FILE" "$CERT_KEY" "$node_port")
  else
    docroot="/var/www/${username}"
    conf_content=$(gen_php_conf "$site_id" "$server_names" "$CERT_FILE" "$CERT_KEY" "$username" "$docroot")
  fi

  write_file "$v2_conf" "$conf_content"

  # ── Remove stale domain-named V2 config ─────────────────────────────────

  if [[ -f "$old_domain_conf" && "$old_domain_conf" != "$v2_conf" ]]; then
    log "  Removing stale domain-named config: $(basename "$old_domain_conf")"
    remove_file "$old_domain_conf"
  fi

  # ── Disable V1 symlink from sites-enabled ───────────────────────────────

  if [[ -L "$v1_enabled" ]]; then
    log "  Disabling V1 sites-enabled symlink: $v1_enabled"
    remove_file "$v1_enabled"
  elif [[ -f "$v1_enabled" ]]; then
    log "  WARNING: $v1_enabled is a plain file (not a symlink) — not touching it"
  fi

  log "  OK: $site_type → $(basename "$v2_conf")"
  ((MIGRATED++)) || true
done

echo

# ── nginx validate + reload ──────────────────────────────────────────────────

if "$DRY_RUN"; then
  log "[dry-run] Would run: nginx -t && systemctl reload nginx"
else
  log "Validating nginx config..."
  if nginx -t 2>&1; then
    log "Config valid — reloading nginx"
    systemctl reload nginx
    log "nginx reloaded."
  else
    log "ERROR: nginx -t failed — configs written but nginx NOT reloaded. Fix manually."
    ((ERRORS++)) || true
  fi
fi

echo
log "Done: migrated=${MIGRATED} skipped=${SKIPPED} errors=${ERRORS}"
[[ $ERRORS -eq 0 ]]
