#!/usr/bin/env bash
# redis-migrate-v1-to-v2.sh — Redis cache migration/cleanup for V1→V2 site moves.
#
# V1 Docker sites used per-site Redis DB numbers (DNSFOX_REDIS_DB env var inside
# the container). V2 bare-metal sites use shared Redis DB 0 with a per-site key
# prefix: "site_{UUID}:".
#
# MIGRATION SCENARIOS
#   - V1 Docker → V2 same server  : Different Redis instances (Docker vs host 6380).
#                                   Just verify V2 wp-config.php has WP_REDIS_PREFIX.
#   - V1 Docker → V2 cross-server : Same as above — no conflict. Verify V2 config.
#   - V2 → V2 cross-server        : Flush old prefix keys on source (or let them
#                                   expire). V2 destination starts fresh; cache
#                                   rebuilds on first request.
#   - Reuse site UUID on new server: Destination may have stale keys from a prior
#                                   provisioning. Run --action flush to clean them.
#
# USAGE
#   # Verify V2 wp-config.php is correct for a site
#   sudo ./redis-migrate-v1-to-v2.sh --site-id UUID --action verify --wp-path /var/www/USERNAME
#
#   # Flush all Redis keys for a site on the V2 host Redis (SCAN+DEL, safe)
#   sudo ./redis-migrate-v1-to-v2.sh --site-id UUID --action flush
#
#   # Flush a V1 per-DB Redis (single SELECT+FLUSHDB, not FLUSHALL)
#   sudo ./redis-migrate-v1-to-v2.sh --site-id UUID --action flush-v1-db --redis-db 3 \
#        --redis-host 127.0.0.1 --redis-port 6379
#
#   # Dry run — show what would be flushed without deleting
#   sudo ./redis-migrate-v1-to-v2.sh --site-id UUID --action flush --dry-run

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SITE_ID=""
ACTION=""
REDIS_HOST="127.0.0.1"
REDIS_PORT="6380"
REDIS_PASSWORD=""
REDIS_DB=""
WP_PATH=""
DRY_RUN=false

# ── Parse args ────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 --site-id UUID --action ACTION [OPTIONS]

Actions:
  verify         Check WP_REDIS_PREFIX in wp-config.php matches expected V2 value
  flush          SCAN+DEL all "site_{UUID}:*" keys on V2 Redis (DB 0, port 6380)
  flush-v1-db    SELECT {db}; FLUSHDB — flush a V1 per-site Redis DB (not FLUSHALL)

Options:
  --redis-host HOST    Redis host (default: 127.0.0.1)
  --redis-port PORT    Redis port (default: 6380)
  --redis-password PW  Redis password (default: none)
  --redis-db NUM       Redis DB number (flush-v1-db only, required)
  --wp-path PATH       WordPress docroot for verify action
  --dry-run            Show what would be done without making changes
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --site-id)         SITE_ID="$2";        shift 2 ;;
    --action)          ACTION="$2";         shift 2 ;;
    --redis-host)      REDIS_HOST="$2";     shift 2 ;;
    --redis-port)      REDIS_PORT="$2";     shift 2 ;;
    --redis-password)  REDIS_PASSWORD="$2"; shift 2 ;;
    --redis-db)        REDIS_DB="$2";       shift 2 ;;
    --wp-path)         WP_PATH="$2";        shift 2 ;;
    --dry-run)         DRY_RUN=true;        shift ;;
    -h|--help)         usage ;;
    *)                 echo "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$SITE_ID" ]] && { echo "ERROR: --site-id is required"; usage; }
[[ -z "$ACTION" ]]  && { echo "ERROR: --action is required";  usage; }

# ── Redis CLI helper ──────────────────────────────────────────────────────────
# Pass password via REDISCLI_AUTH so it does not appear in /proc/PID/cmdline or ps output.
[[ -n "$REDIS_PASSWORD" ]] && export REDISCLI_AUTH="$REDIS_PASSWORD"
rcli() {
  redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" "$@"
}

# ── Actions ───────────────────────────────────────────────────────────────────

action_verify() {
  if [[ -z "$WP_PATH" ]]; then
    echo "ERROR: --wp-path is required for the verify action"
    exit 1
  fi

  local wpcfg="$WP_PATH/wp-config.php"
  if [[ ! -f "$wpcfg" ]]; then
    echo "ERROR: wp-config.php not found at $wpcfg"
    exit 1
  fi

  local expected_prefix="site_${SITE_ID}:"
  echo "Checking $wpcfg for WP_REDIS_PREFIX..."

  if grep -q "WP_REDIS_PREFIX" "$wpcfg"; then
    local found
    found=$(grep "WP_REDIS_PREFIX" "$wpcfg" | head -1)
    echo "  Found: $found"
    if echo "$found" | grep -q "$expected_prefix"; then
      echo "  OK — WP_REDIS_PREFIX matches expected value '$expected_prefix'"
    else
      echo "  WARN — WP_REDIS_PREFIX found but does not match expected '$expected_prefix'"
      echo "  Run: wp-cli --path=$WP_PATH config set WP_REDIS_PREFIX '$expected_prefix' --type=constant"
    fi
  else
    echo "  WARN — WP_REDIS_PREFIX not found in wp-config.php"
    echo "  Run: wp-cli --path=$WP_PATH config set WP_REDIS_PREFIX '$expected_prefix' --type=constant"
  fi

  # Also check the Redis connection is live from this host.
  if rcli PING 2>/dev/null | grep -q "PONG"; then
    echo "  Redis connection: OK ($REDIS_HOST:$REDIS_PORT)"
  else
    echo "  Redis connection: FAILED ($REDIS_HOST:$REDIS_PORT)"
  fi
}

action_flush() {
  local pattern="site_${SITE_ID}:*"
  echo "Scanning for Redis keys matching: $pattern"
  echo "  Host: $REDIS_HOST:$REDIS_PORT  DB: 0"

  local cursor="0"
  local total=0

  while true; do
    local result
    result=$(rcli SCAN "$cursor" MATCH "$pattern" COUNT 200)
    cursor=$(echo "$result" | head -1)
    [[ -z "$cursor" ]] && { echo "ERROR: SCAN returned empty cursor"; exit 1; }
    mapfile -t keys < <(echo "$result" | tail -n +2 | grep -v '^$')

    if [[ ${#keys[@]} -gt 0 ]]; then
      echo "  Batch: ${#keys[@]} keys (cursor=$cursor)"
      if [[ "$DRY_RUN" == "true" ]]; then
        printf '    %s\n' "${keys[@]}"
      else
        rcli DEL "${keys[@]}" > /dev/null
      fi
      total=$(( total + ${#keys[@]} ))
    fi

    [[ "$cursor" == "0" ]] && break
  done

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN: would delete $total keys for site $SITE_ID"
  else
    echo "Done: deleted $total keys for site $SITE_ID"
  fi
}

action_flush_v1_db() {
  if [[ -z "$REDIS_DB" ]]; then
    echo "ERROR: --redis-db is required for flush-v1-db"
    exit 1
  fi

  echo "Flushing V1 Redis DB $REDIS_DB on $REDIS_HOST:$REDIS_PORT (site: $SITE_ID)"
  echo "  This uses SELECT $REDIS_DB; FLUSHDB — NOT FLUSHALL"

  local key_count
  key_count=$(rcli -n "$REDIS_DB" DBSIZE)
  echo "  Keys in DB $REDIS_DB: $key_count"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN: would flush $key_count keys from Redis DB $REDIS_DB"
    return
  fi

  rcli -n "$REDIS_DB" FLUSHDB
  echo "Done: flushed Redis DB $REDIS_DB ($key_count keys)"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$ACTION" in
  verify)       action_verify ;;
  flush)        action_flush ;;
  flush-v1-db)  action_flush_v1_db ;;
  *)            echo "Unknown action: $ACTION"; usage ;;
esac
