# DNSFox v2 Warden Agent — CLAUDE.md

Go binary deployed to every server as `/usr/local/bin/warden`. Current version: **2.70.3**.

## Hosting Model

Sites are provisioned as **systemd services with cgroup v2** — NO Docker containers.

- **Node.js**: `internal/nodejs/` → `dnsfox-node-<uuid>.service`, dedicated Linux user, port 4000-5000
- **PHP/WordPress**: `internal/phpfpm/` and `internal/wordpress/` → `dnsfox-phpfpm-<uuid>.service`, PHP-FPM pool
- **Cgroups**: `internal/cgroups/` → `dnsfox-site-<uuid>.slice` systemd slice for CPU/RAM/IO limits
- **File management**: host-native `dnsfox-mgmt` binary, NOT a Docker sidecar container
- **MariaDB**: host MariaDB on `127.0.0.1:3307`, NOT per-site Docker containers

Do NOT add Docker-based provisioning. The `v1convert/` package and Docker job handlers
have been deleted — the migration from Docker to cgroup is complete.

## Version Bumping (CRITICAL)

When changing ANY warden code, ALWAYS bump version in ALL THREE files:
1. `main.go` — version constant
2. `Makefile` — VERSION variable
3. `build-and-deploy.sh` — version string

Missing any one of these means remote servers (Nordri, Vestri) won't update.

## Build

Always use `-a` flag:
```bash
go build -a -o /tmp/warden-new ./cmd/warden/
```

Without `-a`, Go reuses a stale cached binary silently — no port binding, 502s in production.

## Deploy Steps (when changing warden code)

1. Bump version in `main.go`, `Makefile`, `build-and-deploy.sh`
2. `go build -a -o /tmp/warden-new ./cmd/warden/`
3. `sudo systemctl stop warden && sudo cp /tmp/warden-new /usr/local/bin/warden && sudo systemctl start warden`
4. `sudo cp /tmp/warden-new /opt/dnsfox/binaries/warden-linux-amd64`
5. `echo "X.Y.Z" | sudo tee /opt/dnsfox/binaries/warden-version.txt`
6. Remote servers auto-update within 15s via heartbeat version check

## Key Internals

- Heartbeat: 15s interval, reports to API, returns config + version + B2 creds + cleanup script checksum
- HTTP server: port 9200, handles DB session proxy (Adminer)
- Self-update: downloads new binary from API `/api/agent/binary` when version differs
- Cleanup script auto-sync via SHA-256 checksum comparison

## What NOT To Do

- No `docker run`, `docker exec`, or Docker Compose for customer site provisioning
- No per-site Docker containers of any kind (the v1convert migration is done and deleted)
- Never skip version bump when changing code
- Never use `go build` without `-a`
