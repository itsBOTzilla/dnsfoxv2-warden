// nodejs.go — v1 Docker Node.js → v2 cgroup+systemd conversion.
package v1convert

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// skipEnvKeys are container-level vars we never propagate to the v2 .env file.
// PATH/HOME/NODE_* conflict with systemd's process setup.
var skipEnvKeys = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "SHELL": true, "HOSTNAME": true,
	"NODE_VERSION": true, "NODE_PATH": true, "NODE_OPTIONS": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"DNSFOX_PROVISIONING": true,
}

// convertNodejs performs the site-swap. Called from ConvertNodejsSite once
// the Docker container has been inspected and the volume has been backed up.
func convertNodejs(
	ctx context.Context,
	req NodejsRequest,
	info *ContainerInfo,
	appName, mgmtName, backupPath string,
) (*NodejsResult, error) {
	short := shortID(req.SiteID)
	username := provisioning.SiteUsername(req.SiteID)
	siteRoot := fmt.Sprintf("/var/www/%s", username)
	appDir := filepath.Join(siteRoot, "app")
	envPath := filepath.Join(siteRoot, ".env")
	serviceName := fmt.Sprintf("site_%s.service", short)
	serviceUnitPath := filepath.Join("/etc/systemd/system", serviceName)
	sliceName := fmt.Sprintf("dnsfox-site-%s.slice", req.SiteID)

	// Step A: create user + site root + copy volume contents.
	if err := provisioning.CreateSystemUser(username); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	if err := provisioning.AddToGroup(username, "www-data"); err != nil {
		return nil, fmt.Errorf("add www-data group: %w", err)
	}
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir app dir: %w", err)
	}
	if err := rsyncCopy(ctx, info.SourceDir+"/", appDir+"/"); err != nil {
		return nil, fmt.Errorf("rsync volume → %s: %w", appDir, err)
	}
	if _, err := runCmd(ctx, "chown", "-R", username+":"+username, siteRoot); err != nil {
		return nil, fmt.Errorf("chown site root: %w", err)
	}
	if err := os.Chmod(siteRoot, 0o750); err != nil {
		return nil, fmt.Errorf("chmod site root: %w", err)
	}

	// Step B: apply cgroup limits.
	cgMgr := cgroups.NewManager()
	limits, ok := provisioning.PlanLimits[req.Plan]
	if !ok {
		limits = provisioning.PlanLimits["fox"]
	}
	if err := cgMgr.ApplyLimits(req.SiteID, username, limits); err != nil {
		return nil, fmt.Errorf("apply cgroup limits: %w", err)
	}

	// Step C: decide target port.
	port := info.PublishedPort
	if !req.ReusePort {
		var err error
		port, err = allocateFreePort(4000, 5000, port)
		if err != nil {
			return nil, fmt.Errorf("allocate port: %w", err)
		}
	}

	// Step D: write .env file (mirror container env, minus blocked keys).
	startCmd := detectStartCommand(info)
	if err := writeEnvFile(envPath, username, info.Env, port, startCmd); err != nil {
		return nil, fmt.Errorf("write env: %w", err)
	}

	// Step E: write systemd unit.
	if err := writeSystemdUnit(serviceUnitPath, username, appDir, req.SiteID, startCmd); err != nil {
		return nil, fmt.Errorf("write systemd unit: %w", err)
	}
	if _, err := runCmd(ctx, "systemctl", "daemon-reload"); err != nil {
		return nil, fmt.Errorf("daemon-reload: %w", err)
	}

	// Step F: if we are NOT reusing the port, we need a new nginx v2 vhost.
	// When reusing, the existing v1 vhost keeps pointing to the same port.
	var vhostPath string
	if !req.ReusePort {
		ng := nginx.NewManager()
		if err := ng.WriteProxyVhost(nginx.ProxyVhostConfig{
			SiteID: req.SiteID,
			Domain: req.Domain,
			Port:   port,
		}); err != nil {
			return nil, fmt.Errorf("write v2 nginx vhost: %w", err)
		}
		vhostPath = fmt.Sprintf("/etc/nginx/conf.d-v2/dnsfox-%s.conf", req.SiteID)
	}

	// Step G: service swap — stop Docker, start systemd unit, measure downtime.
	swapStart := time.Now()
	if err := stopContainer(ctx, appName); err != nil {
		// Not fatal if already stopped; log and continue.
		log.Printf("[v1convert] warn: stop %s: %v", appName, err)
	}
	// Start the new service.
	if _, err := runCmd(ctx, "systemctl", "enable", "--now", serviceName); err != nil {
		// Rollback: restart Docker, remove systemd unit.
		_ = rollbackNodejs(ctx, serviceName, serviceUnitPath, vhostPath, appName, "")
		return nil, fmt.Errorf("enable+start %s: %w", serviceName, err)
	}
	if !req.ReusePort {
		_ = reloadNginxIfValid(ctx)
	}

	// Step H: health check — try the app's former healthcheck endpoint.
	healthPath := detectHealthPath(info)
	if err := waitForHTTP(ctx, port, healthPath, 30*time.Second); err != nil {
		_ = rollbackNodejs(ctx, serviceName, serviceUnitPath, vhostPath, appName, "")
		return nil, fmt.Errorf("health check port %d%s: %w", port, healthPath, err)
	}
	downtime := time.Since(swapStart).Milliseconds()

	// Step I: stop the management sidecar too (v2 sidecar will be provisioned later).
	_ = stopContainer(ctx, mgmtName)

	return &NodejsResult{
		SiteID:         req.SiteID,
		Username:       username,
		CgroupSlice:    sliceName,
		ServiceUnit:    serviceName,
		Port:           port,
		NginxVhostPath: vhostPath,
		BackupPath:     backupPath,
		DowntimeMs:     downtime,
		CacheDir:       filepath.Join("/var/cache/nginx/v2-sites", req.SiteID),
	}, nil
}

// rollbackNodejs attempts to undo a failed conversion: stop+remove systemd
// unit, remove nginx v2 vhost if we wrote one, restart Docker container.
// Best-effort — logs errors but does not return them, to avoid hiding the
// original failure.
func rollbackNodejs(ctx context.Context, serviceName, unitPath, vhostPath, appName, mgmtName string) error {
	log.Printf("[v1convert] rolling back: service=%s docker=%s", serviceName, appName)
	_, _ = runCmd(ctx, "systemctl", "disable", "--now", serviceName)
	if unitPath != "" {
		_ = os.Remove(unitPath)
	}
	_, _ = runCmd(ctx, "systemctl", "daemon-reload")
	if vhostPath != "" {
		_ = os.Remove(vhostPath)
		_ = reloadNginxIfValid(ctx)
	}
	if appName != "" {
		if err := startContainer(ctx, appName); err != nil {
			log.Printf("[v1convert] rollback: restart docker %s: %v", appName, err)
		}
	}
	if mgmtName != "" {
		_ = startContainer(ctx, mgmtName)
	}
	return nil
}

// writeEnvFile writes systemd EnvironmentFile with sanitized vars + PORT.
func writeEnvFile(path, username string, containerEnv []string, port int, startCmd string) error {
	var b strings.Builder
	b.WriteString("# DNSFox v2 — generated by v1convert\n")
	b.WriteString(fmt.Sprintf("PORT=%d\n", port))
	b.WriteString("NODE_ENV=production\n")
	seen := map[string]bool{"PORT": true, "NODE_ENV": true}
	for _, kv := range containerEnv {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k, v := kv[:idx], kv[idx+1:]
		if skipEnvKeys[k] || seen[k] {
			continue
		}
		if !validEnvKey(k) {
			continue
		}
		// systemd EnvironmentFile does not support shell escaping; quote newlines out.
		v = strings.ReplaceAll(v, "\n", " ")
		b.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		seen[k] = true
	}
	_ = startCmd // start command lives in the unit, not the env file
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	// The env file is read by systemd as root, but we chown to the site user
	// so operators browsing the site root see consistent ownership.
	exec.Command("chown", username+":"+username, path).Run() //nolint:errcheck
	return nil
}

// validEnvKey mirrors POSIX env-name rules (no injection via key).
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha && c != '_' {
			return false
		}
		if !isAlpha && !isDigit && c != '_' {
			return false
		}
	}
	return true
}

// detectStartCommand picks the ExecStart argument for the systemd unit.
//
// Priority:
//  1. Inspect the container's actual PID 1 cmdline — this is the ground truth
//     (the v1 entrypoint does smart detection for Vite/Next.js/etc. and the
//     result is visible in /proc/1/cmdline).
//  2. START_COMMAND env var — what the customer configured.
//  3. Container Cmd field.
//  4. Fallback "npm start".
func detectStartCommand(info *ContainerInfo) string {
	if cmd := detectContainerPID1Cmd(info.Name); cmd != "" {
		return cmd
	}
	for _, kv := range info.Env {
		if strings.HasPrefix(kv, "START_COMMAND=") {
			return strings.TrimPrefix(kv, "START_COMMAND=")
		}
	}
	if len(info.Cmd) > 0 {
		return strings.Join(info.Cmd, " ")
	}
	return "npm start"
}

// detectContainerPID1Cmd returns PID1's resolved command line, normalized so
// a wrapping "sh -c <cmd>" is unwrapped and the inner cmd is used directly.
// Returns "" when detection fails.
func detectContainerPID1Cmd(containerName string) string {
	// `docker exec <c> cat /proc/1/cmdline` returns NUL-separated args.
	out, err := exec.Command("docker", "exec", containerName,
		"sh", "-c", "cat /proc/1/cmdline").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(parts) >= 3 && parts[0] == "sh" && parts[1] == "-c" {
		return parts[2]
	}
	return strings.Join(parts, " ")
}

// detectHealthPath returns a best-effort healthcheck URL path.
// v1 containers use "http://localhost:<port>/" so we mirror that.
func detectHealthPath(info *ContainerInfo) string {
	_ = info
	return "/"
}

const systemdUnit = `# DNSFox v2 — generated by v1convert for {{.SiteID}}
[Unit]
Description=DNSFox v2 Node.js site {{.SiteID}}
After=network.target

[Service]
Type=simple
User={{.Username}}
Group={{.Username}}
WorkingDirectory={{.Dir}}
EnvironmentFile={{.EnvFile}}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=HOME={{.SiteRoot}}
ExecStart=/bin/bash -c '{{.StartCmd}}'
Restart=on-failure
RestartSec=5
Slice=dnsfox-site-{{.SiteID}}.slice

# Filesystem + capability hardening — mirrors v2 provisioner defaults.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={{.Dir}} {{.SiteRoot}}
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
`

type unitTmpl struct {
	SiteID   string
	Username string
	Dir      string
	SiteRoot string
	EnvFile  string
	StartCmd string
}

// writeSystemdUnit renders the template into /etc/systemd/system/site_<short>.service.
func writeSystemdUnit(path, username, dir, siteID, startCmd string) error {
	tmpl, err := template.New("u").Parse(systemdUnit)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, unitTmpl{
		SiteID:   siteID,
		Username: username,
		Dir:      dir,
		SiteRoot: filepath.Dir(dir),
		EnvFile:  filepath.Join(filepath.Dir(dir), ".env"),
		StartCmd: startCmd,
	})
}

// rsyncCopy copies a directory tree with rsync -a (preserves perms/links/times).
func rsyncCopy(ctx context.Context, src, dst string) error {
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	_, err := runCmd(ctx, "rsync", "-aHAX", "--delete", src, dst)
	return err
}

// allocateFreePort returns a free TCP port in [min,max], excluding `exclude`.
func allocateFreePort(min, max, exclude int) (int, error) {
	for p := min; p <= max; p++ {
		if p == exclude {
			continue
		}
		ln, err := netListen(p)
		if err != nil {
			continue
		}
		ln.Close()
		return p, nil
	}
	return 0, fmt.Errorf("no free port in [%d,%d]", min, max)
}

// reloadNginxIfValid runs `nginx -t` and reloads if valid.
func reloadNginxIfValid(ctx context.Context) error {
	if _, err := runCmd(ctx, "nginx", "-t"); err != nil {
		return err
	}
	_, err := runCmd(ctx, "systemctl", "reload", "nginx")
	return err
}

// waitForHTTP polls GET 127.0.0.1:<port><path> until success or timeout.
func waitForHTTP(ctx context.Context, port int, path string, timeout time.Duration) error {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout after %v", timeout)
	}
	return lastErr
}
