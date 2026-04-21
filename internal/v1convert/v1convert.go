// Package v1convert converts v1 Docker-based customer sites to v2
// cgroup+systemd-based provisioning without losing the site's data or
// interrupting customer traffic beyond a brief service swap.
//
// A v1 Node.js site looks like:
//   - container `node_<domain>_app`    — serves HTTP on 127.0.0.1:<port>
//   - container `node_<domain>_mgmt`   — file-manager sidecar on 127.0.0.1:<mgmt>
//   - docker volume `<id>_node_<id>_app` mounted at /app inside the container
//   - nginx vhost in /etc/nginx/sites-available/<domain> proxies to the port
//
// A v2 Node.js site looks like:
//   - systemd service `site_<short>.service` running as user `site_<short>`
//   - code at /var/www/site_<short>/app/ (copied from the Docker volume)
//   - cgroup slice `dnsfox-sites.slice/dnsfox-site-<full-id>.slice`
//   - metrics collected by warden-v2 from /sys/fs/cgroup/.../dnsfox-site-<id>.slice/
//
// The convert runs on the Warden host where the Docker container lives.
// Rollback is explicit: any failure after the service swap restarts the
// Docker container and removes the new systemd unit.
package v1convert

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// NodejsRequest describes everything needed to convert a v1 Node.js site.
type NodejsRequest struct {
	// SiteID is the instance UUID (e.g. "ed58d27b-f42f-4390-8a39-5ff3d211cc17").
	SiteID string
	// Domain is the customer domain (e.g. "talkingtn.com"), used to find
	// the Docker containers and nginx vhost.
	Domain string
	// Plan for cgroup resource limits. Defaults to "fox" when empty.
	Plan string
	// ReusePort tells the converter to bind the new systemd service to the
	// same port the Docker container was publishing (recommended when the
	// site already has a v1-style nginx vhost that we must NOT rewrite).
	// When false, the converter allocates a new port and writes a v2 vhost
	// in /etc/nginx/conf.d-v2/.
	ReusePort bool
}

// NodejsResult captures post-conversion state for logging + DB back-write.
type NodejsResult struct {
	SiteID         string
	Username       string
	CgroupSlice    string
	ServiceUnit    string
	Port           int
	NginxVhostPath string
	BackupPath     string
	DowntimeMs     int64
	CacheDir       string
}

// Converter orchestrates v1→v2 conversion. A single instance is safe to
// reuse across calls; all mutating state is per-call.
type Converter struct{}

// New returns a Converter ready for use.
func New() *Converter { return &Converter{} }

// ConvertNodejsSite runs the full v1→v2 Node.js conversion.
// On any failure after Docker has been stopped it calls the rollback.
func (c *Converter) ConvertNodejsSite(ctx context.Context, req NodejsRequest) (*NodejsResult, error) {
	if err := validateNodeReq(req); err != nil {
		return nil, err
	}
	if req.Plan == "" {
		req.Plan = "fox"
	}

	log.Printf("[v1convert] begin node site=%s domain=%s reuse_port=%v", req.SiteID, req.Domain, req.ReusePort)

	// 1. Inspect the v1 container.
	appName := fmt.Sprintf("node_%s_app", dockerNameFromDomain(req.Domain))
	mgmtName := fmt.Sprintf("node_%s_mgmt", dockerNameFromDomain(req.Domain))
	info, err := inspectContainer(ctx, appName)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", appName, err)
	}
	log.Printf("[v1convert] inspected %s port=%d mountsrc=%s", appName, info.PublishedPort, info.SourceDir)

	// 2. Backup the volume to a tarball.
	backupDir := "/var/backups/v1convert"
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir backup dir: %w", err)
	}
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s.tar.gz", req.SiteID, time.Now().UTC().Format("20060102T150405Z")))
	if err := tarballDir(ctx, info.SourceDir, backupPath); err != nil {
		return nil, fmt.Errorf("backup tarball: %w", err)
	}
	log.Printf("[v1convert] backup created %s", backupPath)

	// 3. Convert (caller-specific logic for nodejs).
	res, err := convertNodejs(ctx, req, info, appName, mgmtName, backupPath)
	if err != nil {
		return nil, err
	}
	log.Printf("[v1convert] done site=%s port=%d downtime_ms=%d", res.SiteID, res.Port, res.DowntimeMs)
	return res, nil
}

// validateNodeReq returns an error for required-field or format issues.
func validateNodeReq(r NodejsRequest) error {
	if r.SiteID == "" {
		return fmt.Errorf("site_id required")
	}
	if r.Domain == "" {
		return fmt.Errorf("domain required")
	}
	return nil
}

// dockerNameFromDomain converts "talkingtn.com" → "talkingtn_com" the same way
// the v1 provisioner did, so we can find the right container.
func dockerNameFromDomain(domain string) string {
	out := make([]byte, 0, len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			out = append(out, ch)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// shortID returns the site username-suffix form (15 chars of the UUID, hyphens kept).
func shortID(siteID string) string {
	if len(siteID) > 15 {
		return siteID[:15]
	}
	return siteID
}

// runCmd is a small helper that returns combined output on failure.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return out, nil
}
