package provisioning

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/mariadb"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/phpfpm"
)

// SiteConfig holds everything needed to provision a site.
type SiteConfig struct {
	SiteID     string
	Domain     string
	CustomerID string
	PHPVersion string // e.g. "8.3"
	Plan       string // fox, swift, apex, titan
}

// PlanLimits maps plan names to cgroup resource limits.
var PlanLimits = map[string]cgroups.Limits{
	"fox":   {CPUPercent: 25, RAMMb: 512, IOmbps: 10, PidsMax: 50},
	"swift": {CPUPercent: 50, RAMMb: 1024, IOmbps: 25, PidsMax: 100},
	"apex":  {CPUPercent: 100, RAMMb: 2048, IOmbps: 50, PidsMax: 200},
	"titan": {CPUPercent: 200, RAMMb: 4096, IOmbps: 100, PidsMax: 500},
}

// Provisioner orchestrates site creation and deletion.
type Provisioner struct {
	Cgroups *cgroups.Manager
	MariaDB *mariadb.Manager
	Nginx   *nginx.Manager
}

// NewProvisioner creates a new Provisioner with all dependencies.
func NewProvisioner() *Provisioner {
	return &Provisioner{
		Cgroups: cgroups.NewManager(),
		MariaDB: mariadb.NewManager(),
		Nginx:   nginx.NewManager(),
	}
}

// ProvisionSite creates a fully isolated hosting environment for a site.
// DNS record insertion is handled by the API caller after this returns — the warden
// has no DB access on edge nodes. The API inserts into dns_records for the dnsfox.com zone.
func (p *Provisioner) ProvisionSite(ctx context.Context, cfg SiteConfig) error {
	log.Printf("provisioning site %s domain %s plan %s", cfg.SiteID, cfg.Domain, cfg.Plan)

	username := siteUsername(cfg.SiteID)
	docroot := fmt.Sprintf("/var/www/%s/public", username)

	// Step 1: create Linux system user
	if err := createSystemUser(username); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	// nginx worker runs as www-data; add it to the site group so it can read the docroot (mode 750).
	if err := addToGroup(username, "www-data"); err != nil {
		return fmt.Errorf("add www-data to group: %w", err)
	}
	log.Printf("created user %s", username)

	// Step 2: create document root
	if err := createDocumentRoot(docroot, username); err != nil {
		return fmt.Errorf("create docroot: %w", err)
	}
	log.Printf("created docroot %s", docroot)

	// Step 3: write PHP-FPM pool config
	pool := phpfpm.PoolConfig{
		SiteID:      cfg.SiteID,
		Username:    username,
		PHPVersion:  cfg.PHPVersion,
		MaxChildren: planMaxChildren(cfg.Plan),
	}
	if err := phpfpm.WritePoolConfig(pool); err != nil {
		return fmt.Errorf("write phpfpm pool: %w", err)
	}
	log.Printf("wrote php-fpm pool for %s", cfg.SiteID)

	// Step 4: write Nginx vhost config (includes nginx -t validation)
	vhost := nginx.VhostConfig{
		SiteID:       cfg.SiteID,
		Domain:       cfg.Domain,
		Username:     username,
		DocumentRoot: docroot,
		PHPVersion:   cfg.PHPVersion,
	}
	if err := p.Nginx.WriteVhost(vhost); err != nil {
		return fmt.Errorf("write nginx vhost: %w", err)
	}
	log.Printf("wrote nginx vhost for %s", cfg.Domain)

	// Step 5: apply cgroup v2 resource limits via systemd slice
	limits, ok := PlanLimits[cfg.Plan]
	if !ok {
		limits = PlanLimits["fox"]
	}
	if err := p.Cgroups.ApplyLimits(cfg.SiteID, username, limits); err != nil {
		return fmt.Errorf("apply cgroup limits: %w", err)
	}
	log.Printf("applied cgroup limits for %s plan %s", cfg.SiteID, cfg.Plan)

	// Step 6: create MariaDB database and user
	if err := p.MariaDB.CreateSiteDatabase(cfg.SiteID, username); err != nil {
		return fmt.Errorf("create mariadb database: %w", err)
	}
	log.Printf("created mariadb database for %s", cfg.SiteID)

	// Step 7: reload PHP-FPM
	if err := reloadPHPFPM(cfg.PHPVersion); err != nil {
		return fmt.Errorf("reload phpfpm: %w", err)
	}
	// Wait for the PHP-FPM socket to appear before reloading nginx and assigning cgroups.
	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForSocket(socketPath, 20); err != nil {
		return fmt.Errorf("phpfpm socket not ready: %w", err)
	}
	log.Printf("php-fpm socket ready at %s", socketPath)

	// Step 8: assign PHP-FPM workers to site's cgroup slice
	if err := p.Cgroups.AssignWorkers(cfg.SiteID, username); err != nil {
		// Non-fatal: ondemand pools may have no workers until first request.
		log.Printf("warn: assign cgroup workers for %s: %v", cfg.SiteID, err)
	}

	// Step 9: reload Nginx
	if err := reloadNginx(); err != nil {
		return fmt.Errorf("reload nginx: %w", err)
	}
	log.Printf("reloaded php-fpm and nginx")

	log.Printf("provisioning complete for site %s", cfg.SiteID)
	return nil
}

// SwitchPHPVersion migrates a site from one PHP version to another without
// touching MariaDB, cgroups, nginx vhost, or the docroot.
// The socket path (/run/php/{username}.sock) is version-agnostic so nginx
// needs no changes — only the PHP-FPM pool config changes.
//
// Steps:
//  1. Write pool config for the new version
//  2. Reload new PHP-FPM service (starts managing the pool)
//  3. Wait for the socket to be ready
//  4. Remove pool config from the old version
//  5. Reload old PHP-FPM (stops managing the pool gracefully)
//  6. Re-assign PHP-FPM workers to the cgroup slice
func (p *Provisioner) SwitchPHPVersion(ctx context.Context, siteID, fromVersion, toVersion string) error {
	log.Printf("[provisioning] switch php %s → %s for site %s", fromVersion, toVersion, siteID)
	username := siteUsername(siteID)

	pool := phpfpm.PoolConfig{
		SiteID:     siteID,
		Username:   username,
		PHPVersion: toVersion,
		MaxChildren: planMaxChildren("fox"), // will be re-applied by cgroups; use conservative default
	}
	if err := phpfpm.WritePoolConfig(pool); err != nil {
		return fmt.Errorf("write pool config for %s: %w", toVersion, err)
	}
	if err := reloadPHPFPM(toVersion); err != nil {
		return fmt.Errorf("reload php%s-fpm: %w", toVersion, err)
	}

	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForSocket(socketPath, 20); err != nil {
		return fmt.Errorf("socket not ready after switching to php%s: %w", toVersion, err)
	}

	// Remove old pool config and reload to cleanly stop old FPM workers.
	if err := phpfpm.RemovePoolConfig(siteID); err != nil {
		log.Printf("[provisioning] warn: remove old pool config: %v", err)
	}
	// Re-write the new config (RemovePoolConfig removed all versions).
	if err := phpfpm.WritePoolConfig(pool); err != nil {
		return fmt.Errorf("re-write pool config for %s: %w", toVersion, err)
	}
	reloadPHPFPM(fromVersion) //nolint:errcheck — gracefully stop old workers

	// Re-assign PHP-FPM workers to the cgroup slice.
	if err := p.Cgroups.AssignWorkers(siteID, username); err != nil {
		log.Printf("[provisioning] warn: reassign cgroup workers after php switch: %v", err)
	}

	log.Printf("[provisioning] php switch complete: site %s now on php%s", siteID, toVersion)
	return nil
}

// DeprovisionSite removes all resources for a site cleanly.
func (p *Provisioner) DeprovisionSite(ctx context.Context, siteID, phpVersion string) error {
	log.Printf("deprovisioning site %s", siteID)
	username := siteUsername(siteID)

	_ = phpfpm.RemovePoolConfig(siteID)
	_ = p.Nginx.RemoveVhost(siteID)
	_ = reloadPHPFPM(phpVersion)
	_ = reloadNginx()
	_ = p.Cgroups.RemoveLimits(siteID)
	_ = p.MariaDB.DropSiteDatabase(siteID, username)
	_ = removeSystemUser(username)

	log.Printf("deprovisioning complete for site %s", siteID)
	return nil
}

// SiteUsername converts a site ID to a safe Linux username.
// Caps the ID at 15 chars so the total username stays at 20 chars max.
func SiteUsername(siteID string) string {
	id := siteID
	if len(id) > 15 {
		id = id[:15]
	}
	return "site_" + id
}

// siteUsername is the unexported alias used within this package.
func siteUsername(siteID string) string { return SiteUsername(siteID) }

// planMaxChildren maps plan to PHP-FPM pm.max_children.
func planMaxChildren(plan string) int {
	switch plan {
	case "fox":
		return 5
	case "swift":
		return 10
	case "apex":
		return 20
	case "titan":
		return 40
	default:
		return 5
	}
}

// phpServiceName returns the systemd service name for a given PHP version.
// PHP 8.4 is installed via apt; all others are compiled from source.
func phpServiceName(version string) string {
	if version == "8.4" {
		return "php8.4-fpm"
	}
	return fmt.Sprintf("php%s-fpm-dnsfox", version)
}

// CreateSystemUser creates a locked system user with no login shell.
func CreateSystemUser(username string) error {
	return createSystemUser(username)
}

// createSystemUser is the unexported implementation.
func createSystemUser(username string) error {
	cmd := exec.Command("useradd",
		"--system",
		"--no-create-home",
		"--shell", "/usr/sbin/nologin",
		username,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 9 {
			return nil // user already exists
		}
		return fmt.Errorf("useradd failed: %s: %w", out, err)
	}
	return nil
}

// AddToGroup adds member to the specified supplementary group.
func AddToGroup(group, member string) error { return addToGroup(group, member) }

// addToGroup is the unexported implementation.
func addToGroup(group, member string) error {
	out, err := exec.Command("usermod", "-aG", group, member).CombinedOutput()
	if err != nil {
		return fmt.Errorf("usermod -aG %s %s: %s: %w", group, member, out, err)
	}
	return nil
}

// CreateDocumentRoot creates the site directory tree with correct ownership.
func CreateDocumentRoot(docroot, username string) error { return createDocumentRoot(docroot, username) }

// createDocumentRoot is the unexported implementation.
func createDocumentRoot(docroot, username string) error {
	if err := exec.Command("mkdir", "-p", docroot).Run(); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	siteRoot := fmt.Sprintf("/var/www/%s", username)
	if err := exec.Command("chown", "-R", username+":"+username, siteRoot).Run(); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	if err := exec.Command("chmod", "750", siteRoot).Run(); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

// removeSystemUser deletes the system user.
func removeSystemUser(username string) error {
	return exec.Command("userdel", "-r", username).Run()
}

// reloadPHPFPM sends a reload signal to the PHP-FPM service for a given version.
func reloadPHPFPM(phpVersion string) error {
	return exec.Command("systemctl", "reload", phpServiceName(phpVersion)).Run()
}

// ReloadNginx sends a reload signal to Nginx.
func ReloadNginx() error { return reloadNginx() }

// reloadNginx is the unexported implementation.
func reloadNginx() error {
	return exec.Command("systemctl", "reload", "nginx").Run()
}

// waitForSocket polls for a Unix socket to appear, up to maxAttempts × 250ms.
func waitForSocket(path string, maxAttempts int) error {
	for i := 0; i < maxAttempts; i++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("socket %s not ready after %d attempts (%dms)", path, maxAttempts, maxAttempts*250)
}
