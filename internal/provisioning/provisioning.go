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

// ProvisionResult carries data returned to the API after a successful ProvisionSite call.
type ProvisionResult struct {
	Subdomain string // e.g. "abc12345.sites.dnsfox.com"
}

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
func (p *Provisioner) ProvisionSite(ctx context.Context, cfg SiteConfig) (ProvisionResult, error) {
	log.Printf("provisioning site %s domain %s plan %s", cfg.SiteID, cfg.Domain, cfg.Plan)

	username := siteUsername(cfg.SiteID)
	docroot := fmt.Sprintf("/var/www/%s/public", username)

	// Compute the internal subdomain from the first 8 chars of the site UUID.
	shortID := cfg.SiteID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	subdomain := fmt.Sprintf("%s.sites.dnsfox.com", shortID)

	// Step 1: create Linux system user
	if err := createSystemUser(username); err != nil {
		return ProvisionResult{}, fmt.Errorf("create user: %w", err)
	}
	// nginx worker runs as www-data; add it to the site group so it can read the docroot (mode 750).
	if err := addToGroup(username, "www-data"); err != nil {
		return ProvisionResult{}, fmt.Errorf("add www-data to group: %w", err)
	}
	log.Printf("created user %s", username)

	// Step 2: create document root
	if err := createDocumentRoot(docroot, username); err != nil {
		return ProvisionResult{}, fmt.Errorf("create docroot: %w", err)
	}
	log.Printf("created docroot %s", docroot)

	// Step 3: write per-site standalone PHP-FPM config + systemd service.
	// The service runs inside the site's cgroup slice so all workers it spawns
	// are automatically placed in the correct cgroup — no PID-moving needed.
	pool := phpfpm.PoolConfig{
		SiteID:      cfg.SiteID,
		Username:    username,
		PHPVersion:  cfg.PHPVersion,
		MaxChildren: planMaxChildren(cfg.Plan),
		Ondemand:    planIsSmall(cfg.Plan),
	}
	if err := phpfpm.WriteSiteConfig(pool); err != nil {
		return ProvisionResult{}, fmt.Errorf("write phpfpm site config: %w", err)
	}
	if err := phpfpm.WriteServiceUnit(pool); err != nil {
		return ProvisionResult{}, fmt.Errorf("write phpfpm service unit: %w", err)
	}
	log.Printf("wrote php-fpm site config and service for %s", cfg.SiteID)

	// Step 4: write Nginx vhost config (includes nginx -t validation)
	vhost := nginx.VhostConfig{
		SiteID:       cfg.SiteID,
		Domain:       cfg.Domain,
		Subdomain:    subdomain,
		Username:     username,
		DocumentRoot: docroot,
		PHPVersion:   cfg.PHPVersion,
	}
	if err := p.Nginx.WriteVhost(vhost); err != nil {
		return ProvisionResult{}, fmt.Errorf("write nginx vhost: %w", err)
	}
	log.Printf("wrote nginx vhost for %s (subdomain: %s)", cfg.Domain, subdomain)

	// Step 5: apply cgroup v2 resource limits via systemd slice
	limits, ok := PlanLimits[cfg.Plan]
	if !ok {
		limits = PlanLimits["fox"]
	}
	if err := p.Cgroups.ApplyLimits(cfg.SiteID, username, limits); err != nil {
		return ProvisionResult{}, fmt.Errorf("apply cgroup limits: %w", err)
	}
	log.Printf("applied cgroup limits for %s plan %s", cfg.SiteID, cfg.Plan)

	// Step 6: create MariaDB database and user
	if err := p.MariaDB.CreateSiteDatabase(cfg.SiteID, username); err != nil {
		return ProvisionResult{}, fmt.Errorf("create mariadb database: %w", err)
	}
	log.Printf("created mariadb database for %s", cfg.SiteID)

	// Step 7: start per-site PHP-FPM service (daemon-reload already done by ApplyLimits).
	// Workers spawned by this service inherit the cgroup slice automatically.
	svcName := phpfpm.ServiceUnitName(cfg.SiteID)
	exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck
	if out, err := exec.Command("systemctl", "enable", "--now", svcName).CombinedOutput(); err != nil {
		return ProvisionResult{}, fmt.Errorf("start phpfpm service %s: %s: %w", svcName, out, err)
	}
	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForSocket(socketPath, 20); err != nil {
		return ProvisionResult{}, fmt.Errorf("phpfpm socket not ready: %w", err)
	}
	log.Printf("php-fpm service started, socket ready at %s", socketPath)

	// Step 8: reload Nginx
	if err := reloadNginx(); err != nil {
		return ProvisionResult{}, fmt.Errorf("reload nginx: %w", err)
	}
	log.Printf("started php-fpm service and reloaded nginx")

	log.Printf("provisioning complete for site %s", cfg.SiteID)
	return ProvisionResult{Subdomain: subdomain}, nil
}

// SwitchPHPVersion migrates a site from one PHP version to another without
// touching MariaDB, cgroups, nginx vhost, or the docroot.
// The socket path (/run/php/{username}.sock) is version-agnostic so nginx
// needs no changes — only the PHP-FPM service changes.
//
// Steps:
//  1. Write new standalone php-fpm config + service unit for toVersion
//  2. Stop old per-site service (or global pool if legacy)
//  3. Start new per-site service
//  4. Wait for socket
//  5. Clean up any legacy global pool configs
func (p *Provisioner) SwitchPHPVersion(ctx context.Context, siteID, fromVersion, toVersion string) error {
	log.Printf("[provisioning] switch php %s → %s for site %s", fromVersion, toVersion, siteID)
	username := siteUsername(siteID)

	pool := phpfpm.PoolConfig{
		SiteID:      siteID,
		Username:    username,
		PHPVersion:  toVersion,
		MaxChildren: planMaxChildren("fox"),
		Ondemand:    false,
	}

	// Write new config and service unit for the target version.
	if err := phpfpm.WriteSiteConfig(pool); err != nil {
		return fmt.Errorf("write site config for php%s: %w", toVersion, err)
	}
	if err := phpfpm.WriteServiceUnit(pool); err != nil {
		return fmt.Errorf("write service unit for php%s: %w", toVersion, err)
	}

	// Stop the old per-site service if it exists (it may be named with fromVersion but
	// ServiceUnitName is version-agnostic — same unit file, just with updated ExecStart).
	// Since we overwrote the unit, we just restart it.
	svcName := phpfpm.ServiceUnitName(siteID)
	exec.Command("systemctl", "daemon-reload").Run()                 //nolint:errcheck
	exec.Command("systemctl", "restart", svcName).Run()              //nolint:errcheck

	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForSocket(socketPath, 20); err != nil {
		return fmt.Errorf("socket not ready after switching to php%s: %w", toVersion, err)
	}

	// Clean up any legacy global-pool configs and reload the global master gracefully.
	if oldVersion := phpfpm.DetectPoolVersion(siteID); oldVersion != "" {
		phpfpm.RemovePoolConfig(siteID)                             //nolint:errcheck
		phpfpm.ReloadGlobalMaster(oldVersion)                      //nolint:errcheck
		log.Printf("[provisioning] removed legacy global pool config for site %s", siteID)
	}

	log.Printf("[provisioning] php switch complete: site %s now on php%s", siteID, toVersion)
	return nil
}

// DeprovisionSite removes all resources for a site cleanly.
func (p *Provisioner) DeprovisionSite(ctx context.Context, siteID, phpVersion string) error {
	log.Printf("deprovisioning site %s", siteID)
	username := siteUsername(siteID)

	// Stop and remove per-site PHP-FPM service (new model).
	_ = phpfpm.RemoveServiceUnit(siteID)
	_ = phpfpm.RemoveSiteConfig(siteID)
	// Also clean up any legacy global-pool configs.
	_ = phpfpm.RemovePoolConfig(siteID)
	if phpVersion != "" {
		_ = phpfpm.ReloadGlobalMaster(phpVersion)
	}

	_ = p.Nginx.RemoveVhost(siteID)
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

// planIsSmall returns true for low-traffic plans that should use the ondemand
// PHP-FPM process manager instead of dynamic.
func planIsSmall(plan string) bool {
	return plan == "fox"
}

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

// CreateSystemUser creates a locked system user with no login shell.
func CreateSystemUser(username string) error {
	return createSystemUser(username)
}

// createSystemUser is the unexported implementation.
// Exit code 9 from useradd means "username or GID already in use".  If a
// stale group with the same name exists (e.g. after a failed userdel -r),
// useradd --user-group refuses to create the user — so we first check and
// pass --gid to attach to the existing group.  If the user also already
// exists the call is a no-op.
func createSystemUser(username string) error {
	// If the user already exists we're done.
	if _, err := exec.Command("id", "-u", username).Output(); err == nil {
		return nil
	}

	args := []string{
		"--system",
		"--no-create-home",
		"--shell", "/usr/sbin/nologin",
	}
	// Detect an existing group with the same name and reuse it.
	if _, err := exec.Command("getent", "group", username).Output(); err == nil {
		args = append(args, "--gid", username, "--no-user-group")
	}
	args = append(args, username)

	cmd := exec.Command("useradd", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Recheck: if the user now exists (race), succeed.
		if _, err2 := exec.Command("id", "-u", username).Output(); err2 == nil {
			return nil
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
