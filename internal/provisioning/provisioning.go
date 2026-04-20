package provisioning

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/mariadb"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/phpfpm"
)

// SiteConfig holds everything needed to provision a site.
type SiteConfig struct {
	SiteID       string
	Domain       string
	CustomerID   string
	PHPVersion   string // e.g. "8.3"
	Plan         string // fox, swift, apex, titan
	DocumentRoot string // e.g. /var/www/site_abc123/public
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
// Steps: user → dirs → phpfpm pool → nginx vhost → cgroups → mariadb → reload
func (p *Provisioner) ProvisionSite(ctx context.Context, cfg SiteConfig) error {
	log.Printf("provisioning site %s domain %s plan %s", cfg.SiteID, cfg.Domain, cfg.Plan)

	username := siteUsername(cfg.SiteID)
	cfg.DocumentRoot = fmt.Sprintf("/var/www/%s/public", username)

	// Step 1: create Linux system user
	if err := createSystemUser(username); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	log.Printf("created user %s", username)

	// Step 2: create document root
	if err := createDocumentRoot(cfg.DocumentRoot, username); err != nil {
		return fmt.Errorf("create docroot: %w", err)
	}
	log.Printf("created docroot %s", cfg.DocumentRoot)

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

	// Step 4: write Nginx vhost config
	vhost := nginx.VhostConfig{
		SiteID:       cfg.SiteID,
		Domain:       cfg.Domain,
		Username:     username,
		DocumentRoot: cfg.DocumentRoot,
		PHPVersion:   cfg.PHPVersion,
	}
	if err := p.Nginx.WriteVhost(vhost); err != nil {
		return fmt.Errorf("write nginx vhost: %w", err)
	}
	log.Printf("wrote nginx vhost for %s", cfg.Domain)

	// Step 5: apply cgroup v2 resource limits
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

	// Step 7: reload PHP-FPM and Nginx
	if err := reloadPHPFPM(cfg.PHPVersion); err != nil {
		return fmt.Errorf("reload phpfpm: %w", err)
	}
	if err := reloadNginx(); err != nil {
		return fmt.Errorf("reload nginx: %w", err)
	}
	log.Printf("reloaded php-fpm and nginx")

	log.Printf("provisioning complete for site %s", cfg.SiteID)
	return nil
}

// DeprovisionSite removes all resources for a site cleanly.
func (p *Provisioner) DeprovisionSite(ctx context.Context, siteID string) error {
	log.Printf("deprovisioning site %s", siteID)
	username := siteUsername(siteID)

	// Order matters: stop processes first, then remove configs, then user
	_ = phpfpm.RemovePoolConfig(siteID)
	_ = p.Nginx.RemoveVhost(siteID)
	_ = reloadPHPFPM("8.3")
	_ = reloadNginx()
	_ = p.Cgroups.RemoveLimits(siteID)
	_ = p.MariaDB.DropSiteDatabase(siteID, username)
	_ = removeSystemUser(username)

	log.Printf("deprovisioning complete for site %s", siteID)
	return nil
}

// siteUsername converts a site ID to a safe Linux username.
// Caps the ID at 15 chars so the total username stays at 20 chars max.
func siteUsername(siteID string) string {
	id := siteID
	if len(id) > 15 {
		id = id[:15]
	}
	return "site_" + id
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

// createSystemUser creates a locked system user with no login shell.
func createSystemUser(username string) error {
	cmd := exec.Command("useradd",
		"--system",
		"--no-create-home",
		"--shell", "/usr/sbin/nologin",
		username,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 9 means user already exists — treat as success
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 9 {
			return nil
		}
		return fmt.Errorf("useradd failed: %s: %w", out, err)
	}
	return nil
}

// createDocumentRoot creates the site directory tree with correct ownership.
func createDocumentRoot(docroot, username string) error {
	// Create parent and public subdirectory
	if err := exec.Command("mkdir", "-p", docroot).Run(); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	// Chown the whole site root (/var/www/<username>) to the site user
	siteRoot := fmt.Sprintf("/var/www/%s", username)
	if err := exec.Command("chown", "-R", username+":"+username, siteRoot).Run(); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	// Owner rwx, group rx, other none
	if err := exec.Command("chmod", "750", docroot).Run(); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

// removeSystemUser deletes the system user and their home directory.
func removeSystemUser(username string) error {
	return exec.Command("userdel", "-r", username).Run()
}

// reloadPHPFPM sends a reload signal to the PHP-FPM service for a given version.
func reloadPHPFPM(phpVersion string) error {
	service := fmt.Sprintf("php%s-fpm", phpVersion)
	return exec.Command("systemctl", "reload", service).Run()
}

// reloadNginx sends a reload signal to Nginx.
func reloadNginx() error {
	return exec.Command("systemctl", "reload", "nginx").Run()
}
