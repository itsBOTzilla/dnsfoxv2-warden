package phpfpm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

// PoolConfig holds the configuration for a PHP-FPM site.
type PoolConfig struct {
	SiteID      string
	Username    string
	PHPVersion  string // e.g. "8.3"
	MaxChildren int
}

// siteConfigTemplate is a standalone php-fpm config for a single site.
// Running as a per-site systemd service (not a pool in the global master)
// ensures all workers are automatically placed in the site's cgroup slice.
const siteConfigTemplate = `; DNSFox v2 — standalone PHP-FPM for site {{.SiteID}}
; Managed by Warden — do not edit manually

[global]
pid = /run/php/dnsfox-{{.SiteID}}.pid
error_log = /var/log/dnsfox/phpfpm-{{.SiteID}}-fpm.log
daemonize = no

[{{.Username}}]
user = {{.Username}}
group = {{.Username}}

listen = /run/php/{{.Username}}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = ondemand
pm.max_children = {{.MaxChildren}}
pm.process_idle_timeout = 10s
pm.max_requests = 500

access.log = /var/log/dnsfox/phpfpm-{{.SiteID}}-access.log
php_admin_value[error_log] = /var/log/dnsfox/phpfpm-{{.SiteID}}-php.log
php_admin_flag[log_errors] = on

php_admin_value[open_basedir] = /var/www/{{.Username}}:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen

php_value[session.save_path] = /var/lib/php/sessions/{{.Username}}
`

// serviceUnitTemplate defines the systemd service for a per-site PHP-FPM process.
// Slice= places the master and all workers it spawns inside the site's cgroup slice.
const serviceUnitTemplate = `[Unit]
Description=DNSFox PHP{{.PHPVersion}}-FPM for site {{.SiteID}}
After=network.target

[Service]
Type=notify
ExecStart={{.PHPFPMBin}} --nodaemonize --fpm-config /etc/dnsfox/phpfpm/{{.SiteID}}.conf
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=mixed
Slice=dnsfox-site-{{.SiteID}}.slice
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

type serviceUnitData struct {
	SiteID     string
	PHPVersion string
	PHPFPMBin  string
}

// siteConfigDir is where standalone php-fpm configs are written.
const siteConfigDir = "/etc/dnsfox/phpfpm"

// phpFPMBin returns the path to the php-fpm binary for a given version.
// Checks apt-installed path first (/usr/sbin/php-fpm{v}); falls back to
// compiled-from-source (/usr/local/php{v}/sbin/php-fpm).
func phpFPMBin(phpVersion string) string {
	aptPath := fmt.Sprintf("/usr/sbin/php-fpm%s", phpVersion)
	if _, err := os.Stat(aptPath); err == nil {
		return aptPath
	}
	return fmt.Sprintf("/usr/local/php%s/sbin/php-fpm", phpVersion)
}

// ServiceUnitName returns the systemd service unit filename for a site.
func ServiceUnitName(siteID string) string {
	return fmt.Sprintf("dnsfox-phpfpm-%s.service", siteID)
}

// WriteSiteConfig writes a standalone php-fpm config for a site.
func WriteSiteConfig(cfg PoolConfig) error {
	if err := os.MkdirAll("/var/log/dnsfox", 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	if err := os.MkdirAll(siteConfigDir, 0755); err != nil {
		return fmt.Errorf("create phpfpm config dir: %w", err)
	}

	sessionDir := fmt.Sprintf("/var/lib/php/sessions/%s", cfg.Username)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	if err := exec.Command("chown", cfg.Username+":"+cfg.Username, sessionDir).Run(); err != nil {
		return fmt.Errorf("chown session dir: %w", err)
	}

	tmpl, err := template.New("sitecfg").Parse(siteConfigTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	path := fmt.Sprintf("%s/%s.conf", siteConfigDir, cfg.SiteID)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create site config: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}

// WriteServiceUnit writes a systemd service unit for a per-site php-fpm process.
func WriteServiceUnit(cfg PoolConfig) error {
	tmpl, err := template.New("unit").Parse(serviceUnitTemplate)
	if err != nil {
		return fmt.Errorf("parse unit template: %w", err)
	}

	unitPath := fmt.Sprintf("/etc/systemd/system/%s", ServiceUnitName(cfg.SiteID))
	f, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("write service unit %s: %w", unitPath, err)
	}
	defer f.Close()

	return tmpl.Execute(f, serviceUnitData{
		SiteID:     cfg.SiteID,
		PHPVersion: cfg.PHPVersion,
		PHPFPMBin:  phpFPMBin(cfg.PHPVersion),
	})
}

// RemoveSiteConfig removes the standalone php-fpm config for a site.
func RemoveSiteConfig(siteID string) error {
	path := fmt.Sprintf("%s/%s.conf", siteConfigDir, siteID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove site config: %w", err)
	}
	return nil
}

// RemoveServiceUnit stops, disables, and removes the systemd service for a site.
func RemoveServiceUnit(siteID string) error {
	unit := ServiceUnitName(siteID)
	exec.Command("systemctl", "disable", "--now", unit).Run() //nolint:errcheck
	path := fmt.Sprintf("/etc/systemd/system/%s", unit)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove service unit: %w", err)
	}
	return nil
}

// legacy pool config helpers — kept for SwitchPHPVersion cleanup of old global-pool configs.

// poolConfigPath returns the global php-fpm pool config path for a version.
func poolConfigPath(siteID, phpVersion string) string {
	if phpVersion == "8.4" {
		return fmt.Sprintf("/etc/php/8.4/fpm/pool.d/dnsfox-%s.conf", siteID)
	}
	return fmt.Sprintf("/usr/local/php%s/etc/php-fpm.d/dnsfox-%s.conf", phpVersion, siteID)
}

// RemovePoolConfig removes any legacy global-pool config files for a site.
// Called during migration from the old pool-in-global-master model.
func RemovePoolConfig(siteID string) error {
	versions := []string{"8.1", "8.2", "8.3", "8.4", "8.5"}
	for _, v := range versions {
		path := poolConfigPath(siteID, v)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove pool config %s: %w", path, err)
		}
	}
	return nil
}

// DetectPoolVersion returns the PHP version a site uses via the legacy global pool config,
// or empty string if none found. Used during migration to know which global master to reload.
func DetectPoolVersion(siteID string) string {
	versions := []string{"8.4", "8.5", "8.3", "8.2", "8.1"}
	for _, v := range versions {
		if _, err := os.Stat(poolConfigPath(siteID, v)); err == nil {
			return v
		}
	}
	return ""
}

// GlobalMasterServiceName returns the systemd service name for the global PHP-FPM master.
func GlobalMasterServiceName(phpVersion string) string {
	if phpVersion == "8.4" {
		return "php8.4-fpm"
	}
	return fmt.Sprintf("php%s-fpm-dnsfox", phpVersion)
}

// ReloadGlobalMaster sends a reload to the global php-fpm master for a version.
// Only used during migration cleanup.
func ReloadGlobalMaster(phpVersion string) error {
	svc := GlobalMasterServiceName(phpVersion)
	out, err := exec.Command("systemctl", "reload", svc).CombinedOutput()
	if err != nil {
		s := string(out)
		// If the global master isn't running, that's fine.
		if strings.Contains(s, "not loaded") || strings.Contains(s, "not found") {
			return nil
		}
		return fmt.Errorf("reload %s: %s: %w", svc, s, err)
	}
	return nil
}
