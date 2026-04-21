package phpfpm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

// PoolConfig holds the configuration for a PHP-FPM pool.
type PoolConfig struct {
	SiteID      string
	Username    string
	PHPVersion  string // e.g. "8.3"
	MaxChildren int
}

// poolConfigTemplate is the PHP-FPM pool config template.
// Uses ; comments only — # comments with parentheses break parse_ini_file.
const poolConfigTemplate = `; DNSFox v2 — auto-generated pool for site {{.SiteID}}
; Do not edit manually — managed by Warden

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
php_admin_value[error_log] = /var/log/dnsfox/phpfpm-{{.SiteID}}-error.log
php_admin_flag[log_errors] = on

php_admin_value[open_basedir] = /var/www/{{.Username}}:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen

php_value[session.save_path] = /var/lib/php/sessions/{{.Username}}
`

// poolConfigPath returns the path where the pool config should be written.
// PHP 8.4 is installed via apt and uses the standard distro path.
// All other versions are compiled from source under /usr/local/php{v}/.
func poolConfigPath(siteID, phpVersion string) string {
	if phpVersion == "8.4" {
		return fmt.Sprintf("/etc/php/8.4/fpm/pool.d/dnsfox-%s.conf", siteID)
	}
	return fmt.Sprintf("/usr/local/php%s/etc/php-fpm.d/dnsfox-%s.conf", phpVersion, siteID)
}

// WritePoolConfig writes a PHP-FPM pool config file for a site.
func WritePoolConfig(cfg PoolConfig) error {
	if err := os.MkdirAll("/var/log/dnsfox", 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	sessionDir := fmt.Sprintf("/var/lib/php/sessions/%s", cfg.Username)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	// Session dir must be owned by the site user so PHP-FPM workers can write to it.
	if err := exec.Command("chown", cfg.Username+":"+cfg.Username, sessionDir).Run(); err != nil {
		return fmt.Errorf("chown session dir: %w", err)
	}

	tmpl, err := template.New("pool").Parse(poolConfigTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	path := poolConfigPath(cfg.SiteID, cfg.PHPVersion)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create pool.d dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pool config: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}

// RemovePoolConfig removes the PHP-FPM pool config for a site across all supported versions.
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
