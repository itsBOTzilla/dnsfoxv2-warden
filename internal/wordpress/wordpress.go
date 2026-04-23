// Package wordpress provisions WordPress on host PHP-FPM (no Docker).
// It runs AFTER provisioning.ProvisionSite() has already created the site
// user, PHP-FPM pool, nginx vhost, cgroups, and MariaDB database.
//
// Execution order:
//  1. Ensure WP-CLI is present at /usr/local/bin/wp
//  2. Download WordPress core into the docroot
//  3. Parse DB credentials written by the MariaDB provisioner
//  4. Create wp-config.php via WP-CLI and inject Redis + SMTP settings
//  5. Run wp core install (title, admin user, admin email)
//  6. Harden permissions and configure Redis Object Cache plugin
//  7. Deploy the DNSFox mu-plugin from the v2 API
package wordpress

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

const (
	wpCLIPath      = "/usr/local/bin/wp"
	wpCLISourceURL = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
)

// WPParams carries WordPress-specific provisioning parameters.
// All fields except AdminEmail are optional — the provisioner generates
// secure defaults when they are empty.
//
// Two JSON shapes are accepted on the wire:
//   - Canonical v2 shape:  {"admin_email":"…","admin_password":"…"}
//   - Legacy / API shape:  {"wp_admin_email":"…","wp_admin_password":"…",
//                           "wp_site_title":"…"}
// Aliases are exposed via fallback fields filled in on UnmarshalJSON.
type WPParams struct {
	// AdminEmail is the WordPress admin account email. Required.
	AdminEmail string `json:"admin_email"`
	// AdminPassword is the WordPress admin password. Warden generates one if empty.
	AdminPassword string `json:"admin_password"`
	// SiteTitle is the WordPress Site Title. Optional; defaults to the domain.
	SiteTitle string `json:"site_title"`
	// SkipInstall skips wp core install (used in migration mode — files come from backup).
	SkipInstall bool `json:"skip_install"`
}

// UnmarshalJSON accepts both the canonical ("admin_email") and legacy
// ("wp_admin_email") payload shapes, preferring the canonical keys when both
// are present so on-wire v2 payloads never get shadowed by legacy aliases.
func (p *WPParams) UnmarshalJSON(data []byte) error {
	type alias WPParams
	var raw struct {
		alias
		WPAdminEmail    string `json:"wp_admin_email"`
		WPAdminPassword string `json:"wp_admin_password"`
		WPSiteTitle     string `json:"wp_site_title"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = WPParams(raw.alias)
	if p.AdminEmail == "" {
		p.AdminEmail = raw.WPAdminEmail
	}
	if p.AdminPassword == "" {
		p.AdminPassword = raw.WPAdminPassword
	}
	if p.SiteTitle == "" {
		p.SiteTitle = raw.WPSiteTitle
	}
	return nil
}

// Provisioner runs the WordPress-specific install steps after base provisioning.
type Provisioner struct {
	cfg *config.Config
}

// New creates a new WordPress Provisioner.
func New(cfg *config.Config) *Provisioner {
	return &Provisioner{cfg: cfg}
}

// ProvisionWordPress installs WordPress into the site docroot and configures it.
// siteCfg must have SiteID, Domain, PHPVersion, and Plan already set.
// params carries WordPress-specific data; missing optional fields are generated.
//
// This function is idempotent at the WP core level: if wp-config.php already
// exists (e.g. after a failed partial run), WP core install is skipped.
//
// Returns the admin password (generated or supplied) so callers can relay it
// back to the API via result_json.
func (p *Provisioner) ProvisionWordPress(ctx context.Context, siteCfg provisioning.SiteConfig, params WPParams) (adminPass string, err error) {
	// Use the same helper as provisioning.go so the username matches what
	// CreateSystemUser created (15-char cap on the UUID part).
	username := provisioning.SiteUsername(siteCfg.SiteID)
	docroot := fmt.Sprintf("/var/www/%s/public", username)
	credsPath := fmt.Sprintf("/var/www/%s/.db_credentials", username)

	if err := ensureWPCLI(); err != nil {
		return "", fmt.Errorf("wp-cli: %w", err)
	}

	if err := p.downloadCore(docroot); err != nil {
		return "", fmt.Errorf("download wp core: %w", err)
	}

	dbName, dbUser, dbPass, err := parseDBCreds(credsPath)
	if err != nil {
		return "", fmt.Errorf("read db credentials: %w", err)
	}

	adminPass = params.AdminPassword
	if adminPass == "" {
		adminPass = generatePassword()
	}

	if err := p.configureWP(docroot, siteCfg, dbName, dbUser, dbPass); err != nil {
		return "", fmt.Errorf("configure wp-config: %w", err)
	}

	if !params.SkipInstall {
		if err := p.installCore(docroot, siteCfg.Domain, params.AdminEmail, adminPass); err != nil {
			return "", fmt.Errorf("wp core install: %w", err)
		}
		log.Printf("[wordpress] core installed for %s", siteCfg.Domain)

		if err := p.installRedisPlugin(docroot, siteCfg.SiteID); err != nil {
			log.Printf("[wordpress] warn: redis plugin: %v", err)
		}

		if err := DeployMuPlugin(p.cfg, docroot, siteCfg.SiteID); err != nil {
			// Non-fatal: reconcile loop will retry. Log loudly so it's visible.
			log.Printf("[wordpress] ERROR: mu-plugin deploy failed for %s: %v — file manager will not work until reconcile succeeds", siteCfg.Domain, err)
		} else {
			log.Printf("[wordpress] mu-plugin deployed for %s", siteCfg.Domain)
		}
	} else {
		log.Printf("[wordpress] skipping core install (migration mode) for %s", siteCfg.Domain)
	}

	if err := hardenPermissions(docroot, username); err != nil {
		log.Printf("[wordpress] warn: harden permissions: %v", err)
	}

	log.Printf("[wordpress] provisioning complete for %s", siteCfg.Domain)
	return adminPass, nil
}

// ensureWPCLI checks for WP-CLI at /usr/local/bin/wp and downloads it if absent.
func ensureWPCLI() error {
	if _, err := os.Stat(wpCLIPath); err == nil {
		return nil
	}
	log.Printf("[wordpress] WP-CLI not found — downloading from %s", wpCLISourceURL)

	resp, err := http.Get(wpCLISourceURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(wpCLIPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("write %s: %w", wpCLIPath, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	log.Printf("[wordpress] WP-CLI installed at %s", wpCLIPath)
	return nil
}

// downloadCore downloads WordPress core into docroot if index.php is absent.
// Uses WP-CLI to download the latest stable release from wordpress.org.
func (p *Provisioner) downloadCore(docroot string) error {
	if _, err := os.Stat(fmt.Sprintf("%s/index.php", docroot)); err == nil {
		log.Printf("[wordpress] core already present at %s, skipping download", docroot)
		return nil
	}
	out, err := exec.Command(wpCLIPath, "core", "download",
		"--path="+docroot,
		"--locale=en_US",
		"--allow-root",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// parseDBCreds reads the .db_credentials ini file written by the MariaDB provisioner.
// Returns dbName, dbUser, dbPass parsed from the file.
func parseDBCreds(credsPath string) (dbName, dbUser, dbPass string, err error) {
	f, err := os.Open(credsPath)
	if err != nil {
		return "", "", "", fmt.Errorf("open %s: %w", credsPath, err)
	}
	defer f.Close()

	vals := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vals[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	dbName = vals["DB_NAME"]
	dbUser = vals["DB_USER"]
	dbPass = vals["DB_PASS"]
	if dbName == "" || dbUser == "" || dbPass == "" {
		return "", "", "", fmt.Errorf("incomplete credentials in %s", credsPath)
	}
	return dbName, dbUser, dbPass, nil
}

// configureWP creates wp-config.php and injects Redis, SMTP, and HTTPS settings.
// Skips config creation if wp-config.php already exists (idempotent).
func (p *Provisioner) configureWP(docroot string, siteCfg provisioning.SiteConfig, dbName, dbUser, dbPass string) error {
	wpConfig := docroot + "/wp-config.php"

	if _, err := os.Stat(wpConfig); err != nil {
		dbHost := fmt.Sprintf("127.0.0.1:%s", p.cfg.MariaDBPort)
		out, err := exec.Command(wpCLIPath, "config", "create",
			"--path="+docroot,
			"--dbhost="+dbHost,
			"--dbname="+dbName,
			"--dbuser="+dbUser,
			"--dbpass="+dbPass,
			"--skip-check",
			"--allow-root",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("config create: %w: %s", err, out)
		}
	}

	wpSet := func(key, val string, raw bool) {
		args := []string{"config", "set", "--path=" + docroot, key, val, "--allow-root"}
		if raw {
			args = append(args, "--raw")
		}
		exec.Command(wpCLIPath, args...).Run() //nolint:errcheck
	}

	// Redis Object Cache — shared host Redis with per-site key prefix.
	wpSet("WP_REDIS_HOST", p.cfg.RedisHost, false)
	wpSet("WP_REDIS_PORT", p.cfg.RedisPort, false)
	wpSet("WP_REDIS_PREFIX", "site_"+siteCfg.SiteID+":", false)
	if p.cfg.RedisPassword != "" {
		wpSet("WP_REDIS_PASSWORD", p.cfg.RedisPassword, false)
	}

	// SMTP via relay.
	smtpPass := smtpPassword(p.cfg.SMTPRelaySecret, siteCfg.SiteID)
	if smtpPass != "" {
		wpSet("DNSFOX_SMTP_HOST", "relay.dnsfox.com", false)
		wpSet("DNSFOX_SMTP_USER", siteCfg.SiteID+"@relay.dnsfox.com", false)
		wpSet("DNSFOX_SMTP_PASS", smtpPass, false)
		wpSet("DNSFOX_MAIL_FROM", "noreply@"+siteCfg.Domain, false)
	}

	// Instance identity — required by the DNSFox mu-plugin for auth.
	wpSet("DNSFOX_INSTANCE_ID", siteCfg.SiteID, false)

	// SSL and filesystem.
	wpSet("FORCE_SSL_ADMIN", "true", true)
	wpSet("FS_METHOD", "direct", false)

	// Inject HTTP_X_FORWARDED_PROTO detection for any remaining edge cases.
	injectHTTPSDetection(wpConfig)

	// Shuffle security salts from wordpress.org API.
	exec.Command(wpCLIPath, "config", "shuffle-salts", "--path="+docroot, "--allow-root").Run() //nolint:errcheck

	return nil
}

// installCore runs wp core install to create the WordPress database tables and admin user.
// Disables search engine indexing for temporary *.sites.dnsfox.com subdomains.
func (p *Provisioner) installCore(docroot, domain, adminEmail, adminPass string) error {
	args := []string{
		"core", "install",
		"--path=" + docroot,
		"--url=https://" + domain,
		"--title=" + domain,
		"--admin_user=admin",
		"--admin_password=" + adminPass,
		"--admin_email=" + adminEmail,
		"--skip-email",
		"--allow-root",
	}
	out, err := exec.Command(wpCLIPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}

	if strings.HasSuffix(domain, "."+p.cfg.SitesDomain) {
		exec.Command(wpCLIPath, "option", "update", "--path="+docroot, "blog_public", "0", "--allow-root").Run() //nolint:errcheck
	}
	return nil
}

// installRedisPlugin installs and enables the Redis Object Cache plugin via WP-CLI.
func (p *Provisioner) installRedisPlugin(docroot, siteID string) error {
	_ = siteID
	out, err := exec.Command(wpCLIPath, "plugin", "install", "--path="+docroot,
		"redis-cache", "--activate", "--allow-root").CombinedOutput()
	if err != nil {
		return fmt.Errorf("install: %w: %s", err, out)
	}
	exec.Command(wpCLIPath, "redis", "enable", "--path="+docroot, "--allow-root").Run() //nolint:errcheck
	return nil
}

// injectHTTPSDetection inserts a reverse-proxy HTTPS detection snippet after
// the opening <?php tag in wp-config.php. Safe to call multiple times (idempotent).
func injectHTTPSDetection(wpConfig string) {
	data, err := os.ReadFile(wpConfig)
	if err != nil || strings.Contains(string(data), "HTTP_X_FORWARDED_PROTO") {
		return
	}
	snippet := "<?php\n/* HTTPS behind reverse proxy */\n" +
		"if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {\n" +
		"    $_SERVER['HTTPS'] = 'on';\n}\n"
	result := strings.Replace(string(data), "<?php", snippet, 1)
	os.WriteFile(wpConfig, []byte(result), 0440) //nolint:errcheck
}

// hardenPermissions sets secure ownership and modes on the WordPress installation.
// Files: 644, dirs: 755, wp-config.php: 440, uploads: 775.
func hardenPermissions(docroot, username string) error {
	exec.Command("chown", "-R", username+":"+username, docroot).Run()              //nolint:errcheck
	exec.Command("find", docroot, "-type", "d", "-exec", "chmod", "755", "{}", ";").Run() //nolint:errcheck
	exec.Command("find", docroot, "-type", "f", "-exec", "chmod", "644", "{}", ";").Run() //nolint:errcheck

	wpConfig := docroot + "/wp-config.php"
	if _, err := os.Stat(wpConfig); err == nil {
		os.Chmod(wpConfig, 0440) //nolint:errcheck
	}

	uploadsDir := docroot + "/wp-content/uploads"
	if err := os.MkdirAll(uploadsDir, 0775); err == nil {
		exec.Command("chown", "-R", username+":www-data", uploadsDir).Run() //nolint:errcheck
		os.Chmod(uploadsDir, 0775)                                          //nolint:errcheck
	}
	return nil
}

// smtpPassword derives the per-site SMTP relay password using HMAC-SHA256.
// Returns empty string when relaySecret is not configured.
func smtpPassword(relaySecret, siteID string) string {
	if relaySecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(relaySecret))
	mac.Write([]byte(siteID))
	return hex.EncodeToString(mac.Sum(nil)[:20])
}

// generatePassword generates a cryptographically secure 20-character hex password.
func generatePassword() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "WPfallback9!"
	}
	return hex.EncodeToString(b)
}
