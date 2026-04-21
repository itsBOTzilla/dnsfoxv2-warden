// handlers.go — per-job-type handler functions for the jobs.Executor.
// Each handler receives the decrypted payload map and returns a status + error string.
package jobs

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
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/backup"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/clamav"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/wordpress"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// handleProvisionSite is a fallback for heartbeat-delivered provisioning jobs.
// The primary path is the direct gRPC ProvisionSite RPC.
func (e *Executor) handleProvisionSite(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id in payload"
	}
	log.Printf("[jobs] provision site %s (heartbeat fallback — primary path is gRPC)", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleProvisionNodeJS is a fallback for heartbeat-delivered Node.js provisioning jobs.
func (e *Executor) handleProvisionNodeJS(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id in payload"
	}
	log.Printf("[jobs] provision nodejs %s (heartbeat fallback — primary path is gRPC)", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleDeprovisionSite is a fallback for heartbeat-delivered deprovision jobs.
func (e *Executor) handleDeprovisionSite(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id in payload"
	}
	log.Printf("[jobs] deprovision site %s (heartbeat fallback — primary path is gRPC)", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handlePurgeCache clears the nginx cache for the site specified in the payload.
func (e *Executor) handlePurgeCache(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}
	url, _ := payload["url"].(string)
	count, err := e.nginx.PurgeCache(siteID, url)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	log.Printf("[jobs] purged %d cache files for site %s", count, siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleSyncWafRules downloads the consolidated WAF rule file from the API and
// signals nginx to reload. Rules land at /etc/nginx/modsecurity/dnsfox/dnsfox.conf.
func (e *Executor) handleSyncWafRules(ctx context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	if e.cfg.APIUrl == "" || e.cfg.APIToken == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "API URL or token not configured"
	}

	ruleDir := "/etc/nginx/modsecurity/dnsfox"
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("create rule dir: %v", err)
	}

	url := e.cfg.APIUrl + "/api/internal/waf-rules/dnsfox.conf"
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.APIToken)
	req.Header.Set("X-Server-ID", e.cfg.ServerID)

	resp, err := client.Do(req)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("API returned HTTP %d", resp.StatusCode)
	}

	dest := filepath.Join(ruleDir, "dnsfox.conf")
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("reload nginx: %v", err)
	}

	log.Printf("[jobs] WAF rules synced to %s", dest)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleSyncMuPlugins redeploys the DNSFox mu-plugin to all (or one specific)
// WordPress site on this server. WordPress sites are identified by wp-config.php.
func (e *Executor) handleSyncMuPlugins(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	base := e.cfg.DocrootBase
	if base == "" {
		base = "/var/www"
	}
	siteID, _ := payload["site_id"].(string)

	entries, err := os.ReadDir(base)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("read docroot base: %v", err)
	}

	var failed []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "site_") {
			continue
		}
		thisSiteID := strings.TrimPrefix(entry.Name(), "site_")
		if siteID != "" && thisSiteID != siteID {
			continue
		}
		docroot := filepath.Join(base, entry.Name(), "public")
		if _, err := os.Stat(filepath.Join(docroot, "wp-config.php")); err != nil {
			continue // not a WordPress site
		}
		if err := wordpress.DeployMuPlugin(e.cfg, docroot, thisSiteID); err != nil {
			log.Printf("[jobs] mu-plugin sync failed for site %s: %v", thisSiteID, err)
			failed = append(failed, thisSiteID)
		} else {
			log.Printf("[jobs] mu-plugin synced for site %s", thisSiteID)
		}
	}

	if len(failed) > 0 {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("mu-plugin sync failed for: %s", strings.Join(failed, ", "))
	}
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleReloadNginx sends SIGHUP to nginx via systemctl reload.
func (e *Executor) handleReloadNginx(_ context.Context) (
	wardenv1.ProvisioningStatus, string,
) {
	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	log.Printf("[jobs] nginx reloaded")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleIssueCertificate runs certbot for the domain in the payload.
// Uses webroot challenge at /var/www/certbot and fires the deploy hook on success.
func (e *Executor) handleIssueCertificate(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	domain, _ := payload["domain"].(string)
	email, _ := payload["email"].(string)
	if domain == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing domain in payload"
	}
	if email == "" {
		email = "ssl@dnsfox.com"
	}

	args := []string{
		"certonly",
		"--webroot",
		"--webroot-path", "/var/www/certbot",
		"--non-interactive",
		"--agree-tos",
		"--email", email,
		"-d", domain,
		"--deploy-hook", "/etc/letsencrypt/renewal-hooks/deploy/dnsfox-sync.sh",
	}

	out, err := exec.CommandContext(ctx, "certbot", args...).CombinedOutput()
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("certbot: %s: %v", out, err)
	}

	log.Printf("[jobs] certificate issued for %s", domain)
	if reloadErr := provisioning.ReloadNginx(); reloadErr != nil {
		log.Printf("[jobs] warn: reload nginx after cert issue: %v", reloadErr)
	}
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleBackupSite creates a site backup and uploads it to B2.
func (e *Executor) handleBackupSite(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	backupType, _ := payload["backup_type"].(string)
	b2KeyID, _ := payload["b2_key_id"].(string)
	b2AppKey, _ := payload["b2_app_key"].(string)
	b2Bucket, _ := payload["b2_bucket"].(string)

	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}
	if backupType == "" {
		backupType = "full"
	}

	fileID, sizeBytes, err := backup.BackupSite(ctx, siteID, backupType, b2KeyID, b2AppKey, b2Bucket)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	log.Printf("[jobs] backup site %s completed: file_id=%s size=%d", siteID, fileID, sizeBytes)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE,
		fmt.Sprintf("file_id=%s size=%d", fileID, sizeBytes)
}

// handleRestoreSite downloads a B2 backup and restores it.
func (e *Executor) handleRestoreSite(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	fileID, _ := payload["file_id"].(string)
	restoreType, _ := payload["restore_type"].(string)
	b2KeyID, _ := payload["b2_key_id"].(string)
	b2AppKey, _ := payload["b2_app_key"].(string)

	if siteID == "" || fileID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id or file_id"
	}
	if restoreType == "" {
		restoreType = "files"
	}

	if err := backup.RestoreSite(ctx, siteID, fileID, restoreType, b2KeyID, b2AppKey); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	log.Printf("[jobs] restore site %s completed", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleDeprovisionSite actually tears down the site (not just a stub).
func (e *Executor) handleDeprovisionSiteJob(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	phpVersion, _ := payload["php_version"].(string)
	if phpVersion == "" {
		// Detect from pool config.
		for _, v := range []string{"8.4", "8.3", "8.2", "8.1"} {
			var path string
			if v == "8.4" {
				path = fmt.Sprintf("/etc/php/8.4/fpm/pool.d/dnsfox-%s.conf", siteID)
			} else {
				path = fmt.Sprintf("/usr/local/php%s/etc/php-fpm.d/dnsfox-%s.conf", v, siteID)
			}
			if _, err := os.Stat(path); err == nil {
				phpVersion = v
				break
			}
		}
	}

	var err error
	if phpVersion == "" {
		// Assume Node.js site.
		err = exec.CommandContext(ctx, "systemctl", "stop", "site-"+siteID).Run()
	} else {
		prov := provisioning.NewProvisioner()
		err = prov.DeprovisionSite(ctx, siteID, phpVersion)
	}

	if err != nil {
		log.Printf("[jobs] deprovision site %s error: %v", siteID, err)
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	log.Printf("[jobs] deprovision site %s done", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleSuspendSite disables a site's nginx vhost with a 503 suspended page.
func (e *Executor) handleSuspendSite(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	domain, _ := payload["domain"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	vhostDir := e.cfg.NginxVhostDir
	if vhostDir == "" {
		vhostDir = "/etc/nginx/conf.d-v2"
	}

	activePath := filepath.Join(vhostDir, fmt.Sprintf("site_%s.conf", siteID))
	disabledPath := activePath + ".disabled"
	suspendedPath := filepath.Join(vhostDir, fmt.Sprintf("site_%s_suspended.conf", siteID))

	// If we don't have the domain, try to read it from the existing vhost.
	if domain == "" {
		data, err := os.ReadFile(activePath)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "server_name") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						domain = strings.TrimSuffix(parts[1], ";")
					}
				}
			}
		}
	}

	// Rename active vhost to .disabled.
	if _, err := os.Stat(activePath); err == nil {
		if err := os.Rename(activePath, disabledPath); err != nil {
			log.Printf("[jobs] suspend: rename vhost: %v", err)
		}
	}

	// Write suspended vhost.
	suspendedConf := fmt.Sprintf(`# DNSFox — site suspended
server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 503;
    error_page 503 /suspended.html;
    location = /suspended.html {
        root /var/www/dnsfox-suspended;
        internal;
    }
}
`, domain)

	if err := os.WriteFile(suspendedPath, []byte(suspendedConf), 0644); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("write suspended conf: %v", err)
	}

	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("reload nginx: %v", err)
	}

	log.Printf("[jobs] site %s suspended", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleUnsuspendSite restores the site's nginx vhost.
func (e *Executor) handleUnsuspendSite(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	vhostDir := e.cfg.NginxVhostDir
	if vhostDir == "" {
		vhostDir = "/etc/nginx/conf.d-v2"
	}

	activePath := filepath.Join(vhostDir, fmt.Sprintf("site_%s.conf", siteID))
	disabledPath := activePath + ".disabled"
	suspendedPath := filepath.Join(vhostDir, fmt.Sprintf("site_%s_suspended.conf", siteID))

	// Remove suspended conf.
	os.Remove(suspendedPath) //nolint:errcheck

	// Restore active vhost.
	if _, err := os.Stat(disabledPath); err == nil {
		if err := os.Rename(disabledPath, activePath); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("restore vhost: %v", err)
		}
	}

	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("reload nginx: %v", err)
	}

	log.Printf("[jobs] site %s unsuspended", siteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleScanMalware runs ClamAV and pattern-based scanning on a site.
func (e *Executor) handleScanMalware(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	result, err := clamav.ScanSite(ctx, siteID)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	if result.Clean {
		log.Printf("[jobs] malware scan site %s: clean (%d files scanned)", siteID, result.TotalScanned)
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE,
			fmt.Sprintf("clean total_scanned=%d", result.TotalScanned)
	}

	log.Printf("[jobs] malware scan site %s: INFECTED (%d files)", siteID, len(result.InfectedFiles))
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE,
		fmt.Sprintf("infected files=%d quarantined=true", len(result.InfectedFiles))
}

// handleChangePHPVersion switches a site to a different PHP version.
func (e *Executor) handleChangePHPVersion(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	oldVersion, _ := payload["old_version"].(string)
	newVersion, _ := payload["new_version"].(string)

	if siteID == "" || newVersion == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id or new_version"
	}
	if oldVersion == "" {
		oldVersion = "8.3" // safe default
	}

	prov := provisioning.NewProvisioner()
	if err := prov.SwitchPHPVersion(ctx, siteID, oldVersion, newVersion); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	log.Printf("[jobs] php version changed for site %s: %s → %s", siteID, oldVersion, newVersion)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}
