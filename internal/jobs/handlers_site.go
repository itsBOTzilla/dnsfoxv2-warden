// handlers_site.go — per-site job handlers (backup, restore, suspend, scan, etc.).
// Split from handlers.go to keep files under 300 lines.
package jobs

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/backup"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/clamav"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/credsstore"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// handleBackupSite creates a site backup and uploads it to B2.
// B2 credentials are read from the job payload; if absent, fall back to credsstore.
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

	// Fall back to in-memory credsstore if payload didn't carry B2 creds.
	if b2KeyID == "" || b2AppKey == "" {
		cached := credsstore.GetB2()
		if b2KeyID == "" {
			b2KeyID = cached.KeyID
		}
		if b2AppKey == "" {
			b2AppKey = cached.AppKey
		}
		if b2Bucket == "" {
			b2Bucket = cached.BucketName
		}
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

