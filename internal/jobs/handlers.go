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
