package jobs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// handleCreateEdgeVhost creates a CDN edge nginx vhost for a domain, fetching
// the SSL cert from the API if it isn't already installed locally.
//
// Payload fields:
//   domain     string — customer domain (e.g. "example.com")
//   origin_ip  string — IP of the origin server hosting the site
//   site_id    string — instance UUID (used for log paths)
//   has_www    bool   — whether to also serve www.{domain}
func (e *Executor) handleCreateEdgeVhost(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	domain, _ := payload["domain"].(string)
	originIP, _ := payload["origin_ip"].(string)
	siteID, _ := payload["site_id"].(string)
	hasWWW, _ := payload["has_www"].(bool)

	if domain == "" || originIP == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing domain or origin_ip"
	}

	// Ensure SSL cert is installed at /etc/ssl/dnsfox/{domain}/.
	certDir := "/etc/ssl/dnsfox/" + domain
	if _, err := os.Stat(certDir + "/fullchain.pem"); err != nil {
		log.Printf("[edge] cert not found for %s — fetching from API", domain)
		if err := fetchAndInstallCert(ctx, e.cfg.APIUrl, e.cfg.APIToken, domain, certDir); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("install cert for %s: %v", domain, err)
		}
	}

	mgr := nginx.NewManager()
	if err := mgr.WriteEdgeVhost(nginx.EdgeVhostConfig{
		SiteID:   siteID,
		Domain:   domain,
		OriginIP: originIP,
		HasWWW:   hasWWW,
	}); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("nginx reload: %v", err)
	}

	log.Printf("[edge] created edge vhost for %s → %s", domain, originIP)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE,
		fmt.Sprintf("edge vhost created: %s → %s", domain, originIP)
}

// handleDeleteEdgeVhost removes the CDN edge nginx vhost for a domain.
func (e *Executor) handleDeleteEdgeVhost(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	domain, _ := payload["domain"].(string)
	if domain == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing domain"
	}

	mgr := nginx.NewManager()
	if err := mgr.RemoveEdgeVhost(domain); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}

	if err := provisioning.ReloadNginx(); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("nginx reload: %v", err)
	}

	log.Printf("[edge] deleted edge vhost for %s", domain)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, "edge vhost deleted: " + domain
}

// fetchAndInstallCert calls GET /api/agent/ssl-cert/{domain} on the API,
// decodes the returned PEM files, and writes them to certDir.
func fetchAndInstallCert(ctx context.Context, apiURL, apiToken, domain, certDir string) error {
	httpClient := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiURL+"/api/agent/ssl-cert/"+domain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Warden-Token", os.Getenv("WARDEN_AGENT_TOKEN"))

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Fullchain string `json:"fullchain"`
		Privkey   string `json:"privkey"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode cert response: %w", err)
	}
	if result.Fullchain == "" || result.Privkey == "" {
		return fmt.Errorf("empty cert data from API")
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", certDir, err)
	}
	if err := os.WriteFile(certDir+"/fullchain.pem", []byte(result.Fullchain), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(certDir+"/privkey.pem", []byte(result.Privkey), 0600); err != nil {
		return err
	}
	log.Printf("[edge] installed cert for %s", domain)
	return nil
}
