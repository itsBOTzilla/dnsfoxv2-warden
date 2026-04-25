// Package executor dispatches provisioning jobs to the real provisioner.
// Each job runs in a goroutine so the gRPC call returns immediately with
// RUNNING status; the result is reported back via ReportJobResult.
//
// Site-type routing:
//   - "wordpress" → ProvisionSite() then wordpress.ProvisionWordPress()
//   - "php"       → ProvisionSite() only
//   - "nodejs"    → nodejs.ProvisionNodeJS() (no PHP-FPM, no MariaDB by default)
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/migration"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nodejs"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/wordpress"
)

// Executor wraps the provisioner and dispatches async jobs.
type Executor struct {
	prov    *provisioning.Provisioner
	wpProv  *wordpress.Provisioner
	jsProv  *nodejs.Provisioner
	migrate *migration.Migrator
	cfg     *config.Config
}

// New creates an Executor ready to run jobs.
func New(cfg *config.Config, _ wardenv1connect.WardenServiceClient) *Executor {
	return &Executor{
		prov:    provisioning.NewProvisioner(),
		wpProv:  wordpress.New(cfg),
		jsProv:  nodejs.New(cfg),
		migrate: migration.New(cfg),
		cfg:     cfg,
	}
}

// HandleProvisionSite accepts the gRPC request, fires provisioning in a
// goroutine, and returns RUNNING immediately.
func (e *Executor) HandleProvisionSite(
	ctx context.Context,
	req *connect.Request[wardenv1.ProvisionSiteRequest],
) (*connect.Response[wardenv1.ProvisionSiteResponse], error) {
	r := req.Msg
	log.Printf("[executor] provision_site job=%s site=%s domain=%s type=%s plan=%s php=%s",
		r.GetJobId(), r.GetSiteId(), r.GetDomain(), r.GetType(), r.GetPlan(), r.GetPhpVersion())

	siteCfg := provisioning.SiteConfig{
		SiteID:     r.GetSiteId(),
		Domain:     r.GetDomain(),
		CustomerID: r.GetCustomerId(),
		PHPVersion: r.GetPhpVersion(),
		Plan:       r.GetPlan(),
	}
	go e.runProvision(r.GetJobId(), siteCfg, r.GetType(), r.GetEncryptedCredentials())

	return connect.NewResponse(&wardenv1.ProvisionSiteResponse{
		JobId:  r.GetJobId(),
		Status: wardenv1.ProvisioningStatus_PROVISIONING_STATUS_RUNNING,
	}), nil
}

// HandleDeprovisionSite accepts the gRPC request, fires deprovisioning in a goroutine.
func (e *Executor) HandleDeprovisionSite(
	ctx context.Context,
	req *connect.Request[wardenv1.DeprovisionSiteRequest],
) (*connect.Response[wardenv1.DeprovisionSiteResponse], error) {
	r := req.Msg
	log.Printf("[executor] deprovision_site job=%s site=%s", r.GetJobId(), r.GetSiteId())

	go e.runDeprovision(r.GetJobId(), r.GetSiteId())

	return connect.NewResponse(&wardenv1.DeprovisionSiteResponse{
		JobId:  r.GetJobId(),
		Status: wardenv1.ProvisioningStatus_PROVISIONING_STATUS_RUNNING,
	}), nil
}

// HandleMigrateSite accepts the gRPC request and fires the migration in a goroutine.
func (e *Executor) HandleMigrateSite(
	ctx context.Context,
	req *connect.Request[wardenv1.MigrateSiteRequest],
) (*connect.Response[wardenv1.MigrateSiteResponse], error) {
	r := req.Msg
	log.Printf("[executor] migrate_site job site=%s target=%s", r.GetSiteId(), r.GetTargetServerIp())

	jobID := "migrate-" + r.GetSiteId()
	go func() {
		migCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		err := e.migrate.MigrateSite(migCtx, r)
		e.reportResult(jobID, err, "")
	}()

	return connect.NewResponse(&wardenv1.MigrateSiteResponse{
		JobId:  jobID,
		Status: wardenv1.ProvisioningStatus_PROVISIONING_STATUS_RUNNING,
	}), nil
}

// HandlePurgeSiteCache runs nginx cache purge for a single site path.
func (e *Executor) HandlePurgeSiteCache(
	ctx context.Context,
	req *connect.Request[wardenv1.PurgeSiteCacheRequest],
) (*connect.Response[wardenv1.PurgeSiteCacheResponse], error) {
	r := req.Msg
	log.Printf("[executor] purge_cache site=%s url=%s", r.GetSiteId(), r.GetUrl())

	count, err := e.prov.Nginx.PurgeCache(r.GetSiteId(), r.GetUrl())
	if err != nil {
		log.Printf("[executor] purge_cache failed: %v", err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&wardenv1.PurgeSiteCacheResponse{
		Success:     true,
		FilesPurged: count,
	}), nil
}

// provisionResult is the JSON payload reported back to the API in result_json
// after a successful provisioning job.
type provisionResult struct {
	Subdomain     string `json:"subdomain,omitempty"`
	AdminUser     string `json:"admin_user,omitempty"`
	AdminEmail    string `json:"admin_email,omitempty"`
	AdminPassword string `json:"admin_password,omitempty"`
}

// runProvision runs the full site provisioning chain and reports the result.
// When the site already has a PHP pool at a different version, it performs a
// version switch instead of a full provision. For "nodejs" sites it bypasses
// the PHP-FPM-based ProvisionSite entirely.
func (e *Executor) runProvision(jobID string, cfg provisioning.SiteConfig, siteType string, rawCreds []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if siteType == "nodejs" || siteType == "html" {
		params := parseNodeParams(rawCreds)
		if siteType == "html" {
			// Static sites run /usr/bin/serve inside the cgroup slice.
			// Customer uploads files to public/; serve handles SPA routing.
			params.IsStatic = true
			params.StartCommand = ""
			params.BuildCommand = ""
		}
		detectedFramework, err := e.jsProv.ProvisionNodeJS(ctx, cfg, params)
		resultJSON := ""
		if detectedFramework != "" {
			b, _ := json.Marshal(struct {
				DetectedFramework string `json:"detected_framework"`
			}{DetectedFramework: detectedFramework})
			resultJSON = string(b)
		}
		e.reportResult(jobID, err, resultJSON)
		return
	}

	// PHP / WordPress path: check if site already exists (version switch vs fresh provision).
	currentVersion := detectPHPVersion(cfg.SiteID)
	if currentVersion != "" && currentVersion != cfg.PHPVersion && cfg.PHPVersion != "" {
		// Site exists at a different PHP version — perform in-place switch.
		log.Printf("[executor] php version switch: site=%s %s → %s", cfg.SiteID, currentVersion, cfg.PHPVersion)
		err := e.prov.SwitchPHPVersion(ctx, cfg.SiteID, currentVersion, cfg.PHPVersion)
		e.reportResult(jobID, err, "")
		return
	}

	// Fresh provision.
	provRes, err := e.prov.ProvisionSite(ctx, cfg)
	if err != nil {
		e.reportResult(jobID, err, "")
		return
	}

	res := provisionResult{
		Subdomain: provRes.Subdomain,
	}

	if siteType == "wordpress" {
		params := parseWPParams(rawCreds)
		adminPass, wpErr := e.wpProv.ProvisionWordPress(ctx, cfg, params)
		if wpErr != nil {
			e.reportResult(jobID, wpErr, "")
			return
		}
		res.AdminUser = "admin"
		res.AdminEmail = params.AdminEmail
		res.AdminPassword = adminPass
	}

	// Encode result JSON — ignore marshal error (safe struct, no cycles).
	b, _ := json.Marshal(res)
	// "php" — ProvisionSite() is sufficient; result carries subdomain only.
	e.reportResult(jobID, nil, string(b))
}

// runDeprovision tears down a site and reports the result.
// Node.js sites are identified by the absence of a PHP-FPM pool config.
func (e *Executor) runDeprovision(jobID, siteID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	phpVersion := detectPHPVersion(siteID)
	var err error
	if phpVersion == "" {
		// No PHP pool found — assume Node.js site.
		err = e.jsProv.DeprovisionNodeJS(ctx, siteID)
	} else {
		err = e.prov.DeprovisionSite(ctx, siteID, phpVersion)
	}
	e.reportResult(jobID, err, "")
}

// reportResult sends the final job status back to the v2 API.
// resultJSON is an optional JSON string included in the ReportJobResult payload
// so callers (API) can extract provisioning outputs such as admin password and subdomain.
func (e *Executor) reportResult(jobID string, jobErr error, resultJSON string) {
	status := wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE
	errMsg := ""
	if jobErr != nil {
		status = wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED
		errMsg = jobErr.Error()
		log.Printf("[executor] job=%s FAILED: %v", jobID, jobErr)
	} else {
		log.Printf("[executor] job=%s DONE", jobID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	apiClient := wardenv1connect.NewWardenServiceClient(&http.Client{}, e.cfg.APIUrl)
	req := connect.NewRequest(&wardenv1.ReportJobResultRequest{
		JobId:        jobID,
		Status:       status,
		ErrorMessage: errMsg,
		ResultJson:   resultJSON,
	})
	if token := os.Getenv("WARDEN_AGENT_TOKEN"); token != "" {
		req.Header().Set("X-Warden-Token", token)
	}
	_, err := apiClient.ReportJobResult(ctx, req)
	if err != nil {
		log.Printf("[executor] reportResult job=%s failed: %v", jobID, err)
	}
}

// parseWPParams decodes the encrypted_credentials bytes as a JSON WPParams struct.
// Returns safe defaults when the payload is absent or unparseable.
func parseWPParams(raw []byte) wordpress.WPParams {
	var p wordpress.WPParams
	if len(raw) > 0 {
		json.Unmarshal(raw, &p) //nolint:errcheck — defaults used on decode failure
	}
	return p
}

// parseNodeParams decodes the encrypted_credentials bytes as a JSON NodeParams struct.
// Returns safe defaults when the payload is absent or unparseable.
func parseNodeParams(raw []byte) nodejs.NodeParams {
	var p nodejs.NodeParams
	if len(raw) > 0 {
		json.Unmarshal(raw, &p) //nolint:errcheck — defaults used on decode failure
	}
	return p
}

// detectPHPVersion scans config locations to find which PHP version a site uses.
// Checks the new per-site standalone service unit first, then legacy pool configs.
// Returns empty string when no config is found (indicates a non-PHP / Node.js site).
func detectPHPVersion(siteID string) string {
	// New model: per-site standalone service unit at /etc/systemd/system/dnsfox-phpfpm-{id}.service.
	// The ExecStart line encodes the PHP binary path: /usr/sbin/php-fpmX.Y or /usr/local/phpX.Y/...
	unitPath := fmt.Sprintf("/etc/systemd/system/dnsfox-phpfpm-%s.service", siteID)
	if data, err := os.ReadFile(unitPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "ExecStart=") {
				continue
			}
			// /usr/sbin/php-fpm8.3 → "8.3"
			// /usr/local/php8.3/sbin/php-fpm → "8.3"
			for _, v := range []string{"8.5", "8.4", "8.3", "8.2", "8.1"} {
				if strings.Contains(line, v) {
					return v
				}
			}
		}
		// Service unit exists but version not parseable — treat as PHP (8.3 default).
		return "8.3"
	}

	// Legacy model: global pool config files.
	candidates := []struct {
		version string
		path    string
	}{
		{"8.4", "/etc/php/8.4/fpm/pool.d/dnsfox-" + siteID + ".conf"},
		{"8.5", "/usr/local/php8.5/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.3", "/usr/local/php8.3/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.2", "/usr/local/php8.2/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.1", "/usr/local/php8.1/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
	}
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			return c.version
		}
	}
	return ""
}
