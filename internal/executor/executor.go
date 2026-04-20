// Package executor dispatches provisioning jobs to the real provisioner.
// Each job runs in a goroutine so the gRPC call returns immediately with
// RUNNING status; the result is reported back via ReportJobResult.
package executor

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// Executor wraps the provisioner and dispatches async jobs.
type Executor struct {
	prov      *provisioning.Provisioner
	apiClient wardenv1connect.WardenServiceClient
	cfg       *config.Config
}

// New creates an Executor ready to run jobs.
func New(cfg *config.Config, apiClient wardenv1connect.WardenServiceClient) *Executor {
	return &Executor{
		prov:      provisioning.NewProvisioner(),
		apiClient: apiClient,
		cfg:       cfg,
	}
}

// HandleProvisionSite accepts the gRPC request, fires provisioning in a
// goroutine, and returns RUNNING immediately. The goroutine reports the
// final result back to the API via ReportJobResult.
func (e *Executor) HandleProvisionSite(
	ctx context.Context,
	req *connect.Request[wardenv1.ProvisionSiteRequest],
) (*connect.Response[wardenv1.ProvisionSiteResponse], error) {
	r := req.Msg
	log.Printf("[executor] provision_site job=%s site=%s domain=%s plan=%s php=%s",
		r.GetJobId(), r.GetSiteId(), r.GetDomain(), r.GetPlan(), r.GetPhpVersion())

	go e.runProvision(r.GetJobId(), provisioning.SiteConfig{
		SiteID:     r.GetSiteId(),
		Domain:     r.GetDomain(),
		CustomerID: r.GetCustomerId(),
		PHPVersion: r.GetPhpVersion(),
		Plan:       r.GetPlan(),
	})

	return connect.NewResponse(&wardenv1.ProvisionSiteResponse{
		JobId:  r.GetJobId(),
		Status: wardenv1.ProvisioningStatus_PROVISIONING_STATUS_RUNNING,
	}), nil
}

// HandleDeprovisionSite accepts the gRPC request, fires deprovisioning in a
// goroutine, and returns RUNNING immediately.
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

// runProvision runs the full site provisioning and reports the result.
func (e *Executor) runProvision(jobID string, cfg provisioning.SiteConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	err := e.prov.ProvisionSite(ctx, cfg)
	e.reportResult(jobID, err)
}

// runDeprovision tears down a site and reports the result.
func (e *Executor) runDeprovision(jobID, siteID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// PHPVersion is not tracked by the gRPC call — derive from installed pool files.
	phpVersion := detectPHPVersion(siteID)
	err := e.prov.DeprovisionSite(ctx, siteID, phpVersion)
	e.reportResult(jobID, err)
}

// reportResult sends the final job status back to the v2 API.
// Failures are logged but do not panic — the agent must keep running.
func (e *Executor) reportResult(jobID string, jobErr error) {
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
	_, err := apiClient.ReportJobResult(ctx, connect.NewRequest(&wardenv1.ReportJobResultRequest{
		JobId:        jobID,
		Status:       status,
		ErrorMessage: errMsg,
	}))
	if err != nil {
		log.Printf("[executor] reportResult job=%s failed: %v", jobID, err)
	}
}

// detectPHPVersion scans pool config locations to find which PHP version a site uses.
// Returns "8.3" as a safe default when nothing is found.
func detectPHPVersion(siteID string) string {
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
	return "8.3"
}
