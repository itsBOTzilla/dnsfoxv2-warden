// main.go — DNSFox v2 Warden Agent entry point.
//
// The warden runs two concurrent loops:
//  1. gRPC/Connect-Go server — receives provisioning jobs from the API
//  2. Heartbeat loop — pushes system metrics to the API every 15s and
//     receives pending jobs + config-sync directives in the response
//
// Both loops honour context cancellation so SIGTERM shuts everything down
// cleanly. Config is read entirely from environment variables (see
// internal/config/config.go).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/executor"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/heartbeat"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/jobs"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/metrics"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/migration"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/siteusage"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenconnect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// jobStatus tracks the result of a completed job for GetProvisioningStatus queries.
type jobStatus struct {
	status   wardenv1.ProvisioningStatus
	errMsg   string
	finishedAt time.Time
}

// jobTracker stores recent job results in memory for GetProvisioningStatus.
type jobTracker struct {
	mu      sync.RWMutex
	results map[string]*jobStatus
}

func newJobTracker() *jobTracker { return &jobTracker{results: make(map[string]*jobStatus)} }

// record stores a completed job result, evicting entries older than 1 hour.
func (t *jobTracker) record(jobID string, status wardenv1.ProvisioningStatus, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.results[jobID] = &jobStatus{status: status, errMsg: errMsg, finishedAt: now}
	// Evict stale entries to prevent unbounded growth.
	for id, s := range t.results {
		if now.Sub(s.finishedAt) > time.Hour {
			delete(t.results, id)
		}
	}
}

// get returns the stored status for a job, or RUNNING if not yet recorded.
func (t *jobTracker) get(jobID string) (wardenv1.ProvisioningStatus, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if s, ok := t.results[jobID]; ok {
		return s.status, s.errMsg
	}
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_RUNNING, ""
}

// wardenHandler implements the WardenService gRPC interface.
// It embeds UnimplementedWardenServiceHandler for any RPCs not yet wired.
type wardenHandler struct {
	wardenconnect.UnimplementedWardenServiceHandler
	exec    *executor.Executor
	tracker *jobTracker
	cfg     *config.Config
	cpuSampler *metrics.CPUSampler
}

// keep connect referenced to prevent mod tidy from dropping the import.
var _ = connect.CodeUnimplemented

func (h *wardenHandler) ProvisionSite(
	ctx context.Context,
	req *connect.Request[wardenv1.ProvisionSiteRequest],
) (*connect.Response[wardenv1.ProvisionSiteResponse], error) {
	return h.exec.HandleProvisionSite(ctx, req)
}

func (h *wardenHandler) DeprovisionSite(
	ctx context.Context,
	req *connect.Request[wardenv1.DeprovisionSiteRequest],
) (*connect.Response[wardenv1.DeprovisionSiteResponse], error) {
	return h.exec.HandleDeprovisionSite(ctx, req)
}

func (h *wardenHandler) PurgeSiteCache(
	ctx context.Context,
	req *connect.Request[wardenv1.PurgeSiteCacheRequest],
) (*connect.Response[wardenv1.PurgeSiteCacheResponse], error) {
	return h.exec.HandlePurgeSiteCache(ctx, req)
}

func (h *wardenHandler) MigrateSite(
	ctx context.Context,
	req *connect.Request[wardenv1.MigrateSiteRequest],
) (*connect.Response[wardenv1.MigrateSiteResponse], error) {
	return h.exec.HandleMigrateSite(ctx, req)
}

func (h *wardenHandler) GetProvisioningStatus(
	_ context.Context,
	req *connect.Request[wardenv1.GetProvisioningStatusRequest],
) (*connect.Response[wardenv1.GetProvisioningStatusResponse], error) {
	status, errMsg := h.tracker.get(req.Msg.GetJobId())
	return connect.NewResponse(&wardenv1.GetProvisioningStatusResponse{
		Status:       status,
		ErrorMessage: errMsg,
	}), nil
}

func (h *wardenHandler) GetServerStats(
	_ context.Context,
	_ *connect.Request[wardenv1.GetServerStatsRequest],
) (*connect.Response[wardenv1.GetServerStatsResponse], error) {
	hostname, _ := os.Hostname()
	cpuPct, _ := h.cpuSampler.Sample()
	ram, _ := metrics.ReadRAM()
	disk, _ := metrics.ReadDisk("/var/www")
	load, _ := metrics.ReadLoadAvg()
	svcs := metrics.CheckServices()
	siteCount := metrics.CountSites("/var/www")

	beat := &wardenv1.ServerHeartbeat{
		ServerId:      h.cfg.ServerID,
		Hostname:      hostname,
		Status:        wardenv1.ServerStatus_SERVER_STATUS_ONLINE,
		CpuPercent:    cpuPct,
		RamUsedMb:     ram.UsedMB,
		RamTotalMb:    ram.TotalMB,
		DiskUsedGb:    disk.UsedGB,
		DiskTotalGb:   disk.TotalGB,
		LoadAverage:   load,
		Services:      svcs,
		WardenVersion:  "2.0.0",
		SiteCount:     siteCount,
		Timestamp:     timestamppb.Now(),
	}
	return connect.NewResponse(&wardenv1.GetServerStatsResponse{
		Heartbeat: beat,
	}), nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[warden] config error: %v", err)
	}

	log.Printf("[warden] dnsfox v2 warden agent starting")
	log.Printf("[warden]   server_id   : %s", cfg.ServerID)
	log.Printf("[warden]   grpc_port   : %s", cfg.GRPCPort)
	log.Printf("[warden]   environment : %s", cfg.Environment)
	log.Printf("[warden]   mariadb     : %s:%s", cfg.MariaDBHost, cfg.MariaDBPort)
	log.Printf("[warden]   redis       : %s:%s", cfg.RedisHost, cfg.RedisPort)
	log.Printf("[warden]   vhost_dir   : %s", cfg.NginxVhostDir)
	log.Printf("[warden]   docroot     : %s", cfg.DocrootBase)
	log.Printf("[warden]   log_dir     : %s", cfg.LogDir)
	log.Printf("[warden]   sites_domain: %s", cfg.SitesDomain)
	log.Printf("[warden]   api_url     : %s", cfg.APIUrl)

	// Root context cancelled on SIGTERM / SIGINT for graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Build the Connect-Go client used by the heartbeat and job result reporting.
	apiClient := wardenconnect.NewWardenServiceClient(
		&http.Client{},
		cfg.APIUrl,
	)

	// Build executor and job tracker before starting the heartbeat loop.
	exec := executor.New(cfg, apiClient)
	tracker := newJobTracker()

	// Build the heartbeat-job executor for operational jobs (WAF sync, mu-plugin, etc.).
	jobExec := jobs.NewExecutor(cfg)

	// Start heartbeat loop in background.
	reporter := heartbeat.NewReporter(apiClient, cfg, onSync, func(j []*wardenv1.AgentJob) {
		onJobs(j, jobExec, tracker)
	}, jobExec)
	go reporter.Run(ctx)

	// Start per-site resource usage reporting loop in background.
	docrootBase := cfg.DocrootBase
	if docrootBase == "" {
		docrootBase = "/var/www"
	}
	usageReporter := siteusage.NewReporter(apiClient, docrootBase)
	go usageReporter.Run(ctx)

	// Register gRPC/Connect-Go handlers.
	mux := http.NewServeMux()
	mux.Handle(wardenconnect.NewWardenServiceHandler(&wardenHandler{
		exec:       exec,
		tracker:    tracker,
		cfg:        cfg,
		cpuSampler: metrics.NewCPUSampler(),
	}))

	// Register HTTP handler for inbound site migration file uploads.
	mux.Handle("/migration/receive/", migration.ReceiveHandler(cfg.APIToken))

	addr := ":" + cfg.GRPCPort
	log.Printf("[warden] listening on %s (h2c)", addr)

	go func() {
		<-ctx.Done()
		log.Printf("[warden] shutting down")
	}()

	if err := http.ListenAndServe(addr, h2c.NewHandler(mux, &http2.Server{})); err != nil {
		log.Fatalf("[warden] server error: %v", err)
	}
}

// onSync handles a ConfigSyncDirective from the heartbeat response.
func onSync(sync *wardenv1.ConfigSyncDirective) {
	log.Printf("[warden] config sync received (latest_version=%s)", sync.GetLatestWardenVersion())
}

// onJobs dispatches heartbeat-delivered jobs to the job executor.
func onJobs(agentJobs []*wardenv1.AgentJob, exec *jobs.Executor, tracker *jobTracker) {
	for _, j := range agentJobs {
		log.Printf("[warden] heartbeat job: id=%s type=%s", j.GetJobId(), j.GetType())
	}
	exec.ProcessJobs(context.Background(), agentJobs, func(jobID string, status wardenv1.ProvisioningStatus, errMsg string) {
		tracker.record(jobID, status, errMsg)
	})
}
