// Package heartbeat sends periodic heartbeats to the v2 control-plane API
// and processes the responses. Each heartbeat carries real system metrics
// (CPU, RAM, disk, load, per-service health, site count) collected from the
// host kernel. The response carries pending jobs and config-sync directives.
//
// Heartbeat interval: 15 seconds, matching v1 behaviour.
// CPU measurement: two-sample delta via /proc/stat. The first heartbeat sends
// CPU=0 because there is no prior sample; all subsequent heartbeats are real.
package heartbeat

import (
	"context"
	"log"
	"os"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/metrics"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

const (
	heartbeatInterval = 15 * time.Second
	wardenVersion     = "2.0.0"
	docrootBase       = "/var/www"
)

// Reporter sends heartbeats to the control plane and dispatches responses.
// Create with NewReporter and call Run to start the loop.
type Reporter struct {
	client     wardenv1connect.WardenServiceClient
	cfg        *config.Config
	cpuSampler *metrics.CPUSampler

	// onSync is called whenever the heartbeat response contains a
	// ConfigSyncDirective (e.g. new WAF rules, cleanup script update).
	onSync func(*wardenv1.ConfigSyncDirective)

	// onJobs is called when the response contains pending jobs for this agent.
	onJobs func([]*wardenv1.AgentJob)
}

// NewReporter constructs a Reporter. The CPUSampler is created here so that
// the baseline sample is taken before the first heartbeat fires, giving a
// meaningful CPU% reading from the second heartbeat onward.
func NewReporter(
	client wardenv1connect.WardenServiceClient,
	cfg *config.Config,
	onSync func(*wardenv1.ConfigSyncDirective),
	onJobs func([]*wardenv1.AgentJob),
) *Reporter {
	return &Reporter{
		client:     client,
		cfg:        cfg,
		cpuSampler: metrics.NewCPUSampler(),
		onSync:     onSync,
		onJobs:     onJobs,
	}
}

// Run starts the heartbeat loop, firing immediately and then every 15 seconds.
// Blocks until ctx is cancelled (e.g. on SIGTERM). Safe to run in a goroutine.
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	log.Printf("[heartbeat] loop started — interval %s", heartbeatInterval)

	// Fire immediately so the server registers in the control plane at startup.
	r.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[heartbeat] loop stopped")
			return
		case <-ticker.C:
			r.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat collects metrics, sends the heartbeat RPC, and dispatches
// any sync directives or jobs from the response. Errors are logged but do
// not stop the loop — transient network failures must not crash the agent.
func (r *Reporter) sendHeartbeat(ctx context.Context) {
	beat := r.collectMetrics()

	req := connect.NewRequest(&wardenv1.ReportHeartbeatRequest{
		Heartbeat: beat,
	})

	log.Printf("[heartbeat] metrics — CPU %.1f%% RAM %.0f/%.0fMB disk %.1f/%.1fGB load %.2f sites %d",
		beat.CpuPercent, beat.RamUsedMb, beat.RamTotalMb,
		beat.DiskUsedGb, beat.DiskTotalGb,
		beat.LoadAverage[0], beat.SiteCount)

	resp, err := r.client.ReportHeartbeat(ctx, req)
	if err != nil {
		log.Printf("[heartbeat] send failed: %v", err)
		return
	}

	if resp.Msg.Sync != nil && r.onSync != nil {
		log.Printf("[heartbeat] received config sync directive")
		r.onSync(resp.Msg.Sync)
	}

	if len(resp.Msg.PendingJobs) > 0 && r.onJobs != nil {
		log.Printf("[heartbeat] received %d pending jobs", len(resp.Msg.PendingJobs))
		r.onJobs(resp.Msg.PendingJobs)
	}
}

// collectMetrics gathers all system metrics and builds a ServerHeartbeat proto.
// Individual metric failures are logged and zeroed — the control plane will see
// 0 for any field that could not be read rather than a crashed heartbeat loop.
func (r *Reporter) collectMetrics() *wardenv1.ServerHeartbeat {
	hostname, _ := os.Hostname()

	// CPU — first call returns 0 (no prior sample); subsequent calls are real.
	cpuPct, err := r.cpuSampler.Sample()
	if err != nil {
		log.Printf("[heartbeat] cpu sample: %v", err)
	}

	// RAM — MemTotal and MemAvailable from /proc/meminfo.
	ram, err := metrics.ReadRAM()
	if err != nil {
		log.Printf("[heartbeat] ram read: %v", err)
	}

	// Disk — report the docroot filesystem where all v2 site data lives.
	disk, err := metrics.ReadDisk(docrootBase)
	if err != nil {
		log.Printf("[heartbeat] disk read: %v", err)
	}

	// Load averages — 1, 5, 15 minute from /proc/loadavg.
	load, err := metrics.ReadLoadAvg()
	if err != nil {
		log.Printf("[heartbeat] loadavg: %v", err)
		load = []float64{0, 0, 0}
	}

	// Per-service health — runs systemctl is-active for each monitored unit.
	services := metrics.CheckServices()

	// Site count — directories named site_* under the docroot base.
	siteCount := metrics.CountSites(docrootBase)

	return &wardenv1.ServerHeartbeat{
		ServerId:      r.cfg.ServerID,
		Hostname:      hostname,
		Status:        wardenv1.ServerStatus_SERVER_STATUS_ONLINE,
		CpuPercent:    cpuPct,
		RamUsedMb:     ram.UsedMB,
		RamTotalMb:    ram.TotalMB,
		DiskUsedGb:    disk.UsedGB,
		DiskTotalGb:   disk.TotalGB,
		LoadAverage:   load,
		Services:      services,
		WardenVersion:  wardenVersion,
		SiteCount:     siteCount,
		Timestamp:     timestamppb.Now(),
	}
}
