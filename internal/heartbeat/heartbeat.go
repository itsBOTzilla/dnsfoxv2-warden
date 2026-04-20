package heartbeat

import (
	"context"
	"log"
	"os"
	"time"

	"connectrpc.com/connect"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const heartbeatInterval = 15 * time.Second

// Reporter sends heartbeats to the control plane and processes responses.
type Reporter struct {
	client   wardenv1connect.WardenServiceClient
	serverID string
	version  string
	onSync   func(*wardenv1.ConfigSyncDirective)
	onJobs   func([]*wardenv1.AgentJob)
}

// NewReporter creates a heartbeat reporter.
func NewReporter(
	client wardenv1connect.WardenServiceClient,
	serverID string,
	version string,
	onSync func(*wardenv1.ConfigSyncDirective),
	onJobs func([]*wardenv1.AgentJob),
) *Reporter {
	return &Reporter{
		client:   client,
		serverID: serverID,
		version:  version,
		onSync:   onSync,
		onJobs:   onJobs,
	}
}

// Run starts the heartbeat loop and blocks until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	log.Printf("heartbeat: starting loop every %s", heartbeatInterval)

	// Fire immediately, then on every tick.
	r.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("heartbeat: loop stopped")
			return
		case <-ticker.C:
			r.sendHeartbeat(ctx)
		}
	}
}

func (r *Reporter) sendHeartbeat(ctx context.Context) {
	beat := r.collectMetrics()

	req := connect.NewRequest(&wardenv1.ReportHeartbeatRequest{
		Heartbeat: beat,
	})

	resp, err := r.client.ReportHeartbeat(ctx, req)
	if err != nil {
		log.Printf("heartbeat: send failed: %v", err)
		return
	}

	log.Printf("heartbeat: sent — CPU %.1f%% RAM %.0f/%.0fMB",
		beat.CpuPercent, beat.RamUsedMb, beat.RamTotalMb)

	if resp.Msg.Sync != nil && r.onSync != nil {
		r.onSync(resp.Msg.Sync)
	}

	if len(resp.Msg.PendingJobs) > 0 && r.onJobs != nil {
		log.Printf("heartbeat: received %d pending jobs", len(resp.Msg.PendingJobs))
		r.onJobs(resp.Msg.PendingJobs)
	}
}

func (r *Reporter) collectMetrics() *wardenv1.ServerHeartbeat {
	hostname, _ := os.Hostname()

	return &wardenv1.ServerHeartbeat{
		ServerId:      r.serverID,
		Hostname:      hostname,
		Status:        wardenv1.ServerStatus_SERVER_STATUS_ONLINE,
		CpuPercent:    getCPUPercent(),
		RamUsedMb:     getRAMUsedMB(),
		RamTotalMb:    getRAMTotalMB(),
		DiskUsedGb:    getDiskUsedGB(),
		DiskTotalGb:   getDiskTotalGB(),
		LoadAverage:   getLoadAverage(),
		Services:      getServiceStatuses(),
		WardenVersion: r.version,
		Timestamp:     timestamppb.Now(),
	}
}

// getCPUPercent reads CPU usage. TODO: two-sample delta from /proc/stat.
func getCPUPercent() float64 { return 0.0 }

// getRAMUsedMB reads used RAM. TODO: parse /proc/meminfo MemTotal - MemAvailable.
func getRAMUsedMB() float64 { return 0.0 }

// getRAMTotalMB reads total RAM. TODO: parse /proc/meminfo MemTotal.
func getRAMTotalMB() float64 { return 0.0 }

// getDiskUsedGB reads disk usage. TODO: syscall.Statfs("/").
func getDiskUsedGB() float64 { return 0.0 }

// getDiskTotalGB reads total disk. TODO: syscall.Statfs("/").
func getDiskTotalGB() float64 { return 0.0 }

// getLoadAverage reads load averages. TODO: parse /proc/loadavg.
func getLoadAverage() []float64 { return []float64{0.0, 0.0, 0.0} }

// getServiceStatuses checks systemd service health. TODO: systemctl is-active per service.
func getServiceStatuses() []*wardenv1.ServiceStatus {
	services := []string{"nginx", "php8.3-fpm", "mariadb", "redis-server", "clamav-daemon"}
	statuses := make([]*wardenv1.ServiceStatus, 0, len(services))
	for _, name := range services {
		statuses = append(statuses, &wardenv1.ServiceStatus{
			Name:   name,
			Health: wardenv1.ServiceHealth_SERVICE_HEALTH_HEALTHY,
		})
	}
	return statuses
}
