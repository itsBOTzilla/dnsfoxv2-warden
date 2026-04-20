// Package siteusage collects per-site resource usage from cgroup v2 and disk,
// then reports it to the v2 API via the ReportSiteUsage RPC.
//
// Each v2 site runs under a systemd slice named dnsfox-site-{id}.slice.
// Cgroup v2 stats are read directly from /sys/fs/cgroup:
//   - cpu.stat   → usage_usec (cumulative; delta-divided gives %)
//   - memory.current → current RSS in bytes
//
// Disk usage is approximated by reading the size of /var/www/site_{id}/.
// IO throughput (io.stat) is collected but not yet sent (field reserved in proto).
//
// Report interval is 60 seconds, matching v1 behaviour.
package siteusage

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

const (
	reportInterval = 60 * time.Second
	cgroupRoot     = "/sys/fs/cgroup"
)

// prevCPU stores the last sampled cpu.stat usage_usec per site for delta computation.
type prevCPU struct {
	mu      sync.Mutex
	samples map[string]cpuSample
}

type cpuSample struct {
	usageUsec uint64
	at        time.Time
}

// Reporter collects and reports site-level resource usage periodically.
type Reporter struct {
	apiClient   wardenv1connect.WardenServiceClient
	docrootBase string
	prev        prevCPU
}

// NewReporter creates a site usage Reporter.
func NewReporter(apiClient wardenv1connect.WardenServiceClient, docrootBase string) *Reporter {
	return &Reporter{
		apiClient:   apiClient,
		docrootBase: docrootBase,
		prev:        prevCPU{samples: make(map[string]cpuSample)},
	}
}

// Run starts the periodic site usage collection loop. It blocks until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	// Seed the CPU sampler before the first real report.
	r.seedCPUSamples()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.report(ctx)
		}
	}
}

// seedCPUSamples records the current cpu.stat for all sites without reporting.
// This ensures the first real report has a valid delta rather than returning 0%.
func (r *Reporter) seedCPUSamples() {
	entries, err := os.ReadDir(r.docrootBase)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "site_") {
			continue
		}
		siteID := strings.TrimPrefix(e.Name(), "site_")
		usec, _ := readCPUUsec(siteID)
		r.prev.mu.Lock()
		r.prev.samples[siteID] = cpuSample{usageUsec: usec, at: time.Now()}
		r.prev.mu.Unlock()
	}
}

// report collects usage for all sites and sends a single ReportSiteUsage RPC.
func (r *Reporter) report(ctx context.Context) {
	entries, err := os.ReadDir(r.docrootBase)
	if err != nil {
		log.Printf("[siteusage] read docroot: %v", err)
		return
	}

	var usages []*wardenv1.SiteResourceUsage
	now := time.Now()

	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "site_") {
			continue
		}
		siteID := strings.TrimPrefix(e.Name(), "site_")
		usage := r.collectSite(siteID, e.Name(), now)
		usages = append(usages, usage)
	}

	if len(usages) == 0 {
		return
	}

	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err = r.apiClient.ReportSiteUsage(rpcCtx, connect.NewRequest(&wardenv1.ReportSiteUsageRequest{
		Usages: usages,
	}))
	if err != nil {
		log.Printf("[siteusage] report failed: %v", err)
	} else {
		log.Printf("[siteusage] reported usage for %d sites", len(usages))
	}
}

// collectSite gathers cpu%, ram, and disk for one site.
func (r *Reporter) collectSite(siteID, dirName string, now time.Time) *wardenv1.SiteResourceUsage {
	usage := &wardenv1.SiteResourceUsage{
		SiteId:    siteID,
		Timestamp: timestamppb.New(now),
	}

	// CPU% — delta of cpu.stat usage_usec over the elapsed interval.
	currentUsec, err := readCPUUsec(siteID)
	if err == nil {
		r.prev.mu.Lock()
		prev, hasPrev := r.prev.samples[siteID]
		r.prev.samples[siteID] = cpuSample{usageUsec: currentUsec, at: now}
		r.prev.mu.Unlock()

		if hasPrev && currentUsec >= prev.usageUsec {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed > 0 {
				deltaUsec := float64(currentUsec - prev.usageUsec)
				usage.CpuPercent = (deltaUsec / 1e6) / elapsed * 100
			}
		}
	}

	// RAM — memory.current in bytes → MiB.
	ramBytes, err := readMemoryCurrent(siteID)
	if err == nil {
		usage.RamMb = float64(ramBytes) / (1024 * 1024)
	}

	// Disk — du for the site directory.
	siteDir := filepath.Join(r.docrootBase, dirName)
	usage.DiskGb = diskUsageGB(siteDir)

	return usage
}

// readCPUUsec reads the usage_usec field from the site's cgroup cpu.stat.
// Returns 0 and an error if the cgroup or field does not exist.
func readCPUUsec(siteID string) (uint64, error) {
	cgPath := cgroupPathForSite(siteID)
	cpuStatPath := filepath.Join(cgPath, "cpu.stat")

	f, err := os.Open(cpuStatPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "usage_usec ") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				return strconv.ParseUint(parts[1], 10, 64)
			}
		}
	}
	return 0, os.ErrNotExist
}

// readMemoryCurrent reads memory.current for the site's cgroup (bytes).
func readMemoryCurrent(siteID string) (uint64, error) {
	path := filepath.Join(cgroupPathForSite(siteID), "memory.current")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// cgroupPathForSite returns the /sys/fs/cgroup path for a site's systemd slice.
// systemd puts slices at /sys/fs/cgroup/system.slice/dnsfox-site-{id}.slice
// when the parent is dnsfox-sites.slice (which is itself under system.slice).
func cgroupPathForSite(siteID string) string {
	sliceName := "dnsfox-site-" + siteID + ".slice"
	// Preferred path under the parent slice.
	parentedPath := filepath.Join(cgroupRoot, "system.slice", "dnsfox-sites.slice", sliceName)
	if _, err := os.Stat(parentedPath); err == nil {
		return parentedPath
	}
	// Fallback: direct under system.slice.
	return filepath.Join(cgroupRoot, "system.slice", sliceName)
}

// diskUsageGB returns the disk usage of a directory in GB using `du`.
// Returns 0 on error or if du is unavailable.
func diskUsageGB(dir string) float64 {
	out, err := exec.Command("du", "-sb", dir).Output()
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0
	}
	bytes, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return float64(bytes) / (1024 * 1024 * 1024)
}

