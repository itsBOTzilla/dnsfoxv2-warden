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
	"sync/atomic"
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
	for _, siteID := range r.discoverSiteIDs() {
		usec, _ := readCPUUsec(siteID)
		r.prev.mu.Lock()
		r.prev.samples[siteID] = cpuSample{usageUsec: usec, at: time.Now()}
		r.prev.mu.Unlock()
	}
}

// report collects usage for all sites and sends a single ReportSiteUsage RPC.
func (r *Reporter) report(ctx context.Context) {
	siteIDs := r.discoverSiteIDs()
	if len(siteIDs) == 0 {
		return
	}

	var usages []*wardenv1.SiteResourceUsage
	now := time.Now()

	for _, siteID := range siteIDs {
		usage := r.collectSite(siteID, docrootDirFor(r.docrootBase, siteID), now)
		usages = append(usages, usage)
	}

	if len(usages) == 0 {
		return
	}

	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	siteReq := connect.NewRequest(&wardenv1.ReportSiteUsageRequest{
		Usages: usages,
	})
	if token := os.Getenv("WARDEN_AGENT_TOKEN"); token != "" {
		siteReq.Header().Set("X-Warden-Token", token)
	}
	_, err := r.apiClient.ReportSiteUsage(rpcCtx, siteReq)
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

	// Disk — du for the site directory.  The docroot directory name is
	// truncated to 20 characters (provisioning.siteUsername caps at 15 chars
	// after the "site_" prefix) so we cannot reconstruct it from the full
	// UUID — caller passes the actual directory name.
	if dirName != "" {
		siteDir := filepath.Join(r.docrootBase, dirName)
		usage.DiskGb = diskUsageGB(siteDir)
	}

	return usage
}

// discoverSiteIDs enumerates currently-active per-site slices by asking
// systemd.  This is the canonical source of truth for running sites and —
// unlike the docroot directory name — preserves the full site UUID, which is
// required to resolve the cgroup path correctly.
//
// Fallback: if systemctl is unavailable (unit tests, permission denied) we
// scan the docroot, but the returned IDs will be truncated and cgroup lookups
// for long UUIDs will fail.  Operators who see "0% CPU" across every site
// should check warden has permission to run systemctl.
func (r *Reporter) discoverSiteIDs() []string {
	out, err := exec.Command("systemctl", "list-units",
		"--type=slice", "--state=active", "--no-legend", "--plain",
		"dnsfox-site-*.slice").Output()
	if err != nil {
		return r.discoverSiteIDsFallback()
	}
	var ids []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		unit := strings.Fields(scanner.Text())
		if len(unit) == 0 {
			continue
		}
		name := strings.TrimSuffix(unit[0], ".slice")
		id := strings.TrimPrefix(name, "dnsfox-site-")
		if id == "" || id == name || seen[id] {
			continue
		}
		// Skip systemd's auto-generated intermediate slices — a real site
		// slice ID is a 36-char UUID (8-4-4-4-12).
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

// discoverSiteIDsFallback reads truncated IDs from the docroot when systemctl
// is not available.  Kept for resilience; cgroup lookups will still fail for
// full-UUID sites so this is a best-effort degradation only.
func (r *Reporter) discoverSiteIDsFallback() []string {
	entries, err := os.ReadDir(r.docrootBase)
	if err != nil {
		log.Printf("[siteusage] read docroot: %v", err)
		return nil
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "site_") {
			continue
		}
		ids = append(ids, strings.TrimPrefix(e.Name(), "site_"))
	}
	return ids
}

// docrootDirFor returns the on-disk docroot directory for a site ID.  The
// name is the first 15 characters of the ID prefixed with "site_" (matches
// provisioning.SiteUsername).  Returns "" if the directory does not exist so
// the caller can skip disk accounting.
func docrootDirFor(base, siteID string) string {
	short := siteID
	if len(short) > 15 {
		short = short[:15]
	}
	name := "site_" + short
	if _, err := os.Stat(filepath.Join(base, name)); err != nil {
		return ""
	}
	return name
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

// sliceCgroupCache remembers the last resolved cgroup path per site.  systemd
// places a dash-separated slice unit inside a hierarchy of auto-generated
// parent slices (e.g. dnsfox-site-AAAA-BBBB.slice lives at
// /sys/fs/cgroup/dnsfox.slice/dnsfox-site.slice/dnsfox-site-AAAA.slice/
// dnsfox-site-AAAA-BBBB.slice).  Asking `systemctl show ControlGroup` returns
// the correct path but forking systemctl 60 × N_sites is wasteful, so we
// cache the resolved path and only re-resolve on a stat failure.
var sliceCgroupCache sync.Map // siteID → string

// cgroupMissCount counts how many times we fell through to the slow path so
// operators can gauge cache efficacy via the warden log.
var cgroupMissCount atomic.Uint64

// cgroupPathForSite returns the /sys/fs/cgroup path for a site's systemd
// slice.  Resolution order:
//
//  1. Cached path from a previous lookup (fast path).
//  2. `systemctl show <unit> --property=ControlGroup --value` — the
//     authoritative answer; works regardless of where systemd chose to nest
//     the slice.
//  3. A handful of hard-coded fallbacks matching historical layouts so we
//     keep working even if systemctl is unavailable (should never happen on
//     a properly-provisioned host).
//
// If none of those exist the collector will still try to open cpu.stat at the
// returned path and fail gracefully; the RPC will simply report 0% CPU for
// that site this interval.
func cgroupPathForSite(siteID string) string {
	sliceName := "dnsfox-site-" + siteID + ".slice"

	// Cache hit: confirm the directory still exists to avoid reporting on a
	// stale path after a slice restart.
	if v, ok := sliceCgroupCache.Load(siteID); ok {
		if p, ok := v.(string); ok {
			if _, err := os.Stat(p); err == nil {
				return p
			}
			sliceCgroupCache.Delete(siteID)
		}
	}

	cgroupMissCount.Add(1)

	// Authoritative: ask systemd.
	if path, ok := resolveFromSystemctl(sliceName); ok {
		sliceCgroupCache.Store(siteID, path)
		return path
	}

	// Fallbacks — try each in priority order.  First match wins.
	candidates := []string{
		// Current convention: top-level dnsfox-sites.slice with Delegate=yes.
		filepath.Join(cgroupRoot, "dnsfox-sites.slice", sliceName),
		// Durin layout: dnsfox.slice/dnsfox-site.slice/... (systemd
		// auto-nesting of dash-separated names).
		filepath.Join(cgroupRoot, "dnsfox.slice", "dnsfox-site.slice", sliceName),
		// Legacy layouts.
		filepath.Join(cgroupRoot, "system.slice", "dnsfox-sites.slice", sliceName),
		filepath.Join(cgroupRoot, "system.slice", sliceName),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			sliceCgroupCache.Store(siteID, p)
			return p
		}
	}
	// Nothing found — return the preferred path so the caller produces a
	// useful error message.
	return candidates[0]
}

// resolveFromSystemctl asks systemd where a slice's cgroup lives.
// Returns "", false when systemctl fails or reports an empty ControlGroup
// (which happens when the slice is defined but not yet started).
func resolveFromSystemctl(sliceName string) (string, bool) {
	out, err := exec.Command("systemctl", "show", sliceName,
		"--property=ControlGroup", "--value").Output()
	if err != nil {
		return "", false
	}
	rel := strings.TrimSpace(string(out))
	if rel == "" {
		return "", false
	}
	full := filepath.Join(cgroupRoot, rel)
	if _, err := os.Stat(full); err != nil {
		return "", false
	}
	return full, true
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

