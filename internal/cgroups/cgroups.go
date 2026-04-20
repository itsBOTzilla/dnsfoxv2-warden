package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// cgroupRoot is the cgroup v2 unified hierarchy mount point.
const cgroupRoot = "/sys/fs/cgroup"

// Limits defines resource limits for a site.
type Limits struct {
	CPUPercent int // e.g. 50 = 50% of one core
	RAMMb      int // RAM limit in megabytes
	IOmbps     int // IO limit in MB/s
	PidsMax    int // max number of processes
}

// Manager handles cgroup v2 resource limit management.
type Manager struct{}

// NewManager creates a new cgroup Manager.
func NewManager() *Manager {
	return &Manager{}
}

// cgroupPath returns the cgroup directory path for a site.
func cgroupPath(siteID string) string {
	return filepath.Join(cgroupRoot, "dnsfox", "site_"+siteID)
}

// ApplyLimits creates a cgroup v2 hierarchy for a site and applies resource limits.
func (m *Manager) ApplyLimits(siteID, username string, limits Limits) error {
	path := cgroupPath(siteID)

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("create cgroup dir %s: %w", path, err)
	}

	// CPU limit — quota/period in microseconds.
	// CPUPercent 100 = 1 full core = 100000/100000 quota/period.
	cpuQuota := limits.CPUPercent * 1000
	cpuMax := fmt.Sprintf("%d 100000", cpuQuota)
	if err := writeCgroupFile(path, "cpu.max", cpuMax); err != nil {
		return fmt.Errorf("set cpu.max: %w", err)
	}

	// RAM limit in bytes.
	ramBytes := int64(limits.RAMMb) * 1024 * 1024
	if err := writeCgroupFile(path, "memory.max", strconv.FormatInt(ramBytes, 10)); err != nil {
		return fmt.Errorf("set memory.max: %w", err)
	}

	// Swap limit — same as RAM to prevent swap abuse.
	if err := writeCgroupFile(path, "memory.swap.max", strconv.FormatInt(ramBytes, 10)); err != nil {
		return fmt.Errorf("set memory.swap.max: %w", err)
	}

	// PID limit — prevents fork bombs.
	if err := writeCgroupFile(path, "pids.max", strconv.Itoa(limits.PidsMax)); err != nil {
		return fmt.Errorf("set pids.max: %w", err)
	}

	// IO limit — stored for when block device detection is implemented.
	// io.max format: "MAJ:MIN rbps=N wbps=N riops=max wiops=max"
	_ = int64(limits.IOmbps) * 1024 * 1024

	return nil
}

// RemoveLimits removes the cgroup for a site.
func (m *Manager) RemoveLimits(siteID string) error {
	path := cgroupPath(siteID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cgroup %s: %w", path, err)
	}
	return nil
}

// writeCgroupFile writes a value to a cgroup control file.
func writeCgroupFile(cgroupPath, filename, value string) error {
	path := filepath.Join(cgroupPath, filename)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(value); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
