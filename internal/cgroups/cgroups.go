package cgroups

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Limits defines resource limits for a site.
type Limits struct {
	CPUPercent int // e.g. 25 = 25% of one core
	RAMMb      int // RAM limit in megabytes
	IOmbps     int // IO limit in MB/s (reserved for io.max when block device detection is added)
	PidsMax    int // max number of processes
}

// Manager handles cgroup v2 resource limit management via systemd slices.
type Manager struct{}

// NewManager creates a new cgroup Manager.
func NewManager() *Manager {
	return &Manager{}
}

// sliceName returns the per-site systemd slice unit name.
func sliceName(siteID string) string {
	return fmt.Sprintf("dnsfox-site-%s.slice", siteID)
}

// EnsureParentSlice creates the dnsfox-sites.slice systemd unit if absent.
// This is the shared parent that groups all customer site slices.
func EnsureParentSlice() error {
	path := "/etc/systemd/system/dnsfox-sites.slice"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	content := "[Unit]\nDescription=DNSFox customer sites resource group\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write dnsfox-sites.slice: %w", err)
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}

// ApplyLimits creates a per-site systemd slice with resource limits.
// Delegate=yes allows us to create a leaf cgroup within the slice for PHP-FPM workers.
func (m *Manager) ApplyLimits(siteID, username string, limits Limits) error {
	if err := EnsureParentSlice(); err != nil {
		return fmt.Errorf("ensure parent slice: %w", err)
	}

	unit := sliceName(siteID)
	unitPath := fmt.Sprintf("/etc/systemd/system/%s", unit)

	content := fmt.Sprintf(`[Unit]
Description=DNSFox site %s resource group

[Slice]
CPUQuota=%d%%
MemoryMax=%dM
TasksMax=%d
Delegate=yes
`, siteID, limits.CPUPercent, limits.RAMMb, limits.PidsMax)

	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write slice unit %s: %w", unit, err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if out, err := exec.Command("systemctl", "start", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("start slice %s: %s: %w", unit, out, err)
	}
	return nil
}

// AssignWorkers moves PHP-FPM pool worker PIDs for a site into its cgroup slice.
// Must be called after PHP-FPM has been reloaded and workers are running.
// Ondemand pools with no active requests will have no workers — that is not an error.
func (m *Manager) AssignWorkers(siteID, username string) error {
	unit := sliceName(siteID)

	out, err := exec.Command("systemctl", "show", unit, "--property=ControlGroup", "--value").Output()
	if err != nil {
		return fmt.Errorf("get cgroup path for %s: %w", unit, err)
	}
	cgRelPath := strings.TrimSpace(string(out))
	if cgRelPath == "" {
		return fmt.Errorf("slice %s has no cgroup path — is it running?", unit)
	}
	sliceCgPath := "/sys/fs/cgroup" + cgRelPath

	// Create a leaf cgroup within the delegated slice for PHP-FPM workers.
	// Cgroupv2 requires processes to live in leaf cgroups, not internal nodes.
	workersPath := filepath.Join(sliceCgPath, "workers")
	if err := os.MkdirAll(workersPath, 0755); err != nil {
		return fmt.Errorf("create workers cgroup in %s: %w", sliceCgPath, err)
	}

	// Enable controllers for the workers leaf.
	_ = os.WriteFile(filepath.Join(sliceCgPath, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0)

	pidsOut, err := exec.Command("pgrep", "-f", "php-fpm: pool "+username).Output()
	if err != nil {
		return nil // no workers yet (ondemand pool at idle) — not an error
	}

	procsFile := filepath.Join(workersPath, "cgroup.procs")
	for _, pid := range strings.Fields(string(pidsOut)) {
		_ = os.WriteFile(procsFile, []byte(pid), 0)
	}
	return nil
}

// RemoveLimits stops and removes the systemd slice for a site.
func (m *Manager) RemoveLimits(siteID string) error {
	unit := sliceName(siteID)
	unitPath := fmt.Sprintf("/etc/systemd/system/%s", unit)

	out, err := exec.Command("systemctl", "stop", unit).CombinedOutput()
	if err != nil {
		s := string(out)
		if !strings.Contains(s, "not loaded") && !strings.Contains(s, "not found") {
			return fmt.Errorf("stop slice %s: %s: %w", unit, s, err)
		}
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove slice unit %s: %w", unitPath, err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}
