// services.go — checks the health of host systemd services for the heartbeat.
// Each service is probed with `systemctl is-active` because it is the canonical
// interface for service health; parsing unit files or PID files would be fragile.
// Services whose unit does not exist on this host are reported as UNKNOWN rather
// than UNHEALTHY so the control plane can distinguish "not installed" from "crashed".
package metrics

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// monitoredServices lists every service the v2 warden cares about.
// PHP-FPM variants are included only when their unit file is present,
// so this list covers the maximal set across all server configurations.
var monitoredServices = []string{
	"nginx",
	"mariadb",
	"redis-6380",
	"clamav-daemon",
	"geodns",
	"warden",
	"warden-v2",
	"php8.1-fpm-dnsfox",
	"php8.2-fpm-dnsfox",
	"php8.3-fpm-dnsfox",
	"php8.4-fpm",
	"php8.5-fpm-dnsfox",
}

// CheckServices returns a ServiceStatus proto for every monitored service.
// Services whose systemd unit file is not present are skipped entirely so
// the heartbeat payload stays small on minimal installs.
func CheckServices() []*wardenv1.ServiceStatus {
	var statuses []*wardenv1.ServiceStatus
	for _, name := range monitoredServices {
		if !unitExists(name) {
			continue
		}
		statuses = append(statuses, probeService(name))
	}
	return statuses
}

// probeService runs `systemctl is-active <name>` and maps the result to
// a ServiceStatus proto, including PID and memory when available.
func probeService(name string) *wardenv1.ServiceStatus {
	out, err := exec.Command("systemctl", "is-active", name).Output()
	state := strings.TrimSpace(string(out))

	health := wardenv1.ServiceHealth_SERVICE_HEALTH_UNHEALTHY
	switch state {
	case "active":
		health = wardenv1.ServiceHealth_SERVICE_HEALTH_HEALTHY
	case "reloading", "activating":
		health = wardenv1.ServiceHealth_SERVICE_HEALTH_RESTARTING
	}
	// err is non-nil when exit code != 0, which includes "inactive" and
	// "failed". We only override to healthy when the state is explicitly "active".
	_ = err

	status := &wardenv1.ServiceStatus{
		Name:   name,
		Health: health,
	}

	// Enrich with PID and memory when the service is healthy.
	if health == wardenv1.ServiceHealth_SERVICE_HEALTH_HEALTHY {
		status.Pid = int32(servicePID(name))
		status.MemoryMb = serviceMemoryMB(name)
	}

	return status
}

// unitExists returns true if the systemd unit file for name exists on disk.
// We look only in /etc/systemd/system/ (where the warden writes its units)
// and /lib/systemd/system/ (where package managers install them).
func unitExists(name string) bool {
	paths := []string{
		fmt.Sprintf("/etc/systemd/system/%s.service", name),
		fmt.Sprintf("/lib/systemd/system/%s.service", name),
		fmt.Sprintf("/usr/lib/systemd/system/%s.service", name),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// servicePID reads the main PID of a service from systemctl show.
// Returns 0 if the service is not running or the PID cannot be read.
func servicePID(name string) int {
	out, err := exec.Command("systemctl", "show", name, "--property=MainPID", "--value").Output()
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return pid
}

// serviceMemoryMB reads current RSS memory for a service via systemctl show.
// Returns 0 on any error. Units from systemd are in bytes.
func serviceMemoryMB(name string) float64 {
	out, err := exec.Command("systemctl", "show", name, "--property=MemoryCurrent", "--value").Output()
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == "[not set]" || s == "18446744073709551615" {
		// 18446744073709551615 = uint64 max = no accounting configured
		return 0
	}
	bytes, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return float64(bytes) / (1024 * 1024)
}
