// load.go — reads system load averages from /proc/loadavg.
// The kernel exports 1-minute, 5-minute, and 15-minute exponential moving
// averages of the run-queue length. This is what `uptime` and `top` display.
package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadLoadAvg parses /proc/loadavg and returns the three standard load averages
// as a slice: [1min, 5min, 15min]. Values are dimensionless run-queue lengths.
// A value of 1.0 means one process is always runnable on a single-core system;
// on a 4-core system, values under 4.0 indicate light load.
func ReadLoadAvg() ([]float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, fmt.Errorf("read /proc/loadavg: %w", err)
	}

	// Format: "1.47 1.37 1.52 1/1197 486186"
	// First three fields are the load averages.
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("/proc/loadavg: expected at least 3 fields, got %d", len(fields))
	}

	avgs := make([]float64, 3)
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil, fmt.Errorf("/proc/loadavg field %d %q: %w", i, fields[i], err)
		}
		avgs[i] = v
	}
	return avgs, nil
}
