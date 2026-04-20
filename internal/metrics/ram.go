// ram.go — reads physical memory utilization from /proc/meminfo.
// Uses MemAvailable (not MemFree) because MemAvailable accounts for
// reclaimable page cache and is the kernel's own estimate of how much
// memory a new process could actually use. This matches what `free -h`
// reports in its "available" column.
package metrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RAMStats holds memory figures parsed from /proc/meminfo.
type RAMStats struct {
	TotalMB     float64
	UsedMB      float64
	AvailableMB float64
}

// ReadRAM parses /proc/meminfo and returns total, used, and available RAM
// in megabytes. "Used" is defined as Total − Available (kernel convention).
func ReadRAM() (RAMStats, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return RAMStats{}, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer f.Close()

	// We need exactly two values from the file.
	var totalKB, availableKB uint64
	found := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() && found < 2 {
		line := scanner.Text()
		// Format: "MemTotal:        7936592 kB"
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMemLine(line)
			found++
		case strings.HasPrefix(line, "MemAvailable:"):
			availableKB = parseMemLine(line)
			found++
		}
	}
	if err := scanner.Err(); err != nil {
		return RAMStats{}, fmt.Errorf("scan /proc/meminfo: %w", err)
	}
	if found < 2 {
		return RAMStats{}, fmt.Errorf("/proc/meminfo: missing MemTotal or MemAvailable")
	}

	totalMB := float64(totalKB) / 1024
	availMB := float64(availableKB) / 1024
	usedMB := totalMB - availMB

	return RAMStats{
		TotalMB:     totalMB,
		UsedMB:      usedMB,
		AvailableMB: availMB,
	}, nil
}

// parseMemLine extracts the kB integer from a line like "MemTotal:  7936592 kB".
// Returns 0 on any parse error (caller will detect missing data via found counter).
func parseMemLine(line string) uint64 {
	// Fields: ["MemTotal:", "7936592", "kB"]
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}
