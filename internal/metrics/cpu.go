// Package metrics reads system resource utilization from /proc and cgroup v2.
// All reads are non-blocking and safe to call concurrently. The CPU sampler
// is stateful — it computes a delta between consecutive calls, so the first
// call always returns 0 (no prior sample to compare against).
package metrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// cpuStat holds the raw CPU time counters from one /proc/stat sample.
// Fields match the kernel's cpu line order:
// user nice system idle iowait irq softirq steal guest guest_nice
type cpuStat struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

// total returns total elapsed CPU jiffies in this snapshot.
func (s cpuStat) total() uint64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq + s.steal
}

// busy returns non-idle jiffies (everything except idle and iowait).
// iowait is excluded from busy so disk-bound waits don't inflate CPU%.
func (s cpuStat) busy() uint64 {
	return s.user + s.nice + s.system + s.irq + s.softirq + s.steal
}

// CPUSampler measures CPU utilization via successive /proc/stat deltas.
// Create one at program start and call Sample() on each heartbeat interval.
// Goroutine-safe.
type CPUSampler struct {
	mu          sync.Mutex
	last        cpuStat
	initialized bool
}

// NewCPUSampler creates a sampler. The first call to Sample() initialises
// the baseline and returns 0; subsequent calls return real percentages.
func NewCPUSampler() *CPUSampler {
	return &CPUSampler{}
}

// Sample reads the current /proc/stat, computes the percentage of time
// spent in non-idle states since the previous call, and stores the new
// baseline. Returns a value in [0, 100].
func (s *CPUSampler) Sample() (float64, error) {
	curr, err := readCPUStat()
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		s.last = curr
		s.initialized = true
		return 0, nil
	}

	// Guard against time going backwards (VM migration, etc.).
	if curr.total() <= s.last.total() {
		s.last = curr
		return 0, nil
	}

	deltaBusy := curr.busy() - s.last.busy()
	deltaTotal := curr.total() - s.last.total()
	s.last = curr

	pct := float64(deltaBusy) / float64(deltaTotal) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

// readCPUStat parses the first "cpu " aggregate line from /proc/stat.
// The kernel guarantees this line is always present.
func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		// "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
		fields := strings.Fields(line)
		if len(fields) < 9 {
			return cpuStat{}, fmt.Errorf("/proc/stat cpu line has only %d fields", len(fields))
		}
		parse := func(i int) uint64 {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		return cpuStat{
			user:    parse(1),
			nice:    parse(2),
			system:  parse(3),
			idle:    parse(4),
			iowait:  parse(5),
			irq:     parse(6),
			softirq: parse(7),
			steal:   parse(8),
		}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat: no aggregate cpu line found")
}
