// Package redisutil provides shared Redis helpers for the Warden agent.
package redisutil

import (
	"fmt"
	"os/exec"
	"strings"
)

// FlushSiteKeys deletes all Redis keys prefixed "site_{siteID}:" using SCAN+DEL in batches.
// Never calls FLUSHALL or FLUSHDB. Non-fatal: callers should log but not fail on error.
// Returns the total number of keys deleted.
func FlushSiteKeys(host, port, password, siteID string) (int, error) {
	prefix := "site_" + siteID + ":*"
	addr := host + ":" + port

	baseArgs := []string{"-h", host, "-p", port}
	if password != "" {
		baseArgs = append(baseArgs, "-a", password, "--no-auth-warning")
	}

	cursor := "0"
	total := 0
	for {
		// Use a fresh slice each iteration to avoid aliasing the baseArgs backing array.
		scanArgs := append(append([]string{}, baseArgs...), "SCAN", cursor, "MATCH", prefix, "COUNT", "200")
		out, err := exec.Command("redis-cli", scanArgs...).Output()
		if err != nil {
			return total, fmt.Errorf("SCAN %s: %w", addr, err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) < 1 {
			break
		}
		cursor = strings.TrimSpace(lines[0])

		var toDelete []string
		for _, k := range lines[1:] {
			k = strings.TrimSpace(k)
			if k != "" {
				toDelete = append(toDelete, k)
			}
		}
		if len(toDelete) > 0 {
			delArgs := append(append([]string{}, baseArgs...), append([]string{"DEL"}, toDelete...)...)
			if _, err := exec.Command("redis-cli", delArgs...).Output(); err != nil {
				return total, fmt.Errorf("DEL batch: %w", err)
			}
			total += len(toDelete)
		}

		if cursor == "0" {
			break
		}
	}
	return total, nil
}
