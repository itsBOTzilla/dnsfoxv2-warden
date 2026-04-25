// Package redisutil provides shared Redis helpers for the Warden agent.
package redisutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// FlushSiteKeys deletes all Redis keys prefixed "site_{siteID}:" using SCAN+DEL in batches.
// Never calls FLUSHALL or FLUSHDB. Non-fatal: callers should log but not fail on error.
// Returns the total number of keys deleted.
func FlushSiteKeys(host, port, password, siteID string) (int, error) {
	prefix := "site_" + siteID + ":*"
	addr := host + ":" + port

	// Pass the password via REDISCLI_AUTH so it does not appear in /proc/PID/cmdline or ps output.
	baseArgs := []string{"-h", host, "-p", port}
	env := os.Environ()
	if password != "" {
		env = append(env, "REDISCLI_AUTH="+password)
	}

	runcmd := func(args []string) ([]byte, error) {
		cmd := exec.Command("redis-cli", args...)
		cmd.Env = env
		return cmd.Output()
	}

	cursor := "0"
	total := 0
	for {
		scanArgs := append(append([]string{}, baseArgs...), "SCAN", cursor, "MATCH", prefix, "COUNT", "200")
		out, err := runcmd(scanArgs)
		if err != nil {
			return total, fmt.Errorf("SCAN %s: %w", addr, err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) < 1 {
			break
		}
		cursor = strings.TrimSpace(lines[0])
		if cursor == "" {
			return total, fmt.Errorf("SCAN returned empty cursor at addr %s", addr)
		}

		var toDelete []string
		for _, k := range lines[1:] {
			k = strings.TrimSpace(k)
			if k != "" {
				toDelete = append(toDelete, k)
			}
		}
		if len(toDelete) > 0 {
			delArgs := append(append([]string{}, baseArgs...), append([]string{"DEL"}, toDelete...)...)
			if _, err := runcmd(delArgs); err != nil {
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
