// Package cdncache reads /var/log/nginx/cache-stats.log and pushes per-domain
// cache hit/miss counts to the DNSFox API every 5 minutes.
//
// Log format (nginx cache_stats log_format): "$host $upstream_cache_status"
// Only lines where cache status is not "-" or "" are written (nginx map guard).
// Possible status values: HIT, MISS, BYPASS, EXPIRED, STALE, UPDATING.
//
// Offset is tracked in memory. On log rotation (file shrinks below last offset)
// the offset resets to 0 so we don't miss entries in the new file.
package cdncache

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	logFile  = "/var/log/nginx/cache-stats.log"
	interval = 5 * time.Minute
	endpoint = "/api/agent/cdn-cache-metrics"
)

type domainStat struct {
	Domain   string `json:"domain"`
	Hits     int    `json:"hits"`
	Misses   int    `json:"misses"`
	Bypasses int    `json:"bypasses"`
	Expired  int    `json:"expired"`
	Stale    int    `json:"stale"`
	Total    int    `json:"total_requests"`
}

// Collector reads nginx cache-stats.log on a timer and pushes aggregated
// domain stats to the control-plane API.
type Collector struct {
	apiURL     string
	agentToken string
	offset     int64
	client     *http.Client
}

// New creates a Collector. apiURL is the base URL (e.g. "http://127.0.0.1:8091").
// agentToken is the WARDEN_AGENT_TOKEN value for API authentication.
func New(apiURL, agentToken string) *Collector {
	return &Collector{
		apiURL:     strings.TrimRight(apiURL, "/"),
		agentToken: agentToken,
		client:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Run blocks until ctx is cancelled, collecting and pushing cache stats every 5 minutes.
func (c *Collector) Run(ctx context.Context) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.collect(ctx); err != nil {
				log.Printf("[cdncache] collection error: %v", err)
			}
		}
	}
}

func (c *Collector) collect(ctx context.Context) error {
	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nginx not yet writing cache stats
		}
		return err
	}
	defer f.Close()

	// Detect log rotation: file is smaller than our remembered offset.
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < c.offset {
		c.offset = 0
	}

	if _, err := f.Seek(c.offset, io.SeekStart); err != nil {
		return err
	}

	stats := map[string]*domainStat{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		domain, status := parts[0], strings.ToUpper(parts[1])
		if domain == "" || status == "" || status == "-" {
			continue
		}

		ds := stats[domain]
		if ds == nil {
			ds = &domainStat{Domain: domain}
			stats[domain] = ds
		}
		ds.Total++
		switch status {
		case "HIT":
			ds.Hits++
		case "MISS":
			ds.Misses++
		case "BYPASS":
			ds.Bypasses++
		case "EXPIRED":
			ds.Expired++
		case "STALE", "UPDATING":
			ds.Stale++
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Update offset to the current file position so the next run starts here.
	pos, _ := f.Seek(0, io.SeekCurrent)
	c.offset = pos

	if len(stats) == 0 {
		return nil // no new cache events since last run
	}

	metrics := make([]domainStat, 0, len(stats))
	for _, ds := range stats {
		metrics = append(metrics, *ds)
	}

	return c.push(ctx, metrics)
}

func (c *Collector) push(ctx context.Context, metrics []domainStat) error {
	payload, err := json.Marshal(map[string]interface{}{"metrics": metrics})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Warden-Token", c.agentToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}

	log.Printf("[cdncache] pushed %d domain stats to API", len(metrics))
	return nil
}
