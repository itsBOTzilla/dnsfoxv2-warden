// Package clamav provides malware scanning for DNSFox v2 sites.
// Combines ClamAV daemon/CLI scanning with pattern-based PHP/HTML heuristics.
package clamav

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ScanResult holds the outcome of a site malware scan.
type ScanResult struct {
	SiteID        string   `json:"site_id"`
	Clean         bool     `json:"clean"`
	InfectedFiles []string `json:"infected_files"`
	TotalScanned  int      `json:"total_scanned"`
}

// malwarePatterns are heuristic regex patterns applied to PHP/HTML files.
var malwarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(`),
	regexp.MustCompile(`gzinflate\s*\(`),
	regexp.MustCompile(`str_rot13\s*\(`),
	regexp.MustCompile(`<iframe\s+src=`),
	regexp.MustCompile(`document\.write\s*\(\s*unescape\s*\(`),
	regexp.MustCompile(`FilesMan`),
	regexp.MustCompile(`c99shell`),
	regexp.MustCompile(`r57shell`),
	regexp.MustCompile(`coinhive`),
	regexp.MustCompile(`cryptonight`),
	regexp.MustCompile(`base64_decode.*eval`),
	regexp.MustCompile(`preg_replace\s*\(.*\/e`),
	regexp.MustCompile(`\$[a-zA-Z_]\w*\s*=\s*str_rot13\s*\(`),
}

// ScanSite scans a site directory for malware.
// Infected files are moved to /var/quarantine/site_{id}/{timestamp}/.
func ScanSite(ctx context.Context, siteID string) (*ScanResult, error) {
	siteDir := fmt.Sprintf("/var/www/site_%s", siteID)
	if _, err := os.Stat(siteDir); err != nil {
		return nil, fmt.Errorf("clamav: site dir not found: %s", siteDir)
	}

	result := &ScanResult{SiteID: siteID}
	var infected []string

	// Phase 1: ClamAV scan.
	clamInfected, totalScanned, err := runClamScan(ctx, siteDir)
	if err != nil {
		log.Printf("[clamav] clamscan failed (continuing with heuristics): %v", err)
	}
	infected = append(infected, clamInfected...)
	result.TotalScanned = totalScanned

	// Phase 2: Heuristic pattern scan.
	patternInfected, pTotal, err := runPatternScan(siteDir)
	if err != nil {
		log.Printf("[clamav] pattern scan error: %v", err)
	}
	for _, f := range patternInfected {
		if !contains(infected, f) {
			infected = append(infected, f)
		}
	}
	if pTotal > result.TotalScanned {
		result.TotalScanned = pTotal
	}

	result.InfectedFiles = infected
	result.Clean = len(infected) == 0

	if !result.Clean {
		if err := quarantine(siteID, infected); err != nil {
			log.Printf("[clamav] quarantine error: %v", err)
		}
	}

	return result, nil
}

// runClamScan tries clamdscan first, then falls back to clamscan.
func runClamScan(ctx context.Context, siteDir string) (infected []string, total int, err error) {
	out, err := exec.CommandContext(ctx, "clamdscan", "--fdpass", "--no-summary", siteDir).CombinedOutput()
	if err != nil {
		// Try clamscan fallback.
		out2, err2 := exec.CommandContext(ctx, "clamscan", "--no-summary", "-r", siteDir).CombinedOutput()
		if err2 != nil {
			return nil, 0, fmt.Errorf("clamdscan failed (%v) and clamscan failed (%v)", err, err2)
		}
		out = out2
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, " FOUND") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				infected = append(infected, strings.TrimSpace(parts[0]))
			}
			total++
		}
	}
	return infected, total, nil
}

// runPatternScan walks PHP/HTML files and applies heuristic regex patterns.
func runPatternScan(siteDir string) (infected []string, total int, err error) {
	err = filepath.WalkDir(siteDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".php" && ext != ".html" && ext != ".htm" && ext != ".js" {
			return nil
		}

		total++
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		content := string(data)
		for _, pat := range malwarePatterns {
			if pat.MatchString(content) {
				infected = append(infected, path)
				break
			}
		}
		return nil
	})
	return infected, total, err
}

// quarantine moves infected files to /var/quarantine/site_{id}/{timestamp}/ and writes a manifest.
func quarantine(siteID string, files []string) error {
	ts := time.Now().UTC().Format("20060102-150405")
	qDir := fmt.Sprintf("/var/quarantine/site_%s/%s", siteID, ts)
	if err := os.MkdirAll(qDir, 0700); err != nil {
		return fmt.Errorf("quarantine: mkdir: %w", err)
	}

	var manifest []string
	for _, src := range files {
		base := filepath.Base(src)
		dest := filepath.Join(qDir, base)
		if err := os.Rename(src, dest); err != nil {
			log.Printf("[clamav] quarantine: move %s → %s: %v", src, dest, err)
			continue
		}
		manifest = append(manifest, src)
	}

	mData, _ := json.MarshalIndent(map[string]interface{}{
		"site_id":   siteID,
		"timestamp": ts,
		"files":     manifest,
	}, "", "  ")
	manifestPath := filepath.Join(qDir, "manifest.json")
	return os.WriteFile(manifestPath, mData, 0600)
}

// contains checks if a slice contains a string.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
