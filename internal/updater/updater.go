// Package updater handles self-update of the warden-v2 binary from the DNSFox API.
// Version is embedded at build time via:
//
//	-ldflags "-X github.com/itsBOTzilla/dnsfoxv2-warden/internal/updater.CurrentVersion=x.y.z"
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CurrentVersion is set at build time via -ldflags. The baked-in default
// tracks what the warden reports when launched without a version override.
var CurrentVersion = "0.7.1"

// CheckAndUpdate downloads and installs a newer binary if available.
// Returns true if an update was applied (process will restart via systemctl).
// Only updates when activeJobs == 0 to avoid interrupting in-flight work.
func CheckAndUpdate(ctx context.Context, apiURL, token, newVersion string, activeJobs int) (bool, error) {
	if newVersion == "" || !isNewer(CurrentVersion, newVersion) {
		return false, nil
	}
	if activeJobs > 0 {
		log.Printf("[updater] update available (%s → %s) but %d jobs active — deferring", CurrentVersion, newVersion, activeJobs)
		return false, nil
	}

	log.Printf("[updater] update available: %s → %s — downloading", CurrentVersion, newVersion)

	url := apiURL + "/api/agent/binary"
	client := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("updater: request: %w", err)
	}
	req.Header.Set("X-Warden-Token", token)
	req.Header.Set("X-Warden-Version", newVersion)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("updater: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("updater: download HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("updater: read body: %w", err)
	}

	// Verify SHA-256 if provided.
	if checksum := resp.Header.Get("X-Checksum-SHA256"); checksum != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != checksum {
			return false, fmt.Errorf("updater: checksum mismatch (got %s want %s)", got, checksum)
		}
	}

	// Write to a temp file in the SAME directory as the destination so the
	// final rename is atomic and never crosses a filesystem boundary
	// (/tmp is commonly tmpfs on VPSes, triggering EXDEV on rename).
	destPath := "/usr/local/bin/warden-v2"
	destDir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(destDir, ".warden-v2-new-*")
	if err != nil {
		return false, fmt.Errorf("updater: create temp: %w", err)
	}
	tmpPath := tmpFile.Name()
	// Best-effort cleanup on any failure path.
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return false, fmt.Errorf("updater: write binary: %w", err)
	}
	if err := tmpFile.Chmod(0o755); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return false, fmt.Errorf("updater: chmod: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return false, fmt.Errorf("updater: close: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		cleanup()
		return false, fmt.Errorf("updater: install binary: %w", err)
	}

	log.Printf("[updater] binary installed at %s — restarting service", destPath)

	// Restart via systemd. The current process will be killed and replaced.
	if err := exec.Command("systemctl", "restart", "warden-v2").Run(); err != nil {
		return true, fmt.Errorf("updater: systemctl restart: %w", err)
	}

	return true, nil
}

// isNewer returns true if candidate version is strictly greater than current.
// Compares semver segments as integers: "1.2.3" > "1.2.2".
func isNewer(current, candidate string) bool {
	cv := parseVer(current)
	nv := parseVer(candidate)
	for i := 0; i < 3; i++ {
		if nv[i] > cv[i] {
			return true
		}
		if nv[i] < cv[i] {
			return false
		}
	}
	return false // equal
}

// parseVer splits "X.Y.Z" into [X, Y, Z] integers.
func parseVer(v string) [3]int {
	parts := strings.SplitN(v, ".", 3)
	var result [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		n, _ := strconv.Atoi(p)
		result[i] = n
	}
	return result
}
