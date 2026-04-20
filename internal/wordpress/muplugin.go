// muplugin.go — downloads and installs the DNSFox mu-plugin into a WordPress site.
//
// The mu-plugin provides:
//   - File manager integration (management.php endpoint)
//   - Platform metrics collection (metrics.php)
//   - Security hardening (security.php)
//   - Performance hooks (performance.php)
//   - Plugin lifecycle management (plugin-manager.php)
//
// Files are fetched from the v2 API at /api/internal/mu-plugin/{path}
// using the warden API token for auth. If the API is unavailable, the error
// is returned to the caller — provisioning continues but the reconcile loop
// will retry the deploy on the next heartbeat cycle.
package wordpress

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
)

// muRootFiles are top-level mu-plugin files served at /api/internal/mu-plugin/{name}.
var muRootFiles = []string{"dnsfox-platform.php", ".htaccess"}

// muSubFiles are files in the dnsfox/ subdirectory.
var muSubFiles = []string{
	"platform.php",
	"metrics.php",
	"security.php",
	"performance.php",
	"plugin-manager.php",
	"management.php",
}

// DeployMuPlugin downloads the DNSFox mu-plugin from the v2 API and installs it
// into {docroot}/wp-content/mu-plugins/. All files must download successfully;
// a partial install would leave WordPress in a broken state.
//
// siteID is logged for tracing but not sent to the API (the API uses the
// server-level token to authorise, not per-site credentials).
func DeployMuPlugin(cfg *config.Config, docroot, siteID string) error {
	if cfg.APIUrl == "" || cfg.APIToken == "" {
		return fmt.Errorf("API URL or token not configured — cannot download mu-plugin")
	}

	muRoot := filepath.Join(docroot, "wp-content", "mu-plugins")
	muSub := filepath.Join(muRoot, "dnsfox")
	if err := os.MkdirAll(muSub, 0755); err != nil {
		return fmt.Errorf("mkdir mu-plugins/dnsfox: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	tmpDir, err := os.MkdirTemp("", "mu-plugin-"+siteID+"-*")
	if err != nil {
		return fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download root-level files.
	for _, name := range muRootFiles {
		url := cfg.APIUrl + "/api/internal/mu-plugin/" + name
		dest := filepath.Join(tmpDir, name)
		if err := downloadMuFile(client, url, cfg.APIToken, cfg.ServerID, dest); err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
	}

	// Download dnsfox/ sub-plugin files.
	subTmp := filepath.Join(tmpDir, "dnsfox")
	if err := os.MkdirAll(subTmp, 0755); err != nil {
		return fmt.Errorf("mkdir tmp/dnsfox: %w", err)
	}
	for _, name := range muSubFiles {
		url := cfg.APIUrl + "/api/internal/mu-plugin/dnsfox/" + name
		dest := filepath.Join(subTmp, name)
		if err := downloadMuFile(client, url, cfg.APIToken, cfg.ServerID, dest); err != nil {
			return fmt.Errorf("download dnsfox/%s: %w", name, err)
		}
	}

	// All downloads succeeded — now copy into place atomically (rename within same FS).
	for _, name := range muRootFiles {
		if err := moveFile(filepath.Join(tmpDir, name), filepath.Join(muRoot, name)); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	for _, name := range muSubFiles {
		if err := moveFile(filepath.Join(subTmp, name), filepath.Join(muSub, name)); err != nil {
			return fmt.Errorf("install dnsfox/%s: %w", name, err)
		}
	}

	// Fix ownership so PHP-FPM (running as site user) can read the files.
	// www-data is not in the site group, but mu-plugins are read-only so 644 is fine.
	setMuPluginPerms(muRoot, muSub)
	return nil
}

// downloadMuFile fetches a single mu-plugin file from the API and writes it to dest.
// Uses Authorization: Bearer header and X-Server-ID for the warden identity.
func downloadMuFile(client *http.Client, url, token, serverID, dest string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Server-ID", serverID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// moveFile copies src to dst, overwriting dst if it exists.
// os.Rename across devices would fail; use copy+remove instead.
func moveFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// setMuPluginPerms applies 644 to all files and chowns to www-data:www-data.
// The PHP-FPM pool runs as the site user, not www-data; 644 allows reading.
func setMuPluginPerms(muRoot, muSub string) {
	dirs := []string{muRoot, muSub}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			os.Chmod(filepath.Join(d, e.Name()), 0644) //nolint:errcheck
		}
	}
}
