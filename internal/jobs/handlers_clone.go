// handlers_clone.go — staging/migration job handlers (clone_files, push_to_production, migrate_site).
// Split from handlers.go to keep files under 300 lines.
package jobs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// handleCloneFiles rsyncs files from source to destination site and optionally
// clones the database and runs WP search-replace for staging domains.
func (e *Executor) handleCloneFiles(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	sourceSiteID, _ := payload["source_site_id"].(string)
	destSiteID, _ := payload["dest_site_id"].(string)
	stagingDomain, _ := payload["staging_domain"].(string)
	includeDB, _ := payload["include_db"].(bool)

	if sourceSiteID == "" || destSiteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			"missing source_site_id or dest_site_id"
	}

	srcDir := fmt.Sprintf("/var/www/site_%s/", sourceSiteID)
	destDir := fmt.Sprintf("/var/www/site_%s/", destSiteID)

	// Ensure destination directory exists.
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("create dest dir: %v", err)
	}

	// rsync files from source to destination.
	rsyncOut, err := exec.CommandContext(ctx,
		"rsync", "-a", "--delete", "--quiet",
		srcDir, destDir,
	).CombinedOutput()
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("rsync: %s: %v", rsyncOut, err)
	}
	log.Printf("[jobs] rsync %s → %s done", sourceSiteID, destSiteID)

	// Clone database if requested.
	if includeDB {
		srcDB := "db_" + sourceSiteID
		destDB := "db_" + destSiteID
		mysqlArgs := []string{"-h", "127.0.0.1", "-P", "3307", "-u", "root"}

		// Dump source DB.
		dumpCmd := exec.CommandContext(ctx, "mysqldump",
			append(mysqlArgs, srcDB, "--single-transaction", "--quick")...)
		importCmd := exec.CommandContext(ctx, "mysql", append(mysqlArgs, destDB)...)

		dumpOut, dumpErr := dumpCmd.StdoutPipe()
		if dumpErr != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump pipe: %v", dumpErr)
		}
		importCmd.Stdin = dumpOut

		if err := dumpCmd.Start(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump start: %v", err)
		}
		if err := importCmd.Start(); err != nil {
			_ = dumpCmd.Wait()
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("import start: %v", err)
		}
		if err := dumpCmd.Wait(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump: %v", err)
		}
		if err := importCmd.Wait(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("import: %v", err)
		}
		log.Printf("[jobs] db cloned %s → %s", srcDB, destDB)
	}

	// Run WP search-replace if staging domain is provided.
	if stagingDomain != "" && includeDB {
		// Detect production domain from the source site.
		prodDomain := ""
		vhostPath := fmt.Sprintf("/etc/nginx/conf.d-v2/site_%s.conf", sourceSiteID)
		if data, err := os.ReadFile(vhostPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "server_name") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						prodDomain = strings.TrimSuffix(parts[1], ";")
					}
				}
			}
		}
		if prodDomain != "" {
			wpPath := fmt.Sprintf("/var/www/site_%s/public", destSiteID)
			srOut, srErr := exec.CommandContext(ctx,
				"wp", "search-replace", prodDomain, stagingDomain,
				"--path="+wpPath, "--allow-root",
			).CombinedOutput()
			if srErr != nil {
				log.Printf("[jobs] warn: wp search-replace: %s: %v", srOut, srErr)
			} else {
				log.Printf("[jobs] wp search-replace %s → %s done", prodDomain, stagingDomain)
			}
		}
	}

	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handlePushToProduction rsyncs staging files to production and optionally overwrites
// the production database, then runs WP search-replace back to the production domain.
func (e *Executor) handlePushToProduction(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	sourceSiteID, _ := payload["source_site_id"].(string) // staging
	destSiteID, _ := payload["dest_site_id"].(string)     // production
	overwriteDB, _ := payload["overwrite_db"].(bool)
	stagingDomain, _ := payload["staging_domain"].(string)
	prodDomain, _ := payload["prod_domain"].(string)

	if sourceSiteID == "" || destSiteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			"missing source_site_id or dest_site_id"
	}

	srcDir := fmt.Sprintf("/var/www/site_%s/", sourceSiteID)
	destDir := fmt.Sprintf("/var/www/site_%s/", destSiteID)

	// rsync staging → production.
	rsyncOut, err := exec.CommandContext(ctx,
		"rsync", "-a", "--delete", "--quiet",
		srcDir, destDir,
	).CombinedOutput()
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("rsync: %s: %v", rsyncOut, err)
	}
	log.Printf("[jobs] push-to-prod rsync %s → %s done", sourceSiteID, destSiteID)

	if overwriteDB {
		srcDB := "db_" + sourceSiteID
		destDB := "db_" + destSiteID
		mysqlArgs := []string{"-h", "127.0.0.1", "-P", "3307", "-u", "root"}

		dumpCmd := exec.CommandContext(ctx, "mysqldump",
			append(mysqlArgs, srcDB, "--single-transaction", "--quick")...)
		importCmd := exec.CommandContext(ctx, "mysql", append(mysqlArgs, destDB)...)

		dumpOut, dumpErr := dumpCmd.StdoutPipe()
		if dumpErr != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump pipe: %v", dumpErr)
		}
		importCmd.Stdin = dumpOut

		if err := dumpCmd.Start(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump start: %v", err)
		}
		if err := importCmd.Start(); err != nil {
			_ = dumpCmd.Wait()
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("import start: %v", err)
		}
		if err := dumpCmd.Wait(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("dump: %v", err)
		}
		if err := importCmd.Wait(); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("import: %v", err)
		}
		log.Printf("[jobs] push-to-prod db overwrite done")

		// Run WP search-replace to swap staging domain → production domain.
		if stagingDomain != "" && prodDomain != "" {
			wpPath := fmt.Sprintf("/var/www/site_%s/public", destSiteID)
			srOut, srErr := exec.CommandContext(ctx,
				"wp", "search-replace", stagingDomain, prodDomain,
				"--path="+wpPath, "--allow-root",
			).CombinedOutput()
			if srErr != nil {
				log.Printf("[jobs] warn: wp search-replace: %s: %v", srOut, srErr)
			} else {
				log.Printf("[jobs] push-to-prod search-replace %s → %s done", stagingDomain, prodDomain)
			}
		}
	}

	// Reload nginx and php-fpm after push.
	if err := provisioning.ReloadNginx(); err != nil {
		log.Printf("[jobs] warn: reload nginx after push-to-prod: %v", err)
	}

	log.Printf("[jobs] push-to-production %s → %s done", sourceSiteID, destSiteID)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleMigrateSite handles JOB_TYPE_MIGRATE_SITE. Dispatches on migration_type:
//   - "plugin" → download archives from API + import DB + extract files + WP search-replace
//   - other   → log stub (warden-driven pull not yet implemented)
func (e *Executor) handleMigrateSite(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	migrationType, _ := payload["migration_type"].(string)

	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	if migrationType == "plugin" {
		return e.handleMigrateSitePlugin(ctx, payload)
	}

	log.Printf("[jobs] migrate site %s type=%s: auto-pull not supported, failing honestly", siteID, migrationType)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
		"Automatic migration requires the DNSFox Migrator plugin. Install the plugin on your source WordPress site and use the plugin-based migration flow from your dashboard."
}

// handleMigrateSitePlugin imports a WordPress site whose DB dump and files archive
// were uploaded by the DNSFox Migrator plugin and assembled by the API.
func (e *Executor) handleMigrateSitePlugin(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	migImportID, _ := payload["migration_import_id"].(string)
	sourceDomain, _ := payload["source_domain"].(string)
	targetDomain, _ := payload["target_domain"].(string)
	tablePrefix, _ := payload["table_prefix"].(string)
	importFiles, _ := payload["import_files"].(bool)
	importDatabase, _ := payload["import_database"].(bool)

	if siteID == "" || migImportID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			"missing site_id or migration_import_id"
	}

	username := provisioning.SiteUsername(siteID)
	docroot := fmt.Sprintf("%s/%s/public", e.cfg.DocrootBase, username)
	credsPath := fmt.Sprintf("%s/%s/.db_credentials", e.cfg.DocrootBase, username)

	log.Printf("[jobs] plugin-import site=%s migration=%s", siteID, migImportID)

	if importDatabase {
		creds, err := readDBCredentials(credsPath)
		if err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				"read db creds: " + err.Error()
		}
		if err := e.importMigrationDB(ctx, migImportID, creds); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				"import db: " + err.Error()
		}
		log.Printf("[jobs] plugin-import: DB imported for site %s", siteID)
	}

	if importFiles {
		if err := e.extractMigrationFiles(ctx, migImportID, docroot); err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				"extract files: " + err.Error()
		}
		log.Printf("[jobs] plugin-import: files extracted for site %s", siteID)
	}

	// WP-CLI search-replace to swap source domain → target domain in the DB.
	if importDatabase && sourceDomain != "" && targetDomain != "" && sourceDomain != targetDomain {
		if tablePrefix == "" {
			tablePrefix = "wp_"
		}
		srOut, srErr := exec.CommandContext(ctx,
			"wp", "search-replace", sourceDomain, targetDomain,
			"--path="+docroot, "--allow-root", "--all-tables",
		).CombinedOutput()
		if srErr != nil {
			log.Printf("[jobs] warn: wp search-replace: %s: %v", srOut, srErr)
		} else {
			log.Printf("[jobs] plugin-import: search-replace %s → %s done", sourceDomain, targetDomain)
		}
	}

	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// dbCredentials holds parsed MariaDB connection details from .db_credentials.
type dbCredentials struct {
	Name, User, Pass, Host, Port string
}

// readDBCredentials parses the INI-style .db_credentials file written by the
// MariaDB provisioner.
func readDBCredentials(path string) (dbCredentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return dbCredentials{}, fmt.Errorf("read %s: %w", path, err)
	}
	var c dbCredentials
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, ";") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "DB_NAME":
			c.Name = parts[1]
		case "DB_USER":
			c.User = parts[1]
		case "DB_PASS":
			c.Pass = parts[1]
		case "DB_HOST":
			c.Host = parts[1]
		case "DB_PORT":
			c.Port = parts[1]
		}
	}
	if c.Name == "" || c.User == "" {
		return c, fmt.Errorf("incomplete credentials in %s", path)
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == "" {
		c.Port = "3307"
	}
	return c, nil
}

// importMigrationDB downloads the assembled DB dump from the API and imports it
// into the site's MariaDB database via mysql CLI.
func (e *Executor) importMigrationDB(ctx context.Context, migImportID string, creds dbCredentials) error {
	url := fmt.Sprintf("%s/api/agent/migration/%s/archive-db", e.cfg.APIUrl, migImportID)
	data, err := e.downloadFromAPI(ctx, url)
	if err != nil {
		return fmt.Errorf("download db dump: %w", err)
	}
	defer data.Close()

	mysqlArgs := []string{
		"-h", creds.Host, "-P", creds.Port,
		"-u", creds.User, "-p" + creds.Pass,
		creds.Name,
	}
	cmd := exec.CommandContext(ctx, "mysql", mysqlArgs...)
	cmd.Stdin = data
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql: %s: %w", out, err)
	}
	return nil
}

// extractMigrationFiles downloads the assembled files archive from the API and
// extracts it into the site docroot.
func (e *Executor) extractMigrationFiles(ctx context.Context, migImportID, docroot string) error {
	url := fmt.Sprintf("%s/api/agent/migration/%s/archive-files", e.cfg.APIUrl, migImportID)
	data, err := e.downloadFromAPI(ctx, url)
	if err != nil {
		return fmt.Errorf("download files archive: %w", err)
	}
	defer data.Close()

	if err := os.MkdirAll(docroot, 0755); err != nil {
		return fmt.Errorf("mkdir docroot: %w", err)
	}

	cmd := exec.CommandContext(ctx, "tar", "-xzf", "-", "-C", docroot, "--strip-components=1")
	cmd.Stdin = data
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tar: %s: %w", out, err)
	}
	return nil
}

// downloadFromAPI makes an authenticated GET request to the API and returns the
// response body. The caller is responsible for closing the reader.
func (e *Executor) downloadFromAPI(ctx context.Context, url string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Warden-Token", e.cfg.APIToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}
