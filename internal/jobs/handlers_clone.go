// handlers_clone.go — staging/migration job handlers (clone_files, push_to_production, migrate_site).
// Split from handlers.go to keep files under 300 lines.
package jobs

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

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

// handleMigrateSite handles JOB_TYPE_MIGRATE_SITE by delegating to the
// migration package which handles the full site transfer to this warden.
func (e *Executor) handleMigrateSite(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	sourceURL, _ := payload["source_url"].(string)
	migrationID, _ := payload["migration_id"].(string)

	if siteID == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, "missing site_id"
	}

	log.Printf("[jobs] migrate site %s migration_id=%s source=%s", siteID, migrationID, sourceURL)
	// The actual migration logic runs via the gRPC MigrateSite RPC path.
	// This heartbeat fallback just acknowledges the job and logs context.
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}
