// php.go — v1 Docker PHP app → v2 host PHP-FPM conversion.
//
// A v1 PHP site has up to three Docker containers:
//
//	php_<domainSafe>_web   — PHP-FPM + nginx, mounts the app volume at /var/www/html
//	php_<domainSafe>_db    — MariaDB (optional; Laravel/Symfony with DB)
//	php_<domainSafe>_mgmt  — management sidecar (ignored by converter)
//
// Flow mirrors the WordPress converter but skips WP-CLI / wp-config.php /
// mu-plugin steps.  If no db container exists the DB import is skipped
// entirely and the new site has no MariaDB resources provisioned.
package v1convert

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/mariadb"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/phpfpm"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// PHPRequest carries per-site parameters for a PHP-app conversion.
type PHPRequest struct {
	SiteID     string
	Domain     string
	Plan       string
	PHPVersion string // "8.2" / "8.3" / "8.4"
}

// PHPResult captures final state for DB back-write + logging.
type PHPResult struct {
	SiteID         string
	Username       string
	CgroupSlice    string
	DocumentRoot   string
	DBName         string // empty when site had no database
	NginxVhostPath string
	BackupPath     string
	SQLDumpPath    string // empty when no DB
	DowntimeMs     int64
	CacheDir       string
}

// ConvertPHPSite runs the full v1→v2 PHP-app conversion.
func (c *Converter) ConvertPHPSite(ctx context.Context, req PHPRequest) (*PHPResult, error) {
	if req.SiteID == "" || req.Domain == "" {
		return nil, fmt.Errorf("site_id and domain are required")
	}
	if req.Plan == "" {
		req.Plan = "fox"
	}
	if req.PHPVersion == "" {
		req.PHPVersion = "8.3"
	}

	username := provisioning.SiteUsername(req.SiteID)
	siteRoot := fmt.Sprintf("/var/www/%s", username)
	docroot := filepath.Join(siteRoot, "public")

	domainSafe := dockerNameFromDomain(req.Domain)
	webName := fmt.Sprintf("php_%s_web", domainSafe)
	dbName := fmt.Sprintf("php_%s_db", domainSafe)
	mgmtName := fmt.Sprintf("php_%s_mgmt", domainSafe)

	log.Printf("[v1convert] begin php site=%s domain=%s web=%s", req.SiteID, req.Domain, webName)

	// 1. Inspect web container (required).
	webInfo, err := inspectContainer(ctx, webName)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", webName, err)
	}

	// 2. Detect db container presence.
	hasDB := false
	if _, err := inspectContainer(ctx, dbName); err == nil {
		hasDB = true
	}

	// 3. Pause web.
	if err := pauseContainer(ctx, webName); err != nil {
		log.Printf("[v1convert] warn: pause %s: %v", webName, err)
	}

	// 4. Backup paths.
	backupDir := "/var/backups/v1convert"
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		_ = unpauseContainer(ctx, webName)
		return nil, fmt.Errorf("mkdir backup dir: %w", err)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s-php.tar.gz", req.SiteID, ts))
	sqlDumpPath := ""

	// 5. mysqldump BEFORE pausing DB (needs live DB).
	if hasDB {
		sqlDumpPath = filepath.Join(backupDir, fmt.Sprintf("%s-%s-php.sql.gz", req.SiteID, ts))
		if err := mysqldumpFromContainer(ctx, dbName, sqlDumpPath); err != nil {
			_ = unpauseContainer(ctx, webName)
			return nil, fmt.Errorf("mysqldump %s: %w", dbName, err)
		}
		log.Printf("[v1convert] sql dump %s", sqlDumpPath)
		if err := pauseContainer(ctx, dbName); err != nil {
			log.Printf("[v1convert] warn: pause %s: %v", dbName, err)
		}
	}

	// 6. Tar the app volume.
	if err := tarballDir(ctx, webInfo.SourceDir, backupPath); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("tar volume: %w", err)
	}
	log.Printf("[v1convert] volume backup %s", backupPath)

	// 7. Create site user + docroot.
	if err := provisioning.CreateSystemUser(username); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	if err := provisioning.AddToGroup(username, "www-data"); err != nil {
		log.Printf("[v1convert] warn: www-data group: %v", err)
	}
	if err := os.MkdirAll(docroot, 0o750); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("mkdir docroot: %w", err)
	}

	// 8. cgroup limits.
	cgMgr := cgroups.NewManager()
	limits, ok := provisioning.PlanLimits[req.Plan]
	if !ok {
		limits = provisioning.PlanLimits["fox"]
	}
	if err := cgMgr.ApplyLimits(req.SiteID, username, limits); err != nil {
		log.Printf("[v1convert] warn: cgroup limits: %v", err)
	}
	sliceName := fmt.Sprintf("dnsfox-site-%s.slice", req.SiteID)

	// 9. Copy files. The v1 PHP container mounts the app at /var/www/html.
	//    Framework code (Laravel/Symfony) serves from /public.  We copy the
	//    entire mount into docroot's PARENT so /public/ ends up at
	//    /var/www/<user>/public/.
	if err := rsyncCopy(ctx, webInfo.SourceDir+"/", siteRoot+"/app/"); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("rsync app files: %w", err)
	}
	// If the app has its own public/, link it into place.  Otherwise use the
	// app dir itself as the docroot.
	appPublic := filepath.Join(siteRoot, "app", "public")
	if _, err := os.Stat(appPublic); err == nil {
		_ = os.RemoveAll(docroot)
		if err := os.Symlink(appPublic, docroot); err != nil {
			log.Printf("[v1convert] warn: symlink public: %v", err)
		}
	} else {
		_ = os.RemoveAll(docroot)
		if err := os.Symlink(filepath.Join(siteRoot, "app"), docroot); err != nil {
			log.Printf("[v1convert] warn: symlink app: %v", err)
		}
	}
	if _, err := runCmd(ctx, "chown", "-R", username+":"+username, siteRoot); err != nil {
		log.Printf("[v1convert] warn: chown: %v", err)
	}

	// 10. DB import (only if v1 had a db container).
	dbNameOut := ""
	if hasDB {
		mdb := mariadb.NewManager()
		if err := mdb.CreateSiteDatabase(req.SiteID, username); err != nil {
			_ = unpauseContainer(ctx, webName)
			_ = unpauseContainer(ctx, dbName)
			return nil, fmt.Errorf("create host db: %w", err)
		}
		creds, err := readDBCreds(fmt.Sprintf("%s/.db_credentials", siteRoot))
		if err != nil {
			_ = unpauseContainer(ctx, webName)
			_ = unpauseContainer(ctx, dbName)
			return nil, fmt.Errorf("read db creds: %w", err)
		}
		if err := importSQLDump(ctx, sqlDumpPath, creds.Name); err != nil {
			_ = unpauseContainer(ctx, webName)
			_ = unpauseContainer(ctx, dbName)
			return nil, fmt.Errorf("import sql: %w", err)
		}
		dbNameOut = creds.Name
		log.Printf("[v1convert] sql imported into %s", creds.Name)
	}

	// 11. Per-site PHP-FPM service + nginx vhost.
	// Write standalone config + systemd unit so all workers run inside the site cgroup.
	pool := phpfpm.PoolConfig{
		SiteID:      req.SiteID,
		Username:    username,
		PHPVersion:  req.PHPVersion,
		MaxChildren: 5,
		Ondemand:    true,
	}
	if err := phpfpm.WriteSiteConfig(pool); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("write phpfpm site config: %w", err)
	}
	if err := phpfpm.WriteServiceUnit(pool); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("write phpfpm service unit: %w", err)
	}
	_, _ = runCmd(ctx, "systemctl", "daemon-reload")
	if _, err := runCmd(ctx, "systemctl", "enable", "--now", phpfpm.ServiceUnitName(req.SiteID)); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("start phpfpm service: %w", err)
	}
	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForFile(socketPath, 30); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("phpfpm socket: %w", err)
	}

	ng := nginx.NewManager()
	if err := ng.WriteVhost(nginx.VhostConfig{
		SiteID:       req.SiteID,
		Domain:       req.Domain,
		Username:     username,
		DocumentRoot: docroot,
		PHPVersion:   req.PHPVersion,
	}); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("write nginx vhost: %w", err)
	}
	if _, err := runCmd(ctx, "systemctl", "reload", "nginx"); err != nil {
		_ = unpauseContainer(ctx, webName)
		if hasDB {
			_ = unpauseContainer(ctx, dbName)
		}
		return nil, fmt.Errorf("reload nginx: %w", err)
	}

	// 12. Swap + health check.
	swapStart := time.Now()
	if err := waitForHTTPHost(ctx, req.Domain, 30*time.Second); err != nil {
		log.Printf("[v1convert] warn: php health check: %v", err)
	}
	downtime := time.Since(swapStart).Milliseconds()

	// 13. Stop old containers.
	_ = unpauseContainer(ctx, webName)
	if hasDB {
		_ = unpauseContainer(ctx, dbName)
	}
	_ = stopContainer(ctx, webName)
	if hasDB {
		_ = stopContainer(ctx, dbName)
	}
	_ = stopContainer(ctx, mgmtName)

	return &PHPResult{
		SiteID:         req.SiteID,
		Username:       username,
		CgroupSlice:    sliceName,
		DocumentRoot:   docroot,
		DBName:         dbNameOut,
		NginxVhostPath: fmt.Sprintf("/etc/nginx/conf.d-v2/dnsfox-%s.conf", req.SiteID),
		BackupPath:     backupPath,
		SQLDumpPath:    sqlDumpPath,
		DowntimeMs:     downtime,
		CacheDir:       filepath.Join("/var/cache/nginx/v2-sites", req.SiteID),
	}, nil
}
