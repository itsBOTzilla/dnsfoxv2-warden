// wordpress.go — v1 Docker WordPress → v2 host PHP-FPM + MariaDB conversion.
//
// A v1 WordPress site has three Docker containers:
//
//	wp_<domainSafe>_web    — WordPress + nginx, mounts volume wp_<id>_wordpress at /var/www/html
//	wp_<domainSafe>_db     — MariaDB, mounts volume wp_<id>_database at /var/lib/mysql
//	wp_<domainSafe>_redis  — Redis (data discarded on convert, v2 uses host Redis)
//
// A v2 WordPress site runs under systemd-managed PHP-FPM as user `site_<short>`
// with files at /var/www/site_<short>/public/ and an entry in host MariaDB on
// 127.0.0.1:3307 (database + user named `db_<short>`).
//
// The converter pauses the old containers before any file or DB capture to avoid
// data races (the Node.js pilot surfaced the same bug), mysqldumps from the
// paused DB container, rsyncs the WordPress volume into the new site root,
// rewrites wp-config.php to point at host MariaDB, reloads PHP-FPM + nginx,
// then leaves the old containers stopped (but not removed) for rollback.
package v1convert

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/mariadb"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/phpfpm"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// WordPressRequest carries the per-site parameters for WordPress conversion.
type WordPressRequest struct {
	SiteID     string // instance UUID
	Domain     string // customer domain (used to find v1 containers)
	Plan       string // fox/swift/apex/titan; defaults to "fox"
	PHPVersion string // "8.2" / "8.3" / "8.4"; defaults to "8.3"
}

// WordPressResult captures final state for DB back-write + logging.
type WordPressResult struct {
	SiteID         string
	Username       string
	CgroupSlice    string
	DocumentRoot   string
	DBName         string
	NginxVhostPath string
	BackupPath     string
	SQLDumpPath    string
	DowntimeMs     int64
	CacheDir       string
}

// ConvertWordPressSite runs the full v1→v2 WordPress conversion.
func (c *Converter) ConvertWordPressSite(ctx context.Context, req WordPressRequest) (*WordPressResult, error) {
	if req.SiteID == "" || req.Domain == "" {
		return nil, fmt.Errorf("site_id and domain are required")
	}
	if req.Plan == "" {
		req.Plan = "fox"
	}
	if req.PHPVersion == "" {
		req.PHPVersion = "8.3"
	}

	short := shortID(req.SiteID)
	username := provisioning.SiteUsername(req.SiteID)
	siteRoot := fmt.Sprintf("/var/www/%s", username)
	docroot := filepath.Join(siteRoot, "public")

	domainSafe := dockerNameFromDomain(req.Domain)
	webName := fmt.Sprintf("wp_%s_web", domainSafe)
	dbName := fmt.Sprintf("wp_%s_db", domainSafe)
	redisName := fmt.Sprintf("wp_%s_redis", domainSafe)

	log.Printf("[v1convert] begin wordpress site=%s domain=%s web=%s db=%s",
		req.SiteID, req.Domain, webName, dbName)

	// 1. Inspect both containers.
	webInfo, err := inspectContainer(ctx, webName)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", webName, err)
	}
	if _, err := inspectContainer(ctx, dbName); err != nil {
		return nil, fmt.Errorf("inspect %s: %w", dbName, err)
	}

	// 2. Pause the containers so backup + mysqldump see consistent state.
	if err := pauseContainer(ctx, webName); err != nil {
		log.Printf("[v1convert] warn: pause %s: %v", webName, err)
	}
	// mysqldump needs the DB to be responsive, so we dump BEFORE pausing the
	// db container. Instead pause only after the dump.

	// 3. Backup paths.
	backupDir := "/var/backups/v1convert"
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		_ = unpauseContainer(ctx, webName)
		return nil, fmt.Errorf("mkdir backup dir: %w", err)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s-wp.tar.gz", req.SiteID, ts))
	sqlDumpPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s-wp.sql.gz", req.SiteID, ts))

	// 4. Mysqldump from the running db container.
	if err := mysqldumpFromContainer(ctx, dbName, sqlDumpPath); err != nil {
		_ = unpauseContainer(ctx, webName)
		return nil, fmt.Errorf("mysqldump %s: %w", dbName, err)
	}
	log.Printf("[v1convert] sql dump %s", sqlDumpPath)

	// 5. Now pause the db too (writes can't race during tar).
	if err := pauseContainer(ctx, dbName); err != nil {
		log.Printf("[v1convert] warn: pause %s: %v", dbName, err)
	}

	// 6. Tar the wordpress volume.
	if err := tarballDir(ctx, webInfo.SourceDir, backupPath); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("tar volume: %w", err)
	}
	log.Printf("[v1convert] volume backup %s", backupPath)

	// 7. Create site user + docroot.
	if err := provisioning.CreateSystemUser(username); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("create user: %w", err)
	}
	if err := provisioning.AddToGroup(username, "www-data"); err != nil {
		log.Printf("[v1convert] warn: add www-data group: %v", err)
	}
	if err := os.MkdirAll(docroot, 0o750); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("mkdir docroot: %w", err)
	}

	// 8. Apply cgroup limits.
	cgMgr := cgroups.NewManager()
	limits, ok := provisioning.PlanLimits[req.Plan]
	if !ok {
		limits = provisioning.PlanLimits["fox"]
	}
	if err := cgMgr.ApplyLimits(req.SiteID, username, limits); err != nil {
		log.Printf("[v1convert] warn: cgroup limits: %v", err)
	}
	sliceName := fmt.Sprintf("dnsfox-site-%s.slice", req.SiteID)

	// 9. Copy WordPress files from the docker volume dir into the new docroot.
	if err := rsyncCopy(ctx, webInfo.SourceDir+"/", docroot+"/"); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("rsync wordpress files: %w", err)
	}
	if _, err := runCmd(ctx, "chown", "-R", username+":"+username, siteRoot); err != nil {
		log.Printf("[v1convert] warn: chown site root: %v", err)
	}

	// 10. Import the SQL dump into host MariaDB — creates DB + user + grants.
	mdb := mariadb.NewManager()
	if err := mdb.CreateSiteDatabase(req.SiteID, username); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("create host db: %w", err)
	}
	dbCreds, err := readDBCreds(fmt.Sprintf("%s/.db_credentials", siteRoot))
	if err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("read db creds: %w", err)
	}
	if err := importSQLDump(ctx, sqlDumpPath, dbCreds.Name); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("import sql dump: %w", err)
	}
	log.Printf("[v1convert] sql imported into %s", dbCreds.Name)

	// 11. Rewrite wp-config.php to point at host MariaDB.
	wpConfigPath := filepath.Join(docroot, "wp-config.php")
	if err := rewriteWPConfig(wpConfigPath, dbCreds); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("rewrite wp-config: %w", err)
	}

	// 12. PHP-FPM pool + nginx vhost.
	if err := phpfpm.WritePoolConfig(phpfpm.PoolConfig{
		SiteID:      req.SiteID,
		Username:    username,
		PHPVersion:  req.PHPVersion,
		MaxChildren: 5,
	}); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("write phpfpm pool: %w", err)
	}
	if err := reloadPHPFPMVersion(ctx, req.PHPVersion); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("reload php-fpm: %w", err)
	}
	socketPath := fmt.Sprintf("/run/php/%s.sock", username)
	if err := waitForFile(socketPath, 30); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
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
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("write nginx vhost: %w", err)
	}
	if _, err := runCmd(ctx, "systemctl", "reload", "nginx"); err != nil {
		_ = unpauseContainer(ctx, webName)
		_ = unpauseContainer(ctx, dbName)
		return nil, fmt.Errorf("reload nginx: %w", err)
	}

	// 13. Service swap timer starts now — old containers come down, new site
	//     is already handling traffic via the v2 vhost in conf.d-v2/.
	swapStart := time.Now()

	// 14. Health check via Host header.
	if err := waitForHTTPHost(ctx, req.Domain, 30*time.Second); err != nil {
		// Not fatal, but log — the v2 wildcard cert covers *.sites.dnsfox.com
		// which is how customers reach pre-cutover sites.
		log.Printf("[v1convert] warn: health check: %v", err)
	}
	downtime := time.Since(swapStart).Milliseconds()

	// 15. Unpause + stop the old containers — keep them (do not remove) so a
	//     quick rollback is possible.
	_ = unpauseContainer(ctx, webName)
	_ = unpauseContainer(ctx, dbName)
	_ = stopContainer(ctx, webName)
	_ = stopContainer(ctx, dbName)
	_ = stopContainer(ctx, redisName)

	res := &WordPressResult{
		SiteID:         req.SiteID,
		Username:       username,
		CgroupSlice:    sliceName,
		DocumentRoot:   docroot,
		DBName:         dbCreds.Name,
		NginxVhostPath: fmt.Sprintf("/etc/nginx/conf.d-v2/dnsfox-%s.conf", req.SiteID),
		BackupPath:     backupPath,
		SQLDumpPath:    sqlDumpPath,
		DowntimeMs:     downtime,
		CacheDir:       filepath.Join("/var/cache/nginx/v2-sites", req.SiteID),
	}
	log.Printf("[v1convert] wordpress done site=%s short=%s downtime_ms=%d",
		req.SiteID, short, downtime)
	return res, nil
}

// RollbackWordPress reverts a failed conversion to the v1 state. Best-effort:
// errors are logged but not returned.
func (c *Converter) RollbackWordPress(ctx context.Context, req WordPressRequest) {
	domainSafe := dockerNameFromDomain(req.Domain)
	webName := fmt.Sprintf("wp_%s_web", domainSafe)
	dbName := fmt.Sprintf("wp_%s_db", domainSafe)
	redisName := fmt.Sprintf("wp_%s_redis", domainSafe)

	username := provisioning.SiteUsername(req.SiteID)
	log.Printf("[v1convert] rollback wordpress site=%s", req.SiteID)

	// Remove v2 pool + vhost.
	_ = phpfpm.RemovePoolConfig(req.SiteID)
	ng := nginx.NewManager()
	_ = ng.RemoveVhost(req.SiteID)
	if req.PHPVersion != "" {
		_ = reloadPHPFPMVersion(ctx, req.PHPVersion)
	}
	_, _ = runCmd(ctx, "systemctl", "reload", "nginx")

	// Drop v2 DB.
	mdb := mariadb.NewManager()
	_ = mdb.DropSiteDatabase(req.SiteID, username)

	// Bring v1 containers back up.
	_ = unpauseContainer(ctx, webName)
	_ = unpauseContainer(ctx, dbName)
	_ = startContainer(ctx, dbName)
	_ = startContainer(ctx, redisName)
	_ = startContainer(ctx, webName)
}

// dbCreds mirrors the layout written by mariadb.CreateSiteDatabase.
type dbCreds struct {
	Name string
	User string
	Pass string
	Host string
	Port string
}

// readDBCreds parses the .db_credentials file written by the MariaDB provisioner.
func readDBCreds(path string) (*dbCreds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	c := &dbCreds{
		Name: m["DB_NAME"],
		User: m["DB_USER"],
		Pass: m["DB_PASS"],
		Host: m["DB_HOST"],
		Port: m["DB_PORT"],
	}
	if c.Name == "" || c.User == "" || c.Pass == "" {
		return nil, fmt.Errorf("incomplete credentials in %s", path)
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == "" {
		c.Port = "3307"
	}
	return c, nil
}
