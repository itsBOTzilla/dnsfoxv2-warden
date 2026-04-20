// Package migration handles inter-server site migration for DNSFox v2.
//
// The source warden orchestrates the full move:
//  1. Provision the site on the target warden (creates user, PHP-FPM pool, etc.)
//  2. Tar the docroot + DB dump into a single archive
//  3. POST the archive to the target warden's /migration/receive/{siteID} endpoint
//  4. Target warden extracts docroot and imports the DB dump
//
// The MigrateSite gRPC call returns RUNNING immediately; the migration runs
// in a goroutine and calls ReportJobResult when done.
package migration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenv1connect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// Migrator orchestrates outbound site migrations.
type Migrator struct {
	cfg *config.Config
}

// New returns a new Migrator.
func New(cfg *config.Config) *Migrator {
	return &Migrator{cfg: cfg}
}

// MigrateSite packages the site and transfers it to the target warden.
// siteType and phpVersion are detected from the running site config.
func (m *Migrator) MigrateSite(ctx context.Context, req *wardenv1.MigrateSiteRequest) error {
	siteID := req.GetSiteId()
	targetIP := req.GetTargetServerIp()
	targetToken := req.GetTargetWardenToken()

	username := provisioning.SiteUsername(siteID)
	docroot := fmt.Sprintf("/var/www/%s", username)

	log.Printf("[migration] starting migration: site=%s target=%s", siteID, targetIP)

	// Step 1 — detect site type and PHP version.
	phpVersion := detectPHPVersion(siteID)
	siteType := "php"
	if phpVersion == "" {
		siteType = "nodejs"
	}
	log.Printf("[migration] detected type=%s php=%s", siteType, phpVersion)

	// Step 2 — provision infrastructure on the target (creates user, FPM pool, nginx vhost).
	if err := m.provisionOnTarget(ctx, siteID, targetIP, targetToken, siteType, phpVersion); err != nil {
		return fmt.Errorf("provision on target: %w", err)
	}
	log.Printf("[migration] infrastructure provisioned on target")

	// Step 3 — create archive: tar docroot + DB dump.
	archive, dbDump, err := m.packageSite(siteID, username, docroot)
	if err != nil {
		return fmt.Errorf("package site: %w", err)
	}
	defer os.Remove(archive)
	if dbDump != "" {
		defer os.Remove(dbDump)
	}
	log.Printf("[migration] site packaged: archive=%s", archive)

	// Step 4 — transfer to target warden.
	targetURL := fmt.Sprintf("http://%s:9202/migration/receive/%s", targetIP, siteID)
	if err := m.transferToTarget(ctx, targetURL, targetToken, archive, dbDump); err != nil {
		return fmt.Errorf("transfer to target: %w", err)
	}
	log.Printf("[migration] transfer complete to %s", targetIP)

	return nil
}

// provisionOnTarget calls ProvisionSite on the target warden via Connect-Go.
func (m *Migrator) provisionOnTarget(ctx context.Context, siteID, targetIP, token, siteType, phpVersion string) error {
	targetURL := fmt.Sprintf("http://%s:9202", targetIP)
	client := wardenv1connect.NewWardenServiceClient(
		&http.Client{Timeout: 5 * time.Minute},
		targetURL,
	)

	req := connect.NewRequest(&wardenv1.ProvisionSiteRequest{
		SiteId:     siteID,
		JobId:      "migrate-" + siteID,
		Type:       siteType,
		PhpVersion: phpVersion,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.ProvisionSite(ctx, req)
	return err
}

// packageSite creates a gzipped tar of the docroot and a mysqldump.
// Returns paths to the archive and DB dump files (in /tmp).
func (m *Migrator) packageSite(siteID, username, docroot string) (archivePath, dumpPath string, err error) {
	// Create archive.
	archivePath = fmt.Sprintf("/tmp/migrate-%s-files.tar.gz", siteID)
	if err = createTarGz(docroot, archivePath); err != nil {
		return "", "", fmt.Errorf("create tarball: %w", err)
	}

	// Dump MariaDB — skip if DB doesn't exist.
	dbName := "db_" + siteID
	if len(dbName) > 19 {
		dbName = dbName[:19]
	}
	dumpPath = fmt.Sprintf("/tmp/migrate-%s-db.sql", siteID)
	if dumpErr := m.dumpDatabase(dbName, dumpPath); dumpErr != nil {
		log.Printf("[migration] warn: db dump for %s failed (may not exist): %v", siteID, dumpErr)
		os.Remove(dumpPath)
		dumpPath = ""
	}
	return archivePath, dumpPath, nil
}

// createTarGz creates a gzipped tar archive of src at dst.
func createTarGz(src, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tw, file)
		return err
	})
}

// dumpDatabase runs mysqldump for the given database name, writing to dstPath.
func (m *Migrator) dumpDatabase(dbName, dstPath string) error {
	args := []string{
		"-h", "127.0.0.1", "-P", "3307", "-u", "root",
	}
	rootPw := os.Getenv("MARIADB_ROOT_PASSWORD")
	if rootPw != "" {
		args = append(args, "-p"+rootPw)
	}
	args = append(args, "--single-transaction", "--skip-lock-tables", dbName)

	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.Command("mysqldump", args...)
	cmd.Stdout = f
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, errBuf.String())
	}
	return nil
}

// transferToTarget POSTs the archive (and optional DB dump) to the target warden
// via multipart form upload.
func (m *Migrator) transferToTarget(ctx context.Context, url, token, archivePath, dumpPath string) error {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer mw.Close()

		if err := writeFilePart(mw, "files", archivePath); err != nil {
			pw.CloseWithError(fmt.Errorf("write files part: %w", err))
			return
		}
		if dumpPath != "" {
			if err := writeFilePart(mw, "db", dumpPath); err != nil {
				pw.CloseWithError(fmt.Errorf("write db part: %w", err))
			}
		}
	}()

	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodPost, url, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("target returned HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}

// writeFilePart adds a file as a multipart form field.
func writeFilePart(mw *multipart.Writer, fieldName, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	part, err := mw.CreateFormFile(fieldName, filepath.Base(filePath))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, f)
	return err
}

// detectPHPVersion mirrors executor.detectPHPVersion to avoid a circular import.
func detectPHPVersion(siteID string) string {
	candidates := []struct {
		version string
		path    string
	}{
		{"8.4", "/etc/php/8.4/fpm/pool.d/dnsfox-" + siteID + ".conf"},
		{"8.5", "/usr/local/php8.5/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.3", "/usr/local/php8.3/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.2", "/usr/local/php8.2/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
		{"8.1", "/usr/local/php8.1/etc/php-fpm.d/dnsfox-" + siteID + ".conf"},
	}
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			return c.version
		}
	}
	return ""
}
