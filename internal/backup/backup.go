// Package backup provides site backup and restore functionality for DNSFox v2 Warden.
// Backups are uploaded to Backblaze B2 via the native HTTP API (no SDK).
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// uuidRegex matches a canonical lowercase UUID (8-4-4-4-12 hex chars).
// siteID is concatenated into filesystem paths, DB/user names, and B2 object
// keys — a strict check here is the simplest defence against path-traversal,
// shell-metachar, and SQL-injection attempts via a compromised API caller.
// See V2_SECURITY_AUDIT.md M6.
var uuidRegex = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// validateSiteID returns nil if id is a canonical lowercase UUID, else an error.
func validateSiteID(id string) error {
	if !uuidRegex.MatchString(id) {
		return fmt.Errorf("invalid site_id: must be a canonical lowercase UUID")
	}
	return nil
}

// deriveShortID returns the first 12 hex chars of a UUID with dashes removed.
// Matches the v1-cgroup Linux username convention: site_{12hexchars}.
func deriveShortID(siteID string) string {
	hex := strings.ReplaceAll(siteID, "-", "")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// BackupSite creates an archive of the site and uploads it to B2.
// backupType: "files", "db", or "full".
// linuxUser is the OS username for v1-cgroup sites (e.g. "site_ed58d27bf42f");
// leave empty to derive it from siteID using the v2 provisioner convention.
// Returns the B2 file ID, size in bytes, and any error.
func BackupSite(ctx context.Context, siteID, backupType, linuxUser, b2KeyID, b2AppKey, b2Bucket string) (fileID string, sizeBytes int64, err error) {
	if err := validateSiteID(siteID); err != nil {
		return "", 0, err
	}
	ts := time.Now().UTC().Format("20060102-150405")
	tmpDir, err := os.MkdirTemp("", "dnsfox-backup-"+siteID)
	if err != nil {
		return "", 0, fmt.Errorf("backup: mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	b2, err := newB2Client(ctx, b2KeyID, b2AppKey, b2Bucket)
	if err != nil {
		return "", 0, fmt.Errorf("backup: b2 auth: %w", err)
	}

	// Resolve site directory and DB username.
	// Priority order:
	// 1. v1-cgroup explicit: /home/{linuxUser}/public_html  (linuxUser from payload)
	// 2. v1-cgroup derived:  /home/site_{12hexchars}/public_html  (first 12 hex chars of UUID)
	// 2b. cgroup native:     /var/dnsfox/sites/{uuid}/public_html  (post-migration path)
	// 3. v2-provisioner:     /var/www/{SiteUsername}/public
	var siteDir, dbUsername string

	// Attempt 1: explicit linuxUser from payload.
	if linuxUser != "" {
		v1Dir := "/home/" + linuxUser + "/public_html"
		if _, statErr := os.Stat(v1Dir); statErr == nil {
			siteDir = v1Dir
			dbUsername = linuxUser
		}
	}

	// Attempt 2: derive v1 linux user from siteID (first 12 hex chars, no dashes).
	if siteDir == "" {
		derived := "site_" + deriveShortID(siteID)
		v1Dir := "/home/" + derived + "/public_html"
		if _, statErr := os.Stat(v1Dir); statErr == nil {
			siteDir = v1Dir
			dbUsername = derived
		}
	}

	// Attempt 2b: cgroup-native path written by the v2 provisioner.
	if siteDir == "" {
		cgroupDir := "/var/dnsfox/sites/" + siteID + "/public_html"
		if _, statErr := os.Stat(cgroupDir); statErr == nil {
			siteDir = cgroupDir
		}
	}

	// Attempt 3: v2-provisioner path.
	if siteDir == "" {
		username := provisioning.SiteUsername(siteID)
		siteDir = "/var/www/" + username + "/public"
		if dbUsername == "" {
			dbUsername = "db_" + siteID
		}
	}

	switch backupType {
	case "files":
		return backupFiles(ctx, b2, siteID, siteDir, ts, tmpDir)
	case "db":
		return backupDB(ctx, b2, siteID, dbUsername, ts, tmpDir)
	case "full":
		fid, fsz, ferr := backupFiles(ctx, b2, siteID, siteDir, ts, tmpDir)
		if ferr != nil {
			return "", 0, ferr
		}
		_, _, derr := backupDB(ctx, b2, siteID, dbUsername, ts, tmpDir)
		if derr != nil {
			log.Printf("[backup] warn: db backup failed (files OK): %v", derr)
		}
		return fid, fsz, nil
	default:
		return "", 0, fmt.Errorf("backup: unknown backup_type %q", backupType)
	}
}

// backupFiles tars the site directory and uploads to B2.
func backupFiles(ctx context.Context, b2 *b2Client, siteID, siteDir, ts, tmpDir string) (string, int64, error) {
	archivePath := filepath.Join(tmpDir, fmt.Sprintf("site_%s_files_%s.tar.gz", siteID, ts))

	// Resolve symlinks so filepath.Walk inside tarGzDir sees a real directory,
	// not a dangling symlink entry (cgroup migration creates /home/site_X/public_html → /var/dnsfox/sites/…).
	if resolved, err := filepath.EvalSymlinks(siteDir); err == nil {
		siteDir = resolved
	}

	if err := tarGzDir(siteDir, archivePath); err != nil {
		return "", 0, fmt.Errorf("backup: tar: %w", err)
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("backup: read archive: %w", err)
	}

	fileName := fmt.Sprintf("sites/%s/files_%s.tar.gz", siteID, ts)
	fid, err := b2.uploadFile(ctx, fileName, data)
	if err != nil {
		return "", 0, fmt.Errorf("backup: b2 upload: %w", err)
	}

	log.Printf("[backup] site %s files uploaded to B2 (%d bytes)", siteID, len(data))
	return fid, int64(len(data)), nil
}

// backupDB dumps the MariaDB database for the site and uploads to B2.
// dbUsername is either the linux user (v1-cgroup: "site_X") or "db_{siteID}" (v2).
func backupDB(ctx context.Context, b2 *b2Client, siteID, dbUsername, ts, tmpDir string) (string, int64, error) {
	archivePath := filepath.Join(tmpDir, fmt.Sprintf("site_%s_db_%s.sql.gz", siteID, ts))

	// Prefer mariadb-dump (MariaDB 11+), fall back to mysqldump.
	dumpBin := "mariadb-dump"
	if _, err := exec.LookPath(dumpBin); err != nil {
		dumpBin = "mysqldump"
	}

	outFile, err := os.Create(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("backup db: create output: %w", err)
	}
	defer outFile.Close()

	gzw := gzip.NewWriter(outFile)
	defer gzw.Close()

	dumpCmd := exec.CommandContext(ctx,
		dumpBin, "-h", "127.0.0.1", "-P", "3307",
		"-u", dbUsername, dbUsername,
		"--single-transaction", "--quick", "--lock-tables=false")
	dumpCmd.Stdout = gzw

	if err := dumpCmd.Run(); err != nil {
		// DB may not exist (static/Node.js sites) — treat as non-fatal.
		log.Printf("[backup] db dump skipped for site %s (user=%s): %v", siteID, dbUsername, err)
		gzw.Close()  //nolint:errcheck
		outFile.Close() //nolint:errcheck
		return "", 0, nil
	}
	if err := gzw.Close(); err != nil {
		return "", 0, fmt.Errorf("backup db: gzip close: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return "", 0, fmt.Errorf("backup db: file close: %w", err)
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("backup db: read archive: %w", err)
	}
	if len(data) == 0 {
		return "", 0, nil
	}

	fileName := fmt.Sprintf("sites/%s/db_%s.sql.gz", siteID, ts)
	fid, err := b2.uploadFile(ctx, fileName, data)
	if err != nil {
		return "", 0, fmt.Errorf("backup db: b2 upload: %w", err)
	}

	log.Printf("[backup] site %s db uploaded to B2 (%d bytes)", siteID, len(data))
	return fid, int64(len(data)), nil
}

// tarGzDir creates a .tar.gz archive of srcDir at destPath.
func tarGzDir(srcDir, destPath string) error {
	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// For symlinks, read the link target so the tar header is accurate.
		var linkTarget string
		if info.Mode()&os.ModeSymlink != 0 {
			if linkTarget, err = os.Readlink(path); err != nil {
				return err
			}
		}

		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		hdr.Name = rel

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		// Only read content from regular files — dirs, symlinks, devices, FIFOs and
		// sockets all carry no byte content in the tar archive. Using IsRegular()
		// is the single correct guard; the previous IsDir()+ModeSymlink check missed
		// the case where filepath.Walk resolves a symlink-to-directory entry and
		// os.Open succeeds but Read returns EISDIR.
		if !info.Mode().IsRegular() {
			return nil
		}

		ff, err := os.Open(path)
		if err != nil {
			return err
		}
		defer ff.Close()
		_, err = io.Copy(tw, ff)
		return err
	})
}
