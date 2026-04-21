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
	"time"
)

// BackupSite creates an archive of the site and uploads it to B2.
// backupType: "files", "db", or "full"
// Returns the B2 file ID, size in bytes, and any error.
func BackupSite(ctx context.Context, siteID, backupType, b2KeyID, b2AppKey, b2Bucket string) (fileID string, sizeBytes int64, err error) {
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

	username := "site_" + siteID
	siteDir := "/var/www/" + username

	switch backupType {
	case "files":
		return backupFiles(ctx, b2, siteID, siteDir, ts, tmpDir)
	case "db":
		return backupDB(ctx, b2, siteID, username, ts, tmpDir)
	case "full":
		fid, fsz, ferr := backupFiles(ctx, b2, siteID, siteDir, ts, tmpDir)
		if ferr != nil {
			return "", 0, ferr
		}
		_, _, derr := backupDB(ctx, b2, siteID, username, ts, tmpDir)
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
func backupDB(ctx context.Context, b2 *b2Client, siteID, username, ts, tmpDir string) (string, int64, error) {
	dbName := "db_" + siteID
	dbUser := "db_" + siteID
	archivePath := filepath.Join(tmpDir, fmt.Sprintf("site_%s_db_%s.sql.gz", siteID, ts))

	// Check if MySQL user exists.
	checkCmd := exec.CommandContext(ctx,
		"mysql", "-h", "127.0.0.1", "-P", "3307",
		"-u", "root", "-e",
		fmt.Sprintf("SELECT 1 FROM mysql.user WHERE User='%s' LIMIT 1", dbUser))
	if err := checkCmd.Run(); err != nil {
		return "", 0, fmt.Errorf("backup db: user %s not found (no DB for site): %w", dbUser, err)
	}

	outFile, err := os.Create(archivePath)
	if err != nil {
		return "", 0, fmt.Errorf("backup db: create output: %w", err)
	}
	defer outFile.Close()

	gzw := gzip.NewWriter(outFile)
	defer gzw.Close()

	dumpCmd := exec.CommandContext(ctx,
		"mysqldump", "-h", "127.0.0.1", "-P", "3307",
		"-u", dbUser, dbName,
		"--single-transaction", "--quick", "--lock-tables=false")
	dumpCmd.Stdout = gzw

	if err := dumpCmd.Run(); err != nil {
		return "", 0, fmt.Errorf("backup db: mysqldump: %w", err)
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

	fileName := fmt.Sprintf("sites/%s/db_%s.sql.gz", siteID, ts)
	fid, err := b2.uploadFile(ctx, fileName, data)
	if err != nil {
		return "", 0, fmt.Errorf("backup db: b2 upload: %w", err)
	}

	_ = username // kept for future logging
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
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
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
