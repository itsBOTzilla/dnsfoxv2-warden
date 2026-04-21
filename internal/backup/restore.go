// Package backup — restore.go provides site restore from B2 backups.
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
	"strings"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// RestoreSite downloads a backup from B2 and restores it to the site directory.
// restoreType: "files" or "db"
func RestoreSite(ctx context.Context, siteID, fileID, restoreType, b2KeyID, b2AppKey string) error {
	if err := validateSiteID(siteID); err != nil {
		return err
	}
	b2, err := newB2Client(ctx, b2KeyID, b2AppKey, "")
	if err != nil {
		return fmt.Errorf("restore: b2 auth: %w", err)
	}

	data, err := b2.downloadFile(ctx, fileID)
	if err != nil {
		return fmt.Errorf("restore: download: %w", err)
	}

	switch restoreType {
	case "files":
		return restoreFiles(ctx, siteID, data)
	case "db":
		return restoreDB(ctx, siteID, data)
	default:
		return fmt.Errorf("restore: unknown restore_type %q", restoreType)
	}
}

// restoreFiles extracts a tar.gz archive into the site directory.
func restoreFiles(ctx context.Context, siteID string, data []byte) error {
	username := provisioning.SiteUsername(siteID)
	destDir := "/var/www/" + username

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("restore files: mkdir: %w", err)
	}

	// Write archive to a temp file, then extract.
	tmp, err := os.CreateTemp("", "dnsfox-restore-*.tar.gz")
	if err != nil {
		return fmt.Errorf("restore files: mktemp: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("restore files: write tmp: %w", err)
	}
	tmp.Close()

	if err := extractTarGz(tmp.Name(), destDir); err != nil {
		return fmt.Errorf("restore files: extract: %w", err)
	}

	// Fix ownership.
	exec.CommandContext(ctx, "chown", "-R", username+":"+username, destDir).Run() //nolint:errcheck

	// Reload PHP-FPM and Nginx.
	reloadAfterRestore(ctx, siteID)

	log.Printf("[restore] site %s files restored", siteID)
	return nil
}

// restoreDB imports a .sql.gz dump into the site database.
func restoreDB(ctx context.Context, siteID string, data []byte) error {
	dbName := "db_" + siteID
	dbUser := "db_" + siteID

	// Write compressed dump to temp file.
	tmp, err := os.CreateTemp("", "dnsfox-restore-db-*.sql.gz")
	if err != nil {
		return fmt.Errorf("restore db: mktemp: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("restore db: write tmp: %w", err)
	}
	tmp.Close()

	// Decompress and pipe to mysql.
	f, err := os.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("restore db: open tmp: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("restore db: gzip reader: %w", err)
	}
	defer gzr.Close()

	mysqlCmd := exec.CommandContext(ctx,
		"mysql", "-h", "127.0.0.1", "-P", "3307",
		"-u", dbUser, dbName)
	mysqlCmd.Stdin = gzr

	out, err := mysqlCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restore db: mysql import: %s: %w", out, err)
	}

	log.Printf("[restore] site %s db restored", siteID)
	return nil
}

// extractTarGz extracts a tar.gz archive into destDir with path traversal protection.
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		// Path traversal guard.
		if strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("tar: path traversal attempt: %q", hdr.Name)
		}

		target := filepath.Join(destDir, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) && target != filepath.Clean(destDir) {
			return fmt.Errorf("tar: illegal path: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return err
			}
			ff, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(ff, tr); err != nil {
				ff.Close()
				return err
			}
			ff.Close()
		}
	}
	return nil
}

// reloadAfterRestore reloads PHP-FPM and Nginx after a files restore.
func reloadAfterRestore(ctx context.Context, siteID string) {
	for _, version := range []string{"8.2", "8.3", "8.4"} {
		var svc string
		if version == "8.4" {
			svc = "php8.4-fpm"
		} else {
			svc = "php" + version + "-fpm-dnsfox"
		}
		exec.CommandContext(ctx, "systemctl", "reload", svc).Run() //nolint:errcheck
	}
	exec.CommandContext(ctx, "systemctl", "reload", "nginx").Run() //nolint:errcheck
}
