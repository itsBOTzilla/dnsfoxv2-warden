// receive.go — HTTP handler for inbound site migrations.
//
// The target warden exposes POST /migration/receive/{siteID} which accepts
// a multipart upload with two parts:
//   - "files"  — gzipped tar of /var/www/{username}/
//   - "db"     — mysqldump SQL file (optional; absent for sites with no DB)
//
// The handler:
//  1. Authenticates the request via Authorization: Bearer {token}
//  2. Extracts the tar over the existing docroot (created by ProvisionSite)
//  3. Imports the DB dump if present
//  4. Fixes file ownership so PHP-FPM / Node.js can serve the site
package migration

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

const (
	// maxUploadSize is the maximum total multipart upload accepted (10 GiB).
	maxUploadSize = 10 << 30
	// maxMemoryParse is the in-memory multipart buffer; files spill to disk.
	maxMemoryParse = 32 << 20
)

// ReceiveHandler returns an http.Handler for /migration/receive/{siteID}.
// token is the warden's own API token used to authenticate inbound pushes.
func ReceiveHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Authenticate with Bearer token.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract siteID from path: /migration/receive/{siteID}
		siteID := path.Base(r.URL.Path)
		if siteID == "" || siteID == "." {
			http.Error(w, "missing site id", http.StatusBadRequest)
			return
		}

		log.Printf("[migration:receive] inbound migration for site=%s", siteID)

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		if err := r.ParseMultipartForm(maxMemoryParse); err != nil {
			log.Printf("[migration:receive] parse form error: %v", err)
			http.Error(w, "parse form error: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer r.MultipartForm.RemoveAll() //nolint:errcheck

		username := provisioning.SiteUsername(siteID)
		docroot := fmt.Sprintf("/var/www/%s", username)

		// Extract files tarball.
		filesFile, _, err := r.FormFile("files")
		if err != nil {
			http.Error(w, "missing files part: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer filesFile.Close()
		if err := extractTarGz(filesFile, docroot); err != nil {
			log.Printf("[migration:receive] extract failed: %v", err)
			http.Error(w, "extract error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[migration:receive] files extracted to %s", docroot)

		// Import DB dump if present.
		dbFile, _, dbErr := r.FormFile("db")
		if dbErr == nil {
			defer dbFile.Close()
			if err := importDB(dbFile, siteID); err != nil {
				log.Printf("[migration:receive] db import error: %v", err)
				http.Error(w, "db import error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("[migration:receive] db imported for site=%s", siteID)
		}

		// Fix ownership after extraction.
		exec.Command("chown", "-R", username+":"+username, docroot).Run() //nolint:errcheck

		log.Printf("[migration:receive] migration receive complete for site=%s", siteID)
		w.WriteHeader(http.StatusOK)
	})
}

// extractTarGz extracts a gzipped tar stream into the destination directory.
// For security, it rejects paths with ".." components.
func extractTarGz(r io.Reader, dst string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// Guard against path traversal.
		if strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}

		target := filepath.Join(dst, filepath.FromSlash(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)|0700); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent: %w", err)
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
		}
	}
	return nil
}

// importDB pipes a SQL dump into mysql to restore the site database.
func importDB(r io.Reader, siteID string) error {
	dbName := "db_" + siteID
	if len(dbName) > 19 {
		dbName = dbName[:19]
	}

	args := []string{"-h", "127.0.0.1", "-P", "3307", "-u", "root"}
	rootPw := os.Getenv("MARIADB_ROOT_PASSWORD")
	if rootPw != "" {
		args = append(args, "-p"+rootPw)
	}
	args = append(args, dbName)

	cmd := exec.Command("mysql", args...)
	cmd.Stdin = r
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql import: %s: %w", out, err)
	}
	return nil
}
