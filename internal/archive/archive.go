// Package archive implements per-site archive creation (zip and tar.gz)
// for the v2 file manager. It plugs into the same filemgr.Site resolution
// used by list/read/write so every path is validated inside docroot.
//
// Wire flow
//
//	POST /api/files/archive          → creates archive, returns {token,expires_at}
//	GET  /api/files/archive/{token}  → streams the bytes, unlinks the file
//
// Archives live in ArchiveDir (created lazily, 0700, owned by root).
// A background janitor deletes any file older than MaxAge — this bounds
// disk usage even if a client never redeems the token.
//
// Both endpoints are guarded by WARDEN_INTERNAL_TOKEN, same as file upload.
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/filemgr"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

const (
	// ArchiveDir is where generated archives live until redeemed or expired.
	ArchiveDir = "/var/tmp/filemgr-archives"
	// MaxAge is the oldest an unredeemed archive may live before the janitor wipes it.
	MaxAge = 10 * time.Minute
	// MaxArchiveBytes caps the uncompressed payload at 2 GiB to bound disk use.
	MaxArchiveBytes = 2 * 1024 * 1024 * 1024
)

// FormatZip / FormatTarGz are the supported archive formats.
const (
	FormatZip   = "zip"
	FormatTarGz = "tar.gz"
)

// entry tracks a pending archive awaiting download.
type entry struct {
	path      string
	expiresAt time.Time
}

// registry is the in-memory token → archive map.
type registry struct {
	mu      sync.Mutex
	entries map[string]entry
}

var reg = &registry{entries: make(map[string]entry)}

// StartJanitor launches the background cleanup goroutine. Callers should
// spawn it once from main; it exits when ctx is cancelled.
func StartJanitor() {
	if err := os.MkdirAll(ArchiveDir, 0700); err != nil {
		log.Printf("[archive] mkdir %s: %v", ArchiveDir, err)
	}
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			sweep()
		}
	}()
}

// sweep deletes expired archives, on disk and in the registry.
func sweep() {
	now := time.Now()
	reg.mu.Lock()
	var toDel []string
	for tok, e := range reg.entries {
		if now.After(e.expiresAt) {
			toDel = append(toDel, tok)
			_ = os.Remove(e.path)
		}
	}
	for _, tok := range toDel {
		delete(reg.entries, tok)
	}
	reg.mu.Unlock()

	// Also scrub any stray files on disk with mtime older than 2×MaxAge —
	// catches archives orphaned across restarts.
	entries, _ := os.ReadDir(ArchiveDir)
	for _, de := range entries {
		info, err := de.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 2*MaxAge {
			_ = os.Remove(filepath.Join(ArchiveDir, de.Name()))
		}
	}
}

// createRequest mirrors the JSON body accepted by POST /api/files/archive.
type createRequest struct {
	SiteID string   `json:"site_id"`
	Paths  []string `json:"paths"`
	Format string   `json:"format"`
}

// createResponse is the JSON body returned on success.
type createResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	SizeBytes int64  `json:"size_bytes"`
}

// CreateHandler returns POST handler for /api/files/archive.
func CreateHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if !checkBearer(token, r) {
			httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req createRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if req.SiteID == "" || len(req.Paths) == 0 {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "site_id and paths required"})
			return
		}
		format := strings.ToLower(req.Format)
		if format == "" {
			format = FormatZip
		}
		if format != FormatZip && format != FormatTarGz {
			httpJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be zip or tar.gz"})
			return
		}

		site, err := filemgr.LookupSite(provisioning.SiteUsername(req.SiteID))
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}

		tok, info, err := buildArchive(site, req.Paths, format)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		httpJSON(w, http.StatusOK, createResponse{
			Token:     tok,
			ExpiresAt: info.expiresAt.UTC().Format(time.RFC3339),
			SizeBytes: sizeOnDisk(info.path),
		})
	})
}

// DownloadHandler serves GET /api/files/archive/{token}. One-shot: the file is
// deleted after the body is flushed (successful or not — the token is dead once used).
func DownloadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tok := strings.TrimPrefix(r.URL.Path, "/api/files/archive/")
		if tok == "" || strings.ContainsAny(tok, "/?#") {
			http.Error(w, "bad token", http.StatusBadRequest)
			return
		}

		reg.mu.Lock()
		e, ok := reg.entries[tok]
		if ok {
			delete(reg.entries, tok) // one-shot
		}
		reg.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer os.Remove(e.path)
		if time.Now().After(e.expiresAt) {
			http.Error(w, "expired", http.StatusGone)
			return
		}

		f, err := os.Open(e.path)
		if err != nil {
			http.Error(w, "open archive: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", contentTypeFor(e.path))
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(e.path)))
		if st, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
		}
		_, _ = io.Copy(w, f)
	})
}

// buildArchive packs paths (all relative to docroot) into a new archive file
// under ArchiveDir and registers a one-time token for download.
func buildArchive(site *filemgr.Site, relPaths []string, format string) (string, entry, error) {
	if err := os.MkdirAll(ArchiveDir, 0700); err != nil {
		return "", entry{}, fmt.Errorf("mkdir archive dir: %w", err)
	}
	tok, err := randomToken()
	if err != nil {
		return "", entry{}, err
	}
	ext := ".zip"
	if format == FormatTarGz {
		ext = ".tar.gz"
	}
	out := filepath.Join(ArchiveDir, tok+ext)
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return "", entry{}, fmt.Errorf("create archive file: %w", err)
	}
	// cw is a size-capping writer so a malicious path set can't fill the disk.
	cw := &cappedWriter{w: f, max: MaxArchiveBytes}
	var buildErr error
	if format == FormatZip {
		buildErr = writeZip(cw, site, relPaths)
	} else {
		buildErr = writeTarGz(cw, site, relPaths)
	}
	closeErr := f.Close()
	if buildErr != nil {
		_ = os.Remove(out)
		return "", entry{}, buildErr
	}
	if closeErr != nil {
		_ = os.Remove(out)
		return "", entry{}, closeErr
	}

	e := entry{path: out, expiresAt: time.Now().Add(MaxAge)}
	reg.mu.Lock()
	reg.entries[tok] = e
	reg.mu.Unlock()
	return tok, e, nil
}

// cappedWriter returns errQuotaExceeded once total bytes exceed max.
type cappedWriter struct {
	w   io.Writer
	max int64
	n   int64
}

var errQuotaExceeded = errors.New("archive exceeds maximum size")

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > c.max {
		return 0, errQuotaExceeded
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// writeZip walks each relPath and adds it to zip. Directories are recursed.
func writeZip(w io.Writer, site *filemgr.Site, relPaths []string) error {
	zw := zip.NewWriter(w)
	for _, rel := range relPaths {
		if err := addToZip(zw, site, rel); err != nil {
			_ = zw.Close()
			return err
		}
	}
	return zw.Close()
}

func addToZip(zw *zip.Writer, site *filemgr.Site, rel string) error {
	abs, err := resolveSitePath(site, rel)
	if err != nil {
		return err
	}
	return filepath.Walk(abs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Compute archive-internal name relative to docroot.
		name, relErr := filepath.Rel(site.Docroot, p)
		if relErr != nil {
			return relErr
		}
		name = filepath.ToSlash(name)
		if info.IsDir() {
			// Zip dirs are represented with a trailing slash.
			if name != "." {
				_, err = zw.Create(name + "/")
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil // skip symlinks/sockets/devices
		}
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(info.Mode())
		hdr.Modified = info.ModTime()
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(fw, f)
		return err
	})
}

// writeTarGz walks each relPath into a tar stream wrapped in gzip.
func writeTarGz(w io.Writer, site *filemgr.Site, relPaths []string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, rel := range relPaths {
		if err := addToTar(tw, site, rel); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

func addToTar(tw *tar.Writer, site *filemgr.Site, rel string) error {
	abs, err := resolveSitePath(site, rel)
	if err != nil {
		return err
	}
	return filepath.Walk(abs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name, relErr := filepath.Rel(site.Docroot, p)
		if relErr != nil {
			return relErr
		}
		name = filepath.ToSlash(name)
		if name == "." {
			return nil
		}
		hdr, hErr := tar.FileInfoHeader(info, "")
		if hErr != nil {
			return hErr
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, oErr := os.Open(p)
		if oErr != nil {
			return oErr
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

// resolveSitePath reuses the filemgr docroot-traversal guard to turn a
// user-supplied relative path into an absolute filesystem path.
// It exists here so archive doesn't have to duplicate the guard logic.
func resolveSitePath(site *filemgr.Site, rel string) (string, error) {
	// filemgr.Site.resolvePath is unexported — re-implement the check here,
	// keeping the same rules (no "..", no null byte, no escape from docroot).
	if strings.Contains(rel, "\x00") {
		return "", filemgr.ErrPathTraversal
	}
	clean := strings.TrimSpace(rel)
	for strings.HasPrefix(clean, "/") {
		clean = clean[1:]
	}
	if clean == "" || clean == "." {
		return site.Docroot, nil
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return "", filemgr.ErrPathTraversal
		}
	}
	abs := filepath.Clean(filepath.Join(site.Docroot, clean))
	if abs != site.Docroot && !strings.HasPrefix(abs, site.Docroot+string(os.PathSeparator)) {
		return "", filemgr.ErrPathTraversal
	}
	return abs, nil
}

// checkBearer validates Authorization: Bearer <token> in constant time.
func checkBearer(expected string, r *http.Request) bool {
	if expected == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// randomToken returns 32 hex chars (128 bits of entropy).
func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func contentTypeFor(path string) string {
	if strings.HasSuffix(path, ".tar.gz") {
		return "application/gzip"
	}
	return "application/zip"
}

func sizeOnDisk(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.Size()
}

func httpJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
