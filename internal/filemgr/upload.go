// upload.go — HTTP multipart upload handler for the v2 file manager.
//
// POST /api/files/upload?site_id=<uuid>&path=<rel-dir>
//   Authorization: Bearer <warden-shared-token>
//   multipart/form-data with one or more "file" parts.
//
// Each uploaded file is atomically written into <docroot>/<path>/<filename>
// via filemgr.Site.Write (which handles chown + path traversal guard).
// Max 50 MiB per file.
package filemgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// MaxUploadPerFile caps a single upload at 50 MiB.
const MaxUploadPerFile = 50 * 1024 * 1024

// MaxUploadTotal caps the whole multipart envelope at 128 MiB.
const MaxUploadTotal = 128 * 1024 * 1024

// UploadHandler returns an http.Handler guarded by bearer token.
// token is matched verbatim against the Authorization header.
func UploadHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if token == "" {
			httpError(w, http.StatusInternalServerError, "upload not configured")
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		siteID := r.URL.Query().Get("site_id")
		destPath := r.URL.Query().Get("path")
		if siteID == "" {
			httpError(w, http.StatusBadRequest, "site_id required")
			return
		}

		site, err := LookupSite(provisioning.SiteUsername(siteID))
		if err != nil {
			httpError(w, http.StatusNotFound, err.Error())
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadTotal)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			httpError(w, http.StatusBadRequest, "parse form: "+err.Error())
			return
		}
		defer r.MultipartForm.RemoveAll() //nolint:errcheck

		files := r.MultipartForm.File["file"]
		if len(files) == 0 {
			// Some clients use "files" (plural).
			files = r.MultipartForm.File["files"]
		}
		if len(files) == 0 {
			httpError(w, http.StatusBadRequest, "no file part")
			return
		}

		type result struct {
			Name  string `json:"name"`
			Size  int64  `json:"size"`
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
		}
		out := make([]result, 0, len(files))

		for _, fh := range files {
			res := result{Name: fh.Filename, Size: fh.Size}
			if fh.Size > MaxUploadPerFile {
				res.Error = "file exceeds 50 MiB limit"
				out = append(out, res)
				continue
			}
			base := filepath.Base(fh.Filename)
			if base == "" || base == "." || base == "/" || strings.Contains(base, "..") {
				res.Error = "invalid filename"
				out = append(out, res)
				continue
			}
			rel := filepath.Join(destPath, base)
			if err := writeUpload(site, rel, fh); err != nil {
				res.Error = err.Error()
				log.Printf("[filemgr:upload] site=%s file=%s: %v", siteID, base, err)
				out = append(out, res)
				continue
			}
			res.OK = true
			out = append(out, res)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
	})
}

// writeUpload streams the uploaded file to memory (bounded) then hands it
// to the atomic Write path. We cap at MaxUploadPerFile via the fh.Size
// check above, so memory growth is bounded.
func writeUpload(site *Site, rel string, fh *multipart.FileHeader) error {
	f, err := fh.Open()
	if err != nil {
		return fmt.Errorf("open upload: %w", err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, MaxUploadPerFile+1))
	if err != nil {
		return err
	}
	if int64(len(buf)) > MaxUploadPerFile {
		return errors.New("file exceeds 50 MiB limit")
	}
	return site.Write(rel, buf, 0644)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
