// Package filemgr implements the v2 per-site file manager.
//
// All filesystem operations execute with the site's Linux uid/gid so that
// created files end up owned by the correct system user (matching what
// PHP-FPM / Node.js expects). Operations run as the warden process (root)
// for syscalls; we manually chown, and all I/O is confined to the site's
// docroot via strict path validation.
package filemgr

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MaxReadBytes caps ReadFile output at 10 MiB.
const MaxReadBytes = 10 * 1024 * 1024

// MaxWriteBytes caps WriteFile input at 10 MiB (same envelope as reads).
const MaxWriteBytes = 10 * 1024 * 1024

// ErrTooLarge is returned when a file exceeds the allowed size.
var ErrTooLarge = errors.New("filemgr: file exceeds size limit")

// ErrPathTraversal is returned when a caller-supplied path escapes docroot.
var ErrPathTraversal = errors.New("filemgr: path traversal rejected")

// ErrNotEmpty is returned when deleting a non-empty dir without recursive=true.
var ErrNotEmpty = errors.New("filemgr: directory not empty (pass recursive=true)")

// Entry mirrors the proto FileEntry.
type Entry struct {
	Name     string
	IsDir    bool
	Size     int64
	ModTime  time.Time
	Mode     uint32
}

// Site bundles the per-site identity needed for every op.
type Site struct {
	Username string // e.g. site_ef4e3b49-85cc-4
	Docroot  string // e.g. /var/www/site_xxx/public
	UID      uint32
	GID      uint32
}

// LookupSite resolves username → uid/gid and builds the docroot path.
// The docroot is rooted at /var/www/<username>/public (matches provisioning).
func LookupSite(username string) (*Site, error) {
	if username == "" || !strings.HasPrefix(username, "site_") {
		return nil, fmt.Errorf("filemgr: invalid site username %q", username)
	}
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("filemgr: user lookup %s: %w", username, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("filemgr: parse uid: %w", err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("filemgr: parse gid: %w", err)
	}
	docroot := filepath.Join("/var/www", username, "public")
	return &Site{
		Username: username,
		Docroot:  docroot,
		UID:      uint32(uid),
		GID:      uint32(gid),
	}, nil
}

// resolvePath joins rel under docroot and rejects anything escaping docroot.
// Empty / "/" / "." all map to docroot itself. Rejects any ".." component.
func (s *Site) resolvePath(rel string) (string, error) {
	if strings.Contains(rel, "\x00") {
		return "", ErrPathTraversal
	}
	// Normalise and strip leading slashes so filepath.Join treats it relative.
	clean := strings.TrimSpace(rel)
	for strings.HasPrefix(clean, "/") {
		clean = clean[1:]
	}
	if clean == "" || clean == "." {
		return s.Docroot, nil
	}
	// Reject any ".." component outright — even if Join would resolve it.
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return "", ErrPathTraversal
		}
	}
	abs := filepath.Clean(filepath.Join(s.Docroot, clean))
	if abs != s.Docroot && !strings.HasPrefix(abs, s.Docroot+string(os.PathSeparator)) {
		return "", ErrPathTraversal
	}
	return abs, nil
}

// List returns directory entries at rel (relative to docroot).
func (s *Site) List(rel string) ([]Entry, error) {
	abs, err := s.resolvePath(rel)
	if err != nil {
		return nil, err
	}
	// Ensure docroot exists — create it lazily (owned by site user) if missing.
	if err := s.ensureDocroot(); err != nil {
		return nil, err
	}
	dirents, err := os.ReadDir(abs)
	if err != nil {
		return nil, fmt.Errorf("filemgr: readdir %s: %w", rel, err)
	}
	out := make([]Entry, 0, len(dirents))
	for _, d := range dirents {
		info, err := d.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{
			Name:    d.Name(),
			IsDir:   d.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Mode:    uint32(info.Mode().Perm()),
		})
	}
	return out, nil
}

// Read returns up to MaxReadBytes of the file at rel.
func (s *Site) Read(rel string) ([]byte, fs.FileInfo, error) {
	abs, err := s.resolvePath(rel)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("filemgr: stat %s: %w", rel, err)
	}
	if info.IsDir() {
		return nil, nil, fmt.Errorf("filemgr: %s is a directory", rel)
	}
	if info.Size() > MaxReadBytes {
		return nil, info, ErrTooLarge
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("filemgr: open %s: %w", rel, err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, MaxReadBytes+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(buf)) > MaxReadBytes {
		return nil, info, ErrTooLarge
	}
	return buf, info, nil
}

// Write atomically writes content to rel with the given mode, owned by the
// site user. mode=0 → 0644.
func (s *Site) Write(rel string, content []byte, mode uint32) error {
	if int64(len(content)) > MaxWriteBytes {
		return ErrTooLarge
	}
	abs, err := s.resolvePath(rel)
	if err != nil {
		return err
	}
	if abs == s.Docroot {
		return fmt.Errorf("filemgr: refusing to write docroot as a file")
	}
	if mode == 0 {
		mode = 0644
	}
	if err := s.ensureDocroot(); err != nil {
		return err
	}
	// Ensure parent dir exists.
	parent := filepath.Dir(abs)
	if err := s.mkdirAllOwned(parent, 0755); err != nil {
		return err
	}
	// Atomic tmp + rename.
	tmp, err := os.CreateTemp(parent, ".filemgr-*")
	if err != nil {
		return fmt.Errorf("filemgr: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, os.FileMode(mode&0777)); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chown(tmpName, int(s.UID), int(s.GID)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("filemgr: chown: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Delete removes a file or empty directory. If recursive is true, non-empty
// directories are removed with RemoveAll.
func (s *Site) Delete(rel string, recursive bool) error {
	abs, err := s.resolvePath(rel)
	if err != nil {
		return err
	}
	if abs == s.Docroot {
		return fmt.Errorf("filemgr: refusing to delete docroot")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("filemgr: stat: %w", err)
	}
	if !info.IsDir() {
		return os.Remove(abs)
	}
	if recursive {
		return os.RemoveAll(abs)
	}
	// Empty-only delete.
	entries, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return ErrNotEmpty
	}
	return os.Remove(abs)
}

// Mkdir creates rel (and any missing parents) owned by the site user.
// mode=0 → 0755.
func (s *Site) Mkdir(rel string, mode uint32) error {
	abs, err := s.resolvePath(rel)
	if err != nil {
		return err
	}
	if abs == s.Docroot {
		return nil
	}
	if mode == 0 {
		mode = 0755
	}
	return s.mkdirAllOwned(abs, os.FileMode(mode&0777))
}

// Move renames from → to within docroot. Parent of destination is created if missing.
func (s *Site) Move(from, to string) error {
	src, err := s.resolvePath(from)
	if err != nil {
		return err
	}
	dst, err := s.resolvePath(to)
	if err != nil {
		return err
	}
	if src == s.Docroot || dst == s.Docroot {
		return fmt.Errorf("filemgr: refusing to move docroot")
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("filemgr: source stat: %w", err)
	}
	if err := s.mkdirAllOwned(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

// ensureDocroot creates /var/www/<user>/public owned by the site user
// if the tree is missing. Idempotent.
func (s *Site) ensureDocroot() error {
	return s.mkdirAllOwned(s.Docroot, 0750)
}

// mkdirAllOwned is like os.MkdirAll but chowns any newly-created directories
// to the site user. Existing directories are left untouched.
func (s *Site) mkdirAllOwned(abs string, mode os.FileMode) error {
	if !strings.HasPrefix(abs, s.Docroot) && abs != filepath.Dir(s.Docroot) && abs != "/var/www/"+s.Username {
		// Allow the docroot chain up through /var/www/<user>/public
		allowed := []string{
			"/var/www/" + s.Username,
			s.Docroot,
		}
		ok := false
		for _, p := range allowed {
			if abs == p {
				ok = true
				break
			}
		}
		if !ok && !strings.HasPrefix(abs, s.Docroot+string(os.PathSeparator)) {
			return ErrPathTraversal
		}
	}
	if _, err := os.Stat(abs); err == nil {
		return nil
	}
	// Build list of missing ancestors (up to docroot's parent dir).
	var missing []string
	cur := abs
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		missing = append([]string{cur}, missing...)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	for _, p := range missing {
		if err := os.Mkdir(p, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("filemgr: mkdir %s: %w", p, err)
		}
		if err := os.Chown(p, int(s.UID), int(s.GID)); err != nil {
			return fmt.Errorf("filemgr: chown %s: %w", p, err)
		}
	}
	return nil
}

// _ suppresses "imported and not used" while we keep syscall for future cred drops.
var _ = syscall.Stat_t{}
