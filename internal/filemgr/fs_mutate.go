// fs_mutate.go — mutation ops split out of filemgr.go to keep files
// under the 300-line project cap. Covers Mkdir, Move and the shared
// mkdirAllOwned helper used by Write/Mkdir/Move for parent-chain setup.
package filemgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	// Build list of missing ancestors.
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
