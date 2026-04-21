package mariadb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
)

// Manager handles MariaDB database and user provisioning.
type Manager struct {
	RootUser     string
	RootPassword string
}

// NewManager creates a new MariaDB Manager.
// The administrative account is read from MARIADB_ROOT_USER (defaults to
// "root") and MARIADB_ROOT_PASSWORD env vars.  On hosts where root auth is
// unix_socket-only, provision a dedicated TCP user with GRANT OPTION and set
// MARIADB_ROOT_USER to that user.
func NewManager() *Manager {
	user := os.Getenv("MARIADB_ROOT_USER")
	if user == "" {
		user = "root"
	}
	return &Manager{
		RootUser:     user,
		RootPassword: os.Getenv("MARIADB_ROOT_PASSWORD"),
	}
}

// CreateSiteDatabase creates a MariaDB database and dedicated user for a site.
// Connects to 127.0.0.1:3307 (host MariaDB, not the Docker container on 3306).
// Credentials are written to /var/www/<username>/.db_credentials (mode 0600).
func (m *Manager) CreateSiteDatabase(siteID, username string) error {
	dbName := sanitizeID(siteID)
	dbUser := sanitizeID(siteID)

	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}

	// Grant is to 127.0.0.1, matching how PHP connects (DB_HOST=127.0.0.1).
	sql := fmt.Sprintf(`
CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '%s'@'127.0.0.1' IDENTIFIED BY '%s';
GRANT ALL PRIVILEGES ON %s.* TO '%s'@'127.0.0.1';
FLUSH PRIVILEGES;
`, dbName, dbUser, password, dbName, dbUser)

	if err := m.execSQL(sql); err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	credsPath := fmt.Sprintf("/var/www/%s/.db_credentials", username)
	creds := fmt.Sprintf("; DNSFox v2 — auto-generated credentials for site %s\n; Do not edit manually — managed by Warden\nDB_NAME=%s\nDB_USER=%s\nDB_PASS=%s\nDB_HOST=127.0.0.1\nDB_PORT=3307\n",
		siteID, dbName, dbUser, password)
	if err := os.WriteFile(credsPath, []byte(creds), 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// DropSiteDatabase removes the MariaDB database and user for a site.
func (m *Manager) DropSiteDatabase(siteID, username string) error {
	dbName := sanitizeID(siteID)
	dbUser := sanitizeID(siteID)

	sql := fmt.Sprintf(`
DROP DATABASE IF EXISTS %s;
DROP USER IF EXISTS '%s'@'127.0.0.1';
FLUSH PRIVILEGES;
`, dbName, dbUser)

	return m.execSQL(sql)
}

// execSQL executes a SQL string against the host MariaDB on 127.0.0.1:3307.
func (m *Manager) execSQL(sql string) error {
	args := []string{"-h", "127.0.0.1", "-P", "3307", "-u", m.RootUser}
	if m.RootPassword != "" {
		args = append(args, "-p"+m.RootPassword)
	}
	args = append(args, "-e", sql)

	cmd := exec.Command("mysql", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql error: %s: %w", out, err)
	}
	return nil
}

// sanitizeID converts a site ID to a safe database/user name.
// MariaDB identifiers must consist of [A-Za-z0-9_$] (unquoted), so hyphens
// from UUIDs are replaced with underscores.  Prefix db_ ensures it starts
// with a letter; capped at 16 chars for the ID part to keep total length
// well under the 64-char MariaDB identifier limit.
func sanitizeID(siteID string) string {
	// Strip hyphens before truncation so the 16 chars are dense.
	out := make([]byte, 0, len(siteID))
	for i := 0; i < len(siteID); i++ {
		c := siteID[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			// hyphens, dots, etc. become underscores
			out = append(out, '_')
		}
	}
	id := string(out)
	if len(id) > 16 {
		id = id[:16]
	}
	return "db_" + id
}

// generatePassword generates a cryptographically random 32-char hex password.
func generatePassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
