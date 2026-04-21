// Package credsstore holds server-delivered credentials in memory.
// Values are populated from ConfigSyncDirective on each heartbeat.
// All operations are safe for concurrent use.
package credsstore

import "sync"

// B2Creds holds Backblaze B2 credentials delivered via the heartbeat sync directive.
type B2Creds struct {
	KeyID      string
	AppKey     string
	BucketName string
}

// MariaDBCreds holds the platform MariaDB root credentials delivered via the
// heartbeat sync directive. RootUser defaults to "root" if empty.
type MariaDBCreds struct {
	RootUser     string
	RootPassword string
}

var (
	mu             sync.RWMutex
	b2             B2Creds
	mariadb        MariaDBCreds
	wardenInternal string
)

// SetB2 stores new B2 credentials atomically.
func SetB2(creds B2Creds) {
	mu.Lock()
	defer mu.Unlock()
	b2 = creds
}

// GetB2 returns the current B2 credentials. Returns zero value if not set.
func GetB2() B2Creds {
	mu.RLock()
	defer mu.RUnlock()
	return b2
}

// SetMariaDB stores new MariaDB root credentials atomically.
func SetMariaDB(c MariaDBCreds) {
	mu.Lock()
	defer mu.Unlock()
	mariadb = c
}

// GetMariaDB returns the current MariaDB root credentials. RootUser defaults
// to "root" if no directive has been received yet.
func GetMariaDB() MariaDBCreds {
	mu.RLock()
	defer mu.RUnlock()
	c := mariadb
	if c.RootUser == "" {
		c.RootUser = "root"
	}
	return c
}

// SetWardenInternalToken stores the shared warden-internal-token that the
// v2 API uses for inbound mgmt calls.
func SetWardenInternalToken(tok string) {
	mu.Lock()
	defer mu.Unlock()
	wardenInternal = tok
}

// GetWardenInternalToken returns the current warden-internal-token.
func GetWardenInternalToken() string {
	mu.RLock()
	defer mu.RUnlock()
	return wardenInternal
}
