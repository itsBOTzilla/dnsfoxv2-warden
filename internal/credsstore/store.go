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

var (
	mu sync.RWMutex
	b2 B2Creds
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
