// sites.go — counts active v2 sites by enumerating the site user directories
// under /var/www. Each v2 site is provisioned with a directory named site_{id}.
// This approach is authoritative: if the directory exists, the site is present
// on this server regardless of what the control plane thinks.
package metrics

import (
	"os"
	"strings"
)

// CountSites returns the number of v2 sites currently hosted on this server.
// It counts directories under docrootBase (e.g. /var/www) whose names begin
// with "site_". This is a filesystem read and therefore O(n sites).
func CountSites(docrootBase string) int32 {
	entries, err := os.ReadDir(docrootBase)
	if err != nil {
		return 0
	}
	var count int32
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "site_") {
			count++
		}
	}
	return count
}
