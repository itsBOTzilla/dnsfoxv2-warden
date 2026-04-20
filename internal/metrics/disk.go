// disk.go — reports disk utilization for a given path using syscall.Statfs.
// We check /var/www (the v2 docroot base) rather than / because the site
// data partition is what we actually care about. On Durin they are the same
// filesystem, but this keeps the code correct if they are ever split.
package metrics

import (
	"fmt"
	"syscall"
)

// DiskStats holds block-device capacity figures for one filesystem.
type DiskStats struct {
	TotalGB float64
	UsedGB  float64
	FreeGB  float64
}

// ReadDisk returns capacity statistics for the filesystem containing path.
// path is typically "/var/www" for site storage or "/" for the root fs.
// Both values are in gigabytes.
func ReadDisk(path string) (DiskStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return DiskStats{}, fmt.Errorf("statfs %q: %w", path, err)
	}

	// Bsize is the fundamental block size in bytes.
	// Blocks = total filesystem blocks.
	// Bavail = blocks available to unprivileged processes (free - reserved).
	blockSize := uint64(st.Bsize)
	totalBytes := st.Blocks * blockSize
	freeBytes := st.Bavail * blockSize // use Bavail, not Bfree (excludes root reserve)
	usedBytes := totalBytes - (st.Bfree * blockSize) // actual used including reserved

	const gb = 1 << 30
	return DiskStats{
		TotalGB: float64(totalBytes) / gb,
		UsedGB:  float64(usedBytes) / gb,
		FreeGB:  float64(freeBytes) / gb,
	}, nil
}
