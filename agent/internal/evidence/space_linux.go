//go:build linux

package evidence

import "syscall"

func freeSpace(path string, needed int64) bool {
	var s syscall.Statfs_t
	return syscall.Statfs(path, &s) == nil && uint64(s.Bavail)*uint64(s.Bsize) >= uint64(needed)
}
