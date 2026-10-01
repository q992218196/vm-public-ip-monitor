//go:build !linux

package evidence

func freeSpace(string, int64) bool { return true }
