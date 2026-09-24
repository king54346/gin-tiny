//go:build !unix && !windows

package ginTiny

// isBrokenConnErrno 在没有 syscall.Errno 的平台（如 plan9）上无法按错误码判断
func isBrokenConnErrno(error) bool { return false }
