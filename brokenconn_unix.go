//go:build unix

package ginTiny

import "syscall"

// brokenConnErrnos 表示对端已断开连接的错误码
var brokenConnErrnos = []syscall.Errno{
	syscall.EPIPE,      // broken pipe
	syscall.ECONNRESET, // connection reset by peer
}
