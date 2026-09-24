//go:build windows

package ginTiny

import "syscall"

// brokenConnErrnos 表示对端已断开连接的错误码
var brokenConnErrnos = []syscall.Errno{
	syscall.WSAECONNRESET,     // 10054 连接被对端重置
	syscall.WSAECONNABORTED,   // 10053 连接被本机网络栈中止
	syscall.ERROR_BROKEN_PIPE, // 109 管道已结束
	232,                       // ERROR_NO_DATA 管道正在被关闭（syscall 包未定义该常量）
}
