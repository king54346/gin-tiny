//go:build unix || windows

package ginTiny

import (
	"errors"
	"slices"
	"syscall"
)

// isBrokenConnErrno 按错误码判断是否为「对端已断开连接」。
// 错误信息是本地化文本（例如中文 Windows 上是中文），只能按错误码判断才可靠
func isBrokenConnErrno(err error) bool {
	errno, ok := errors.AsType[syscall.Errno](err)
	return ok && slices.Contains(brokenConnErrnos, errno)
}
