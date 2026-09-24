package main

import (
	"os"
	"testing"
)

// skipUnlessManual 跳过需要常驻监听 :8080 的手动联调测试，
// 设置 GINTEST_MANUAL=1 后才会运行，避免 go test ./... 被阻塞。
func skipUnlessManual(t *testing.T) {
	t.Helper()
	if os.Getenv("GINTEST_MANUAL") == "" {
		t.Skip("manual test, set GINTEST_MANUAL=1 to run")
	}
}
