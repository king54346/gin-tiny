package ginTiny

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMode 临时切换 gin 模式，测试结束后恢复
func withMode(t *testing.T, mode string) {
	t.Helper()
	old := Mode()
	SetMode(mode)
	t.Cleanup(func() { SetMode(old) })
}

func TestRecoveryReturns500AndLogsStack(t *testing.T) {
	var buf bytes.Buffer
	r := New()
	r.Use(RecoveryWithWriter(&buf))
	r.GET("/panic", func(c Context) { panic("boom") })

	w := PerformRequest(r, http.MethodGet, "/panic")
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	log := buf.String()
	assert.Contains(t, log, "panic recovered")
	assert.Contains(t, log, "boom")
	// 堆栈中包含 panic 所在的函数和源码行
	assert.Contains(t, log, "TestRecoveryReturns500AndLogsStack")
	assert.Contains(t, log, `panic("boom")`)
}

// requestDump 截取恢复日志中的请求转储部分（请求行到空行），不含堆栈；
// 堆栈会打印源码行，测试代码里的字面量也会出现在其中，不能直接对整段日志断言
func requestDump(log string) string {
	_, after, ok := strings.Cut(log, "panic recovered:\n")
	if !ok {
		return ""
	}
	rest := after
	before, _, ok := strings.Cut(rest, "\r\n\r\n")
	if !ok {
		return ""
	}
	return before
}

func TestRecoveryRedactsAuthorizationInDebugMode(t *testing.T) {
	withMode(t, DebugMode)
	var buf bytes.Buffer
	r := New()
	r.Use(RecoveryWithWriter(&buf))
	r.GET("/panic", func(c Context) { panic("boom") })

	PerformRequest(r, http.MethodGet, "/panic", header{Key: "Authorization", Value: "Bearer top-secret"}, header{Key: "X-Trace", Value: "t1"})

	dump := requestDump(buf.String())
	assert.Contains(t, dump, "GET /panic HTTP/1.1")
	assert.Contains(t, dump, "Authorization: *")
	assert.NotContains(t, dump, "top-secret")
	// debug 模式下其余请求头原样输出，便于排查
	assert.Contains(t, dump, "X-Trace: t1")
}

func TestRecoveryOmitsHeadersOutsideDebugMode(t *testing.T) {
	withMode(t, ReleaseMode)
	var buf bytes.Buffer
	r := New()
	r.Use(RecoveryWithWriter(&buf))
	r.GET("/panic", func(c Context) { panic("boom") })

	PerformRequest(r, http.MethodGet, "/panic", header{Key: "X-Trace", Value: "t1"})
	assert.Contains(t, buf.String(), "boom")
	assert.Empty(t, requestDump(buf.String()), "request headers must not be logged outside debug mode")
}

func TestCustomRecovery(t *testing.T) {
	DefaultErrorWriter = io.Discard
	t.Cleanup(func() { DefaultErrorWriter = os.Stderr })

	r := New()
	r.Use(CustomRecovery(func(c Context, err any) {
		c.String(http.StatusBadGateway, "recovered: %v", err)
	}))
	r.GET("/panic", func(c Context) { panic(errors.New("db down")) })

	w := PerformRequest(r, http.MethodGet, "/panic")
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, "recovered: db down", w.Body.String())
}

func TestRecoveryUsesDefaultErrorWriter(t *testing.T) {
	var buf bytes.Buffer
	DefaultErrorWriter = &buf
	t.Cleanup(func() { DefaultErrorWriter = os.Stderr })

	r := New()
	r.Use(Recovery())
	r.GET("/panic", func(c Context) { panic("to default writer") })

	assert.Equal(t, http.StatusInternalServerError, PerformRequest(r, http.MethodGet, "/panic").Code)
	assert.Contains(t, buf.String(), "to default writer")
}

func TestRecoveryWithNilWriterDoesNotLog(t *testing.T) {
	r := New()
	r.Use(RecoveryWithWriter(nil))
	r.GET("/panic", func(c Context) { panic("silent") })
	assert.Equal(t, http.StatusInternalServerError, PerformRequest(r, http.MethodGet, "/panic").Code)
}

// http.ErrAbortHandler 是标准库约定的静默中止信号，必须原样交还给 net/http
func TestRecoveryRepanicsErrAbortHandler(t *testing.T) {
	r := New()
	r.Use(RecoveryWithWriter(nil))
	r.GET("/abort", func(c Context) { panic(http.ErrAbortHandler) })
	r.GET("/wrapped", func(c Context) { panic(fmt.Errorf("proxy: %w", http.ErrAbortHandler)) })

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() { PerformRequest(r, http.MethodGet, "/abort") })
	assert.Panics(t, func() { PerformRequest(r, http.MethodGet, "/wrapped") })
}

// realConnResetError 产生一个真实的「对端重置连接」写错误（错误码、错误信息都来自操作系统）
func realConnResetError(t *testing.T) error {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		// SO_LINGER=0：关闭时发送 RST 而不是 FIN
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	}()
	s, err := l.Accept()
	require.NoError(t, err)
	defer s.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.Write(make([]byte, 64<<10)); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected write to fail after the peer reset the connection")
	return nil
}

// 客户端断开引起的 panic：不打印堆栈、不调用处理函数（连接已断，无法再写响应），只记录错误
func TestRecoveryBrokenConnection(t *testing.T) {
	resetErr := realConnResetError(t)
	require.True(t, isBrokenPipe(resetErr), "real connection reset must be detected: %v", resetErr)

	var buf bytes.Buffer
	var recorded errorMsgs
	handled := false
	r := New()
	r.Use(func(c Context) {
		c.Next()
		recorded = c.Errors()
	})
	r.Use(CustomRecoveryWithWriter(&buf, func(c Context, err any) { handled = true }))
	r.GET("/", func(c Context) { panic(resetErr) })

	PerformRequest(r, http.MethodGet, "/")

	assert.False(t, handled, "recovery handler must not run for a broken connection")
	if assert.Len(t, recorded, 1) {
		assert.ErrorIs(t, recorded[0], resetErr)
	}
	assert.NotContains(t, buf.String(), "panic recovered", "no stack trace for a broken connection")
}

func TestIsBrokenPipe(t *testing.T) {
	assert.False(t, isBrokenPipe("not an error"))
	assert.False(t, isBrokenPipe(errors.New("broken pipe")), "only syscall errors are considered")
	// 兜底：按英文错误信息匹配
	assert.True(t, isBrokenPipe(os.NewSyscallError("write", errors.New("broken pipe"))))
	assert.True(t, isBrokenPipe(os.NewSyscallError("write", errors.New("Connection reset by peer"))))
	assert.False(t, isBrokenPipe(os.NewSyscallError("write", errors.New("no space left on device"))))

	// 按错误码判断：包装多层也能识别
	for _, errno := range brokenConnErrnos {
		err := &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", errno)}
		assert.True(t, isBrokenPipe(fmt.Errorf("handler: %w", err)), "errno %d", uintptr(errno))
	}
}

func TestStackHelpers(t *testing.T) {
	lines := [][]byte{[]byte("  first  "), []byte("second")}
	assert.Equal(t, []byte("first"), source(lines, 1))
	assert.Equal(t, dunno, source(lines, 0))
	assert.Equal(t, dunno, source(lines, 3))

	assert.Equal(t, dunno, function(0))
	// 去掉包路径，只保留函数名
	st := string(stack(0))
	assert.Contains(t, st, "TestStackHelpers")
	assert.NotContains(t, strings.SplitN(st, "\n", 3)[1], "github.com/king54346")

	assert.Equal(t, "2026/01/02 - 03:04:05", timeFormat(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)))
}

func TestRecoveryRedactsSensitiveHeaders(t *testing.T) {
	withMode(t, DebugMode)
	var buf bytes.Buffer
	r := New()
	r.Use(RecoveryWithWriter(&buf))
	r.GET("/token:x", func(c Context) { panic("boom") })

	secret := strings.Repeat("s", 3) + "-leak" // 避免字面量出现在堆栈打印的源码行中
	PerformRequest(r, http.MethodGet, "/token:x",
		header{Key: "Authorization", Value: secret},
		header{Key: "Proxy-Authorization", Value: secret},
		header{Key: "Cookie", Value: "sid=" + secret},
		header{Key: "X-Api-Key", Value: secret},
		header{Key: "X-Auth-Token", Value: secret},
		header{Key: "X-Custom-Secret", Value: secret},
		header{Key: "X-Trace", Value: "t1"},
	)

	dump := requestDump(buf.String())
	assert.NotContains(t, dump, secret)
	for _, k := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Custom-Secret"} {
		assert.Contains(t, dump, k+": *")
	}
	assert.Contains(t, dump, "X-Trace: t1", "non-sensitive headers are kept for debugging")
	assert.True(t, strings.HasPrefix(dump, "GET /token:x HTTP/1.1"), "the request line must not be altered: %q", dump)
}

func TestIsSensitiveHeader(t *testing.T) {
	for _, h := range []string{"Authorization", "cookie", "Set-Cookie", "X-API-KEY", "X-Apikey", "X-CSRF-Token", "X-Session-Id", "X-Hub-Signature"} {
		assert.True(t, isSensitiveHeader(h), h)
	}
	for _, h := range []string{"Accept", "User-Agent", "X-Request-Id", "Content-Type"} {
		assert.False(t, isSensitiveHeader(h), h)
	}
}
