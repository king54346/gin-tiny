package ginTiny

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// withColorMode 临时修改全局颜色模式，测试结束后恢复
func withColorMode(t *testing.T, mode consoleColorModeValue) {
	t.Helper()
	old := consoleColorMode.Load()
	consoleColorMode.Store(int32(mode))
	t.Cleanup(func() { consoleColorMode.Store(old) })
}

func TestLoggerWithWriter(t *testing.T) {
	var buf bytes.Buffer
	r := New()
	r.Use(LoggerWithWriter(&buf))
	r.GET("/users/:id", func(c Context) { c.String(http.StatusOK, "ok") })
	r.POST("/fail", func(c Context) { c.Status(http.StatusInternalServerError) })

	PerformRequest(r, http.MethodGet, "/users/1?verbose=true")
	line := buf.String()
	assert.True(t, strings.HasPrefix(line, "[GIN] "))
	assert.Contains(t, line, "200")
	assert.Contains(t, line, http.MethodGet)
	assert.Contains(t, line, `"/users/1?verbose=true"`)

	buf.Reset()
	PerformRequest(r, http.MethodPost, "/fail")
	assert.Contains(t, buf.String(), "500")
	assert.Contains(t, buf.String(), `"/fail"`)

	buf.Reset()
	PerformRequest(r, http.MethodGet, "/missing")
	assert.Contains(t, buf.String(), "404")
}

func TestLoggerSkipPaths(t *testing.T) {
	var buf bytes.Buffer
	r := New()
	r.Use(LoggerWithWriter(&buf, "/health"))
	r.GET("/health", func(c Context) {})
	r.GET("/api", func(c Context) {})

	PerformRequest(r, http.MethodGet, "/health")
	assert.Empty(t, buf.String())

	PerformRequest(r, http.MethodGet, "/api")
	assert.Contains(t, buf.String(), `"/api"`)
}

func TestLoggerWithFormatterReceivesParams(t *testing.T) {
	var got LogFormatterParams
	var buf bytes.Buffer
	DefaultWriter = &buf
	t.Cleanup(func() { DefaultWriter = os.Stdout })

	r := New()
	r.Use(LoggerWithFormatter(func(p LogFormatterParams) string {
		got = p
		return "custom\n"
	}))
	r.GET("/items", func(c Context) {
		_ = c.Error(errors.New("internal detail"))
		_ = c.Error(errors.New("shown to user")).SetType(ErrorTypePublic)
		c.String(http.StatusCreated, "hello")
	})

	PerformRequest(r, http.MethodGet, "/items?q=1", header{Key: "X-Forwarded-For", Value: "203.0.113.9"})

	assert.Equal(t, "custom\n", buf.String())
	assert.Equal(t, http.StatusCreated, got.StatusCode)
	assert.Equal(t, http.MethodGet, got.Method)
	assert.Equal(t, "/items?q=1", got.Path)
	assert.Equal(t, "203.0.113.9", got.ClientIP)
	assert.Equal(t, len("hello"), got.BodySize)
	assert.NotNil(t, got.Request)
	assert.GreaterOrEqual(t, got.Latency, time.Duration(0))
	// 只记录私有错误
	assert.Contains(t, got.ErrorMessage, "internal detail")
	assert.NotContains(t, got.ErrorMessage, "shown to user")
}

func TestLoggerUsesDefaultWriter(t *testing.T) {
	var buf bytes.Buffer
	DefaultWriter = &buf
	t.Cleanup(func() { DefaultWriter = os.Stdout })

	r := New()
	r.Use(Logger())
	r.GET("/", func(c Context) {})
	PerformRequest(r, http.MethodGet, "/")
	assert.Contains(t, buf.String(), `"/"`)
}

func TestLogFormatterColors(t *testing.T) {
	statusColors := map[int]string{
		http.StatusOK:                  green,
		http.StatusNoContent:           green,
		http.StatusMovedPermanently:    white,
		http.StatusNotFound:            yellow,
		http.StatusInternalServerError: red,
		http.StatusContinue:            red,
	}
	for code, want := range statusColors {
		p := LogFormatterParams{StatusCode: code}
		assert.Equal(t, want, p.StatusCodeColor(), "status %d", code)
	}

	methodColors := map[string]string{
		http.MethodGet:     blue,
		http.MethodPost:    cyan,
		http.MethodPut:     yellow,
		http.MethodDelete:  red,
		http.MethodPatch:   green,
		http.MethodHead:    magenta,
		http.MethodOptions: white,
		"PURGE":            reset,
	}
	for method, want := range methodColors {
		p := LogFormatterParams{Method: method}
		assert.Equal(t, want, p.MethodColor(), method)
	}
	assert.Equal(t, reset, (&LogFormatterParams{}).ResetColor())
}

func TestConsoleColorModes(t *testing.T) {
	withColorMode(t, autoColor)
	assert.True(t, (&LogFormatterParams{isTerm: true}).IsOutputColor())
	assert.False(t, (&LogFormatterParams{isTerm: false}).IsOutputColor())

	ForceConsoleColor()
	assert.True(t, (&LogFormatterParams{isTerm: false}).IsOutputColor())

	DisableConsoleColor()
	assert.False(t, (&LogFormatterParams{isTerm: true}).IsOutputColor())
}

func TestDefaultLogFormatter(t *testing.T) {
	ts := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	p := LogFormatterParams{
		TimeStamp:  ts,
		StatusCode: http.StatusOK,
		Latency:    5 * time.Second,
		ClientIP:   "20.20.20.20",
		Method:     http.MethodGet,
		Path:       "/",
	}

	withColorMode(t, disableColor)
	plain := defaultLogFormatter(p)
	assert.Equal(t, `[GIN] 2026/09/23 - 10:00:00 | 200 |            5s |     20.20.20.20 | GET      "/"`+"\n", plain)
	assert.NotContains(t, plain, "\033[")

	ForceConsoleColor()
	colored := defaultLogFormatter(p)
	assert.Contains(t, colored, green)
	assert.Contains(t, colored, blue)
	assert.Contains(t, colored, reset)

	// 超过一分钟的耗时截断到秒，避免输出过长
	p.Latency = 2*time.Minute + 123456789*time.Nanosecond
	DisableConsoleColor()
	assert.Contains(t, defaultLogFormatter(p), "2m0s")
}

func TestErrorLogger(t *testing.T) {
	r := New()
	r.GET("/any", ErrorLogger(), func(c Context) {
		_ = c.Error(errors.New("first"))
		_ = c.Error(errors.New("second")).SetType(ErrorTypePublic)
	})
	r.GET("/public", ErrorLoggerT(ErrorTypePublic), func(c Context) {
		_ = c.Error(errors.New("private"))
		_ = c.Error(errors.New("public")).SetType(ErrorTypePublic)
	})
	r.GET("/none", ErrorLogger(), func(c Context) { c.String(http.StatusOK, "fine") })

	w := PerformRequest(r, http.MethodGet, "/any")
	assert.JSONEq(t, `[{"error":"first"},{"error":"second"}]`, w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/public")
	assert.JSONEq(t, `{"error":"public"}`, w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/none")
	assert.Equal(t, "fine", w.Body.String())
}
