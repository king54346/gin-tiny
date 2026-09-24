package ginTiny

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// captureDebugOutput 在 debug 模式下捕获 DefaultWriter / DefaultErrorWriter 的输出
func captureDebugOutput(t *testing.T, mode string) (out, errOut *bytes.Buffer) {
	t.Helper()
	withMode(t, mode)
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	DefaultWriter, DefaultErrorWriter = out, errOut
	t.Cleanup(func() { DefaultWriter, DefaultErrorWriter = os.Stdout, os.Stderr })
	return out, errOut
}

func TestDebugPrint(t *testing.T) {
	out, _ := captureDebugOutput(t, DebugMode)
	debugPrint("hello %s", "world")
	debugPrint("already has newline\n")
	assert.Equal(t, "[GIN-debug] hello world\n[GIN-debug] already has newline\n", out.String())

	out, _ = captureDebugOutput(t, ReleaseMode)
	debugPrint("hidden")
	assert.Empty(t, out.String())
}

func TestDebugPrintRoute(t *testing.T) {
	out, _ := captureDebugOutput(t, DebugMode)
	r := New()
	out.Reset()
	r.GET("/users/:id", handlerTest1)
	assert.Regexp(t, `^\[GIN-debug\] GET\s+/users/:id\s+--> .*handlerTest1 \(1 handlers\)\n$`, out.String())

	var got []any
	DebugPrintRouteFunc = func(method, path, handler string, n int) { got = []any{method, path, handler, n} }
	t.Cleanup(func() { DebugPrintRouteFunc = nil })
	out.Reset()
	r.POST("/users", handlerTest1, handlerTest2)
	assert.Empty(t, out.String(), "custom DebugPrintRouteFunc replaces the default output")
	assert.Equal(t, "POST", got[0])
	assert.Equal(t, "/users", got[1])
	assert.Contains(t, got[2], "handlerTest2")
	assert.Equal(t, 2, got[3])
}

func TestDebugPrintError(t *testing.T) {
	_, errOut := captureDebugOutput(t, DebugMode)
	debugPrintError(nil)
	assert.Empty(t, errOut.String())
	debugPrintError(errors.New("listen failed"))
	assert.Equal(t, "[GIN-debug] [ERROR] listen failed\n", errOut.String())

	_, errOut = captureDebugOutput(t, ReleaseMode)
	debugPrintError(errors.New("hidden"))
	assert.Empty(t, errOut.String())
}

func TestDebugWarnings(t *testing.T) {
	out, _ := captureDebugOutput(t, DebugMode)
	Default()
	assert.Contains(t, out.String(), "Logger and Recovery middleware already attached")
	assert.Contains(t, out.String(), `Running in "debug" mode`)
}
