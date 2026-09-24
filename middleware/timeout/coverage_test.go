package timeout

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gin "github.com/king54346/gin-tiny"
	"github.com/stretchr/testify/assert"
)

func TestNilOptionPanics(t *testing.T) {
	assert.Panics(t, func() { New(nil) })
}

// handler 在副本上记录的错误和中止状态要同步回原 context，外层中间件才能看到
func TestErrorsAndAbortPropagate(t *testing.T) {
	var seen []string
	nextCalled := false

	r := gin.New()
	r.Use(func(c gin.Context) {
		c.Next()
		seen = c.Errors().Errors()
	})
	r.GET("/", New(
		WithTimeout(time.Second),
		WithHandler(func(c gin.Context) {
			_ = c.Error(errors.New("handler failed"))
			c.AbortWithStatus(http.StatusForbidden)
		}),
	), func(c gin.Context) { nextCalled = true })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, []string{"handler failed"}, seen)
	assert.False(t, nextCalled, "handlers after an aborted timeout handler must not run")
}

// 未中止时，后续 handler 在超时 handler 之后继续执行，二者的输出都写入响应
func TestNextHandlersRunAfterTimeoutHandler(t *testing.T) {
	r := gin.New()
	r.GET("/", New(
		WithTimeout(time.Second),
		WithHandler(func(c gin.Context) {
			c.Header("X-From", "timeout-handler")
			_, _ = io.WriteString(c.Response(), "a")
		}),
	), func(c gin.Context) { _, _ = c.Response().WriteString("b") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ab", w.Body.String())
	assert.Equal(t, "timeout-handler", w.Header().Get("X-From"))
}

// 超时后 handler 的迟到写入必须被丢弃，不能出现在响应中
func TestLateWritesAfterTimeoutAreDropped(t *testing.T) {
	wrote := make(chan struct{})
	r := gin.New()
	r.GET("/", New(
		WithTimeout(10*time.Millisecond),
		WithHandler(func(c gin.Context) {
			<-c.Request().Context().Done()
			_, _ = c.Response().WriteString("late")
			close(wrote)
		}),
	))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	<-wrote

	assert.Equal(t, http.StatusRequestTimeout, w.Code)
	assert.NotContains(t, w.Body.String(), "late")
}

type failingResponseWriter struct{ header http.Header }

func (f *failingResponseWriter) Header() http.Header       { return f.header }
func (f *failingResponseWriter) WriteHeader(int)           {}
func (f *failingResponseWriter) Write([]byte) (int, error) { return 0, errors.New("connection lost") }

// 写回缓冲内容失败时记录错误，而不是 panic
func TestWriteBackErrorIsRecorded(t *testing.T) {
	var seen []string
	r := gin.New()
	r.Use(func(c gin.Context) {
		c.Next()
		seen = c.Errors().Errors()
	})
	r.GET("/", New(
		WithTimeout(time.Second),
		WithHandler(func(c gin.Context) { c.String(http.StatusOK, "body") }),
	))

	assert.NotPanics(t, func() {
		r.ServeHTTP(&failingResponseWriter{header: http.Header{}}, httptest.NewRequest(http.MethodGet, "/", nil))
	})
	assert.Contains(t, seen, "connection lost")
}

func TestInvalidStatusCodePanics(t *testing.T) {
	w := NewWriter(nil, nil)
	assert.Panics(t, func() { w.WriteHeader(99) })
	assert.Panics(t, func() { w.WriteHeader(1000) })
}
