package render

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 调用方传入的 Headers 常是包级共享变量，Render 不能修改它
func TestReaderDoesNotMutateHeaders(t *testing.T) {
	headers := map[string]string{"Content-Disposition": `attachment; filename="a.txt"`}
	w := httptest.NewRecorder()
	require.NoError(t, Reader{ContentType: "text/plain", ContentLength: 3, Reader: strings.NewReader("abc"), Headers: headers}.Render(w))

	assert.Equal(t, map[string]string{"Content-Disposition": `attachment; filename="a.txt"`}, headers)
	assert.Equal(t, "3", w.Header().Get("Content-Length"))
	assert.Equal(t, `attachment; filename="a.txt"`, w.Header().Get("Content-Disposition"))
	assert.Equal(t, "abc", w.Body.String())
}

func TestReaderHeaderPrecedence(t *testing.T) {
	// 已在响应头中设置的值不被覆盖；ContentLength < 0 表示长度未知，不写 Content-Length
	w := httptest.NewRecorder()
	w.Header().Set("Content-Length", "99")
	w.Header().Set("X-Keep", "original")
	require.NoError(t, Reader{ContentLength: 3, Reader: strings.NewReader("abc"), Headers: map[string]string{"X-Keep": "new"}}.Render(w))
	assert.Equal(t, "99", w.Header().Get("Content-Length"))
	assert.Equal(t, "original", w.Header().Get("X-Keep"))

	w = httptest.NewRecorder()
	require.NoError(t, Reader{ContentLength: -1, Reader: strings.NewReader("abc")}.Render(w))
	assert.Empty(t, w.Header().Get("Content-Length"))
}

var sharedHeaders = map[string]string{"Content-Disposition": `attachment; filename="a.txt"`}

// 修复前这里会 fatal error: concurrent map writes，整个测试进程崩溃
func TestReaderConcurrentSharedHeaders(t *testing.T) {
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 500 {
				_ = Reader{ContentType: "text/plain", ContentLength: 3, Reader: strings.NewReader("abc"), Headers: sharedHeaders}.Render(httptest.NewRecorder())
			}
		})
	}
	wg.Wait()
}
