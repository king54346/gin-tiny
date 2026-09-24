package gzip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	stdctx "context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gin "github.com/king54346/gin-tiny"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Flush 必须把 gzip 内部缓冲的数据刷到连接上：handler 尚未返回时，客户端就能解压读到已发送的数据
func TestGzipFlushStreamsBeforeHandlerReturns(t *testing.T) {
	release := make(chan struct{})
	router := gin.New()
	router.Use(Gzip(DefaultCompression))
	router.GET("/stream", func(c gin.Context) {
		_, _ = c.Response().Write([]byte("first\n"))
		c.Response().Flush()
		<-release
		_, _ = c.Response().Write([]byte("second\n"))
	})
	srv := httptest.NewServer(router)
	defer srv.Close()
	defer close(release)

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, srv.URL+"/stream", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))

	lineCh := make(chan string, 1)
	go func() {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			lineCh <- "error: " + err.Error()
			return
		}
		line, _ := bufio.NewReader(gr).ReadString('\n')
		lineCh <- line
	}()

	select {
	case line := <-lineCh:
		assert.Equal(t, "first\n", line)
	case <-time.After(3 * time.Second):
		t.Fatal("flushed data did not reach the client before the handler returned")
	}
}

func TestExcludedPathsRegexs(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(DefaultCompression, WithExcludedPathsRegexs([]string{`^/api/v\d+/raw`})))
	router.GET("/api/:ver/raw", func(c gin.Context) { c.String(http.StatusOK, "raw") })
	router.GET("/api/:ver/data", func(c gin.Context) { c.String(http.StatusOK, "data") })

	do := func(path string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	w := do("/api/v1/raw")
	assert.Empty(t, w.Header().Get("Content-Encoding"))
	assert.Equal(t, "raw", w.Body.String())

	w = do("/api/v1/data")
	assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
}

func TestShouldCompressSkipsUpgradeAndSSE(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(DefaultCompression))
	router.GET("/", func(c gin.Context) { c.String(http.StatusOK, "plain") })

	for name, h := range map[string][2]string{
		"no accept-encoding": {"Accept-Encoding", ""},
		"websocket upgrade":  {"Connection", "Upgrade"},
		"server-sent events": {"Accept", "text/event-stream"},
	} {
		req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, "/", nil)
		if h[0] != "Accept-Encoding" {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		req.Header.Set(h[0], h[1])
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Empty(t, w.Header().Get("Content-Encoding"), name)
		assert.Equal(t, "plain", w.Body.String(), name)
	}
}

func TestInvalidCompressionLevelPanics(t *testing.T) {
	h := Gzip(42)
	router := gin.New()
	router.Use(h)
	router.GET("/", func(c gin.Context) {})

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	assert.Panics(t, func() { router.ServeHTTP(httptest.NewRecorder(), req) })
}

// 压缩后的数据可以被完整解压，多次请求复用 sync.Pool 中的 writer 不会串数据
func TestGzipWriterReuse(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(BestSpeed))
	router.GET("/:n", func(c gin.Context) { c.String(http.StatusOK, "payload-"+c.Param("n")) })

	for _, n := range []string{"1", "2", "3", "1"} {
		req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, "/"+n, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		gr, err := gzip.NewReader(w.Body)
		require.NoError(t, err)
		body, err := io.ReadAll(gr)
		require.NoError(t, err)
		assert.Equal(t, "payload-"+n, string(body))
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(data)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// 高压缩比的数据（gzip 炸弹）解压超过上限时读取失败，而不是把内存耗尽
func TestDecompressHandleWithLimitStopsGzipBomb(t *testing.T) {
	bomb := gzipBytes(t, bytes.Repeat([]byte{0}, 8<<20)) // 8 MiB 的 0 压缩后只有几 KB
	require.Less(t, len(bomb), 64<<10)

	var readErr error
	var n int
	router := gin.New()
	router.Use(Gzip(DefaultCompression, WithDecompressFn(DecompressHandleWithLimit(1<<20))))
	router.POST("/", func(c gin.Context) {
		data, err := io.ReadAll(c.Request().Body)
		n, readErr = len(data), err
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodPost, "/", bytes.NewReader(bomb))
	req.Header.Set("Content-Encoding", "gzip")
	router.ServeHTTP(httptest.NewRecorder(), req)

	var maxErr *http.MaxBytesError
	require.ErrorAs(t, readErr, &maxErr)
	assert.Equal(t, int64(1<<20), maxErr.Limit)
	assert.LessOrEqual(t, n, 1<<20)
}

func TestDecompressHandleWithinLimit(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(DefaultCompression, WithDecompressFn(DecompressHandleWithLimit(1<<20))))
	router.POST("/", func(c gin.Context) {
		assert.Equal(t, int64(-1), c.Request().ContentLength, "decompressed length is unknown")
		data, err := io.ReadAll(c.Request().Body)
		require.NoError(t, err)
		assert.NoError(t, c.Request().Body.Close())
		c.Data(http.StatusOK, "text/plain", data)
	})

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodPost, "/", bytes.NewReader(gzipBytes(t, []byte("hello"))))
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, "hello", w.Body.String())
}

// 服务端收到的空请求体是 http.NoBody，不能被当作非法 gzip 拒绝
func TestDecompressEmptyNoBody(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(DefaultCompression, WithDecompressFn(DefaultDecompressHandle)))
	router.POST("/", func(c gin.Context) { c.String(http.StatusOK, "ok") })

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodPost, "/", http.NoBody)
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestDecompressedBodyClosesOriginal(t *testing.T) {
	orig := &closeTracker{Reader: bytes.NewReader(gzipBytes(t, []byte("x")))}
	router := gin.New()
	router.Use(Gzip(DefaultCompression, WithDecompressFn(DefaultDecompressHandle)))
	router.POST("/", func(c gin.Context) { _ = c.Request().Body.Close() })

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodPost, "/", orig)
	req.Header.Set("Content-Encoding", "gzip")
	router.ServeHTTP(httptest.NewRecorder(), req)
	assert.True(t, orig.closed)
}

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		header []string
		want   bool
	}{
		{[]string{"gzip"}, true},
		{[]string{"GZIP"}, true},
		{[]string{"deflate, gzip;q=0.8"}, true},
		{[]string{"x-gzip"}, true},
		{[]string{"xgzip"}, false},         // 不能按子串匹配
		{[]string{"gzip-lite"}, false},     // 同上
		{[]string{"gzip;q=0"}, false},      // 客户端明确拒绝
		{[]string{"gzip; q=0.000"}, false}, // 带空格的 q=0
		{[]string{"*"}, true},              // 通配符
		{[]string{"*;q=0"}, false},
		{[]string{"*, gzip;q=0"}, false}, // 显式声明优先于通配符
		{[]string{"gzip;q=0, *"}, false},
		{[]string{"br", "gzip"}, true},  // 多个 Accept-Encoding 头
		{[]string{"gzip;q=abc"}, false}, // 非法 q 值视为不可接受
		{[]string{"identity"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, acceptsGzip(tt.header), "%q", tt.header)
	}
}

func TestShouldCompressConnectionUpgradeCaseInsensitive(t *testing.T) {
	router := gin.New()
	router.Use(Gzip(DefaultCompression))
	router.GET("/", func(c gin.Context) { c.String(http.StatusOK, "plain") })

	req, _ := http.NewRequestWithContext(stdctx.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "keep-alive, upgrade")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Empty(t, w.Header().Get("Content-Encoding"))

	req.Header.Set("Accept-Encoding", "xgzip")
	req.Header.Del("Connection")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Empty(t, w.Header().Get("Content-Encoding"))
}
