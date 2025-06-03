package gzip

import (
	"compress/gzip"
	"fmt"
	gin "gin-tiny"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

type gzipHandler struct {
	*Options
	gzPool sync.Pool
}

func newGzipHandler(level int, options ...Option) *gzipHandler {
	handler := &gzipHandler{
		Options: DefaultOptions,
		gzPool: sync.Pool{
			New: func() interface{} {
				gz, err := gzip.NewWriterLevel(ioutil.Discard, level)
				if err != nil {
					panic(err)
				}
				return gz
			},
		},
	}
	for _, setter := range options {
		setter(handler.Options)
	}
	return handler
}

func (g *gzipHandler) Handle(c gin.Context) {
	if fn := g.DecompressFn; fn != nil && c.Request().Header.Get("Content-Encoding") == "gzip" {
		fn(c)
	}

	if !g.shouldCompress(c.Request()) {
		return
	}

	gz := g.gzPool.Get().(*gzip.Writer)
	defer g.gzPool.Put(gz)
	defer gz.Reset(ioutil.Discard)

	// 创建计数器来跟踪压缩后的大小
	counter := &countingWriter{ResponseWriter: c.Response()}
	gz.Reset(counter)

	c.Header("Content-Encoding", "gzip")
	c.Header("Vary", "Accept-Encoding")

	// 创建 gzipWriter
	gzWriter := &gzipWriter{
		ResponseWriter: c.Response(),
		writer:         gz, // countingWriter用于跟踪压缩后的大小
	}

	// 使用 SetResponse 方法
	c.SetResponse(gzWriter)

	defer func() {
		gz.Close()
		// 使用实际写入的字节数
		c.Header("Content-Length", fmt.Sprint(atomic.LoadInt64(&counter.count)))
	}()

	c.Next()
}

func (g *gzipHandler) shouldCompress(req *http.Request) bool {
	if !strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") ||
		strings.Contains(req.Header.Get("Connection"), "Upgrade") ||
		strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		return false
	}

	extension := filepath.Ext(req.URL.Path)
	if g.ExcludedExtensions.Contains(extension) {
		return false
	}

	if g.ExcludedPaths.Contains(req.URL.Path) {
		return false
	}
	if g.ExcludedPathesRegexs.Contains(req.URL.Path) {
		return false
	}

	return true
}
