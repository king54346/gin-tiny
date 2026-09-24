package gzip

import (
	"compress/gzip"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	gin "github.com/king54346/gin-tiny"
)

type gzipHandler struct {
	*Options
	gzPool sync.Pool
}

func newGzipHandler(level int, options ...Option) *gzipHandler {
	// 复制一份默认配置，Option 只修改当前实例，不能污染全局的 DefaultOptions
	opts := *DefaultOptions
	handler := &gzipHandler{
		Options: &opts,
		gzPool: sync.Pool{
			New: func() any {
				gz, err := gzip.NewWriterLevel(io.Discard, level)
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
	defer gz.Reset(io.Discard)
	gz.Reset(c.Response())

	c.Header("Content-Encoding", "gzip")
	c.Header("Vary", "Accept-Encoding")

	c.SetResponse(&gzipWriter{ResponseWriter: c.Response(), writer: gz})
	defer gz.Close()

	c.Next()
}

func (g *gzipHandler) shouldCompress(req *http.Request) bool {
	if !acceptsGzip(req.Header.Values("Accept-Encoding")) ||
		headerHasToken(req.Header.Values("Connection"), "upgrade") ||
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

// acceptsGzip 按 RFC 9110 §12.5.3 解析 Accept-Encoding：
// 逐项比较编码名（不能用子串匹配，否则 "xgzip" 也会命中），q=0 表示明确拒绝；
// gzip / x-gzip 的显式声明优先于通配符 *
func acceptsGzip(values []string) bool {
	gzipQ, starQ := -1.0, -1.0
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			coding, params, _ := strings.Cut(part, ";")
			coding = strings.TrimSpace(coding)
			q := 1.0
			for p := range strings.SplitSeq(params, ";") {
				if name, val, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(strings.TrimSpace(name), "q") {
					parsed, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
					if err != nil || parsed < 0 || parsed > 1 {
						parsed = 0 // 非法的 q 值视为不可接受
					}
					q = parsed
				}
			}
			switch {
			case strings.EqualFold(coding, "gzip"), strings.EqualFold(coding, "x-gzip"):
				gzipQ = max(gzipQ, q)
			case coding == "*":
				starQ = max(starQ, q)
			}
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return starQ > 0
}

// headerHasToken 判断逗号分隔的头部（如 Connection: keep-alive, Upgrade）是否包含某个 token，忽略大小写
func headerHasToken(values []string, token string) bool {
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
