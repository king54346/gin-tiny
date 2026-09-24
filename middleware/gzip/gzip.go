package gzip

import (
	"compress/gzip"

	gin "github.com/king54346/gin-tiny"
)

const (
	BestCompression    = gzip.BestCompression
	BestSpeed          = gzip.BestSpeed
	DefaultCompression = gzip.DefaultCompression
	NoCompression      = gzip.NoCompression
)

func Gzip(level int, options ...Option) gin.HandlerFunc {
	return newGzipHandler(level, options...).Handle
}

// gzipWriter 把写入的数据先经过 gzip 压缩，再写到原始的 ResponseWriter
type gzipWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
}

// WriteHeader 在响应头发出前删除 Content-Length：
// 下游设置的是未压缩长度（例如 c.File），原样发出会导致客户端读取截断
func (g *gzipWriter) WriteHeader(code int) {
	g.Header().Del("Content-Length")
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(data []byte) (int, error) {
	g.Header().Del("Content-Length")
	return g.writer.Write(data)
}

// WriteString 必须覆盖，否则 io.WriteString 会走到内嵌 ResponseWriter 的 WriteString 而绕过压缩
func (g *gzipWriter) WriteString(s string) (int, error) {
	return g.Write([]byte(s))
}

// Flush 先把 gzip 内部缓冲的数据刷出，SSE / Stream 场景才能及时送达客户端
func (g *gzipWriter) Flush() {
	_ = g.writer.Flush()
	g.ResponseWriter.Flush()
}
