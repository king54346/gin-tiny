package gzip

import (
	"bytes"
	"compress/gzip"
	gin "gin-tiny"
	"net/http"
	"sync/atomic"
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

// 方案1: 自定义 gzipResponseWriter 直接实现 ResponseWriter 接口
type gzipResponseWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
	size   int // 记录压缩后的实际大小
}

func (w *gzipResponseWriter) Write(data []byte) (int, error) {
	// 写入数据到 gzip writer
	n, err := w.writer.Write(data)
	w.size += n
	return n, err
}

func (w *gzipResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *gzipResponseWriter) Size() int {
	return w.size
}

// 获取压缩后的实际大小
func (w *gzipResponseWriter) CompressedSize() int {
	return w.size
}

//func (g *gzipHandler) Handle(c gin.Context) {
//	if fn := g.DecompressFn; fn != nil && c.Request().Header.Get("Content-Encoding") == "gzip" {
//		fn(c)
//	}
//
//	if !g.shouldCompress(c.Request()) {
//		return
//	}
//
//	gz := g.gzPool.Get().(*gzip.Writer)
//	defer g.gzPool.Put(gz)
//	defer gz.Reset(ioutil.Discard)
//
//	// 创建自定义的 gzipResponseWriter
//	gzWriter := &gzipResponseWriter{
//		ResponseWriter: c.Writer,
//		writer:         gz,
//		size:           0,
//	}
//	gz.Reset(gzWriter.ResponseWriter)
//
//	c.Header("Content-Encoding", "gzip")
//	c.Header("Vary", "Accept-Encoding")
//
//	// 替换 Writer
//	c.Writer = gzWriter
//
//	defer func() {
//		gz.Close()
//		// 使用压缩后的实际大小
//		c.Header("Content-Length", fmt.Sprint(gzWriter.CompressedSize()))
//	}()
//
//	c.Next()
//}

// 方案2: 使用 CountingWriter 来跟踪压缩后的字节数
type countingWriter struct {
	http.ResponseWriter
	count int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	atomic.AddInt64(&w.count, int64(n))
	return n, err
}

// 方案3: 如果你想保持现有结构，可以修改 gzipWriter 来追踪压缩后的大小
type gzipWriter struct {
	gin.ResponseWriter
	writer         *gzip.Writer
	compressedSize int
}

func (g *gzipWriter) Write(data []byte) (int, error) {
	// 先写入到 gzip writer
	n, err := g.writer.Write(data)
	if err != nil {
		return n, err
	}

	// gzip.Writer 不会直接告诉我们压缩后的大小
	// 所以我们需要通过其他方式追踪
	// 这里返回的是原始数据大小，用于上层统计
	return len(data), nil
}

// 更完整的解决方案：使用 io.MultiWriter 和 计数器
//func (g *gzipHandler) HandleV3(c *gin.Context) {
//	if fn := g.DecompressFn; fn != nil && c.Request().Header.Get("Content-Encoding") == "gzip" {
//		fn(c)
//	}
//
//	if !g.shouldCompress(c.Request()) {
//		return
//	}
//
//	gz := g.gzPool.Get().(*gzip.Writer)
//	defer g.gzPool.Put(gz)
//	defer gz.Reset(ioutil.Discard)
//
//	// 使用 bytes.Buffer 来缓存压缩后的数据
//	var buf bytes.Buffer
//	gz.Reset(&buf)
//
//	c.Header("Content-Encoding", "gzip")
//	c.Header("Vary", "Accept-Encoding")
//
//	// 保存原始 writer
//	originalWriter := c.Writer
//
//	// 创建自定义 writer
//	gzWriter := &bufferedGzipWriter{
//		ResponseWriter: c.Writer,
//		writer:         gz,
//		buffer:         &buf,
//	}
//
//	c.Writer = gzWriter
//
//	defer func() {
//		gz.Close()
//
//		// 将缓冲的数据写入原始 writer
//		compressedData := buf.Bytes()
//		c.Header("Content-Length", fmt.Sprint(len(compressedData)))
//
//		// 恢复原始 writer 并写入数据
//		c.Writer = originalWriter
//		c.Writer.Write(compressedData)
//	}()
//
//	c.Next()
//}

type bufferedGzipWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
	buffer *bytes.Buffer
}

func (w *bufferedGzipWriter) Write(data []byte) (int, error) {
	return w.writer.Write(data)
}

func (w *bufferedGzipWriter) WriteString(s string) (int, error) {
	return w.writer.Write([]byte(s))
}
