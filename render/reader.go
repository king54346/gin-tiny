package render

import (
	"io"
	"net/http"
	"strconv"
)

// Reader contains the IO reader and its length, and custom ContentType and other headers.
type Reader struct {
	ContentType   string
	ContentLength int64
	Reader        io.Reader
	Headers       map[string]string
}

// Render (Reader) writes data with custom ContentType and headers.
func (r Reader) Render(w http.ResponseWriter) (err error) {
	r.WriteContentType(w)
	// 不能把 Content-Length 写进 r.Headers：那是调用方的 map，常被声明为包级变量在请求间共享，
	// 并发写入会触发 fatal error: concurrent map writes（recover 无法拦截，整个进程退出）
	r.writeHeaders(w, r.Headers)
	if r.ContentLength >= 0 && w.Header().Get("Content-Length") == "" {
		w.Header().Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	_, err = io.Copy(w, r.Reader)
	return
}

// WriteContentType (Reader) writes custom ContentType.
func (r Reader) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, []string{r.ContentType})
}

// writeHeaders writes custom Header.
func (r Reader) writeHeaders(w http.ResponseWriter, headers map[string]string) {
	header := w.Header()
	for k, v := range headers {
		if header.Get(k) == "" {
			header.Set(k, v)
		}
	}
}
