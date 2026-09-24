// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

const (
	noWritten     = -1
	defaultStatus = http.StatusOK
)

// ResponseWriter 的接口定义了一个响应写入器，它是 http.ResponseWriter 的扩展，
type ResponseWriter interface {
	http.ResponseWriter
	http.Hijacker
	http.Flusher
	// 关闭连接的通知通过Request.Context().Done()方法发送
	//http.CloseNotifier

	// Status returns the HTTP response status code of the current request.
	Status() int

	SetStatus(int)
	// Size returns the number of bytes already written into the response http body.
	// See Written()
	Size() int

	// WriteString writes the string into the response body.
	WriteString(string) (int, error)

	// Written returns true if the response body was already written.
	Written() bool

	// WriteHeaderNow forces to write the http header (status code + headers).
	WriteHeaderNow()

	// Header / Write / WriteHeader 由内嵌的 http.ResponseWriter 提供，不要在此重复声明：
	// 重复声明虽然能编译，但会让嵌入 ResponseWriter 的类型（如 gzipWriter）在 IDE 中报「不明确的引用」

	// Pusher get the http.Pusher for server push
	Pusher() http.Pusher
	// Before registers a function to be called before WriteHeaderNow.
	Before(func())
	// After registers a function to be called after Write.
	After(func())
}

type responseWriter struct {
	http.ResponseWriter
	beforeFuncs []func()
	afterFuncs  []func()
	size        int
	status      int
}

var _ ResponseWriter = (*responseWriter)(nil)

func NewResponseWriter(writer http.ResponseWriter) *responseWriter {
	w := &responseWriter{
		ResponseWriter: writer,
		beforeFuncs:    make([]func(), 0, 4),
		afterFuncs:     make([]func(), 0, 4),
		size:           noWritten,
		status:         defaultStatus,
	}
	return w
}

func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// reset 在 context 从 sync.Pool 取出时调用。
// 复用切片底层数组避免每个请求都分配，clear 掉旧闭包避免持有上个请求的引用导致内存无法回收
func (w *responseWriter) reset(writer http.ResponseWriter) {
	clear(w.beforeFuncs)
	clear(w.afterFuncs)
	w.beforeFuncs = w.beforeFuncs[:0]
	w.afterFuncs = w.afterFuncs[:0]
	w.ResponseWriter = writer
	w.size = noWritten
	w.status = defaultStatus
}

// WriteHeader 只记录状态码，真正写出延迟到 WriteHeaderNow/Write，方便中间件在写出前修改
func (w *responseWriter) WriteHeader(code int) {
	w.SetStatus(code)
}

func (w *responseWriter) WriteHeaderNow() {
	if !w.Written() {
		w.size = 0
		for _, fn := range w.beforeFuncs {
			fn()
		}
		w.ResponseWriter.WriteHeader(w.status)
	}
}

func (w *responseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *responseWriter) Before(fn func()) {
	w.beforeFuncs = append(w.beforeFuncs, fn)
}
func (w *responseWriter) After(fn func()) {
	w.afterFuncs = append(w.afterFuncs, fn)
}

func (w *responseWriter) Write(data []byte) (n int, err error) {
	w.WriteHeaderNow()
	n, err = w.ResponseWriter.Write(data)
	w.size += n
	for _, fn := range w.afterFuncs {
		fn()
	}
	return
}

func (w *responseWriter) WriteString(s string) (n int, err error) {
	w.WriteHeaderNow()
	n, err = io.WriteString(w.ResponseWriter, s)
	w.size += n
	for _, fn := range w.afterFuncs {
		fn()
	}
	return
}

func (w *responseWriter) Status() int {
	return w.status
}

func (w *responseWriter) Size() int {
	return w.size
}

// Written 表示响应是否已经被写入, 如果 size 为 noWritten，则表示尚未写入响应体；
func (w *responseWriter) Written() bool {
	return w.size != noWritten
}

// Hijack implements the http.Hijacker interface.
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.size < 0 {
		w.size = 0
	}
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// Flush implements the http.Flusher interface.
// 使用 http.ResponseController，可以穿透实现了 Unwrap() 的多层包装 writer
func (w *responseWriter) Flush() {
	w.WriteHeaderNow()
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Pusher() (pusher http.Pusher) {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher
	}
	return nil
}

func (w *responseWriter) SetStatus(status int) {
	if status > 0 && w.status != status && !w.Written() {
		w.status = status
	}
}
