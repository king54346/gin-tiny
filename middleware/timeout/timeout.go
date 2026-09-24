package timeout

import (
	"context"
	"maps"
	"time"

	gin "github.com/king54346/gin-tiny"
)

const (
	defaultTimeout = 5 * time.Second
)

// New wraps a handler and aborts the process of the handler if the timeout is reached
//
// handler 在独立的 goroutine 中执行，拿到的是 c.Copy() 得到的副本：
// 超时后本中间件会先返回，原 context 随即被放回 sync.Pool 给下一个请求复用，
// 如果 goroutine 继续持有原 context 就会和新请求互相踩数据。
// 副本的 Request().Context() 带有超时时间，handler 应当监听它及时退出。
func New(opts ...Option) gin.HandlerFunc {
	t := &Timeout{
		timeout:  defaultTimeout,
		handler:  nil,
		response: defaultResponse,
	}

	// Loop through each option
	for _, opt := range opts {
		if opt == nil {
			panic("timeout Option not be nil")
		}

		// Call the option giving the instantiated
		opt(t)
	}

	if t.timeout <= 0 {
		return t.handler
	}

	// 每个中间件实例独享一个 pool，避免多个实例互相覆盖
	bufPool := &BufferPool{}

	return func(c gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request().Context(), t.timeout)
		defer cancel()

		w := c.Response()
		buffer := bufPool.Get()
		buffer.Reset()
		tw := NewWriter(w, buffer)
		c.SetResponse(tw)

		// 必须在 SetResponse 之后复制，副本的 writer 才会写入 tw 的缓冲区
		cp := c.Copy()
		cp.SetRequest(c.Request().WithContext(ctx))

		finish := make(chan struct{})
		panicChan := make(chan any, 1)

		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			t.handler(cp)
			// 只调用了 c.Status() 而没有写 body 时，状态码还停留在副本的 writer 里
			cp.Response().WriteHeaderNow()
			close(finish)
		}()

		select {
		case p := <-panicChan:
			tw.mu.Lock()
			tw.FreeBuffer()
			tw.mu.Unlock()
			bufPool.Put(buffer)
			c.SetResponse(w)
			panic(p)

		case <-finish:
			// 把副本上记录的错误和中止状态同步回原 context
			for _, err := range cp.Errors() {
				_ = c.Error(err)
			}
			if cp.IsAborted() {
				c.Abort()
			}
			c.Next()

			tw.mu.Lock()
			defer tw.mu.Unlock()
			dst := w.Header()
			maps.Copy(dst, tw.Header())
			w.WriteHeader(tw.code)
			if _, err := w.Write(buffer.Bytes()); err != nil {
				_ = c.Error(err)
			}
			tw.FreeBuffer()
			bufPool.Put(buffer)
			c.SetResponse(w)

		case <-ctx.Done():
			c.Abort()
			tw.mu.Lock()
			tw.timeout = true
			// 置 timeout 后 handler 的写入都会被丢弃，缓冲区可以安全回收
			tw.FreeBuffer()
			tw.mu.Unlock()
			bufPool.Put(buffer)

			c.SetResponse(w)
			t.response(c)
		}
	}
}
