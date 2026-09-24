package ginTiny

import (
	stdctx "context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return l
}

// ctx 取消后，进行中的请求必须完整返回，之后服务退出并返回 nil，新连接被拒绝
func TestRunListenerContextGracefulShutdown(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	router := New()
	router.GET("/slow", func(c Context) {
		close(entered)
		<-release
		c.String(http.StatusOK, "done")
	})

	l := newLocalListener(t)
	addr := l.Addr().String()
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- router.RunListenerContext(ctx, l) }()

	type result struct {
		body string
		err  error
	}
	respCh := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			respCh <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		respCh <- result{string(b), err}
	}()
	<-entered

	cancel()
	// 请求尚未完成时服务不能退出
	select {
	case err := <-runErr:
		t.Fatalf("server exited before in-flight request finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	// Shutdown 会先关闭 listener，新连接应当失败
	require.Eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err != nil
	}, 2*time.Second, 10*time.Millisecond)

	close(release)
	res := <-respCh
	require.NoError(t, res.err)
	assert.Equal(t, "done", res.body)

	select {
	case err := <-runErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after in-flight request finished")
	}
}

// 超过 ShutdownTimeout 仍有请求未完成时，强制关闭并返回超时错误
func TestRunListenerContextShutdownTimeout(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	router := New()
	router.ShutdownTimeout = 50 * time.Millisecond
	router.GET("/stuck", func(c Context) {
		close(entered)
		<-release
	})

	l := newLocalListener(t)
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- router.RunListenerContext(ctx, l) }()
	go func() {
		if resp, err := http.Get("http://" + l.Addr().String() + "/stuck"); err == nil {
			resp.Body.Close()
		}
	}()
	<-entered

	start := time.Now()
	cancel()
	select {
	case err := <-runErr:
		assert.ErrorIs(t, err, stdctx.DeadlineExceeded)
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("ShutdownTimeout was not honored")
	}
}

func TestRunContextServesAndStops(t *testing.T) {
	// 先占一个空闲端口再释放，得到可用于 RunContext 的地址
	l := newLocalListener(t)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	router := New()
	router.GET("/ping", func(c Context) { c.String(http.StatusOK, "pong") })
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- router.RunContext(ctx, addr) }()
	waitForServer(t, "tcp", addr)

	resp, err := http.Get("http://" + addr + "/ping")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "pong", string(body))

	cancel()
	assert.NoError(t, <-runErr)
	// 端口已释放，可以再次监听
	l2, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	l2.Close()
}

func TestRunContextStartupErrors(t *testing.T) {
	router := New()
	ctx := stdctx.Background()

	// 地址不合法：监听失败立即返回
	assert.Error(t, router.RunContext(ctx, "not-an-address"))

	// 证书不存在：ServeTLS 失败立即返回，而不是阻塞等待 ctx
	l := newLocalListener(t)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	done := make(chan error, 1)
	go func() { done <- router.RunTLSContext(ctx, addr, "missing-cert.pem", "missing-key.pem") }()
	select {
	case err := <-done:
		assert.Error(t, err)
		assert.False(t, errors.Is(err, http.ErrServerClosed))
	case <-time.After(5 * time.Second):
		t.Fatal("RunTLSContext should fail fast on invalid certificate")
	}
}

// ctx 在启动前就已取消时，应当立即优雅退出
func TestRunListenerContextAlreadyCanceled(t *testing.T) {
	router := New()
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel()
	assert.NoError(t, router.RunListenerContext(ctx, newLocalListener(t)))
}
