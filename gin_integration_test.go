// Copyright 2017 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"bufio"
	stdctx "context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// params[0]=url example:http://127.0.0.1:8080/index (cannot be empty)
// params[1]=response status (custom compare status) default:"200 OK"
// params[2]=response body (custom compare content)  default:"it worked"
func testRequest(t *testing.T, params ...string) {

	if len(params) == 0 {
		t.Fatal("url cannot be empty")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(params[0])
	require.NoError(t, err)
	defer resp.Body.Close()

	body, ioerr := io.ReadAll(resp.Body)
	assert.NoError(t, ioerr)

	var responseStatus = "200 OK"
	if len(params) > 1 && params[1] != "" {
		responseStatus = params[1]
	}

	var responseBody = "it worked"
	if len(params) > 2 && params[2] != "" {
		responseBody = params[2]
	}

	assert.Equal(t, responseStatus, resp.Status, "should get a "+responseStatus)
	if responseStatus == "200 OK" {
		assert.Equal(t, responseBody, string(body), "resp body should match")
	}
}

func TestRunEmpty(t *testing.T) {
	t.Setenv("PORT", "")
	router := New()
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
	startServer(t, func(ctx stdctx.Context) error { return router.RunContext(ctx) })
	waitForServer(t, "tcp", "localhost:8080")

	assert.Error(t, router.Run(":8080"))
	testRequest(t, "http://localhost:8080/example")
}

func TestRunTLS(t *testing.T) {
	router := New()
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
	startServer(t, func(ctx stdctx.Context) error {
		return router.RunTLSContext(ctx, ":8443", "./testdata/certificate/cert.pem", "./testdata/certificate/key.pem")
	})
	waitForServer(t, "tcp", "localhost:8443")

	assert.Error(t, router.RunTLS(":8443", "./testdata/certificate/cert.pem", "./testdata/certificate/key.pem"))
	testRequest(t, "https://localhost:8443/example")
}

func TestRunEmptyWithEnv(t *testing.T) {
	t.Setenv("PORT", "3123")
	router := New()
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
	startServer(t, func(ctx stdctx.Context) error { return router.RunContext(ctx) })
	waitForServer(t, "tcp", "localhost:3123")

	assert.Error(t, router.Run(":3123"))
	testRequest(t, "http://localhost:3123/example")
}

func TestBadTrustedCIDRs(t *testing.T) {
	router := New()
	assert.Error(t, router.SetTrustedProxies([]string{"hello/world"}))
}

/* legacy tests
func TestBadTrustedCIDRsForRun(t *testing.T) {
	os.Setenv("PORT", "")
	router := New()
	router.TrustedProxies = []string{"hello/world"}
	assert.Error(t, router.Run(":8080"))
}

func TestBadTrustedCIDRsForRunUnix(t *testing.T) {
	router := New()
	router.TrustedProxies = []string{"hello/world"}

	unixTestSocket := filepath.Join(os.TempDir(), "unix_unit_test")

	defer os.Remove(unixTestSocket)

	go func() {
		router.GET("/example", func(c *context) { c.String(http.StatusOK, "it worked") })
		assert.Error(t, router.RunUnix(unixTestSocket))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	time.Sleep(5 * time.Millisecond)
}

func TestBadTrustedCIDRsForRunFd(t *testing.T) {
	router := New()
	router.TrustedProxies = []string{"hello/world"}

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	assert.NoError(t, err)
	listener, err := net.ListenTCP("tcp", addr)
	assert.NoError(t, err)
	socketFile, err := listener.File()
	assert.NoError(t, err)

	go func() {
		router.GET("/example", func(c *context) { c.String(http.StatusOK, "it worked") })
		assert.Error(t, router.RunFd(int(socketFile.Fd())))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	time.Sleep(5 * time.Millisecond)
}

func TestBadTrustedCIDRsForRunListener(t *testing.T) {
	router := New()
	router.TrustedProxies = []string{"hello/world"}

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	assert.NoError(t, err)
	listener, err := net.ListenTCP("tcp", addr)
	assert.NoError(t, err)
	go func() {
		router.GET("/example", func(c *context) { c.String(http.StatusOK, "it worked") })
		assert.Error(t, router.RunListener(listener))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	time.Sleep(5 * time.Millisecond)
}

func TestBadTrustedCIDRsForRunTLS(t *testing.T) {
	os.Setenv("PORT", "")
	router := New()
	router.TrustedProxies = []string{"hello/world"}
	assert.Error(t, router.RunTLS(":8080", "./testdata/certificate/cert.pem", "./testdata/certificate/key.pem"))
}
*/

func TestRunTooMuchParams(t *testing.T) {
	router := New()
	assert.Panics(t, func() {
		assert.NoError(t, router.Run("2", "2"))
	})
}

func TestRunWithPort(t *testing.T) {
	router := New()
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
	startServer(t, func(ctx stdctx.Context) error { return router.RunContext(ctx, ":5150") })
	waitForServer(t, "tcp", "localhost:5150")

	assert.Error(t, router.Run(":5150"))
	testRequest(t, "http://localhost:5150/example")
}

func TestUnixSocket(t *testing.T) {
	router := New()

	// 每个测试独立的路径：固定路径在进程被中断时会残留 socket 文件，下次运行可能连到失效的旧 socket
	unixTestSocket := filepath.Join(t.TempDir(), "gin.sock")

	go func() {
		router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
		assert.NoError(t, router.RunUnix(unixTestSocket))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	waitForServer(t, "unix", unixTestSocket)

	response := rawGet(t, "unix", unixTestSocket, "/example")
	assert.Contains(t, response, "HTTP/1.0 200", "should get a 200")
	assert.Contains(t, response, "it worked", "resp body should match")
}

func TestBadUnixSocket(t *testing.T) {
	router := New()
	assert.Error(t, router.RunUnix("#/tmp/unix_unit_test"))
}

func TestFileDescriptor(t *testing.T) {
	if isWindows() {
		t.Skip("net.FileListener is not supported on windows")
	}
	router := New()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	assert.NoError(t, err)
	listener, err := net.ListenTCP("tcp", addr)
	assert.NoError(t, err)
	socketFile, err := listener.File()
	if isWindows() {
		// not supported by windows, it is unimplemented now
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}

	if socketFile == nil {
		return
	}

	go func() {
		router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
		assert.NoError(t, router.RunFd(int(socketFile.Fd())))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	waitForServer(t, "tcp", listener.Addr().String())

	response := rawGet(t, "tcp", listener.Addr().String(), "/example")
	assert.Contains(t, response, "HTTP/1.0 200", "should get a 200")
	assert.Contains(t, response, "it worked", "resp body should match")
}

func TestBadFileDescriptor(t *testing.T) {
	router := New()
	assert.Error(t, router.RunFd(0))
}

func TestListener(t *testing.T) {
	router := New()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	assert.NoError(t, err)
	listener, err := net.ListenTCP("tcp", addr)
	assert.NoError(t, err)
	go func() {
		router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })
		assert.NoError(t, router.RunListener(listener))
	}()
	// have to wait for the goroutine to start and run the server
	// otherwise the main thread will complete
	waitForServer(t, "tcp", listener.Addr().String())

	response := rawGet(t, "tcp", listener.Addr().String(), "/example")
	assert.Contains(t, response, "HTTP/1.0 200", "should get a 200")
	assert.Contains(t, response, "it worked", "resp body should match")
}

func TestBadListener(t *testing.T) {
	router := New()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:10086")
	assert.NoError(t, err)
	listener, err := net.ListenTCP("tcp", addr)
	assert.NoError(t, err)
	listener.Close()
	assert.Error(t, router.RunListener(listener))
}

func TestWithHttptestWithAutoSelectedPort(t *testing.T) {
	router := New()
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })

	ts := httptest.NewServer(router)
	defer ts.Close()

	testRequest(t, ts.URL+"/example")
}

func TestConcurrentHandleContext(t *testing.T) {
	router := New()
	router.GET("/", func(c Context) {
		c.Request().URL.Path = "/example"
		c2 := c.Copy()
		router.HandleContext(c2)
	})
	router.GET("/example", func(c Context) { c.String(http.StatusOK, "it worked") })

	var wg sync.WaitGroup
	iterations := 200
	wg.Add(iterations)
	for range iterations {
		go func() {
			testGetRequestHandler(t, router, "/")
			wg.Done()
		}()
	}
	wg.Wait()
}

// func TestWithHttptestWithSpecifiedPort(t *testing.T) {
// 	router := New()
// 	router.GET("/example", func(c *context) { c.String(http.StatusOK, "it worked") })

// 	l, _ := net.Listen("tcp", ":8033")
// 	ts := httptest.Server{
// 		Listener: l,
// 		Config:   &http.Server{Handler: router},
// 	}
// 	ts.Start()
// 	defer ts.Close()

// 	testRequest(t, "http://localhost:8033/example")
// }

func testGetRequestHandler(t *testing.T, h http.Handler, url string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, "it worked", w.Body.String(), "resp body should match")
	assert.Equal(t, 200, w.Code, "should get a 200")
}

func TestTreeRunDynamicRouting(t *testing.T) {
	router := New()
	router.GET("/aa/*xx", func(c Context) { c.String(http.StatusOK, "/aa/*xx") })
	router.GET("/ab/*xx", func(c Context) { c.String(http.StatusOK, "/ab/*xx") })
	router.GET("/", func(c Context) { c.String(http.StatusOK, "home") })
	router.GET("/:cc", func(c Context) { c.String(http.StatusOK, "/:cc") })
	router.GET("/c1/:dd/e", func(c Context) { c.String(http.StatusOK, "/c1/:dd/e") })
	router.GET("/c1/:dd/e1", func(c Context) { c.String(http.StatusOK, "/c1/:dd/e1") })
	router.GET("/c1/:dd/f1", func(c Context) { c.String(http.StatusOK, "/c1/:dd/f1") })
	router.GET("/c1/:dd/f2", func(c Context) { c.String(http.StatusOK, "/c1/:dd/f2") })
	router.GET("/:cc/cc", func(c Context) { c.String(http.StatusOK, "/:cc/cc") })
	router.GET("/:cc/:dd/ee", func(c Context) { c.String(http.StatusOK, "/:cc/:dd/ee") })
	router.GET("/:cc/:dd/f", func(c Context) { c.String(http.StatusOK, "/:cc/:dd/f") })
	router.GET("/:cc/:dd/:ee/ff", func(c Context) { c.String(http.StatusOK, "/:cc/:dd/:ee/ff") })
	router.GET("/:cc/:dd/:ee/:ff/gg", func(c Context) { c.String(http.StatusOK, "/:cc/:dd/:ee/:ff/gg") })
	router.GET("/:cc/:dd/:ee/:ff/:gg/hh", func(c Context) { c.String(http.StatusOK, "/:cc/:dd/:ee/:ff/:gg/hh") })
	router.GET("/get/test/abc/", func(c Context) { c.String(http.StatusOK, "/get/test/abc/") })
	router.GET("/get/:param/abc/", func(c Context) { c.String(http.StatusOK, "/get/:param/abc/") })
	router.GET("/something/:paramname/thirdthing", func(c Context) { c.String(http.StatusOK, "/something/:paramname/thirdthing") })
	router.GET("/something/secondthing/test", func(c Context) { c.String(http.StatusOK, "/something/secondthing/test") })
	router.GET("/get/abc", func(c Context) { c.String(http.StatusOK, "/get/abc") })
	router.GET("/get/:param", func(c Context) { c.String(http.StatusOK, "/get/:param") })
	router.GET("/get/abc/123abc", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc") })
	router.GET("/get/abc/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/:param") })
	router.GET("/get/abc/123abc/xxx8", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8") })
	router.GET("/get/abc/123abc/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/:param") })
	router.GET("/get/abc/123abc/xxx8/1234", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/1234") })
	router.GET("/get/abc/123abc/xxx8/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/:param") })
	router.GET("/get/abc/123abc/xxx8/1234/ffas", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/1234/ffas") })
	router.GET("/get/abc/123abc/xxx8/1234/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/1234/:param") })
	router.GET("/get/abc/123abc/xxx8/1234/kkdd/12c", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/1234/kkdd/12c") })
	router.GET("/get/abc/123abc/xxx8/1234/kkdd/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abc/xxx8/1234/kkdd/:param") })
	router.GET("/get/abc/:param/test", func(c Context) { c.String(http.StatusOK, "/get/abc/:param/test") })
	router.GET("/get/abc/123abd/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abd/:param") })
	router.GET("/get/abc/123abddd/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abddd/:param") })
	router.GET("/get/abc/123/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123/:param") })
	router.GET("/get/abc/123abg/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abg/:param") })
	router.GET("/get/abc/123abf/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abf/:param") })
	router.GET("/get/abc/123abfff/:param", func(c Context) { c.String(http.StatusOK, "/get/abc/123abfff/:param") })

	ts := httptest.NewServer(router)
	defer ts.Close()

	testRequest(t, ts.URL+"/", "", "home")
	testRequest(t, ts.URL+"/aa/aa", "", "/aa/*xx")
	testRequest(t, ts.URL+"/ab/ab", "", "/ab/*xx")
	testRequest(t, ts.URL+"/all", "", "/:cc")
	testRequest(t, ts.URL+"/all/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/a/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/c1/d/e", "", "/c1/:dd/e")
	testRequest(t, ts.URL+"/c1/d/e1", "", "/c1/:dd/e1")
	testRequest(t, ts.URL+"/c1/d/ee", "", "/:cc/:dd/ee")
	testRequest(t, ts.URL+"/c1/d/f", "", "/:cc/:dd/f")
	testRequest(t, ts.URL+"/c/d/ee", "", "/:cc/:dd/ee")
	testRequest(t, ts.URL+"/c/d/e/ff", "", "/:cc/:dd/:ee/ff")
	testRequest(t, ts.URL+"/c/d/e/f/gg", "", "/:cc/:dd/:ee/:ff/gg")
	testRequest(t, ts.URL+"/c/d/e/f/g/hh", "", "/:cc/:dd/:ee/:ff/:gg/hh")
	testRequest(t, ts.URL+"/cc/dd/ee/ff/gg/hh", "", "/:cc/:dd/:ee/:ff/:gg/hh")
	testRequest(t, ts.URL+"/a", "", "/:cc")
	testRequest(t, ts.URL+"/d", "", "/:cc")
	testRequest(t, ts.URL+"/ad", "", "/:cc")
	testRequest(t, ts.URL+"/dd", "", "/:cc")
	testRequest(t, ts.URL+"/aa", "", "/:cc")
	testRequest(t, ts.URL+"/aaa", "", "/:cc")
	testRequest(t, ts.URL+"/aaa/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/ab", "", "/:cc")
	testRequest(t, ts.URL+"/abb", "", "/:cc")
	testRequest(t, ts.URL+"/abb/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/dddaa", "", "/:cc")
	testRequest(t, ts.URL+"/allxxxx", "", "/:cc")
	testRequest(t, ts.URL+"/alldd", "", "/:cc")
	testRequest(t, ts.URL+"/cc/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/ccc/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/deedwjfs/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/acllcc/cc", "", "/:cc/cc")
	testRequest(t, ts.URL+"/get/test/abc/", "", "/get/test/abc/")
	testRequest(t, ts.URL+"/get/testaa/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/te/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/xx/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/tt/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/a/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/t/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/aa/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/get/abas/abc/", "", "/get/:param/abc/")
	testRequest(t, ts.URL+"/something/secondthing/test", "", "/something/secondthing/test")
	testRequest(t, ts.URL+"/something/secondthingaaaa/thirdthing", "", "/something/:paramname/thirdthing")
	testRequest(t, ts.URL+"/something/abcdad/thirdthing", "", "/something/:paramname/thirdthing")
	testRequest(t, ts.URL+"/something/se/thirdthing", "", "/something/:paramname/thirdthing")
	testRequest(t, ts.URL+"/something/s/thirdthing", "", "/something/:paramname/thirdthing")
	testRequest(t, ts.URL+"/something/secondthing/thirdthing", "", "/something/:paramname/thirdthing")
	testRequest(t, ts.URL+"/get/abc", "", "/get/abc")
	testRequest(t, ts.URL+"/get/a", "", "/get/:param")
	testRequest(t, ts.URL+"/get/abz", "", "/get/:param")
	testRequest(t, ts.URL+"/get/12a", "", "/get/:param")
	testRequest(t, ts.URL+"/get/abcd", "", "/get/:param")
	testRequest(t, ts.URL+"/get/abc/123abc", "", "/get/abc/123abc")
	testRequest(t, ts.URL+"/get/abc/12", "", "/get/abc/:param")
	testRequest(t, ts.URL+"/get/abc/123ab", "", "/get/abc/:param")
	testRequest(t, ts.URL+"/get/abc/xyz", "", "/get/abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abcddxx", "", "/get/abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8", "", "/get/abc/123abc/xxx8")
	testRequest(t, ts.URL+"/get/abc/123abc/x", "", "/get/abc/123abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx", "", "/get/abc/123abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/abc", "", "/get/abc/123abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8xxas", "", "/get/abc/123abc/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234", "", "/get/abc/123abc/xxx8/1234")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1", "", "/get/abc/123abc/xxx8/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/123", "", "/get/abc/123abc/xxx8/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/78k", "", "/get/abc/123abc/xxx8/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234xxxd", "", "/get/abc/123abc/xxx8/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/ffas", "", "/get/abc/123abc/xxx8/1234/ffas")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/f", "", "/get/abc/123abc/xxx8/1234/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/ffa", "", "/get/abc/123abc/xxx8/1234/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kka", "", "/get/abc/123abc/xxx8/1234/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/ffas321", "", "/get/abc/123abc/xxx8/1234/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/12c", "", "/get/abc/123abc/xxx8/1234/kkdd/12c")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/1", "", "/get/abc/123abc/xxx8/1234/kkdd/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/12", "", "/get/abc/123abc/xxx8/1234/kkdd/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/12b", "", "/get/abc/123abc/xxx8/1234/kkdd/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/34", "", "/get/abc/123abc/xxx8/1234/kkdd/:param")
	testRequest(t, ts.URL+"/get/abc/123abc/xxx8/1234/kkdd/12c2e3", "", "/get/abc/123abc/xxx8/1234/kkdd/:param")
	testRequest(t, ts.URL+"/get/abc/12/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abdd/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abdddf/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123ab/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abgg/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abff/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abffff/test", "", "/get/abc/:param/test")
	testRequest(t, ts.URL+"/get/abc/123abd/test", "", "/get/abc/123abd/:param")
	testRequest(t, ts.URL+"/get/abc/123abddd/test", "", "/get/abc/123abddd/:param")
	testRequest(t, ts.URL+"/get/abc/123/test22", "", "/get/abc/123/:param")
	testRequest(t, ts.URL+"/get/abc/123abg/test", "", "/get/abc/123abg/:param")
	testRequest(t, ts.URL+"/get/abc/123abf/testss", "", "/get/abc/123abf/:param")
	testRequest(t, ts.URL+"/get/abc/123abfff/te", "", "/get/abc/123abfff/:param")
	// 404 not found
	testRequest(t, ts.URL+"/c/d/e", "404 Not Found")
	testRequest(t, ts.URL+"/c/d/e1", "404 Not Found")
	testRequest(t, ts.URL+"/c/d/eee", "404 Not Found")
	testRequest(t, ts.URL+"/c1/d/eee", "404 Not Found")
	testRequest(t, ts.URL+"/c1/d/e2", "404 Not Found")
	testRequest(t, ts.URL+"/cc/dd/ee/ff/gg/hh1", "404 Not Found")
	testRequest(t, ts.URL+"/a/dd", "404 Not Found")
	testRequest(t, ts.URL+"/addr/dd/aa", "404 Not Found")
	testRequest(t, ts.URL+"/something/secondthing/121", "404 Not Found")
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

// waitForServer 轮询直到服务可以连接，取代固定时长的 sleep：
// 机器负载高时 5ms 不足以让服务启动，连接失败后继续使用 nil 连接会 panic 并拖垮整个包的测试
func waitForServer(t *testing.T, network, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		c, err := net.Dial(network, addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 3*time.Second, 5*time.Millisecond, "server %s://%s did not start", network, addr)
}

// rawGet 通过原始连接发送 HTTP/1.0 请求并读取完整响应。
// 设置读写截止时间，服务端异常时让测试失败，而不是一直阻塞到全局超时
func rawGet(t *testing.T, network, addr, path string) string {
	t.Helper()
	c, err := net.Dial(network, addr)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = fmt.Fprintf(c, "GET %s HTTP/1.0\r\n\r\n", path)
	require.NoError(t, err)
	var response strings.Builder
	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
	}
	require.NoError(t, scanner.Err())
	return response.String()
}

// startServer 在后台运行服务，测试结束时取消 ctx 并等待服务优雅退出、释放端口，
// 这样固定端口的测试也能在同一进程中重复运行（go test -count=N）
func startServer(t *testing.T, run func(ctx stdctx.Context) error) {
	t.Helper()
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down in time")
		}
	})
}
