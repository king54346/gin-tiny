// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
)

func formatAsDate(t time.Time) string {
	year, month, day := t.Date()
	return fmt.Sprintf("%d/%02d/%02d", year, month, day)
}

func TestH2c(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	r := Default()
	r.UseH2C = true
	r.GET("/", func(c *context) {
		c.String(200, "<h1>Hello world</h1>")
	})
	go func() {
		err := http.Serve(ln, r.Handler())
		if err != nil {
			t.Log(err)
		}
	}()
	defer ln.Close()

	url := "http://" + ln.Addr().String() + "/"

	httpClient := http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
		},
	}

	res, err := httpClient.Get(url)
	if err != nil {
		t.Error(err)
	}

	resp, _ := io.ReadAll(res.Body)
	assert.Equal(t, "<h1>Hello world</h1>", string(resp))
}

func init() {
	SetMode(TestMode)
}

func TestCreateEngine(t *testing.T) {
	router := New()
	assert.Equal(t, "/", router.basePath)
	assert.Equal(t, router.engine, router)
	assert.Empty(t, router.Handlers)
}

func TestAddRoute(t *testing.T) {
	router := New()
	router.addRoute("GET", "/", HandlersChain{func(_ *context) {}})

	assert.Len(t, router.trees, 1)
	assert.NotNil(t, router.trees.get("GET"))
	assert.Nil(t, router.trees.get("POST"))

	router.addRoute("POST", "/", HandlersChain{func(_ *context) {}})

	assert.Len(t, router.trees, 2)
	assert.NotNil(t, router.trees.get("GET"))
	assert.NotNil(t, router.trees.get("POST"))

	router.addRoute("POST", "/post", HandlersChain{func(_ *context) {}})
	assert.Len(t, router.trees, 2)
}

func TestAddRouteFails(t *testing.T) {
	router := New()
	assert.Panics(t, func() { router.addRoute("", "/", HandlersChain{func(_ *context) {}}) })
	assert.Panics(t, func() { router.addRoute("GET", "a", HandlersChain{func(_ *context) {}}) })
	assert.Panics(t, func() { router.addRoute("GET", "/", HandlersChain{}) })

	router.addRoute("POST", "/post", HandlersChain{func(_ *context) {}})
	assert.Panics(t, func() {
		router.addRoute("POST", "/post", HandlersChain{func(_ *context) {}})
	})
}

func TestCreateDefaultRouter(t *testing.T) {
	router := Default()
	assert.Len(t, router.Handlers, 2)
}

func TestNoRouteWithoutGlobalHandlers(t *testing.T) {
	var middleware0 HandlerFunc = func(c *context) {}
	var middleware1 HandlerFunc = func(c *context) {}

	router := New()

	router.NoRoute(middleware0)
	assert.Nil(t, router.Handlers)
	assert.Len(t, router.noRoute, 1)
	assert.Len(t, router.allNoRoute, 1)
	compareFunc(t, router.noRoute[0], middleware0)
	compareFunc(t, router.allNoRoute[0], middleware0)

	router.NoRoute(middleware1, middleware0)
	assert.Len(t, router.noRoute, 2)
	assert.Len(t, router.allNoRoute, 2)
	compareFunc(t, router.noRoute[0], middleware1)
	compareFunc(t, router.allNoRoute[0], middleware1)
	compareFunc(t, router.noRoute[1], middleware0)
	compareFunc(t, router.allNoRoute[1], middleware0)
}

func TestNoRouteWithGlobalHandlers(t *testing.T) {
	var middleware0 HandlerFunc = func(c *context) {}
	var middleware1 HandlerFunc = func(c *context) {}
	var middleware2 HandlerFunc = func(c *context) {}

	router := New()
	router.Use(middleware2)

	router.NoRoute(middleware0)
	assert.Len(t, router.allNoRoute, 2)
	assert.Len(t, router.Handlers, 1)
	assert.Len(t, router.noRoute, 1)

	compareFunc(t, router.Handlers[0], middleware2)
	compareFunc(t, router.noRoute[0], middleware0)
	compareFunc(t, router.allNoRoute[0], middleware2)
	compareFunc(t, router.allNoRoute[1], middleware0)

	router.Use(middleware1)
	assert.Len(t, router.allNoRoute, 3)
	assert.Len(t, router.Handlers, 2)
	assert.Len(t, router.noRoute, 1)

	compareFunc(t, router.Handlers[0], middleware2)
	compareFunc(t, router.Handlers[1], middleware1)
	compareFunc(t, router.noRoute[0], middleware0)
	compareFunc(t, router.allNoRoute[0], middleware2)
	compareFunc(t, router.allNoRoute[1], middleware1)
	compareFunc(t, router.allNoRoute[2], middleware0)
}

func TestNoMethodWithoutGlobalHandlers(t *testing.T) {
	var middleware0 HandlerFunc = func(c *context) {}
	var middleware1 HandlerFunc = func(c *context) {}

	router := New()

	router.NoMethod(middleware0)
	assert.Empty(t, router.Handlers)
	assert.Len(t, router.noMethod, 1)
	assert.Len(t, router.allNoMethod, 1)
	compareFunc(t, router.noMethod[0], middleware0)
	compareFunc(t, router.allNoMethod[0], middleware0)

	router.NoMethod(middleware1, middleware0)
	assert.Len(t, router.noMethod, 2)
	assert.Len(t, router.allNoMethod, 2)
	compareFunc(t, router.noMethod[0], middleware1)
	compareFunc(t, router.allNoMethod[0], middleware1)
	compareFunc(t, router.noMethod[1], middleware0)
	compareFunc(t, router.allNoMethod[1], middleware0)
}

func TestRebuild404Handlers(t *testing.T) {
}

func TestNoMethodWithGlobalHandlers(t *testing.T) {
	var middleware0 HandlerFunc = func(c *context) {}
	var middleware1 HandlerFunc = func(c *context) {}
	var middleware2 HandlerFunc = func(c *context) {}

	router := New()
	router.Use(middleware2)

	router.NoMethod(middleware0)
	assert.Len(t, router.allNoMethod, 2)
	assert.Len(t, router.Handlers, 1)
	assert.Len(t, router.noMethod, 1)

	compareFunc(t, router.Handlers[0], middleware2)
	compareFunc(t, router.noMethod[0], middleware0)
	compareFunc(t, router.allNoMethod[0], middleware2)
	compareFunc(t, router.allNoMethod[1], middleware0)

	router.Use(middleware1)
	assert.Len(t, router.allNoMethod, 3)
	assert.Len(t, router.Handlers, 2)
	assert.Len(t, router.noMethod, 1)

	compareFunc(t, router.Handlers[0], middleware2)
	compareFunc(t, router.Handlers[1], middleware1)
	compareFunc(t, router.noMethod[0], middleware0)
	compareFunc(t, router.allNoMethod[0], middleware2)
	compareFunc(t, router.allNoMethod[1], middleware1)
	compareFunc(t, router.allNoMethod[2], middleware0)
}

func compareFunc(t *testing.T, a, b any) {
	sf1 := reflect.ValueOf(a)
	sf2 := reflect.ValueOf(b)
	if sf1.Pointer() != sf2.Pointer() {
		t.Error("different functions")
	}
}

func TestListOfRoutes(t *testing.T) {
	router := New()
	router.GET("/", handlerTest1)
	group := router.Group("/users")
	{
		group.GET("/", handlerTest2)
		group.GET("/:id", handlerTest1)
		group.POST("/:id", handlerTest2)
	}

	list := router.Routes()

	assert.Len(t, list, 4)
	assertRoutePresent(t, list, RouteInfo{
		Method:  "GET",
		Path:    "/",
		Handler: "^(.*/vendor/)?gin-tiny.handlerTest1$",
	})
	assertRoutePresent(t, list, RouteInfo{
		Method:  "GET",
		Path:    "/users/",
		Handler: "^(.*/vendor/)?gin-tiny.handlerTest2$",
	})
	assertRoutePresent(t, list, RouteInfo{
		Method:  "GET",
		Path:    "/users/:id",
		Handler: "^(.*/vendor/)?gin-tiny.handlerTest1$",
	})
	assertRoutePresent(t, list, RouteInfo{
		Method:  "POST",
		Path:    "/users/:id",
		Handler: "^(.*/vendor/)?gin-tiny.handlerTest2$",
	})
}

func TestEngineHandleContext(t *testing.T) {
	r := New()
	r.GET("/", func(c *context) {
		c.Request.URL.Path = "/v2"
		r.HandleContext(c)
	})
	v2 := r.Group("/v2")
	{
		v2.GET("/", func(c *context) {})
	}

	assert.NotPanics(t, func() {
		w := PerformRequest(r, "GET", "/")
		assert.Equal(t, 301, w.Code)
	})
}

func TestEngineHandleContextManyReEntries(t *testing.T) {
	expectValue := 10000

	var handlerCounter, middlewareCounter int64

	r := New()
	r.Use(func(c *context) {
		atomic.AddInt64(&middlewareCounter, 1)
	})
	r.GET("/:count", func(c *context) {
		countStr := c.Param("count")
		count, err := strconv.Atoi(countStr)
		assert.NoError(t, err)

		n, err := c.Writer.Write([]byte("."))
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		switch {
		case count > 0:
			c.Request.URL.Path = "/" + strconv.Itoa(count-1)
			r.HandleContext(c)
		}
	}, func(c *context) {
		atomic.AddInt64(&handlerCounter, 1)
	})

	assert.NotPanics(t, func() {
		w := PerformRequest(r, "GET", "/"+strconv.Itoa(expectValue-1)) // include 0 value
		assert.Equal(t, 200, w.Code)
		assert.Equal(t, expectValue, w.Body.Len())
	})

	assert.Equal(t, int64(expectValue), handlerCounter)
	assert.Equal(t, int64(expectValue), middlewareCounter)
}

func TestPrepareTrustedCIRDsWith(t *testing.T) {
	r := New()

	// valid ipv4 cidr
	{
		expectedTrustedCIDRs := []*net.IPNet{parseCIDR("0.0.0.0/0")}
		err := r.SetTrustedProxies([]string{"0.0.0.0/0"})

		assert.NoError(t, err)
		assert.Equal(t, expectedTrustedCIDRs, r.trustedCIDRs)
	}

	// invalid ipv4 cidr
	{
		err := r.SetTrustedProxies([]string{"192.168.1.33/33"})

		assert.Error(t, err)
	}

	// valid ipv4 address
	{
		expectedTrustedCIDRs := []*net.IPNet{parseCIDR("192.168.1.33/32")}

		err := r.SetTrustedProxies([]string{"192.168.1.33"})

		assert.NoError(t, err)
		assert.Equal(t, expectedTrustedCIDRs, r.trustedCIDRs)
	}

	// invalid ipv4 address
	{
		err := r.SetTrustedProxies([]string{"192.168.1.256"})

		assert.Error(t, err)
	}

	// valid ipv6 address
	{
		expectedTrustedCIDRs := []*net.IPNet{parseCIDR("2002:0000:0000:1234:abcd:ffff:c0a8:0101/128")}
		err := r.SetTrustedProxies([]string{"2002:0000:0000:1234:abcd:ffff:c0a8:0101"})

		assert.NoError(t, err)
		assert.Equal(t, expectedTrustedCIDRs, r.trustedCIDRs)
	}

	// invalid ipv6 address
	{
		err := r.SetTrustedProxies([]string{"gggg:0000:0000:1234:abcd:ffff:c0a8:0101"})

		assert.Error(t, err)
	}

	// valid ipv6 cidr
	{
		expectedTrustedCIDRs := []*net.IPNet{parseCIDR("::/0")}
		err := r.SetTrustedProxies([]string{"::/0"})

		assert.NoError(t, err)
		assert.Equal(t, expectedTrustedCIDRs, r.trustedCIDRs)
	}

	// invalid ipv6 cidr
	{
		err := r.SetTrustedProxies([]string{"gggg:0000:0000:1234:abcd:ffff:c0a8:0101/129"})

		assert.Error(t, err)
	}

	// valid combination
	{
		expectedTrustedCIDRs := []*net.IPNet{
			parseCIDR("::/0"),
			parseCIDR("192.168.0.0/16"),
			parseCIDR("172.16.0.1/32"),
		}
		err := r.SetTrustedProxies([]string{
			"::/0",
			"192.168.0.0/16",
			"172.16.0.1",
		})

		assert.NoError(t, err)
		assert.Equal(t, expectedTrustedCIDRs, r.trustedCIDRs)
	}

	// invalid combination
	{
		err := r.SetTrustedProxies([]string{
			"::/0",
			"192.168.0.0/16",
			"172.16.0.256",
		})

		assert.Error(t, err)
	}

	// nil value
	{
		err := r.SetTrustedProxies(nil)

		assert.Nil(t, r.trustedCIDRs)
		assert.Nil(t, err)
	}
}

func parseCIDR(cidr string) *net.IPNet {
	_, parsedCIDR, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println(err)
	}
	return parsedCIDR
}

func assertRoutePresent(t *testing.T, gotRoutes RoutesInfo, wantRoute RouteInfo) {
	for _, gotRoute := range gotRoutes {
		if gotRoute.Path == wantRoute.Path && gotRoute.Method == wantRoute.Method {
			assert.Regexp(t, wantRoute.Handler, gotRoute.Handler)
			return
		}
	}
	t.Errorf("route not found: %v", wantRoute)
}

func handlerTest1(c *context) {}
func handlerTest2(c *context) {}
