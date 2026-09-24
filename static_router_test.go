package ginTiny

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticMatchDifferentHandlersPerMethod(t *testing.T) {
	r := New()
	r.StaticMatch([]string{http.MethodGet}, "/res", func(c Context) { c.String(http.StatusOK, "get") })
	r.StaticMatch([]string{http.MethodPost}, "/res", func(c Context) { c.String(http.StatusCreated, "post") })

	w := PerformRequest(r, http.MethodGet, "/res")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "get", w.Body.String())

	w = PerformRequest(r, http.MethodPost, "/res")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "post", w.Body.String())
}

func TestStaticMatchCustomMethod(t *testing.T) {
	r := New()
	r.StaticMatch([]string{"PURGE"}, "/cache", func(c Context) { c.String(http.StatusOK, "purged") })

	w := PerformRequest(r, "PURGE", "/cache")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "purged", w.Body.String())
}

func TestStaticMatchDuplicatePanics(t *testing.T) {
	r := New()
	r.StaticMatch([]string{http.MethodGet}, "/dup", func(c Context) {})
	assert.Panics(t, func() {
		r.StaticMatch([]string{http.MethodGet}, "/dup", func(c Context) {})
	})
}

func TestStaticMatchFallsBackToTree(t *testing.T) {
	r := New()
	r.StaticMatch([]string{http.MethodGet}, "/mix", func(c Context) { c.String(http.StatusOK, "static") })
	r.POST("/mix", func(c Context) { c.String(http.StatusOK, "tree") })

	w := PerformRequest(r, http.MethodPost, "/mix")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tree", w.Body.String())
}

func TestStaticMatchMethodNotAllowed(t *testing.T) {
	r := New()
	r.HandleMethodNotAllowed = true
	r.StaticMatch([]string{http.MethodGet}, "/only-get", func(c Context) {})

	w := PerformRequest(r, http.MethodPost, "/only-get")
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestRoutesIncludeStaticRouter(t *testing.T) {
	r := New()
	r.StaticMatch([]string{http.MethodGet, http.MethodPost}, "/s", handlerTest1)
	r.GET("/t/:id", handlerTest2)

	routes := r.Routes()
	assert.Len(t, routes, 3)
	assertRoutePresent(t, routes, RouteInfo{Method: http.MethodGet, Path: "/s", Handler: "handlerTest1$"})
	assertRoutePresent(t, routes, RouteInfo{Method: http.MethodPost, Path: "/s", Handler: "handlerTest1$"})
	assertRoutePresent(t, routes, RouteInfo{Method: http.MethodGet, Path: "/t/:id", Handler: "handlerTest2$"})
}

func TestRouteParamsAreNotShared(t *testing.T) {
	r := New()
	r.GET("/user/:id", func(c Context) { c.String(http.StatusOK, c.Param("id")) })

	for _, id := range []string{"1", "2", "3", "1"} {
		w := PerformRequest(r, http.MethodGet, "/user/"+id)
		assert.Equal(t, id, w.Body.String())
	}
}

func TestWithErrorHandlers(t *testing.T) {
	r := New()
	var called bool
	r.PUTWithError("/bad", func(c Context) error {
		return &Error{Err: errors.New("bad id"), Type: ErrorTypePublic}
	}, func(c Context) error {
		called = true
		return nil
	})
	r.DELETEWithError("/boom", func(c Context) error { return errors.New("db down") })
	r.GETWithError("/abort", func(c Context) error {
		c.AbortWithStatus(http.StatusForbidden)
		return nil
	}, func(c Context) error {
		called = true
		return nil
	})

	w := PerformRequest(r, http.MethodPut, "/bad")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "bad id")

	w = PerformRequest(r, http.MethodDelete, "/boom")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "db down")

	w = PerformRequest(r, http.MethodGet, "/abort")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, called)
}

func TestGetAs(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("n", 42)

	n, ok := GetAs[int](c, "n")
	assert.True(t, ok)
	assert.Equal(t, 42, n)

	_, ok = GetAs[string](c, "n")
	assert.False(t, ok)

	_, ok = GetAs[int](c, "missing")
	assert.False(t, ok)

	assert.Equal(t, 42, MustGetAs[int](c, "n"))
	assert.Panics(t, func() { MustGetAs[string](c, "n") })
}

func TestClientIPWithIPv4MappedTrustedProxy(t *testing.T) {
	r := New()
	assert.NoError(t, r.SetTrustedProxies([]string{"10.0.0.0/8"}))

	c, _ := CreateTestContext(httptest.NewRecorder())
	c.engine = r
	c.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.request.RemoteAddr = "[::ffff:10.1.2.3]:1234"
	c.request.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.2")

	assert.Equal(t, "1.1.1.1", c.ClientIP())
}

// 静态索引只是 radix 树的加速缓存：有索引与只查树（清空索引）的结果必须完全一致，
// 包括 404/405、Allow、尾斜杠重定向和大小写修正
func TestStaticIndexEquivalentToTree(t *testing.T) {
	routes := []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/users"},
		{http.MethodGet, "/users/new"},
		{http.MethodGet, "/users/:id"},
		{http.MethodGet, "/users/:id/posts"},
		{http.MethodPost, "/users"},
		{http.MethodGet, "/files/*path"},
		{http.MethodGet, "/a/b/c"},
		{http.MethodGet, "/a/:x/d"},
		{http.MethodGet, "/trailing/"},
		{http.MethodGet, "/Mixed/Case"},
		{http.MethodPut, "/only-put"},
		{"PURGE", "/cache"},
	}
	build := func(withIndex bool) *Engine {
		r := New()
		r.HandleMethodNotAllowed = true
		r.RedirectFixedPath = true
		for _, rt := range routes {
			r.Handle(rt.method, rt.path, func(c Context) {
				c.String(http.StatusOK, "%s %s %v", rt.method, c.FullPath(), c.Params())
			})
		}
		if !withIndex {
			for _, tree := range r.trees.getNotNullMethodTree() {
				clear(tree.static)
			}
		}
		return r
	}
	indexed, treeOnly := build(true), build(false)
	assert.NotEmpty(t, indexed.trees.getTree(http.MethodGet).static)

	requests := []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/users"}, {"GET", "/users/"}, {"GET", "/users/new"},
		{"GET", "/users/new/"}, {"GET", "/users/42"}, {"GET", "/users/42/posts"},
		{"POST", "/users"}, {"PUT", "/users"}, {"DELETE", "/users/new"},
		{"GET", "/files/readme"}, {"GET", "/files/"}, {"GET", "/files"},
		{"GET", "/a/b/c"}, {"GET", "/a/b/d"}, {"GET", "/a/z/d"}, {"GET", "/a/b/c/"},
		{"GET", "/trailing"}, {"GET", "/trailing/"}, {"POST", "/trailing"},
		{"GET", "/USERS/NEW"}, {"GET", "/Users"}, {"GET", "/mixed/case"}, {"GET", "/MIXED/CASE/"},
		{"GET", "/only-put"}, {"PURGE", "/cache"}, {"GET", "/cache"}, {"GET", "/missing"},
		{"GET", "//users"}, {"GET", "/users/../users/new"},
	}
	for _, req := range requests {
		want := PerformRequest(treeOnly, req.method, req.path)
		got := PerformRequest(indexed, req.method, req.path)
		name := req.method + " " + req.path
		assert.Equal(t, want.Code, got.Code, name)
		assert.Equal(t, want.Body.String(), got.Body.String(), name)
		assert.Equal(t, want.Header().Get("Location"), got.Header().Get("Location"), name)
		assert.ElementsMatch(t, splitAllow(want.Header().Get("Allow")), splitAllow(got.Header().Get("Allow")), name)
	}
}

func splitAllow(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ", ")
}

// 静态路由与同层 catch-all 冲突时由树在注册阶段报错，与原版 gin 一致
func TestStaticRouteConflictsWithCatchAll(t *testing.T) {
	r := New()
	r.GET("/files/*path", func(c Context) {})
	assert.Panics(t, func() { r.StaticFile("/files/readme", "./gin.go") })

	// 注册失败时索引不能被写入
	assert.NotContains(t, r.trees.getTree(http.MethodGet).static, "/files/readme")
}

func TestStaticIndexOnlyHoldsStaticPaths(t *testing.T) {
	r := New()
	r.GET("/plain", handlerTest1)
	r.GET("/p/:id", handlerTest1)
	r.GET("/c/*all", handlerTest1)

	get := r.trees.getTree(http.MethodGet)
	assert.Len(t, get.static, 1)
	assert.Contains(t, get.static, "/plain")

	// 静态路由同样存在于树中，树仍是完整的数据源
	skipped := make([]skippedNode, 0)
	assert.NotNil(t, get.root.getValue("/plain", nil, &skipped, false).handlers)
}

func TestStaticMatchConflictsWithNormalRoute(t *testing.T) {
	r := New()
	r.GET("/dup", func(c Context) {})
	assert.Panics(t, func() {
		r.StaticMatch([]string{http.MethodGet}, "/dup", func(c Context) {})
	})

	r = New()
	r.StaticMatch([]string{http.MethodGet}, "/dup2", func(c Context) {})
	assert.Panics(t, func() { r.GET("/dup2", func(c Context) {}) })
}

func TestStaticMatchRejectsWildcards(t *testing.T) {
	r := New()
	assert.Panics(t, func() { r.StaticMatch([]string{http.MethodGet}, "/user/:id", func(c Context) {}) })
	assert.Panics(t, func() { r.StaticRouter("/files/*path", func(c Context) {}) })
}

func TestStaticMatchRedirects(t *testing.T) {
	r := New()
	r.RedirectFixedPath = true
	r.StaticMatch([]string{http.MethodGet}, "/foo", func(c Context) {})
	r.StaticMatch([]string{http.MethodGet}, "/bar/", func(c Context) {})

	w := PerformRequest(r, http.MethodGet, "/foo/")
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, "/foo", w.Header().Get("Location"))

	// 注册时保留尾斜杠，不再被 path.Clean 吞掉
	assert.Equal(t, http.StatusOK, PerformRequest(r, http.MethodGet, "/bar/").Code)
	assert.Equal(t, http.StatusMovedPermanently, PerformRequest(r, http.MethodGet, "/bar").Code)

	w = PerformRequest(r, http.MethodGet, "/FOO")
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, "/foo", w.Header().Get("Location"))
}

func TestHandleWithErrorVariants(t *testing.T) {
	r := New()
	ok := func(c Context) error { c.String(http.StatusOK, c.Request().Method); return nil }
	r.HandleWithError("PURGE", "/e", ok)
	r.POSTWithError("/e", ok)
	r.PATCHWithError("/e", ok)

	for _, m := range []string{"PURGE", http.MethodPost, http.MethodPatch} {
		w := PerformRequest(r, m, "/e")
		assert.Equal(t, http.StatusOK, w.Code, m)
		assert.Equal(t, m, w.Body.String())
	}

	assert.Panics(t, func() { r.HandleWithError("get", "/x", ok) })
	assert.Panics(t, func() { r.GETWithError("/x") })
}

func TestDefaultHTTPErrorHandler(t *testing.T) {
	r := New()
	// 被包装的 *Error 也要识别为参数错误
	r.GETWithError("/wrapped", func(c Context) error {
		return fmt.Errorf("wrap: %w", &Error{Err: errors.New("bad id"), Type: ErrorTypePublic})
	})
	// 响应已写出时不能再改状态码，只记录错误
	var recorded errorMsgs
	r.GETWithError("/written", func(c Context) error {
		c.String(http.StatusAccepted, "partial")
		return errors.New("late failure")
	}, func(c Context) error {
		t.Error("handler after error must not run")
		return nil
	})
	r.Use(func(c Context) {
		c.Next()
		recorded = c.Errors()
	})
	r.GETWithError("/written2", func(c Context) error {
		c.String(http.StatusAccepted, "partial")
		return errors.New("late failure")
	})

	w := PerformRequest(r, http.MethodGet, "/wrapped")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "bad id")

	w = PerformRequest(r, http.MethodGet, "/written")
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Equal(t, "partial", w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/written2")
	assert.Equal(t, http.StatusAccepted, w.Code)
	if assert.Len(t, recorded, 1) {
		assert.EqualError(t, recorded[0], "late failure")
	}
}

func TestCustomHTTPErrorHandler(t *testing.T) {
	r := New()
	r.HTTPErrorHandler = func(err error, c Context) {
		c.AbortWithStatusJSON(http.StatusTeapot, H{"msg": err.Error()})
	}
	r.GETWithError("/boom", func(c Context) error { return errors.New("boom") })

	w := PerformRequest(r, http.MethodGet, "/boom")
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.JSONEq(t, `{"msg":"boom"}`, w.Body.String())
}

type foreignContext struct{ Context }

func TestHandleContextRejectsForeignContext(t *testing.T) {
	r := New()
	assert.Panics(t, func() { r.HandleContext(foreignContext{}) })
}

func TestHandleContextReroutesStaticAndParamRoutes(t *testing.T) {
	r := New()
	r.GET("/old", func(c Context) {
		c.Request().URL.Path = "/users/7"
		r.HandleContext(c)
	})
	r.GET("/users/:id", func(c Context) { c.String(http.StatusOK, "user "+c.Param("id")) })

	w := PerformRequest(r, http.MethodGet, "/old")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user 7", w.Body.String())
}

func TestRouterGroupBasePath(t *testing.T) {
	r := New()
	assert.Equal(t, "/", r.BasePath())
	assert.Equal(t, "/api/v1", r.Group("/api").Group("v1").BasePath())
}

func TestMethodTreesNilAndCustomMethod(t *testing.T) {
	var trees *methodTrees
	assert.Nil(t, trees.getTree(http.MethodGet))
	assert.Nil(t, trees.getMethodTree(http.MethodGet))
	assert.Nil(t, trees.getNotNullMethodTree())

	r := New()
	r.Handle("PURGE", "/cache", handlerTest1)
	r.Handle("PURGE", "/cache/:key", handlerTest1)
	purge := r.trees.getTree("PURGE")
	if assert.NotNil(t, purge) {
		assert.Contains(t, purge.static, "/cache")
		assert.NotContains(t, purge.static, "/cache/:key")
	}
	// 同一个自定义方法只创建一棵树
	assert.Len(t, r.trees.getNotNullMethodTree(), 1)
}

func TestStaticIndexWithRawPathAndExtraSlash(t *testing.T) {
	r := New()
	r.UseRawPath = true
	r.RemoveExtraSlash = true
	r.GET("/a%2Fb", func(c Context) { c.String(http.StatusOK, "raw") })
	r.GET("/x/y", func(c Context) { c.String(http.StatusOK, "clean") })

	w := PerformRequest(r, http.MethodGet, "/a%2Fb")
	assert.Equal(t, "raw", w.Body.String())

	w = PerformRequest(r, http.MethodGet, "//x///y")
	assert.Equal(t, "clean", w.Body.String())
}

func TestHandlersChainLastEmpty(t *testing.T) {
	assert.Nil(t, HandlersChain{}.Last())
	assert.Nil(t, Params(nil).Copy())
}

// currentUser 只依赖 KeyValueStore，而不是整个 Context
func currentUser(kv KeyValueStore) (string, bool) {
	v, ok := kv.Get("user")
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// fakeKV 只需实现 KeyValueStore，无需实现 Context 的其余方法
type fakeKV struct {
	KeyValueStore
	m map[string]any
}

func (f fakeKV) Get(key string) (any, bool) { v, ok := f.m[key]; return v, ok }

func TestNarrowInterfaces(t *testing.T) {
	// 真实请求中直接传入 Context
	r := New()
	r.GET("/me", func(c Context) {
		c.Set("user", "alice")
		name, _ := currentUser(c)
		c.String(http.StatusOK, name)
	})
	assert.Equal(t, "alice", PerformRequest(r, http.MethodGet, "/me").Body.String())

	// 单元测试中用最小实现替代
	name, ok := currentUser(fakeKV{m: map[string]any{"user": "bob"}})
	assert.True(t, ok)
	assert.Equal(t, "bob", name)
}

// 服务已处理过请求（池中已有按旧 maxParams / maxSections 分配的 context）后再注册路由：
// catch-all 不能越界 panic，普通参数不能被静默丢弃，回溯缓冲区同样不能越界
func TestRoutesRegisteredAfterServing(t *testing.T) {
	r := New()
	r.GET("/a", func(c Context) {})
	for range 3 {
		PerformRequest(r, http.MethodGet, "/a")
	}

	r.GET("/files/*path", func(c Context) { c.String(http.StatusOK, "path=%s", c.Param("path")) })
	r.GET("/users/:id/posts/:post", func(c Context) { c.String(http.StatusOK, "%s/%s", c.Param("id"), c.Param("post")) })
	r.GET("/users/:id", func(c Context) { c.String(http.StatusOK, "id=%s", c.Param("id")) })
	r.GET("/users/new/x", func(c Context) {})

	assert.NotPanics(t, func() {
		for range 3 {
			assert.Equal(t, "path=/x.txt", PerformRequest(r, http.MethodGet, "/files/x.txt").Body.String())
			assert.Equal(t, "7/9", PerformRequest(r, http.MethodGet, "/users/7/posts/9").Body.String())
			// 先进入静态分支 new/x，失败后回溯到 :id（依赖 skippedNodes）
			assert.Equal(t, "id=new", PerformRequest(r, http.MethodGet, "/users/new").Body.String())
		}
	})
}

// Allow 头按方法名排序，包括存放在 map 中的自定义方法，输出稳定
func TestAllowHeaderIsSorted(t *testing.T) {
	r := New()
	r.HandleMethodNotAllowed = true
	for _, m := range []string{"PURGE", http.MethodPut, "LINK", http.MethodDelete, "UNLINK", http.MethodGet} {
		r.Handle(m, "/res", func(c Context) {})
	}
	for range 10 {
		w := PerformRequest(r, http.MethodPost, "/res")
		assert.Equal(t, "DELETE, GET, LINK, PURGE, PUT, UNLINK", w.Header().Get("Allow"))
	}
}
