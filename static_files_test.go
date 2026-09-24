package ginTiny

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStaticDir 创建临时静态资源目录：
//
//	root/hello.txt
//	root/sub/inner.txt
//
// 并在 root 的上一级放一个 secret.txt，用于验证路径穿越
func newStaticDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "public")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "inner.txt"), []byte("inner"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644))
	return root
}

func TestStaticServesFiles(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/static/hello.txt")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "hello", w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/static/sub/inner.txt")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "inner", w.Body.String())

	w = PerformRequest(r, http.MethodHead, "/static/hello.txt")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestStaticMissingFileFallsBackToNoRoute(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/static/missing.txt")
	assert.Equal(t, http.StatusNotFound, w.Code)

	r.NoRoute(func(c Context) { c.String(http.StatusNotFound, "custom 404") })
	w = PerformRequest(r, http.MethodGet, "/static/missing.txt")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "custom 404", w.Body.String())
}

func TestStaticDisablesDirectoryListing(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/static/sub/")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "inner.txt")
}

func TestStaticFSWithDirectoryListing(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.StaticFS("/assets", Dir(root, true))

	w := PerformRequest(r, http.MethodGet, "/assets/sub/")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "inner.txt")
}

func TestStaticPreventsPathTraversal(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Static("/static", root)

	for _, p := range []string{"/static/../secret.txt", "/static/..%2fsecret.txt", "/static/sub/../../secret.txt"} {
		w := PerformRequest(r, http.MethodGet, p)
		assert.NotContains(t, w.Body.String(), "secret", p)
	}
}

func TestStaticInGroup(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Group("/v1").Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/v1/static/hello.txt")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "hello", w.Body.String())
}

func TestStaticFileAndStaticFileFS(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.StaticFile("/hello", filepath.Join(root, "hello.txt"))
	r.StaticFileFS("/inner", "sub/inner.txt", Dir(root, false))

	w := PerformRequest(r, http.MethodGet, "/hello")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "hello", w.Body.String())

	w = PerformRequest(r, http.MethodHead, "/hello")
	assert.Equal(t, http.StatusOK, w.Code)

	w = PerformRequest(r, http.MethodGet, "/inner")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "inner", w.Body.String())

	// StaticFile 注册的是静态路由，应当进入静态索引
	get := r.trees.getTree(http.MethodGet)
	assert.Contains(t, get.static, "/hello")
	assert.Contains(t, get.static, "/inner")
	assert.Contains(t, r.trees.getTree(http.MethodHead).static, "/hello")
}

func TestStaticRejectsWildcards(t *testing.T) {
	r := New()
	assert.Panics(t, func() { r.Static("/static/:dir", ".") })
	assert.Panics(t, func() { r.StaticFS("/static/*all", Dir(".", false)) })
	assert.Panics(t, func() { r.StaticFile("/file/:name", "./gin.go") })
	assert.Panics(t, func() { r.StaticFileFS("/file/*name", "gin.go", Dir(".", false)) })
}

// 普通文件走 ServeContent 快速路径：条件请求与 Range 请求的行为要和 http.FileServer 一致
func TestStaticConditionalAndRangeRequests(t *testing.T) {
	root := newStaticDir(t)
	r := New()
	r.Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/static/hello.txt")
	require.Equal(t, http.StatusOK, w.Code)
	lastModified := w.Header().Get("Last-Modified")
	require.NotEmpty(t, lastModified)
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))

	w = PerformRequest(r, http.MethodGet, "/static/hello.txt", header{Key: "If-Modified-Since", Value: lastModified})
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.Empty(t, w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/static/hello.txt", header{Key: "Range", Value: "bytes=1-3"})
	assert.Equal(t, http.StatusPartialContent, w.Code)
	assert.Equal(t, "ell", w.Body.String())
}

// 目录与 index.html 相关的请求仍交给 http.FileServer，保留它的重定向规则
func TestStaticIndexAndRedirects(t *testing.T) {
	root := newStaticDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "index.html"), []byte("<h1>index</h1>"), 0o644))
	r := New()
	r.Static("/static", root)

	w := PerformRequest(r, http.MethodGet, "/static/sub/")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<h1>index</h1>", w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/static/sub/index.html")
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, "./", w.Header().Get("Location"))

	w = PerformRequest(r, http.MethodGet, "/static/hello.txt/")
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, "../hello.txt", w.Header().Get("Location"))
}
