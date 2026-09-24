package ginTiny

import (
	"bytes"
	"fmt"
	"github.com/king54346/gin-tiny/binding"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------- HTML 模板 ----------------

// testdata/template 下的模板使用自定义分隔符 {[{ }]} 和自定义函数 formatAsDate
func newTemplateEngine(t *testing.T, mode string) *Engine {
	t.Helper()
	withMode(t, mode)
	r := New()
	r.Delims("{[{", "}]}")
	r.SetFuncMap(template.FuncMap{"formatAsDate": formatAsDate})
	r.LoadHTMLGlob("./testdata/template/*")
	r.GET("/hello", func(c Context) { c.HTML(http.StatusOK, "hello.tmpl", H{"name": "world"}) })
	r.GET("/raw", func(c Context) {
		c.HTML(http.StatusOK, "raw.tmpl", H{"now": time.Date(2017, 7, 1, 0, 0, 0, 0, time.UTC)})
	})
	return r
}

func TestHTMLRenderDelimsAndFuncMap(t *testing.T) {
	for _, mode := range []string{ReleaseMode, DebugMode} {
		r := newTemplateEngine(t, mode)

		w := PerformRequest(r, http.MethodGet, "/hello")
		assert.Equal(t, http.StatusOK, w.Code, mode)
		assert.Equal(t, "<h1>Hello world</h1>", w.Body.String(), mode)
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"), mode)

		w = PerformRequest(r, http.MethodGet, "/raw")
		assert.Equal(t, "Date: 2017/07/01", w.Body.String(), mode)
	}
}

// debug 模式每次渲染都重新解析，修改模板文件后无需重启
func TestHTMLDebugModeReloadsTemplates(t *testing.T) {
	withMode(t, DebugMode)
	dir := t.TempDir()
	file := filepath.Join(dir, "page.tmpl")
	require.NoError(t, os.WriteFile(file, []byte("v1 {{.}}"), 0o644))

	r := New()
	r.LoadHTMLFiles(file)
	r.GET("/", func(c Context) { c.HTML(http.StatusOK, "page.tmpl", "x") })
	assert.Equal(t, "v1 x", PerformRequest(r, http.MethodGet, "/").Body.String())

	require.NoError(t, os.WriteFile(file, []byte("v2 {{.}}"), 0o644))
	assert.Equal(t, "v2 x", PerformRequest(r, http.MethodGet, "/").Body.String())
}

func TestHTMLLoadFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"views/index.tmpl":  {Data: []byte(`{{define "index"}}<p>{{.}}</p>{{end}}`)},
		"views/ignored.txt": {Data: []byte("not a template")},
	}
	for _, mode := range []string{ReleaseMode, DebugMode} {
		withMode(t, mode)
		r := New()
		r.LoadHTMLFS(fsys, "views/*.tmpl")
		r.GET("/", func(c Context) { c.HTML(http.StatusOK, "index", "<b>escaped</b>") })
		assert.Equal(t, "<p>&lt;b&gt;escaped&lt;/b&gt;</p>", PerformRequest(r, http.MethodGet, "/").Body.String(), mode)
	}
}

func TestSetHTMLTemplate(t *testing.T) {
	r := New()
	r.SetHTMLTemplate(template.Must(template.New("t").Parse("hi {{.}}")))
	r.GET("/", func(c Context) { c.HTML(http.StatusCreated, "t", "there") })
	w := PerformRequest(r, http.MethodGet, "/")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "hi there", w.Body.String())
}

// 模板执行出错：返回 500，且不输出被截断的页面
func TestHTMLTemplateErrorReturns500WithoutPartialOutput(t *testing.T) {
	r := New()
	r.SetHTMLTemplate(template.Must(template.New("t").Parse(`<h1>partial {{.Missing.Field}}</h1>`)))
	var recorded errorMsgs
	r.Use(func(c Context) { c.Next(); recorded = c.Errors() })
	r.GET("/", func(c Context) { c.HTML(http.StatusOK, "t", H{"Missing": 42}) })

	w := PerformRequest(r, http.MethodGet, "/")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Body.String(), "no truncated HTML must be sent")
	assert.Len(t, recorded, 1)
}

func TestHTMLWithoutTemplatesPanicsWithClearMessage(t *testing.T) {
	r := New()
	r.GET("/", func(c Context) { c.HTML(http.StatusOK, "x", nil) })
	assert.PanicsWithValue(t,
		"ginTiny: HTML templates are not loaded, call LoadHTMLGlob / LoadHTMLFiles / LoadHTMLFS / SetHTMLTemplate first",
		func() { PerformRequest(r, http.MethodGet, "/") })
}

// 其他渲染器失败且尚未写出内容时同样返回 500（修改前是 200 加空响应体）
func TestRenderErrorBeforeWriteReturns500(t *testing.T) {
	r := New()
	r.GET("/", func(c Context) { c.JSON(http.StatusOK, H{"ch": make(chan int)}) })
	w := PerformRequest(r, http.MethodGet, "/")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestDebugPrintLoadTemplate(t *testing.T) {
	out, _ := captureDebugOutput(t, DebugMode)
	r := New()
	out.Reset()
	r.Delims("{[{", "}]}")
	r.SetFuncMap(template.FuncMap{"formatAsDate": formatAsDate})
	r.LoadHTMLGlob("./testdata/template/*")
	assert.Contains(t, out.String(), "Loaded HTML Templates (2):")
	assert.Contains(t, out.String(), "hello.tmpl")
}

// ---------------- Cookie ----------------

func setCookieAndReadBack(t *testing.T, set func(c Context)) (*http.Cookie, *http.Cookie, Context) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request = httptest.NewRequest(http.MethodGet, "/", nil)
	set(c)
	sent := w.Result().Cookies()
	require.Len(t, sent, 1)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sent[0].Name, Value: sent[0].Value})
	c2, _ := CreateTestContext(httptest.NewRecorder())
	c2.request = req
	got, err := c2.Cookie(sent[0].Name)
	require.NoError(t, err)
	return sent[0], got, c2
}

func TestCookieRoundTrip(t *testing.T) {
	for _, v := range []string{"plain", "张三", "a b&c=d;e", "100%", "a+b", ""} {
		_, got, c2 := setCookieAndReadBack(t, func(c Context) { c.SetCookie("k", v, 60, "", "", false, true) })
		assert.Equal(t, v, got.Value, "value %q", v)

		all := c2.Cookies()
		require.Len(t, all, 1)
		assert.Equal(t, v, all[0].Value)
	}

	// 需要原始编码值时通过 Request().Cookie 读取
	sent, _, c2 := setCookieAndReadBack(t, func(c Context) { c.SetCookie("k", "张三", 60, "", "", false, true) })
	raw, err := c2.Request().Cookie("k")
	require.NoError(t, err)
	assert.Equal(t, sent.Value, raw.Value)
	assert.NotEqual(t, "张三", raw.Value)
}

func TestCookieNotEncodedBySetCookieKeepsValue(t *testing.T) {
	// 由其他系统写入、本身不是合法 URL 编码的值保持原样
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "k", Value: "50%off"})
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request = req
	ck, err := c.Cookie("k")
	require.NoError(t, err)
	assert.Equal(t, "50%off", ck.Value)
}

func TestSetCookieData(t *testing.T) {
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	in := &http.Cookie{Name: "session", Value: "张三", Expires: expires, HttpOnly: true, Secure: true, Partitioned: true}

	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookieData(in)

	header := w.Header().Get("Set-Cookie")
	assert.Contains(t, header, "Expires=Wed, 02 Jan 2030 03:04:05 GMT")
	assert.Contains(t, header, "Partitioned")
	assert.Contains(t, header, "Path=/")
	assert.Contains(t, header, "SameSite=Strict", "unset SameSite inherits SetSameSite")
	// 调用方传入的对象不被修改
	assert.Equal(t, "张三", in.Value)
	assert.Empty(t, in.Path)
	assert.Equal(t, http.SameSite(0), in.SameSite)

	// 显式设置的 SameSite 不被覆盖
	w = httptest.NewRecorder()
	c, _ = CreateTestContext(w)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookieData(&http.Cookie{Name: "a", Value: "b", SameSite: http.SameSiteLaxMode})
	assert.Contains(t, w.Header().Get("Set-Cookie"), "SameSite=Lax")
}

// ---------------- Keys ----------------

type userKey struct{}
type tenantKey struct{}

func TestKeysWithTypedKeys(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())

	// 不同类型的 key 即使底层值相同也互不冲突
	c.Set(userKey{}, "alice")
	c.Set(tenantKey{}, "acme")
	c.Set("userKey", "string-key")
	c.Set(0, "zero")

	assert.Equal(t, "alice", c.MustGet(userKey{}))
	assert.Equal(t, "acme", c.GetString(tenantKey{}))
	assert.Equal(t, "string-key", c.GetString("userKey"))
	u, ok := GetAs[string](c, userKey{})
	assert.True(t, ok)
	assert.Equal(t, "alice", u)

	// 作为 context.Context 传给下游时，typed key 同样可以取到
	assert.Equal(t, "alice", c.Value(userKey{}))
	assert.Equal(t, "zero", c.Value(0))

	assert.PanicsWithValue(t, "Key ginTiny.tenantKey{} does not exist", func() {
		c.Delete(tenantKey{})
		c.MustGet(tenantKey{})
	})
}

func TestKeysDeleteAndSnapshot(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	assert.Nil(t, c.Keys())
	c.Delete("missing") // 删除不存在的 key 不报错

	c.Set("a", 1)
	c.Set("b", 2)
	c.Delete("a")
	_, exists := c.Get("a")
	assert.False(t, exists)

	snapshot := c.Keys()
	assert.Equal(t, map[any]any{"b": 2}, snapshot)

	// 遍历快照期间可以安全地修改 context（持锁回调会死锁）
	done := make(chan struct{})
	go func() {
		for k := range c.Keys() {
			c.Set(fmt.Sprint(k, "-copy"), true)
			c.Delete(k)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("modifying keys while iterating the snapshot deadlocked")
	}

	// 修改快照不影响 context
	snapshot["b"] = 99
	_, exists = c.Get("b")
	assert.False(t, exists)
	assert.Equal(t, true, c.MustGet("b-copy"))
}

func TestLoggerReceivesKeys(t *testing.T) {
	var got map[any]any
	var buf bytes.Buffer
	r := New()
	r.Use(LoggerWithConfig(LoggerConfig{
		Output:    &buf,
		Formatter: func(p LogFormatterParams) string { got = p.Keys; return "" },
	}))
	r.GET("/", func(c Context) {
		c.Set(userKey{}, "alice")
		c.Set("request_id", "r-1")
	})
	PerformRequest(r, http.MethodGet, "/")
	assert.Equal(t, map[any]any{userKey{}: "alice", "request_id": "r-1"}, got)
}

func TestContextRequestKey(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request = httptest.NewRequest(http.MethodGet, "/x", nil)
	assert.Same(t, c.request, c.Value(ContextRequestKey))
	assert.Same(t, c, c.Value(ContextKey))
	assert.True(t, strings.HasSuffix(c.Value(ContextRequestKey).(*http.Request).URL.Path, "/x"))
}

// ---------------- 纯文本绑定 / 日志 Skip / 上传文件权限 ----------------

func TestContextPlainBinding(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/", strings.NewReader("plain body"))
	c.request.Header.Set("Content-Type", MIMEPlain)

	// 多次读取同一个请求体：ShouldBindBodyWith 会缓存
	var s1 string
	var b2 []byte
	require.NoError(t, c.ShouldBindBodyWith(&s1, binding.Plain))
	require.NoError(t, c.ShouldBindBodyWith(&b2, binding.Plain))
	assert.Equal(t, "plain body", s1)
	assert.Equal(t, "plain body", string(b2))

	c, _ = newTestContext(http.MethodPost, "/", strings.NewReader("via ShouldBind"))
	c.request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	var s string
	require.NoError(t, c.ShouldBind(&s), "text/plain selects the plain binding")
	assert.Equal(t, "via ShouldBind", s)

	c, _ = newTestContext(http.MethodPost, "/", strings.NewReader("x"))
	var n int
	assert.Error(t, c.ShouldBindPlain(&n))

	c, w := newTestContext(http.MethodPost, "/", strings.NewReader("x"))
	assert.Error(t, c.BindPlain(&n))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	c, _ = newTestContext(http.MethodPost, "/", strings.NewReader("ok"))
	require.NoError(t, c.BindPlain(&s))
	assert.Equal(t, "ok", s)
}

func TestLoggerSkipper(t *testing.T) {
	var buf bytes.Buffer
	r := New()
	r.Use(LoggerWithConfig(LoggerConfig{
		Output: &buf,
		// 只记录出错的请求：Skip 在处理链执行完之后调用，可以读到状态码
		Skip: func(c Context) bool { return c.Response().Status() < http.StatusBadRequest },
	}))
	r.GET("/ok", func(c Context) { c.Status(http.StatusOK) })
	r.GET("/bad", func(c Context) { c.Status(http.StatusBadRequest) })

	PerformRequest(r, http.MethodGet, "/ok")
	assert.Empty(t, buf.String())
	PerformRequest(r, http.MethodGet, "/bad")
	assert.Contains(t, buf.String(), `"/bad"`)
}

func uploadedFile(t *testing.T, content string) *multipart.FileHeader {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "a.txt")
	require.NoError(t, err)
	_, _ = fw.Write([]byte(content))
	require.NoError(t, mw.Close())
	c, _ := newTestContext(http.MethodPost, "/", &buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	fh, err := c.FormFile("file")
	require.NoError(t, err)
	return fh
}

func TestSaveUploadedFilePerm(t *testing.T) {
	fh := uploadedFile(t, "data")
	c := &context{}
	dir := t.TempDir()

	// 默认权限：可写
	def := filepath.Join(dir, "default.txt")
	require.NoError(t, c.SaveUploadedFile(fh, def))
	info, err := os.Stat(def)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode().Perm()&0o200, "default mode must be writable")

	// 指定只读权限
	ro := filepath.Join(dir, "sub", "readonly.txt")
	require.NoError(t, c.SaveUploadedFile(fh, ro, 0o444))
	t.Cleanup(func() { _ = os.Chmod(ro, 0o644) }) // Windows 上只读文件无法被 TempDir 清理
	info, err = os.Stat(ro)
	require.NoError(t, err)
	assert.Zero(t, info.Mode().Perm()&0o200, "file must be read-only")
	data, err := os.ReadFile(ro)
	require.NoError(t, err)
	assert.Equal(t, "data", string(data))

	// 已存在的目录权限不被修改（上游会 chmod 父目录）
	before, err := os.Stat(dir)
	require.NoError(t, err)
	require.NoError(t, c.SaveUploadedFile(fh, filepath.Join(dir, "again.txt"), 0o600))
	after, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, before.Mode(), after.Mode())
}

// ---------------- 与上游对齐的小功能 ----------------

func TestBasicAuthForProxy(t *testing.T) {
	r := New()
	r.Use(BasicAuthForProxy(Accounts{"proxy": "secret"}, ""))
	r.Any("/*proxyPath", func(c Context) { c.String(http.StatusOK, c.GetString(AuthProxyUserKey)) })

	w := PerformRequest(r, http.MethodGet, "/x")
	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)
	assert.Equal(t, `Basic realm="Proxy Authorization Required"`, w.Header().Get("Proxy-Authenticate"))

	// 普通的 Authorization 头不能通过代理认证
	w = PerformRequest(r, http.MethodGet, "/x", header{Key: "Authorization", Value: authorizationHeader("proxy", "secret")})
	assert.Equal(t, http.StatusProxyAuthRequired, w.Code)

	w = PerformRequest(r, http.MethodGet, "/x", header{Key: "Proxy-Authorization", Value: authorizationHeader("proxy", "secret")})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "proxy", w.Body.String())

	r2 := New()
	r2.Use(BasicAuthForProxy(Accounts{"p": "s"}, "my realm"))
	r2.GET("/", func(c Context) {})
	assert.Equal(t, `Basic realm="my realm"`, PerformRequest(r2, http.MethodGet, "/").Header().Get("Proxy-Authenticate"))
}

func mainHandler(c Context) { c.String(http.StatusOK, "main") }

func TestContextMainHandler(t *testing.T) {
	r := New()
	var got HandlerFunc
	r.Use(func(c Context) { got = c.Handler(); c.Next() })
	r.GET("/", mainHandler)
	PerformRequest(r, http.MethodGet, "/")
	require.NotNil(t, got)
	assert.Equal(t, nameOfFunction(mainHandler), nameOfFunction(got))

	assert.Nil(t, (&context{}).Handler())
}

func TestAbortWithStatusPureJSON(t *testing.T) {
	nextCalled := false
	r := New()
	r.GET("/", func(c Context) { c.AbortWithStatusPureJSON(http.StatusBadRequest, H{"html": "<b>&</b>"}) },
		func(c Context) { nextCalled = true })

	w := PerformRequest(r, http.MethodGet, "/")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"html":"<b>&</b>"}`, w.Body.String())
	assert.Contains(t, w.Body.String(), "<b>&</b>", "PureJSON must not escape HTML characters")
	assert.False(t, nextCalled)
}

func TestEngineOptions(t *testing.T) {
	withMNA := func(e *Engine) { e.HandleMethodNotAllowed = true }
	withTimeout := func(e *Engine) { e.ShutdownTimeout = time.Second }

	r := New(withMNA, withTimeout)
	assert.True(t, r.HandleMethodNotAllowed)
	assert.Equal(t, time.Second, r.ShutdownTimeout)

	// With 可以链式调用，返回 engine 本身
	var order []string
	r2 := New().With(func(e *Engine) { order = append(order, "a") }, func(e *Engine) { order = append(order, "b") })
	assert.Equal(t, []string{"a", "b"}, order)
	assert.NotNil(t, r2)

	// Default 在挂载 Logger/Recovery 之后应用选项，选项里注册的中间件排在它们后面
	var seen int
	d := Default(func(e *Engine) { e.Use(func(c Context) { seen = len(c.Handlers()) }) })
	d.GET("/", func(c Context) {})
	PerformRequest(d, http.MethodGet, "/")
	assert.Equal(t, 4, seen, "Logger + Recovery + option middleware + handler")
}

func TestDebugPrintFunc(t *testing.T) {
	out, _ := captureDebugOutput(t, DebugMode)
	var lines []string
	DebugPrintFunc = func(format string, values ...any) { lines = append(lines, fmt.Sprintf(format, values...)) }
	t.Cleanup(func() { DebugPrintFunc = nil })

	debugPrint("custom %d", 42)
	assert.Equal(t, []string{"custom 42"}, lines)
	assert.Empty(t, out.String(), "the default writer is bypassed")

	// release 模式下不调用
	withMode(t, ReleaseMode)
	debugPrint("hidden")
	assert.Len(t, lines, 1)
}

func TestUseEscapedPath(t *testing.T) {
	newEngine := func(configure func(*Engine)) *Engine {
		r := New()
		configure(r)
		r.GET("/files/:name", func(c Context) { c.String(http.StatusOK, "file:"+c.Param("name")) })
		r.GET("/files/:name/meta", func(c Context) { c.String(http.StatusOK, "meta:"+c.Param("name")) })
		return r
	}

	// 默认：%2F 已被解码为 /，a%2Fb 被拆成两段，匹配不到 :name
	def := newEngine(func(*Engine) {})
	assert.Equal(t, http.StatusNotFound, PerformRequest(def, http.MethodGet, "/files/a%2Fb").Code)

	// UseEscapedPath：按转义后的路径匹配，%2F 留在同一段内，参数值被解码
	esc := newEngine(func(e *Engine) { e.UseEscapedPath = true })
	assert.Equal(t, "file:a/b", PerformRequest(esc, http.MethodGet, "/files/a%2Fb").Body.String())
	assert.Equal(t, "meta:a/b", PerformRequest(esc, http.MethodGet, "/files/a%2Fb/meta").Body.String())

	// UnescapePathValues=false 时保留转义形式
	raw := newEngine(func(e *Engine) { e.UseEscapedPath = true; e.UnescapePathValues = false })
	assert.Equal(t, "file:a%2Fb", PerformRequest(raw, http.MethodGet, "/files/a%2Fb").Body.String())

	// UseEscapedPath 优先于 UseRawPath
	both := newEngine(func(e *Engine) { e.UseEscapedPath = true; e.UseRawPath = true })
	assert.Equal(t, "file:a/b", PerformRequest(both, http.MethodGet, "/files/a%2Fb").Body.String())
}

// 路径中的 + 是字面量：无论是否启用 UseRawPath / UseEscapedPath，同一请求的参数值必须一致
// （修复前这两种模式用 QueryUnescape 解码，会把 + 变成空格）
func TestPathParamPlusSignConsistentAcrossModes(t *testing.T) {
	configs := map[string]func(*Engine){
		"default":        func(*Engine) {},
		"UseRawPath":     func(e *Engine) { e.UseRawPath = true },
		"UseEscapedPath": func(e *Engine) { e.UseEscapedPath = true },
	}
	for name, configure := range configs {
		r := New()
		configure(r)
		r.GET("/files/:name", func(c Context) { c.String(http.StatusOK, c.Param("name")) })
		r.GET("/src/*path", func(c Context) { c.String(http.StatusOK, c.Param("path")) })

		assert.Equal(t, "C++.pdf", PerformRequest(r, http.MethodGet, "/files/C++.pdf").Body.String(), name)
		assert.Equal(t, "a+b c", PerformRequest(r, http.MethodGet, "/files/a+b%20c").Body.String(), name)
		assert.Equal(t, "/x/a+b", PerformRequest(r, http.MethodGet, "/src/x/a+b").Body.String(), name)
	}
}
