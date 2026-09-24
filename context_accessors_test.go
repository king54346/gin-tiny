package ginTiny

import (
	"bytes"
	stdctx "context"
	"crypto/tls"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestContext(method, target string, body io.Reader) (*context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request = httptest.NewRequest(method, target, body)
	return c, w
}

func TestContextNilRequestGuards(t *testing.T) {
	c := &context{engine: New()}

	assert.PanicsWithValue(t, ErrNilRequest, func() { c.Request() })
	assert.False(t, c.IsTLS())
	assert.False(t, c.IsWebsocket())
	assert.Empty(t, c.RequestHeader("X"))
	assert.Empty(t, c.RemoteIP())
	assert.Empty(t, c.QueryString())
	assert.Empty(t, c.QueryParams())
	assert.Empty(t, c.PostForm("k"))
	assert.Empty(t, c.Cookies())

	_, err := c.GetRawData()
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.Cookie("session")
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.FormFile("file")
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.MultipartForm()
	assert.ErrorIs(t, err, ErrNilRequest)

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	c.SetRequest(r)
	assert.Same(t, r, c.Request())
}

func TestContextRequestInfo(t *testing.T) {
	c, _ := newTestContext(http.MethodGet, "/", nil)
	assert.False(t, c.IsTLS())
	assert.Equal(t, "http", c.Scheme())

	c.request.TLS = &tls.ConnectionState{}
	assert.True(t, c.IsTLS())
	assert.Equal(t, "https", c.Scheme())

	c.request.RemoteAddr = "10.0.0.1:1234"
	c.request.Header.Set("X-Forwarded-For", "203.0.113.5")
	assert.Equal(t, "203.0.113.5", c.RealIP())
	assert.Equal(t, c.ClientIP(), c.RealIP())

	c.request.RemoteAddr = "not-an-address"
	assert.Empty(t, c.RemoteIP())
}

func TestContextSchemeFromForwardedHeaders(t *testing.T) {
	tests := []struct {
		header, value, want string
	}{
		{"X-Forwarded-Proto", "https", "https"},
		{"X-Forwarded-Protocol", "https", "https"},
		{"X-Forwarded-Ssl", "on", "https"},
		{"X-Forwarded-Ssl", "off", "http"},
	}
	for _, tt := range tests {
		c, _ := newTestContext(http.MethodGet, "/", nil)
		c.request.Header.Set(tt.header, tt.value)
		assert.Equal(t, tt.want, c.Scheme(), "%s: %s", tt.header, tt.value)
	}
}

// 配置了可信代理后，只采信来自可信代理的转发头，直连客户端伪造的 X-Forwarded-Proto 无效
func TestContextSchemeIgnoresUntrustedForwardedHeaders(t *testing.T) {
	c, _ := newTestContext(http.MethodGet, "/", nil)
	require.NoError(t, c.engine.SetTrustedProxies([]string{"10.0.0.0/8"}))
	c.request.Header.Set("X-Forwarded-Proto", "https")

	c.request.RemoteAddr = "203.0.113.9:4000" // 直连客户端
	assert.Equal(t, "http", c.Scheme())

	c.request.RemoteAddr = "10.1.2.3:4000" // 可信代理
	assert.Equal(t, "https", c.Scheme())
}

func TestContextIsWebsocket(t *testing.T) {
	c, _ := newTestContext(http.MethodGet, "/ws", nil)
	assert.False(t, c.IsWebsocket())

	c.request.Header.Set("Connection", "keep-alive, Upgrade")
	c.request.Header.Set("Upgrade", "WebSocket")
	assert.True(t, c.IsWebsocket())

	c.request.Header.Set("Upgrade", "h2c")
	assert.False(t, c.IsWebsocket())
}

func TestContextPathParams(t *testing.T) {
	c := &context{}
	assert.Empty(t, c.Params())
	assert.Empty(t, c.ParamNames())
	assert.Empty(t, c.ParamValues())

	c.SetParamNames("id", "name")
	c.SetParamValues("7", "alice", "ignored-extra")
	assert.Equal(t, []string{"id", "name"}, c.ParamNames())
	assert.Equal(t, []string{"7", "alice"}, c.ParamValues())
	assert.Equal(t, "alice", c.Param("name"))

	// SetParamNames 重新设置时清空旧值
	c.SetParamNames("x")
	assert.Equal(t, Params{{Key: "x"}}, c.Params())

	// Params 返回副本，修改副本不影响 context
	p := c.Params()
	p[0].Value = "changed"
	assert.Empty(t, c.Param("x"))

	c2 := &context{}
	c2.AddParam("k", "v")
	c2.SetParamValues()
	v, ok := c2.ParamGet("k")
	assert.True(t, ok)
	assert.Equal(t, "v", v)

	c3 := &context{}
	c3.SetParamValues("orphan")
	assert.Empty(t, c3.Params(), "values without names are ignored")

	c.SetPath("/users/:id")
	assert.Equal(t, "/users/:id", c.Path())
	assert.Equal(t, c.FullPath(), c.Path())
}

func TestContextQueryAndForm(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/?q=go&tag=a&tag=b", strings.NewReader("name=alice&age=3"))
	c.request.Header.Set("Content-Type", MIMEPOSTForm)

	assert.Equal(t, "q=go&tag=a&tag=b", c.QueryString())
	assert.Equal(t, []string{"a", "b"}, c.QueryParams()["tag"])

	assert.Equal(t, "alice", c.FormValue("name"))
	assert.Empty(t, c.FormValue("q"), "FormValue only reads the request body, like PostForm")
	form, err := c.FormParams()
	require.NoError(t, err)
	assert.Equal(t, "3", form.Get("age"))
}

func TestContextFormFileErrors(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/", strings.NewReader("a=b"))
	c.request.Header.Set("Content-Type", MIMEPOSTForm)
	_, err := c.FormFile("file")
	assert.ErrorIs(t, err, http.ErrNotMultipart)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.WriteField("field", "value"))
	require.NoError(t, mw.Close())
	c, _ = newTestContext(http.MethodPost, "/", &buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	_, err = c.FormFile("missing")
	assert.ErrorIs(t, err, http.ErrMissingFile)
}

func TestSaveUploadedFileCreatesDirectories(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "a.txt")
	require.NoError(t, err)
	_, _ = fw.Write([]byte("content"))
	require.NoError(t, mw.Close())

	c, _ := newTestContext(http.MethodPost, "/", &buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	fh, err := c.FormFile("file")
	require.NoError(t, err)

	dst := filepath.Join(t.TempDir(), "nested", "dir", "a.txt")
	require.NoError(t, c.SaveUploadedFile(fh, dst))
	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "content", string(data))

	// 目标路径的父级是文件时无法创建目录
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o644))
	assert.Error(t, c.SaveUploadedFile(fh, filepath.Join(blocker, "sub", "a.txt")))
}

func TestContextCookies(t *testing.T) {
	c, _ := newTestContext(http.MethodGet, "/", nil)
	c.request.AddCookie(&http.Cookie{Name: "a", Value: "1"})
	c.request.AddCookie(&http.Cookie{Name: "b", Value: "2"})

	assert.Len(t, c.Cookies(), 2)
	ck, err := c.Cookie("b")
	require.NoError(t, err)
	assert.Equal(t, "2", ck.Value)
	_, err = c.Cookie("missing")
	assert.ErrorIs(t, err, http.ErrNoCookie)
}

type validatedInput struct {
	Name string `json:"name" binding:"required"`
}

type stubValidator struct{ err error }

func (s stubValidator) Validate(any) error { return s.err }

func TestShouldBindAsAndValidate(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/", strings.NewReader(`{"name":"alice"}`))
	c.request.Header.Set("Content-Type", MIMEJSON)
	in, err := ShouldBindAs[validatedInput](c)
	require.NoError(t, err)
	assert.Equal(t, "alice", in.Name)

	c, _ = newTestContext(http.MethodPost, "/", strings.NewReader(`{}`))
	c.request.Header.Set("Content-Type", MIMEJSON)
	_, err = ShouldBindAs[validatedInput](c)
	assert.Error(t, err)

	assert.ErrorIs(t, c.Validate(in), ErrValidatorNotRegistered)
	c.engine.Validator = stubValidator{}
	assert.NoError(t, c.Validate(in))
	c.engine.Validator = stubValidator{err: errors.New("invalid")}
	assert.EqualError(t, c.Validate(in), "invalid")
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestContextBodyReadErrors(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/", failingBody{})
	_, err := c.GetRawData()
	assert.EqualError(t, err, "read failed")

	c, _ = newTestContext(http.MethodPost, "/", failingBody{})
	var v map[string]any
	assert.EqualError(t, c.ShouldBindBodyWith(&v, nil), "read failed")
}

func TestContextBlobRenderers(t *testing.T) {
	tests := []struct {
		name   string
		render func(c *context) error
		ctype  string
	}{
		{"HTMLBlob", func(c *context) error { return c.HTMLBlob(http.StatusOK, []byte("<p>x</p>")) }, "text/html; charset=utf-8"},
		{"JSONBlob", func(c *context) error { return c.JSONBlob(http.StatusOK, []byte(`{"a":1}`)) }, "application/json; charset=utf-8"},
		{"XMLBlob", func(c *context) error { return c.XMLBlob(http.StatusOK, []byte("<a/>")) }, "application/xml; charset=utf-8"},
		{"Blob", func(c *context) error { return c.Blob(http.StatusAccepted, "application/octet-stream", []byte{1, 2}) }, "application/octet-stream"},
	}
	for _, tt := range tests {
		c, w := newTestContext(http.MethodGet, "/", nil)
		require.NoError(t, tt.render(c), tt.name)
		assert.Equal(t, tt.ctype, w.Header().Get("Content-Type"), tt.name)
		assert.NotEmpty(t, w.Body.Bytes(), tt.name)
	}
}

func TestContextNoContentAndAttachment(t *testing.T) {
	r := New()
	r.DELETE("/item", func(c Context) { c.NoContent(http.StatusNoContent) })
	r.GET("/download", func(c Context) { _ = c.Attachment("./gin.go", "source.go") })

	w := PerformRequest(r, http.MethodDelete, "/item")
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())

	w = PerformRequest(r, http.MethodGet, "/download")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `attachment; filename="source.go"`, w.Header().Get("Content-Disposition"))
	assert.Contains(t, w.Body.String(), "package ginTiny")
}

func TestContextStream(t *testing.T) {
	c, w := newTestContext(http.MethodGet, "/", nil)
	n := 0
	clientGone := c.Stream(func(w io.Writer) bool {
		n++
		_, _ = io.WriteString(w, "chunk;")
		return n < 3
	})
	assert.False(t, clientGone)
	assert.Equal(t, "chunk;chunk;chunk;", w.Body.String())
	assert.True(t, w.Flushed)

	// 客户端断开后停止推送并返回 true
	reqCtx, cancel := stdctx.WithCancel(stdctx.Background())
	c, _ = newTestContext(http.MethodGet, "/", nil)
	c.request = c.request.WithContext(reqCtx)
	calls := 0
	done := make(chan bool, 1)
	go func() {
		done <- c.Stream(func(w io.Writer) bool {
			calls++
			if calls == 2 {
				cancel()
			}
			return true
		})
	}()
	select {
	case gone := <-done:
		assert.True(t, gone)
	case <-time.After(3 * time.Second):
		t.Fatal("Stream did not stop after the client went away")
	}
}

func TestContextHandlerAccessors(t *testing.T) {
	c := &context{}
	chain := HandlersChain{handlerTest1, handlerTest2}
	c.SetHandlers(chain)
	assert.Len(t, c.Handlers(), 2)

	c.SetHandler(handlerTest1)
	assert.Len(t, c.Handlers(), 1)
	assert.Regexp(t, "handlerTest1$", c.HandlerName())
}

func TestResponseWriterExtras(t *testing.T) {
	w := NewResponseWriter(httptest.NewRecorder())
	assert.Nil(t, w.Pusher(), "httptest.ResponseRecorder does not support server push")

	var after int
	w.After(func() { after++ })
	n, err := w.WriteString("hello")
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, 5, w.Size())
	assert.Equal(t, 1, after, "After callbacks run after WriteString")
}

func TestContextSchemeWithoutEngine(t *testing.T) {
	c := &context{request: httptest.NewRequest(http.MethodGet, "/", nil)}
	c.request.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https", c.Scheme(), "without an engine there is no proxy configuration to enforce")
}

// 畸形的 multipart 表单：解析失败时 PostForm 返回空值而不是 panic
func TestContextMalformedMultipartForm(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/", strings.NewReader("--broken\r\nnot a valid part"))
	c.request.Header.Set("Content-Type", "multipart/form-data; boundary=broken")
	assert.NotPanics(t, func() { assert.Empty(t, c.PostForm("field")) })
}

type failingResponse struct {
	*httptest.ResponseRecorder
	failOn int
	writes int
}

func (f *failingResponse) Write(b []byte) (int, error) {
	f.writes++
	if f.writes == f.failOn {
		return 0, errors.New("write failed")
	}
	return f.ResponseRecorder.Write(b)
}

// JSONPBlob 分三次写出（callback(、数据、);），任意一次失败都要把错误返回给调用方
func TestContextJSONPBlobWriteErrors(t *testing.T) {
	for failOn := 1; failOn <= 3; failOn++ {
		c, _ := newTestContext(http.MethodGet, "/", nil)
		c.writermem = NewResponseWriter(&failingResponse{ResponseRecorder: httptest.NewRecorder(), failOn: failOn})
		assert.EqualError(t, c.JSONPBlob(http.StatusOK, "cb", []byte(`{}`)), "write failed", "fail on write %d", failOn)
	}
}

func TestNegotiateFormatRequiresFullMediaTypeMatch(t *testing.T) {
	tests := []struct {
		accept  string
		offered []string
		want    string
	}{
		{"application/jso", []string{MIMEJSON}, ""},               // 前缀不算匹配
		{"application/json2", []string{MIMEJSON}, ""},             // 更长的也不算
		{"Application/JSON", []string{MIMEJSON}, MIMEJSON},        // 大小写不敏感
		{"application/*", []string{MIMEXML, MIMEJSON}, MIMEXML},   // 子类型通配
		{"*/*", []string{MIMEYAML}, MIMEYAML},                     // 全通配
		{"text/html", []string{"*/*"}, "*/*"},                     // 服务端通配
		{"image/*", []string{MIMEJSON, "image/png"}, "image/png"}, // 跳过类型不符的
		{"text/plain, application/json;q=0.9", []string{MIMEJSON}, MIMEJSON},
	}
	for _, tt := range tests {
		c, _ := newTestContext(http.MethodGet, "/", nil)
		c.request.Header.Set("Accept", tt.accept)
		assert.Equal(t, tt.want, c.NegotiateFormat(tt.offered...), "Accept: %s", tt.accept)
	}
}

// 手工构造的参数里出现空切片不能 panic
func TestQueryMapWithEmptyValues(t *testing.T) {
	c := &context{queryCache: map[string][]string{"ids[a]": {}, "ids[b]": {"2"}, "ids[]": {"x"}, "other[c]": {"3"}}}
	m, ok := c.GetQueryMap("ids")
	assert.True(t, ok)
	assert.Equal(t, map[string]string{"b": "2"}, m)

	m, ok = c.GetQueryMap("")
	assert.False(t, ok)
	assert.Empty(t, m)
}

func TestParseAcceptAndFilterFlagsEdgeCases(t *testing.T) {
	assert.Equal(t, []string{"text/html"}, parseAccept(";q=0.5, text/html"), "a part that is only parameters is dropped")
	assert.Empty(t, parseAccept(""))
	assert.Equal(t, "application/json", filterFlags("application/json; charset=utf-8"))
	assert.Equal(t, "", filterFlags(";"))
	assert.Equal(t, "text/plain", filterFlags("text/plain"))
}
