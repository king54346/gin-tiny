// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"errors"
	"gin-tiny/binding"
	"gin-tiny/render"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sse"
)

// Content-Type MIME of the most common data formats.
const (
	MIMEJSON              = binding.MIMEJSON
	MIMEXML               = binding.MIMEXML
	MIMEXML2              = binding.MIMEXML2
	MIMEPlain             = binding.MIMEPlain
	MIMEPOSTForm          = binding.MIMEPOSTForm
	MIMEMultipartPOSTForm = binding.MIMEMultipartPOSTForm
	MIMEYAML              = binding.MIMEYAML
	MIMETOML              = binding.MIMETOML
)

// BodyBytesKey indicates a default body bytes key.
const BodyBytesKey = "_gin-gonic/gin/bodybyteskey"

// ContextKey is the key that a context returns itself for.
const ContextKey = "_gin-gonic/gin/contextkey"

// abortIndex represents a typical value used in abort functions.
const abortIndex int8 = math.MaxInt8 >> 1

// todo 需要去返回一个error
type Context interface {
	// Request returns `*http.Request`.
	Request() *http.Request

	// SetRequest sets `*http.Request`.
	SetRequest(r *http.Request)

	// SetResponse sets `*Response`.
	//SetResponse(r *Response)

	// Response returns `*Response`.
	Response() ResponseWriter

	// IsTLS returns true if HTTP connection is TLS otherwise false.
	IsTLS() bool

	// IsWebSocket returns true if HTTP connection is WebSocket otherwise false.
	IsWebSocket() bool

	// Scheme returns the HTTP protocol scheme, `http` or `https`.
	Scheme() string

	// RealIP returns the client's network address based on `X-Forwarded-For`
	// or `X-Real-IP` request header.
	// The behavior can be configured using `Echo#IPExtractor`.
	RealIP() string

	// Path returns the registered path for the handler.
	Path() string

	// SetPath sets the registered path for the handler.
	SetPath(p string)

	// Param returns path parameter by name.
	Param(name string) string

	// ParamNames returns path parameter names.
	ParamNames() []string

	// SetParamNames sets path parameter names.
	SetParamNames(names ...string)

	// ParamValues returns path parameter values.
	ParamValues() []string

	// SetParamValues sets path parameter values.
	SetParamValues(values ...string)

	// QueryParam returns the query param for the provided name.
	QueryParam(name string) string

	// QueryParams returns the query parameters as `url.Values`.
	QueryParams() url.Values

	// QueryString returns the URL query string.
	QueryString() string

	// FormValue returns the form field value for the provided name.
	FormValue(name string) string

	// FormParams returns the form parameters as `url.Values`.
	FormParams() (url.Values, error)

	// FormFile returns the multipart form file for the provided name.
	FormFile(name string) (*multipart.FileHeader, error)

	// MultipartForm returns the multipart form.
	MultipartForm() (*multipart.Form, error)

	// Cookie returns the named cookie provided in the request.
	Cookie(name string) (*http.Cookie, error)

	// SetCookie adds a `Set-Cookie` header in HTTP response.
	SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)

	// Cookies returns the HTTP cookies sent with the request.
	Cookies() []*http.Cookie

	// Get retrieves data from the context.
	Get(key string) (value any, exists bool)

	// Set saves data in the context.
	Set(key string, val interface{})

	// Bind binds path params, query params and the request body into provided type `i`. The default binder
	// binds body based on Content-Type header.
	Bind(i interface{}) error

	// Validate validates provided `i`. It is usually called after `Context#Bind()`.
	// Validator must be registered using `Echo#Validator`.
	Validate(i interface{}) error

	// Render renders a template with data and sends a text/html response with status
	// code. Renderer must be registered using `Echo.Renderer`.
	Render(code int, r render.Render)

	// HTML sends an HTTP response with status code.
	HTML(code int, html string) error

	// HTMLBlob sends an HTTP blob response with status code.
	HTMLBlob(code int, b []byte) error

	// String sends a string response with status code.
	String(code int, format string, values ...any)

	// JSON sends a JSON response with status code.
	JSON(code int, obj any)

	// JSONPretty sends a pretty-print JSON with status code.
	JSONPretty(code int, i interface{}, indent string) error

	// JSONBlob sends a JSON blob response with status code.
	JSONBlob(code int, b []byte) error

	// JSONP sends a JSONP response with status code. It uses `callback` to construct
	// the JSONP payload.
	JSONP(code int, obj any)

	// JSONPBlob sends a JSONP blob response with status code. It uses `callback`
	// to construct the JSONP payload.
	JSONPBlob(code int, callback string, b []byte) error

	// XML sends an XML response with status code.
	XML(code int, obj any)

	// XMLPretty sends a pretty-print XML with status code.
	XMLPretty(code int, i interface{}, indent string) error

	// XMLBlob sends an XML blob response with status code.
	XMLBlob(code int, b []byte) error

	// Blob sends a blob response with status code and content type.
	Blob(code int, contentType string, b []byte) error

	// Stream sends a streaming response with status code and content type.
	Stream(step func(w io.Writer) bool) bool

	// File sends a response with the content of the file.
	File(filepath string)

	// Attachment sends a response as attachment, prompting client to save the
	// file.
	Attachment(file string, name string) error

	// Inline sends a response as inline, opening the file in the browser.
	Inline(file string, name string) error

	// NoContent sends a response with no body and a status code.
	NoContent(code int) error

	// Redirect redirects the request to a provided URL with status code.
	Redirect(code int, location string)

	// Error invokes the registered global HTTP error handler. Generally used by middleware.
	// A side-effect of calling global error handler is that now Response has been committed (sent to the client) and
	// middlewares up in chain can not change Response status code or Response body anymore.
	//
	// Avoid using this method in handlers as no middleware will be able to effectively handle errors after that.
	Error(err error) *Error

	// Handler returns the matched handler by router.
	Handlers() HandlersChain
	SetHandlers(handlers HandlersChain)

	// SetHandler sets the matched handler by router.
	SetHandler(h HandlerFunc)

	// Logger returns the `Logger` instance.
	//Logger() Logger
	//
	//// SetLogger Set the logger
	//SetLogger(l Logger)

	// Echo returns the `Echo` instance.
	//Echo() *Echo

	// Reset resets the context after request completes. It must be called along
	// with `Echo#AcquireContext()` and `Echo#ReleaseContext()`.
	// See `Echo#ServeHTTP()`
	Reset()
	FileFromFS(f string, fs http.FileSystem)
	Header(s string, realm string)
	AbortWithStatus(unauthorized int)
	RequestHeader(s string) string
	Abort()
	Next()
	ClientIP() string
	Errors() errorMsgs
	ServeStaticFile(fs http.FileSystem, fileServer http.Handler)
	ShouldBind(obj any) error
	Copy() *context
	Done() <-chan struct{}
	Deadline() (deadline time.Time, ok bool)
	Err() error
	Value(key any) any
	MustGet(key string) any
}

// todo 响应hook（after/before hooks）在gin中没有实现，而不是像echo通过将func放入到response中,hook reponse的Write去实现

// context is the most important part of gin. It allows us to pass variables between middleware,
// manage the flow, validate the JSON of a request and render a JSON response for example.
type context struct {
	// writermem 是一个自定义的响应写入器，实现了 ResponseWriter 接口。
	writermem responseWriter
	request   *http.Request

	Params   Params // 外部使用的参数是params的值拷贝
	handlers HandlersChain
	index    int8 // index 表示当前处理器在handlers链中的索引位置。它的值会随着调用Next()方法而递增，直到达到handlers链的末尾或被Abort()方法中断。
	fullPath string

	engine       *Engine
	params       *Params        // context内部使用的参数，用于解析url中的参数，实现路由参数的功能
	skippedNodes *[]skippedNode // 节点可能会被标记为跳过，因为它们不匹配任何实际的路由

	// 保证keys的并发安全
	mu sync.RWMutex

	// Keys 是专门用于每个请求上下文的键/值对。
	// 用于共享数据 例如身份认证中间件当用户通过身份验证后，你可以将用户的信息存储在 Keys 中，以便在后续的处理器中使用。
	Keys map[string]any

	// Errors 是一个错误列表，附加到使用此上下文的所有处理程序/中间件。
	errors errorMsgs

	// Accepted defines a list of manually accepted formats for content negotiation.
	Accepted []string

	// queryCache 缓存 c.Request.URL.Query() 的结果。
	queryCache url.Values

	// formCache caches c.Request.PostForm, which contains the parsed form data from POST, PATCH,
	// or PUT body parameters.
	// formCache 缓存 c.Request.PostForm 包含从 POST、PATCH 或 PUT 请求体参数解析的表单数据。
	formCache url.Values

	// SameSite allows a server to define a cookie attribute making it impossible for
	// the browser to send this cookie along with cross-site requests.
	sameSite http.SameSite
}

func (c *context) Handlers() HandlersChain {
	return c.handlers
}

func (c *context) SetHandlers(handlers HandlersChain) {
	c.handlers = handlers
}
func (c *context) Errors() errorMsgs {
	return c.errors
}
func (c *context) Request() *http.Request {
	if c.request == nil {
		panic("request is nil")
	}
	return c.request
}

func (c *context) SetRequest(r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (c *context) Response() ResponseWriter {
	return &c.writermem
}

func (c *context) IsTLS() bool {
	//TODO implement me
	panic("implement me")
}

func (c *context) IsWebSocket() bool {
	//TODO implement me
	panic("implement me")
}

func (c *context) Scheme() string {
	//TODO implement me
	panic("implement me")
}

func (c *context) RealIP() string {
	//TODO implement me
	panic("implement me")
}

func (c *context) Path() string {
	//TODO implement me
	panic("implement me")
}

func (c *context) SetPath(p string) {
	//TODO implement me
	panic("implement me")
}

func (c *context) ParamNames() []string {
	//TODO implement me
	panic("implement me")
}

func (c *context) SetParamNames(names ...string) {
	//TODO implement me
	panic("implement me")
}

func (c *context) ParamValues() []string {
	//TODO implement me
	panic("implement me")
}

func (c *context) SetParamValues(values ...string) {
	//TODO implement me
	panic("implement me")
}

func (c *context) QueryParam(name string) string {
	//TODO implement me
	panic("implement me")
}

func (c *context) QueryParams() url.Values {
	//TODO implement me
	panic("implement me")
}

func (c *context) QueryString() string {
	//TODO implement me
	panic("implement me")
}

func (c *context) FormValue(name string) string {
	//TODO implement me
	panic("implement me")
}

func (c *context) FormParams() (url.Values, error) {
	//TODO implement me
	panic("implement me")
}

func (c *context) Cookies() []*http.Cookie {
	//TODO implement me
	panic("implement me")
}

func (c *context) Validate(i interface{}) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) HTML(code int, html string) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) HTMLBlob(code int, b []byte) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) JSONPretty(code int, i interface{}, indent string) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) JSONBlob(code int, b []byte) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) JSONPBlob(code int, callback string, b []byte) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) XMLPretty(code int, i interface{}, indent string) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) XMLBlob(code int, b []byte) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) Blob(code int, contentType string, b []byte) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) Attachment(file string, name string) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) Inline(file string, name string) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) NoContent(code int) error {
	//TODO implement me
	panic("implement me")
}

func (c *context) SetHandler(h HandlerFunc) {
	//TODO implement me
	panic("implement me")
}

/************************************/
/********** CONTEXT CREATION ********/
/************************************/

func (c *context) Reset() {
	c.Params = c.Params[:0]
	c.handlers = nil
	c.index = -1

	c.fullPath = ""
	c.Keys = nil
	c.errors = c.errors[:0]
	c.Accepted = nil
	c.queryCache = nil
	c.formCache = nil
	c.sameSite = 0
	*c.params = (*c.params)[:0]
	*c.skippedNodes = (*c.skippedNodes)[:0]
}

// Copy returns a copy of the current context that can be safely used outside the request's scope.
// This has to be used when the context has to be passed to a goroutine.
func (c *context) Copy() *context {
	cp := context{
		writermem: c.writermem,
		request:   c.Request(),
		Params:    c.Params,
		engine:    c.engine,
	}
	cp.writermem.ResponseWriter = nil
	cp.index = abortIndex
	cp.handlers = nil
	cp.Keys = map[string]any{}
	for k, v := range c.Keys {
		cp.Keys[k] = v
	}
	paramCopy := make([]Param, len(cp.Params))
	copy(paramCopy, cp.Params)
	cp.Params = paramCopy
	return &cp
}

// HandlerName returns the main handler's name. For example if the handler is "handleGetUsers()",
// this function will return "main.handleGetUsers".
func (c *context) HandlerName() string {
	return nameOfFunction(c.handlers.Last())
}

// HandlerNames returns a list of all registered handlers for this context in descending order,
// following the semantics of HandlerName()
func (c *context) HandlerNames() []string {
	hn := make([]string, 0, len(c.handlers))
	for _, val := range c.handlers {
		hn = append(hn, nameOfFunction(val))
	}
	return hn
}

// FullPath returns a matched route full path. For not found routes
// returns an empty string.
//
//	router.GET("/user/:id", func(c *gin.context) {
//	    c.FullPath() == "/user/:id" // true
//	})
func (c *context) FullPath() string {
	return c.fullPath
}

/************************************/
/*********** FLOW CONTROL ***********/
/************************************/

// Next 应该只在中间件中使用。它执行调用处理程序中链中的挂起处理程序。
func (c *context) Next() {
	c.index++
	// 通过 for 循环，依次执行链中的处理器
	// handlers 链的长度必须小于 63否则在注册时就会直接 panic(combineHandlers函数). 因此在 context.Next 方法中，一旦 index 被设为 63，则必然大于整条 handlers 链的长度，for 循环便会提前终止.
	for c.index < int8(len(c.handlers)) {
		c.handlers[c.index](c)
		c.index++
	}
}

// IsAborted returns true if the current context was aborted.
func (c *context) IsAborted() bool {
	return c.index >= abortIndex
}

// Abort prevents pending handlers from being called. Note that this will not stop the current handler.
// Let's say you have an authorization middleware that validates that the current request is authorized.
// If the authorization fails (ex: the password does not match), call Abort to ensure the remaining handlers
// for this request are not called.

func (c *context) Abort() {
	c.index = abortIndex
}

// AbortWithStatus calls `Abort()` and writes the headers with the specified status code.
// For example, a failed attempt to authenticate a request could use: context.AbortWithStatus(401).
func (c *context) AbortWithStatus(code int) {
	c.Status(code)
	c.Response().WriteHeaderNow()
	c.Abort()
}

// AbortWithStatusJSON calls `Abort()` and then `JSON` internally.
// This method stops the chain, writes the status code and return a JSON body.
// It also sets the Content-Type as "application/json".
func (c *context) AbortWithStatusJSON(code int, jsonObj any) {
	c.Abort()
	c.JSON(code, jsonObj)
}

// AbortWithError calls `AbortWithStatus()` and `Error()` internally.
// This method stops the chain, writes the status code and pushes the specified error to `c.Errors`.
// See context.Error() for more details.
func (c *context) AbortWithError(code int, err error) *Error {
	c.AbortWithStatus(code)
	return c.Error(err)
}

/************************************/
/********* ERROR MANAGEMENT *********/
/************************************/

// Error attaches an error to the current context. The error is pushed to a list of errors.
// It's a good idea to call Error for each error that occurred during the resolution of a request.
// A middleware can be used to collect all the errors and push them to a database together,
// print a log, or append it in the HTTP response.
// Error will panic if err is nil.
func (c *context) Error(err error) *Error {
	if err == nil {
		panic("err is nil")
	}

	var parsedError *Error
	ok := errors.As(err, &parsedError)
	if !ok {
		parsedError = &Error{
			Err:  err,
			Type: ErrorTypePrivate,
		}
	}

	c.errors = append(c.errors, parsedError)
	return parsedError
}

/************************************/
/******** METADATA MANAGEMENT********/
/************************************/

// Set is used to store a new key/value pair exclusively for this context.
// It also lazy initializes  c.Keys if it was not used previously.
func (c *context) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Keys == nil {
		c.Keys = make(map[string]any)
	}

	c.Keys[key] = value
}

// Get returns the value for the given key, ie: (value, true).
// If the value does not exist it returns (nil, false)
// Get 返回指定键的值，即 (value, true)。
// 如果值不存在，则返回 (nil, false)。
func (c *context) Get(key string) (value any, exists bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists = c.Keys[key]
	return
}

// MustGet returns the value for the given key if it exists, otherwise it panics.
func (c *context) MustGet(key string) any {
	if value, exists := c.Get(key); exists {
		return value
	}
	panic("Key \"" + key + "\" does not exist")
}

// GetString returns the value associated with the key as a string.
func (c *context) GetString(key string) (s string) {
	if val, ok := c.Get(key); ok && val != nil {
		s, _ = val.(string)
	}
	return
}

// GetBool returns the value associated with the key as a boolean.
func (c *context) GetBool(key string) (b bool) {
	if val, ok := c.Get(key); ok && val != nil {
		b, _ = val.(bool)
	}
	return
}

// GetInt returns the value associated with the key as an integer.
func (c *context) GetInt(key string) (i int) {
	if val, ok := c.Get(key); ok && val != nil {
		i, _ = val.(int)
	}
	return
}

// GetInt64 returns the value associated with the key as an integer.
func (c *context) GetInt64(key string) (i64 int64) {
	if val, ok := c.Get(key); ok && val != nil {
		i64, _ = val.(int64)
	}
	return
}

// GetUint returns the value associated with the key as an unsigned integer.
func (c *context) GetUint(key string) (ui uint) {
	if val, ok := c.Get(key); ok && val != nil {
		ui, _ = val.(uint)
	}
	return
}

// GetUint64 returns the value associated with the key as an unsigned integer.
func (c *context) GetUint64(key string) (ui64 uint64) {
	if val, ok := c.Get(key); ok && val != nil {
		ui64, _ = val.(uint64)
	}
	return
}

// GetFloat64 returns the value associated with the key as a float64.
func (c *context) GetFloat64(key string) (f64 float64) {
	if val, ok := c.Get(key); ok && val != nil {
		f64, _ = val.(float64)
	}
	return
}

// GetTime returns the value associated with the key as time.
func (c *context) GetTime(key string) (t time.Time) {
	if val, ok := c.Get(key); ok && val != nil {
		t, _ = val.(time.Time)
	}
	return
}

// GetDuration returns the value associated with the key as a duration.
func (c *context) GetDuration(key string) (d time.Duration) {
	if val, ok := c.Get(key); ok && val != nil {
		d, _ = val.(time.Duration)
	}
	return
}

// GetStringSlice returns the value associated with the key as a slice of strings.
func (c *context) GetStringSlice(key string) (ss []string) {
	if val, ok := c.Get(key); ok && val != nil {
		ss, _ = val.([]string)
	}
	return
}

// GetStringMap returns the value associated with the key as a map of interfaces.
func (c *context) GetStringMap(key string) (sm map[string]any) {
	if val, ok := c.Get(key); ok && val != nil {
		sm, _ = val.(map[string]any)
	}
	return
}

// GetStringMapString returns the value associated with the key as a map of strings.
func (c *context) GetStringMapString(key string) (sms map[string]string) {
	if val, ok := c.Get(key); ok && val != nil {
		sms, _ = val.(map[string]string)
	}
	return
}

// GetStringMapStringSlice returns the value associated with the key as a map to a slice of strings.
func (c *context) GetStringMapStringSlice(key string) (smss map[string][]string) {
	if val, ok := c.Get(key); ok && val != nil {
		smss, _ = val.(map[string][]string)
	}
	return
}

/************************************/
/************ INPUT DATA ************/
/************************************/

// Param returns the value of the URL param.
// It is a shortcut for c.Params.ByName(key)
//
//	router.GET("/user/:id", func(c *gin.context) {
//	    // a GET request to /user/john
//	    id := c.Param("id") // id == "/john"
//	    // a GET request to /user/john/
//	    id := c.Param("id") // id == "/john/"
//	})
func (c *context) Param(key string) string {
	return c.Params.ByName(key)
}

// AddParam adds param to context and
// replaces path param key with given value for e2e testing purposes
// Example Route: "/user/:id"
// AddParam("id", 1)
// Result: "/user/1"
func (c *context) AddParam(key, value string) {
	c.Params = append(c.Params, Param{Key: key, Value: value})
}

// Query returns the keyed url query value if it exists,
// otherwise it returns an empty string `("")`.
// It is shortcut for `c.Request.URL.Query().Get(key)`
//
//	    GET /path?id=1234&name=Manu&value=
//		   c.Query("id") == "1234"
//		   c.Query("name") == "Manu"
//		   c.Query("value") == ""
//		   c.Query("wtf") == ""
func (c *context) Query(key string) (value string) {
	value, _ = c.GetQuery(key)
	return
}

// DefaultQuery returns the keyed url query value if it exists,
// otherwise it returns the specified defaultValue string.
// See: Query() and GetQuery() for further information.
//
//	GET /?name=Manu&lastname=
//	c.DefaultQuery("name", "unknown") == "Manu"
//	c.DefaultQuery("id", "none") == "none"
//	c.DefaultQuery("lastname", "none") == ""
func (c *context) DefaultQuery(key, defaultValue string) string {
	if value, ok := c.GetQuery(key); ok {
		return value
	}
	return defaultValue
}

// GetQuery is like Query(), it returns the keyed url query value
// if it exists `(value, true)` (even when the value is an empty string),
// otherwise it returns `("", false)`.
// It is shortcut for `c.Request.URL.Query().Get(key)`
//
//	GET /?name=Manu&lastname=
//	("Manu", true) == c.GetQuery("name")
//	("", false) == c.GetQuery("id")
//	("", true) == c.GetQuery("lastname")
func (c *context) GetQuery(key string) (string, bool) {
	if values, ok := c.GetQueryArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// QueryArray returns a slice of strings for a given query key.
// The length of the slice depends on the number of params with the given key.
func (c *context) QueryArray(key string) (values []string) {
	values, _ = c.GetQueryArray(key)
	return
}

func (c *context) initQueryCache() {
	if c.queryCache == nil {
		if c.Request != nil {
			c.queryCache = c.Request().URL.Query()
		} else {
			c.queryCache = url.Values{}
		}
	}
}

// GetQueryArray returns a slice of strings for a given query key, plus
// a boolean value whether at least one value exists for the given key.
func (c *context) GetQueryArray(key string) (values []string, ok bool) {
	c.initQueryCache()
	values, ok = c.queryCache[key]
	return
}

// QueryMap returns a map for a given query key.
func (c *context) QueryMap(key string) (dicts map[string]string) {
	dicts, _ = c.GetQueryMap(key)
	return
}

// GetQueryMap returns a map for a given query key, plus a boolean value
// whether at least one value exists for the given key.
func (c *context) GetQueryMap(key string) (map[string]string, bool) {
	c.initQueryCache()
	return c.get(c.queryCache, key)
}

// PostForm returns the specified key from a POST urlencoded form or multipart form
// when it exists, otherwise it returns an empty string `("")`.
func (c *context) PostForm(key string) (value string) {
	value, _ = c.GetPostForm(key)
	return
}

// DefaultPostForm returns the specified key from a POST urlencoded form or multipart form
// when it exists, otherwise it returns the specified defaultValue string.
// See: PostForm() and GetPostForm() for further information.
func (c *context) DefaultPostForm(key, defaultValue string) string {
	if value, ok := c.GetPostForm(key); ok {
		return value
	}
	return defaultValue
}

// GetPostForm is like PostForm(key). It returns the specified key from a POST urlencoded
// form or multipart form when it exists `(value, true)` (even when the value is an empty string),
// otherwise it returns ("", false).
// For example, during a PATCH request to update the user's email:
//
//	    email=mail@example.com  -->  ("mail@example.com", true) := GetPostForm("email") // set email to "mail@example.com"
//		   email=                  -->  ("", true) := GetPostForm("email") // set email to ""
//	                            -->  ("", false) := GetPostForm("email") // do nothing with email
func (c *context) GetPostForm(key string) (string, bool) {
	if values, ok := c.GetPostFormArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// PostFormArray returns a slice of strings for a given form key.
// The length of the slice depends on the number of params with the given key.
func (c *context) PostFormArray(key string) (values []string) {
	values, _ = c.GetPostFormArray(key)
	return
}

func (c *context) initFormCache() {
	if c.formCache == nil {
		c.formCache = make(url.Values)
		req := c.Request()
		if err := req.ParseMultipartForm(c.engine.MaxMultipartMemory); err != nil {
			if !errors.Is(err, http.ErrNotMultipart) {
				debugPrint("error on parse multipart form array: %v", err)
			}
		}
		c.formCache = req.PostForm
	}
}

// GetPostFormArray returns a slice of strings for a given form key, plus
// a boolean value whether at least one value exists for the given key.
func (c *context) GetPostFormArray(key string) (values []string, ok bool) {
	c.initFormCache()
	values, ok = c.formCache[key]
	return
}

// PostFormMap returns a map for a given form key.
func (c *context) PostFormMap(key string) (dicts map[string]string) {
	dicts, _ = c.GetPostFormMap(key)
	return
}

// GetPostFormMap returns a map for a given form key, plus a boolean value
// whether at least one value exists for the given key.
func (c *context) GetPostFormMap(key string) (map[string]string, bool) {
	c.initFormCache()
	return c.get(c.formCache, key)
}

// get is an internal method and returns a map which satisfies conditions.
func (c *context) get(m map[string][]string, key string) (map[string]string, bool) {
	dicts := make(map[string]string)
	exist := false
	for k, v := range m {
		if i := strings.IndexByte(k, '['); i >= 1 && k[0:i] == key {
			if j := strings.IndexByte(k[i+1:], ']'); j >= 1 {
				exist = true
				dicts[k[i+1:][:j]] = v[0]
			}
		}
	}
	return dicts, exist
}

// FormFile returns the first file for the provided form key.
func (c *context) FormFile(name string) (*multipart.FileHeader, error) {
	if c.Request().MultipartForm == nil {
		if err := c.Request().ParseMultipartForm(c.engine.MaxMultipartMemory); err != nil {
			return nil, err
		}
	}
	f, fh, err := c.Request().FormFile(name)
	if err != nil {
		return nil, err
	}
	f.Close()
	return fh, err
}

// MultipartForm is the parsed multipart form, including file uploads.
func (c *context) MultipartForm() (*multipart.Form, error) {
	err := c.Request().ParseMultipartForm(c.engine.MaxMultipartMemory)
	return c.Request().MultipartForm, err
}

// SaveUploadedFile uploads the form file to specific dst.
func (c *context) SaveUploadedFile(file *multipart.FileHeader, dst string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	if err = os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, src)
	return err
}

// Bind checks the Method and Content-Type to select a binding engine automatically,
// Depending on the "Content-Type" header different bindings are used, for example:
//
//	"application/json" --> JSON binding
//	"application/xml"  --> XML binding
//
// It parses the request's body as JSON if Content-Type == "application/json" using JSON or XML as a JSON input.
// It decodes the json payload into the struct specified as a pointer.
// It writes a 400 error and sets Content-Type header "text/plain" in the response if input is not valid.
func (c *context) Bind(obj any) error {
	b := binding.Default(c.Request().Method, c.ContentType())
	return c.MustBindWith(obj, b)
}

// BindJSON is a shortcut for c.MustBindWith(obj, binding.JSON).
func (c *context) BindJSON(obj any) error {
	return c.MustBindWith(obj, binding.JSON)
}

// BindXML is a shortcut for c.MustBindWith(obj, binding.BindXML).
func (c *context) BindXML(obj any) error {
	return c.MustBindWith(obj, binding.XML)
}

// BindQuery is a shortcut for c.MustBindWith(obj, binding.Query).
func (c *context) BindQuery(obj any) error {
	return c.MustBindWith(obj, binding.Query)
}

// BindYAML is a shortcut for c.MustBindWith(obj, binding.YAML).
func (c *context) BindYAML(obj any) error {
	return c.MustBindWith(obj, binding.YAML)
}

// BindTOML is a shortcut for c.MustBindWith(obj, binding.TOML).
func (c *context) BindTOML(obj any) error {
	return c.MustBindWith(obj, binding.TOML)
}

// BindHeader is a shortcut for c.MustBindWith(obj, binding.Header).
func (c *context) BindHeader(obj any) error {
	return c.MustBindWith(obj, binding.Header)
}

// BindUri binds the passed struct pointer using binding.Uri.
// It will abort the request with HTTP 400 if any error occurs.
func (c *context) BindUri(obj any) error {
	if err := c.ShouldBindUri(obj); err != nil {
		c.AbortWithError(http.StatusBadRequest, err).SetType(ErrorTypeBind) //nolint: errcheck
		return err
	}
	return nil
}

// MustBindWith binds the passed struct pointer using the specified binding engine.
// It will abort the request with HTTP 400 if any error occurs.
// See the binding package.
func (c *context) MustBindWith(obj any, b binding.Binding) error {
	if err := c.ShouldBindWith(obj, b); err != nil {
		c.AbortWithError(http.StatusBadRequest, err).SetType(ErrorTypeBind) //nolint: errcheck
		return err
	}
	return nil
}

// ShouldBind checks the Method and Content-Type to select a binding engine automatically,
// Depending on the "Content-Type" header different bindings are used, for example:
//
//	"application/json" --> JSON binding
//	"application/xml"  --> XML binding
//
// It parses the request's body as JSON if Content-Type == "application/json" using JSON or XML as a JSON input.
// It decodes the json payload into the struct specified as a pointer.
// Like c.Bind() but this method does not set the response status code to 400 or abort if input is not valid.
// 如果是 `GET` 请求，只使用 `Form` 绑定引擎（`query`）。
// 如果是 `POST` 请求，首先检查 `content-type` 是否为 `JSON` 或 `XML`，然后再使用 `Form`（`form-data`）。
// 只支持JSON、XML、YAML,form,msgpack
// 选择绑定引擎时返回response
func (c *context) ShouldBind(obj any) error {
	b := binding.Default(c.Request().Method, c.ContentType())
	return c.ShouldBindWith(obj, b)
}

// ShouldBindJSON is a shortcut for c.ShouldBindWith(obj, binding.JSON).
func (c *context) ShouldBindJSON(obj any) error {
	return c.ShouldBindWith(obj, binding.JSON)
}

// ShouldBindXML is a shortcut for c.ShouldBindWith(obj, binding.XML).
func (c *context) ShouldBindXML(obj any) error {
	return c.ShouldBindWith(obj, binding.XML)
}

// ShouldBindQuery is a shortcut for c.ShouldBindWith(obj, binding.Query).
func (c *context) ShouldBindQuery(obj any) error {
	return c.ShouldBindWith(obj, binding.Query)
}

// ShouldBindYAML is a shortcut for c.ShouldBindWith(obj, binding.YAML).
func (c *context) ShouldBindYAML(obj any) error {
	return c.ShouldBindWith(obj, binding.YAML)
}

// ShouldBindTOML is a shortcut for c.ShouldBindWith(obj, binding.TOML).
func (c *context) ShouldBindTOML(obj any) error {
	return c.ShouldBindWith(obj, binding.TOML)
}

// ShouldBindHeader is a shortcut for c.ShouldBindWith(obj, binding.Header).
func (c *context) ShouldBindHeader(obj any) error {
	return c.ShouldBindWith(obj, binding.Header)
}

// ShouldBindUri 绑定传递的结构指针使用指定的绑定引擎。
// 例如：/:name/:id
func (c *context) ShouldBindUri(obj any) error {
	m := make(map[string][]string)
	for _, v := range c.Params {
		m[v.Key] = []string{v.Value}
	}
	return binding.Uri.BindUri(m, obj)
}

// ShouldBindWith 使用指定的绑定引擎绑定传递的结构指针。
// 根据“Content-Type”标头使用不同的绑定，
//
//	"application/json" --> JSON binding 。。。。
//
// 例如：/name?id=1
func (c *context) ShouldBindWith(obj any, b binding.Binding) error {
	return b.Bind(c.Request(), obj)
}

// ShouldBindBodyWith is similar with ShouldBindWith, but it stores the request
// body into the context, and reuse when it is called again.
//
// NOTE: This method reads the body before binding. So you should use
// ShouldBindWith for better performance if you need to call only once.
func (c *context) ShouldBindBodyWith(obj any, bb binding.BindingBody) (err error) {
	var body []byte
	if cb, ok := c.Get(BodyBytesKey); ok {
		if cbb, ok := cb.([]byte); ok {
			body = cbb
		}
	}
	if body == nil {
		body, err = io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		c.Set(BodyBytesKey, body)
	}
	return bb.BindBody(body, obj)
}

// ClientIP implements one best effort algorithm to return the real client IP.
// It calls c.RemoteIP() under the hood, to check if the remote IP is a trusted proxy or not.
// If it is it will then try to parse the headers defined in Engine.RemoteIPHeaders (defaulting to [X-Forwarded-For, X-Real-Ip]).
// If the headers are not syntactically valid OR the remote IP does not correspond to a trusted proxy,
// the remote IP (coming from Request.RemoteAddr) is returned.
func (c *context) ClientIP() string {
	// Check if we're running on a trusted platform, continue running backwards if error
	if c.engine.TrustedPlatform != "" {
		// Developers can define their own header of Trusted Platform or use predefined constants
		if addr := c.RequestHeader(c.engine.TrustedPlatform); addr != "" {
			return addr
		}
	}

	// Legacy "AppEngine" flag
	if c.engine.AppEngine {
		log.Println(`The AppEngine flag is going to be deprecated. Please check issues #2723 and #2739 and use 'TrustedPlatform: gin.PlatformGoogleAppEngine' instead.`)
		if addr := c.RequestHeader("X-Appengine-Remote-Addr"); addr != "" {
			return addr
		}
	}

	// It also checks if the remoteIP is a trusted proxy or not.
	// In order to perform this validation, it will see if the IP is contained within at least one of the CIDR blocks
	// defined by Engine.SetTrustedProxies()
	remoteIP := net.ParseIP(c.RemoteIP())
	if remoteIP == nil {
		return ""
	}
	trusted := c.engine.isTrustedProxy(remoteIP)

	if trusted && c.engine.ForwardedByClientIP && c.engine.RemoteIPHeaders != nil {
		for _, headerName := range c.engine.RemoteIPHeaders {
			ip, valid := c.engine.validateHeader(c.RequestHeader(headerName))
			if valid {
				return ip
			}
		}
	}
	return remoteIP.String()
}

// RemoteIP parses the IP from Request.RemoteAddr, normalizes and returns the IP (without the port).
func (c *context) RemoteIP() string {
	ip, _, err := net.SplitHostPort(strings.TrimSpace(c.Request().RemoteAddr))
	if err != nil {
		return ""
	}
	return ip
}

// ContentType returns the Content-Type header of the request.
func (c *context) ContentType() string {
	return filterFlags(c.RequestHeader("Content-Type"))
}

// IsWebsocket returns true if the request headers indicate that a websocket
// handshake is being initiated by the client.
func (c *context) IsWebsocket() bool {
	if strings.Contains(strings.ToLower(c.RequestHeader("Connection")), "upgrade") &&
		strings.EqualFold(c.RequestHeader("Upgrade"), "websocket") {
		return true
	}
	return false
}

func (c *context) RequestHeader(key string) string {
	return c.Request().Header.Get(key)
}

/************************************/
/******** RESPONSE RENDERING ********/
/************************************/

// bodyAllowedForStatus is a copy of http.bodyAllowedForStatus non-exported function.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	}
	return true
}

// Status sets the HTTP response code.
func (c *context) Status(code int) {
	c.Response().WriteHeader(code)
}

// Header is an intelligent shortcut for c.Writer.Header().Set(key, value).
// It writes a header in the response.
// If value == "", this method removes the header `c.Writer.Header().Del(key)`
func (c *context) Header(key, value string) {
	if value == "" {
		c.Response().Header().Del(key)
		return
	}
	c.Response().Header().Set(key, value)
}

// GetHeader returns value from request headers.
func (c *context) GetHeader(key string) string {
	return c.RequestHeader(key)
}

// GetRawData returns stream data.
func (c *context) GetRawData() ([]byte, error) {
	return io.ReadAll(c.Request().Body)
}

// SetSameSite with cookie
func (c *context) SetSameSite(samesite http.SameSite) {
	c.sameSite = samesite
}

// SetCookie adds a Set-Cookie header to the ResponseWriter's headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
func (c *context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	if path == "" {
		path = "/"
	}
	http.SetCookie(c.Response(), &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		SameSite: c.sameSite,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// Cookie returns the named cookie provided in the request or
// ErrNoCookie if not found. And return the named cookie is unescaped.
// If multiple cookies match the given name, only one cookie will
// be returned.
func (c *context) Cookie(name string) (*http.Cookie, error) {
	return c.request.Cookie(name)
}

// Render writes the response headers and calls render.Render to render data.
// Render 写入响应头并调用 render.Render 来渲染数据。
func (c *context) Render(code int, r render.Render) {
	c.Status(code)

	if !bodyAllowedForStatus(code) {
		r.WriteContentType(c.Response())
		c.Response().WriteHeaderNow()
		return
	}

	if err := r.Render(c.Response()); err != nil {
		// Pushing error to c.Errors
		_ = c.Error(err)
		c.Abort()
	}
}

// IndentedJSON serializes the given struct as pretty JSON (indented + endlines) into the response body.
// It also sets the Content-Type as "application/json".
// WARNING: we recommend using this only for development purposes since printing pretty JSON is
// more CPU and bandwidth consuming. Use context.JSON() instead.
func (c *context) IndentedJSON(code int, obj any) {
	c.Render(code, render.IndentedJSON{Data: obj})
}

// 使用 SecureJSON 防止 json 劫持。如果给定的结构是数组值，则默认预置 "while(1)," 到响应体。
func (c *context) SecureJSON(code int, obj any) {
	c.Render(code, render.SecureJSON{Prefix: c.engine.secureJSONPrefix, Data: obj})
}

// JSONP 使用 JSONP 向不同域的服务器请求数据。如果查询参数存在回调，则将回调添加到响应体中。
// 设置 Content-Type 为 "application/javascript"。
func (c *context) JSONP(code int, obj any) {
	callback := c.DefaultQuery("callback", "")
	if callback == "" {
		c.Render(code, render.JSON{Data: obj})
		return
	}
	c.Render(code, render.JsonpJSON{Callback: callback, Data: obj})
}

// JSON serializes the given struct as JSON into the response body.
// It also sets the Content-Type as "application/json".
func (c *context) JSON(code int, obj any) {
	c.Render(code, render.JSON{Data: obj})
}

// AsciiJSON serializes the given struct as JSON into the response body with unicode to ASCII string.
// It also sets the Content-Type as "application/json".
func (c *context) AsciiJSON(code int, obj any) {
	c.Render(code, render.AsciiJSON{Data: obj})
}

// PureJSON serializes the given struct as JSON into the response body.
// PureJSON, unlike JSON, does not replace special html characters with their unicode entities.
func (c *context) PureJSON(code int, obj any) {
	c.Render(code, render.PureJSON{Data: obj})
}

// XML serializes the given struct as XML into the response body.
// It also sets the Content-Type as "application/xml".
func (c *context) XML(code int, obj any) {
	c.Render(code, render.XML{Data: obj})
}

// YAML serializes the given struct as YAML into the response body.
func (c *context) YAML(code int, obj any) {
	c.Render(code, render.YAML{Data: obj})
}

// TOML serializes the given struct as TOML into the response body.
func (c *context) TOML(code int, obj any) {
	c.Render(code, render.TOML{Data: obj})
}

// ProtoBuf serializes the given struct as ProtoBuf into the response body.
func (c *context) ProtoBuf(code int, obj any) {
	c.Render(code, render.ProtoBuf{Data: obj})
}

// String writes the given string into the response body.
// string 写入响应体中给定的字符串。
func (c *context) String(code int, format string, values ...any) {
	c.Render(code, render.String{Format: format, Data: values})
}

// Redirect 返回一个 HTTP 重定向到指定的位置。
func (c *context) Redirect(code int, location string) {
	c.Render(-1, render.Redirect{
		Code:     code,
		Location: location,
		Request:  c.Request(),
	})
}

// Data writes some data into the body stream and updates the HTTP code.
func (c *context) Data(code int, contentType string, data []byte) {
	c.Render(code, render.Data{
		ContentType: contentType,
		Data:        data,
	})
}

// DataFromReader 写入指定的 reader 到 body 流中，并更新 HTTP 状态码。
func (c *context) DataFromReader(code int, contentLength int64, contentType string, reader io.Reader, extraHeaders map[string]string) {
	c.Render(code, render.Reader{
		Headers:       extraHeaders,
		ContentType:   contentType,
		ContentLength: contentLength,
		Reader:        reader,
	})
}

// SSEvent 写入一个 Server-Sent Event 到 body 流中，content-type 为 text/event-stream
func (c *context) SSEvent(name string, message any) {
	c.Render(-1, sse.Event{
		Event: name,
		Data:  message,
	})
}

// Stream 发送一个流式响应并返回一个布尔值，表示“客户端是否在流中断开连接”
// step 返回false时，流将被关闭并且返回false, 如果客户端断开连接，流将被关闭并且返回true
// Stream 返回true表示客户端断开，返回false表示手动关闭
func (c *context) Stream(step func(w io.Writer) bool) bool {
	w := c.Response()
	clientGone := c.Request().Context().Done()
	for {
		select {
		case <-clientGone:
			return true
		default:
			keepOpen := step(w)
			w.Flush()
			if !keepOpen {
				return false
			}
		}
	}
}

/************************************/
/******** CONTENT NEGOTIATION *******/
/************************************/

// Negotiate contains all negotiations data.
type Negotiate struct {
	Offered  []string
	HTMLName string
	HTMLData any
	JSONData any
	XMLData  any
	YAMLData any
	Data     any
	TOMLData any
}

// Negotiate calls different Render according to acceptable Accept format.
func (c *context) Negotiate(code int, config Negotiate) {
	switch c.NegotiateFormat(config.Offered...) {
	case binding.MIMEJSON:
		data := chooseData(config.JSONData, config.Data)
		c.JSON(code, data)

	case binding.MIMEXML:
		data := chooseData(config.XMLData, config.Data)
		c.XML(code, data)

	case binding.MIMEYAML:
		data := chooseData(config.YAMLData, config.Data)
		c.YAML(code, data)

	case binding.MIMETOML:
		data := chooseData(config.TOMLData, config.Data)
		c.TOML(code, data)

	default:
		c.AbortWithError(http.StatusNotAcceptable, errors.New("the accepted formats are not offered by the server")) //nolint: errcheck
	}
}

// NegotiateFormat returns an acceptable Accept format.
func (c *context) NegotiateFormat(offered ...string) string {
	assert1(len(offered) > 0, "you must provide at least one offer")

	if c.Accepted == nil {
		c.Accepted = parseAccept(c.RequestHeader("Accept"))
	}
	if len(c.Accepted) == 0 {
		return offered[0]
	}
	for _, accepted := range c.Accepted {
		for _, offer := range offered {
			// According to RFC 2616 and RFC 2396, non-ASCII characters are not allowed in headers,
			// therefore we can just iterate over the string without casting it into []rune
			i := 0
			for ; i < len(accepted) && i < len(offer); i++ {
				if accepted[i] == '*' || offer[i] == '*' {
					return offer
				}
				if accepted[i] != offer[i] {
					break
				}
			}
			if i == len(accepted) {
				return offer
			}
		}
	}
	return ""
}

// SetAccepted sets Accept header data.
func (c *context) SetAccepted(formats ...string) {
	c.Accepted = formats
}

/************************************/
/***** GOLANG.ORG/X/NET/CONTEXT *****/
/************************************/

// hasRequestContext 返回c.Request是否有Context和 ContextWithFallback是否为true
func (c *context) hasRequestContext() bool {
	hasFallback := c.engine != nil && c.engine.ContextWithFallback
	hasRequestContext := c.Request != nil && c.Request().Context() != nil
	return hasFallback && hasRequestContext
}

// Deadline returns that there is no deadline (ok==false) when c.Request has no context.
func (c *context) Deadline() (deadline time.Time, ok bool) {
	if !c.hasRequestContext() {
		return
	}
	return c.Request().Context().Deadline()
}

// Done 返回nil（将永远等待的chan）当c.Request没有Context时
// context 在gin v1.8.0中总是被取消除非设置了ContextWithFallback
func (c *context) Done() <-chan struct{} {
	if !c.hasRequestContext() {
		return nil
	}
	return c.Request().Context().Done()
}

// Err returns nil when c.Request has no context.
func (c *context) Err() error {
	if !c.hasRequestContext() {
		return nil
	}
	return c.Request().Context().Err()
}

// Value 返回关联context的key的value，如果没有关联的value则返回nil
func (c *context) Value(key any) any {
	if key == 0 {
		return c.Request
	}
	if key == ContextKey {
		return c
	}
	if keyAsString, ok := key.(string); ok {
		if val, exists := c.Get(keyAsString); exists {
			return val
		}
	}
	if !c.hasRequestContext() {
		return nil
	}
	return c.Request().Context().Value(key)
}
