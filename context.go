// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"errors"
	"fmt"
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

// Context keys
const (
	// BodyBytesKey indicates a default body bytes key.
	BodyBytesKey = "_gin-gonic/gin/bodybyteskey"
	// ContextKey is the key that a context returns itself for.
	ContextKey = "_gin-gonic/gin/contextkey"
)

// abortIndex represents a typical value used in abort functions.
const abortIndex int8 = math.MaxInt8 >> 1

// 预定义错误
var (
	ErrNilRequest             = errors.New("request is nil")
	ErrNilParam               = errors.New("parameter is nil")
	ErrKeyNotFound            = errors.New("key not found")
	ErrValidatorNotRegistered = errors.New("validator not registered")
)

// Context 接口定义保持不变...
type Context interface {
	// 保持原有接口定义不变
	Request() *http.Request
	SetRequest(r *http.Request)
	SetResponse(r ResponseWriter)
	Response() ResponseWriter
	IsTLS() bool
	IsWebsocket() bool
	Scheme() string
	RealIP() string
	Path() string
	SetPath(p string)
	Param(name string) string
	ParamGet(name string) (string, bool)
	ParamNames() []string
	SetParamNames(names ...string)
	ParamValues() []string
	SetParamValues(values ...string)
	QueryParams() url.Values
	QueryString() string
	FormValue(name string) string
	FormParams() (url.Values, error)
	FormFile(name string) (*multipart.FileHeader, error)
	MultipartForm() (*multipart.Form, error)
	Cookie(name string) (*http.Cookie, error)
	SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)
	Cookies() []*http.Cookie
	Get(key string) (value any, exists bool)
	Set(key string, val interface{})
	Bind(i interface{}) error
	Validate(i interface{}) error
	Render(code int, r render.Render)
	HTMLBlob(code int, b []byte) error
	String(code int, format string, values ...any)
	JSON(code int, obj any)
	JSONBlob(code int, b []byte) error
	JSONP(code int, obj any)
	JSONPBlob(code int, callback string, b []byte) error
	XML(code int, obj any)
	XMLBlob(code int, b []byte) error
	Blob(code int, contentType string, b []byte) error
	Stream(step func(w io.Writer) bool) bool
	File(filepath string)
	Attachment(file string, name string) error
	Inline(file string, name string) error
	NoContent(code int)
	Redirect(code int, location string)
	Data(code int, contentType string, data []byte)
	DataFromReader(code int, contentLength int64, contentType string, reader io.Reader, extraHeaders map[string]string)
	Error(err error) *Error
	Handlers() HandlersChain
	SetHandlers(handlers HandlersChain)
	SetHandler(h HandlerFunc)
	Reset()
	FileFromFS(f string, fs http.FileSystem)
	Header(s string, realm string)
	AbortWithStatus(unauthorized int)
	AbortWithStatusJSON(code int, jsonObj any)
	AbortWithError(code int, err error) *Error
	RequestHeader(s string) string
	GetRawData() ([]byte, error)
	Abort()
	Next()
	ClientIP() string
	RemoteIP() string
	Errors() errorMsgs
	ServeStaticFile(fs http.FileSystem, fileServer http.Handler)
	ShouldBind(obj any) error
	Copy() *context
	Done() <-chan struct{}
	Deadline() (deadline time.Time, ok bool)
	Err() error
	Value(key any) any
	MustGet(key string) any
	FullPath() string
	Status(code int)
	ShouldBindUri(obj any) error
	BindUri(obj any) error
	Params() Params
	ShouldBindJSON(obj any) error
	ShouldBindXML(obj any) error
	ShouldBindYAML(obj any) error
	ShouldBindQuery(obj any) error
	ShouldBindTOML(obj any) error
	ShouldBindWith(obj any, b binding.Binding) error
}

type context struct {
	writermem *responseWriter
	request   *http.Request

	handlers HandlersChain
	index    int8
	fullPath string

	engine       *Engine
	params       *Params
	skippedNodes *[]skippedNode

	// 保证 keys 的并发安全
	mu sync.RWMutex

	// Keys 用于存储请求上下文的键值对
	Keys map[string]any

	// Errors 错误列表
	errors errorMsgs

	// Accepted 手动接受的内容协商格式
	Accepted []string

	// 缓存
	queryCache url.Values
	formCache  url.Values

	// SameSite cookie 属性
	sameSite http.SameSite
}

/************************************/
/********* CONTEXT CREATION *********/
/************************************/

// Reset 重置 context
func (c *context) Reset() {
	c.handlers = nil
	c.index = -1
	c.fullPath = ""
	c.Keys = nil
	c.errors = c.errors[:0]
	c.Accepted = nil
	c.queryCache = nil
	c.formCache = nil
	c.sameSite = 0
	if c.params != nil {
		*c.params = (*c.params)[:0]
	}
	if c.skippedNodes != nil {
		*c.skippedNodes = (*c.skippedNodes)[:0]
	}
}

// Copy 返回可安全在请求范围外使用的 context 副本
func (c *context) Copy() *context {
	cp := context{
		request: c.request,
		engine:  c.engine,
	}

	// 深拷贝 writermem
	if c.writermem != nil {
		w := *c.writermem
		cp.writermem = &w
	}

	cp.index = abortIndex
	cp.handlers = nil
	cp.fullPath = c.fullPath

	// 深拷贝 Keys
	cp.Keys = make(map[string]any, len(c.Keys))
	c.mu.RLock()
	for k, v := range c.Keys {
		cp.Keys[k] = v
	}
	c.mu.RUnlock()

	// 深拷贝 params
	if c.params != nil {
		newParams := make(Params, len(*c.params))
		copy(newParams, *c.params)
		cp.params = &newParams
	}

	// 深拷贝 errors
	if len(c.errors) > 0 {
		cp.errors = make(errorMsgs, len(c.errors))
		copy(cp.errors, c.errors)
	}

	cp.skippedNodes = c.skippedNodes
	return &cp
}

/************************************/
/********** REQUEST METHODS *********/
/************************************/

// Request 返回 HTTP 请求
func (c *context) Request() *http.Request {
	if c.request == nil {
		panic(ErrNilRequest)
	}
	return c.request
}

// SetRequest 设置 HTTP 请求
func (c *context) SetRequest(r *http.Request) {
	c.request = r
}

// Response 返回响应写入器
func (c *context) Response() ResponseWriter {
	return c.writermem
}

// SetResponse 设置响应写入器
func (c *context) SetResponse(r ResponseWriter) {
	// 设置响应写入器
	if rw, ok := r.(*responseWriter); ok {
		c.writermem = rw
	} else {
		c.writermem = NewResponseWriter(r)
	}
}

// IsTLS 返回是否是 TLS 连接
func (c *context) IsTLS() bool {
	return c.request != nil && c.request.TLS != nil
}

// IsWebsocket 返回是否是 WebSocket 连接
func (c *context) IsWebsocket() bool {
	if c.request == nil {
		return false
	}
	connection := strings.ToLower(c.RequestHeader("Connection"))
	upgrade := c.RequestHeader("Upgrade")
	return strings.Contains(connection, "upgrade") && strings.EqualFold(upgrade, "websocket")
}

// Scheme 返回 HTTP 协议方案
func (c *context) Scheme() string {
	if c.IsTLS() {
		return "https"
	}
	if scheme := c.RequestHeader("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if scheme := c.RequestHeader("X-Forwarded-Protocol"); scheme != "" {
		return scheme
	}
	if ssl := c.RequestHeader("X-Forwarded-Ssl"); ssl == "on" {
		return "https"
	}
	return "http"
}

// RealIP 返回客户端真实 IP
func (c *context) RealIP() string {
	return c.ClientIP()
}

// Path 返回请求路径
func (c *context) Path() string {
	return c.fullPath
}

// SetPath 设置请求路径
func (c *context) SetPath(p string) {
	c.fullPath = p
}

// FullPath 返回匹配的路由完整路径
func (c *context) FullPath() string {
	return c.fullPath
}

/************************************/
/********** PARAM METHODS ***********/
/************************************/
// Param 返回 URL 参数值
func (c *context) Param(key string) string {
	return c.params.ByName(key)
}

// ParamGet 返回 URL 参数值和是否存在
func (c *context) ParamGet(name string) (string, bool) {
	return c.params.Get(name)
}

// Params 返回所有参数
func (c *context) Params() Params {
	if c.params == nil {
		return Params{}
	}
	return c.params.Copy()
}

// ParamNames 返回参数名称列表
func (c *context) ParamNames() []string {
	if c.params == nil {
		return []string{}
	}
	names := make([]string, 0, len(*c.params))
	for _, p := range *c.params {
		names = append(names, p.Key)
	}
	return names
}

// SetParamNames 设置参数名称
func (c *context) SetParamNames(names ...string) {
	if c.params == nil {
		params := make(Params, 0, len(names))
		c.params = &params
	}
	*c.params = (*c.params)[:0]
	for _, name := range names {
		*c.params = append(*c.params, Param{Key: name})
	}
}

// ParamValues 返回参数值列表
func (c *context) ParamValues() []string {
	if c.params == nil {
		return []string{}
	}
	values := make([]string, 0, len(*c.params))
	for _, p := range *c.params {
		values = append(values, p.Value)
	}
	return values
}

// SetParamValues 设置参数值
func (c *context) SetParamValues(values ...string) {
	if c.params == nil {
		params := make(Params, 0, len(values))
		c.params = &params
	}
	for i, value := range values {
		if i < len(*c.params) {
			(*c.params)[i].Value = value
		}
	}
}

// AddParam 添加参数
func (c *context) AddParam(key, value string) {
	if c.params == nil {
		params := make(Params, 0, 1)
		c.params = &params
	}
	*c.params = append(*c.params, Param{Key: key, Value: value})
}

/************************************/
/********** QUERY METHODS ***********/
/************************************/
// initQueryCache 初始化查询缓存
func (c *context) initQueryCache() {
	if c.queryCache == nil {
		if c.request != nil {
			c.queryCache = c.request.URL.Query()
		} else {
			c.queryCache = url.Values{}
		}
	}
}

// QueryParams 返回查询参数
func (c *context) QueryParams() url.Values {
	c.initQueryCache()
	return c.queryCache
}

// QueryString 返回查询字符串
func (c *context) QueryString() string {
	if c.request != nil {
		return c.request.URL.RawQuery
	}
	return ""
}

// Query 返回指定键的查询值
func (c *context) Query(key string) (value string) {
	value, _ = c.GetQuery(key)
	return
}

// DefaultQuery 返回指定键的查询值，不存在则返回默认值
func (c *context) DefaultQuery(key, defaultValue string) string {
	if value, ok := c.GetQuery(key); ok {
		return value
	}
	return defaultValue
}

// GetQuery 返回指定键的查询值和是否存在
func (c *context) GetQuery(key string) (string, bool) {
	if values, ok := c.GetQueryArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// QueryArray 返回指定键的查询值数组
func (c *context) QueryArray(key string) (values []string) {
	values, _ = c.GetQueryArray(key)
	return
}

// GetQueryArray 返回指定键的查询值数组和是否存在
func (c *context) GetQueryArray(key string) (values []string, ok bool) {
	c.initQueryCache()
	values, ok = c.queryCache[key]
	return
}

// QueryMap 返回指定键的查询映射
func (c *context) QueryMap(key string) (dicts map[string]string) {
	dicts, _ = c.GetQueryMap(key)
	return
}

// GetQueryMap 返回指定键的查询映射和是否存在
func (c *context) GetQueryMap(key string) (map[string]string, bool) {
	c.initQueryCache()
	return c.get(c.queryCache, key)
}

// initFormCache 初始化表单缓存
func (c *context) initFormCache() {
	if c.formCache == nil {
		c.formCache = make(url.Values)
		if c.request != nil {
			if err := c.request.ParseMultipartForm(c.engine.MaxMultipartMemory); err != nil {
				if !errors.Is(err, http.ErrNotMultipart) {
					debugPrint("error on parse multipart form array: %v", err)
				}
			}
			c.formCache = c.request.PostForm
		}
	}
}

// FormValue 返回指定键的表单值
func (c *context) FormValue(key string) string {
	return c.PostForm(key)
}

// FormParams 返回表单参数
func (c *context) FormParams() (url.Values, error) {
	c.initFormCache()
	return c.formCache, nil
}

// PostForm 返回指定键的 POST 表单值
func (c *context) PostForm(key string) (value string) {
	value, _ = c.GetPostForm(key)
	return
}

// DefaultPostForm 返回指定键的 POST 表单值，不存在则返回默认值
func (c *context) DefaultPostForm(key, defaultValue string) string {
	if value, ok := c.GetPostForm(key); ok {
		return value
	}
	return defaultValue
}

// GetPostForm 返回指定键的 POST 表单值和是否存在
func (c *context) GetPostForm(key string) (string, bool) {
	if values, ok := c.GetPostFormArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// PostFormArray 返回指定键的 POST 表单值数组
func (c *context) PostFormArray(key string) (values []string) {
	values, _ = c.GetPostFormArray(key)
	return
}

// GetPostFormArray 返回指定键的 POST 表单值数组和是否存在
func (c *context) GetPostFormArray(key string) (values []string, ok bool) {
	c.initFormCache()
	values, ok = c.formCache[key]
	return
}

// PostFormMap 返回指定键的 POST 表单映射
func (c *context) PostFormMap(key string) (dicts map[string]string) {
	dicts, _ = c.GetPostFormMap(key)
	return
}

// GetPostFormMap 返回指定键的 POST 表单映射和是否存在
func (c *context) GetPostFormMap(key string) (map[string]string, bool) {
	c.initFormCache()
	return c.get(c.formCache, key)
}

// get 内部方法，返回满足条件的映射
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

// FormFile 返回指定键的上传文件
func (c *context) FormFile(name string) (*multipart.FileHeader, error) {
	if c.request == nil {
		return nil, ErrNilRequest
	}
	if c.request.MultipartForm == nil {
		if err := c.request.ParseMultipartForm(c.engine.MaxMultipartMemory); err != nil {
			return nil, err
		}
	}
	f, fh, err := c.request.FormFile(name)
	if err != nil {
		return nil, err
	}
	f.Close()
	return fh, err
}

// MultipartForm 返回解析的多部分表单
func (c *context) MultipartForm() (*multipart.Form, error) {
	if c.request == nil {
		return nil, ErrNilRequest
	}
	err := c.request.ParseMultipartForm(c.engine.MaxMultipartMemory)
	return c.request.MultipartForm, err
}

// SaveUploadedFile 保存上传的文件
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

/************************************/
/********* COOKIE METHODS ***********/
/************************************/
// SetSameSite 设置 SameSite cookie 属性
func (c *context) SetSameSite(samesite http.SameSite) {
	c.sameSite = samesite
}

// SetCookie 添加 Set-Cookie 头
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

// Cookie 返回指定名称的 cookie
func (c *context) Cookie(name string) (*http.Cookie, error) {
	if c.request == nil {
		return nil, ErrNilRequest
	}
	return c.request.Cookie(name)
}

// Cookies 返回所有 cookies
func (c *context) Cookies() []*http.Cookie {
	if c.request == nil {
		return []*http.Cookie{}
	}
	return c.request.Cookies()
}

// Set 存储键值对
func (c *context) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Keys == nil {
		c.Keys = make(map[string]any)
	}
	c.Keys[key] = value
}

// Get 返回指定键的值
func (c *context) Get(key string) (value any, exists bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists = c.Keys[key]
	return
}

// MustGet 返回指定键的值，不存在则 panic
func (c *context) MustGet(key string) any {
	if value, exists := c.Get(key); exists {
		return value
	}
	panic(fmt.Sprintf("Key \"%s\" does not exist", key))
}

// 泛型获取方法，减少重复代码
func getValue[T any](c *context, key string) (t T) {
	if val, ok := c.Get(key); ok && val != nil {
		t, _ = val.(T)
	}
	return
}

// GetString 返回字符串值
func (c *context) GetString(key string) string {
	return getValue[string](c, key)
}

// GetBool 返回布尔值
func (c *context) GetBool(key string) bool {
	return getValue[bool](c, key)
}

// GetInt 返回整数值
func (c *context) GetInt(key string) int {
	return getValue[int](c, key)
}

// GetInt64 返回 int64 值
func (c *context) GetInt64(key string) int64 {
	return getValue[int64](c, key)
}

// GetUint 返回无符号整数值
func (c *context) GetUint(key string) uint {
	return getValue[uint](c, key)
}

// GetUint64 返回 uint64 值
func (c *context) GetUint64(key string) uint64 {
	return getValue[uint64](c, key)
}

// GetFloat64 返回 float64 值
func (c *context) GetFloat64(key string) float64 {
	return getValue[float64](c, key)
}

// GetTime 返回时间值
func (c *context) GetTime(key string) time.Time {
	return getValue[time.Time](c, key)
}

// GetDuration 返回持续时间值
func (c *context) GetDuration(key string) time.Duration {
	return getValue[time.Duration](c, key)
}

// GetStringSlice 返回字符串切片值
func (c *context) GetStringSlice(key string) []string {
	return getValue[[]string](c, key)
}

// GetStringMap 返回字符串映射值
func (c *context) GetStringMap(key string) map[string]any {
	return getValue[map[string]any](c, key)
}

// GetStringMapString 返回字符串到字符串的映射值
func (c *context) GetStringMapString(key string) map[string]string {
	return getValue[map[string]string](c, key)
}

// GetStringMapStringSlice 返回字符串到字符串切片的映射值
func (c *context) GetStringMapStringSlice(key string) map[string][]string {
	return getValue[map[string][]string](c, key)
}

/************************************/
/********** FLOW CONTROL ************/
/************************************/

// Next 执行链中的下一个处理器
func (c *context) Next() {
	c.index++
	for c.index < int8(len(c.handlers)) {
		c.handlers[c.index](c)
		c.index++
	}
}

// IsAborted 返回是否已中止
func (c *context) IsAborted() bool {
	return c.index >= abortIndex
}

// Abort 中止后续处理器
func (c *context) Abort() {
	c.index = abortIndex
}

// AbortWithStatus 中止并设置状态码
func (c *context) AbortWithStatus(code int) {
	c.Status(code)
	c.Response().WriteHeaderNow()
	c.Abort()
}

// AbortWithStatusJSON 中止并返回 JSON
func (c *context) AbortWithStatusJSON(code int, jsonObj any) {
	c.Abort()
	c.JSON(code, jsonObj)
}

// AbortWithError 中止并添加错误
func (c *context) AbortWithError(code int, err error) *Error {
	c.AbortWithStatus(code)
	return c.Error(err)
}

/************************************/
/******** ERROR MANAGEMENT **********/
/************************************/

// Error 添加错误到错误列表，在最后统一处理所有收集到的错误(不过这与统一error处理方式不同)
// 例如 if len(c.Errors) > 0 { c.JSON(http.StatusInternalServerError, gin.H{"errors": c.Errors}) }
func (c *context) Error(err error) *Error {
	if err == nil {
		panic(ErrNilParam)
	}

	var parsedError *Error
	if !errors.As(err, &parsedError) {
		parsedError = &Error{
			Err:  err,
			Type: ErrorTypePrivate,
		}
	}

	c.errors = append(c.errors, parsedError)
	return parsedError
}

// Errors 返回错误列表
func (c *context) Errors() errorMsgs {
	return c.errors
}

/************************************/
/********* BINDING METHODS **********/
/************************************/

// 绑定辅助方法
func (c *context) bindWith(obj any, b binding.Binding, must bool) error {
	if must {
		return c.MustBindWith(obj, b)
	}
	return c.ShouldBindWith(obj, b)
}

// Bind 自动选择绑定引擎
func (c *context) Bind(obj any) error {
	b := binding.Default(c.Request().Method, c.ContentType())
	return c.MustBindWith(obj, b)
}

// ShouldBind 自动选择绑定引擎（不中止）
func (c *context) ShouldBind(obj any) error {
	b := binding.Default(c.Request().Method, c.ContentType())
	return c.ShouldBindWith(obj, b)
}

// MustBindWith 使用指定绑定引擎（错误时中止）
func (c *context) MustBindWith(obj any, b binding.Binding) error {
	if err := c.ShouldBindWith(obj, b); err != nil {
		c.AbortWithError(http.StatusBadRequest, err).SetType(ErrorTypeBind)
		return err
	}
	return nil
}

// ShouldBindWith 使用指定绑定引擎
func (c *context) ShouldBindWith(obj any, b binding.Binding) error {
	return b.Bind(c.Request(), obj)
}

// 各种绑定方法的简化实现
func (c *context) BindJSON(obj any) error         { return c.bindWith(obj, binding.JSON, true) }
func (c *context) BindXML(obj any) error          { return c.bindWith(obj, binding.XML, true) }
func (c *context) BindQuery(obj any) error        { return c.bindWith(obj, binding.Query, true) }
func (c *context) BindYAML(obj any) error         { return c.bindWith(obj, binding.YAML, true) }
func (c *context) BindTOML(obj any) error         { return c.bindWith(obj, binding.TOML, true) }
func (c *context) BindHeader(obj any) error       { return c.bindWith(obj, binding.Header, true) }
func (c *context) ShouldBindJSON(obj any) error   { return c.bindWith(obj, binding.JSON, false) }
func (c *context) ShouldBindXML(obj any) error    { return c.bindWith(obj, binding.XML, false) }
func (c *context) ShouldBindQuery(obj any) error  { return c.bindWith(obj, binding.Query, false) }
func (c *context) ShouldBindYAML(obj any) error   { return c.bindWith(obj, binding.YAML, false) }
func (c *context) ShouldBindTOML(obj any) error   { return c.bindWith(obj, binding.TOML, false) }
func (c *context) ShouldBindHeader(obj any) error { return c.bindWith(obj, binding.Header, false) }

// BindUri 绑定 URI 参数
func (c *context) BindUri(obj any) error {
	if err := c.ShouldBindUri(obj); err != nil {
		c.AbortWithError(http.StatusBadRequest, err).SetType(ErrorTypeBind)
		return err
	}
	return nil
}

// ShouldBindUri 绑定 URI 参数（不中止）
func (c *context) ShouldBindUri(obj any) error {
	m := make(map[string][]string)
	for _, v := range *c.params {
		m[v.Key] = []string{v.Value}
	}
	return binding.Uri.BindUri(m, obj)
}

// ShouldBindBodyWith 绑定请求体（带缓存）
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

// Validate 验证数据
func (c *context) Validate(i interface{}) error {
	if c.engine != nil && c.engine.Validator != nil {
		return c.engine.Validator.Validate(i)
	}
	return ErrValidatorNotRegistered
}

/************************************/
/********* RESPONSE METHODS *********/
/************************************/

// Status 设置响应状态码
func (c *context) Status(code int) {
	c.Response().WriteHeader(code)
}

// Header 设置响应头
func (c *context) Header(key, value string) {
	if value == "" {
		c.Response().Header().Del(key)
		return
	}
	c.Response().Header().Set(key, value)
}

// GetHeader 获取请求头
func (c *context) GetHeader(key string) string {
	return c.RequestHeader(key)
}

// RequestHeader 获取请求头
func (c *context) RequestHeader(key string) string {
	if c.request == nil {
		return ""
	}
	return c.request.Header.Get(key)
}

// GetRawData 获取原始请求数据
func (c *context) GetRawData() ([]byte, error) {
	if c.request == nil {
		return nil, ErrNilRequest
	}
	return io.ReadAll(c.request.Body)
}

// ContentType 返回 Content-Type
func (c *context) ContentType() string {
	return filterFlags(c.RequestHeader("Content-Type"))
}

// Render 渲染响应
func (c *context) Render(code int, r render.Render) {
	c.Status(code)

	if !bodyAllowedForStatus(code) {
		r.WriteContentType(c.Response())
		c.Response().WriteHeaderNow()
		return
	}

	if err := r.Render(c.Response()); err != nil {
		_ = c.Error(err)
		c.Abort()
	}
}

// 各种渲染方法
func (c *context) JSON(code int, obj any) {
	c.Render(code, render.JSON{Data: obj})
}

func (c *context) IndentedJSON(code int, obj any) {
	c.Render(code, render.IndentedJSON{Data: obj})
}

func (c *context) SecureJSON(code int, obj any) {
	c.Render(code, render.SecureJSON{Prefix: c.engine.secureJSONPrefix, Data: obj})
}

func (c *context) JSONP(code int, obj any) {
	callback := c.DefaultQuery("callback", "")
	if callback == "" {
		c.Render(code, render.JSON{Data: obj})
		return
	}
	c.Render(code, render.JsonpJSON{Callback: callback, Data: obj})
}

func (c *context) AsciiJSON(code int, obj any) {
	c.Render(code, render.AsciiJSON{Data: obj})
}

func (c *context) PureJSON(code int, obj any) {
	c.Render(code, render.PureJSON{Data: obj})
}

func (c *context) XML(code int, obj any) {
	c.Render(code, render.XML{Data: obj})
}

func (c *context) YAML(code int, obj any) {
	c.Render(code, render.YAML{Data: obj})
}

func (c *context) TOML(code int, obj any) {
	c.Render(code, render.TOML{Data: obj})
}

func (c *context) ProtoBuf(code int, obj any) {
	c.Render(code, render.ProtoBuf{Data: obj})
}

func (c *context) String(code int, format string, values ...any) {
	c.Render(code, render.String{Format: format, Data: values})
}

func (c *context) Redirect(code int, location string) {
	c.Render(-1, render.Redirect{
		Code:     code,
		Location: location,
		Request:  c.Request(),
	})
}

func (c *context) Data(code int, contentType string, data []byte) {
	c.Render(code, render.Data{
		ContentType: contentType,
		Data:        data,
	})
}

func (c *context) DataFromReader(code int, contentLength int64, contentType string, reader io.Reader, extraHeaders map[string]string) {
	c.Render(code, render.Reader{
		Headers:       extraHeaders,
		ContentType:   contentType,
		ContentLength: contentLength,
		Reader:        reader,
	})
}

// HTMLBlob 渲染 HTML 字节
func (c *context) HTMLBlob(code int, b []byte) error {
	c.Data(code, "text/html; charset=utf-8", b)
	return nil
}

// JSONBlob 渲染 JSON 字节
func (c *context) JSONBlob(code int, b []byte) error {
	c.Data(code, "application/json; charset=utf-8", b)
	return nil
}

// JSONPBlob 渲染 JSONP 字节
func (c *context) JSONPBlob(code int, callback string, b []byte) error {
	c.Status(code)
	c.Header("Content-Type", "application/javascript; charset=utf-8")
	if _, err := c.Response().Write([]byte(callback + "(")); err != nil {
		return err
	}
	if _, err := c.Response().Write(b); err != nil {
		return err
	}
	_, err := c.Response().Write([]byte(");"))
	return err
}

// XMLBlob 渲染 XML 字节
func (c *context) XMLBlob(code int, b []byte) error {
	c.Data(code, "application/xml; charset=utf-8", b)
	return nil
}

// Blob 渲染二进制数据
func (c *context) Blob(code int, contentType string, b []byte) error {
	c.Data(code, contentType, b)
	return nil
}

// NoContent 返回无内容响应
func (c *context) NoContent(code int) {
	c.Status(code)
}

// Attachment 发送响应作为附件
func (c *context) Attachment(file string, name string) error {
	c.FileAttachment(file, name)
	return nil
}

// Inline 发送响应作为内联
func (c *context) Inline(file string, name string) error {
	c.Response().Header().Set("Content-Disposition", `inline; filename="`+name+`"`)
	http.ServeFile(c.Response(), c.Request(), file)
	return nil
}

// SSEvent 发送 Server-Sent Event
func (c *context) SSEvent(name string, message any) {
	c.Render(-1, sse.Event{
		Event: name,
		Data:  message,
	})
}

// Stream 发送流式响应
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
/******* CONTENT NEGOTIATION ********/
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

// NegotiateFormat 返回可接受的格式
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

// SetAccepted 设置接受的格式
func (c *context) SetAccepted(formats ...string) {
	c.Accepted = formats
}

/************************************/
/********* CLIENT IP METHODS ********/
/************************************/

// ClientIP 返回客户端 IP
func (c *context) ClientIP() string {
	if c.engine != nil && c.engine.TrustedPlatform != "" {
		if addr := c.RequestHeader(c.engine.TrustedPlatform); addr != "" {
			return addr
		}
	}

	if c.engine != nil && c.engine.AppEngine {
		log.Println(`The AppEngine flag is going to be deprecated. Please check issues #2723 and #2739 and use 'TrustedPlatform: gin.PlatformGoogleAppEngine' instead.`)
		if addr := c.RequestHeader("X-Appengine-Remote-Addr"); addr != "" {
			return addr
		}
	}

	remoteIP := net.ParseIP(c.RemoteIP())
	if remoteIP == nil {
		return ""
	}

	if c.engine != nil {
		trusted := c.engine.isTrustedProxy(remoteIP)
		if trusted && c.engine.ForwardedByClientIP && c.engine.RemoteIPHeaders != nil {
			for _, headerName := range c.engine.RemoteIPHeaders {
				ip, valid := c.engine.validateHeader(c.RequestHeader(headerName))
				if valid {
					return ip
				}
			}
		}
	}

	return remoteIP.String()
}

// RemoteIP 解析并返回远程 IP
func (c *context) RemoteIP() string {
	if c.request == nil {
		return ""
	}
	ip, _, err := net.SplitHostPort(strings.TrimSpace(c.request.RemoteAddr))
	if err != nil {
		return ""
	}
	return ip
}

/************************************/
/********* CONTEXT METHODS **********/
/************************************/

// hasRequestContext 检查是否有请求上下文
func (c *context) hasRequestContext() bool {
	hasFallback := c.engine != nil && c.engine.ContextWithFallback
	hasRequestContext := c.request != nil && c.request.Context() != nil
	return hasFallback && hasRequestContext
}

// Deadline 返回截止时间
func (c *context) Deadline() (deadline time.Time, ok bool) {
	if !c.hasRequestContext() {
		return
	}
	return c.request.Context().Deadline()
}

// Done 返回完成通道
func (c *context) Done() <-chan struct{} {
	if !c.hasRequestContext() {
		return nil
	}
	return c.request.Context().Done()
}

// Err 返回错误
func (c *context) Err() error {
	if !c.hasRequestContext() {
		return nil
	}
	return c.request.Context().Err()
}

// Value 返回上下文值
func (c *context) Value(key any) any {
	if key == 0 {
		return c.request
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
	return c.request.Context().Value(key)
}

/************************************/
/********* HANDLER METHODS **********/
/************************************/

// Handlers 返回处理器链
func (c *context) Handlers() HandlersChain {
	return c.handlers
}

// SetHandlers 设置处理器链
func (c *context) SetHandlers(handlers HandlersChain) {
	c.handlers = handlers
}

// SetHandler 设置单个处理器
func (c *context) SetHandler(h HandlerFunc) {
	c.handlers = HandlersChain{h}
}

// HandlerName 返回主处理器名称
func (c *context) HandlerName() string {
	return nameOfFunction(c.handlers.Last())
}

// HandlerNames 返回所有处理器名称
func (c *context) HandlerNames() []string {
	hn := make([]string, 0, len(c.handlers))
	for _, val := range c.handlers {
		hn = append(hn, nameOfFunction(val))
	}
	return hn
}

/************************************/
/********* HELPER FUNCTIONS *********/
/************************************/

// bodyAllowedForStatus 检查状态码是否允许响应体
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
