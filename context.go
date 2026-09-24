package ginTiny

import (
	stdctx "context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"maps"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/king54346/gin-tiny/binding"
	"github.com/king54346/gin-tiny/render"
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
	// （与上游 gin 保持一致，仍是字符串常量）
	ContextKey = "_gin-gonic/gin/contextkey"
)

// ContextKeyType 是框架内部使用的 context key 类型。
// 使用独立类型而不是字面量 0：Keys 支持任意类型的 key 后，用户 c.Set(0, x) 不会与之冲突
type ContextKeyType int

// ContextRequestKey 通过 c.Value(ContextRequestKey) 取得当前的 *http.Request
const ContextRequestKey ContextKeyType = 0

// abortIndex represents a typical value used in abort functions.
const abortIndex int8 = math.MaxInt8 >> 1

// 预定义错误
var (
	ErrNilRequest             = errors.New("request is nil")
	ErrNilParam               = errors.New("parameter is nil")
	ErrKeyNotFound            = errors.New("key not found")
	ErrValidatorNotRegistered = errors.New("validator not registered")
)

// Context 是处理函数拿到的请求上下文。
// 具体实现为非导出的 *context，这样框架可以在不破坏用户代码的前提下调整内部字段；
// 所有对外能力都必须出现在这个接口里，否则用户通过 Context 调用不到。
//
// Context 由下面按职责划分的小接口组合而成。编写辅助函数或中间件时，
// 参数只声明实际需要的那部分（例如 func currentUser(kv KeyValueStore)），
// 依赖更清晰，测试时也只需 mock 少量方法。
type Context interface {
	stdctx.Context // Deadline / Done / Err / Value，均基于 Request().Context()

	RequestReader
	PathParams
	QueryReader
	FormReader
	CookieAccessor
	KeyValueStore
	Binder
	Renderer
	FileResponder
	FlowController

	// Reset 重置为初始状态，由框架在复用 context 时调用
	Reset()
	// Copy 返回可以安全地在 goroutine 中使用的只读副本
	Copy() Context
}

// RequestReader 读取请求信息，以及读写底层的 Request / ResponseWriter
type RequestReader interface {
	Request() *http.Request
	SetRequest(r *http.Request)
	Response() ResponseWriter
	SetResponse(r ResponseWriter)
	IsTLS() bool
	IsWebsocket() bool
	Scheme() string
	ClientIP() string
	RealIP() string // 等价于 ClientIP
	RemoteIP() string
	ContentType() string
	RequestHeader(key string) string
	GetHeader(key string) string // 等价于 RequestHeader
	GetRawData() ([]byte, error)
}

// PathParams 读写路由匹配得到的路径参数
type PathParams interface {
	FullPath() string
	Path() string // 等价于 FullPath
	SetPath(p string)
	Param(name string) string
	ParamGet(name string) (string, bool)
	Params() Params
	ParamNames() []string
	SetParamNames(names ...string)
	ParamValues() []string
	SetParamValues(values ...string)
	AddParam(key, value string)
}

// QueryReader 读取 URL 查询参数
type QueryReader interface {
	QueryParams() url.Values
	QueryString() string
	Query(key string) string
	DefaultQuery(key, defaultValue string) string
	GetQuery(key string) (string, bool)
	QueryArray(key string) []string
	GetQueryArray(key string) ([]string, bool)
	QueryMap(key string) map[string]string
	GetQueryMap(key string) (map[string]string, bool)
}

// FormReader 读取表单与上传文件
type FormReader interface {
	PostForm(key string) string
	FormValue(name string) string // 等价于 PostForm
	FormParams() (url.Values, error)
	DefaultPostForm(key, defaultValue string) string
	GetPostForm(key string) (string, bool)
	PostFormArray(key string) []string
	GetPostFormArray(key string) ([]string, bool)
	PostFormMap(key string) map[string]string
	GetPostFormMap(key string) (map[string]string, bool)
	FormFile(name string) (*multipart.FileHeader, error)
	MultipartForm() (*multipart.Form, error)
	SaveUploadedFile(file *multipart.FileHeader, dst string, perm ...fs.FileMode) error
}

// CookieAccessor 读写 Cookie
type CookieAccessor interface {
	Cookie(name string) (*http.Cookie, error)
	Cookies() []*http.Cookie
	SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)
	SetCookieData(cookie *http.Cookie)
	SetSameSite(samesite http.SameSite)
}

// KeyValueStore 请求级别的键值存储，并发安全。
// 类型化读取推荐使用泛型函数 GetAs / MustGetAs，GetString 等方法为兼容 gin 保留
type KeyValueStore interface {
	Set(key any, val any)
	Get(key any) (value any, exists bool)
	MustGet(key any) any
	Delete(key any)
	// Keys 返回所有键值对的快照（副本）
	Keys() map[any]any
	GetString(key any) string
	GetBool(key any) bool
	GetInt(key any) int
	GetInt64(key any) int64
	GetUint(key any) uint
	GetUint64(key any) uint64
	GetFloat64(key any) float64
	GetTime(key any) time.Time
	GetDuration(key any) time.Duration
	GetStringSlice(key any) []string
	GetStringMap(key any) map[string]any
	GetStringMapString(key any) map[string]string
	GetStringMapStringSlice(key any) map[string][]string
}

// Binder 把请求数据绑定到结构体并校验。
// Bind* 失败时以 400 中止请求；ShouldBind* 只返回错误，由调用方决定如何响应
type Binder interface {
	Bind(obj any) error
	BindJSON(obj any) error
	BindXML(obj any) error
	BindQuery(obj any) error
	BindYAML(obj any) error
	BindTOML(obj any) error
	BindPlain(obj any) error
	BindHeader(obj any) error
	BindUri(obj any) error
	MustBindWith(obj any, b binding.Binding) error
	ShouldBind(obj any) error
	ShouldBindJSON(obj any) error
	ShouldBindXML(obj any) error
	ShouldBindQuery(obj any) error
	ShouldBindYAML(obj any) error
	ShouldBindTOML(obj any) error
	ShouldBindPlain(obj any) error // 绑定到 *string 或 *[]byte
	ShouldBindHeader(obj any) error
	ShouldBindUri(obj any) error
	ShouldBindWith(obj any, b binding.Binding) error
	ShouldBindBodyWith(obj any, bb binding.BindingBody) error
	Validate(i any) error
}

// Renderer 设置状态码和响应头，并以各种格式写出响应体
type Renderer interface {
	Status(code int)
	Header(key, value string)
	Render(code int, r render.Render)
	String(code int, format string, values ...any)
	JSON(code int, obj any)
	IndentedJSON(code int, obj any)
	SecureJSON(code int, obj any)
	JSONP(code int, obj any)
	AsciiJSON(code int, obj any)
	PureJSON(code int, obj any)
	XML(code int, obj any)
	YAML(code int, obj any)
	TOML(code int, obj any)
	ProtoBuf(code int, obj any)
	HTML(code int, name string, obj any)
	Data(code int, contentType string, data []byte)
	DataFromReader(code int, contentLength int64, contentType string, reader io.Reader, extraHeaders map[string]string)
	Blob(code int, contentType string, b []byte) error // 等价于 Data
	HTMLBlob(code int, b []byte) error                 // 等价于 Data(code, "text/html; charset=utf-8", b)
	JSONBlob(code int, b []byte) error                 // 等价于 Data(code, "application/json; charset=utf-8", b)
	XMLBlob(code int, b []byte) error                  // 等价于 Data(code, "application/xml; charset=utf-8", b)
	JSONPBlob(code int, callback string, b []byte) error
	NoContent(code int)
	Redirect(code int, location string)
	SSEvent(name string, message any)
	Stream(step func(w io.Writer) bool) bool
	Negotiate(code int, config Negotiate)
	NegotiateFormat(offered ...string) string
	SetAccepted(formats ...string)
}

// FileResponder 以文件内容作为响应
type FileResponder interface {
	File(filepath string)
	FileFromFS(filepath string, fs http.FileSystem)
	FileAttachment(filepath, filename string)
	Attachment(file string, name string) error // 等价于 FileAttachment
	Inline(file string, name string) error
	ServeStaticFile(fs http.FileSystem, fileServer http.Handler)
}

// FlowController 控制处理链的执行，并收集处理过程中的错误
type FlowController interface {
	Next()
	Abort()
	IsAborted() bool
	AbortWithStatus(code int)
	AbortWithStatusJSON(code int, jsonObj any)
	AbortWithStatusPureJSON(code int, jsonObj any)
	AbortWithError(code int, err error) *Error
	Error(err error) *Error
	Errors() errorMsgs
	Handlers() HandlersChain
	SetHandlers(handlers HandlersChain)
	SetHandler(h HandlerFunc)
	Handler() HandlerFunc // 主处理函数（处理链的最后一个）
	HandlerName() string
	HandlerNames() []string
}

var _ Context = (*context)(nil)

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
	keys map[any]any

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
	c.keys = nil
	// 和 responseWriter.reset 一样先 clear，避免底层数组继续引用上个请求的 *Error
	clear(c.errors)
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
//
// 副本的请求 context 通过 context.WithoutCancel 与原请求脱钩：保留其中的值，但不继承取消和截止时间。
// handler 返回后 net/http 会取消原请求的 context，若副本继承取消信号，
// 在 goroutine 中用副本发起的异步调用会被立即中断
func (c *context) Copy() Context {
	cp := context{
		request: c.request,
		engine:  c.engine,
	}
	if c.request != nil {
		cp.request = c.request.WithContext(stdctx.WithoutCancel(c.request.Context()))
	}

	// 深拷贝 writermem。before/after 回调切片也要独立一份，
	// 否则副本 append 时可能写进原切片底层数组的空闲容量，与原请求互相覆盖
	if c.writermem != nil {
		w := *c.writermem
		w.beforeFuncs = slices.Clone(w.beforeFuncs)
		w.afterFuncs = slices.Clone(w.afterFuncs)
		cp.writermem = &w
	}

	// 副本没有处理链，对它调用 Next() 不会执行任何 handler；初始为未中止状态，
	// 这样 IsAborted() 能如实反映副本上是否调用过 Abort()（timeout 中间件依赖这一点）
	cp.index = -1
	cp.handlers = nil
	cp.fullPath = c.fullPath

	// 深拷贝 Keys
	c.mu.RLock()
	cp.keys = maps.Clone(c.keys)
	c.mu.RUnlock()

	// 深拷贝 params
	if c.params != nil {
		newParams := slices.Clone(*c.params)
		cp.params = &newParams
	}

	// 深拷贝 errors
	cp.errors = slices.Clone(c.errors)

	// skippedNodes 是路由匹配时的临时缓冲区，副本必须独立一份，
	// 否则在 goroutine 中对副本调用 HandleContext 会和原请求竞争同一块内存
	var skipped []skippedNode
	if c.skippedNodes != nil {
		skipped = make([]skippedNode, 0, cap(*c.skippedNodes))
	}
	cp.skippedNodes = &skipped
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
	// 与 ClientIP 一致：只采信可信代理转发的头，否则客户端可以伪造 X-Forwarded-Proto: https
	if c.fromTrustedProxy() {
		if scheme := c.RequestHeader("X-Forwarded-Proto"); scheme != "" {
			return scheme
		}
		if scheme := c.RequestHeader("X-Forwarded-Protocol"); scheme != "" {
			return scheme
		}
		if ssl := c.RequestHeader("X-Forwarded-Ssl"); ssl == "on" {
			return "https"
		}
	}
	return "http"
}

// fromTrustedProxy 判断请求的直接来源是否为 Engine.SetTrustedProxies 配置的可信代理（默认信任全部）
func (c *context) fromTrustedProxy() bool {
	if c.engine == nil {
		return true
	}
	ip, err := parseAddr(c.RemoteIP())
	return err == nil && c.engine.isTrustedProxy(ip)
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
	if key == "" {
		return dicts, false
	}
	exist := false
	prefix := key + "["
	for k, v := range m {
		// 形如 key[sub]=value 的参数；手工构造的 url.Values 可能出现空切片
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok || len(v) == 0 {
			continue
		}
		if sub, _, found := strings.Cut(rest, "]"); found && sub != "" {
			exist = true
			dicts[sub] = v[0]
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

// SaveUploadedFile 保存上传的文件。perm 可选，指定新建文件的权限（默认 0o666，受 umask 影响，与 os.Create 相同）；
// 所需目录按 0o750 创建，已存在的目录权限不变。
// 与上游 gin 不同：上游的 perm 作用于目录，并且每次都会 chmod 父目录，保存到 /tmp/x 这类路径时会改掉 /tmp 的权限
func (c *context) SaveUploadedFile(file *multipart.FileHeader, dst string, perm ...fs.FileMode) (err error) {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	if err = os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}

	mode := fs.FileMode(0o666)
	if len(perm) > 0 {
		mode = perm[0]
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	// 写入的数据可能在 Close 时才真正落盘，关闭失败（如磁盘已满）必须作为错误返回
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()

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

// SetCookie 添加 Set-Cookie 头。value 会经过 url.QueryEscape 编码，Cookie/Cookies 读取时自动解码
func (c *context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	c.SetCookieData(&http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// SetCookieData 以完整的 http.Cookie 设置 Cookie，可以使用 Expires、Partitioned 等 SetCookie 参数无法表达的属性。
// 与 SetCookie 一致：Value 经过 url.QueryEscape 编码；Path 为空时默认为 "/"；
// SameSite 未设置时使用 SetSameSite 配置的值。传入的 cookie 不会被修改
func (c *context) SetCookieData(cookie *http.Cookie) {
	ck := *cookie
	ck.Value = url.QueryEscape(ck.Value)
	if ck.Path == "" {
		ck.Path = "/"
	}
	// SameSite 的零值 0 表示未设置（http.SameSiteDefaultMode 是 1，属于显式设置）
	if ck.SameSite == 0 {
		ck.SameSite = c.sameSite
	}
	http.SetCookie(c.Response(), &ck)
}

// Cookie 返回指定名称的 cookie，Value 已做 URL 解码，与 SetCookie 写入的原值一致。
// 需要原始未解码的值时使用 c.Request().Cookie(name)
func (c *context) Cookie(name string) (*http.Cookie, error) {
	if c.request == nil {
		return nil, ErrNilRequest
	}
	ck, err := c.request.Cookie(name)
	if err != nil {
		return nil, err
	}
	decodeCookieValue(ck)
	return ck, nil
}

// Cookies 返回所有 cookie，Value 已做 URL 解码
func (c *context) Cookies() []*http.Cookie {
	if c.request == nil {
		return []*http.Cookie{}
	}
	cookies := c.request.Cookies()
	for _, ck := range cookies {
		decodeCookieValue(ck)
	}
	return cookies
}

// decodeCookieValue 对 SetCookie 编码过的值做 URL 解码；不是合法编码的值保持原样。
// http.Request.Cookie 每次都返回新的 *http.Cookie，原地修改不影响请求本身
func decodeCookieValue(ck *http.Cookie) {
	if v, err := url.QueryUnescape(ck.Value); err == nil {
		ck.Value = v
	}
}

// Set 存储键值对
func (c *context) Set(key any, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = make(map[any]any)
	}
	c.keys[key] = value
}

// Get 返回指定键的值
func (c *context) Get(key any) (value any, exists bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists = c.keys[key]
	return
}

// Delete 删除指定键
func (c *context) Delete(key any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.keys, key)
}

// Keys 返回所有键值对的快照。
// 返回副本而不是内部 map：遍历期间可以安全地调用 Set/Delete（持锁回调会死锁），修改副本也不影响 context
func (c *context) Keys() map[any]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return maps.Clone(c.keys)
}

// MustGet 返回指定键的值，不存在则 panic
func (c *context) MustGet(key any) any {
	if value, exists := c.Get(key); exists {
		return value
	}
	panic(fmt.Sprintf("Key %#v does not exist", key))
}

// GetAs 以泛型方式从 Context 的 Keys 中取值，key 不存在或类型不匹配时 ok 为 false
//
//	user, ok := ginTiny.GetAs[*User](c, "user")
func GetAs[T any](c Context, key any) (v T, ok bool) {
	val, exists := c.Get(key)
	if !exists {
		return v, false
	}
	v, ok = val.(T)
	return v, ok
}

// MustGetAs 与 GetAs 相同，但 key 不存在或类型不匹配时 panic
func MustGetAs[T any](c Context, key any) T {
	v, ok := GetAs[T](c, key)
	if !ok {
		panic(fmt.Sprintf("key %#v does not exist or is not of type %T", key, v))
	}
	return v
}

// ShouldBindAs 自动选择绑定器并返回绑定好的值，省去先声明变量再传指针
//
//	req, err := ginTiny.ShouldBindAs[LoginReq](c)
func ShouldBindAs[T any](c Context) (T, error) {
	var obj T
	err := c.ShouldBind(&obj)
	return obj, err
}

// getValue 是 GetString/GetInt 等方法的内部实现
func getValue[T any](c *context, key any) T {
	v, _ := GetAs[T](c, key)
	return v
}

// GetString 返回字符串值
func (c *context) GetString(key any) string {
	return getValue[string](c, key)
}

// GetBool 返回布尔值
func (c *context) GetBool(key any) bool {
	return getValue[bool](c, key)
}

// GetInt 返回整数值
func (c *context) GetInt(key any) int {
	return getValue[int](c, key)
}

// GetInt64 返回 int64 值
func (c *context) GetInt64(key any) int64 {
	return getValue[int64](c, key)
}

// GetUint 返回无符号整数值
func (c *context) GetUint(key any) uint {
	return getValue[uint](c, key)
}

// GetUint64 返回 uint64 值
func (c *context) GetUint64(key any) uint64 {
	return getValue[uint64](c, key)
}

// GetFloat64 返回 float64 值
func (c *context) GetFloat64(key any) float64 {
	return getValue[float64](c, key)
}

// GetTime 返回时间值
func (c *context) GetTime(key any) time.Time {
	return getValue[time.Time](c, key)
}

// GetDuration 返回持续时间值
func (c *context) GetDuration(key any) time.Duration {
	return getValue[time.Duration](c, key)
}

// GetStringSlice 返回字符串切片值
func (c *context) GetStringSlice(key any) []string {
	return getValue[[]string](c, key)
}

// GetStringMap 返回字符串映射值
func (c *context) GetStringMap(key any) map[string]any {
	return getValue[map[string]any](c, key)
}

// GetStringMapString 返回字符串到字符串的映射值
func (c *context) GetStringMapString(key any) map[string]string {
	return getValue[map[string]string](c, key)
}

// GetStringMapStringSlice 返回字符串到字符串切片的映射值
func (c *context) GetStringMapStringSlice(key any) map[string][]string {
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

// AbortWithStatusPureJSON 中止后续处理器，并以不转义 HTML 字符（<、>、&）的 JSON 响应
func (c *context) AbortWithStatusPureJSON(code int, jsonObj any) {
	c.Abort()
	c.PureJSON(code, jsonObj)
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

	parsedError, ok := asError(err)
	if !ok {
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
func (c *context) BindPlain(obj any) error        { return c.bindWith(obj, binding.Plain, true) }
func (c *context) BindHeader(obj any) error       { return c.bindWith(obj, binding.Header, true) }
func (c *context) ShouldBindJSON(obj any) error   { return c.bindWith(obj, binding.JSON, false) }
func (c *context) ShouldBindXML(obj any) error    { return c.bindWith(obj, binding.XML, false) }
func (c *context) ShouldBindQuery(obj any) error  { return c.bindWith(obj, binding.Query, false) }
func (c *context) ShouldBindYAML(obj any) error   { return c.bindWith(obj, binding.YAML, false) }
func (c *context) ShouldBindTOML(obj any) error   { return c.bindWith(obj, binding.TOML, false) }
func (c *context) ShouldBindPlain(obj any) error  { return c.bindWith(obj, binding.Plain, false) }
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
	for _, v := range c.Params() {
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
func (c *context) Validate(i any) error {
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
		// 渲染失败且尚未写出任何内容（如 JSON 序列化失败、模板执行出错）时改为 500，
		// 否则客户端会收到调用方指定的状态码（通常是 200）加空响应体
		if !c.Response().Written() {
			c.Status(http.StatusInternalServerError)
		}
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

// HTML 渲染 name 指定的模板（模板需先通过 engine.LoadHTMLGlob 等方法加载）
func (c *context) HTML(code int, name string, obj any) {
	if c.engine == nil || c.engine.HTMLRender == nil {
		panic("ginTiny: HTML templates are not loaded, call LoadHTMLGlob / LoadHTMLFiles / LoadHTMLFS / SetHTMLTemplate first")
	}
	c.Render(code, c.engine.HTMLRender.Instance(name, obj))
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
	// callback 通常来自 query 参数，和 render.JsonpJSON 一样转义，防止 XSS
	if _, err := c.Response().Write([]byte(template.JSEscapeString(callback) + "(")); err != nil {
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
	c.Response().Header().Set("Content-Disposition", contentDisposition("inline", name))
	http.ServeFile(c.Response(), c.Request(), file)
	return nil
}

// SSEvent 发送 Server-Sent Event
func (c *context) SSEvent(name string, message any) {
	c.Render(-1, render.SSEvent{
		Event: name,
		Data:  message,
	})
}

// Stream 发送流式响应
func (c *context) Stream(step func(w io.Writer) bool) bool {
	w := c.Response()
	clientGone := c.Done()
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
			if mediaTypeMatch(accepted, offer) {
				return offer
			}
		}
	}
	return ""
}

// mediaTypeMatch 按 type/subtype 两段分别比较（RFC 9110 §12.5.1）：每段相等（忽略大小写）或任意一方为 *。
// 不能按字符前缀比较，否则 Accept: application/jso 会匹配到 application/json
func mediaTypeMatch(accepted, offered string) bool {
	aType, aSub, _ := strings.Cut(accepted, "/")
	oType, oSub, _ := strings.Cut(offered, "/")
	return mediaRangePartMatch(aType, oType) && mediaRangePartMatch(aSub, oSub)
}

func mediaRangePartMatch(a, b string) bool {
	return a == "*" || b == "*" || strings.EqualFold(a, b)
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

	// AppEngine 已废弃（见字段注释），这里只保留兼容逻辑，不再每个请求都打日志
	if c.engine != nil && c.engine.AppEngine {
		if addr := c.RequestHeader("X-Appengine-Remote-Addr"); addr != "" {
			return addr
		}
	}

	remoteIP, err := parseAddr(c.RemoteIP())
	if err != nil {
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

// requestContext 返回请求的 context；没有请求时（例如测试中手动构造）视为永不取消的空 context。
// Deadline/Done/Err/Value 全部基于它，客户端断开、服务端超时都能传递给把 c 当作 context.Context 的下游调用
func (c *context) requestContext() stdctx.Context {
	if c.request == nil {
		return stdctx.Background()
	}
	return c.request.Context()
}

// Deadline 返回请求 context 的截止时间
func (c *context) Deadline() (deadline time.Time, ok bool) {
	return c.requestContext().Deadline()
}

// Done 返回请求 context 的完成通道
func (c *context) Done() <-chan struct{} {
	return c.requestContext().Done()
}

// Err 返回请求 context 的错误
func (c *context) Err() error {
	return c.requestContext().Err()
}

// Value 依次查找：ContextRequestKey → *http.Request，ContextKey → 自身，Keys 中的值，最后是请求 context
func (c *context) Value(key any) any {
	if key == ContextRequestKey {
		return c.request
	}
	if key == ContextKey {
		return c
	}
	if val, exists := c.Get(key); exists {
		return val
	}
	return c.requestContext().Value(key)
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

// Handler 返回处理链中的主处理函数（最后一个）
func (c *context) Handler() HandlerFunc {
	return c.handlers.Last()
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
