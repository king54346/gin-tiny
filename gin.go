package ginTiny

import (
	stdctx "context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/king54346/gin-tiny/internal/bytesconv"
	"github.com/king54346/gin-tiny/render"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	defaultMultipartMemory = 32 << 20 // 32 MB
	defaultShutdownTimeout = 10 * time.Second
)

var (
	default404Body = []byte("404 page not found")
	default405Body = []byte("405 method not allowed")
)

var defaultPlatform string

// defaultTrustedCIDRs 默认信任所有代理（0.0.0.0/0 和 ::/0）
var defaultTrustedCIDRs = []netip.Prefix{
	netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	netip.PrefixFrom(netip.IPv6Unspecified(), 0),
}

var regSafePrefix = regexp.MustCompile("[^a-zA-Z0-9/-]+")
var regRemoveRepeatedChar = regexp.MustCompile("/{2,}")

// OptionFunc 用于配置 Engine，见 New / Default / Engine.With
type OptionFunc func(*Engine)

// HandlerFunc 定义中间件使用的处理函数类型
type HandlerFunc func(Context)

// HandlersChain defines a HandlerFunc slice.
type HandlersChain []HandlerFunc

// HandlerFuncReturnError 包装一个 HandlerFunc，使其可以统一的处理错误返回。
type HandlerFuncReturnError func(Context) error

// Last returns the last handler in the chain. i.e. the last handler is the main one.
func (c HandlersChain) Last() HandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

// RouteInfo represents a request route's specification which contains method and path and its handler.
type RouteInfo struct {
	Method      string
	Path        string
	Handler     string
	HandlerFunc HandlerFunc
}

// RoutesInfo defines a RouteInfo slice.
type RoutesInfo []RouteInfo

type Validator interface {
	Validate(i any) error
}

type HTTPErrorHandler func(err error, c Context)

// Trusted platforms
const (
	// PlatformGoogleAppEngine when running on Google App Engine. Trust X-Appengine-Remote-Addr
	// for determining the client's IP
	PlatformGoogleAppEngine = "X-Appengine-Remote-Addr"
	// PlatformCloudflare when using Cloudflare's CDN. Trust CF-Connecting-IP for determining
	// the client's IP
	PlatformCloudflare = "CF-Connecting-IP"
)

// Engine is the framework's instance, it contains the muxer, middleware and configuration settings.
// Create an instance of Engine, by using New() or Default()
type Engine struct {
	RouterGroup

	// RedirectTrailingSlash enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 307 for all other request methods.
	RedirectTrailingSlash bool

	// RedirectFixedPath if enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 307 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash is independent of this option.
	RedirectFixedPath bool

	// HandleMethodNotAllowed if enabled, the router checks if another method is allowed for the
	// current route, if the current request can not be routed.
	// If this is the case, the request is answered with 'Method Not Allowed'
	// and HTTP status code 405.
	// If no other Method is allowed, the request is delegated to the NotFound
	// handler.
	HandleMethodNotAllowed bool

	// ForwardedByClientIP if enabled, client IP will be parsed from the request's headers that
	// match those stored at `(*gin.Engine).RemoteIPHeaders`. If no IP was
	// fetched, it falls back to the IP obtained from
	// `(*gin.context).Request.RemoteAddr`.
	ForwardedByClientIP bool

	// AppEngine was deprecated.
	// Deprecated: USE `TrustedPlatform` WITH VALUE `gin.PlatformGoogleAppEngine` INSTEAD
	// #726 #755 If enabled, it will trust some headers starting with
	// 'X-AppEngine...' for better integration with that PaaS.
	AppEngine bool

	// UseRawPath if enabled, the url.RawPath will be used to find parameters.
	UseRawPath bool

	// UseEscapedPath 为 true 时使用 url.EscapedPath() 匹配路由，优先于 UseRawPath。
	// 与 UseRawPath 的区别：RawPath 只在请求的编码方式与默认编码不同时才被设置，EscapedPath() 总是返回转义后的路径，
	// 因此匹配行为稳定一致（如 /a%2Fb 不会被当作 /a/b）。注意此时注册的静态路由需使用转义后的形式
	UseEscapedPath bool

	// UnescapePathValues if true, the path value will be unescaped.
	// If UseRawPath is false (by default), the UnescapePathValues effectively is true,
	// as url.Path gonna be used, which is already unescaped.
	UnescapePathValues bool

	// RemoveExtraSlash a parameter can be parsed from the URL even with extra slashes.
	// See the PR #1817 and issue #1644
	RemoveExtraSlash bool

	// RemoteIPHeaders list of headers used to obtain the client IP when
	// `(*gin.Engine).ForwardedByClientIP` is `true` and
	// `(*gin.context).Request.RemoteAddr` is matched by at least one of the
	// network origins of list defined by `(*gin.Engine).SetTrustedProxies()`.
	RemoteIPHeaders []string

	// TrustedPlatform if set to a constant of value gin.Platform*, trusts the headers set by
	// that platform, for example to determine the client IP
	TrustedPlatform string

	// MaxMultipartMemory value of 'maxMemory' param that is given to http.Request's ParseMultipartForm
	// method call.
	MaxMultipartMemory int64

	// ShutdownTimeout 是 RunContext 等方法在 ctx 取消后等待进行中请求结束的最长时间，
	// 超时后强制关闭剩余连接。<= 0 表示一直等待。默认 10 秒。
	ShutdownTimeout time.Duration

	// UseH2C enable h2c support.
	// h2c 是否开启，http/2的变种，但是不像通常的HTTP/2那样通过TLS加密
	UseH2C bool

	// ContextWithFallback 已不再起作用：Context 的 Deadline/Done/Err/Value 始终基于 Request().Context()，
	// Copy() 得到的副本通过 context.WithoutCancel 脱离原请求的取消信号，可安全用于异步任务。
	//
	// Deprecated: 无需再设置，保留字段仅为兼容旧代码。
	ContextWithFallback bool

	secureJSONPrefix string

	allNoRoute       HandlersChain
	allNoMethod      HandlersChain
	noRoute          HandlersChain
	noMethod         HandlersChain
	pool             sync.Pool
	trees            *methodTrees
	maxParams        uint16
	maxSections      uint16
	trustedProxies   []string
	trustedCIDRs     []netip.Prefix
	Validator        Validator
	HTTPErrorHandler HTTPErrorHandler

	// HTMLRender 用于 c.HTML 渲染，由 LoadHTMLGlob / LoadHTMLFiles / LoadHTMLFS / SetHTMLTemplate 设置
	HTMLRender render.HTMLRender
	// FuncMap 模板函数，见 SetFuncMap
	FuncMap template.FuncMap
	delims  render.Delims
}

var _ IRouter = (*Engine)(nil)

// New returns a new blank Engine instance without any middleware attached.
// By default, the configuration is:
// - RedirectTrailingSlash:  true
// - RedirectFixedPath:      false
// - HandleMethodNotAllowed: false
// - ForwardedByClientIP:    true
// - UseRawPath:             false
// - UseEscapedPath:         false
// - UnescapePathValues:     true
func New(opts ...OptionFunc) *Engine {
	debugPrintWARNINGNew()
	engine := &Engine{
		RouterGroup: RouterGroup{
			Handlers: nil,
			basePath: "/",
			root:     true,
		},

		RedirectTrailingSlash:  true,
		RedirectFixedPath:      false,
		HandleMethodNotAllowed: false,
		ForwardedByClientIP:    true,
		RemoteIPHeaders:        []string{"X-Forwarded-For", "X-Real-IP"},
		TrustedPlatform:        defaultPlatform,
		UseRawPath:             false,
		RemoveExtraSlash:       false,
		UnescapePathValues:     true,
		MaxMultipartMemory:     defaultMultipartMemory,
		ShutdownTimeout:        defaultShutdownTimeout,
		trees:                  newMethodTrees(),
		secureJSONPrefix:       "while(1);",
		FuncMap:                template.FuncMap{},
		delims:                 render.Delims{Left: "{{", Right: "}}"},
		trustedProxies:         []string{"0.0.0.0/0", "::/0"},
		trustedCIDRs:           defaultTrustedCIDRs,
	}
	engine.RouterGroup.engine = engine
	engine.HTTPErrorHandler = engine.DefaultHTTPErrorHandler
	engine.pool.New = func() any {
		return engine.allocateContext(engine.maxParams)
	}
	return engine.With(opts...)
}

// Default returns an Engine instance with the Logger and Recovery middleware already attached.
// opts 在挂载 Logger / Recovery 之后应用
func Default(opts ...OptionFunc) *Engine {
	debugPrintWARNINGDefault()
	engine := New()
	//logger和recovery中间件
	engine.Use(Logger(), Recovery())
	return engine.With(opts...)
}

// With 依次应用选项函数并返回 engine 本身，便于链式调用：
//
//	r := gin.New(func(e *gin.Engine) { e.HandleMethodNotAllowed = true })
//	r.With(withTemplates, withTrustedProxies)
func (engine *Engine) With(opts ...OptionFunc) *Engine {
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func (engine *Engine) Handler() http.Handler {

	if !engine.UseH2C {
		return engine
	}

	h2s := &http2.Server{}
	return h2c.NewHandler(engine, h2s)
}

func (engine *Engine) allocateContext(maxParams uint16) *context {
	v := make(Params, 0, maxParams)
	skippedNodes := make([]skippedNode, 0, engine.maxSections)
	return &context{engine: engine, params: &v, skippedNodes: &skippedNodes, writermem: NewResponseWriter(nil)}
}

// SecureJsonPrefix sets the secureJSONPrefix used in context.SecureJSON.
func (engine *Engine) SecureJsonPrefix(prefix string) *Engine {
	engine.secureJSONPrefix = prefix
	return engine
}

// NoRoute adds handlers for NoRoute. It returns a 404 code by default.
func (engine *Engine) NoRoute(handlers ...HandlerFunc) {
	engine.noRoute = handlers
	engine.rebuild404Handlers()
}

// NoMethod sets the handlers called when Engine.HandleMethodNotAllowed = true.
func (engine *Engine) NoMethod(handlers ...HandlerFunc) {
	engine.noMethod = handlers
	engine.rebuild405Handlers()
}

// Use attaches a global middleware to the router. i.e. the middleware attached through Use() will be
// included in the handlers chain for every single request. Even 404, 405, static files...
// For example, this is the right place for a logger or error management middleware.
func (engine *Engine) Use(middleware ...HandlerFunc) IRoutes {
	engine.RouterGroup.Use(middleware...)
	engine.rebuild404Handlers()
	engine.rebuild405Handlers()
	return engine
}

func (engine *Engine) rebuild404Handlers() {
	engine.allNoRoute = engine.combineHandlers(engine.noRoute)
}

func (engine *Engine) rebuild405Handlers() {
	engine.allNoMethod = engine.combineHandlers(engine.noMethod)
}

// 添加路由
func (engine *Engine) addRoute(method, path string, handlers HandlersChain) {
	assert1(path[0] == '/', "path must begin with '/'")
	assert1(method != "", "HTTP method can not be empty")
	assert1(len(handlers) > 0, "there must be at least one handler")

	debugPrintRoute(method, path, handlers)

	// 树负责冲突检测和通配符校验，不含通配符的路由会同时写入该方法的静态索引（见 methodTree）
	engine.trees.getOrCreateTree(method).addRoute(path, handlers)

	// Update maxParams
	if paramsCount := countParams(path); paramsCount > engine.maxParams {
		engine.maxParams = paramsCount
	}

	if sectionsCount := countSections(path); sectionsCount > engine.maxSections {
		engine.maxSections = sectionsCount
	}
}

// Routes 用于获取引擎中所有已注册的路由信息，返回RoutesInfo
// 静态索引只是树的副本，遍历树即可得到全部路由
func (engine *Engine) Routes() (routes RoutesInfo) {
	for _, tree := range engine.trees.getNotNullMethodTree() {
		routes = iterate("", tree.method, routes, tree.root)
	}
	return routes
}

func iterate(path, method string, routes RoutesInfo, root *node) RoutesInfo {
	path += root.path
	if len(root.handlers) > 0 {
		handlerFunc := root.handlers.Last()
		routes = append(routes, RouteInfo{
			Method:      method,
			Path:        path,
			Handler:     nameOfFunction(handlerFunc),
			HandlerFunc: handlerFunc,
		})
	}
	for _, child := range root.children {
		routes = iterate(path, method, routes, child)
	}
	return routes
}

// Run attaches the router to a http.Server and starts listening and serving HTTP requests.
// It is a shortcut for RunContext(context.Background(), addr...).
// Note: this method will block the calling goroutine indefinitely unless an error happens.
func (engine *Engine) Run(addr ...string) error {
	return engine.RunContext(stdctx.Background(), addr...)
}

// RunContext 与 Run 相同，但在 ctx 取消后优雅关闭：停止接收新连接，等待进行中的请求处理完毕
// （最长 Engine.ShutdownTimeout），然后返回 nil。配合 signal.NotifyContext 使用：
//
//	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer stop()
//	if err := router.RunContext(ctx, ":8080"); err != nil {
//		log.Fatal(err)
//	}
func (engine *Engine) RunContext(ctx stdctx.Context, addr ...string) (err error) {
	defer func() { debugPrintError(err) }()

	address := resolveAddress(addr)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	debugPrint("Listening and serving HTTP on %s\n", listener.Addr())
	return engine.serve(ctx, listener, "", "")
}

func (engine *Engine) prepareTrustedCIDRs() ([]netip.Prefix, error) {
	if engine.trustedProxies == nil {
		return nil, nil
	}

	cidr := make([]netip.Prefix, 0, len(engine.trustedProxies))
	for _, trustedProxy := range engine.trustedProxies {
		if !strings.Contains(trustedProxy, "/") {
			ip, err := parseAddr(trustedProxy)
			if err != nil {
				return cidr, &net.ParseError{Type: "IP address", Text: trustedProxy}
			}
			cidr = append(cidr, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(trustedProxy)
		if err != nil {
			return cidr, &net.ParseError{Type: "CIDR address", Text: trustedProxy}
		}
		cidr = append(cidr, prefix.Masked())
	}
	return cidr, nil
}

// SetTrustedProxies set a list of network origins (IPv4 addresses,
// IPv4 CIDRs, IPv6 addresses or IPv6 CIDRs) from which to trust
// request's headers that contain alternative client IP when
// `(*gin.Engine).ForwardedByClientIP` is `true`. `TrustedProxies`
// feature is enabled by default, and it also trusts all proxies
// by default. If you want to disable this feature, use
// Engine.SetTrustedProxies(nil), then context.ClientIP() will
// return the remote address directly.
func (engine *Engine) SetTrustedProxies(trustedProxies []string) error {
	engine.trustedProxies = trustedProxies
	return engine.parseTrustedProxies()
}

// isUnsafeTrustedProxies checks if Engine.trustedCIDRs contains all IPs, it's not safe if it has (returns true)
func (engine *Engine) isUnsafeTrustedProxies() bool {
	return engine.isTrustedProxy(netip.IPv4Unspecified()) || engine.isTrustedProxy(netip.IPv6Unspecified())
}

// warnUnsafeTrustedProxies 在信任所有代理时打印警告
func (engine *Engine) warnUnsafeTrustedProxies() {
	if engine.isUnsafeTrustedProxies() {
		debugPrint("[WARNING] You trusted all proxies, this is NOT safe. We recommend you to set a value.\n" +
			"Please check https://pkg.go.dev/github.com/gin-gonic/gin#readme-don-t-trust-all-proxies for details.")
	}
}

// parseTrustedProxies parse Engine.trustedProxies to Engine.trustedCIDRs
func (engine *Engine) parseTrustedProxies() error {
	trustedCIDRs, err := engine.prepareTrustedCIDRs()
	engine.trustedCIDRs = trustedCIDRs
	return err
}

// isTrustedProxy will check whether the IP address is included in the trusted list according to Engine.trustedCIDRs
func (engine *Engine) isTrustedProxy(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap() // ::ffff:1.2.3.4 按 IPv4 处理
	for _, cidr := range engine.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// validateHeader will parse X-Forwarded-For header and return the trusted client IP address
func (engine *Engine) validateHeader(header string) (clientIP string, valid bool) {
	if header == "" {
		return "", false
	}
	// X-Forwarded-For 由代理逐级追加，从右往左检查，遇到第一个不受信任的地址即为客户端 IP
	// 用 LastIndexByte 从后向前切分，避免 strings.Split 的切片分配
	for header != "" {
		item := header
		if i := strings.LastIndexByte(header, ','); i >= 0 {
			item, header = header[i+1:], header[:i]
		} else {
			header = ""
		}
		ipStr := strings.TrimSpace(item)
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			break
		}
		if header == "" || !engine.isTrustedProxy(ip) {
			return ipStr, true
		}
	}
	return "", false
}

// parseAddr 解析 IP 字符串，IPv4-mapped IPv6 地址会被还原为 IPv4
func parseAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

// RunTLS attaches the router to a http.Server and starts listening and serving HTTPS (secure) requests.
// It is a shortcut for RunTLSContext(context.Background(), addr, certFile, keyFile).
// Note: this method will block the calling goroutine indefinitely unless an error happens.
func (engine *Engine) RunTLS(addr, certFile, keyFile string) error {
	return engine.RunTLSContext(stdctx.Background(), addr, certFile, keyFile)
}

// RunTLSContext 与 RunTLS 相同，但在 ctx 取消后优雅关闭，见 RunContext
func (engine *Engine) RunTLSContext(ctx stdctx.Context, addr, certFile, keyFile string) (err error) {
	defer func() { debugPrintError(err) }()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	debugPrint("Listening and serving HTTPS on %s\n", listener.Addr())
	return engine.serve(ctx, listener, certFile, keyFile)
}

// RunUnix attaches the router to a http.Server and starts listening and serving HTTP requests
// through the specified unix socket (i.e. a file).
// Note: this method will block the calling goroutine indefinitely unless an error happens.
// 需要优雅关闭时，可自行 net.Listen("unix", file) 后调用 RunListenerContext。
func (engine *Engine) RunUnix(file string) (err error) {
	debugPrint("Listening and serving HTTP on unix:/%s", file)
	defer func() { debugPrintError(err) }()

	listener, err := net.Listen("unix", file)
	if err != nil {
		return
	}
	defer os.Remove(file)

	return engine.serve(stdctx.Background(), listener, "", "")
}

// RunFd attaches the router to a http.Server and starts listening and serving HTTP requests
// through the specified file descriptor.
// Note: this method will block the calling goroutine indefinitely unless an error happens.
func (engine *Engine) RunFd(fd int) (err error) {
	debugPrint("Listening and serving HTTP on fd@%d", fd)
	defer func() { debugPrintError(err) }()

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd@%d", fd))
	listener, err := net.FileListener(f)
	if err != nil {
		return
	}
	return engine.serve(stdctx.Background(), listener, "", "")
}

// RunListener attaches the router to a http.Server and starts listening and serving HTTP requests
// through the specified net.Listener
func (engine *Engine) RunListener(listener net.Listener) error {
	return engine.RunListenerContext(stdctx.Background(), listener)
}

// RunListenerContext 与 RunListener 相同，但在 ctx 取消后优雅关闭，见 RunContext
func (engine *Engine) RunListenerContext(ctx stdctx.Context, listener net.Listener) (err error) {
	debugPrint("Listening and serving HTTP on listener what's bind with address@%s", listener.Addr())
	defer func() { debugPrintError(err) }()

	return engine.serve(ctx, listener, "", "")
}

// serve 是所有 Run* 方法的公共实现。certFile/keyFile 非空时以 TLS 方式服务。
// listener 的所有权转交给 serve，返回时一定已被关闭。
//
// ctx 取消后调用 http.Server.Shutdown：先关闭 listener 不再接收新连接，再等待进行中的请求结束。
// 等待时间受 ShutdownTimeout 限制，超时后强制关闭剩余连接并返回超时错误；正常关闭返回 nil。
func (engine *Engine) serve(ctx stdctx.Context, listener net.Listener, certFile, keyFile string) error {
	engine.warnUnsafeTrustedProxies()

	srv := &http.Server{Handler: engine.Handler()}
	serveErr := make(chan error, 1)
	go func() {
		if certFile != "" || keyFile != "" {
			serveErr <- srv.ServeTLS(listener, certFile, keyFile)
			return
		}
		serveErr <- srv.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		// 未调用 Shutdown 就返回，说明服务本身出错（例如证书无效），ctx 此时没有被取消
		return err
	case <-ctx.Done():
	}

	// ctx 已取消，关闭流程必须使用不会被取消的 context，否则 Shutdown 会立刻放弃等待
	shutdownCtx := stdctx.WithoutCancel(ctx)
	if engine.ShutdownTimeout > 0 {
		var cancel stdctx.CancelFunc
		shutdownCtx, cancel = stdctx.WithTimeout(shutdownCtx, engine.ShutdownTimeout)
		defer cancel()
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("ginTiny: graceful shutdown did not finish: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ServeHTTP conforms to the http.Handler interface.
func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := engine.pool.Get().(*context)
	c.writermem.reset(w)
	c.request = req
	c.Reset()

	engine.handleHTTPRequest(c)

	engine.pool.Put(c)
}

// HandleContext 用于重新处理一个已经被重写（如 c.Request().URL.Path 被修改）的上下文。
// 它会重置上下文的状态，重新走一遍路由匹配，结束后恢复原来的 index。
func (engine *Engine) HandleContext(ctx Context) {
	c, ok := ctx.(*context)
	if !ok {
		panic("ginTiny: HandleContext only accepts Context created by ginTiny")
	}
	oldIndexValue := c.index
	c.Reset()
	engine.handleHTTPRequest(c)

	c.index = oldIndexValue
}

func (engine *Engine) handleHTTPRequest(c *context) {
	req := c.Request()
	httpMethod := req.Method
	rPath := req.URL.Path
	unescape := false
	if engine.UseEscapedPath {
		rPath = req.URL.EscapedPath()
		unescape = engine.UnescapePathValues
	} else if engine.UseRawPath && len(req.URL.RawPath) > 0 {
		rPath = req.URL.RawPath
		unescape = engine.UnescapePathValues
	}

	if engine.RemoveExtraSlash {
		rPath = cleanPath(rPath)
	}

	// 1. 查找路由：methodTree 内部先查静态索引，未命中再走 radix 树
	if tree := engine.trees.getTree(httpMethod); tree != nil {
		value := tree.getValue(rPath, c.params, c.skippedNodes, unescape)
		if value.params != nil {
			c.params = value.params
		}
		if value.handlers != nil {
			c.handlers = value.handlers
			c.fullPath = value.fullPath
			c.Next()
			c.writermem.WriteHeaderNow()
			return
		}
		// 2. 未命中：尾斜杠和大小写修正重定向，全部由树完成
		if httpMethod != http.MethodConnect && rPath != "/" {
			if value.tsr && engine.RedirectTrailingSlash {
				redirectTrailingSlash(c)
				return
			}
			// 处理固定路径重定向 例如将 /FOO 重定向到 /foo，或者处理多余斜杠如 //foo 重定向到 /foo
			if engine.RedirectFixedPath && redirectFixedPath(c, tree.root, engine.RedirectFixedPath) {
				return
			}
		}
	}

	// 3. 处理 405 Method Not Allowed
	if engine.HandleMethodNotAllowed {
		if allowed := engine.allowedMethods(c, rPath, httpMethod, unescape); len(allowed) > 0 {
			// RFC 9110 §15.5.6：405 响应必须带 Allow 头
			c.writermem.Header().Set("Allow", strings.Join(allowed, ", "))
			c.handlers = engine.allNoMethod
			serveError(c, http.StatusMethodNotAllowed, default405Body)
			return
		}
	}
	c.handlers = engine.allNoRoute
	serveError(c, http.StatusNotFound, default404Body)
}

// allowedMethods 返回该路径上注册过的其它 HTTP 方法，结果为空表示路径本身不存在，应当走 404
func (engine *Engine) allowedMethods(c *context, rPath, httpMethod string, unescape bool) []string {
	var allowed []string
	for _, tree := range engine.trees.getNotNullMethodTree() {
		if tree.method == httpMethod {
			continue
		}
		// skippedNodes 是回溯缓冲区，残留上一棵树的节点会让本次查找回溯到别的树上，
		// 导致把没注册的方法误判为允许，每次查找前必须清空
		*c.skippedNodes = (*c.skippedNodes)[:0]
		if value := tree.getValue(rPath, nil, c.skippedNodes, unescape); value.handlers != nil {
			allowed = append(allowed, tree.method)
		}
	}
	// 自定义方法存放在 map 中，遍历顺序随机；排序后 Allow 头的输出稳定
	slices.Sort(allowed)
	return allowed
}

var mimePlain = []string{MIMEPlain}

// serveError 是一个通用的错误处理函数，用于在处理请求时发生错误时返回相应的 HTTP 状态码和默认消息。
func serveError(c *context, code int, defaultMessage []byte) {
	c.writermem.status = code
	c.Next()
	if c.writermem.Written() {
		return
	}
	if c.writermem.Status() == code {
		c.writermem.Header()["Content-Type"] = mimePlain
		_, err := c.Response().Write(defaultMessage)
		if err != nil {
			debugPrint("cannot write message to writer during serve error: %v", err)
		}
		return
	}
	c.writermem.WriteHeaderNow()
}

func redirectTrailingSlash(c *context) {
	req := c.Request()
	p := req.URL.Path
	if prefix := path.Clean(c.Request().Header.Get("X-Forwarded-Prefix")); prefix != "." {
		prefix = regSafePrefix.ReplaceAllString(prefix, "")
		prefix = regRemoveRepeatedChar.ReplaceAllString(prefix, "/")

		p = prefix + "/" + req.URL.Path
	}
	req.URL.Path = p + "/"
	if length := len(p); length > 1 && p[length-1] == '/' {
		req.URL.Path = p[:length-1]
	}
	redirectRequest(c)
}

func redirectFixedPath(c *context, root *node, trailingSlash bool) bool {
	req := c.Request()
	rPath := req.URL.Path

	if fixedPath, ok := root.findCaseInsensitivePath(cleanPath(rPath), trailingSlash); ok {
		req.URL.Path = bytesconv.BytesToString(fixedPath)
		redirectRequest(c)
		return true
	}
	return false
}

func redirectRequest(c *context) {
	req := c.Request()
	rPath := req.URL.Path
	rURL := req.URL.String()

	code := http.StatusMovedPermanently // Permanent redirect, request with GET method
	if req.Method != http.MethodGet {
		code = http.StatusTemporaryRedirect
	}
	debugPrint("redirecting request %d: %s --> %s", code, rPath, rURL)
	http.Redirect(c.Response(), req, rURL, code)
	c.writermem.WriteHeaderNow()
}

// DefaultHTTPErrorHandler 是 *WithError 系列路由的默认错误处理器。
// *Error（可被 errors.Is/As 解包得到）视为请求参数错误返回 400，其它错误统一返回 500 且不暴露细节。
func (engine *Engine) DefaultHTTPErrorHandler(err error, c Context) {
	if c.Response().Written() {
		// 响应已经写出，无法再修改状态码，只记录错误
		_ = c.Error(err)
		c.Abort()
		return
	}

	if e, ok := asError(err); ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, H{
			"error":   "Invalid request parameters",
			"details": e.JSON(),
		})
		return
	}
	c.AbortWithStatusJSON(http.StatusInternalServerError, H{
		"error": "Internal server error",
	})
}
