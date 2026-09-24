// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"net/http"
	"path"
	"regexp"
	"strings"
)

var (
	// regEnLetter matches english letters for http method name
	regEnLetter = regexp.MustCompile("^[A-Z]+$")
)

// IRouter 定义所有路由handle接口包括单个和组路由
// 使用例如 router.Group()...
type IRouter interface {
	IRoutes
	Group(string, ...HandlerFunc) *RouterGroup
}

// IRoutes defines all router handle interface.
type IRoutes interface {
	Use(...HandlerFunc) IRoutes

	Handle(string, string, ...HandlerFunc) IRoutes
	Any(string, ...HandlerFunc) IRoutes
	GET(string, ...HandlerFunc) IRoutes
	POST(string, ...HandlerFunc) IRoutes
	DELETE(string, ...HandlerFunc) IRoutes
	PATCH(string, ...HandlerFunc) IRoutes
	PUT(string, ...HandlerFunc) IRoutes
	OPTIONS(string, ...HandlerFunc) IRoutes
	HEAD(string, ...HandlerFunc) IRoutes
	Match([]string, string, ...HandlerFunc) IRoutes
}

// RouterGroup 用于配置路由器，RouterGroup与前缀和处理程序（中间件）数组相关联。
// 实现路由分组功能
type RouterGroup struct {
	Handlers HandlersChain
	basePath string
	engine   *Engine
	root     bool
}

var _ IRouter = (*RouterGroup)(nil)

// Use adds middleware to the group, see example code in GitHub.
func (group *RouterGroup) Use(middleware ...HandlerFunc) IRoutes {
	group.Handlers = append(group.Handlers, middleware...)
	return group.returnObj()
}

// Group creates a new router group. You should add all the routes that have common middlewares or the same path prefix.
// For example, all the routes that use a common middleware for authorization could be grouped.
func (group *RouterGroup) Group(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	return &RouterGroup{
		Handlers: group.combineHandlers(handlers),
		basePath: group.calculateAbsolutePath(relativePath),
		engine:   group.engine,
	}
}

// BasePath 返回当前路由组的基础路径
// 例如，如果 v := router.Group("/rest/n/v1/api")，则 v.BasePath() 返回 "/rest/n/v1/api"。
func (group *RouterGroup) BasePath() string {
	return group.basePath
}

// handle 计算绝对路径、合并组中间件后把路由注册到 radix 树
func (group *RouterGroup) handle(httpMethod, relativePath string, handlers HandlersChain) IRoutes {
	// 计算绝对路径
	absolutePath := group.calculateAbsolutePath(relativePath)
	// 合并handlers
	handlers = group.combineHandlers(handlers)
	group.engine.addRoute(httpMethod, absolutePath, handlers)
	return group.returnObj()
}

// Handle 方法用于注册一个新的请求处理器和中间件，指定路径和 HTTP 方法
func (group *RouterGroup) Handle(httpMethod, relativePath string, handlers ...HandlerFunc) IRoutes {
	if !regEnLetter.MatchString(httpMethod) {
		panic("http method " + httpMethod + " is not valid")
	}
	return group.handle(httpMethod, relativePath, handlers)
}

// POST 是一个快捷方式，用于注册 POST 请求的处理函数。
func (group *RouterGroup) POST(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodPost, relativePath, handlers)
}

// GET 是一个快捷方式，用于注册 GET 请求的处理函数。
func (group *RouterGroup) GET(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodGet, relativePath, handlers)
}

// HandleWithError 注册返回 error 的处理函数，错误统一交给 Engine.HTTPErrorHandler 处理。
// 多个处理函数按顺序执行，任意一个返回 error 或调用了 Abort() 都会终止后续执行。
func (group *RouterGroup) HandleWithError(httpMethod, relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	if !regEnLetter.MatchString(httpMethod) {
		panic("http method " + httpMethod + " is not valid")
	}
	return group.handle(httpMethod, relativePath, group.wrap(handlers))
}

// GETWithError 是 HandleWithError(GET, ...) 的快捷方式
func (group *RouterGroup) GETWithError(relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	return group.handle(http.MethodGet, relativePath, group.wrap(handlers))
}

// POSTWithError 是 HandleWithError(POST, ...) 的快捷方式
func (group *RouterGroup) POSTWithError(relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	return group.handle(http.MethodPost, relativePath, group.wrap(handlers))
}

// PUTWithError 是 HandleWithError(PUT, ...) 的快捷方式
func (group *RouterGroup) PUTWithError(relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	return group.handle(http.MethodPut, relativePath, group.wrap(handlers))
}

// PATCHWithError 是 HandleWithError(PATCH, ...) 的快捷方式
func (group *RouterGroup) PATCHWithError(relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	return group.handle(http.MethodPatch, relativePath, group.wrap(handlers))
}

// DELETEWithError 是 HandleWithError(DELETE, ...) 的快捷方式
func (group *RouterGroup) DELETEWithError(relativePath string, handlers ...HandlerFuncReturnError) IRoutes {
	return group.handle(http.MethodDelete, relativePath, group.wrap(handlers))
}

// wrap 把一组返回 error 的处理函数合并成一个 HandlerFunc，
// 这样在 handlersChain 中只占一个位置，错误在这里被统一拦截。
func (group *RouterGroup) wrap(handlers []HandlerFuncReturnError) HandlersChain {
	assert1(len(handlers) > 0, "there must be at least one handler")
	engine := group.engine
	return HandlersChain{func(c Context) {
		for _, h := range handlers {
			if err := h(c); err != nil {
				engine.HTTPErrorHandler(err, c)
				return
			}
			if c.IsAborted() {
				return
			}
		}
	}}
}

// DELETE is a shortcut for router.Handle("DELETE", path, handlers).
func (group *RouterGroup) DELETE(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodDelete, relativePath, handlers)
}

// PATCH is a shortcut for router.Handle("PATCH", path, handlers).
func (group *RouterGroup) PATCH(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodPatch, relativePath, handlers)
}

// PUT is a shortcut for router.Handle("PUT", path, handlers).
func (group *RouterGroup) PUT(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodPut, relativePath, handlers)
}

// OPTIONS is a shortcut for router.Handle("OPTIONS", path, handlers).
func (group *RouterGroup) OPTIONS(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodOptions, relativePath, handlers)
}

// HEAD is a shortcut for router.Handle("HEAD", path, handlers).
func (group *RouterGroup) HEAD(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.handle(http.MethodHead, relativePath, handlers)
}

func (group *RouterGroup) Any(relativePath string, handlers ...HandlerFunc) IRoutes {
	for _, method := range anyMethods {
		group.handle(method, relativePath, handlers)
	}

	return group.returnObj()
}

// StaticRouter 注册一个支持所有 HTTP 方法的静态路由，等价于 Any，但要求路径不含通配符。
func (group *RouterGroup) StaticRouter(relativePath string, handlers ...HandlerFunc) IRoutes {
	return group.StaticMatch(anyMethods, relativePath, handlers...)
}

// StaticMatch 为多个方法注册静态路由，等价于 Match，但要求路径不含通配符。
//
// 所有不含 :param / *catchAll 的路由（包括 GET/POST 等普通注册方式）都会自动进入
// map 索引走 O(1) 精确匹配，同时保留在 radix 树中负责冲突检测、重定向和 405。
// 这里的通配符检查只是让「我以为它是静态路由」的错误在启动时就暴露出来
func (group *RouterGroup) StaticMatch(methods []string, relativePath string, handlers ...HandlerFunc) IRoutes {
	if !isStaticPath(relativePath) {
		panic("URL parameters can not be used in a static route: " + relativePath)
	}
	return group.Match(methods, relativePath, handlers...)
}

// Match registers a route that matches the specified methods that you declared.
// 给定的相对路径注册多个HTTP方法。
// 例如r.Match([]string{"GET", "POST"}, "/data", myHandlerFunc)
func (group *RouterGroup) Match(methods []string, relativePath string, handlers ...HandlerFunc) IRoutes {
	for _, method := range methods {
		group.handle(method, relativePath, handlers)
	}

	return group.returnObj()
}

// StaticFile 注册一个静态文件处理器，允许直接访问指定的文件。
func (group *RouterGroup) StaticFile(relativePath, filepath string) IRoutes {
	return group.staticFileHandler(relativePath, func(c Context) {
		c.File(filepath)
	})
}

// StaticFileFS 工作方式与 `StaticFile` 类似，但可以使用自定义的 `http.FileSystem`。
// 例如：router.StaticFileFS("favicon.ico", "./resources/favicon.ico", Dir{".", false})
// 这允许你使用内存中的文件、嵌入的文件或其他实现了 `http.FileSystem` 接口的资源。
func (group *RouterGroup) StaticFileFS(relativePath, filepath string, fs http.FileSystem) IRoutes {
	return group.staticFileHandler(relativePath, func(c Context) {
		c.FileFromFS(filepath, fs)
	})
}

func (group *RouterGroup) staticFileHandler(relativePath string, handler HandlerFunc) IRoutes {
	if !isStaticPath(relativePath) {
		panic("URL parameters can not be used when serving a static file")
	}
	group.handle(http.MethodGet, relativePath, HandlersChain{handler})
	group.handle(http.MethodHead, relativePath, HandlersChain{handler})
	return group.returnObj()
}

// Static serves files from the given file system root.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use :
//
//	router.Static("/static", "/var/www")
func (group *RouterGroup) Static(relativePath, root string) IRoutes {
	return group.StaticFS(relativePath, Dir(root, false))
}

// StaticFS 不是为一个物理目录服务，而是为 http.FileSystem 接口提供服务。这是一个更灵活的方法，允许你为内存中的文件、嵌入的文件或其他实现了 http.FileSystem 接口的资源提供服务
func (group *RouterGroup) StaticFS(relativePath string, fs http.FileSystem) IRoutes {
	if strings.Contains(relativePath, ":") || strings.Contains(relativePath, "*") {
		panic("URL parameters can not be used when serving a static folder")
	}
	handler := group.createStaticHandler(relativePath, fs)
	urlPattern := path.Join(relativePath, "/*filepath")

	// Register GET and HEAD handlers
	group.GET(urlPattern, handler)
	group.HEAD(urlPattern, handler)
	return group.returnObj()
}

// 创建一个处理静态文件请求的处理函数（HandlerFunc）
// 处理文件访问权限和文件存在性检查
// 在文件不存在或无权限访问时提供优雅的错误处理
func (group *RouterGroup) createStaticHandler(relativePath string, fs http.FileSystem) HandlerFunc {
	absolutePath := group.calculateAbsolutePath(relativePath)
	fileServer := http.StripPrefix(absolutePath, http.FileServer(fs))

	return func(c Context) {
		if _, noListing := fs.(*onlyFilesFS); noListing {
			c.Response().WriteHeader(http.StatusNotFound)
		}
		c.ServeStaticFile(fs, fileServer)
	}
}
func (group *RouterGroup) combineHandlers(handlers HandlersChain) HandlersChain {
	finalSize := len(group.Handlers) + len(handlers)
	assert1(finalSize < int(abortIndex), "too many handlers")
	mergedHandlers := make(HandlersChain, finalSize)
	copy(mergedHandlers, group.Handlers)
	copy(mergedHandlers[len(group.Handlers):], handlers)
	return mergedHandlers
}

func (group *RouterGroup) calculateAbsolutePath(relativePath string) string {
	return joinPaths(group.basePath, relativePath)
}

func (group *RouterGroup) returnObj() IRoutes {
	if group.root {
		return group.engine
	}
	return group
}
