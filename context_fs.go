package ginTiny

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// File writes the specified file into the body stream in an efficient way.
// 文件写入指定的文件到 body 流中，以有效的方式。
func (c *context) File(filepath string) {
	http.ServeFile(c.Response(), c.Request(), filepath)
}

// FileFromFS 写入指定的文件从 http.FileSystem 到 body 流中，以有效的方式。
func (c *context) FileFromFS(filepath string, fs http.FileSystem) {
	defer func(old string) {
		c.Request().URL.Path = old
	}(c.Request().URL.Path)

	c.Request().URL.Path = filepath
	// 委托 http.FileServer 来处理文件系统
	http.FileServer(fs).ServeHTTP(c.Response(), c.Request())
}

// ServeStaticFile 服务静态文件请求
// 检查文件是否存在以及是否有权限访问
// 如果文件不存在或无访问权限，则返回404并重置处理链
func (c *context) ServeStaticFile(fs http.FileSystem, fileServer http.Handler) {
	file := c.Param("filepath")
	// 检查文件是否存在及是否有权限访问
	f, err := fs.Open(file)
	if err != nil {
		c.Response().WriteHeader(http.StatusNotFound)

		c.handlers = c.engine.noRoute
		// 重置索引
		c.index = -1
		return
	}
	defer f.Close()

	// 普通文件直接复用已打开的句柄，避免 FileServer 再打开一次；
	// 目录（index.html、目录列表）、以 / 结尾或名为 index.html 的请求涉及 FileServer 的重定向规则，仍交给它处理
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() &&
		!strings.HasSuffix(file, "/") && path.Base(file) != "index.html" {
		http.ServeContent(c.Response(), c.Request(), fi.Name(), fi.ModTime(), f)
		return
	}
	fileServer.ServeHTTP(c.Response(), c.Request())
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// FileAttachment writes the specified file into the body stream in an efficient way
// On the client side, the file will typically be downloaded with the given filename
func (c *context) FileAttachment(filepath, filename string) {
	c.Response().Header().Set("Content-Disposition", contentDisposition("attachment", filename))
	http.ServeFile(c.Response(), c.Request(), filepath)
}

// contentDisposition 生成 Content-Disposition 头，dispositionType 为 attachment 或 inline。
// ASCII 文件名转义引号后直接放入 filename，非 ASCII 使用 RFC 5987 的 filename* 编码
func contentDisposition(dispositionType, filename string) string {
	if isASCII(filename) {
		return dispositionType + `; filename="` + escapeQuotes(filename) + `"`
	}
	return dispositionType + `; filename*=UTF-8''` + url.QueryEscape(filename)
}
