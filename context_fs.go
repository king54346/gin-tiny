package ginTiny

import (
	"net/http"
	"net/url"
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
	f.Close()

	fileServer.ServeHTTP(c.Response(), c.Request())
}

//func (c *context) FileFromFS(file string, filesystem fs.FS) error {
//	return fsFile(c, file, filesystem)
//}
//
//func fsFile(c Context, file string, filesystem fs.FS) error {
//	f, err := filesystem.Open(file)
//	if err != nil {
//		return ErrNotFound
//	}
//	defer f.Close()
//
//	fi, _ := f.Stat()
//	if fi.IsDir() {
//		file = filepath.ToSlash(filepath.Join(file, "index.html")) // ToSlash is necessary for Windows. fs.Open and os.Open are different in that aspect.
//		f, err = filesystem.Open(file)
//		if err != nil {
//			return ErrNotFound
//		}
//		defer f.Close()
//		if fi, err = f.Stat(); err != nil {
//			return err
//		}
//	}
//	ff, ok := f.(io.ReadSeeker)
//	if !ok {
//		return errors.New("file does not implement io.ReadSeeker")
//	}
//	http.ServeContent(c.Response(), c.Request(), fi.Name(), fi.ModTime(), ff)
//	return nil
//}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// FileAttachment writes the specified file into the body stream in an efficient way
// On the client side, the file will typically be downloaded with the given filename
func (c *context) FileAttachment(filepath, filename string) {
	if isASCII(filename) {
		c.Response().Header().Set("Content-Disposition", `attachment; filename="`+escapeQuotes(filename)+`"`)
	} else {
		c.Response().Header().Set("Content-Disposition", `attachment; filename*=UTF-8''`+url.QueryEscape(filename))
	}
	http.ServeFile(c.Response(), c.Request(), filepath)
}
