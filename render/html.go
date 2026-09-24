package render

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
)

// Delims 模板的左右分隔符，默认 {{ 和 }}
type Delims struct {
	Left  string
	Right string
}

// HTMLRender 根据模板名和数据生成一次渲染
type HTMLRender interface {
	Instance(name string, data any) Render
}

// HTMLProduction 使用启动时解析好的模板（release / test 模式）
type HTMLProduction struct {
	Template *template.Template
	Delims   Delims
}

// HTMLDebug 每次渲染都重新解析模板（debug 模式），修改模板文件后无需重启服务
type HTMLDebug struct {
	Files    []string
	Glob     string
	FS       fs.FS
	Patterns []string
	Delims   Delims
	FuncMap  template.FuncMap
}

// HTML 渲染一个模板。Name 为空时执行根模板，否则执行同名的子模板
type HTML struct {
	Template *template.Template
	Name     string
	Data     any
}

var htmlContentType = []string{"text/html; charset=utf-8"}

// Instance (HTMLProduction) returns an HTML instance which it realizes Render interface.
func (r HTMLProduction) Instance(name string, data any) Render {
	return HTML{Template: r.Template, Name: name, Data: data}
}

// Instance (HTMLDebug) returns an HTML instance which it realizes Render interface.
func (r HTMLDebug) Instance(name string, data any) Render {
	return HTML{Template: r.loadTemplate(), Name: name, Data: data}
}

func (r HTMLDebug) loadTemplate() *template.Template {
	t := template.New("").Delims(r.Delims.Left, r.Delims.Right).Funcs(r.FuncMap)
	switch {
	case len(r.Files) > 0:
		return template.Must(t.ParseFiles(r.Files...))
	case r.Glob != "":
		return template.Must(t.ParseGlob(r.Glob))
	case r.FS != nil && len(r.Patterns) > 0:
		return template.Must(t.ParseFS(r.FS, r.Patterns...))
	}
	panic("the HTML debug render was created without files or glob pattern or file system with patterns")
}

// Render (HTML) executes template and writes its result with custom ContentType for response.
// 先渲染到缓冲区，成功后再写出：模板执行到一半出错时，客户端不会收到被截断的页面，
// 调用方也还来得及把状态码改成 500
func (r HTML) Render(w http.ResponseWriter) error {
	var buf bytes.Buffer
	var err error
	if r.Name == "" {
		err = r.Template.Execute(&buf, r.Data)
	} else {
		err = r.Template.ExecuteTemplate(&buf, r.Name, r.Data)
	}
	if err != nil {
		return err
	}
	r.WriteContentType(w)
	_, err = w.Write(buf.Bytes())
	return err
}

// WriteContentType (HTML) writes HTML ContentType.
func (r HTML) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, htmlContentType)
}
