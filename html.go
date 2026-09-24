package ginTiny

import (
	"html/template"
	"io/fs"
	"strings"

	"github.com/king54346/gin-tiny/render"
)

// 模板相关方法都应在启动阶段、开始处理请求之前调用：HTMLRender 在请求期间只读，运行中替换没有加锁保护

// Delims 设置模板分隔符，需在 LoadHTML* 之前调用
func (engine *Engine) Delims(left, right string) *Engine {
	engine.delims = render.Delims{Left: left, Right: right}
	return engine
}

// SetFuncMap 设置模板函数，需在 LoadHTML* 之前调用
func (engine *Engine) SetFuncMap(funcMap template.FuncMap) {
	engine.FuncMap = funcMap
}

// LoadHTMLGlob 加载匹配 glob 模式的模板文件。debug 模式下每次渲染都重新解析，修改模板无需重启
func (engine *Engine) LoadHTMLGlob(pattern string) {
	templ := template.Must(engine.newTemplate().ParseGlob(pattern))
	if IsDebugging() {
		debugPrintLoadTemplate(templ)
		engine.HTMLRender = render.HTMLDebug{Glob: pattern, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}
	engine.SetHTMLTemplate(templ)
}

// LoadHTMLFiles 加载指定的模板文件。debug 模式下每次渲染都重新解析
func (engine *Engine) LoadHTMLFiles(files ...string) {
	templ := template.Must(engine.newTemplate().ParseFiles(files...))
	if IsDebugging() {
		debugPrintLoadTemplate(templ)
		engine.HTMLRender = render.HTMLDebug{Files: files, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}
	engine.SetHTMLTemplate(templ)
}

// LoadHTMLFS 从 fs.FS 加载匹配 patterns 的模板，可直接传入 embed.FS，或用 os.DirFS("templates") 读取本地目录。
// 与上游 gin 接收 http.FileSystem 不同：fs.FS 是标准库文件系统抽象，也与 template.ParseFS 的参数一致
func (engine *Engine) LoadHTMLFS(fsys fs.FS, patterns ...string) {
	templ := template.Must(engine.newTemplate().ParseFS(fsys, patterns...))
	if IsDebugging() {
		debugPrintLoadTemplate(templ)
		engine.HTMLRender = render.HTMLDebug{FS: fsys, Patterns: patterns, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}
	engine.SetHTMLTemplate(templ)
}

// SetHTMLTemplate 直接使用已解析好的模板
func (engine *Engine) SetHTMLTemplate(templ *template.Template) {
	engine.HTMLRender = render.HTMLProduction{Template: templ.Funcs(engine.FuncMap)}
}

func (engine *Engine) newTemplate() *template.Template {
	return template.New("").Delims(engine.delims.Left, engine.delims.Right).Funcs(engine.FuncMap)
}

func debugPrintLoadTemplate(templ *template.Template) {
	if !IsDebugging() {
		return
	}
	var names []string
	for _, t := range templ.Templates() {
		if t.Name() != "" {
			names = append(names, t.Name())
		}
	}
	debugPrint("Loaded HTML Templates (%d): %s\n", len(names), strings.Join(names, ", "))
}
