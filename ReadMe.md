RESTful风格
GET用来获取资源的信息。
POST用来创建新的资源。
DELETE用来删除已存在的资源。
PATCH用来对已存在资源进行部分更新。
PUT表示完整地替换资源,用新内容完全覆盖旧资源
RESTful API 拥有清楚又简短的 URI，可读性非常强，举个例子
- GET /api/files/ 得到所有档案
- GET /api/files/1 得到档案 ID 为 1 的档案
- POST /api/files/ 新增一个档案
- PUT /api/files/1 更新 ID 为 1 的档案
- PATCH /api/files/1 更新 ID 为 1 的部分档案内容
- DELETE /api/files/1 删除 ID 为 1 的档案


//beego：路由结构
type ControllerRegister struct {
routers      map[string]*Tree      //key method value routertree
enablePolicy bool
enableFilter bool
policies     map[string]*Tree
filters      [FinishRouter + 1][]*FilterRouter
pool         sync.Pool

	// the filter created by FilterChain
	chainRoot *FilterRouter

	// keep registered chain and build it when serve http
	filterChains []filterChainConfig

	cfg *Config
}

// iris
type repository struct {
routes []*Route
paths  map[string]*Route
}

// echo
Echo struct {
//....
router        *Router// 路由树
routers       map[string]*Router //key host value 路由树，RouterGroup功能host相当于namespace 
//....
}
Router struct {
tree   *node
//key  method+path value route信息  根据路由名称和提供的参数查找Route的信息。 Reverse函数中用到感觉没什么用，废代码
routes map[string]*Route  
// 框架实例
echo   *Echo
}


当在中间件或 handler 中启动新的 Goroutine 时，不能使用原始的上下文，必须使用只读副本。
c.copy()

jwt 的通常传输格式 Authorization: Bearer aaa.bbb.ccc


HTTP/2（推送，甚至嵌入数据）
中间件（Accesslog、Basicauth、CORS、gRPC、Anti-Bot hCaptcha、JWT、MethodOverride、ModRevision、Monitor、PPROF、Ratelimit、Anti-Bot reCaptcha、Recovery、RequestID、Rewrite）
API版本控制
模型-视图-控制器
网络套接字
远程过程调用
自动HTTPS
具有动态路径作为参数的独特路由器，具有标准类型，例如：uuid、：string、：int...以及创建您自己的能力
压缩
创建您自己的文件服务器并托管您自己的 WebDAV 服务器
缓存
本地化（i18n、站点地图）
会议
丰富的响应（HTML、文本、Markdown、XML、YAML、二进制、JSON、JSONP、协议缓冲区、MessagePack、内容协商、流式传输、服务器发送的事件等）
响应压缩（gzip、deflate、brotli、snappy、s2）
丰富的请求（绑定 URL 查询、标头、表单、文本、XML、YAML、二进制、JSON、验证、协议缓冲区、MessagePack 等）
依赖注入（MVC、处理程序、API 路由器）
测试套件



路由参数问题
