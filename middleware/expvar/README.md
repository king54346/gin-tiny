一个 HTTP 端点轻松地公开你的应用程序中的特定变量，从而进行监视和调试。
例如，你可以使用它来公开内存分配器统计信息、GC 暂停时间、goroutine 数量和运行时间统计信息。

```go
package main

import (
  "log"

  "github.com/gin-contrib/expvar"
  "github.com/gin-gonic/gin"
)

func main() {
  r := gin.Default()

  r.GET("/debug/vars", expvar.Handler())

  if err := r.Run(":8080"); err != nil {
    log.Fatal(err)
  }
}
```
