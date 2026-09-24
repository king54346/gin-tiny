package expvar

import (
	"expvar"

	gin "github.com/king54346/gin-tiny"
)

// Handler for gin framework
// 直接复用标准库的 expvar.Handler，输出格式与 /debug/vars 完全一致
func Handler() gin.HandlerFunc {
	h := expvar.Handler()
	return func(c gin.Context) {
		h.ServeHTTP(c.Response(), c.Request())
		c.Abort()
	}
}
