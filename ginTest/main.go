package main

import (
	gin "gin-tiny"
	"net/http"
)

func main() {
	//router := gin.Default()
	//
	//// 此 handler 将匹配 /user/john 但不会匹配 /user/ 或者 /user
	//router.GET("/user/:name", func(c *gin.context) {
	//	name := c.Param("name")
	//	c.String(http.StatusOK, "Hello %s", name)
	//})
	//
	//// 此 handler 将匹配 /user/john/ 和 /user/john/send
	//// 如果没有其他路由匹配 /user/john，它将重定向到 /user/john/
	//router.GET("/user/:name/*action", func(c *gin.context) {
	//	name := c.Param("name")
	//	action := c.Param("action")
	//	message := name + " is " + action
	//	c.String(http.StatusOK, message)
	//})
	//
	//router.Run(":8080")
	r := gin.Default()

	r.Static("/static", "./ginTest/static")
	// 方法2: 服务单个静态文件
	// 访问路径: http://localhost:8080/favicon.ico
	// 对应本地文件: ./assets/favicon.ico
	// 方法1: 检查文件存在再设置路由

	r.StaticFile("/favicon.ico", "./ginTest/assets/favicon.ico")

	// 方法3: 使用StaticFS提供更多控制
	// 访问路径: http://localhost:8080/assets/filename.ext
	// 对应本地路径: ./public/filename.ext
	r.StaticFS("/assets", http.Dir("./ginTest/public"))

	r.StaticMatch(
		[]string{"GET", "HEAD"},
		"/test",
		func(c gin.Context) {
			c.JSON(200, gin.H{
				"method":  c.Request().Method,
				"message": "公开资源",
			})
		},
	)
	// StaticFile,StaticFileFS,Static,StaticFS

	r.Run(":8080")

}
