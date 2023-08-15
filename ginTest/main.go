package main

import (
	"fmt"
	gin "gin-tiny"
	"io"
	"time"
)

func main() {
	//router := gin.Default()
	//
	//// 此 handler 将匹配 /user/john 但不会匹配 /user/ 或者 /user
	//router.GET("/user/:name", func(c *gin.Context) {
	//	name := c.Param("name")
	//	c.String(http.StatusOK, "Hello %s", name)
	//})
	//
	//// 此 handler 将匹配 /user/john/ 和 /user/john/send
	//// 如果没有其他路由匹配 /user/john，它将重定向到 /user/john/
	//router.GET("/user/:name/*action", func(c *gin.Context) {
	//	name := c.Param("name")
	//	action := c.Param("action")
	//	message := name + " is " + action
	//	c.String(http.StatusOK, message)
	//})
	//
	//router.Run(":8080")
	r := gin.Default()

	r.GET("/stream", func(c *gin.Context) {
		// Send a stream of data to the client.
		now := time.Now().Unix()
		c.Stream(func(w io.Writer) bool {
			// Write the current time to the client every second.
			println(time.Now().Unix() - now)
			fmt.Fprintf(w, "Current time: %s\n", time.Now().Format(time.RFC1123))
			time.Sleep(time.Second)
			//如果超过10秒就返回false
			if time.Now().Unix()-now > 100 {
				return false
			}
			return true

		})
	})

	r.Run(":8080")

}
