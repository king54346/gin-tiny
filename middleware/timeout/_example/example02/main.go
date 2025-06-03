package main

import (
	"gin-tiny/middleware/timeout"
	"log"
	"log/slog"
	"net/http"
	"time"

	gin "gin-tiny"
)

func testResponse(c *gin.context) {
	c.String(http.StatusRequestTimeout, "timeout")
}

func timeoutMiddleware() gin.HandlerFunc {
	return timeout.New(
		timeout.WithTimeout(500*time.Millisecond),
		timeout.WithHandler(func(c *gin.context) {
			c.Next()
		}),
		timeout.WithResponse(testResponse),
	)
}

func main() {
	r := gin.New()
	r.Use(timeoutMiddleware())
	r.GET("/slow", func(c *gin.context) {
		time.Sleep(800 * time.Millisecond)
		c.Status(http.StatusOK)
	})
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
	slog.Default()
}
