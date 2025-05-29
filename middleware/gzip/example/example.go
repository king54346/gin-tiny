package main

import (
	"fmt"
	gin "gin-tiny"
	"gin-tiny/middleware/gzip"
	"log"
	"net/http"
	"time"
)

func main() {
	r := gin.Default()
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.GET("/ping", func(c *gin.context) {
		c.String(http.StatusOK, "pong "+fmt.Sprint(time.Now().Unix()))
	})

	// Listen and Server in 0.0.0.0:8080
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
