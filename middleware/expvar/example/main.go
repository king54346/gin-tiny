package main

import (
	gin "gin-tiny"
	"gin-tiny/middleware/expvar"
	"log"
)

func main() {
	r := gin.Default()

	r.GET("/debug/vars", expvar.Handler())

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
