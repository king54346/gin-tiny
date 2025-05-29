package main

import (
	"gin-tiny"
	"net/http"
	"testing"
)

func TestRest(t *testing.T) {
	r := ginTiny.Default()
	r.GET("/user", func(c ginTiny.Context) {
		type s struct {
			Name string `form:"name"`
		}
		if c.Request().Method == http.MethodGet {
			s2 := s{}
			c.ShouldBind(&s2)
			c.String(http.StatusOK, "Hello %s", s2.Name)
		}

	})

	r.Run(":8080")
}
