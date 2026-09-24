package main

import (
	ginTiny "github.com/king54346/gin-tiny"
	"net/http"
	"testing"
)

func TestRest(t *testing.T) {
	skipUnlessManual(t)
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
