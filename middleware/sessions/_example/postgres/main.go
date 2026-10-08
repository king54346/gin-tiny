package main

import (
	"database/sql"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/postgres"

	gin "github.com/king54346/gin-tiny"
)

func main() {
	r := gin.Default()
	db, err := sql.Open("postgres", "postgresql://username:password@localhost:5432/database")
	if err != nil {
		// handle err
	}

	store, err := postgres.NewStore(db, []byte("secret"))
	if err != nil {
		// handle err
	}

	r.Use(sessions.Sessions("mysession", store))

	r.GET("/incr", func(c gin.Context) {
		session := sessions.Default(c)
		var count int
		v := session.Get("count")
		if v == nil {
			count = 0
		} else {
			count = v.(int)
			count++
		}
		session.Set("count", count)
		session.Save()
		c.JSON(200, gin.H{"count": count})
	})
	r.Run(":8000")
}
