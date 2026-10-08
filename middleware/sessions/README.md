# sessions

> 移植自 [gin-contrib/sessions](https://github.com/gin-contrib/sessions)，适配 gin-tiny（处理函数参数为 `gin.Context` 接口）。
>
> `cookie`、`memstore`、`filesystem` 属于 gin-tiny 主模块；`redis`、`memcached`、`gorm`、`postgres`、`mongo` 依赖较重，各自是独立的 Go module（目录下有自己的 go.mod），只在用到时才会引入对应依赖。

Gin middleware for session management with multi-backend support:

- [cookie-based](#cookie-based)
- [Redis](#redis)
- [memcached](#memcached)
- [MongoDB](#mongodb)
- [GORM](#gorm)
- [memstore](#memstore)
- [PostgreSQL](#postgresql)
- [Filesystem](#Filesystem)

## Usage

### Start using it

Download and install it:

```bash
go get github.com/king54346/gin-tiny/middleware/sessions
```

Import it in your code:

```go
import "github.com/king54346/gin-tiny/middleware/sessions"
```

## Basic Examples

### single session

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/cookie"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store := cookie.NewStore([]byte("secret"))
  r.Use(sessions.Sessions("mysession", store))

  r.GET("/hello", func(c gin.Context) {
    session := sessions.Default(c)

    if session.Get("hello") != "world" {
      session.Set("hello", "world")
      session.Save()
    }

    c.JSON(200, gin.H{"hello": session.Get("hello")})
  })
  r.Run(":8000")
}
```

### multiple sessions

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/cookie"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store := cookie.NewStore([]byte("secret"))
  sessionNames := []string{"a", "b"}
  r.Use(sessions.SessionsMany(sessionNames, store))

  r.GET("/hello", func(c gin.Context) {
    sessionA := sessions.DefaultMany(c, "a")
    sessionB := sessions.DefaultMany(c, "b")

    if sessionA.Get("hello") != "world!" {
      sessionA.Set("hello", "world!")
      sessionA.Save()
    }

    if sessionB.Get("hello") != "world?" {
      sessionB.Set("hello", "world?")
      sessionB.Save()
    }

    c.JSON(200, gin.H{
      "a": sessionA.Get("hello"),
      "b": sessionB.Get("hello"),
    })
  })
  r.Run(":8000")
}
```

### multiple sessions with different stores

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/cookie"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  cookieStore := cookie.NewStore([]byte("secret"))
  redisStore, _ := redis.NewStore(10, "tcp", "localhost:6379", "", []byte("secret"))
  sessionStores := []sessions.SessionStore{
    {
      Name:  "a",
      Store: cookieStore,
    },
    {
      Name:  "b",
      Store: redisStore,
    },
  }
  r.Use(sessions.SessionsManyStores(sessionStores))

  r.GET("/hello", func(c gin.Context) {
    sessionA := sessions.DefaultMany(c, "a")
    sessionB := sessions.DefaultMany(c, "b")

    if sessionA.Get("hello") != "world!" {
      sessionA.Set("hello", "world!")
      sessionA.Save()
    }

    if sessionB.Get("hello") != "world?" {
      sessionB.Set("hello", "world?")
      sessionB.Save()
    }

    c.JSON(200, gin.H{
      "a": sessionA.Get("hello"),
      "b": sessionB.Get("hello"),
    })
  })
  r.Run(":8000")
}
```

## Backend Examples

### cookie-based

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/cookie"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store := cookie.NewStore([]byte("secret"))
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
```

### Redis

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/redis"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", []byte("secret"))
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
```

### Memcached

#### ASCII Protocol

```go
package main

import (
  "github.com/bradfitz/gomemcache/memcache"
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/memcached"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store := memcached.NewStore(memcache.New("localhost:11211"), "", []byte("secret"))
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
```

#### Binary protocol (with optional SASL authentication)

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/memcached"
  gin "github.com/king54346/gin-tiny"
  "github.com/memcachier/mc"
)

func main() {
  r := gin.Default()
  client := mc.NewMC("localhost:11211", "username", "password")
  store := memcached.NewMemcacheStore(client, "", []byte("secret"))
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
```

### MongoDB

```go
package main

import (
  "context"
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/mongo/mongodriver"
  gin "github.com/king54346/gin-tiny"
  "go.mongodb.org/mongo-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
  r := gin.Default()
  mongoOptions := options.Client().ApplyURI("mongodb://localhost:27017")
  client, err := mongo.Connect(context.Background(), mongoOptions)
  if err != nil {
    // handle err
  }

  c := client.Database("test").Collection("sessions")
  store := mongodriver.NewStore(c, 3600, true, []byte("secret"))
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
```

### memstore

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/memstore"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()
  store := memstore.NewStore([]byte("secret"))
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
```

### GORM

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  gormsessions "github.com/king54346/gin-tiny/middleware/sessions/gorm"
  gin "github.com/king54346/gin-tiny"
  "gorm.io/driver/sqlite"
  "gorm.io/gorm"
)

func main() {
  db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
  if err != nil {
    panic(err)
  }
  store := gormsessions.NewStore(db, true, []byte("secret"))

  r := gin.Default()
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
```

### PostgreSQL

```go
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
```

### Filesystem

```go
package main

import (
  "github.com/king54346/gin-tiny/middleware/sessions"
  "github.com/king54346/gin-tiny/middleware/sessions/filesystem"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  r := gin.Default()

  var sessionPath = "/tmp/" // in case of empty string, the system's default tmp folder is used

  store := filesystem.NewStore(sessionPath,[]byte("secret"))
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
```
