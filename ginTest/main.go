package main

import (
	"errors"
	"fmt"
	gin "gin-tiny"
	"net/http"
	"time"
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

	r.GETWithError("/hello", func(c gin.Context) error {
		name := c.QueryParams().Get("name")
		if name == "" {
			return &gin.Error{
				Err:  errors.New("name is required"),
				Type: gin.ErrorTypePublic,
			}
		}

		if name == "error" {
			return &gin.Error{
				Err:  errors.New("an internal error occurred"),
				Type: gin.ErrorTypePrivate,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": fmt.Sprintf("Hello, %s!", name),
		})

		return nil
	})
	r.HTTPErrorHandler = func(err error, c gin.Context) {
		if ginErr, ok := err.(gin.Error); ok {
			switch ginErr.Type {
			case gin.ErrorTypePublic:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "public error",
					"message": ginErr.Error(),
				})
			case gin.ErrorTypePrivate:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "private error",
					"message": "An internal error occurred. Please try again later.",
				})
			case gin.ErrorTypeBind:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "binding error",
					"message": "Invalid input data. Please check your request.",
				})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "unknown error",
					"message": "An unknown error occurred.",
				})
			}
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal server error",
			"message": "An unexpected error occurred.",
		})
		return
	}

	// StaticFile,StaticFileFS,Static,StaticFS
	r.POSTWithError("/users", createUserHandler)

	r.Run(":8080")

}

func createUserHandler(c gin.Context) error {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Age      int    `json:"age" binding:"min=1,max=120"`
	}

	// 1. 参数绑定和验证
	if err := c.ShouldBindJSON(&req); err != nil {
		return gin.Error{
			Err:  err,
			Type: gin.ErrorTypeBind,
		}
	}

	// 2. 业务规则验证
	if exists, err := checkUserExists(req.Username); err != nil {
		return gin.Error{
			Err:  err,
			Type: gin.ErrorTypePrivate,
		}
	} else if exists {
		return gin.Error{
			Err:  errors.New("用户名已存在"),
			Type: gin.ErrorTypePublic,
		}
	}

	// 3. 创建用户
	user, err := createUser(req.Username, req.Email, req.Age)
	if err != nil {
		return gin.Error{
			Err:  err,
			Type: gin.ErrorTypePrivate,
		}
	}

	// 4. 成功响应
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "用户创建成功",
		"data":    user,
	})

	return nil
}

func checkUserExists(username string) (bool, error) {
	if username == "error_user" {
		return false, errors.New("database query failed")
	}
	return username == "existing_user", nil
}

func createUser(username, email string, age int) (map[string]any, error) {
	if username == "error_user" {
		return nil, errors.New("failed to create user")
	}

	return map[string]any{
		"id":         time.Now().Unix(),
		"username":   username,
		"email":      email,
		"age":        age,
		"created_at": time.Now(),
	}, nil
}
