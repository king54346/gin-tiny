package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gin "github.com/king54346/gin-tiny"
	"github.com/stretchr/testify/assert"
)

func TestWildcardRules(t *testing.T) {
	c := newCors(Config{
		AllowWildcard: true,
		AllowOrigins: []string{
			"https://api.example.*", // * 在末尾
			"*.trusted.com",         // * 在开头
			"https://*.corp.io",     // * 在中间
			"https://a*a",           // 前后缀共享字符
		},
	})

	tests := []struct {
		origin string
		want   bool
	}{
		{"https://api.example.com", true},
		{"https://api.example.org", true},
		// 旧实现把规则解析成前缀 "https://api.example"，会放行以下伪造来源
		{"https://api.example-evil.com", false},
		{"https://api.exampleevil.com", false},

		{"https://app.trusted.com", true},
		{"https://trusted.com.evil.net", false},

		{"https://dev.corp.io", true},
		{"https://corp.io", false},
		{"http://dev.corp.io", false},

		// 前缀与后缀不能重叠
		{"https://a", false},
		{"https://aa", true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, c.validateWildcardOrigin(tt.origin), tt.origin)
	}
}

func TestWildcardDisabledIgnoresRules(t *testing.T) {
	cfg := Config{AllowOrigins: []string{"https://*.example.com"}}
	assert.Empty(t, cfg.parseWildcardRules())
}

func TestWildcardMultipleStarsPanics(t *testing.T) {
	assert.Panics(t, func() {
		Config{AllowWildcard: true, AllowOrigins: []string{"https://*.*.example.com"}}.parseWildcardRules()
	})
}

func TestDefaultAllowsAllOrigins(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.AllowAllOrigins)
	assert.Contains(t, cfg.AllowMethods, http.MethodPatch)

	router := gin.New()
	router.Use(Default())
	router.GET("/", func(c gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anything.example")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))

	// 预检请求
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://anything.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
}

// 通配符规则经由完整的中间件链路生效，伪造来源被拒绝
func TestWildcardThroughMiddleware(t *testing.T) {
	router := gin.New()
	router.Use(New(Config{AllowWildcard: true, AllowOrigins: []string{"https://api.example.*"}}))
	router.GET("/", func(c gin.Context) { c.String(http.StatusOK, "ok") })

	do := func(origin string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", origin)
		router.ServeHTTP(w, req)
		return w
	}

	w := do("https://api.example.com")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://api.example.com", w.Header().Get("Access-Control-Allow-Origin"))

	w = do("https://api.example-evil.com")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// 下游对响应头的原地修改不能影响之后的请求
func TestHeadersNotSharedAcrossRequests(t *testing.T) {
	router := gin.New()
	router.Use(New(Config{AllowOrigins: []string{"https://a.com"}, ExposeHeaders: []string{"X-Total"}, AllowMethods: []string{"GET"}}))
	first := true
	mutate := func(c gin.Context) {
		if first {
			for _, k := range []string{"Access-Control-Expose-Headers", "Access-Control-Allow-Methods"} {
				if v := c.Response().Header()[k]; len(v) > 0 {
					v[0] = "polluted"
				}
			}
			first = false
		}
	}
	router.GET("/", mutate)
	router.OPTIONS("/", mutate)

	do := func(method string) http.Header {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(method, "/", nil)
		req.Header.Set("Origin", "https://a.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		router.ServeHTTP(w, req)
		return w.Header()
	}

	do(http.MethodGet)
	assert.Equal(t, "X-Total", do(http.MethodGet).Get("Access-Control-Expose-Headers"))
	first = true
	do(http.MethodOptions)
	assert.Equal(t, "GET", do(http.MethodOptions).Get("Access-Control-Allow-Methods"))
}
