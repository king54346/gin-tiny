package expvar

import (
	"encoding/json"
	"expvar"
	"net/http"
	"net/http/httptest"
	"testing"

	gin "github.com/king54346/gin-tiny"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func performRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHandler(t *testing.T) {
	router := gin.New()
	router.GET("/debug/vars", Handler())

	w := performRequest(router, "GET", "/debug/vars")
	assert.Equal(t, w.Code, 200)
}

func TestHandlerOutputsJSON(t *testing.T) {
	expvar.NewString("gin_tiny_test_var").Set("hello")
	nextCalled := false
	router := gin.New()
	router.GET("/debug/vars", Handler(), func(c gin.Context) { nextCalled = true })

	w := performRequest(router, "GET", "/debug/vars")
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var vars map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &vars))
	assert.Equal(t, "hello", vars["gin_tiny_test_var"])
	assert.Contains(t, vars, "memstats")
	assert.False(t, nextCalled)
}
