package ginTiny

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/king54346/gin-tiny/internal/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorJSON(t *testing.T) {
	base := errors.New("bad input")

	// 无 Meta
	assert.Equal(t, H{"error": "bad input"}, (&Error{Err: base}).JSON())

	// 结构体 Meta 原样返回
	type detail struct{ Field string }
	assert.Equal(t, detail{"name"}, (&Error{Err: base, Meta: detail{"name"}}).JSON())

	// map Meta 展开，并补充 error 字段
	assert.Equal(t, H{"field": "name", "error": "bad input"}, (&Error{Err: base, Meta: map[string]string{"field": "name"}}).JSON())

	// Meta 自带 error 键时不覆盖
	assert.Equal(t, H{"error": "custom"}, (&Error{Err: base, Meta: H{"error": "custom"}}).JSON())

	// 非字符串类型的键也要正确转换，不能互相覆盖
	assert.Equal(t, H{"1": "a", "2": "b", "error": "bad input"}, (&Error{Err: base, Meta: map[int]string{1: "a", 2: "b"}}).JSON())

	// 其他类型的 Meta 放到 meta 字段
	assert.Equal(t, H{"meta": 42, "error": "bad input"}, (&Error{Err: base, Meta: 42}).JSON())
}

func TestErrorMarshalJSONAndUnwrap(t *testing.T) {
	sentinel := errors.New("not found")
	e := &Error{Err: fmt.Errorf("user 7: %w", sentinel), Type: ErrorTypePublic}

	b, err := json.Marshal(e)
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":"user 7: not found"}`, string(b))

	assert.ErrorIs(t, e, sentinel)
	assert.Equal(t, e.Err, errors.Unwrap(e))
	assert.True(t, e.IsType(ErrorTypePublic))
	assert.False(t, e.IsType(ErrorTypePrivate))
	assert.Same(t, e, e.SetMeta("m"))
	assert.Equal(t, "m", e.Meta)
}

func TestErrorMsgs(t *testing.T) {
	var empty errorMsgs
	assert.Nil(t, empty.Last())
	assert.Nil(t, empty.Errors())
	assert.Nil(t, empty.ByType(ErrorTypeAny))
	assert.Nil(t, empty.JSON())
	assert.Empty(t, empty.String())
	b, err := json.Marshal(empty)
	require.NoError(t, err)
	assert.Equal(t, "null", string(b))

	errs := errorMsgs{
		{Err: errors.New("first"), Type: ErrorTypePrivate},
		{Err: errors.New("second"), Type: ErrorTypePublic, Meta: "extra"},
		{Err: errors.New("third"), Type: ErrorTypeBind},
	}
	assert.Equal(t, "third", errs.Last().Error())
	assert.Equal(t, []string{"first", "second", "third"}, errs.Errors())
	assert.Len(t, errs.ByType(ErrorTypeAny), 3)
	assert.Equal(t, []string{"second"}, errs.ByType(ErrorTypePublic).Errors())
	assert.Equal(t, []string{"first", "second"}, errs.ByType(ErrorTypePrivate|ErrorTypePublic).Errors())
	assert.Nil(t, errs.ByType(ErrorTypeRender))

	assert.Equal(t, "Error #01: first\nError #02: second\n     Meta: extra\nError #03: third\n", errs.String())

	b, err = json.Marshal(errs)
	require.NoError(t, err)
	assert.JSONEq(t, `[{"error":"first"},{"error":"second","meta":"extra"},{"error":"third"}]`, string(b))

	// 只有一个错误时输出对象而不是数组
	b, err = json.Marshal(errs[:1])
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":"first"}`, string(b))
}

// 值类型的 Error 同样实现了 error 接口，框架要和指针类型一样识别
func TestValueErrorIsRecognized(t *testing.T) {
	r := New()
	r.GETWithError("/ptr", func(c Context) error { return &Error{Err: errors.New("bad"), Type: ErrorTypePublic} })
	r.GETWithError("/val", func(c Context) error { return Error{Err: errors.New("bad"), Type: ErrorTypePublic} })
	r.GETWithError("/wrapped", func(c Context) error {
		return fmt.Errorf("handler: %w", Error{Err: errors.New("bad"), Type: ErrorTypePublic})
	})
	for _, p := range []string{"/ptr", "/val", "/wrapped"} {
		w := PerformRequest(r, http.MethodGet, p)
		assert.Equal(t, http.StatusBadRequest, w.Code, p)
		assert.Contains(t, w.Body.String(), "bad", p)
	}

	c := &context{}
	e := c.Error(Error{Err: errors.New("x"), Type: ErrorTypePublic})
	assert.Equal(t, ErrorTypePublic, e.Type, "the error type must be preserved")
	assert.Len(t, c.Errors().ByType(ErrorTypePublic), 1)
}
