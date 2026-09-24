package binding

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type requiredName struct {
	Name string `toml:"name" msgpack:"name" json:"name" binding:"required"`
	Age  int    `toml:"age" msgpack:"age" json:"age"`
}

// TOML 和其他格式一样要执行 binding 标签校验
func TestTOMLBindingValidates(t *testing.T) {
	var ok requiredName
	require.NoError(t, TOML.BindBody([]byte("name = \"alice\"\nage = 3\n"), &ok))
	assert.Equal(t, requiredName{"alice", 3}, ok)

	var missing requiredName
	assert.Error(t, TOML.BindBody([]byte("age = 3\n"), &missing))

	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader("age = 3\n"))
	assert.Error(t, TOML.Bind(req, &missing))
}

func TestMsgpackBindingFillsCallerObjectAndValidates(t *testing.T) {
	var got requiredName
	require.NoError(t, MsgPack.BindBody(msgpackBody(t, map[string]any{"name": "bob", "age": 7}), &got))
	assert.Equal(t, requiredName{"bob", 7}, got)

	var missing requiredName
	assert.Error(t, MsgPack.BindBody(msgpackBody(t, map[string]any{"age": 7}), &missing))
}

// 切片中的 nil 指针不能导致 panic，其余元素照常校验
func TestValidateSliceWithNilPointers(t *testing.T) {
	type item struct {
		N string `binding:"required"`
	}
	assert.NotPanics(t, func() {
		assert.NoError(t, Validator.ValidateStruct([]*item{{N: "x"}, nil}))
	})
	err := Validator.ValidateStruct([]*item{nil, {N: ""}})
	var sliceErr SliceValidationError
	require.ErrorAs(t, err, &sliceErr)
	assert.Len(t, sliceErr, 1)

	var nilPtr *item
	assert.NoError(t, Validator.ValidateStruct(nilPtr))
}

// 手工构造的 url.Values 可能出现空切片
func TestSetFormMapWithEmptyValues(t *testing.T) {
	m := map[string]string{}
	assert.NotPanics(t, func() {
		require.NoError(t, setFormMap(m, map[string][]string{"a": {}, "b": {"1", "2"}}))
	})
	assert.Equal(t, map[string]string{"b": "2"}, m)

	ms := map[string][]string{}
	require.NoError(t, setFormMap(ms, map[string][]string{"a": {}, "b": {"1"}}))
	assert.Equal(t, map[string][]string{"a": {}, "b": {"1"}}, ms)
}
