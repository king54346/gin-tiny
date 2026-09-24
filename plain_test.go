package binding

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlainBinding(t *testing.T) {
	assert.Equal(t, "plain", Plain.Name())
	assert.Equal(t, Plain, Default(http.MethodPost, MIMEPlain))

	var s string
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader("hello 世界"))
	require.NoError(t, Plain.Bind(req, &s))
	assert.Equal(t, "hello 世界", s)

	var b []byte
	require.NoError(t, Plain.BindBody([]byte("raw"), &b))
	assert.Equal(t, []byte("raw"), b)

	// 多级指针
	ps := new(string)
	require.NoError(t, Plain.BindBody([]byte("deep"), &ps))
	assert.Equal(t, "deep", *ps)

	// 自定义的字符串 / 字节切片类型
	type text string
	var tx text
	require.NoError(t, Plain.BindBody([]byte("typed"), &tx))
	assert.Equal(t, text("typed"), tx)

	// nil 与 nil 指针不报错也不做任何事
	assert.NoError(t, Plain.BindBody([]byte("x"), nil))
	var nilPtr *string
	assert.NoError(t, Plain.BindBody([]byte("x"), nilPtr))

	var n int
	assert.EqualError(t, Plain.BindBody([]byte("1"), &n), "plain binding: unsupported type *int, want *string or *[]byte")
	assert.Error(t, Plain.BindBody([]byte("1"), s), "a non-pointer value cannot be set")
}

// 绑定结果是副本，修改它不影响输入（ShouldBindBodyWith 会缓存请求体供多次绑定）
func TestPlainBindingCopiesData(t *testing.T) {
	body := []byte("cached")
	var b []byte
	require.NoError(t, Plain.BindBody(body, &b))
	b[0] = 'X'
	assert.Equal(t, "cached", string(body))
}
