//go:build !nomsgpack

package binding

import (
	"bytes"
	"testing"

	"github.com/king54346/gin-tiny/internal/msgpack"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMsgpackBindingBindBody(t *testing.T) {
	type teststruct struct {
		Foo string `msgpack:"foo"`
	}
	var s teststruct
	err := msgpackBinding{}.BindBody(msgpackBody(t, teststruct{"FOO"}), &s)
	require.NoError(t, err)
	assert.Equal(t, "FOO", s.Foo)
}

func msgpackBody(t *testing.T, obj any) []byte {
	var bs bytes.Buffer
	err := msgpack.NewEncoder(&bs).Encode(obj)
	require.NoError(t, err)
	return bs.Bytes()
}
