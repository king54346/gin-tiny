package ginTiny

import (
	"testing"

	"github.com/king54346/gin-tiny/binding"
	"github.com/stretchr/testify/assert"
)

func TestSetMode(t *testing.T) {
	old := Mode()
	t.Cleanup(func() { SetMode(old) })

	for _, m := range []string{DebugMode, ReleaseMode, TestMode} {
		SetMode(m)
		assert.Equal(t, m, Mode())
		assert.Equal(t, m == DebugMode, IsDebugging())
	}

	// 空字符串：在 go test 中默认为 test 模式
	SetMode("")
	assert.Equal(t, TestMode, Mode())

	assert.PanicsWithValue(t, "gin mode unknown: prod (available mode: debug release test)", func() { SetMode("prod") })
	assert.Equal(t, TestMode, Mode(), "an invalid mode must not change the current mode")
}

func TestBindingSwitches(t *testing.T) {
	oldValidator, oldUseNumber, oldDisallow := binding.Validator, binding.EnableDecoderUseNumber, binding.EnableDecoderDisallowUnknownFields
	t.Cleanup(func() {
		binding.Validator = oldValidator
		binding.EnableDecoderUseNumber = oldUseNumber
		binding.EnableDecoderDisallowUnknownFields = oldDisallow
	})

	DisableBindValidation()
	assert.Nil(t, binding.Validator)

	EnableJsonDecoderUseNumber()
	assert.True(t, binding.EnableDecoderUseNumber)

	EnableJsonDecoderDisallowUnknownFields()
	assert.True(t, binding.EnableDecoderDisallowUnknownFields)
}
