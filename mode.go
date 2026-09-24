package ginTiny

import (
	"flag"
	"io"
	"os"
	"sync/atomic"

	"github.com/king54346/gin-tiny/binding"
)

// EnvGinMode indicates environment name for gin mode.
const EnvGinMode = "GIN_MODE"

const (
	// DebugMode indicates gin mode is debug.
	DebugMode = "debug"
	// ReleaseMode indicates gin mode is release.
	ReleaseMode = "release"
	// TestMode indicates gin mode is test.
	TestMode = "test"
)

const (
	debugCode = iota
	releaseCode
	testCode
)

// DefaultWriter is the default io.Writer used by Gin for debug output and
// middleware output like Logger() or Recovery().
// Note that both Logger and Recovery provides custom ways to configure their
// output io.Writer.
// To support coloring in Windows use:
//
//	import "github.com/mattn/go-colorable"
//	gin.DefaultWriter = colorable.NewColorableStdout()
var DefaultWriter io.Writer = os.Stdout

// DefaultErrorWriter is the default io.Writer used by Gin to debug errors
var DefaultErrorWriter io.Writer = os.Stderr

// ginMode 是唯一的模式状态，Mode() 返回的名字由它推导，保证并发 SetMode 时二者不会不一致
var ginMode atomic.Int32

// modeNames 按模式码索引的模式名
var modeNames = [...]string{debugCode: DebugMode, releaseCode: ReleaseMode, testCode: TestMode}

func init() {
	mode := os.Getenv(EnvGinMode)
	SetMode(mode)
}

// SetMode sets gin mode according to input string.
func SetMode(value string) {
	if value == "" {
		if flag.Lookup("test.v") != nil {
			value = TestMode
		} else {
			value = DebugMode
		}
	}

	switch value {
	case DebugMode:
		ginMode.Store(debugCode)
	case ReleaseMode:
		ginMode.Store(releaseCode)
	case TestMode:
		ginMode.Store(testCode)
	default:
		panic("gin mode unknown: " + value + " (available mode: debug release test)")
	}
}

// DisableBindValidation closes the default validator.
func DisableBindValidation() {
	binding.Validator = nil
}

// EnableJsonDecoderUseNumber sets true for binding.EnableDecoderUseNumber to
// call the UseNumber method on the JSON Decoder instance.
func EnableJsonDecoderUseNumber() {
	binding.EnableDecoderUseNumber = true
}

// EnableJsonDecoderDisallowUnknownFields sets true for binding.EnableDecoderDisallowUnknownFields to
// call the DisallowUnknownFields method on the JSON Decoder instance.
func EnableJsonDecoderDisallowUnknownFields() {
	binding.EnableDecoderDisallowUnknownFields = true
}

// Mode returns current gin mode.
func Mode() string {
	return modeNames[ginMode.Load()]
}
