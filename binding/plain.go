package binding

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
)

type plainBinding struct{}

func (plainBinding) Name() string {
	return "plain"
}

func (plainBinding) Bind(req *http.Request, obj any) error {
	all, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	return decodePlain(all, obj)
}

func (plainBinding) BindBody(body []byte, obj any) error {
	return decodePlain(body, obj)
}

// decodePlain 把请求体原样写入 *string 或 *[]byte（支持多级指针）。
// 写入的是数据的副本：BindBody 的输入可能是 ShouldBindBodyWith 缓存的请求体，
// 共享底层数组会让调用方修改结果时顺带改掉缓存
func decodePlain(data []byte, obj any) error {
	if obj == nil {
		return nil
	}
	v := reflect.ValueOf(obj)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if !v.CanSet() {
		return fmt.Errorf("plain binding: %T is not settable, pass a pointer", obj)
	}
	switch {
	case v.Kind() == reflect.String:
		v.SetString(string(data))
		return nil
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8:
		v.SetBytes(bytes.Clone(data))
		return nil
	}
	return fmt.Errorf("plain binding: unsupported type %T, want *string or *[]byte", obj)
}

var _ BindingBody = Plain
