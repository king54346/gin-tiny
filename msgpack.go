//go:build !nomsgpack

package binding

import (
	"bytes"
	"io"
	"net/http"

	"github.com/king54346/gin-tiny/internal/msgpack"
)

type msgpackBinding struct{}

func (msgpackBinding) Name() string {
	return "msgpack"
}

func (msgpackBinding) Bind(req *http.Request, obj any) error {
	return decodeMsgPack(req.Body, obj)
}

func (msgpackBinding) BindBody(body []byte, obj any) error {
	return decodeMsgPack(bytes.NewReader(body), obj)
}

func decodeMsgPack(r io.Reader, obj any) error {
	if err := msgpack.NewDecoder(r).Decode(obj); err != nil {
		return err
	}
	return validate(obj)
}
