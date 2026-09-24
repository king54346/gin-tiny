package render

import (
	"net/http"

	"github.com/king54346/gin-tiny/internal/msgpack"
)

// Check interface implemented here to support go build tag nomsgpack.
// See: https://github.com/gin-gonic/gin/pull/1852/
var (
	_ Render = MsgPack{}
)

// MsgPack contains the given interface object.
type MsgPack struct {
	Data any
}

var msgpackContentType = []string{MIMEApplicationMsgpack}

// WriteContentType (MsgPack) writes MsgPack ContentType.
func (r MsgPack) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, msgpackContentType)
}

// Render (MsgPack) encodes the given interface object and writes data with custom ContentType.
func (r MsgPack) Render(w http.ResponseWriter) error {
	return WriteMsgPack(w, r.Data)
}

// WriteMsgPack writes MsgPack ContentType and encodes the given interface object.
func WriteMsgPack(w http.ResponseWriter, obj any) error {
	writeContentType(w, msgpackContentType)
	return msgpack.NewEncoder(w).Encode(obj)
}
