package render

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/king54346/gin-tiny/internal/json"
)

// SSEvent 是一条 Server-Sent Event，格式遵循 https://html.spec.whatwg.org/multipage/server-sent-events.html
//
//	id: <ID>
//	event: <Event>
//	retry: <Retry>
//	data: <Data>
type SSEvent struct {
	ID    string
	Event string
	Retry uint // 客户端重连间隔（毫秒），0 表示不发送
	Data  any  // string/[]byte 原样输出，数字/布尔用文本形式，其它类型编码为 JSON
}

var sseContentType = []string{"text/event-stream"}

// sseFieldReplacer 去掉单行字段（id/event）中的换行，防止注入额外字段
var sseFieldReplacer = strings.NewReplacer("\n", "", "\r", "")

// Render (SSEvent) 将事件写入响应。
// 先完整编码到缓冲区再一次性写出：Data 编码失败时不会在流中留下半个事件
func (r SSEvent) Render(w http.ResponseWriter) error {
	r.WriteContentType(w)

	data, err := sseData(r.Data)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if r.ID != "" {
		writeSSEField(&buf, "id", sseFieldReplacer.Replace(r.ID))
	}
	if r.Event != "" {
		writeSSEField(&buf, "event", sseFieldReplacer.Replace(r.Event))
	}
	if r.Retry > 0 {
		writeSSEField(&buf, "retry", strconv.FormatUint(uint64(r.Retry), 10))
	}
	// data 按 CRLF / LF / CR 拆成多个 data: 行，客户端会用 \n 重新拼接
	for {
		i := strings.IndexAny(data, "\r\n")
		if i < 0 {
			writeSSEField(&buf, "data", data)
			break
		}
		writeSSEField(&buf, "data", data[:i])
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		data = data[i+1:]
	}
	buf.WriteByte('\n')

	_, err = w.Write(buf.Bytes())
	return err
}

// writeSSEField 写出一行 "name:value"。
// 规范规定客户端会去掉冒号后的第一个空格，值本身以空格开头时需要多补一个，否则首个空格会丢失
func writeSSEField(buf *bytes.Buffer, name, value string) {
	buf.WriteString(name)
	buf.WriteByte(':')
	if strings.HasPrefix(value, " ") {
		buf.WriteByte(' ')
	}
	buf.WriteString(value)
	buf.WriteByte('\n')
}

// WriteContentType (SSEvent) 写入 text/event-stream 以及禁止缓存的响应头。
func (r SSEvent) WriteContentType(w http.ResponseWriter) {
	header := w.Header()
	writeContentType(w, sseContentType)
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
}

func sseData(data any) (string, error) {
	switch v := data.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case fmt.Stringer:
		return v.String(), nil
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprint(v), nil
	default:
		b, err := json.Marshal(v)
		return string(b), err
	}
}
