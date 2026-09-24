package render

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type parsedEvent struct {
	ID, Event, Data string
	Retry           int
}

// parseSSE 按 WHATWG 规范解析事件流，模拟浏览器 EventSource 实际看到的内容：
// 行以 CRLF / LF / CR 结尾；冒号后的第一个空格会被去掉；data 多行以 \n 连接；
// retry 只接受纯数字；空行派发事件，data 为空的事件不派发
func parseSSE(stream string) []parsedEvent {
	stream = strings.ReplaceAll(stream, "\r\n", "\n")
	stream = strings.ReplaceAll(stream, "\r", "\n")

	var events []parsedEvent
	var cur parsedEvent
	var data []string
	hasData := false
	for line := range strings.SplitSeq(stream, "\n") {
		if line == "" {
			if hasData {
				cur.Data = strings.Join(data, "\n")
				events = append(events, cur)
			}
			cur, data, hasData = parsedEvent{}, nil, false
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			cur.ID = value
		case "event":
			cur.Event = value
		case "retry":
			if n, err := strconv.Atoi(value); err == nil {
				cur.Retry = n
			}
		case "data":
			data = append(data, value)
			hasData = true
		}
	}
	return events
}

func renderSSE(t *testing.T, events ...SSEvent) string {
	t.Helper()
	w := httptest.NewRecorder()
	for _, e := range events {
		require.NoError(t, e.Render(w))
	}
	return w.Body.String()
}

// 客户端解析出来的 data 必须和发送的字符串完全一致
func TestSSEDataRoundTrip(t *testing.T) {
	for _, data := range []string{
		"hello",
		"multi\nline\ndata",
		"crlf\r\nand\rcr",
		"id:not-a-field",
		"trailing newline\n",
		"   leading spaces",
		"line1\n  indented line2",
		" ",
		"unicode 你好 🚀",
	} {
		events := parseSSE(renderSSE(t, SSEvent{Data: data}))
		require.Len(t, events, 1, "%q", data)
		// 规范中换行统一为 \n
		want := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(data)
		assert.Equal(t, want, events[0].Data, "%q", data)
	}
}

func TestSSEFieldsRoundTrip(t *testing.T) {
	events := parseSSE(renderSSE(t, SSEvent{ID: " 42", Event: " update", Retry: 1500, Data: "x"}))
	require.Len(t, events, 1)
	assert.Equal(t, " 42", events[0].ID)
	assert.Equal(t, " update", events[0].Event)
	assert.Equal(t, 1500, events[0].Retry)
}

// 字段中的换行不能注入新字段或提前结束事件
func TestSSEFieldInjection(t *testing.T) {
	events := parseSSE(renderSSE(t, SSEvent{ID: "1\n\ndata:injected", Event: "a\r\nevent:evil", Data: "real"}))
	require.Len(t, events, 1)
	assert.Equal(t, "real", events[0].Data)
	assert.NotEqual(t, "evil", events[0].Event)
}

func TestSSEStreamOfEvents(t *testing.T) {
	stream := renderSSE(t,
		SSEvent{Event: "float", Data: 1.5},
		SSEvent{ID: "123", Data: map[string]string{"foo": "bar"}},
		SSEvent{ID: "124", Event: "chat", Data: "hi! dude"},
	)
	assert.Equal(t, []parsedEvent{
		{Event: "float", Data: "1.5"},
		{ID: "123", Data: `{"foo":"bar"}`},
		{ID: "124", Event: "chat", Data: "hi! dude"},
	}, parseSSE(stream))
}

type sseStruct struct {
	A int
	B string `json:"value"`
}

type sseStringer struct{ v string }

func (s sseStringer) String() string { return "stringer:" + s.v }

func TestSSEDataTypes(t *testing.T) {
	var nilPtr *sseStruct
	tests := []struct {
		name string
		data any
		want string
	}{
		{"int", 1, "1"},
		{"float", 1.5, "1.5"},
		{"bool", true, "true"},
		{"bytes", []byte("raw\nbytes"), "raw\nbytes"},
		{"map", map[string]any{"b": "id: 2", "a": "x\ny"}, `{"a":"x\ny","b":"id: 2"}`},
		{"slice", []any{1, "text", map[string]string{"foo": "bar"}}, `[1,"text",{"foo":"bar"}]`},
		{"struct", sseStruct{1, "number"}, `{"A":1,"value":"number"}`},
		{"struct pointer", &sseStruct{1, "number"}, `{"A":1,"value":"number"}`},
		{"nil pointer", nilPtr, "null"},
		{"stringer", sseStringer{"v"}, "stringer:v"},
	}
	for _, tt := range tests {
		events := parseSSE(renderSSE(t, SSEvent{Data: tt.data}))
		require.Len(t, events, 1, tt.name)
		want := tt.want
		if strings.HasPrefix(want, "{") || strings.HasPrefix(want, "[") {
			assert.JSONEq(t, want, events[0].Data, tt.name)
		} else {
			assert.Equal(t, want, events[0].Data, tt.name)
		}
	}
}

func TestSSEKeepsExistingCacheControl(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Cache-Control", "no-store")
	require.NoError(t, SSEvent{Data: "x"}.Render(w))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func BenchmarkSSEvent(b *testing.B) {
	w := httptest.NewRecorder()
	e := SSEvent{ID: "13435", Event: "new_message", Retry: 10, Data: "hi! how are you? I am fine. this is a long stupid message!!!"}
	b.ReportAllocs()
	for b.Loop() {
		w.Body.Reset()
		_ = e.Render(w)
	}
}
