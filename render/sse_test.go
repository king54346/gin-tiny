package render

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderSSEvent(t *testing.T) {
	w := httptest.NewRecorder()
	err := SSEvent{ID: "1", Event: "msg", Retry: 3000, Data: "hello"}.Render(w)

	assert.NoError(t, err)
	assert.Equal(t, "id:1\nevent:msg\nretry:3000\ndata:hello\n\n", w.Body.String())
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestRenderSSEventMultilineData(t *testing.T) {
	w := httptest.NewRecorder()
	err := SSEvent{Data: "a\nb\r\nc"}.Render(w)

	assert.NoError(t, err)
	assert.Equal(t, "data:a\ndata:b\ndata:c\n\n", w.Body.String())
}

func TestRenderSSEventStripsNewlineInFields(t *testing.T) {
	w := httptest.NewRecorder()
	err := SSEvent{ID: "1\nevent:evil", Event: "a\rb", Data: 1}.Render(w)

	assert.NoError(t, err)
	assert.Equal(t, "id:1event:evil\nevent:ab\ndata:1\n\n", w.Body.String())
}

func TestRenderSSEventJSONData(t *testing.T) {
	w := httptest.NewRecorder()
	err := SSEvent{Data: map[string]int{"a": 1}}.Render(w)

	assert.NoError(t, err)
	assert.Equal(t, "data:{\"a\":1}\n\n", w.Body.String())
}

func TestRenderSSEventJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	err := SSEvent{Data: make(chan int)}.Render(w)

	assert.Error(t, err)
	assert.Empty(t, w.Body.String())
}
