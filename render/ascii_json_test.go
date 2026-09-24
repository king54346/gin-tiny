package render

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsciiJSONRoundTrip(t *testing.T) {
	for _, s := range []string{"plain", "中文", "🚀 emoji", "mixed 𝄞 music é", "<html>&"} {
		w := httptest.NewRecorder()
		require.NoError(t, AsciiJSON{Data: map[string]string{"v": s}}.Render(w))

		for _, b := range w.Body.Bytes() {
			require.Less(t, b, byte(0x80), "output must be pure ASCII: %s", w.Body.String())
		}
		var got map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, s, got["v"])
	}
}

func TestAsciiEscapeSurrogatePair(t *testing.T) {
	bs := string(rune(92)) // 反斜杠
	// U+1F680 必须编码为 UTF-16 代理对 D83D DE80，而不是五位十六进制
	assert.Equal(t, `"`+bs+"ud83d"+bs+"ude80"+`"`, string(asciiEscape([]byte("\"\U0001F680\""))))
	assert.Equal(t, `"`+bs+"u4e2d"+`"`, string(asciiEscape([]byte("\"\U00004E2D\""))))
}

func BenchmarkAsciiJSONChinese(b *testing.B) {
	data := map[string]string{"text": "这是一段用于测试 AsciiJSON 性能的中文内容，包含一些标点符号。"}
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		w.Body.Reset()
		_ = AsciiJSON{Data: data}.Render(w)
	}
}
