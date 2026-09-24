package validator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDateValidator(t *testing.T) {
	v := NewDateValidator()
	now := time.Now().UTC()

	tests := []struct {
		name string
		date string
		err  error
	}{
		{"now", now.Format(http.TimeFormat), nil},
		{"within gap", now.Add(-maxTimeGap / 2).Format(http.TimeFormat), nil},
		{"too old", now.Add(-2 * maxTimeGap).Format(http.TimeFormat), ErrDateNotInRange},
		{"in the future", now.Add(2 * maxTimeGap).Format(http.TimeFormat), ErrDateNotInRange},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Date", tt.date)
		assert.Equal(t, tt.err, v.Validate(req), tt.name)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Date", "not a date")
	err := v.Validate(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Could not parse date header")

	custom := &DateValidator{TimeGap: time.Hour}
	req.Header.Set("Date", now.Add(-30*time.Minute).Format(http.TimeFormat))
	assert.NoError(t, custom.Validate(req))
}

func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestDigestValidator(t *testing.T) {
	v := NewDigestValidator()

	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	req.Header.Set("Digest", digestOf("hello"))
	require.NoError(t, v.Validate(req))
	// 校验后请求体必须仍可被后续 handler 读取
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(body))

	req, _ = http.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	req.Header.Set("Digest", digestOf("tampered"))
	assert.Equal(t, ErrInvalidDigest, v.Validate(req))

	// 空请求体不需要 Digest
	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, v.Validate(req))
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestDigestValidatorBodyReadError(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/", io.NopCloser(failingReader{}))
	req.ContentLength = 10
	err := NewDigestValidator().Validate(req)
	assert.EqualError(t, err, "read failed")
}

// 请求体已被替换为可重复读取的缓冲区，多个 validator 依次读取也不会丢数据
func TestDigestValidatorPreservesBodyForSecondRead(t *testing.T) {
	v := NewDigestValidator()
	req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewBufferString("payload"))
	req.Header.Set("Digest", digestOf("payload"))
	require.NoError(t, v.Validate(req))
	require.NoError(t, v.Validate(req))
}

func TestDigestValidatorBodyLimit(t *testing.T) {
	v := &DigestValidator{MaxBodySize: 8}

	// 恰好在上限内
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader("12345678"))
	req.Header.Set("Digest", digestOf("12345678"))
	assert.NoError(t, v.Validate(req))

	// Content-Length 已声明超限：不读取请求体直接拒绝
	req, _ = http.NewRequest(http.MethodPost, "/", strings.NewReader("123456789"))
	assert.Equal(t, ErrBodyTooLarge, v.Validate(req))

	// 分块传输（Content-Length 未知）同样受限
	req, _ = http.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader("123456789")))
	req.ContentLength = -1
	assert.Equal(t, ErrBodyTooLarge, v.Validate(req))

	// 零值配置使用默认上限
	assert.Equal(t, DefaultMaxBodySize, NewDigestValidator().MaxBodySize)
	req, _ = http.NewRequest(http.MethodPost, "/", strings.NewReader("abc"))
	req.Header.Set("Digest", digestOf("abc"))
	assert.NoError(t, (&DigestValidator{}).Validate(req))
}
