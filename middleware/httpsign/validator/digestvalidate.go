package validator

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"

	gin "github.com/king54346/gin-tiny"
)

// DefaultMaxBodySize 是计算摘要时允许读取的最大请求体字节数
const DefaultMaxBodySize int64 = 10 << 20 // 10 MiB

// ErrInvalidDigest error when sha256 of body do not match with submitted digest
var ErrInvalidDigest = &gin.Error{
	Err:  errors.New("sha256 of body is not match with digest"),
	Type: gin.ErrorTypePublic,
}

// ErrBodyTooLarge 请求体超过 DigestValidator.MaxBodySize
var ErrBodyTooLarge = &gin.Error{
	Err:  errors.New("request body is too large to verify digest"),
	Type: gin.ErrorTypePublic,
}

// DigestValidator checking digest in header match body
type DigestValidator struct {
	// MaxBodySize 为计算摘要而读入内存的请求体上限，<= 0 时使用 DefaultMaxBodySize。
	// 摘要校验发生在签名校验之前，未认证的客户端也能触发，必须限制读取量
	MaxBodySize int64
}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestValidator() *DigestValidator {
	return &DigestValidator{MaxBodySize: DefaultMaxBodySize}
}

// Validate return error when checking digest match body
func (v *DigestValidator) Validate(r *http.Request) error {
	digest, err := v.calculateDigest(r)
	if err != nil {
		return err
	}
	// 与签名校验保持一致，使用常数时间比较
	if subtle.ConstantTimeCompare([]byte(digest), []byte(r.Header.Get("digest"))) != 1 {
		return ErrInvalidDigest
	}
	return nil
}

func (v *DigestValidator) calculateDigest(r *http.Request) (string, error) {
	if r.ContentLength == 0 || r.Body == nil {
		return "", nil
	}
	limit := v.MaxBodySize
	if limit <= 0 {
		limit = DefaultMaxBodySize
	}
	if r.ContentLength > limit {
		return "", ErrBodyTooLarge
	}

	// 多读一个字节用于判断是否超限（ContentLength 为 -1 的分块请求只能这样判断）
	buf := new(bytes.Buffer)
	h := sha256.New()
	n, err := io.Copy(buf, io.TeeReader(io.LimitReader(r.Body, limit+1), h))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", ErrBodyTooLarge
	}

	// 替换请求体，供后续 handler 读取
	r.Body = io.NopCloser(buf)
	return "SHA-256=" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
