package validator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	gin "gin-tiny"
)

// ErrInvalidDigest error when sha256 of body do not match with submitted digest
var ErrInvalidDigest = &gin.Error{
	Err:  errors.New("sha256 of body is not match with digest"),
	Type: gin.ErrorTypePublic,
}

// DigestValidator checking digest in header match body
type DigestValidator struct{}

// NewDigestValidator return pointer of new DigestValidator
func NewDigestValidator() *DigestValidator {
	return &DigestValidator{}
}

// Validate return error when checking digest match body
func (v *DigestValidator) Validate(r *http.Request) error {
	headerDigest := r.Header.Get("digest")
	digest, err := calculateDigest(r)
	if err != nil {
		return err
	}
	if digest != headerDigest {
		return ErrInvalidDigest
	}
	return nil
}

func calculateDigest(r *http.Request) (string, error) {
	if r.ContentLength == 0 {
		return "", nil
	}

	// Create a buffer to store the body
	buf := new(bytes.Buffer)

	// Create a tee reader that writes to h while reading from r.Body
	h := sha256.New()
	//传入一个 Reader 和一个 Writer ，返回一个 teeReader 对象 ，当你读取 teeReader 中的内容时，会无缓冲的将读取内容写入到 Writer 中
	tee := io.TeeReader(r.Body, h)

	// Copy from the tee reader to the buffer, which stores the body for later use
	if _, err := io.Copy(buf, tee); err != nil {
		return "", err
	}

	// 替换请求体和缓冲区以供以后读取
	r.Body = io.NopCloser(buf)

	// Generate the digest
	digest := fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	return digest, nil
}
