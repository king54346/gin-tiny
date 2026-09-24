package httpsign

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"

	gin "github.com/king54346/gin-tiny"
	"github.com/king54346/gin-tiny/middleware/httpsign/crypto"
	"github.com/king54346/gin-tiny/middleware/httpsign/validator"
)

const (
	requestTarget = "(request-target)"
	date          = "date"
	digest        = "digest"
	host          = "host"
)

var defaultRequiredHeaders = []string{requestTarget, date, digest}

// Authenticator is the gin authenticator middleware.
type Authenticator struct {
	secrets    Secrets
	validators []validator.Validator
	headers    []string
	// requireAlgorithm 为 true 时签名头必须携带 algorithm 参数，见 WithRequireAlgorithm
	requireAlgorithm bool
}

// Option is the option to the Authenticator constructor.
type Option func(*Authenticator)

// WithValidator configures the Authenticator to use custom validator.
// The default validators are time based and digest.
func WithValidator(validators ...validator.Validator) Option {
	return func(a *Authenticator) {
		a.validators = validators
	}
}

// WithRequiredHeaders is list of all requires HTTP headers that the client
// have to include in the singing string for the request to be considered valid.
// If not provided, the created Authenticator instance will use defaultRequiredHeaders variable.
func WithRequiredHeaders(headers []string) Option {
	return func(a *Authenticator) {
		a.headers = headers
	}
}

// NewAuthenticator creates a new Authenticator instance with
// given allowed permissions and required header and secret keys.
func NewAuthenticator(secretKeys Secrets, options ...Option) *Authenticator {
	a := &Authenticator{secrets: secretKeys}

	for _, fn := range options {
		fn(a)
	}

	if a.validators == nil {
		a.validators = []validator.Validator{
			validator.NewDateValidator(),
			validator.NewDigestValidator(),
		}
	}

	if len(a.headers) == 0 {
		a.headers = defaultRequiredHeaders
	}

	return a
}

// Authenticated returns a gin middleware which permits given permissions in parameter.
func (a *Authenticator) Authenticated() gin.HandlerFunc {
	return func(c gin.Context) {
		sigHeader, err := NewSignatureHeader(c.Request())
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		for _, v := range a.validators {
			if err := v.Validate(c.Request()); err != nil {
				_ = c.AbortWithError(http.StatusBadRequest, err)
				return
			}
		}
		if !a.isValidHeader(sigHeader.headers) {
			_ = c.AbortWithError(http.StatusBadRequest, ErrHeaderNotEnough)
			return
		}

		// keyId 不存在、algorithm 不符、签名错误统一返回 401，且都执行一次签名计算：
		// 状态码或耗时不同都会让攻击者探测出哪些 keyId 存在（旧实现对存在的 keyId 返回 400、不存在的返回 401）
		secret, authErr := a.lookupSecret(sigHeader.keyID, sigHeader.algorithm)
		signString := constructSignMessage(c.Request(), sigHeader.headers)
		signature, err := secret.Algorithm.Sign(signString, secret.Key)
		if err != nil && authErr == nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		// 用常数时间比较，避免通过响应耗时逐字节猜出正确签名
		signatureBase64 := base64.StdEncoding.EncodeToString(signature)
		signatureOK := hmac.Equal([]byte(signatureBase64), []byte(sigHeader.signature))
		if authErr != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, authErr)
			return
		}
		if !signatureOK {
			_ = c.AbortWithError(http.StatusUnauthorized, ErrInvalidSign)
			return
		}
		c.Next()
	}
}

// isValidHeader check if all server required header is in header list
func (a *Authenticator) isValidHeader(headers []string) bool {
	for _, h := range a.headers {
		if !slices.Contains(headers, h) {
			return false
		}
	}
	return true
}

// dummySecret 用于 keyId 不存在时照常执行一次签名计算，使响应耗时与 keyId 存在时一致
var dummySecret = &Secret{Key: "gin-tiny-httpsign-dummy-key", Algorithm: &crypto.HmacSha512{}}

// lookupSecret 查找 keyId 对应的密钥并检查 algorithm。无论成功与否都返回一个可用于计算签名的密钥，
// 失败原因通过 error 返回，由调用方在完成签名计算后统一处理
func (a *Authenticator) lookupSecret(keyID KeyID, algorithm string) (*Secret, error) {
	secret, ok := a.secrets[keyID]
	if !ok {
		return dummySecret, ErrInvalidKeyID
	}
	if algorithm == "" {
		if a.requireAlgorithm {
			return secret, ErrMissingAlgorithm
		}
		// 签名算法始终取自服务端为该 keyId 配置的算法，客户端省略 algorithm 不会导致降级；
		// 规范（draft-cavage 第 10 版起）也建议从 keyId 推导算法，该参数可省略
		return secret, nil
	}
	if secret.Algorithm.Name() != algorithm {
		return secret, ErrIncorrectAlgorithm
	}
	return secret, nil
}

// 结构化签名字符串
func constructSignMessage(r *http.Request, headers []string) string {
	var signBuffer bytes.Buffer
	for i, field := range headers {
		var fieldValue string
		switch field {
		case host:
			fieldValue = r.Host
		case requestTarget:
			fieldValue = fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.RequestURI())
		default:
			fieldValue = r.Header.Get(field)
		}
		signString := fmt.Sprintf("%s: %s", field, fieldValue)
		signBuffer.WriteString(signString)
		if i < len(headers)-1 {
			signBuffer.WriteString("\n")
		}
	}
	return signBuffer.String()
}

// WithRequireAlgorithm 要求签名头必须携带 algorithm 参数。
// 默认不要求：签名算法总是取自服务端配置，省略该参数没有安全影响，且规范允许省略
func WithRequireAlgorithm() Option {
	return func(a *Authenticator) {
		a.requireAlgorithm = true
	}
}
