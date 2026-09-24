package httpsign

import (
	"context"
	"errors"
	"fmt"
	gin "github.com/king54346/gin-tiny"
	"github.com/king54346/gin-tiny/middleware/httpsign/crypto"
	"github.com/king54346/gin-tiny/middleware/httpsign/validator"
	"github.com/king54346/gin-tiny/render"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	readID                 = KeyID("read")
	writeID                = KeyID("write")
	invalidKeyID           = KeyID("invalid key")
	invaldAlgo             = "invalidAlgo"
	requestNilBodySig      = "ewYjBILGshEmTDDMWLeBc9kQfIscSKxmFLnUBU/eXQCb0hrY1jh7U5SH41JmYowuA4p6+YPLcB9z/ay7OvG/Sg=="
	requestBodyDigest      = "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	requestBodyFalseDigest = "SHA-256=fakeDigest="
	requestBodySig         = "s8MEyer3dSpSsnL0+mQvUYgKm2S4AEX+hsvKmeNI7wgtLFplbCZtt8YOcySZrCyYbOJdPF1NASDHfupSuekecg=="
	requestHost            = "kyber.network"
	requestHostSig         = "+qpk6uAlILo/1YV1ZDK2suU46fbaRi5guOyg4b6aS4nWqLi9u57V6mVwQNh0s6OpfrVZwAYaWHCmQFCgJiZ6yg=="
	algoHmacSha512         = "hmac-sha512"
)

var (
	hmacsha512 = &crypto.HmacSha512{}
	secrets    = Secrets{
		readID: &Secret{
			Key:       "1234",
			Algorithm: hmacsha512,
		},
		writeID: &Secret{
			Key:       "5678",
			Algorithm: hmacsha512,
		},
	}
	requiredHeaders = []string{"(request-target)", "date", "digest"}
	submitHeader    = []string{"(request-target)", "date", "digest"}
	submitHeader2   = []string{"(request-target)", "date", "digest", "host"}
	requestTime     = time.Date(2018, time.October, 22, 0o7, 0o0, 0o7, 0o0, time.UTC)
)

func runTest(secretKeys Secrets, headers []string, v []validator.Validator, req *http.Request) gin.Context {
	gin.SetMode(gin.TestMode)
	auth := NewAuthenticator(secretKeys, WithRequiredHeaders(headers), WithValidator(v...))
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.SetRequest(req)
	auth.Authenticated()(c)
	return c
}

func generateSignature(keyID KeyID, algorithm string, headers []string, signature string) string {
	return fmt.Sprintf(
		"Signature keyId=\"%s\",algorithm=\"%s\",headers=\"%s\",signature=\"%s\"",
		keyID, algorithm, strings.Join(headers, " "), signature,
	)
}

func TestAuthenticatedHeaderNoSignature(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, ErrNoSignature, c.Errors()[0])
}

func TestAuthenticatedHeaderInvalidSignature(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	req.Header.Set(authorizationHeader, "hello")
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, ErrInvalidAuthorizationHeader, c.Errors()[0])
}

func TestAuthenticatedHeaderWrongKey(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(invalidKeyID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, ErrInvalidKeyID, c.Errors()[0])
}

func TestAuthenticateDateNotAccept(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Date(1990, time.October, 20, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Response().Status())
	assert.Equal(t, validator.ErrDateNotInRange, c.Errors()[0])
}

func TestAuthenticateInvalidRequiredHeader(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	invalidRequiredHeaders := []string{"date"}
	sigHeader := generateSignature(readID, algoHmacSha512, invalidRequiredHeaders, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)

	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Response().Status())
	assert.Equal(t, ErrHeaderNotEnough, c.Errors()[0])
}

func TestAuthenticateInvalidAlgo(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, invaldAlgo, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	// 与 keyId 不存在时一样返回 401，否则可以通过状态码探测 keyId 是否存在
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, ErrIncorrectAlgorithm, c.Errors()[0])
}

func TestInvalidSign(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, ErrInvalidSign, c.Errors()[0])
}

// mock interface always return true
type dateAlwaysValid struct{}

func (v *dateAlwaysValid) Validate(r *http.Request) error { return nil }

var mockValidator = []validator.Validator{
	&dateAlwaysValid{},
	validator.NewDigestValidator(),
}

func httpTestGet(c gin.Context) {
	c.JSON(http.StatusOK,
		gin.H{
			"success": true,
		})
}

func httpTestPost(c gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	c.Render(http.StatusOK, render.Data{Data: body})
}

func TestHttpInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.GET("/", httpTestGet)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestHttpInvalidDigest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/", strings.NewReader(sampleBodyContent))
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyFalseDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHttpValidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.GET("/", httpTestGet)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHttpValidRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	println(secrets)
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))

	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/", strings.NewReader(sampleBodyContent))
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := io.ReadAll(w.Result().Body)
	assert.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

func TestHttpValidRequestHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	requestURL := fmt.Sprintf("http://%s/", requestHost)
	req, err := http.NewRequestWithContext(context.Background(), "POST", requestURL, strings.NewReader(sampleBodyContent))
	assert.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader2, requestHostSig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := io.ReadAll(w.Result().Body)
	assert.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

type failingAlgo struct{}

func (failingAlgo) Name() string                        { return "failing" }
func (failingAlgo) Sign(string, string) ([]byte, error) { return nil, errors.New("sign failed") }

func TestAuthenticatedSignError(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	req.Header.Set(authorizationHeader, generateSignature(readID, "failing", submitHeader, requestNilBodySig))
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(Secrets{readID: &Secret{Key: "1234", Algorithm: failingAlgo{}}}, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusInternalServerError, c.Response().Status())
	assert.EqualError(t, c.Errors()[0], "sign failed")
}

// 存在与不存在的 keyId，在 algorithm 错误或签名错误时响应必须完全一致，不能据此探测 keyId
func TestAuthenticateDoesNotRevealKeyIDExistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(NewAuthenticator(secrets, WithValidator()).Authenticated())
	r.GET("/", func(c gin.Context) {})

	do := func(id KeyID, algo string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
		req.Header.Set(authorizationHeader, generateSignature(id, algo, submitHeader, "AAAA"))
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	for _, algo := range []string{"bogus-algo", algoHmacSha512, ""} {
		known, unknown := do(readID, algo), do("no-such-key", algo)
		assert.Equal(t, http.StatusUnauthorized, known.Code, "algorithm %q", algo)
		assert.Equal(t, known.Code, unknown.Code, "algorithm %q", algo)
		assert.Equal(t, known.Body.String(), unknown.Body.String(), "algorithm %q", algo)
	}

	// 能区分 keyId 是否存在的错误只供服务端排查，不能标记为可公开
	assert.True(t, ErrInvalidKeyID.IsType(gin.ErrorTypePrivate))
	assert.True(t, ErrIncorrectAlgorithm.IsType(gin.ErrorTypePrivate))
}

func TestWithRequireAlgorithm(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	require.NoError(t, err)
	req.Header.Set(authorizationHeader, generateSignature(readID, "", submitHeader, requestNilBodySig))
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))

	// 默认允许省略 algorithm（签名算法取自服务端配置）
	c := runTest(secrets, requiredHeaders, []validator.Validator{}, req)
	assert.NotEqual(t, http.StatusUnauthorized, c.Response().Status())

	// WithValidator() 不传参数时使用默认的日期与摘要校验器，需要当前时间的 Date 头
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	auth := NewAuthenticator(secrets, WithRequiredHeaders(requiredHeaders), WithValidator(), WithRequireAlgorithm())
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.SetRequest(req)
	auth.Authenticated()(c2)
	assert.Equal(t, http.StatusUnauthorized, c2.Response().Status())
	assert.Equal(t, ErrMissingAlgorithm, c2.Errors()[0])
}
