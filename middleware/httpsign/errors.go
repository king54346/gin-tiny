package httpsign

import (
	"errors"
	gin "github.com/king54346/gin-tiny"
)

func newPublicError(msg string) *gin.Error {
	return &gin.Error{
		Err:  errors.New(msg),
		Type: gin.ErrorTypePublic,
	}
}

// newPrivateError 用于不能展示给客户端的认证失败原因：它们能区分 keyId 是否存在，
// 只记录在 c.Errors 中供服务端排查（ErrorLoggerT(ErrorTypePublic) 等不会输出）
func newPrivateError(msg string) *gin.Error {
	return &gin.Error{
		Err:  errors.New(msg),
		Type: gin.ErrorTypePrivate,
	}
}

var (
	// ErrInvalidAuthorizationHeader error when get invalid format of Authorization header
	ErrInvalidAuthorizationHeader = newPublicError("Authorization header format is incorrect")
	// ErrInvalidKeyID error when KeyID in header does not provided
	ErrInvalidKeyID = newPrivateError("Invalid keyId")
	// ErrDateNotFound error when no date in header
	ErrDateNotFound = newPublicError("There is no Date on Headers")
	// ErrIncorrectAlgorithm error when Algorithm in header does not match with secret key
	ErrIncorrectAlgorithm = newPrivateError("Algorithm does not match")
	// ErrMissingAlgorithm 启用 WithRequireAlgorithm 时签名头缺少 algorithm 参数
	ErrMissingAlgorithm = newPublicError("algorithm must be on header")
	// ErrHeaderNotEnough error when requirements header do not appear on header field
	ErrHeaderNotEnough = newPublicError("Header field is not match requirement")
	// ErrNoSignature error when no Signature not found in header
	ErrNoSignature = newPublicError("No Signature header found in request")
	// ErrInvalidSign error when signing string do not match
	ErrInvalidSign = newPublicError("Invalid sign")
	// ErrMissingKeyID error when keyId not in header
	ErrMissingKeyID = newPublicError("keyId must be on header")
	// ErrDuplicateParameter 签名头中同一参数出现多次
	ErrDuplicateParameter = newPublicError("Duplicate parameter in signature header")
	// ErrMissingSignature error when signature not in header
	ErrMissingSignature = newPublicError("signature must be on header")

	// ErrUnterminatedParameter err when could not parse value
	ErrUnterminatedParameter = newPublicError("Unterminated parameter")
	// ErrMisingDoubleQuote err when after character = not have double quote
	ErrMisingDoubleQuote = newPublicError(`Missing " after = character`)
	// ErrMisingEqualCharacter err when there is no character = before " or , character
	ErrMisingEqualCharacter = newPublicError(`Missing = character =`)
)
