package httpsign

import (
	"net/http"
	"strings"
)

const (
	authorizationHeader           = "Authorization"
	authorizationHeaderInitString = "Signature "
	signatureHeader               = "Signature"
	signingKeyID                  = "keyId"
	signingAlgorithm              = "algorithm"
	signingSignature              = "signature"
	signingHeaders                = "headers"
)

// SignatureHeader contains basic info signature header
type SignatureHeader struct {
	keyID     KeyID
	headers   []string
	signature string
	algorithm string
}

// NewSignatureHeader new instance of SignatureHeader
func NewSignatureHeader(r *http.Request) (*SignatureHeader, error) {
	return parseHTTPRequest(r)
}

func parseHTTPRequest(r *http.Request) (*SignatureHeader, error) {
	s, err := getSignatureString(r)
	if err != nil {
		return nil, err
	}
	return parseSignatureString(s)
}

func parseSignatureString(s string) (*SignatureHeader, error) {
	p := newParser(s)
	results, err := p.parse()
	if err != nil {
		return nil, err
	}
	keyID, ok := results[signingKeyID]
	if !ok {
		return nil, ErrMissingKeyID
	}
	signature, ok := results[signingSignature]
	if !ok {
		return nil, ErrMissingSignature
	}
	headerString, ok := results[signingHeaders]
	var headers []string
	if !ok || len(headerString) == 0 {
		headers = []string{"date"}
	} else {
		headers = strings.Split(headerString, " ")
	}

	algorithm := results[signingAlgorithm]

	return &SignatureHeader{
		keyID:     KeyID(keyID),
		signature: signature,
		headers:   headers,
		algorithm: algorithm,
	}, nil
}

func getSignatureString(r *http.Request) (string, error) {
	if s := r.Header.Get(signatureHeader); s != "" {
		return s, nil
	}
	if s := r.Header.Get(authorizationHeader); s != "" {
		sig, ok := strings.CutPrefix(s, authorizationHeaderInitString)
		if !ok {
			return "", ErrInvalidAuthorizationHeader
		}
		return sig, nil
	}
	return "", ErrNoSignature
}
