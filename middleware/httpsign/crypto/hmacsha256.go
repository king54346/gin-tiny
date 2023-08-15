package crypto

import (
	"crypto/hmac"
	"golang.org/x/crypto/sha3"
)

const algoHmacSha256 = "hmac-sha256"

// HmacSha256 signing algorithm using hmac and sha256
type HmacSha256 struct{}

// Sign return signing of input msg with secret string
func (h *HmacSha256) Sign(msg string, secret string) ([]byte, error) {
	mac := hmac.New(sha3.New256, []byte(secret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Name return name of algorithm
func (h *HmacSha256) Name() string {
	return algoHmacSha256
}
