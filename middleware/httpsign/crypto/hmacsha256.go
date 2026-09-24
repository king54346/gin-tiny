package crypto

import "crypto/sha256"

const algoHmacSha256 = "hmac-sha256"

// HmacSha256 signing algorithm using hmac and sha256
type HmacSha256 struct{}

// Sign return signing of input msg with secret string
func (h *HmacSha256) Sign(msg string, secret string) ([]byte, error) {
	return sign(sha256.New, msg, secret)
}

// Name return name of algorithm
func (h *HmacSha256) Name() string {
	return algoHmacSha256
}
