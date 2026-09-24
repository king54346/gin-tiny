package crypto

import "crypto/sha512"

const algoHmacSha512 = "hmac-sha512"

// HmacSha512 signing algorithm using hmac and sha512
type HmacSha512 struct{}

// Sign return signing of input msg with secret string
func (h *HmacSha512) Sign(msg string, secret string) ([]byte, error) {
	return sign(sha512.New, msg, secret)
}

// Name return name of algorithm
func (h *HmacSha512) Name() string {
	return algoHmacSha512
}
