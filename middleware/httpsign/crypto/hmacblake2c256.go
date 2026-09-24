package crypto

import (
	"hash"

	"golang.org/x/crypto/blake2s"
)

const algoHmacBlake2c256 = "hmac-blake2c256"

// HmacBlake2c256 signing algorithm using hmac and blake2s
type HmacBlake2c256 struct{}

// newHash 不带 key 时 blake2s.New256 不会返回错误
func (h *HmacBlake2c256) newHash() hash.Hash {
	hasher, _ := blake2s.New256(nil)
	return hasher
}

// Sign return signing of input msg with secret string
func (h *HmacBlake2c256) Sign(msg string, secret string) ([]byte, error) {
	return sign(h.newHash, msg, secret)
}

// Name return name of algorithm
func (h *HmacBlake2c256) Name() string {
	return algoHmacBlake2c256
}
