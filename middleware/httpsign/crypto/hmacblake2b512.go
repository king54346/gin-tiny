package crypto

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

const algoHmacBlake2b512 = "hmac-blake2b512"

// HmacBlake2b512 signing algorithm using hmac and blake2b
type HmacBlake2b512 struct{}

// newHash 不带 key 时 blake2b.New512 不会返回错误
func (h *HmacBlake2b512) newHash() hash.Hash {
	hasher, _ := blake2b.New512(nil)
	return hasher
}

// Sign return signing of input msg with secret string
func (h *HmacBlake2b512) Sign(msg string, secret string) ([]byte, error) {
	return sign(h.newHash, msg, secret)
}

// Name return name of algorithm
func (h *HmacBlake2b512) Name() string {
	return algoHmacBlake2b512
}
