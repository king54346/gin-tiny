package crypto

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

const algoHmacBlake2b256 = "hmac-blake2b256"

// HmacBlake2b256 signing algorithm using hmac and blake2b
type HmacBlake2b256 struct{}

// newHash 不带 key 时 blake2b.New256 不会返回错误
func (h *HmacBlake2b256) newHash() hash.Hash {
	hasher, _ := blake2b.New256(nil)
	return hasher
}

// Sign return signing of input msg with secret string
func (h *HmacBlake2b256) Sign(msg string, secret string) ([]byte, error) {
	return sign(h.newHash, msg, secret)
}

// Name return name of algorithm
func (h *HmacBlake2b256) Name() string {
	return algoHmacBlake2b256
}
