package crypto

import (
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"hash"
)

const algoHmacBlake2b256 = "hmac-blake2b256"

type HmacBlake2b256 struct {
}

// Sign return signing of input msg with secret string
func (h *HmacBlake2b256) Sign(msg string, secret string) ([]byte, error) {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(func() hash.Hash { return hasher }, []byte(secret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

// Name return name of algorithm
func (h *HmacBlake2b256) Name() string {
	return algoHmacBlake2b256
}
