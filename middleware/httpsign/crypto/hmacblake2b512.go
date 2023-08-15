package crypto

import (
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"hash"
)

const algoHmacBlake2b512 = "hmac-blake2b512"

type HmacBlake2b512 struct {
}

// Sign return signing of input msg with secret string
func (h *HmacBlake2b512) Sign(msg string, secret string) ([]byte, error) {
	hasher, err := blake2b.New512(nil)
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
func (h *HmacBlake2b512) Name() string {
	return algoHmacBlake2b512
}
