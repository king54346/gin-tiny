package crypto

import (
	"crypto/hmac"
	"golang.org/x/crypto/sha3"
	"hash"
)

const algoHmacShake256 = "hmac-shake256"

// HmacShake256 signing algorithm using hmac and sha256
type HmacShake256 struct{}

type shake256Wrapper struct {
	shake sha3.ShakeHash
}

func newHmacShake256() hash.Hash {
	return &shake256Wrapper{shake: sha3.NewShake256()}
}

func (s *shake256Wrapper) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}

func (s *shake256Wrapper) Sum(b []byte) []byte {
	sum := make([]byte, 32)
	s.shake.Read(sum)
	return append(b, sum...)
}

func (s *shake256Wrapper) Reset() {
	s.shake.Reset()
}

func (s *shake256Wrapper) Size() int {
	return 32
}

func (s *shake256Wrapper) BlockSize() int {
	return 256
}

// Sign return signing of input msg with secret string
func (h *HmacShake256) Sign(msg string, secret string) ([]byte, error) {
	mac := hmac.New(newHmacShake256, []byte(secret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Name return name of algorithm
func (h *HmacShake256) Name() string {
	return algoHmacShake256
}
