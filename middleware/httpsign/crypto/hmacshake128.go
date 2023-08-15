package crypto

import (
	"crypto/hmac"
	"golang.org/x/crypto/sha3"
	"hash"
)

const algoHmacShake128 = "hmac-shake128"

// HmacShake128 signing algorithm using hmac and sha128
type HmacShake128 struct{}

type shake128Wrapper struct {
	shake sha3.ShakeHash
}

func newHmacShake128() hash.Hash {
	return &shake128Wrapper{shake: sha3.NewShake128()}
}

func (s *shake128Wrapper) Write(p []byte) (n int, err error) {
	return s.shake.Write(p)
}

func (s *shake128Wrapper) Sum(b []byte) []byte {
	// 你需要决定一个固定的输出长度，这里我们选择32字节，类似于SHA-256
	sum := make([]byte, 16)

	s.shake.Read(sum)
	return append(b, sum...)
}

func (s *shake128Wrapper) Reset() {
	s.shake.Reset()
}

func (s *shake128Wrapper) Size() int {
	return 16
}

func (s *shake128Wrapper) BlockSize() int {
	// SHAKE128 的块大小是 128 字节
	return 128
}

// Sign return signing of input msg with secret string
func (h *HmacShake128) Sign(msg string, secret string) ([]byte, error) {
	mac := hmac.New(newHmacShake128, []byte(secret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// Name return name of algorithm
func (h *HmacShake128) Name() string {
	return algoHmacShake128
}
