package crypto

import (
	"crypto/sha3"
	"hash"
)

// shakeHash 把可变长输出的 SHAKE 包装成固定输出长度的 hash.Hash，供 hmac 使用
type shakeHash struct {
	shake     *sha3.SHAKE
	newShake  func() *sha3.SHAKE
	size      int
	blockSize int
}

func (s *shakeHash) Write(p []byte) (int, error) { return s.shake.Write(p) }
func (s *shakeHash) Reset()                      { s.shake.Reset() }
func (s *shakeHash) Size() int                   { return s.size }
func (s *shakeHash) BlockSize() int              { return s.blockSize }

// Sum 按 hash.Hash 约定不能改变内部状态，而 SHAKE 的 Read 会推进状态，
// 所以先在状态副本上读取输出
func (s *shakeHash) Sum(b []byte) []byte {
	state, err := s.shake.MarshalBinary()
	if err != nil {
		panic("crypto: shake MarshalBinary failed: " + err.Error())
	}
	clone := s.newShake()
	if err := clone.UnmarshalBinary(state); err != nil {
		panic("crypto: shake UnmarshalBinary failed: " + err.Error())
	}
	out := make([]byte, s.size)
	_, _ = clone.Read(out)
	return append(b, out...)
}

func newShakeHash(newShake func() *sha3.SHAKE, size, blockSize int) func() hash.Hash {
	return func() hash.Hash {
		return &shakeHash{shake: newShake(), newShake: newShake, size: size, blockSize: blockSize}
	}
}
