package crypto

import (
	"crypto/hmac"
	"hash"
)

// Crypto interface for signing algorithm
type Crypto interface {
	Name() string
	Sign(msg string, secret string) ([]byte, error)
}

// sign 是各 HMAC 算法的公共实现。
// newHash 每次调用都必须返回新的 hash 实例：hmac 内部会分别为 inner/outer 各取一个，
// 返回同一个实例时标准库会直接 panic
func sign(newHash func() hash.Hash, msg, secret string) ([]byte, error) {
	mac := hmac.New(newHash, []byte(secret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}
