package httpsign

import "gin-tiny/middleware/httpsign/crypto"

// KeyID 选择哪一个算法
type KeyID string

// Secret secret.Algorithm.Sign(signString, Key)
type Secret struct {
	Key       string
	Algorithm crypto.Crypto
}

// Secrets map with keyID and secret
type Secrets map[KeyID]*Secret
