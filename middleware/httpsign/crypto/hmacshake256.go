package crypto

import "crypto/sha3"

const algoHmacShake256 = "hmac-shake256"

// HmacShake256 signing algorithm using hmac and shake256（输出 32 字节）
//
// 警告：非标准实现，HMAC 块大小为 256 字节（SHAKE256 标准为 136），产出的 MAC 与其他 HMAC-SHAKE256 实现不一致，
// 只能在客户端与服务端都使用本框架时使用。新项目请使用 HmacSha256 / HmacSha512
type HmacShake256 struct{}

// 注意：SHAKE256 的标准块大小（rate）是 136 字节，这里沿用原实现的 256 以保证已有签名结果不变。
// 因此本算法产出的 MAC 与其他 HMAC-SHAKE256 实现不兼容，只能在本框架的客户端与服务端之间使用
var newHmacShake256 = newShakeHash(sha3.NewSHAKE256, 32, 256)

// Sign return signing of input msg with secret string
func (h *HmacShake256) Sign(msg string, secret string) ([]byte, error) {
	return sign(newHmacShake256, msg, secret)
}

// Name return name of algorithm
func (h *HmacShake256) Name() string {
	return algoHmacShake256
}
