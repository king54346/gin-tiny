package crypto

import "crypto/sha3"

const algoHmacShake128 = "hmac-shake128"

// HmacShake128 signing algorithm using hmac and shake128（输出 16 字节）
//
// 警告：非标准实现，HMAC 块大小为 128 字节（SHAKE128 标准为 168），产出的 MAC 与其他 HMAC-SHAKE128 实现不一致，
// 只能在客户端与服务端都使用本框架时使用。新项目请使用 HmacSha256 / HmacSha512
type HmacShake128 struct{}

// 注意：SHAKE128 的标准块大小（rate）是 168 字节，这里沿用原实现的 128 以保证已有签名结果不变。
// 因此本算法产出的 MAC 与其他 HMAC-SHAKE128 实现不兼容，只能在本框架的客户端与服务端之间使用
var newHmacShake128 = newShakeHash(sha3.NewSHAKE128, 16, 128)

// Sign return signing of input msg with secret string
func (h *HmacShake128) Sign(msg string, secret string) ([]byte, error) {
	return sign(newHmacShake128, msg, secret)
}

// Name return name of algorithm
func (h *HmacShake128) Name() string {
	return algoHmacShake128
}
