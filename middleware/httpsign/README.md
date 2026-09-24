gin框架中的httpsign中间件实现了HTTP签名验证,可以用来验证请求者身份。

HTTP签名(HTTP Signature)是一种安全机制,通过添加签名到HTTP请求中,让服务端可以验证该请求确实来自预期的客户端。

httpsign中间件的使用流程是:

1.客户端使用私钥和请求内容生成签名,添加到请求头中。
2.服务器端使用注册的公钥验证请求签名。
3.如果签名验证失败,httpsign中间件将返回401 Unauthorized。
4.验证成功则请求通过,调用后续handler。
5.添加httpsign中间件后,可以保证接受到的请求确实来自已知客户端,防止请求伪造。

并且不需要在请求中发送客户端证书或密钥,更加高效安全。
通过控制访问公钥,也可以实现细粒度的访问控制。


## Example

``` go

package main

import (
  "github.com/king54346/gin-tiny/middleware/httpsign"
  "github.com/king54346/gin-tiny/middleware/httpsign/crypto"
  gin "github.com/king54346/gin-tiny"
)

func main() {
  // Define algorithm
  hmacsha256 := &crypto.HmacSha256{}
  hmacsha512 := &crypto.HmacSha512{}
  // Init define secret params
  readKeyID := httpsign.KeyID("read")
  writeKeyID := httpsign.KeyID("write")
  secrets := httpsign.Secrets{
    readKeyID: &httpsign.Secret{
      Key:       "HMACSHA256-SecretKey",
      Algorithm: hmacsha256, // You could using other algo with interface Crypto
    },
    writeKeyID: &httpsign.Secret{
      Key:       "HMACSHA512-SecretKey",
      Algorithm: hmacsha512,
    },
  }

  // Init server
  r := gin.Default()

  //Create middleware with default rule. Could modify by parse Option func
  auth := httpsign.NewAuthenticator(secrets)

  r.Use(auth.Authenticated())
  r.GET("/a", a)
  r.POST("/b", b)
  r.POST("/c", c)

  r.Run(":8080")
}
```

## 支持的算法与兼容性

| 算法名 (`algorithm`) | 类型 | 可与其他实现互通 |
|---|---|---|
| `hmac-sha256` | `crypto.HmacSha256` | ✅ 标准 HMAC-SHA256 |
| `hmac-sha512` | `crypto.HmacSha512` | ✅ 标准 HMAC-SHA512 |
| `hmac-blake2b256` / `hmac-blake2b512` / `hmac-blake2c256` | `crypto.HmacBlake2*` | ✅ 标准 HMAC + BLAKE2 |
| `hmac-shake128` / `hmac-shake256` | `crypto.HmacShake*` | ⚠️ **否** |

> ⚠️ **HMAC-SHAKE 为非标准实现，不要用于跨实现的互通场景。**
> 为保持与历史签名结果一致，`hmac-shake128` / `hmac-shake256` 使用的 HMAC 块大小分别为 128 / 256 字节，
> 而 SHAKE128 / SHAKE256 的标准块大小（rate）是 168 / 136 字节，因此产出的 MAC 与其他语言或库的 HMAC-SHAKE 实现**不一致**。
> 只在客户端和服务端都使用本框架时使用；新项目请优先选择 `hmac-sha256` 或 `hmac-sha512`。

## 安全行为说明

- keyId 不存在、`algorithm` 与服务端配置不符、签名错误，一律返回 **401**，并且都会执行一次签名计算，
  避免通过状态码或响应耗时探测哪些 keyId 存在。区分具体原因的 `ErrInvalidKeyID` / `ErrIncorrectAlgorithm`
  是 `ErrorTypePrivate`，只用于服务端日志，不要回显给客户端。
- 签名算法始终取自服务端为该 keyId 配置的 `Secret.Algorithm`，客户端省略 `algorithm` 参数不会导致算法降级
  （规范也允许省略）。如需强制携带，使用 `httpsign.WithRequireAlgorithm()`。
- 签名头中同一参数重复出现（如两个 `keyId`）会被拒绝，防止网关与应用解析出不同的值。
- 摘要校验在签名校验之前执行，读取请求体有上限（`validator.DefaultMaxBodySize`，10 MiB），
  可通过 `&validator.DigestValidator{MaxBodySize: n}` 调整。
