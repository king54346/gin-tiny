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
  "github.com/gin-contrib/httpsign"
  "github.com/gin-contrib/httpsign/crypto"
  "github.com/gin-gonic/gin"
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
