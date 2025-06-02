package main

import (
	gin "gin-tiny"
	"gin-tiny/middleware/httpsign"
	"gin-tiny/middleware/httpsign/crypto"
)

/*
*

	 header中设置
		date
		digest(验证body的数据是否完整)
		signature ( keyId="read",algorithm="hmac-sha256",headers="(request-target) date digest",signature="base64(hmac-sha256((request-target)+method+uri+date+digest))" )

)
*/
func main() {
	// Define algorithm
	hmacsha256 := &crypto.HmacSha256{}
	hmacsha512 := &crypto.HmacSha512{}
	// Init define secret params
	readKeyID := httpsign.KeyID("read")
	writeKeyID := httpsign.KeyID("write")
	// 定义多个sign算法
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

	// 可以选择一种或多种验证方式
	r.GET("/a", a)
	r.POST("/b", b)
	r.POST("/c", c)

	r.Run(":8080")
}

func c(context *gin.context) {
	context.String(200, "c")
}

func b(context *gin.context) {

}

func a(context *gin.context) {
	context.String(200, "a")
}
