package ginTiny

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	"github.com/king54346/gin-tiny/internal/bytesconv"
)

// AuthUserKey is the cookie name for user credential in basic auth.
const AuthUserKey = "user"

// Accounts defines a key/value for user/pass list of authorized logins.
type Accounts map[string]string

type authPair struct {
	value string
	user  string
}

type authPairs []authPair

func (a authPairs) searchCredential(authValue string) (string, bool) {
	// RFC 7617：认证方案名不区分大小写，方案名与凭据之间可以有多个空格。规范化后再做常数时间比较
	scheme, credentials, ok := strings.Cut(strings.TrimSpace(authValue), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	authValue = "Basic " + strings.TrimSpace(credentials)
	for _, pair := range a {
		if subtle.ConstantTimeCompare(bytesconv.StringToBytes(pair.value), bytesconv.StringToBytes(authValue)) == 1 {
			return pair.user, true
		}
	}
	return "", false
}

// BasicAuthForRealm returns a Basic HTTP Authorization middleware. It takes as arguments a map[string]string where
// the key is the user name and the value is the password, as well as the name of the Realm.
// If the realm is empty, "Authorization Required" will be used by default.
// (see http://tools.ietf.org/html/rfc2617#section-1.2)
func BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc {
	if realm == "" {
		realm = "Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)
	pairs := processAccounts(accounts)
	return func(c Context) {
		// Search user in the slice of allowed credentials
		user, found := pairs.searchCredential(c.RequestHeader("Authorization"))
		if !found {
			// Credentials doesn't match, we return 401 and abort handlers chain.
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// The user credentials was found, set user's id to key AuthUserKey in this context, the user's id can be read later using
		// c.MustGet(gin.AuthUserKey).
		c.Set(AuthUserKey, user)
	}
}

// BasicAuth returns a Basic HTTP Authorization middleware. It takes as argument a map[string]string where
// the key is the user name and the value is the password.
// accounts 为预设的用户名和密码
func BasicAuth(accounts Accounts) HandlerFunc {
	return BasicAuthForRealm(accounts, "")
}

func processAccounts(accounts Accounts) authPairs {
	length := len(accounts)
	assert1(length > 0, "Empty list of authorized credentials")
	pairs := make(authPairs, 0, length)
	for user, password := range accounts {
		assert1(user != "", "User can not be empty")
		value := authorizationHeader(user, password)
		pairs = append(pairs, authPair{
			value: value,
			user:  user,
		})
	}
	return pairs
}

func authorizationHeader(user, password string) string {
	base := user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString(bytesconv.StringToBytes(base))
}

// AuthProxyUserKey 是 BasicAuthForProxy 认证通过后，在 Context 中保存代理用户名使用的 key
const AuthProxyUserKey = "proxy_user"

// BasicAuthForProxy 返回代理认证（Proxy-Authorization）中间件，用于实现 HTTP 正向代理。
// 认证失败时返回 407 Proxy Authentication Required 并附带 Proxy-Authenticate 头；
// 成功时代理用户名可以通过 c.MustGet(gin.AuthProxyUserKey) 读取。realm 为空时使用 "Proxy Authorization Required"
func BasicAuthForProxy(accounts Accounts, realm string) HandlerFunc {
	if realm == "" {
		realm = "Proxy Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)
	pairs := processAccounts(accounts)
	return func(c Context) {
		proxyUser, found := pairs.searchCredential(c.RequestHeader("Proxy-Authorization"))
		if !found {
			c.Header("Proxy-Authenticate", realm)
			c.AbortWithStatus(http.StatusProxyAuthRequired)
			return
		}
		c.Set(AuthProxyUserKey, proxyUser)
	}
}
