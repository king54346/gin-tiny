package cors

import (
	"errors"
	"slices"
	"strings"
	"time"

	gin "github.com/king54346/gin-tiny"
)

// Config represents all available options for the middleware.
type Config struct {
	// AllowOriginFunc is a custom function to validate the origin. It take the origin
	// as argument and returns true if allowed or false otherwise. If this option is
	// set, the content of AllowOrigins is ignored.
	AllowOriginFunc func(origin string) bool
	// AllowOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// Default value is []
	AllowOrigins []string
	// AllowMethods is a list of methods the client is allowed to use with
	// cross-domain requests. Default value is simple methods (GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS)
	AllowMethods []string
	// AllowHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	AllowHeaders []string
	// ExposeHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposeHeaders []string
	// MaxAge indicates how long (with second-precision) the results of a preflight request
	// can be cached
	MaxAge          time.Duration
	AllowAllOrigins bool
	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool
	// Allows to add origins like http://some-domain/*, https://api.* or http://some.*.subdomain.com
	AllowWildcard bool
	// Allows usage of popular browser extensions schemas
	AllowBrowserExtensions bool
	// Allows usage of WebSocket protocol
	AllowWebSockets bool
	// Allows usage of file:// schema (dangerous!) use it only when you 100% sure it's needed
	AllowFiles bool
}

// AddAllowMethods is allowed to add custom methods
func (c *Config) AddAllowMethods(methods ...string) {
	c.AllowMethods = append(c.AllowMethods, methods...)
}

// AddAllowHeaders is allowed to add custom headers
func (c *Config) AddAllowHeaders(headers ...string) {
	c.AllowHeaders = append(c.AllowHeaders, headers...)
}

// AddExposeHeaders is allowed to add custom expose headers
func (c *Config) AddExposeHeaders(headers ...string) {
	c.ExposeHeaders = append(c.ExposeHeaders, headers...)
}

func (c Config) getAllowedSchemas() []string {
	// Clone 一份再 append，避免写入全局 DefaultSchemas 的底层数组
	allowedSchemas := slices.Clone(DefaultSchemas)
	if c.AllowBrowserExtensions {
		allowedSchemas = append(allowedSchemas, ExtensionSchemas...)
	}
	if c.AllowWebSockets {
		allowedSchemas = append(allowedSchemas, WebSocketSchemas...)
	}
	if c.AllowFiles {
		allowedSchemas = append(allowedSchemas, FileSchemas...)
	}
	return allowedSchemas
}

func (c Config) validateAllowedSchemas(origin string) bool {
	allowedSchemas := c.getAllowedSchemas()
	for _, schema := range allowedSchemas {
		if strings.HasPrefix(origin, schema) {
			return true
		}
	}
	return false
}

// Validate is check configuration of user defined.
func (c Config) Validate() error {
	if c.AllowAllOrigins && (c.AllowOriginFunc != nil || len(c.AllowOrigins) > 0) {
		return errors.New("conflict settings: all origins are allowed. AllowOriginFunc or AllowOrigins is not needed")
	}
	if !c.AllowAllOrigins && c.AllowOriginFunc == nil && len(c.AllowOrigins) == 0 {
		return errors.New("conflict settings: all origins disabled")
	}
	for _, origin := range c.AllowOrigins {
		if !strings.Contains(origin, "*") && !c.validateAllowedSchemas(origin) {
			return errors.New("bad origin: origins must contain '*' or include " + strings.Join(c.getAllowedSchemas(), ","))
		}
	}
	return nil
}

// wildcardRule 表示一条带单个 * 的来源规则，* 两侧分别为 prefix 和 suffix：
// "*.example.com" → ("", ".example.com")，"https://example.*" → ("https://example.", "")
type wildcardRule struct {
	prefix, suffix string
}

// match 要求 origin 同时以 prefix 开头、以 suffix 结尾，且两者不能重叠
func (w wildcardRule) match(origin string) bool {
	return len(origin) >= len(w.prefix)+len(w.suffix) &&
		strings.HasPrefix(origin, w.prefix) &&
		strings.HasSuffix(origin, w.suffix)
}

func (c Config) parseWildcardRules() []wildcardRule {
	if !c.AllowWildcard {
		return nil
	}

	var rules []wildcardRule
	for _, o := range c.AllowOrigins {
		prefix, suffix, found := strings.Cut(o, "*")
		if !found {
			continue
		}
		if strings.Contains(suffix, "*") {
			panic("only one * is allowed")
		}
		rules = append(rules, wildcardRule{prefix: prefix, suffix: suffix})
	}
	return rules
}

// DefaultConfig returns a generic default configuration mapped to localhost.
func DefaultConfig() Config {
	return Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
}

// Default returns the location middleware with default configuration.
func Default() gin.HandlerFunc {
	config := DefaultConfig()
	config.AllowAllOrigins = true
	return New(config)
}

// New returns the location middleware with user-defined custom configuration.
func New(config Config) gin.HandlerFunc {
	cors := newCors(config)
	return func(c gin.Context) {
		cors.applyCors(c)
	}
}
