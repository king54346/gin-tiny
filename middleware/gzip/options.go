package gzip

import (
	"compress/gzip"
	"errors"
	gin "github.com/king54346/gin-tiny"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

var (
	DefaultExcludedExtentions = NewExcludedExtensions([]string{
		".png", ".gif", ".jpeg", ".jpg",
	})
	DefaultOptions = &Options{
		ExcludedExtensions: DefaultExcludedExtentions,
	}
)

type Options struct {
	ExcludedExtensions   ExcludedExtensions
	ExcludedPaths        ExcludedPaths
	ExcludedPathesRegexs ExcludedPathesRegexs
	DecompressFn         func(c gin.Context)
}

type Option func(*Options)

func WithExcludedExtensions(args []string) Option {
	return func(o *Options) {
		o.ExcludedExtensions = NewExcludedExtensions(args)
	}
}

func WithExcludedPaths(args []string) Option {
	return func(o *Options) {
		o.ExcludedPaths = NewExcludedPaths(args)
	}
}

func WithExcludedPathsRegexs(args []string) Option {
	return func(o *Options) {
		o.ExcludedPathesRegexs = NewExcludedPathesRegexs(args)
	}
}

func WithDecompressFn(decompressFn func(c gin.Context)) Option {
	return func(o *Options) {
		o.DecompressFn = decompressFn
	}
}

// Using map for better lookup performance
type ExcludedExtensions map[string]bool

func NewExcludedExtensions(extensions []string) ExcludedExtensions {
	res := make(ExcludedExtensions)
	for _, e := range extensions {
		res[e] = true
	}
	return res
}

func (e ExcludedExtensions) Contains(target string) bool {
	_, ok := e[target]
	return ok
}

type ExcludedPaths []string

func NewExcludedPaths(paths []string) ExcludedPaths {
	return ExcludedPaths(paths)
}

func (e ExcludedPaths) Contains(requestURI string) bool {
	return slices.ContainsFunc(e, func(path string) bool { return strings.HasPrefix(requestURI, path) })
}

type ExcludedPathesRegexs []*regexp.Regexp

func NewExcludedPathesRegexs(regexs []string) ExcludedPathesRegexs {
	result := make([]*regexp.Regexp, len(regexs))
	for i, reg := range regexs {
		result[i] = regexp.MustCompile(reg)
	}
	return result
}

func (e ExcludedPathesRegexs) Contains(requestURI string) bool {
	return slices.ContainsFunc(e, func(reg *regexp.Regexp) bool { return reg.MatchString(requestURI) })
}

// DefaultDecompressHandle 解压 Content-Encoding: gzip 的请求体，解压后大小不设上限。
// 面向不可信客户端时应改用 DecompressHandleWithLimit，防止很小的 gzip 数据解压出巨量内容（gzip 炸弹）
func DefaultDecompressHandle(c gin.Context) {
	decompressRequest(c, 0)
}

// DecompressHandleWithLimit 与 DefaultDecompressHandle 相同，但解压后超过 maxSize 字节时读取请求体会返回错误
func DecompressHandleWithLimit(maxSize int64) func(c gin.Context) {
	return func(c gin.Context) { decompressRequest(c, maxSize) }
}

func decompressRequest(c gin.Context, maxSize int64) {
	req := c.Request()
	if req.Body == nil || req.Body == http.NoBody {
		return
	}
	gz, err := gzip.NewReader(req.Body)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	req.Header.Del("Content-Encoding")
	req.Header.Del("Content-Length")
	// 解压后的长度未知
	req.ContentLength = -1

	var body io.ReadCloser = &gzipRequestBody{gz: gz, orig: req.Body}
	if maxSize > 0 {
		body = http.MaxBytesReader(c.Response(), body, maxSize)
	}
	req.Body = body
}

// gzipRequestBody 关闭时同时关闭 gzip reader 和原始请求体
type gzipRequestBody struct {
	gz   *gzip.Reader
	orig io.ReadCloser
}

func (b *gzipRequestBody) Read(p []byte) (int, error) { return b.gz.Read(p) }

func (b *gzipRequestBody) Close() error {
	return errors.Join(b.gz.Close(), b.orig.Close())
}
