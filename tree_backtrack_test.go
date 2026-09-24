package ginTiny

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refMatch 是用于对照的参考匹配器，语义直观但效率低：
// 逐段比较路由与请求路径，:param 匹配一个非空段，*catchAll 匹配剩余全部（以 / 开头）。
// 多条路由都能匹配时，逐段比较段的类型，静态段 > 参数段 > catch-all，第一个不同的段决定优先级。
// radix 树通过「静态子节点优先 + 失败时回溯」实现的应当正是这个语义。
func refMatch(routes []string, path string) (route string, params Params, ok bool) {
	bestRank := ""
	for _, r := range routes {
		ps, rank, matched := refMatchOne(r, path)
		if !matched {
			continue
		}
		if !ok || rank < bestRank {
			route, params, bestRank, ok = r, ps, rank, true
		}
	}
	return
}

// refMatchOne 返回匹配到的参数，以及由各段类型组成的排序键（'0' 静态，'1' 参数，'2' catch-all）
func refMatchOne(route, path string) (Params, string, bool) {
	rSegs := strings.Split(route, "/")[1:]
	pSegs := strings.Split(path, "/")[1:]
	var ps Params
	var rank strings.Builder
	for i, rs := range rSegs {
		switch {
		case strings.HasPrefix(rs, "*"):
			rank.WriteByte('2')
			ps = append(ps, Param{Key: rs[1:], Value: "/" + strings.Join(pSegs[i:], "/")})
			return ps, rank.String(), i < len(pSegs)
		case i >= len(pSegs):
			return nil, "", false
		case strings.HasPrefix(rs, ":"):
			if pSegs[i] == "" {
				return nil, "", false
			}
			rank.WriteByte('1')
			ps = append(ps, Param{Key: rs[1:], Value: pSegs[i]})
		default:
			if rs != pSegs[i] {
				return nil, "", false
			}
			rank.WriteByte('0')
		}
	}
	return ps, rank.String(), len(rSegs) == len(pSegs)
}

// lookup 只做路由匹配（不做重定向），返回匹配到的路由与参数
func lookup(root *node, path string) (string, Params, bool) {
	params := make(Params, 0, 8)
	skipped := make([]skippedNode, 0, 8)
	v := root.getValue(path, &params, &skipped, false)
	if v.handlers == nil {
		return "", nil, false
	}
	var ps Params
	if v.params != nil {
		ps = *v.params
	}
	return v.fullPath, ps, true
}

func buildTree(t *testing.T, routes []string) (*node, []string) {
	t.Helper()
	root := &node{}
	var added []string
	for _, r := range routes {
		func() {
			// 与已有路由冲突的组合会在注册时 panic（例如同一位置两个不同名的参数），跳过即可
			defer func() { _ = recover() }()
			root.addRoute(r, fakeHandler(r))
			added = append(added, r)
		}()
	}
	return root, added
}

func assertSameAsReference(t *testing.T, root *node, routes []string, path string) {
	t.Helper()
	wantRoute, wantParams, wantOK := refMatch(routes, path)
	gotRoute, gotParams, gotOK := lookup(root, path)
	if !assert.Equal(t, wantOK, gotOK, "routes=%q path=%q (want %q)", routes, path, wantRoute) || !wantOK {
		return
	}
	assert.Equal(t, wantRoute, gotRoute, "routes=%q path=%q", routes, path)
	assert.Equal(t, wantParams, gotParams, "routes=%q path=%q", routes, path)
}

func TestTreeBacktrackingKnownCases(t *testing.T) {
	cases := []struct {
		routes []string
		path   string
	}{
		// 静态分支在参数节点处耗尽路径，但该参数节点没有 handler，需要回溯到上层的 :id
		{[]string{"/users/:id/posts/:post", "/users/new/posts/:post/y"}, "/users/new/posts/9"},
		// 静态分支的参数节点还有剩余路径，但没有子节点，需要回溯
		{[]string{"/users/:id/:a/z", "/users/new/:b"}, "/users/new/1/z"},
		// 多层回溯：最近的回溯点也失败，需要继续回到更早的回溯点
		{[]string{"/a/:x/b/:y/c", "/a/s/b/:y", "/a/s/b/t/d"}, "/a/s/b/t/c"},
		// 回溯后参数必须被正确截断，不能残留失败分支中捕获的参数
		{[]string{"/p/:id/:name", "/p/new/:x/deep"}, "/p/new/abc"},
		// 仍然优先匹配静态分支
		{[]string{"/users/:id/posts/:post", "/users/new/posts/:post"}, "/users/new/posts/9"},
	}
	for _, tc := range cases {
		root, added := buildTree(t, tc.routes)
		require.Len(t, added, len(tc.routes), "all routes must register: %q", tc.routes)
		assertSameAsReference(t, root, added, tc.path)
	}
}

// 随机生成路由集合和请求，与参考匹配器逐一比对
func TestTreeMatchesReferenceRandomized(t *testing.T) {
	statics := []string{"a", "b", "new", "posts", "x"}
	params := []string{":id", ":name"}

	randRoute := func(rng *rand.Rand) string {
		n := 1 + rng.IntN(4)
		segs := make([]string, n)
		for i := range segs {
			switch k := rng.IntN(10); {
			case k < 6:
				segs[i] = statics[rng.IntN(len(statics))]
			case k < 9 || i < n-1:
				// 同一位置的参数名在不同路由间必须一致，否则注册冲突；按位置固定参数名
				segs[i] = params[i%len(params)] + fmt.Sprint(i)
			default:
				segs[i] = "*rest"
			}
		}
		return "/" + strings.Join(segs, "/")
	}
	randPath := func(rng *rand.Rand) string {
		n := 1 + rng.IntN(5)
		segs := make([]string, n)
		for i := range segs {
			if rng.IntN(3) == 0 {
				segs[i] = []string{"v1", "zz", "9"}[rng.IntN(3)]
			} else {
				segs[i] = statics[rng.IntN(len(statics))]
			}
		}
		return "/" + strings.Join(segs, "/")
	}

	for seed := range uint64(3000) {
		rng := rand.New(rand.NewPCG(seed, seed*7+1))
		var routes []string
		for range 2 + rng.IntN(6) {
			routes = append(routes, randRoute(rng))
		}
		root, added := buildTree(t, routes)
		if len(added) == 0 {
			continue
		}
		for range 20 {
			path := randPath(rng)
			if rng.IntN(3) == 0 {
				// 以已注册路由为模板生成请求，保证有足够多的命中
				path = strings.NewReplacer(":id0", "v1", ":name1", "zz", ":id2", "9", ":name3", "new", "*rest", "tail/x").Replace(added[rng.IntN(len(added))])
			}
			assertSameAsReference(t, root, added, path)
		}
		if t.Failed() {
			t.Logf("first failing seed: %d", seed)
			return
		}
	}
}

// 第一个分支失败时给出了尾斜杠建议，回溯后的分支也失败：最终仍要保留这个建议，
// 否则修复前能正确 301 的请求会变成 404
func TestTreeBacktrackKeepsEarlierTSR(t *testing.T) {
	root, added := buildTree(t, []string{"/a/new/:x/", "/a/:id/b/c"})
	require.Len(t, added, 2)

	v := root.getValue("/a/new/1", getParams(), getSkippedNodes(), false)
	assert.Nil(t, v.handlers)
	assert.True(t, v.tsr, "/a/new/1/ exists, a trailing slash redirect must be suggested")

	// 通过 Engine 验证最终的重定向行为
	r := New()
	r.GET("/a/new/:x/", func(c Context) {})
	r.GET("/a/:id/b/c", func(c Context) {})
	w := PerformRequest(r, "GET", "/a/new/1")
	assert.Equal(t, 301, w.Code)
	assert.Equal(t, "/a/new/1/", w.Header().Get("Location"))
}

// 通过 Engine 验证修复后的完整行为
func TestEngineBacktracksToParamRoute(t *testing.T) {
	r := New()
	r.GET("/users/:id/posts/:post", func(c Context) {
		c.String(200, "%s/%s", c.Param("id"), c.Param("post"))
	})
	r.GET("/users/new/posts/:post/y", func(c Context) { c.String(200, "y:%s", c.Param("post")) })

	assert.Equal(t, "new/9", PerformRequest(r, "GET", "/users/new/posts/9").Body.String())
	assert.Equal(t, "y:9", PerformRequest(r, "GET", "/users/new/posts/9/y").Body.String())
	assert.Equal(t, "7/9", PerformRequest(r, "GET", "/users/7/posts/9").Body.String())
}
