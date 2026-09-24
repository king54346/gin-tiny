// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package ginTiny

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/king54346/gin-tiny/internal/bytesconv"
)

// Param 是一个URL参数，包含一个key和一个value，key代表参数名，value代表参数值
type Param struct {
	Key   string
	Value string
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
type Params []Param

// Get 方法返回第一个匹配的参数值和一个布尔值，如果没有找到匹配的参数，则返回空字符串和布尔值false
// 注意：如果有多个参数具有相同的key，Get方法只会返回第一个匹配的参数值。
func (ps Params) Get(name string) (string, bool) {
	for _, entry := range ps {
		if entry.Key == name {
			return entry.Value, true
		}
	}
	return "", false
}

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
// ByName 返回第一个匹配的参数值，如果没有找到匹配的参数，则返回空字符串。
func (ps Params) ByName(name string) (va string) {
	va, _ = ps.Get(name)
	return
}

func (ps Params) Copy() Params {
	return slices.Clone(ps)
}

// methodTree 是某个 HTTP 方法的路由表：radix 树是唯一的数据源，static 是它的精确匹配索引。
//
// 不含 :param / *catchAll 的路由在插入树之后，会再以完整路径为 key 写入 static。
// 静态路由命中的充要条件就是路径完全相等，而树对同一路径本就优先匹配静态节点，
// 所以先查 static 再查树，结果与只查树完全一致，只是省去了逐层比较前缀的开销。
// 冲突检测、通配符校验、尾斜杠/大小写重定向、405 都仍由树负责，调用方无需感知索引的存在。
type methodTree struct {
	method string
	root   *node
	static map[string]HandlersChain
}

func newMethodTree(method string) *methodTree {
	root := &node{fullPath: "/"}
	return &methodTree{method: method, root: root, static: make(map[string]HandlersChain)}
}

// addRoute 先插入树，重复注册或非法路径会在这里 panic，索引就不会被写脏
func (t *methodTree) addRoute(path string, handlers HandlersChain) {
	t.root.addRoute(path, handlers)
	if isStaticPath(path) {
		t.static[path] = handlers
	}
}

// getValue 先查静态索引（O(1)），未命中再走 radix 树
func (t *methodTree) getValue(path string, params *Params, skippedNodes *[]skippedNode, unescape bool) nodeValue {
	if handlers, ok := t.static[path]; ok {
		return nodeValue{handlers: handlers, fullPath: path}
	}
	return t.root.getValue(path, params, skippedNodes, unescape)
}

// isStaticPath 判断路径是否不含 :param 与 *catchAll
func isStaticPath(path string) bool {
	return !strings.ContainsAny(path, ":*")
}

// methodTrees 标准方法按 methodIndex 下标放在数组里（O(1)，无 map 开销），自定义方法放在 map 中
type methodTrees struct {
	std      [len(standardMethods)]*methodTree
	anyOther map[string]*methodTree // 存储其他HTTP方法的路由树
}

// standardMethods 标准 HTTP 方法，下标与 methodIndex 的返回值一一对应
var standardMethods = [...]string{
	http.MethodConnect,
	http.MethodDelete,
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
	http.MethodPost,
	http.MethodPut,
	http.MethodTrace,
}

// anyMethods 是 Any / StaticRouter 注册的全部方法
var anyMethods = standardMethods[:]

// methodIndex 返回标准方法在 standardMethods 中的下标，非标准方法返回 -1
// 使用 switch 而不是 map，编译器会生成跳转表，避免哈希计算
func methodIndex(method string) int {
	switch method {
	case http.MethodConnect:
		return 0
	case http.MethodDelete:
		return 1
	case http.MethodGet:
		return 2
	case http.MethodHead:
		return 3
	case http.MethodOptions:
		return 4
	case http.MethodPatch:
		return 5
	case http.MethodPost:
		return 6
	case http.MethodPut:
		return 7
	case http.MethodTrace:
		return 8
	}
	return -1
}

func newMethodTrees() *methodTrees {
	return &methodTrees{
		anyOther: make(map[string]*methodTree),
	}
}

// getNotNullMethodTree 返回一个包含所有非空方法树的切片
func (trees *methodTrees) getNotNullMethodTree() []*methodTree {
	if trees == nil {
		return nil
	}

	t := make([]*methodTree, 0, len(trees.std)+len(trees.anyOther))
	for _, tree := range trees.std {
		if tree != nil {
			t = append(t, tree)
		}
	}
	for _, tree := range trees.anyOther {
		t = append(t, tree)
	}
	return t
}

// getTree 获取指定方法的路由表，不存在返回 nil
func (trees *methodTrees) getTree(method string) *methodTree {
	if trees == nil {
		return nil
	}
	if i := methodIndex(method); i >= 0 {
		return trees.std[i]
	}
	return trees.anyOther[method]
}

// getOrCreateTree 获取指定方法的路由表，不存在时创建
func (trees *methodTrees) getOrCreateTree(method string) *methodTree {
	if tree := trees.getTree(method); tree != nil {
		return tree
	}
	tree := newMethodTree(method)
	if i := methodIndex(method); i >= 0 {
		trees.std[i] = tree
	} else {
		trees.anyOther[method] = tree
	}
	return tree
}

// getMethodTree 获取指定方法的路由树根节点
func (trees *methodTrees) getMethodTree(method string) *node {
	if tree := trees.getTree(method); tree != nil {
		return tree.root
	}
	return nil
}

func longestCommonPrefix(a, b string) int {
	i := 0
	m := min(len(a), len(b))
	for i < m && a[i] == b[i] {
		i++
	}
	return i
}

// addChild will add a child node, keeping wildcardChild at the end
func (n *node) addChild(child *node) {
	if n.wildChild && len(n.children) > 0 {
		wildcardChild := n.children[len(n.children)-1]
		n.children = append(n.children[:len(n.children)-1], child, wildcardChild)
	} else {
		n.children = append(n.children, child)
	}
}

// 统计path中的参数个数
// strings.Count 对单字节子串走的就是 bytealg 快速路径，无需 unsafe 转换
func countParams(path string) uint16 {
	return uint16(strings.Count(path, ":") + strings.Count(path, "*"))
}

func countSections(path string) uint16 {
	return uint16(strings.Count(path, "/"))
}

type nodeType uint8

const (
	static nodeType = iota
	root
	param
	catchAll
)

// 路由树的节点
type node struct {
	path      string
	indices   string // 子节点的path第一个字符拼接的字符串
	wildChild bool
	nType     nodeType
	priority  uint32        //后继节点数
	children  []*node       // 路径更多的节点排在前面
	handlers  HandlersChain // 处理程序链
	fullPath  string        //path拼接上面前缀后的完整路径
}

// Increments priority of the given child and reorders if necessary
func (n *node) incrementChildPrio(pos int) int {
	cs := n.children
	cs[pos].priority++
	prio := cs[pos].priority

	// 调整子节点的顺序，使得priority大的排在前面
	newPos := pos
	for ; newPos > 0 && cs[newPos-1].priority < prio; newPos-- {
		// Swap node positions
		cs[newPos-1], cs[newPos] = cs[newPos], cs[newPos-1]
	}

	// 调整子节点的顺序后，需要调整indices
	if newPos != pos {
		n.indices = n.indices[:newPos] + // Unchanged prefix, might be empty
			n.indices[pos:pos+1] + // The index char we move
			n.indices[newPos:pos] + n.indices[pos+1:] // Rest without char at 'pos'
	}

	return newPos
}

// addRoute方法将一个节点添加到路由树中，路径为path，处理程序为handlers
func (n *node) addRoute(path string, handlers HandlersChain) {
	fullPath := path
	n.priority++

	//检查当前节点是否为空，如果是，则插入子节点并返回。
	if len(n.path) == 0 && len(n.children) == 0 {
		n.insertChild(path, fullPath, handlers)
		n.nType = root
		return
	}

	parentFullPathIndex := 0

walk:
	for {
		// Find the longest common prefix.
		// This also implies that the common prefix contains no ':' or '*'
		// since the existing key can't contain those chars.
		i := longestCommonPrefix(path, n.path)
		// 如果最长公共前缀小于node.path的长度，代表node需要分裂
		// 例如：node.path = /contact, path = /co，最长公共前缀为1
		// 需要将node分裂为两个节点，/co，/ntact

		if i < len(n.path) {
			//原节点分裂后的非公共部分/ntact
			child := node{
				path:      n.path[i:],
				wildChild: n.wildChild,
				nType:     static,
				indices:   n.indices, // indices转移到新节点
				children:  n.children,
				handlers:  n.handlers,
				priority:  n.priority - 1, // priority减1是因为之前新节点添加时加过1
				fullPath:  n.fullPath,
			}

			n.children = []*node{&child}
			// 设置公共部分的indices的值为子节点的第一个字符
			n.indices = bytesconv.BytesToString([]byte{n.path[i]})
			// 调整原来的节点的path为公共部分
			n.path = path[:i]
			n.handlers = nil
			n.wildChild = false
			n.fullPath = fullPath[:parentFullPathIndex+i]
		}

		// 新节点插入到原节点的子节点中
		if i < len(path) {
			path = path[i:]
			c := path[0]

			// '/' after param
			if n.nType == param && c == '/' && len(n.children) == 1 {
				parentFullPathIndex += len(n.path)
				n = n.children[0]
				n.priority++
				continue walk
			}

			//indices辅助判断,其子节点是否与当前path的公共前缀相同
			for i, max := 0, len(n.indices); i < max; i++ {
				//	如果还有公共前缀,令node=child,继续循环
				if c == n.indices[i] {
					parentFullPathIndex += len(n.path)
					i = n.incrementChildPrio(i)
					n = n.children[i]
					continue walk
				}
			}

			// Otherwise insert it
			if c != ':' && c != '*' && n.nType != catchAll {

				//node和path没有公共前缀,则插入新节点
				n.indices += bytesconv.BytesToString([]byte{c})
				child := &node{
					fullPath: fullPath,
				}
				n.addChild(child)
				n.incrementChildPrio(len(n.indices) - 1)
				//child成为新的node,插入path到child中
				n = child
			} else if n.wildChild {
				// inserting a wildcard node, need to check if it conflicts with the existing wildcard
				n = n.children[len(n.children)-1]
				n.priority++

				// Check if the wildcard matches
				if len(path) >= len(n.path) && n.path == path[:len(n.path)] &&
					// Adding a child to a catchAll is not possible
					n.nType != catchAll &&
					// Check for longer wildcard, e.g. :name and :names
					(len(n.path) >= len(path) || path[len(n.path)] == '/') {
					continue walk
				}

				// Wildcard conflict
				pathSeg := path
				if n.nType != catchAll {
					pathSeg = strings.SplitN(pathSeg, "/", 2)[0]
				}
				prefix := fullPath[:strings.Index(fullPath, pathSeg)] + n.path
				panic("'" + pathSeg +
					"' in new path '" + fullPath +
					"' conflicts with existing wildcard '" + n.path +
					"' in existing prefix '" + prefix +
					"'")
			}

			n.insertChild(path, fullPath, handlers)
			return
		}

		// Otherwise add handle to current node
		if n.handlers != nil {
			panic("handlers are already registered for path '" + fullPath + "'")
		}
		n.handlers = handlers
		n.fullPath = fullPath
		return
	}
}

// Search for a wildcard segment and check the name for invalid characters.
// Returns -1 as index, if no wildcard was found.
func findWildcard(path string) (wildcard string, i int, valid bool) {
	// Find start
	for start, c := range []byte(path) {
		// A wildcard starts with ':' (param) or '*' (catch-all)
		if c != ':' && c != '*' {
			continue
		}

		// Find end and check for invalid characters
		valid = true
		for end, c := range []byte(path[start+1:]) {
			switch c {
			case '/':
				return path[start : start+1+end], start, valid
			case ':', '*':
				valid = false
			}
		}
		return path[start:], start, valid
	}
	return "", -1, false
}

func (n *node) insertChild(path string, fullPath string, handlers HandlersChain) {
	for {
		// Find prefix until first wildcard
		wildcard, i, valid := findWildcard(path)
		if i < 0 { // No wildcard found
			break
		}

		// The wildcard name must only contain one ':' or '*' character
		if !valid {
			panic("only one wildcard per path segment is allowed, has: '" +
				wildcard + "' in path '" + fullPath + "'")
		}

		// check if the wildcard has a name
		if len(wildcard) < 2 {
			panic("wildcards must be named with a non-empty name in path '" + fullPath + "'")
		}

		if wildcard[0] == ':' { // param
			if i > 0 {
				// Insert prefix before the current wildcard
				n.path = path[:i]
				path = path[i:]
			}

			child := &node{
				nType:    param,
				path:     wildcard,
				fullPath: fullPath,
			}
			n.addChild(child)
			n.wildChild = true
			n = child
			n.priority++

			// if the path doesn't end with the wildcard, then there
			// will be another subpath starting with '/'
			if len(wildcard) < len(path) {
				path = path[len(wildcard):]

				child := &node{
					priority: 1,
					fullPath: fullPath,
				}
				n.addChild(child)
				n = child
				continue
			}

			// Otherwise we're done. Insert the handle in the new leaf
			n.handlers = handlers
			return
		}

		// catchAll
		if i+len(wildcard) != len(path) {
			panic("catch-all routes are only allowed at the end of the path in path '" + fullPath + "'")
		}

		if len(n.path) > 0 && n.path[len(n.path)-1] == '/' {
			pathSeg := strings.SplitN(n.children[0].path, "/", 2)[0]
			panic("catch-all wildcard '" + path +
				"' in new path '" + fullPath +
				"' conflicts with existing path segment '" + pathSeg +
				"' in existing prefix '" + n.path + pathSeg +
				"'")
		}

		// currently fixed width 1 for '/'
		i--
		if path[i] != '/' {
			panic("no / before catch-all in path '" + fullPath + "'")
		}

		n.path = path[:i]

		// First node: catchAll node with empty path
		child := &node{
			wildChild: true,
			nType:     catchAll,
			fullPath:  fullPath,
		}

		n.addChild(child)
		n.indices = string('/')
		n = child
		n.priority++

		// second node: node holding the variable
		child = &node{
			path:     path[i:],
			nType:    catchAll,
			handlers: handlers,
			priority: 1,
			fullPath: fullPath,
		}
		n.children = []*node{child}

		return
	}

	// If no wildcard was found, simply insert the path and handle
	n.path = path
	n.handlers = handlers
	n.fullPath = fullPath
}

// nodeValue holds return values of (*Node).getValue method
type nodeValue struct {
	handlers HandlersChain
	params   *Params
	tsr      bool // 表示是否需要处理尾部斜杠重定向
	fullPath string
}

type skippedNode struct {
	path        string
	node        *node
	paramsCount int16
}

// getValue 从路由树中获取对应的处理程序
// 优化版本：减少内存分配，提高性能
func (n *node) getValue(path string, params *Params, skippedNodes *[]skippedNode, unescape bool) (value nodeValue) {
	var globalParamsCount int16
	// backtracked 表示当前节点是从 skippedNodes 回溯恢复的：它的静态子节点已经试过且失败，
	// 这一轮只能走通配符子节点，否则会再次进入同一个静态分支，形成死循环。
	// （旧实现保存的是一份不含 indices 的节点副本来达到同样效果，每个回溯点都要堆分配）
	backtracked := false
	// tsrCandidate 记录回溯之前某个失败分支给出的尾斜杠重定向建议：
	// 优先尝试回溯找到真正的匹配，全部失败时才采用重定向建议
	tsrCandidate := false
	defer func() {
		if value.handlers == nil && tsrCandidate {
			value.tsr = true
		}
	}()

	// backtrack 弹出最近一个能接上当前剩余路径的回溯点并恢复现场，成功返回 true。
	// 回溯点在「经过有通配符兄弟的静态子节点」时压入，恢复后只走通配符子节点
	backtrack := func() bool {
		for length := len(*skippedNodes); length > 0; length-- {
			skipped := (*skippedNodes)[length-1]
			*skippedNodes = (*skippedNodes)[:length-1]
			if strings.HasSuffix(skipped.path, path) {
				path = skipped.path
				n = skipped.node
				backtracked = true
				if value.params != nil {
					*value.params = (*value.params)[:skipped.paramsCount]
				}
				globalParamsCount = skipped.paramsCount
				return true
			}
		}
		return false
	}

walk:
	for {
		prefix := n.path
		skipStatic := backtracked
		backtracked = false

		// 情况1：待匹配路径长于当前节点路径
		if len(path) > len(prefix) {
			// 检查前缀是否匹配
			if path[:len(prefix)] == prefix {
				// 获取剩余路径
				path = path[len(prefix):]

				// 获取下一个字符用于匹配
				idxc := path[0]

				// 遍历子节点索引（回溯恢复的节点跳过静态子节点）
				for i := range len(n.indices) {
					if !skipStatic && n.indices[i] == idxc {
						// 如果有通配符子节点，保存当前状态
						if n.wildChild {
							// 查找期间树是只读的，直接保存节点指针即可，无需每个回溯点复制一份 node；
							// 用 append 的原因同 param 分支（容量来自创建 context 时的 maxSections）
							*skippedNodes = append(*skippedNodes, skippedNode{
								path:        prefix + path,
								node:        n,
								paramsCount: globalParamsCount,
							})
						}
						// 继续遍历匹配的子节点
						n = n.children[i]
						continue walk
					}
				}

				// 没有通配符子节点
				if !n.wildChild {
					// 尝试回退到之前跳过的节点
					if path != "/" && backtrack() {
						continue walk
					}

					// 检查尾部斜杠重定向
					value.tsr = path == "/" && n.handlers != nil
					return
				}

				// 处理通配符子节点（总是在最后）
				n = n.children[len(n.children)-1]
				globalParamsCount++

				// 根据节点类型处理
				switch n.nType {
				case param:
					// 查找参数结束位置（'/' 或路径末尾）
					end := 0
					for end < len(path) && path[end] != '/' {
						end++
					}

					// 保存参数值。用 append 而不是按预分配容量重新切片：服务启动后再注册参数更多的路由时，
					// 池中复用的旧 context 容量不足，重新切片会越界，旧的 cap > 0 判断则会静默丢掉参数
					if params != nil {
						if value.params == nil {
							value.params = params
						}
						val := path[:end]
						if unescape {
							if v, err := url.QueryUnescape(val); err == nil {
								val = v
							}
						}
						*value.params = append(*value.params, Param{
							Key:   n.path[1:],
							Value: val,
						})
					}

					// 检查是否还有剩余路径
					if end < len(path) {
						if len(n.children) > 0 {
							path = path[end:]
							n = n.children[0]
							continue walk
						}

						// 参数之后还有路径但没有子节点：当前分支失败，先尝试回溯，都失败时再给出尾斜杠建议
						tsr := len(path) == end+1
						if backtrack() {
							tsrCandidate = tsrCandidate || tsr
							continue walk
						}
						value.tsr = tsr
						return
					}

					// 检查当前节点是否有处理程序
					if value.handlers = n.handlers; value.handlers != nil {
						value.fullPath = n.fullPath
						return
					}

					// 路径已耗尽但参数节点没有 handler（例如只注册了 /x/:p/y）：同样先尝试回溯
					tsr := false
					if len(n.children) == 1 {
						child := n.children[0]
						tsr = (child.path == "/" && child.handlers != nil) ||
							(child.path == "" && child.indices == "/")
					}
					if backtrack() {
						tsrCandidate = tsrCandidate || tsr
						continue walk
					}
					value.tsr = tsr
					return

				case catchAll:
					// 保存catch-all参数（用 append 的原因同 param 分支）
					if params != nil {
						if value.params == nil {
							value.params = params
						}
						val := path
						if unescape {
							if v, err := url.QueryUnescape(path); err == nil {
								val = v
							}
						}
						*value.params = append(*value.params, Param{
							Key:   n.path[2:],
							Value: val,
						})
					}

					value.handlers = n.handlers
					value.fullPath = n.fullPath
					return

				default:
					panic("invalid node type")
				}
			}
		}

		// 情况2：路径完全匹配当前节点
		if path == prefix {
			// 如果没有处理程序且不是根路径，尝试回退
			if n.handlers == nil && path != "/" && backtrack() {
				continue walk
			}

			// 检查是否有处理程序
			if value.handlers = n.handlers; value.handlers != nil {
				value.fullPath = n.fullPath
				return
			}

			// 检查各种尾部斜杠重定向情况
			if path == "/" && n.wildChild && n.nType != root {
				value.tsr = true
				return
			}

			if path == "/" && n.nType == static {
				value.tsr = true
				return
			}

			// 检查子节点中的斜杠
			for i := range len(n.indices) {
				if n.indices[i] == '/' {
					n = n.children[i]
					value.tsr = (len(n.path) == 1 && n.handlers != nil) ||
						(n.nType == catchAll && n.children[0].handlers != nil)
					return
				}
			}

			return
		}

		// 情况3：没有找到匹配
		// 检查是否可以进行尾部斜杠重定向
		value.tsr = path == "/" ||
			(len(prefix) == len(path)+1 &&
				prefix[len(path)] == '/' &&
				path == prefix[:len(prefix)-1] &&
				n.handlers != nil)

		// 最后尝试回退
		if !value.tsr && path != "/" && backtrack() {
			continue walk
		}

		return
	}
}

// findCaseInsensitivePath 大小写不敏感路径查找
// findCaseInsensitivePath 大小写不敏感的路径查找（优化版本）
func (n *node) findCaseInsensitivePath(path string, fixTrailingSlash bool) ([]byte, bool) {
	const stackBufSize = 128

	// 预分配缓冲区
	buf := make([]byte, 0, stackBufSize)
	if length := len(path) + 1; length > stackBufSize {
		buf = make([]byte, 0, length)
	}

	ciPath := n.findCaseInsensitivePathRec(
		path,
		buf,
		[4]byte{},
		fixTrailingSlash,
	)

	return ciPath, ciPath != nil
}

// Shift bytes in array by n bytes left
func shiftNRuneBytes(rb [4]byte, n int) [4]byte {
	switch n {
	case 0:
		return rb
	case 1:
		return [4]byte{rb[1], rb[2], rb[3], 0}
	case 2:
		return [4]byte{rb[2], rb[3]}
	case 3:
		return [4]byte{rb[3]}
	default:
		return [4]byte{}
	}
}

// findCaseInsensitivePathRec 递归查找大小写不敏感路径
func (n *node) findCaseInsensitivePathRec(path string, ciPath []byte, rb [4]byte, fixTrailingSlash bool) []byte {
	npLen := len(n.path)

walk:
	for len(path) >= npLen && (npLen == 0 || strings.EqualFold(path[1:npLen], n.path[1:])) {
		oldPath := path
		path = path[npLen:]
		ciPath = append(ciPath, n.path...)

		if len(path) == 0 {
			if n.handlers != nil {
				return ciPath
			}

			// 尝试修复尾部斜杠
			if fixTrailingSlash {
				for i := range len(n.indices) {
					if n.indices[i] == '/' {
						n = n.children[i]
						if (len(n.path) == 1 && n.handlers != nil) ||
							(n.nType == catchAll && n.children[0].handlers != nil) {
							return append(ciPath, '/')
						}
						return nil
					}
				}
			}
			return nil
		}

		// 静态子节点和通配符子节点可以是兄弟（如 /users/new 与 /users/:id），
		// addChild 保证通配符子节点总在最后、且不出现在 indices 中。
		// 先按静态子节点查找，找不到再回退到通配符子节点
		rbBeforeStatic := rb
		{
			// 处理已处理的rune字节
			rb = shiftNRuneBytes(rb, npLen)

			if rb[0] != 0 {
				// 继续处理未完成的rune
				idxc := rb[0]
				for i := range len(n.indices) {
					if n.indices[i] == idxc {
						n = n.children[i]
						npLen = len(n.path)
						continue walk
					}
				}
			} else {
				// 处理新的rune
				var rv rune
				var off int

				// 查找rune起始位置
				for max := min(npLen, 3); off < max; off++ {
					if i := npLen - off; utf8.RuneStart(oldPath[i]) {
						rv, _ = utf8.DecodeRuneInString(oldPath[i:])
						break
					}
				}

				// 计算小写字节
				lo := unicode.ToLower(rv)
				utf8.EncodeRune(rb[:], lo)
				rb = shiftNRuneBytes(rb, off)

				idxc := rb[0]
				for i := range len(n.indices) {
					if n.indices[i] == idxc {
						// 递归方法处理大小写
						if out := n.children[i].findCaseInsensitivePathRec(
							path, ciPath, rb, fixTrailingSlash,
						); out != nil {
							return out
						}
						break
					}
				}

				// 尝试大写
				if up := unicode.ToUpper(rv); up != lo {
					utf8.EncodeRune(rb[:], up)
					rb = shiftNRuneBytes(rb, off)

					idxc := rb[0]
					for i := range len(n.indices) {
						if n.indices[i] == idxc {
							n = n.children[i]
							npLen = len(n.path)
							continue walk
						}
					}
				}
			}

			if !n.wildChild {
				// 未找到匹配
				if fixTrailingSlash && path == "/" && n.handlers != nil {
					return ciPath
				}
				return nil
			}
		}

		// 静态子节点都没匹配上，回退到通配符子节点；通配符分支不消费 rune 缓冲，恢复进入前的状态
		rb = rbBeforeStatic
		n = n.children[len(n.children)-1]
		switch n.nType {
		case param:
			// 查找参数结束位置
			end := 0
			for end < len(path) && path[end] != '/' {
				end++
			}

			ciPath = append(ciPath, path[:end]...)

			if end < len(path) {
				if len(n.children) > 0 {
					n = n.children[0]
					npLen = len(n.path)
					path = path[end:]
					continue
				}

				if fixTrailingSlash && len(path) == end+1 {
					return ciPath
				}
				return nil
			}

			if n.handlers != nil {
				return ciPath
			}

			if fixTrailingSlash && len(n.children) == 1 {
				n = n.children[0]
				if n.path == "/" && n.handlers != nil {
					return append(ciPath, '/')
				}
			}
			return nil

		case catchAll:
			return append(ciPath, path...)

		default:
			panic("invalid node type")
		}
	}

	// 尝试修复尾部斜杠
	if fixTrailingSlash {
		if path == "/" {
			return ciPath
		}
		if len(path)+1 == npLen && n.path[len(path)] == '/' &&
			strings.EqualFold(path[1:], n.path[1:len(path)]) && n.handlers != nil {
			return append(ciPath, n.path...)
		}
	}
	return nil
}
