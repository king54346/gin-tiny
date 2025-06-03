// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package ginTiny

import (
	"bytes"
	"gin-tiny/internal/bytesconv"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	strColon = []byte(":")
	strStar  = []byte("*")
	strSlash = []byte("/")
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
	if ps == nil {
		return nil
	}
	c := make(Params, len(ps))
	copy(c, ps)
	return c
}

// http的请求方法Get，Post等
type methodTree struct {
	method string
	root   *node // 先通过 methodTrees.get方法获取对应的路由树，在通过addRoute方法添加到路由树中
}

type supportMethodsHandlers struct {
	handers          HandlersChain // 支持的HTTP方法对应的处理程序链
	supportedMethods uint16
}

type methodTrees struct {
	connect      *methodTree
	delete       *methodTree
	get          *methodTree
	head         *methodTree
	options      *methodTree
	patch        *methodTree
	post         *methodTree
	put          *methodTree
	trace        *methodTree
	anyOther     map[string]*methodTree            // 存储其他HTTP方法的路由树
	allowHeader  string                            // 用于存储允许的请求头
	staticRouter map[string]supportMethodsHandlers // 存储静态路由或多个http方法的处理程序
}

// HTTP方法位掩码常量
const (
	MethodConnect = 1 << iota
	MethodDelete
	MethodGet
	MethodHead
	MethodOptions
	MethodPatch
	MethodPost
	MethodPut
	MethodTrace
)

// 方法映射（单一数据源，使用数组保证顺序）
var methodMappings = [...]struct {
	name    string
	bitmask uint16
}{
	{http.MethodConnect, MethodConnect},
	{http.MethodDelete, MethodDelete},
	{http.MethodGet, MethodGet},
	{http.MethodHead, MethodHead},
	{http.MethodOptions, MethodOptions},
	{http.MethodPatch, MethodPatch},
	{http.MethodPost, MethodPost},
	{http.MethodPut, MethodPut},
	{http.MethodTrace, MethodTrace},
}

// 自动生成的映射和切片
var (
	methodToBitmask = func() map[string]uint16 {
		m := make(map[string]uint16, len(methodMappings))
		for _, mapping := range methodMappings {
			m[mapping.name] = mapping.bitmask
		}
		return m
	}()

	anyMethods = func() []string {
		methods := make([]string, len(methodMappings))
		for i, mapping := range methodMappings {
			methods[i] = mapping.name
		}
		return methods
	}()
)

// IsMethodSupported 检查给定的HTTP方法是否被支持
func (smh *supportMethodsHandlers) IsMethodSupported(method string) bool {
	// 首先检查标准方法（位运算，最快）
	if bitmask, isStandard := methodToBitmask[method]; isStandard {
		return smh.supportedMethods&bitmask != 0
	}
	return false
}

// findHanders 在muchOrStaticRouter中查找指定路径和方法的处理程序链
func (trees *methodTrees) findHandlers(path, method string) (HandlersChain, bool) {
	// 1. 检查路径
	pathHandlers, pathExists := trees.staticRouter[path]
	if !pathExists {
		return nil, false // 404
	}

	// 2. 检查方法
	if !pathHandlers.IsMethodSupported(method) {
		return nil, false // 405
	}

	return pathHandlers.handers, true
}

func (trees *methodTrees) addStaticRouter(method string, path string, handlers HandlersChain) {
	if trees.staticRouter == nil {
		trees.staticRouter = make(map[string]supportMethodsHandlers)
	}

	// 检查路径是否已存在
	if pathHandlers, exists := trees.staticRouter[path]; exists {
		// 如果路径已存在，更新处理程序和支持的方法
		pathHandlers.handers = handlers
		pathHandlers.supportedMethods |= methodToBitmask[method]
		trees.staticRouter[path] = pathHandlers
	} else {
		// 如果路径不存在，创建新的条目
		trees.staticRouter[path] = supportMethodsHandlers{
			handers:          handlers,
			supportedMethods: methodToBitmask[method],
		}
	}
}

func newMethodTrees() *methodTrees {
	trees := &methodTrees{
		anyOther: make(map[string]*methodTree),
	}

	return trees
}

// getNotNullMethodTree 返回一个包含所有非空方法树的切片
func (trees *methodTrees) getNotNullMethodTree() []*methodTree {
	if trees == nil {
		return nil
	}

	// 预分配足够的容量以避免多次扩容
	t := make([]*methodTree, 0, 9+len(trees.anyOther))

	// 使用标准HTTP方法的数组来简化代码
	standardMethods := [...]*methodTree{
		trees.connect,
		trees.delete,
		trees.get,
		trees.head,
		trees.options,
		trees.patch,
		trees.post,
		trees.put,
		trees.trace,
	}

	// 添加所有非nil的标准HTTP方法
	for _, tree := range standardMethods {
		if tree != nil {
			t = append(t, tree)
		}
	}

	// 添加所有自定义HTTP方法
	for _, tree := range trees.anyOther {
		t = append(t, tree)
	}
	//// staticRouter中的路由方法
	//for _, pathHandlers := range trees.staticRouter {
	//	if pathHandlers.handers != nil {
	//		t = append(t, &methodTree{
	//			method: pathHandlers.handers,
	//			root:   nil, // 静态路由没有对应的node树
	//		})
	//	}
	//}

	return t
}

func (trees *methodTrees) initMethodTree(tree methodTree) {
	switch tree.method {
	case http.MethodConnect:
		trees.connect = &tree
	case http.MethodDelete:
		trees.delete = &tree
	case http.MethodGet:
		trees.get = &tree
	case http.MethodHead:
		trees.head = &tree
	case http.MethodOptions:
		trees.options = &tree
	case http.MethodPatch:
		trees.patch = &tree
	case http.MethodPost:
		trees.post = &tree
	case http.MethodPut:
		trees.put = &tree
	case http.MethodTrace:
		trees.trace = &tree
	default:
		if _, ok := trees.anyOther[tree.method]; !ok {
			trees.anyOther[tree.method] = &tree
		}
	}
}

// 获取指定方法的路由树
func (trees *methodTrees) getMethodTree(method string) *node {
	if trees == nil {
		return nil
	}

	switch method {
	case http.MethodConnect:
		if trees.connect != nil {
			return trees.connect.root
		}
	case http.MethodDelete:
		if trees.delete != nil {
			return trees.delete.root
		}
	case http.MethodGet:
		if trees.get != nil {
			return trees.get.root
		}
	case http.MethodHead:
		if trees.head != nil {
			return trees.head.root
		}
	case http.MethodOptions:
		if trees.options != nil {
			return trees.options.root
		}
	case http.MethodPatch:
		if trees.patch != nil {
			return trees.patch.root
		}
	case http.MethodPost:
		if trees.post != nil {
			return trees.post.root
		}
	case http.MethodPut:
		if trees.put != nil {
			return trees.put.root
		}
	case http.MethodTrace:
		if trees.trace != nil {
			return trees.trace.root
		}
	default:
		if tree, ok := trees.anyOther[method]; ok {
			return tree.root
		}
	}
	return nil
}

//func (trees methodTrees) get(method string) *node {
//	for _, tree := range trees {
//		if tree.method == method {
//			return tree.root
//		}
//	}
//	return nil
//}

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
func countParams(path string) uint16 {
	var n uint16
	s := bytesconv.StringToBytes(path)
	n += uint16(bytes.Count(s, strColon))
	n += uint16(bytes.Count(s, strStar))
	return n
}

func countSections(path string) uint16 {
	s := bytesconv.StringToBytes(path)
	return uint16(bytes.Count(s, strSlash))
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

walk:
	for {
		prefix := n.path

		// 情况1：待匹配路径长于当前节点路径
		if len(path) > len(prefix) {
			// 检查前缀是否匹配
			if path[:len(prefix)] == prefix {
				// 获取剩余路径
				path = path[len(prefix):]

				// 获取下一个字符用于匹配
				idxc := path[0]

				// 遍历子节点索引
				for i := 0; i < len(n.indices); i++ {
					if n.indices[i] == idxc {
						// 如果有通配符子节点，保存当前状态
						if n.wildChild {
							index := len(*skippedNodes)
							*skippedNodes = (*skippedNodes)[:index+1]
							(*skippedNodes)[index] = skippedNode{
								path: prefix + path,
								node: &node{
									path:      n.path,
									wildChild: n.wildChild,
									nType:     n.nType,
									priority:  n.priority,
									children:  n.children,
									handlers:  n.handlers,
									fullPath:  n.fullPath,
								},
								paramsCount: globalParamsCount,
							}
						}
						// 继续遍历匹配的子节点
						n = n.children[i]
						continue walk
					}
				}

				// 没有通配符子节点
				if !n.wildChild {
					// 尝试回退到之前跳过的节点
					if path != "/" {
						for length := len(*skippedNodes); length > 0; length-- {
							skipped := (*skippedNodes)[length-1]
							*skippedNodes = (*skippedNodes)[:length-1]
							if strings.HasSuffix(skipped.path, path) {
								path = skipped.path
								n = skipped.node
								if value.params != nil {
									*value.params = (*value.params)[:skipped.paramsCount]
								}
								globalParamsCount = skipped.paramsCount
								continue walk
							}
						}
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

					// 保存参数值
					if params != nil && cap(*params) > 0 {
						if value.params == nil {
							value.params = params
						}
						i := len(*value.params)
						*value.params = (*value.params)[:i+1]
						val := path[:end]
						if unescape {
							if v, err := url.QueryUnescape(val); err == nil {
								val = v
							}
						}
						(*value.params)[i] = Param{
							Key:   n.path[1:],
							Value: val,
						}
					}

					// 检查是否还有剩余路径
					if end < len(path) {
						if len(n.children) > 0 {
							path = path[end:]
							n = n.children[0]
							continue walk
						}

						// 不能继续，检查尾部斜杠
						value.tsr = len(path) == end+1
						return
					}

					// 检查当前节点是否有处理程序
					if value.handlers = n.handlers; value.handlers != nil {
						value.fullPath = n.fullPath
						return
					}

					// 检查是否有尾部斜杠的处理程序
					if len(n.children) == 1 {
						n = n.children[0]
						value.tsr = (n.path == "/" && n.handlers != nil) ||
							(n.path == "" && n.indices == "/")
					}
					return

				case catchAll:
					// 保存catch-all参数
					if params != nil {
						if value.params == nil {
							value.params = params
						}
						i := len(*value.params)
						*value.params = (*value.params)[:i+1]
						val := path
						if unescape {
							if v, err := url.QueryUnescape(path); err == nil {
								val = v
							}
						}
						(*value.params)[i] = Param{
							Key:   n.path[2:],
							Value: val,
						}
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
			if n.handlers == nil && path != "/" {
				for length := len(*skippedNodes); length > 0; length-- {
					skipped := (*skippedNodes)[length-1]
					*skippedNodes = (*skippedNodes)[:length-1]
					if strings.HasSuffix(skipped.path, path) {
						path = skipped.path
						n = skipped.node
						if value.params != nil {
							*value.params = (*value.params)[:skipped.paramsCount]
						}
						globalParamsCount = skipped.paramsCount
						continue walk
					}
				}
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
			for i := 0; i < len(n.indices); i++ {
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
		if !value.tsr && path != "/" {
			for length := len(*skippedNodes); length > 0; length-- {
				skipped := (*skippedNodes)[length-1]
				*skippedNodes = (*skippedNodes)[:length-1]
				if strings.HasSuffix(skipped.path, path) {
					path = skipped.path
					n = skipped.node
					if value.params != nil {
						*value.params = (*value.params)[:skipped.paramsCount]
					}
					globalParamsCount = skipped.paramsCount
					continue walk
				}
			}
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
				for i := 0; i < len(n.indices); i++ {
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

		if !n.wildChild {
			// 处理已处理的rune字节
			rb = shiftNRuneBytes(rb, npLen)

			if rb[0] != 0 {
				// 继续处理未完成的rune
				idxc := rb[0]
				for i := 0; i < len(n.indices); i++ {
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
				for i := 0; i < len(n.indices); i++ {
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
					for i := 0; i < len(n.indices); i++ {
						if n.indices[i] == idxc {
							n = n.children[i]
							npLen = len(n.path)
							continue walk
						}
					}
				}
			}

			// 未找到匹配
			if fixTrailingSlash && path == "/" && n.handlers != nil {
				return ciPath
			}
			return nil
		}

		n = n.children[0]
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
