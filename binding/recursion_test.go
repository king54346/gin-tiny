package binding

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type category struct {
	Name   string    `form:"name" header:"X-Name"`
	Parent *category `form:"parent" header:"X-Parent"`
}

type nodeA struct {
	A string `form:"a"`
	B *nodeB
}

type nodeB struct {
	B string `form:"b"`
	A *nodeA
}

// 自引用结构体修复前会无限递归直到栈溢出（进程直接崩溃）
func TestBindSelfReferentialStruct(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?name=go", nil)
	var c category
	require.NoError(t, Query.Bind(req, &c))
	assert.Equal(t, "go", c.Name)
	// 表单键是扁平的，嵌套的同类型指针只会新建一层
	require.NotNil(t, c.Parent)
	assert.Equal(t, "go", c.Parent.Name)
	assert.Nil(t, c.Parent.Parent)

	req.Header.Set("X-Name", "hdr")
	var h category
	require.NoError(t, Header.Bind(req, &h))
	assert.Equal(t, "hdr", h.Name)
}

func TestBindMutuallyRecursiveStructs(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?a=1&b=2", nil)
	var a nodeA
	require.NoError(t, Query.Bind(req, &a))
	assert.Equal(t, "1", a.A)
	// 绑定目标本身不是新建的；链上每个类型最多新建一次：nodeB → nodeA，再遇到 nodeB 时停止
	require.NotNil(t, a.B)
	assert.Equal(t, "2", a.B.B)
	require.NotNil(t, a.B.A)
	assert.Equal(t, "1", a.B.A.A)
	assert.Nil(t, a.B.A.B)
}

// 调用方已经分配好的指针不受限制，照常填充
func TestBindExistingPointerStillFilled(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?name=x", nil)
	c := category{Parent: &category{Parent: &category{}}}
	require.NoError(t, Query.Bind(req, &c))
	assert.Equal(t, "x", c.Parent.Parent.Name)
}

// 字段没有对应值时不创建指针
func TestBindNestedPointerNotCreatedWithoutValues(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?other=1", nil)
	var c category
	require.NoError(t, Query.Bind(req, &c))
	assert.Nil(t, c.Parent)
}
