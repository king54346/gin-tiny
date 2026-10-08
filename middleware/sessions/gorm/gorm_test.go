package gorm

import (
	"testing"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var newStore = func(t *testing.T) sessions.Store {
	// 使用纯 Go 的 sqlite 驱动，不需要 cgo；每个测试一个独立的内存数据库
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	return NewStore(db, true, []byte("secret"))
}

func TestGorm_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newStore)
}

func TestGorm_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newStore)
}

func TestGorm_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newStore)
}

func TestGorm_SessionClear(t *testing.T) {
	tester.Clear(t, newStore)
}

func TestGorm_SessionOptions(t *testing.T) {
	tester.Options(t, newStore)
}

func TestGorm_SessionMany(t *testing.T) {
	tester.Many(t, newStore)
}
