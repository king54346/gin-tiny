package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"
)

// 使用内存中的 miniredis，不依赖本地 redis 服务
var newRedisStore = func(t *testing.T) sessions.Store {
	store, err := NewStore(10, "tcp", miniredis.RunT(t).Addr(), "", "", []byte("secret"))
	if err != nil {
		panic(err)
	}
	return store
}

func TestRedis_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newRedisStore)
}

func TestRedis_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newRedisStore)
}

func TestRedis_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newRedisStore)
}

func TestRedis_SessionClear(t *testing.T) {
	tester.Clear(t, newRedisStore)
}

func TestRedis_SessionOptions(t *testing.T) {
	tester.Options(t, newRedisStore)
}

func TestRedis_SessionMany(t *testing.T) {
	tester.Many(t, newRedisStore)
}

func TestRedis_SessionManyStores(t *testing.T) {
	tester.ManyStores(t, newRedisStore)
}

func TestGetRedisStore(t *testing.T) {
	t.Run("unmatched type", func(t *testing.T) {
		type store struct{ Store }
		rediStore, err := GetRedisStore(store{})
		if err == nil || rediStore != nil {
			t.Fail()
		}
	})
}
