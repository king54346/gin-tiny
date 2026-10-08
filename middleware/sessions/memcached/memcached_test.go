package memcached

import (
	"net"
	"testing"
	"time"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/memcachier/mc"
)

const memcachedTestServer = "localhost:11211"

var newStore = func(t *testing.T) sessions.Store {
	skipIfUnreachable(t, memcachedTestServer)
	store := NewStore(
		memcache.New(memcachedTestServer), "", []byte("secret"),
	)
	return store
}

func TestMemcached_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newStore)
}

func TestMemcached_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newStore)
}

func TestMemcached_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newStore)
}

func TestMemcached_SessionClear(t *testing.T) {
	tester.Clear(t, newStore)
}

func TestMemcached_SessionOptions(t *testing.T) {
	tester.Options(t, newStore)
}

func TestMemcached_SessionMany(t *testing.T) {
	tester.Many(t, newStore)
}

func TestMemcached_SessionManyStores(t *testing.T) {
	tester.ManyStores(t, newStore)
}

var newBinaryStore = func(t *testing.T) sessions.Store {
	skipIfUnreachable(t, memcachedTestServer)
	store := NewMemcacheStore(
		mc.NewMC(memcachedTestServer, "", ""), "", []byte("secret"),
	)
	return store
}

func TestBinaryMemcached_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newBinaryStore)
}

func TestBinaryMemcached_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newBinaryStore)
}

func TestBinaryMemcached_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newBinaryStore)
}

func TestBinaryMemcached_SessionClear(t *testing.T) {
	tester.Clear(t, newBinaryStore)
}

func TestBinaryMemcached_SessionOptions(t *testing.T) {
	tester.Options(t, newBinaryStore)
}

func TestBinaryMemcached_SessionMany(t *testing.T) {
	tester.Many(t, newBinaryStore)
}

func TestBinaryMemcached_SessionManyStores(t *testing.T) {
	tester.ManyStores(t, newBinaryStore)
}

// 本地没有对应服务时跳过，而不是 panic
func skipIfUnreachable(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Skipf("%s unreachable: %v", addr, err)
	}
	conn.Close()
}
