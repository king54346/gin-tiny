package postgres

import (
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"
)

// test-only credentials for local CI
const postgresTestServer = "postgres://testuser:testpw@localhost:5432/testdb?sslmode=disable" //nolint:gosec // test-only credentials for local CI

var newStore = func(t *testing.T) sessions.Store {
	skipIfUnreachable(t, "localhost:5432")
	db, err := sql.Open("postgres", postgresTestServer)
	if err != nil {
		panic(err)
	}

	store, err := NewStore(db, []byte("secret"))
	if err != nil {
		panic(err)
	}

	return store
}

func TestPostgres_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newStore)
}

func TestPostgres_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newStore)
}

func TestPostgres_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newStore)
}

func TestPostgres_SessionClear(t *testing.T) {
	tester.Clear(t, newStore)
}

func TestPostgres_SessionOptions(t *testing.T) {
	tester.Options(t, newStore)
}

func TestPostgres_SessionMany(t *testing.T) {
	tester.Many(t, newStore)
}

func TestPostgres_SessionManyStores(t *testing.T) {
	tester.ManyStores(t, newStore)
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
