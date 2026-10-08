package mongodriver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const mongoTestServer = "mongodb://localhost:27017"

var newStore = func(t *testing.T) sessions.Store {
	skipIfUnreachable(t, "localhost:27017")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoTestServer))
	if err != nil {
		panic(err)
	}

	c := client.Database("test").Collection("sessions")
	return NewStore(c, 3600, true, []byte("secret"))
}

func TestMongoDriver_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newStore)
}

func TestMongoDriver_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newStore)
}

func TestMongoDriver_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newStore)
}

func TestMongoDriver_SessionClear(t *testing.T) {
	tester.Clear(t, newStore)
}

func TestMongoDriver_SessionOptions(t *testing.T) {
	tester.Options(t, newStore)
}

func TestMongoDriver_SessionMany(t *testing.T) {
	tester.Many(t, newStore)
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
