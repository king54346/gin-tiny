package filesystem

import (
	"os"
	"testing"

	"github.com/king54346/gin-tiny/middleware/sessions"
	"github.com/king54346/gin-tiny/middleware/sessions/tester"
)

var sessionPath = os.TempDir()

var newStore = func(_ *testing.T) sessions.Store {
	store := NewStore(sessionPath, []byte("secret"))
	return store
}

func TestFilesystem_SessionGetSet(t *testing.T) {
	tester.GetSet(t, newStore)
}

func TestFilesystem_SessionDeleteKey(t *testing.T) {
	tester.DeleteKey(t, newStore)
}

func TestFilesystem_SessionFlashes(t *testing.T) {
	tester.Flashes(t, newStore)
}

func TestFilesystem_SessionClear(t *testing.T) {
	tester.Clear(t, newStore)
}

func TestFilesystem_SessionOptions(t *testing.T) {
	tester.Options(t, newStore)
}

func TestFilesystem_SessionMany(t *testing.T) {
	tester.Many(t, newStore)
}
