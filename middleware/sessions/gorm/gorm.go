package gorm

import (
	"time"

	"github.com/king54346/gin-tiny/middleware/sessions"

	"github.com/wader/gormstore/v2"
	"gorm.io/gorm"
)

type Store interface {
	sessions.Store
}

func NewStore(d *gorm.DB, expiredSessionCleanup bool, keyPairs ...[]byte) Store {
	s := gormstore.New(d, keyPairs...)
	if expiredSessionCleanup {
		quit := make(chan struct{})
		go s.PeriodicCleanup(1*time.Hour, quit)
	}
	return &store{s}
}

type store struct {
	*gormstore.Store
}

func (s *store) Options(options sessions.Options) {
	s.SessionOpts = options.ToGorillaOptions()
}
