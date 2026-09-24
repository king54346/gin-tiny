package main

import (
	gin "github.com/king54346/gin-tiny"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestGinContextCancel(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		return
	}))
	defer serv.Close()

	wg := &sync.WaitGroup{}

	r := gin.New()
	println(r.ContextWithFallback)
	r.GET("/", func(ginctx gin.Context) {
		wg.Add(1)

		ginctx = ginctx.Copy()

		// start async goroutine for calling serv
		go func() {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ginctx, http.MethodGet, serv.URL, nil)
			if err != nil {
				panic(err)
			}
			// 如果ContextWithFallback设置为true，则会共享ginctx的context，当ginctx的context被取消，req的context也会被取消
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				// context is always canceled with gin v1.8.0, it is big breaking change with gin v1.7
				t.Error("context is always canceled with gin v1.8.0, it is big breaking change with gin v1.7", err)
				return
			}

			if res.StatusCode != http.StatusOK {
				log.Println("unexpected status code ", res.Status)
				return
			}
		}()
	})

	ginServ := httptest.NewServer(r)
	defer ginServ.Close()

	res, err := http.Get(ginServ.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code %d", res.StatusCode)
	}

	wg.Wait()
}
