// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import (
	"bytes"
	"errors"
	"fmt"
	"gin-tiny/binding"
	testdata "gin-tiny/testdata/protoexample"
	"github.com/gin-contrib/sse"
	"github.com/stretchr/testify/assert"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	//别名 context为 ctx
	ctx "context"
	"google.golang.org/protobuf/proto"
)

//var _ context.Context = (*context)(nil)

var errTestRender = errors.New("TestRender")

// Unit tests TODO
// func (c *context) File(filepath string) {
// func (c *context) Negotiate(code int, config Negotiate) {
// BAD case: func (c *context) Render(code int, render render.Render, obj ...any) {
// test that information is not leaked when reusing Contexts (using the Pool)

func createMultipartRequest() *http.Request {
	boundary := "--testboundary"
	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	defer mw.Close()

	must(mw.SetBoundary(boundary))
	must(mw.WriteField("foo", "bar"))
	must(mw.WriteField("bar", "10"))
	must(mw.WriteField("bar", "foo2"))
	must(mw.WriteField("array", "first"))
	must(mw.WriteField("array", "second"))
	must(mw.WriteField("id", ""))
	must(mw.WriteField("time_local", "31/12/2016 14:55"))
	must(mw.WriteField("time_utc", "31/12/2016 14:55"))
	must(mw.WriteField("time_location", "31/12/2016 14:55"))
	must(mw.WriteField("names[a]", "thinkerou"))
	must(mw.WriteField("names[b]", "tianou"))
	req, err := http.NewRequest("POST", "/", body)
	must(err)
	req.Header.Set("Content-Type", MIMEMultipartPOSTForm+"; boundary="+boundary)
	return req
}

func must(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func TestContextFormFile(t *testing.T) {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	w, err := mw.CreateFormFile("file", "test")
	if assert.NoError(t, err) {
		_, err = w.Write([]byte("test"))
		assert.NoError(t, err)
	}
	mw.Close()
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	f, err := c.FormFile("file")
	if assert.NoError(t, err) {
		assert.Equal(t, "test", f.Filename)
	}

	assert.NoError(t, c.SaveUploadedFile(f, "test"))
}

func TestContextMultipartForm(t *testing.T) {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	assert.NoError(t, mw.WriteField("foo", "bar"))
	w, err := mw.CreateFormFile("file", "test")
	if assert.NoError(t, err) {
		_, err = w.Write([]byte("test"))
		assert.NoError(t, err)
	}
	mw.Close()
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	f, err := c.MultipartForm()
	if assert.NoError(t, err) {
		assert.NotNil(t, f)
	}

	assert.NoError(t, c.SaveUploadedFile(f.File["file"][0], "test"))
}

func TestSaveUploadedOpenFailed(t *testing.T) {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	mw.Close()

	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())

	f := &multipart.FileHeader{
		Filename: "file",
	}
	assert.Error(t, c.SaveUploadedFile(f, "test"))
}

func TestSaveUploadedCreateFailed(t *testing.T) {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	w, err := mw.CreateFormFile("file", "test")
	if assert.NoError(t, err) {
		_, err = w.Write([]byte("test"))
		assert.NoError(t, err)
	}
	mw.Close()
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", buf)
	c.request.Header.Set("Content-Type", mw.FormDataContentType())
	f, err := c.FormFile("file")
	if assert.NoError(t, err) {
		assert.Equal(t, "test", f.Filename)
	}

	assert.Error(t, c.SaveUploadedFile(f, "/"))
}

func TestContextReset(t *testing.T) {
	router := New()
	c := router.allocateContext(0)
	assert.Equal(t, c.engine, router)

	c.index = 2
	c.writermem = &responseWriter{ResponseWriter: httptest.NewRecorder()}
	c.params = &Params{Param{}}
	c.Error(errors.New("test")) //nolint: errcheck
	c.Set("foo", "bar")
	c.Reset()

	assert.False(t, c.IsAborted())
	assert.Nil(t, c.Keys)
	assert.Nil(t, c.Accepted)
	assert.Len(t, c.errors, 0)
	assert.Empty(t, c.errors.Errors())
	assert.Empty(t, c.errors.ByType(ErrorTypeAny))
	assert.Len(t, c.Params(), 0)
	assert.EqualValues(t, c.index, -1)
	assert.Equal(t, c.Response().(*responseWriter), c.writermem)
}

//func TestContextHandlers(t *testing.T) {
//	c, _ := CreateTestContext(httptest.NewRecorder())
//	assert.Nil(t, c.handlers)
//	assert.Nil(t, c.handlers.Last())
//
//	c.handlers = HandlersChain{}
//	assert.NotNil(t, c.handlers)
//	assert.Nil(t, c.handlers.Last())
//
//	f := func(c Context) {}
//	g := func(c Context) {}
//
//	c.handlers = HandlersChain{f}
//	compareFunc(t, f, c.handlers.Last())
//
//	c.handlers = HandlersChain{f, g}
//	compareFunc(t, g, c.handlers.Last())
//}

// TestContextSetGet tests that a parameter is set correctly on the
// current context and can be retrieved using Get.
func TestContextSetGet(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("foo", "bar")

	value, err := c.Get("foo")
	assert.Equal(t, "bar", value)
	assert.True(t, err)

	value, err = c.Get("foo2")
	assert.Nil(t, value)
	assert.False(t, err)

	assert.Equal(t, "bar", c.MustGet("foo"))
	assert.Panics(t, func() { c.MustGet("no_exist") })
}

func TestContextSetGetValues(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("string", "this is a string")
	c.Set("int32", int32(-42))
	c.Set("int64", int64(42424242424242))
	c.Set("uint64", uint64(42))
	c.Set("float32", float32(4.2))
	c.Set("float64", 4.2)
	var a any = 1
	c.Set("intInterface", a)

	assert.Exactly(t, c.MustGet("string").(string), "this is a string")
	assert.Exactly(t, c.MustGet("int32").(int32), int32(-42))
	assert.Exactly(t, c.MustGet("int64").(int64), int64(42424242424242))
	assert.Exactly(t, c.MustGet("uint64").(uint64), uint64(42))
	assert.Exactly(t, c.MustGet("float32").(float32), float32(4.2))
	assert.Exactly(t, c.MustGet("float64").(float64), 4.2)
	assert.Exactly(t, c.MustGet("intInterface").(int), 1)
}

func TestContextGetString(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("string", "this is a string")
	assert.Equal(t, "this is a string", c.GetString("string"))
}

func TestContextSetGetBool(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("bool", true)
	assert.True(t, c.GetBool("bool"))
}

func TestContextGetInt(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("int", 1)
	assert.Equal(t, 1, c.GetInt("int"))
}

func TestContextGetInt64(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("int64", int64(42424242424242))
	assert.Equal(t, int64(42424242424242), c.GetInt64("int64"))
}

func TestContextGetUint(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("uint", uint(1))
	assert.Equal(t, uint(1), c.GetUint("uint"))
}

func TestContextGetUint64(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("uint64", uint64(18446744073709551615))
	assert.Equal(t, uint64(18446744073709551615), c.GetUint64("uint64"))
}

func TestContextGetFloat64(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("float64", 4.2)
	assert.Equal(t, 4.2, c.GetFloat64("float64"))
}

func TestContextGetTime(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	t1, _ := time.Parse("1/2/2006 15:04:05", "01/01/2017 12:00:00")
	c.Set("time", t1)
	assert.Equal(t, t1, c.GetTime("time"))
}

func TestContextGetDuration(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("duration", time.Second)
	assert.Equal(t, time.Second, c.GetDuration("duration"))
}

func TestContextGetStringSlice(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Set("slice", []string{"foo"})
	assert.Equal(t, []string{"foo"}, c.GetStringSlice("slice"))
}

func TestContextGetStringMap(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	m := make(map[string]any)
	m["foo"] = 1
	c.Set("map", m)

	assert.Equal(t, m, c.GetStringMap("map"))
	assert.Equal(t, 1, c.GetStringMap("map")["foo"])
}

func TestContextGetStringMapString(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	m := make(map[string]string)
	m["foo"] = "bar"
	c.Set("map", m)

	assert.Equal(t, m, c.GetStringMapString("map"))
	assert.Equal(t, "bar", c.GetStringMapString("map")["foo"])
}

func TestContextGetStringMapStringSlice(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	m := make(map[string][]string)
	m["foo"] = []string{"foo"}
	c.Set("map", m)

	assert.Equal(t, m, c.GetStringMapStringSlice("map"))
	assert.Equal(t, []string{"foo"}, c.GetStringMapStringSlice("map")["foo"])
}

func TestContextCopy(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.index = 2
	c.request, _ = http.NewRequest("POST", "/hola", nil)
	c.handlers = HandlersChain{func(c Context) {}}
	c.params = &Params{Param{Key: "foo", Value: "bar"}}
	c.Set("foo", "bar")
	c.fullPath = "/hola"
	cp := c.Copy()
	assert.Nil(t, cp.handlers)
	//assert.Nil(t, cp.writermem.ResponseWriter)
	assert.Equal(t, cp.writermem, cp.Response().(*responseWriter))
	assert.Equal(t, cp.request, c.request)
	assert.Equal(t, cp.index, abortIndex)
	assert.Equal(t, cp.Keys, c.Keys)
	assert.Equal(t, cp.engine, c.engine)
	assert.Equal(t, cp.Params(), c.Params())
	cp.Set("foo", "notBar")
	assert.False(t, cp.Keys["foo"] == c.Keys["foo"])
}

func TestContextHandlerName(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.handlers = HandlersChain{func(c Context) {}, handlerNameTest}

	assert.Regexp(t, "^(.*/vendor/)?gin-tiny.handlerNameTest$", c.HandlerName())
}

func TestContextHandlerNames(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.handlers = HandlersChain{func(c Context) {}, handlerNameTest, func(c Context) {}, handlerNameTest2}

	names := c.HandlerNames()

	assert.True(t, len(names) == 4)
	for _, name := range names {
		assert.Regexp(t, `^(.*/vendor/)?(gin-tiny\.){1}(TestContextHandlerNames\.func.*){0,1}(handlerNameTest.*){0,1}`, name)
	}
}

func handlerNameTest(c Context) {
}

func handlerNameTest2(c Context) {
}

var handlerTest HandlerFunc = func(c Context) {
}

func TestContextHandler(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.handlers = HandlersChain{func(c Context) {}, handlerTest}

	assert.Equal(t, reflect.ValueOf(handlerTest).Pointer(), reflect.ValueOf(c.handlers[len(c.handlers)-1]).Pointer())
}

func TestContextQuery(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("GET", "http://example.com/?foo=bar&page=10&id=", nil)

	value, ok := c.GetQuery("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", value)
	assert.Equal(t, "bar", c.DefaultQuery("foo", "none"))
	assert.Equal(t, "bar", c.Query("foo"))

	value, ok = c.GetQuery("page")
	assert.True(t, ok)
	assert.Equal(t, "10", value)
	assert.Equal(t, "10", c.DefaultQuery("page", "0"))
	assert.Equal(t, "10", c.Query("page"))

	value, ok = c.GetQuery("id")
	assert.True(t, ok)
	assert.Empty(t, value)
	assert.Empty(t, c.DefaultQuery("id", "nada"))
	assert.Empty(t, c.Query("id"))

	value, ok = c.GetQuery("NoKey")
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Equal(t, "nada", c.DefaultQuery("NoKey", "nada"))
	assert.Empty(t, c.Query("NoKey"))

	// postform should not mess
	value, ok = c.GetPostForm("page")
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Empty(t, c.PostForm("foo"))
}

func TestContextDefaultQueryOnEmptyRequest(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder()) // here c.Request == nil
	assert.NotPanics(t, func() {
		value, ok := c.GetQuery("NoKey")
		assert.False(t, ok)
		assert.Empty(t, value)
	})
	assert.NotPanics(t, func() {
		assert.Equal(t, "nada", c.DefaultQuery("NoKey", "nada"))
	})
	assert.NotPanics(t, func() {
		assert.Empty(t, c.Query("NoKey"))
	})
}

func TestContextQueryAndPostForm(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	body := bytes.NewBufferString("foo=bar&page=11&both=&foo=second")
	c.request, _ = http.NewRequest("POST",
		"/?both=GET&id=main&id=omit&array[]=first&array[]=second&ids[a]=hi&ids[b]=3.14", body)
	c.request.Header.Add("Content-Type", MIMEPOSTForm)

	assert.Equal(t, "bar", c.DefaultPostForm("foo", "none"))
	assert.Equal(t, "bar", c.PostForm("foo"))
	assert.Empty(t, c.Query("foo"))

	value, ok := c.GetPostForm("page")
	assert.True(t, ok)
	assert.Equal(t, "11", value)
	assert.Equal(t, "11", c.DefaultPostForm("page", "0"))
	assert.Equal(t, "11", c.PostForm("page"))
	assert.Empty(t, c.Query("page"))

	value, ok = c.GetPostForm("both")
	assert.True(t, ok)
	assert.Empty(t, value)
	assert.Empty(t, c.PostForm("both"))
	assert.Empty(t, c.DefaultPostForm("both", "nothing"))
	assert.Equal(t, "GET", c.Query("both"), "GET")

	value, ok = c.GetQuery("id")
	assert.True(t, ok)
	assert.Equal(t, "main", value)
	assert.Equal(t, "000", c.DefaultPostForm("id", "000"))
	assert.Equal(t, "main", c.Query("id"))
	assert.Empty(t, c.PostForm("id"))

	value, ok = c.GetQuery("NoKey")
	assert.False(t, ok)
	assert.Empty(t, value)
	value, ok = c.GetPostForm("NoKey")
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Equal(t, "nada", c.DefaultPostForm("NoKey", "nada"))
	assert.Equal(t, "nothing", c.DefaultQuery("NoKey", "nothing"))
	assert.Empty(t, c.PostForm("NoKey"))
	assert.Empty(t, c.Query("NoKey"))

	var obj struct {
		Foo   string   `form:"foo"`
		ID    string   `form:"id"`
		Page  int      `form:"page"`
		Both  string   `form:"both"`
		Array []string `form:"array[]"`
	}
	assert.NoError(t, c.Bind(&obj))
	assert.Equal(t, "bar", obj.Foo, "bar")
	assert.Equal(t, "main", obj.ID, "main")
	assert.Equal(t, 11, obj.Page, 11)
	assert.Empty(t, obj.Both)
	assert.Equal(t, []string{"first", "second"}, obj.Array)

	values, ok := c.GetQueryArray("array[]")
	assert.True(t, ok)
	assert.Equal(t, "first", values[0])
	assert.Equal(t, "second", values[1])

	values = c.QueryArray("array[]")
	assert.Equal(t, "first", values[0])
	assert.Equal(t, "second", values[1])

	values = c.QueryArray("nokey")
	assert.Equal(t, 0, len(values))

	values = c.QueryArray("both")
	assert.Equal(t, 1, len(values))
	assert.Equal(t, "GET", values[0])

	dicts, ok := c.GetQueryMap("ids")
	assert.True(t, ok)
	assert.Equal(t, "hi", dicts["a"])
	assert.Equal(t, "3.14", dicts["b"])

	dicts, ok = c.GetQueryMap("nokey")
	assert.False(t, ok)
	assert.Equal(t, 0, len(dicts))

	dicts, ok = c.GetQueryMap("both")
	assert.False(t, ok)
	assert.Equal(t, 0, len(dicts))

	dicts, ok = c.GetQueryMap("array")
	assert.False(t, ok)
	assert.Equal(t, 0, len(dicts))

	dicts = c.QueryMap("ids")
	assert.Equal(t, "hi", dicts["a"])
	assert.Equal(t, "3.14", dicts["b"])

	dicts = c.QueryMap("nokey")
	assert.Equal(t, 0, len(dicts))
}

func TestContextPostFormMultipart(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request = createMultipartRequest()

	var obj struct {
		Foo          string    `form:"foo"`
		Bar          string    `form:"bar"`
		BarAsInt     int       `form:"bar"`
		Array        []string  `form:"array"`
		ID           string    `form:"id"`
		TimeLocal    time.Time `form:"time_local" time_format:"02/01/2006 15:04"`
		TimeUTC      time.Time `form:"time_utc" time_format:"02/01/2006 15:04" time_utc:"1"`
		TimeLocation time.Time `form:"time_location" time_format:"02/01/2006 15:04" time_location:"Asia/Tokyo"`
		BlankTime    time.Time `form:"blank_time" time_format:"02/01/2006 15:04"`
	}
	assert.NoError(t, c.Bind(&obj))
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, "10", obj.Bar)
	assert.Equal(t, 10, obj.BarAsInt)
	assert.Equal(t, []string{"first", "second"}, obj.Array)
	assert.Empty(t, obj.ID)
	assert.Equal(t, "31/12/2016 14:55", obj.TimeLocal.Format("02/01/2006 15:04"))
	assert.Equal(t, time.Local, obj.TimeLocal.Location())
	assert.Equal(t, "31/12/2016 14:55", obj.TimeUTC.Format("02/01/2006 15:04"))
	assert.Equal(t, time.UTC, obj.TimeUTC.Location())
	loc, _ := time.LoadLocation("Asia/Tokyo")
	assert.Equal(t, "31/12/2016 14:55", obj.TimeLocation.Format("02/01/2006 15:04"))
	assert.Equal(t, loc, obj.TimeLocation.Location())
	assert.True(t, obj.BlankTime.IsZero())

	value, ok := c.GetQuery("foo")
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Empty(t, c.Query("bar"))
	assert.Equal(t, "nothing", c.DefaultQuery("id", "nothing"))

	value, ok = c.GetPostForm("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", value)
	assert.Equal(t, "bar", c.PostForm("foo"))

	value, ok = c.GetPostForm("array")
	assert.True(t, ok)
	assert.Equal(t, "first", value)
	assert.Equal(t, "first", c.PostForm("array"))

	assert.Equal(t, "10", c.DefaultPostForm("bar", "nothing"))

	value, ok = c.GetPostForm("id")
	assert.True(t, ok)
	assert.Empty(t, value)
	assert.Empty(t, c.PostForm("id"))
	assert.Empty(t, c.DefaultPostForm("id", "nothing"))

	value, ok = c.GetPostForm("nokey")
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Equal(t, "nothing", c.DefaultPostForm("nokey", "nothing"))

	values, ok := c.GetPostFormArray("array")
	assert.True(t, ok)
	assert.Equal(t, "first", values[0])
	assert.Equal(t, "second", values[1])

	values = c.PostFormArray("array")
	assert.Equal(t, "first", values[0])
	assert.Equal(t, "second", values[1])

	values = c.PostFormArray("nokey")
	assert.Equal(t, 0, len(values))

	values = c.PostFormArray("foo")
	assert.Equal(t, 1, len(values))
	assert.Equal(t, "bar", values[0])

	dicts, ok := c.GetPostFormMap("names")
	assert.True(t, ok)
	assert.Equal(t, "thinkerou", dicts["a"])
	assert.Equal(t, "tianou", dicts["b"])

	dicts, ok = c.GetPostFormMap("nokey")
	assert.False(t, ok)
	assert.Equal(t, 0, len(dicts))

	dicts = c.PostFormMap("names")
	assert.Equal(t, "thinkerou", dicts["a"])
	assert.Equal(t, "tianou", dicts["b"])

	dicts = c.PostFormMap("nokey")
	assert.Equal(t, 0, len(dicts))
}

func TestContextSetCookie(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("user", "gin", 1, "/", "localhost", true, true)
	assert.Equal(t, "user=gin; Path=/; Domain=localhost; Max-Age=1; HttpOnly; Secure; SameSite=Lax", c.writermem.Header().Get("Set-Cookie"))
}

func TestContextSetCookiePathEmpty(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("user", "gin", 1, "", "localhost", true, true)
	assert.Equal(t, "user=gin; Path=/; Domain=localhost; Max-Age=1; HttpOnly; Secure; SameSite=Lax", c.writermem.Header().Get("Set-Cookie"))
}

func TestContextGetCookie(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("GET", "/get", nil)
	c.request.Header.Set("Cookie", "user=gin")
	cookie, _ := c.Cookie("user")
	assert.Equal(t, "gin", cookie.Value)

	_, err := c.Cookie("nokey")
	assert.Error(t, err)
}

func TestContextBodyAllowedForStatus(t *testing.T) {
	assert.False(t, false, bodyAllowedForStatus(http.StatusProcessing))
	assert.False(t, false, bodyAllowedForStatus(http.StatusNoContent))
	assert.False(t, false, bodyAllowedForStatus(http.StatusNotModified))
	assert.True(t, true, bodyAllowedForStatus(http.StatusInternalServerError))
}

type TestRender struct{}

func (*TestRender) Render(http.ResponseWriter) error {
	return errTestRender
}

func (*TestRender) WriteContentType(http.ResponseWriter) {}

func TestContextRenderIfErr(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Render(http.StatusOK, &TestRender{})

	assert.Equal(t, errorMsgs{&Error{Err: errTestRender, Type: 1}}, c.errors)
}

// Tests that the response is serialized as JSON
// and Content-Type is set to application/json
// and special HTML characters are escaped
func TestContextRenderJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.JSON(http.StatusCreated, H{"foo": "bar", "html": "<b>"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "{\"foo\":\"bar\",\"html\":\"\\u003cb\\u003e\"}", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that the response is serialized as JSONP
// and Content-Type is set to application/javascript
func TestContextRenderJSONP(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("GET", "http://example.com/?callback=x", nil)

	c.JSONP(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "x({\"foo\":\"bar\"});", w.Body.String())
	assert.Equal(t, "application/javascript; charset=UTF-8", w.Header().Get("Content-Type"))
}

// Tests that the response is serialized as JSONP
// and Content-Type is set to application/json
func TestContextRenderJSONPWithoutCallback(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("GET", "http://example.com", nil)

	c.JSONP(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "{\"foo\":\"bar\"}", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that no JSON is rendered if code is 204
func TestContextRenderNoContentJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.JSON(http.StatusNoContent, H{"foo": "bar"})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that the response is serialized as JSON
// we change the content-type before
func TestContextRenderAPIJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Header("Content-Type", "application/vnd.api+json")
	c.JSON(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "{\"foo\":\"bar\"}", w.Body.String())
	assert.Equal(t, "application/vnd.api+json", w.Header().Get("Content-Type"))
}

// Tests that no Custom JSON is rendered if code is 204
func TestContextRenderNoContentAPIJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Header("Content-Type", "application/vnd.api+json")
	c.JSON(http.StatusNoContent, H{"foo": "bar"})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, w.Header().Get("Content-Type"), "application/vnd.api+json")
}

// Tests that the response is serialized as JSON
// and Content-Type is set to application/json
func TestContextRenderIndentedJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.IndentedJSON(http.StatusCreated, H{"foo": "bar", "bar": "foo", "nested": H{"foo": "bar"}})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "{\n    \"bar\": \"foo\",\n    \"foo\": \"bar\",\n    \"nested\": {\n        \"foo\": \"bar\"\n    }\n}", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that no Custom JSON is rendered if code is 204
func TestContextRenderNoContentIndentedJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.IndentedJSON(http.StatusNoContent, H{"foo": "bar", "bar": "foo", "nested": H{"foo": "bar"}})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that the response is serialized as Secure JSON
// and Content-Type is set to application/json
func TestContextRenderSecureJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, router := CreateTestContext(w)

	router.SecureJsonPrefix("&&&START&&&")
	c.SecureJSON(http.StatusCreated, []string{"foo", "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "&&&START&&&[\"foo\",\"bar\"]", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that no Custom JSON is rendered if code is 204
func TestContextRenderNoContentSecureJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.SecureJSON(http.StatusNoContent, []string{"foo", "bar"})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestContextRenderNoContentAsciiJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.AsciiJSON(http.StatusNoContent, []string{"lang", "Go语言"})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// Tests that the response is serialized as JSON
// and Content-Type is set to application/json
// and special HTML characters are preserved
func TestContextRenderPureJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.PureJSON(http.StatusCreated, H{"foo": "bar", "html": "<b>"})
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "{\"foo\":\"bar\",\"html\":\"<b>\"}\n", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// TestContextXML tests that the response is serialized as XML
// and Content-Type is set to application/xml
func TestContextRenderXML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.XML(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "<map><foo>bar</foo></map>", w.Body.String())
	assert.Equal(t, "application/xml; charset=UTF-8", w.Header().Get("Content-Type"))
}

// Tests that no XML is rendered if code is 204
func TestContextRenderNoContentXML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.XML(http.StatusNoContent, H{"foo": "bar"})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "application/xml; charset=UTF-8", w.Header().Get("Content-Type"))
}

// TestContextString tests that the response is returned
// with Content-Type set to text/plain
func TestContextRenderString(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.String(http.StatusCreated, "test %s %d", "string", 2)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "test string 2", w.Body.String())
	assert.Equal(t, "text/plain; charset=UTF-8", w.Header().Get("Content-Type"))
}

// Tests that no String is rendered if code is 204
func TestContextRenderNoContentString(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.String(http.StatusNoContent, "test %s %d", "string", 2)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "text/plain; charset=UTF-8", w.Header().Get("Content-Type"))
}

// TestContextString tests that the response is returned
// with Content-Type set to text/html
func TestContextRenderHTMLString(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Header("Content-Type", "text/html; charset=UTF-8")
	c.String(http.StatusCreated, "<html>%s %d</html>", "string", 3)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "<html>string 3</html>", w.Body.String())
	assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))
}

// Tests that no HTML String is rendered if code is 204
func TestContextRenderNoContentHTMLString(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Header("Content-Type", "text/html; charset=UTF-8")
	c.String(http.StatusNoContent, "<html>%s %d</html>", "string", 3)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))
}

// TestContextData tests that the response can be written from `bytestring`
// with specified MIME type
func TestContextRenderData(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Data(http.StatusCreated, "text/csv", []byte(`foo,bar`))

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "foo,bar", w.Body.String())
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
}

// Tests that no Custom Data is rendered if code is 204
func TestContextRenderNoContentData(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Data(http.StatusNoContent, "text/csv", []byte(`foo,bar`))

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
}

func TestContextRenderSSE(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.SSEvent("float", 1.5)
	c.Render(-1, sse.Event{
		Id:   "123",
		Data: "text",
	})
	c.SSEvent("chat", H{
		"foo": "bar",
		"bar": "foo",
	})

	assert.Equal(t, strings.Replace(w.Body.String(), " ", "", -1), strings.Replace("event:float\ndata:1.5\n\nid:123\ndata:text\n\nevent:chat\ndata:{\"bar\":\"foo\",\"foo\":\"bar\"}\n\n", " ", "", -1))
}

func TestContextRenderFile(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("GET", "/", nil)
	c.File("./gin.go")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "func New() *Engine {")
	// Content-Type='text/plain; charset=utf-8' when go version <= 1.16,
	// else, Content-Type='text/x-go; charset=utf-8'
	assert.NotEqual(t, "", w.Header().Get("Content-Type"))
}

func TestContextRenderFileFromFS(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("GET", "/some/path", nil)
	c.FileFromFS("./gin.go", Dir(".", false))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "func New() *Engine {")
	// Content-Type='text/plain; charset=utf-8' when go version <= 1.16,
	// else, Content-Type='text/x-go; charset=utf-8'
	assert.NotEqual(t, "", w.Header().Get("Content-Type"))
	assert.Equal(t, "/some/path", c.request.URL.Path)
}

func TestContextRenderAttachment(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	newFilename := "new_filename.go"

	c.request, _ = http.NewRequest("GET", "/", nil)
	c.FileAttachment("./gin.go", newFilename)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "func New() *Engine {")
	assert.Equal(t, fmt.Sprintf("attachment; filename=\"%s\"", newFilename), w.Header().Get("Content-Disposition"))
}

func TestContextRenderAndEscapeAttachment(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	maliciousFilename := "tampering_field.sh\"; \\\"; dummy=.go"
	actualEscapedResponseFilename := "tampering_field.sh\\\"; \\\\\\\"; dummy=.go"

	c.request, _ = http.NewRequest("GET", "/", nil)
	c.FileAttachment("./gin.go", maliciousFilename)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "func New() *Engine {")
	assert.Equal(t, fmt.Sprintf("attachment; filename=\"%s\"", actualEscapedResponseFilename), w.Header().Get("Content-Disposition"))
}

func TestContextRenderUTF8Attachment(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	newFilename := "new🧡_filename.go"

	c.request, _ = http.NewRequest("GET", "/", nil)
	c.FileAttachment("./gin.go", newFilename)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "func New() *Engine {")
	assert.Equal(t, `attachment; filename*=UTF-8''`+url.QueryEscape(newFilename), w.Header().Get("Content-Disposition"))
}

// TestContextRenderYAML tests that the response is serialized as YAML
// and Content-Type is set to application/x-yaml
func TestContextRenderYAML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.YAML(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "foo: bar\n", w.Body.String())
	assert.Equal(t, "application/yaml; charset=UTF-8", w.Header().Get("Content-Type"))
}

// TestContextRenderTOML tests that the response is serialized as TOML
// and Content-Type is set to application/toml
func TestContextRenderTOML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.TOML(http.StatusCreated, H{"foo": "bar"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "foo = 'bar'\n", w.Body.String())
	assert.Equal(t, "application/toml; charset=UTF-8", w.Header().Get("Content-Type"))
}

// TestContextRenderProtoBuf tests that the response is serialized as ProtoBuf
// and Content-Type is set to application/x-protobuf
// and we just use the example protobuf to check if the response is correct
func TestContextRenderProtoBuf(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	reps := []int64{int64(1), int64(2)}
	label := "test"
	data := &testdata.Test{
		Label: &label,
		Reps:  reps,
	}

	c.ProtoBuf(http.StatusCreated, data)

	protoData, err := proto.Marshal(data)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, string(protoData), w.Body.String())
	assert.Equal(t, "application/protobuf", w.Header().Get("Content-Type"))
}

func TestContextHeaders(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Header("Content-Type", "text/plain")
	c.Header("X-Custom", "value")

	assert.Equal(t, "text/plain", c.writermem.Header().Get("Content-Type"))
	assert.Equal(t, "value", c.writermem.Header().Get("X-Custom"))

	c.Header("Content-Type", "text/html")
	c.Header("X-Custom", "")

	assert.Equal(t, "text/html", c.writermem.Header().Get("Content-Type"))
	_, exist := c.writermem.Header()["X-Custom"]
	assert.False(t, exist)
}

// TODO
func TestContextRenderRedirectWithRelativePath(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "http://example.com", nil)
	assert.Panics(t, func() { c.Redirect(299, "/new_path") })
	assert.Panics(t, func() { c.Redirect(309, "/new_path") })

	c.Redirect(http.StatusMovedPermanently, "/path")
	c.Response().WriteHeaderNow()
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, "/path", w.Header().Get("Location"))
}

func TestContextRenderRedirectWithAbsolutePath(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "http://example.com", nil)
	c.Redirect(http.StatusFound, "http://google.com")
	c.Response().WriteHeaderNow()

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "http://google.com", w.Header().Get("Location"))
}

func TestContextRenderRedirectWith201(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "http://example.com", nil)
	c.Redirect(http.StatusCreated, "/resource")
	c.Response().WriteHeaderNow()

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "/resource", w.Header().Get("Location"))
}

func TestContextRenderRedirectAll(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "http://example.com", nil)
	assert.Panics(t, func() { c.Redirect(http.StatusOK, "/resource") })
	assert.Panics(t, func() { c.Redirect(http.StatusAccepted, "/resource") })
	assert.Panics(t, func() { c.Redirect(299, "/resource") })
	assert.Panics(t, func() { c.Redirect(309, "/resource") })
	assert.NotPanics(t, func() { c.Redirect(http.StatusMultipleChoices, "/resource") })
	assert.NotPanics(t, func() { c.Redirect(http.StatusPermanentRedirect, "/resource") })
}

func TestContextNegotiationWithJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("POST", "", nil)

	c.Negotiate(http.StatusOK, Negotiate{
		Offered: []string{MIMEJSON, MIMEXML, MIMEYAML},
		Data:    H{"foo": "bar"},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"foo\":\"bar\"}", w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestContextNegotiationWithXML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("POST", "", nil)

	c.Negotiate(http.StatusOK, Negotiate{
		Offered: []string{MIMEXML, MIMEJSON, MIMEYAML},
		Data:    H{"foo": "bar"},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<map><foo>bar</foo></map>", w.Body.String())
	assert.Equal(t, "application/xml; charset=UTF-8", w.Header().Get("Content-Type"))
}

func TestContextNegotiationWithYAML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("POST", "", nil)

	c.Negotiate(http.StatusOK, Negotiate{
		Offered: []string{MIMEYAML, MIMEXML, MIMEJSON, MIMETOML},
		Data:    H{"foo": "bar"},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "foo: bar\n", w.Body.String())
	assert.Equal(t, "application/yaml; charset=UTF-8", w.Header().Get("Content-Type"))
}

func TestContextNegotiationWithTOML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("POST", "", nil)

	c.Negotiate(http.StatusOK, Negotiate{
		Offered: []string{MIMETOML, MIMEXML, MIMEJSON, MIMEYAML},
		Data:    H{"foo": "bar"},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "foo = 'bar'\n", w.Body.String())
	assert.Equal(t, "application/toml; charset=UTF-8", w.Header().Get("Content-Type"))
}

func TestContextNegotiationNotSupport(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.request, _ = http.NewRequest("POST", "", nil)

	c.Negotiate(http.StatusOK, Negotiate{
		Offered: []string{MIMEPOSTForm},
	})

	assert.Equal(t, http.StatusNotAcceptable, w.Code)
	assert.Equal(t, c.index, abortIndex)
	assert.True(t, c.IsAborted())
}

func TestContextNegotiationFormat(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "", nil)

	assert.Panics(t, func() { c.NegotiateFormat() })
	assert.Equal(t, MIMEJSON, c.NegotiateFormat(MIMEJSON, MIMEXML))
}

func TestContextNegotiationFormatWithAccept(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8")

	assert.Equal(t, MIMEXML, c.NegotiateFormat(MIMEJSON, MIMEXML))
	assert.Empty(t, c.NegotiateFormat(MIMEJSON))
}

func TestContextNegotiationFormatWithWildcardAccept(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("Accept", "*/*")

	assert.Equal(t, c.NegotiateFormat("*/*"), "*/*")
	assert.Equal(t, c.NegotiateFormat("text/*"), "text/*")
	assert.Equal(t, c.NegotiateFormat("application/*"), "application/*")
	assert.Equal(t, c.NegotiateFormat(MIMEJSON), MIMEJSON)
	assert.Equal(t, c.NegotiateFormat(MIMEXML), MIMEXML)

	c, _ = CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("Accept", "text/*")

	assert.Equal(t, c.NegotiateFormat("*/*"), "*/*")
	assert.Equal(t, c.NegotiateFormat("text/*"), "text/*")
	assert.Equal(t, c.NegotiateFormat("application/*"), "")
	assert.Equal(t, c.NegotiateFormat(MIMEJSON), "")
	assert.Equal(t, c.NegotiateFormat(MIMEXML), "")
}

func TestContextNegotiationFormatCustom(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8")

	c.Accepted = nil
	c.SetAccepted(MIMEJSON, MIMEXML)

	assert.Equal(t, MIMEJSON, c.NegotiateFormat(MIMEJSON, MIMEXML))
	assert.Equal(t, MIMEJSON, c.NegotiateFormat(MIMEJSON))
}

func TestContextNegotiationFormat2(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("Accept", "image/tiff-fx")

	assert.Equal(t, "", c.NegotiateFormat("image/tiff"))
}

func TestContextIsAborted(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	assert.False(t, c.IsAborted())

	c.Abort()
	assert.True(t, c.IsAborted())

	c.Next()
	assert.True(t, c.IsAborted())

	c.index++
	assert.True(t, c.IsAborted())
}

// TestContextData tests that the response can be written from `bytestring`
// with specified MIME type
func TestContextAbortWithStatus(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.index = 4
	c.AbortWithStatus(http.StatusUnauthorized)

	assert.Equal(t, abortIndex, c.index)
	assert.Equal(t, http.StatusUnauthorized, c.Response().Status())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, c.IsAborted())
}

type testJSONAbortMsg struct {
	Foo string `json:"foo"`
	Bar string `json:"bar"`
}

func TestContextAbortWithStatusJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)
	c.index = 4

	in := new(testJSONAbortMsg)
	in.Bar = "barValue"
	in.Foo = "fooValue"

	c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, in)

	assert.Equal(t, abortIndex, c.index)
	assert.Equal(t, http.StatusUnsupportedMediaType, c.Response().Status())
	assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	assert.True(t, c.IsAborted())

	contentType := w.Header().Get("Content-Type")
	assert.Equal(t, "application/json", contentType)

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(w.Body)
	assert.NoError(t, err)
	jsonStringBody := buf.String()
	assert.Equal(t, "{\"foo\":\"fooValue\",\"bar\":\"barValue\"}", jsonStringBody)
}

func TestContextError(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	assert.Empty(t, c.errors)

	firstErr := errors.New("first error")
	c.Error(firstErr) //nolint: errcheck
	assert.Len(t, c.errors, 1)
	assert.Equal(t, "Error #01: first error\n", c.errors.String())

	secondErr := errors.New("second error")
	c.Error(&Error{ //nolint: errcheck
		Err:  secondErr,
		Meta: "some data 2",
		Type: ErrorTypePublic,
	})
	assert.Len(t, c.errors, 2)

	assert.Equal(t, firstErr, c.errors[0].Err)
	assert.Nil(t, c.errors[0].Meta)
	assert.Equal(t, ErrorTypePrivate, c.errors[0].Type)

	assert.Equal(t, secondErr, c.errors[1].Err)
	assert.Equal(t, "some data 2", c.errors[1].Meta)
	assert.Equal(t, ErrorTypePublic, c.errors[1].Type)

	assert.Equal(t, c.errors.Last(), c.errors[1])

	defer func() {
		if recover() == nil {
			t.Error("didn't panic")
		}
	}()
	c.Error(nil) //nolint: errcheck
}

func TestContextTypedError(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.Error(errors.New("externo 0")).SetType(ErrorTypePublic)  //nolint: errcheck
	c.Error(errors.New("interno 0")).SetType(ErrorTypePrivate) //nolint: errcheck

	for _, err := range c.errors.ByType(ErrorTypePublic) {
		assert.Equal(t, ErrorTypePublic, err.Type)
	}
	for _, err := range c.errors.ByType(ErrorTypePrivate) {
		assert.Equal(t, ErrorTypePrivate, err.Type)
	}
	assert.Equal(t, []string{"externo 0", "interno 0"}, c.errors.Errors())
}

func TestContextAbortWithError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.AbortWithError(http.StatusUnauthorized, errors.New("bad input")).SetMeta("some input") //nolint: errcheck

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, abortIndex, c.index)
	assert.True(t, c.IsAborted())
}

func TestContextClientIP(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.engine.trustedCIDRs, _ = c.engine.prepareTrustedCIDRs()
	resetContextForClientIPTests(c)

	// Legacy tests (validating that the defaults don't break the
	// (insecure!) old behaviour)
	assert.Equal(t, "20.20.20.20", c.ClientIP())

	c.request.Header.Del("X-Forwarded-For")
	assert.Equal(t, "10.10.10.10", c.ClientIP())

	c.request.Header.Set("X-Forwarded-For", "30.30.30.30  ")
	assert.Equal(t, "30.30.30.30", c.ClientIP())

	c.request.Header.Del("X-Forwarded-For")
	c.request.Header.Del("X-Real-IP")
	c.engine.TrustedPlatform = PlatformGoogleAppEngine
	assert.Equal(t, "50.50.50.50", c.ClientIP())

	c.request.Header.Del("X-Appengine-Remote-Addr")
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// no port
	c.request.RemoteAddr = "50.50.50.50"
	assert.Empty(t, c.ClientIP())

	// Tests exercising the TrustedProxies functionality
	resetContextForClientIPTests(c)

	// IPv6 support
	c.request.RemoteAddr = "[::1]:12345"
	assert.Equal(t, "20.20.20.20", c.ClientIP())

	resetContextForClientIPTests(c)
	// No trusted proxies
	_ = c.engine.SetTrustedProxies([]string{})
	c.engine.RemoteIPHeaders = []string{"X-Forwarded-For"}
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Disabled TrustedProxies feature
	_ = c.engine.SetTrustedProxies(nil)
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Last proxy is trusted, but the RemoteAddr is not
	_ = c.engine.SetTrustedProxies([]string{"30.30.30.30"})
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Only trust RemoteAddr
	_ = c.engine.SetTrustedProxies([]string{"40.40.40.40"})
	assert.Equal(t, "30.30.30.30", c.ClientIP())

	// All steps are trusted
	_ = c.engine.SetTrustedProxies([]string{"40.40.40.40", "30.30.30.30", "20.20.20.20"})
	assert.Equal(t, "20.20.20.20", c.ClientIP())

	// Use CIDR
	_ = c.engine.SetTrustedProxies([]string{"40.40.25.25/16", "30.30.30.30"})
	assert.Equal(t, "20.20.20.20", c.ClientIP())

	// Use hostname that resolves to all the proxies
	_ = c.engine.SetTrustedProxies([]string{"foo"})
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Use hostname that returns an error
	_ = c.engine.SetTrustedProxies([]string{"bar"})
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// X-Forwarded-For has a non-IP element
	_ = c.engine.SetTrustedProxies([]string{"40.40.40.40"})
	c.request.Header.Set("X-Forwarded-For", " blah ")
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Result from LookupHost has non-IP element. This should never
	// happen, but we should test it to make sure we handle it
	// gracefully.
	_ = c.engine.SetTrustedProxies([]string{"baz"})
	c.request.Header.Set("X-Forwarded-For", " 30.30.30.30 ")
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	_ = c.engine.SetTrustedProxies([]string{"40.40.40.40"})
	c.request.Header.Del("X-Forwarded-For")
	c.engine.RemoteIPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
	assert.Equal(t, "10.10.10.10", c.ClientIP())

	c.engine.RemoteIPHeaders = []string{}
	c.engine.TrustedPlatform = PlatformGoogleAppEngine
	assert.Equal(t, "50.50.50.50", c.ClientIP())

	// Use custom TrustedPlatform header
	c.engine.TrustedPlatform = "X-CDN-IP"
	c.request.Header.Set("X-CDN-IP", "80.80.80.80")
	assert.Equal(t, "80.80.80.80", c.ClientIP())
	// wrong header
	c.engine.TrustedPlatform = "X-Wrong-Header"
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	c.request.Header.Del("X-CDN-IP")
	// TrustedPlatform is empty
	c.engine.TrustedPlatform = ""
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	// Test the legacy flag
	c.engine.AppEngine = true
	assert.Equal(t, "50.50.50.50", c.ClientIP())
	c.engine.AppEngine = false
	c.engine.TrustedPlatform = PlatformGoogleAppEngine

	c.request.Header.Del("X-Appengine-Remote-Addr")
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	c.engine.TrustedPlatform = PlatformCloudflare
	assert.Equal(t, "60.60.60.60", c.ClientIP())

	c.request.Header.Del("CF-Connecting-IP")
	assert.Equal(t, "40.40.40.40", c.ClientIP())

	c.engine.TrustedPlatform = ""

	// no port
	c.request.RemoteAddr = "50.50.50.50"
	assert.Empty(t, c.ClientIP())
}

func resetContextForClientIPTests(c *context) {
	c.request.Header.Set("X-Real-IP", " 10.10.10.10  ")
	c.request.Header.Set("X-Forwarded-For", "  20.20.20.20, 30.30.30.30")
	c.request.Header.Set("X-Appengine-Remote-Addr", "50.50.50.50")
	c.request.Header.Set("CF-Connecting-IP", "60.60.60.60")
	c.request.RemoteAddr = "  40.40.40.40:42123 "
	c.engine.TrustedPlatform = ""
	c.engine.trustedCIDRs = defaultTrustedCIDRs
	c.engine.AppEngine = false
}

func TestContextContentType(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Set("Content-Type", "application/json; charset=utf-8")

	assert.Equal(t, "application/json", c.ContentType())
}

func TestContextAutoBindJSON(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("{\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEJSON)

	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	assert.NoError(t, c.Bind(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Empty(t, c.errors)
}

func TestContextBindWithJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("{\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	assert.NoError(t, c.BindJSON(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBindWithXML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(`<?xml version="1.0" encoding="UTF-8"?>
		<root>
			<foo>FOO</foo>
		   	<bar>BAR</bar>
		</root>`))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `xml:"foo"`
		Bar string `xml:"bar"`
	}
	assert.NoError(t, c.BindXML(&obj))
	assert.Equal(t, "FOO", obj.Foo)
	assert.Equal(t, "BAR", obj.Bar)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBindHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("rate", "8000")
	c.request.Header.Add("domain", "music")
	c.request.Header.Add("limit", "1000")

	var testHeader struct {
		Rate   int    `header:"Rate"`
		Domain string `header:"Domain"`
		Limit  int    `header:"limit"`
	}

	assert.NoError(t, c.BindHeader(&testHeader))
	assert.Equal(t, 8000, testHeader.Rate)
	assert.Equal(t, "music", testHeader.Domain)
	assert.Equal(t, 1000, testHeader.Limit)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBindWithQuery(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/?foo=bar&bar=foo", bytes.NewBufferString("foo=unused"))

	var obj struct {
		Foo string `form:"foo"`
		Bar string `form:"bar"`
	}
	assert.NoError(t, c.BindQuery(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBindWithYAML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("foo: bar\nbar: foo"))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `yaml:"foo"`
		Bar string `yaml:"bar"`
	}
	assert.NoError(t, c.BindYAML(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBindWithTOML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("foo = 'bar'\nbar = 'foo'"))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `toml:"foo"`
		Bar string `toml:"bar"`
	}
	assert.NoError(t, c.BindTOML(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBadAutoBind(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "http://example.com", bytes.NewBufferString("\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEJSON)
	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}

	assert.False(t, c.IsAborted())
	assert.Error(t, c.Bind(&obj))
	c.Response().WriteHeaderNow()

	assert.Empty(t, obj.Bar)
	assert.Empty(t, obj.Foo)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.True(t, c.IsAborted())
}

func TestContextAutoShouldBindJSON(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("{\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEJSON)

	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	assert.NoError(t, c.ShouldBind(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Empty(t, c.errors)
}

func TestContextShouldBindWithJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("{\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	assert.NoError(t, c.ShouldBindJSON(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextShouldBindWithXML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString(`<?xml version="1.0" encoding="UTF-8"?>
		<root>
			<foo>FOO</foo>
			<bar>BAR</bar>
		</root>`))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `xml:"foo"`
		Bar string `xml:"bar"`
	}
	assert.NoError(t, c.ShouldBindXML(&obj))
	assert.Equal(t, "FOO", obj.Foo)
	assert.Equal(t, "BAR", obj.Bar)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextShouldBindHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.Header.Add("rate", "8000")
	c.request.Header.Add("domain", "music")
	c.request.Header.Add("limit", "1000")

	var testHeader struct {
		Rate   int    `header:"Rate"`
		Domain string `header:"Domain"`
		Limit  int    `header:"limit"`
	}

	assert.NoError(t, c.ShouldBindHeader(&testHeader))
	assert.Equal(t, 8000, testHeader.Rate)
	assert.Equal(t, "music", testHeader.Domain)
	assert.Equal(t, 1000, testHeader.Limit)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextShouldBindWithQuery(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/?foo=bar&bar=foo&Foo=bar1&Bar=foo1", bytes.NewBufferString("foo=unused"))

	var obj struct {
		Foo  string `form:"foo"`
		Bar  string `form:"bar"`
		Foo1 string `form:"Foo"`
		Bar1 string `form:"Bar"`
	}
	assert.NoError(t, c.ShouldBindQuery(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, "foo1", obj.Bar1)
	assert.Equal(t, "bar1", obj.Foo1)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextShouldBindWithYAML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("foo: bar\nbar: foo"))
	c.request.Header.Add("Content-Type", MIMEXML) // set fake content-type

	var obj struct {
		Foo string `yaml:"foo"`
		Bar string `yaml:"bar"`
	}
	assert.NoError(t, c.ShouldBindYAML(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextShouldBindWithTOML(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("foo='bar'\nbar= 'foo'"))
	c.request.Header.Add("Content-Type", MIMETOML) // set fake content-type

	var obj struct {
		Foo string `toml:"foo"`
		Bar string `toml:"bar"`
	}
	assert.NoError(t, c.ShouldBindTOML(&obj))
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}

func TestContextBadAutoShouldBind(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.request, _ = http.NewRequest("POST", "http://example.com", bytes.NewBufferString("\"foo\":\"bar\", \"bar\":\"foo\"}"))
	c.request.Header.Add("Content-Type", MIMEJSON)
	var obj struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}

	assert.False(t, c.IsAborted())
	assert.Error(t, c.ShouldBind(&obj))

	assert.Empty(t, obj.Bar)
	assert.Empty(t, obj.Foo)
	assert.False(t, c.IsAborted())
}

func TestContextShouldBindBodyWith(t *testing.T) {
	type typeA struct {
		Foo string `json:"foo" xml:"foo" binding:"required"`
	}
	type typeB struct {
		Bar string `json:"bar" xml:"bar" binding:"required"`
	}
	for _, tt := range []struct {
		name               string
		bindingA, bindingB binding.BindingBody
		bodyA, bodyB       string
	}{
		{
			name:     "JSON & JSON",
			bindingA: binding.JSON,
			bindingB: binding.JSON,
			bodyA:    `{"foo":"FOO"}`,
			bodyB:    `{"bar":"BAR"}`,
		},
		{
			name:     "JSON & XML",
			bindingA: binding.JSON,
			bindingB: binding.XML,
			bodyA:    `{"foo":"FOO"}`,
			bodyB: `<?xml version="1.0" encoding="UTF-8"?>
<root>
   <bar>BAR</bar>
</root>`,
		},
		{
			name:     "XML & XML",
			bindingA: binding.XML,
			bindingB: binding.XML,
			bodyA: `<?xml version="1.0" encoding="UTF-8"?>
<root>
   <foo>FOO</foo>
</root>`,
			bodyB: `<?xml version="1.0" encoding="UTF-8"?>
<root>
   <bar>BAR</bar>
</root>`,
		},
	} {
		t.Logf("testing: %s", tt.name)
		// bodyA to typeA and typeB
		{
			w := httptest.NewRecorder()
			c, _ := CreateTestContext(w)
			c.request, _ = http.NewRequest(
				"POST", "http://example.com", bytes.NewBufferString(tt.bodyA),
			)
			// When it binds to typeA and typeB, it finds the body is
			// not typeB but typeA.
			objA := typeA{}
			assert.NoError(t, c.ShouldBindBodyWith(&objA, tt.bindingA))
			assert.Equal(t, typeA{"FOO"}, objA)
			objB := typeB{}
			assert.Error(t, c.ShouldBindBodyWith(&objB, tt.bindingB))
			assert.NotEqual(t, typeB{"BAR"}, objB)
		}
		// bodyB to typeA and typeB
		{
			// When it binds to typeA and typeB, it finds the body is
			// not typeA but typeB.
			w := httptest.NewRecorder()
			c, _ := CreateTestContext(w)
			c.request, _ = http.NewRequest(
				"POST", "http://example.com", bytes.NewBufferString(tt.bodyB),
			)
			objA := typeA{}
			assert.Error(t, c.ShouldBindBodyWith(&objA, tt.bindingA))
			assert.NotEqual(t, typeA{"FOO"}, objA)
			objB := typeB{}
			assert.NoError(t, c.ShouldBindBodyWith(&objB, tt.bindingB))
			assert.Equal(t, typeB{"BAR"}, objB)
		}
	}
}

//func TestContextGolangContext(t *testing.T) {
//	c, _ := CreateTestContext(httptest.NewRecorder())
//	c.request, _ = http.NewRequest("POST", "/", bytes.NewBufferString("{\"foo\":\"bar\", \"bar\":\"foo\"}"))
//	assert.NoError(t, c.Err())
//	assert.Nil(t, c.Done())
//	ti, ok := c.Deadline()
//	assert.Equal(t, ti, time.Time{})
//	assert.False(t, ok)
//	assert.Equal(t, c.Value(0), c.request)
//	assert.Equal(t, c.Value(ContextKey), c)
//	assert.Nil(t, c.Value("foo"))
//
//	c.Set("foo", "bar")
//	assert.Equal(t, "bar", c.Value("foo"))
//	assert.Nil(t, c.Value(1))
//}

func TestWebsocketsRequired(t *testing.T) {
	// Example request from spec: https://tools.ietf.org/html/rfc6455#section-1.2
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("GET", "/chat", nil)
	c.request.Header.Set("Host", "server.example.com")
	c.request.Header.Set("Upgrade", "websocket")
	c.request.Header.Set("Connection", "Upgrade")
	c.request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	c.request.Header.Set("Origin", "http://example.com")
	c.request.Header.Set("Sec-WebSocket-Protocol", "chat, superchat")
	c.request.Header.Set("Sec-WebSocket-Version", "13")

	assert.True(t, c.IsWebsocket())

	// Normal request, no websocket required.
	c, _ = CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("GET", "/chat", nil)
	c.request.Header.Set("Host", "server.example.com")

	assert.False(t, c.IsWebsocket())
}

func TestGetRequestHeaderValue(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("GET", "/chat", nil)
	c.request.Header.Set("Gin-Version", "1.0.0")

	assert.Equal(t, "1.0.0", c.GetHeader("Gin-Version"))
	assert.Empty(t, c.GetHeader("Connection"))
}

func TestContextGetRawData(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	body := bytes.NewBufferString("Fetch binary post data")
	c.request, _ = http.NewRequest("POST", "/", body)
	c.request.Header.Add("Content-Type", MIMEPOSTForm)

	data, err := c.GetRawData()
	assert.Nil(t, err)
	assert.Equal(t, "Fetch binary post data", string(data))
}

func TestContextRenderDataFromReader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	body := "#!PNG some raw data"
	reader := strings.NewReader(body)
	contentLength := int64(len(body))
	contentType := "image/png"
	extraHeaders := map[string]string{"Content-Disposition": `attachment; filename="gopher.png"`}

	c.DataFromReader(http.StatusOK, contentLength, contentType, reader, extraHeaders)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, body, w.Body.String())
	assert.Equal(t, contentType, w.Header().Get("Content-Type"))
	assert.Equal(t, fmt.Sprintf("%d", contentLength), w.Header().Get("Content-Length"))
	assert.Equal(t, extraHeaders["Content-Disposition"], w.Header().Get("Content-Disposition"))
}

func TestContextRenderDataFromReaderNoHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	body := "#!PNG some raw data"
	reader := strings.NewReader(body)
	contentLength := int64(len(body))
	contentType := "image/png"

	c.DataFromReader(http.StatusOK, contentLength, contentType, reader, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, body, w.Body.String())
	assert.Equal(t, contentType, w.Header().Get("Content-Type"))
	assert.Equal(t, fmt.Sprintf("%d", contentLength), w.Header().Get("Content-Length"))
}

type TestResponseRecorder struct {
	*httptest.ResponseRecorder
	closeChannel chan bool
}

func (r *TestResponseRecorder) CloseNotify() <-chan bool {
	return r.closeChannel
}

func (r *TestResponseRecorder) closeClient() {
	r.closeChannel <- true
}

func CreateTestResponseRecorder() *TestResponseRecorder {
	return &TestResponseRecorder{
		httptest.NewRecorder(),
		make(chan bool, 1),
	}
}

//func TestContextStream(t *testing.T) {
//	w := CreateTestResponseRecorder()
//	c, _ := CreateTestContext(w)
//
//	stopStream := true
//	c.Stream(func(w io.Writer) bool {
//		defer func() {
//			stopStream = false
//		}()
//
//		_, err := w.Write([]byte("test"))
//		assert.NoError(t, err)
//
//		return stopStream
//	})
//
//	assert.Equal(t, "testtest", w.Body.String())
//}
//
//func TestContextStreamWithClientGone(t *testing.T) {
//	w := CreateTestResponseRecorder()
//	c, _ := CreateTestContext(w)
//
//	c.Stream(func(writer io.Writer) bool {
//		defer func() {
//			w.closeClient()
//		}()
//
//		_, err := writer.Write([]byte("test"))
//		assert.NoError(t, err)
//
//		return true
//	})
//
//	assert.Equal(t, "test", w.Body.String())
//}

func TestContextResetInHandler(t *testing.T) {
	w := CreateTestResponseRecorder()
	c, _ := CreateTestContext(w)

	c.handlers = []HandlerFunc{
		func(c Context) { c.Reset() },
	}
	assert.NotPanics(t, func() {
		c.Next()
	})
}

//func TestRaceParamsContextCopy(t *testing.T) {
//	DefaultWriter = os.Stdout
//	router := Default()
//	nameGroup := router.Group("/:name")
//	var wg sync.WaitGroup
//	wg.Add(2)
//	{
//		nameGroup.GET("/api", func(c Context) {
//			go func(c *context, param string) {
//				defer wg.Done()
//				// First assert must be executed after the second request
//				time.Sleep(50 * time.Millisecond)
//				assert.Equal(t, c.Param("name"), param)
//			}(c.Copy(), c.Param("name"))
//		})
//	}
//	PerformRequest(router, "GET", "/name1/api")
//	PerformRequest(router, "GET", "/name2/api")
//	wg.Wait()
//}

func TestContextWithKeysMutex(t *testing.T) {
	c := &context{}
	c.Set("foo", "bar")

	value, err := c.Get("foo")
	assert.Equal(t, "bar", value)
	assert.True(t, err)

	value, err = c.Get("foo2")
	assert.Nil(t, value)
	assert.False(t, err)
}

func TestRemoteIPFail(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	c.request, _ = http.NewRequest("POST", "/", nil)
	c.request.RemoteAddr = "[:::]:80"
	ip := net.ParseIP(c.RemoteIP())
	trust := c.engine.isTrustedProxy(ip)
	assert.Nil(t, ip)
	assert.False(t, trust)
}

func TestHasRequestContext(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	assert.False(t, c.hasRequestContext(), "no request, no fallback")
	c.engine.ContextWithFallback = true
	assert.False(t, c.hasRequestContext(), "no request, has fallback")
	c.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	assert.True(t, c.hasRequestContext(), "has request, has fallback")
	c.request, _ = http.NewRequestWithContext(nil, "", "", nil) //nolint:staticcheck
	assert.False(t, c.hasRequestContext(), "has request with nil ctx, has fallback")
	c.engine.ContextWithFallback = false
	assert.False(t, c.hasRequestContext(), "has request, no fallback")

	c = &context{}
	assert.False(t, c.hasRequestContext(), "no request, no engine")
	c.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, c.hasRequestContext(), "has request, no engine")
}

func TestContextWithFallbackDeadlineFromRequestContext(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c.engine.ContextWithFallback = true

	deadline, ok := c.Deadline()
	assert.Zero(t, deadline)
	assert.False(t, ok)

	c2, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c2.engine.ContextWithFallback = true

	c2.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	d := time.Now().Add(time.Second)
	ctx, cancel := ctx.WithDeadline(ctx.Background(), d)
	defer cancel()
	c2.request = c2.request.WithContext(ctx)
	deadline, ok = c2.Deadline()
	assert.Equal(t, d, deadline)
	assert.True(t, ok)
}

func TestContextWithFallbackDoneFromRequestContext(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c.engine.ContextWithFallback = true

	assert.Nil(t, c.Done())

	c2, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c2.engine.ContextWithFallback = true

	c2.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	ctx, cancel := ctx.WithCancel(ctx.Background())
	c2.request = c2.request.WithContext(ctx)
	cancel()
	assert.NotNil(t, <-c2.Done())
}

func TestContextWithFallbackErrFromRequestContext(t *testing.T) {
	c, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c.engine.ContextWithFallback = true

	assert.Nil(t, c.Err())

	c2, _ := CreateTestContext(httptest.NewRecorder())
	// enable ContextWithFallback feature flag
	c2.engine.ContextWithFallback = true

	c2.request, _ = http.NewRequest(http.MethodGet, "/", nil)
	ctx1, cancel := ctx.WithCancel(ctx.Background())
	c2.request = c2.request.WithContext(ctx1)
	cancel()

	assert.EqualError(t, c2.Err(), ctx.Canceled.Error())
}

func TestContextWithFallbackValueFromRequestContext(t *testing.T) {
	type contextKey string

	tests := []struct {
		name             string
		getContextAndKey func() (*context, any)
		value            any
	}{
		{
			name: "c with struct context key",
			getContextAndKey: func() (*context, any) {
				var key struct{}
				c, _ := CreateTestContext(httptest.NewRecorder())
				// enable ContextWithFallback feature flag
				c.engine.ContextWithFallback = true
				c.request, _ = http.NewRequest("POST", "/", nil)
				c.request = c.request.WithContext(ctx.WithValue(ctx.TODO(), key, "value"))
				return c, key
			},
			value: "value",
		},
		{
			name: "c with string context key",
			getContextAndKey: func() (*context, any) {
				c, _ := CreateTestContext(httptest.NewRecorder())
				// enable ContextWithFallback feature flag
				c.engine.ContextWithFallback = true
				c.request, _ = http.NewRequest("POST", "/", nil)
				c.request = c.request.WithContext(ctx.WithValue(ctx.TODO(), contextKey("key"), "value"))
				return c, contextKey("key")
			},
			value: "value",
		},
		{
			name: "c with nil http.Request",
			getContextAndKey: func() (*context, any) {
				c, _ := CreateTestContext(httptest.NewRecorder())
				// enable ContextWithFallback feature flag
				c.engine.ContextWithFallback = true
				c.request = nil
				return c, "key"
			},
			value: nil,
		},
		{
			name: "c with nil http.Request.context()",
			getContextAndKey: func() (*context, any) {
				c, _ := CreateTestContext(httptest.NewRecorder())
				// enable ContextWithFallback feature flag
				c.engine.ContextWithFallback = true
				c.request, _ = http.NewRequest("POST", "/", nil)
				return c, "key"
			},
			value: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, key := tt.getContextAndKey()
			assert.Equal(t, tt.value, c.Value(key))
		})
	}
}

func TestContextCopyShouldNotCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ensureRequestIsOver := make(chan struct{})

	wg := &sync.WaitGroup{}

	r := New()
	r.GET("/", func(ginctx Context) {
		wg.Add(1)

		ginctx = ginctx.Copy()

		// start async goroutine for calling srv
		go func() {
			defer wg.Done()

			<-ensureRequestIsOver // ensure request is done

			req, err := http.NewRequestWithContext(ginctx, http.MethodGet, srv.URL, nil)
			must(err)

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(fmt.Errorf("request error: %w", err))
				return
			}

			if res.StatusCode != http.StatusOK {
				t.Error(fmt.Errorf("unexpected status code: %s", res.Status))
			}
		}()
	})

	l, err := net.Listen("tcp", ":0")
	must(err)
	go func() {
		s := &http.Server{
			Handler: r,
		}

		must(s.Serve(l))
	}()

	addr := strings.Split(l.Addr().String(), ":")
	res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/", addr[len(addr)-1]))
	if err != nil {
		t.Error(fmt.Errorf("request error: %w", err))
		return
	}

	close(ensureRequestIsOver)

	if res.StatusCode != http.StatusOK {
		t.Error(fmt.Errorf("unexpected status code: %s", res.Status))
		return
	}

	wg.Wait()
}

func TestContextAddParam(t *testing.T) {
	c := &context{
		params: &Params{},
	}
	id := "id"
	value := "1"
	c.AddParam(id, value)

	v, ok := c.params.Get(id)
	assert.Equal(t, ok, true)
	assert.Equal(t, value, v)
}

func TestCreateTestContextWithRouteParams(t *testing.T) {
	w := httptest.NewRecorder()
	engine := New()
	engine.GET("/:action/:name", func(ctx Context) {
		ctx.String(http.StatusOK, "%s %s", ctx.Param("action"), ctx.Param("name"))
	})
	c := CreateTestContextOnly(w, engine)
	c.request, _ = http.NewRequest(http.MethodGet, "/hello/gin", nil)
	engine.HandleContext(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "hello gin", w.Body.String())
}

type interceptedWriter struct {
	ResponseWriter
	b *bytes.Buffer
}

func (i interceptedWriter) WriteHeader(code int) {
	i.ResponseWriter.Header().Del("X-Test")
	i.ResponseWriter.WriteHeader(code)
}

func TestInterceptedHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, r := CreateTestContext(w)

	r.Use(func(c Context) {
		i := interceptedWriter{
			ResponseWriter: c.Response(),
			b:              bytes.NewBuffer(nil),
		}
		c.SetResponse(&i)
		c.Next()
		c.Header("X-Test", "overridden")
		c.SetResponse(i.ResponseWriter)
	})
	r.GET("/", func(c Context) {
		c.Header("X-Test", "original")
		c.Header("X-Test-2", "present")
		c.String(http.StatusOK, "hello world")
	})
	c.request = httptest.NewRequest("GET", "/", nil)
	r.HandleContext(c)
	// Result() has headers frozen when WriteHeaderNow() has been called
	// Compared to this time, this is when the response headers will be flushed
	// As response is flushed on c.String, the Header cannot be set by the first
	// middleware. Assert this
	assert.Equal(t, "", w.Result().Header.Get("X-Test"))
	assert.Equal(t, "present", w.Result().Header.Get("X-Test-2"))
}
