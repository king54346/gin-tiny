package binding

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// day 是自定义日期类型，只接受 2006-01-02 格式
type day struct{ time.Time }

func (d *day) UnmarshalParam(param string) error {
	t, err := time.Parse("2006-01-02", param)
	if err != nil {
		return errors.New("invalid day: " + param)
	}
	d.Time = t
	return nil
}

// csv 把 "a,b,c" 解析成切片，底层类型是 []string，但不按切片的规则逐个绑定
type csv []string

func (c *csv) UnmarshalParam(param string) error {
	*c = strings.Split(param, ",")
	return nil
}

// level 的底层类型是 int，自定义解析应优先于内置的整数转换
type level int

func (l *level) UnmarshalParam(param string) error {
	switch param {
	case "low":
		*l = 1
	case "high":
		*l = 3
	default:
		return errors.New("unknown level " + param)
	}
	return nil
}

type customParams struct {
	From   day     `form:"from" header:"X-From" uri:"from"`
	Tags   csv     `form:"tags"`
	Levels []level `form:"lv"`
	Until  *day    `form:"until"`
	Plain  int     `form:"plain"`
}

func TestBindUnmarshalerQuery(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?from=2024-01-02&tags=a,b,c&lv=low&lv=high&until=2024-12-31&plain=5", nil)
	var p customParams
	require.NoError(t, Query.Bind(req, &p))

	assert.Equal(t, time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), p.From.Time)
	assert.Equal(t, csv{"a", "b", "c"}, p.Tags)
	assert.Equal(t, []level{1, 3}, p.Levels)
	require.NotNil(t, p.Until)
	assert.Equal(t, 2024, p.Until.Year())
	assert.Equal(t, 5, p.Plain, "types without UnmarshalParam keep the built-in rules")
}

func TestBindUnmarshalerErrors(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?from=not-a-date", nil)
	var p customParams
	assert.EqualError(t, Query.Bind(req, &p), "invalid day: not-a-date")

	req, _ = http.NewRequest(http.MethodGet, "/?lv=medium", nil)
	assert.EqualError(t, Query.Bind(req, &p), "unknown level medium")
}

func TestBindUnmarshalerHeaderAndURI(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-From", "2023-05-06")
	var h customParams
	require.NoError(t, Header.Bind(req, &h))
	assert.Equal(t, 2023, h.From.Year())

	var u customParams
	require.NoError(t, Uri.BindUri(map[string][]string{"from": {"2022-07-08"}}, &u))
	assert.Equal(t, 2022, u.From.Year())
}
