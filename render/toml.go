// Copyright 2022 Gin Core Team. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package render

import (
	"net/http"

	"github.com/pelletier/go-toml/v2"
)

// TOML contains the given interface object.
type TOML struct {
	Data any
}

var tomlContentType = []string{MIMEApplicationTomlCharsetUTF8}

// TOMLContentType 保留以兼容上游 gin 的导出名。
//
// Deprecated: 渲染使用内部的 tomlContentType，修改此变量不会影响响应头。
var TOMLContentType = []string{MIMEApplicationTomlCharsetUTF8}

// Render (TOML) marshals the given interface object and writes data with custom ContentType.
func (r TOML) Render(w http.ResponseWriter) error {
	r.WriteContentType(w)

	bytes, err := toml.Marshal(r.Data)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)
	return err
}

// WriteContentType (TOML) writes TOML ContentType for response.
func (r TOML) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, tomlContentType)
}
