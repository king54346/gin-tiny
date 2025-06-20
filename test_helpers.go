// Copyright 2017 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package ginTiny

import "net/http"

// CreateTestContext returns a fresh engine and context for testing purposes
func CreateTestContext(w http.ResponseWriter) (c *context, r *Engine) {
	r = New()
	c = r.allocateContext(0)

	c.Reset()
	c.writermem = NewResponseWriter(w)
	return
}

// CreateTestContextOnly returns a fresh context base on the engine for testing purposes
func CreateTestContextOnly(w http.ResponseWriter, r *Engine) (c *context) {
	c = r.allocateContext(r.maxParams)
	c.Reset()
	c.writermem = NewResponseWriter(w)
	return
}
