package httpsign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		params map[string]string
		err    error
	}{
		{
			name:  `Missing = character`,
			input: `keyId="rsa-key-1",algorithm"rsa-sha256",headers="(request-target) host date digest",signature="Hello world"`,
			err:   ErrMisingEqualCharacter,
		},
		{
			name:  `Missing " at end value`,
			input: `keyId="rsa-key-1",algorithm="rsa-sha256,headers="(request-target) host date digest",signature="Hello world"`,
			err:   ErrUnterminatedParameter,
		},
		{
			name:  `Missing " at begin value`,
			input: `keyId="rsa-key-1",algorithm=rsa-sha256",headers="(request-target) host date digest",signature="Hello world"`,
			err:   ErrMisingDoubleQuote,
		},
		{
			name:  `empty value`,
			input: `keyId="",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="Hello world"`,
			params: map[string]string{
				"keyId":     "",
				"algorithm": "rsa-sha256",
				"headers":   "(request-target) host date digest",
				"signature": "Hello world",
			},
			err: nil,
		},
		{
			name:  `correct test`,
			input: `keyId="rsa-key-1",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ=="`,
			params: map[string]string{
				"keyId":     "rsa-key-1",
				"algorithm": "rsa-sha256",
				"headers":   "(request-target) host date digest",
				"signature": "70AaN3BDO0XC9QbtgksgCy2jJvmOvshq8VmjSthdXC+sgcgrKrl9WME4DbZv4W7UZKElvCemhDLHQ1Nln9GMkQ==",
			},
			err: nil,
		},
	}
	for _, tc := range tests {
		p := newParser(tc.input)
		results, err := p.parse()
		require.Equal(t, tc.err, err, tc.name)
		if err != nil {
			continue
		}
		assert.Equal(t, tc.params, results, tc.name)
	}
}

func TestParserEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		params map[string]string
		err    error
	}{
		{
			name:   "whitespace after comma",
			input:  "keyId=\"a\", algorithm=\"b\",\tsignature=\"c\"",
			params: map[string]string{"keyId": "a", "algorithm": "b", "signature": "c"},
		},
		{
			name:   "trailing comma and whitespace",
			input:  `keyId="a", `,
			params: map[string]string{"keyId": "a"},
		},
		{
			name:   "quote inside value",
			input:  `keyId="a"b",signature="c"`,
			params: map[string]string{"keyId": `a"b`, "signature": "c"},
		},
		{
			name:   "equal sign inside value (base64 padding)",
			input:  `signature="YWJj=="`,
			params: map[string]string{"signature": "YWJj=="},
		},
		{
			name:  "quote before equal sign",
			input: `keyId"a"`,
			err:   ErrMisingEqualCharacter,
		},
		{
			name:   "empty input",
			input:  "",
			params: map[string]string{},
		},
	}
	for _, tc := range tests {
		results, err := newParser(tc.input).parse()
		require.Equal(t, tc.err, err, tc.name)
		if err == nil {
			assert.Equal(t, tc.params, results, tc.name)
		}
	}
}

func TestParseSignatureStringWithSpaces(t *testing.T) {
	h, err := parseSignatureString(`keyId="read", algorithm="hmac-sha512", headers="(request-target) date", signature="abc"`)
	require.NoError(t, err)
	assert.Equal(t, KeyID("read"), h.keyID)
	assert.Equal(t, "hmac-sha512", h.algorithm)
	assert.Equal(t, []string{"(request-target)", "date"}, h.headers)
	assert.Equal(t, "abc", h.signature)
}

func TestParserRejectsDuplicateParameters(t *testing.T) {
	_, err := newParser(`keyId="a",keyId="b",signature="c"`).parse()
	assert.Equal(t, ErrDuplicateParameter, err)

	_, err = parseSignatureString(`keyId="read", signature="x", signature="y"`)
	assert.Equal(t, ErrDuplicateParameter, err)
}
