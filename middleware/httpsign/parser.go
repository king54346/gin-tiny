package httpsign

import (
	"bytes"
	"io"
)

// 将摘要字符串转换为map
type parser struct {
	input string
	pos   int
	ch    byte
}

func newParser(input string) *parser {
	p := &parser{input: input, pos: -1}
	p.readChar()
	return p
}

func (p *parser) readChar() {
	if p.pos+1 >= len(p.input) {
		p.ch = 0
	} else {
		p.ch = p.input[p.pos+1]
	}
	p.pos++
}

func (p *parser) peekChar() byte {
	if p.pos+1 >= len(p.input) {
		return 0
	}
	return p.input[p.pos+1]
}

func (p *parser) nextParam() (string, string, error) {
	var (
		key       = bytes.NewBuffer(nil)
		keyParsed = false

		val       = bytes.NewBuffer(nil)
		valParsed = false
	)

	// 参数之间允许有可选空白（RFC 7230 OWS），如 keyId="a", signature="b"
	for p.ch == ' ' || p.ch == '\t' {
		p.readChar()
	}
	if p.ch == 0 {
		return "", "", io.EOF
	}

	for {
		switch p.ch {
		case ',', 0:
			if !valParsed {
				return "", "", ErrUnterminatedParameter
			}
			p.readChar()
			return key.String(), val.String(), nil
		case '"':
			if !keyParsed {
				return "", "", ErrMisingEqualCharacter
			}
			if p.peekChar() != ',' && p.peekChar() != 0 {
				if err := val.WriteByte(p.ch); err != nil {
					return "", "", err
				}
			} else {
				valParsed = true
			}
			p.readChar()
		case '=':
			if !keyParsed {
				p.readChar()
				if p.ch != '"' {
					return "", "", ErrMisingDoubleQuote
				}
				keyParsed = true
			} else {
				if err := val.WriteByte(p.ch); err != nil {
					return "", "", err
				}
			}
			p.readChar()
		default:
			if !keyParsed {
				if err := key.WriteByte(p.ch); err != nil {
					return "", "", err
				}
			} else {
				if err := val.WriteByte(p.ch); err != nil {
					return "", "", err
				}
			}
			p.readChar()
		}
	}
}

func (p *parser) parse() (map[string]string, error) {
	params := make(map[string]string)

	for {
		key, val, err := p.nextParam()
		if err == io.EOF {
			return params, nil
		} else if err != nil {
			return nil, err
		}
		// 重复参数（如两个 keyId）会让不同实现取到不同的值，签名协议中必须拒绝，不能静默以后者为准
		if _, dup := params[key]; dup {
			return nil, ErrDuplicateParameter
		}
		params[key] = val
	}
}
