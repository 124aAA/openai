package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

type strictJSONPolicy struct {
	MaxDepth      int
	DisallowNull  bool
	LowercaseKeys bool
	TopLevelOnly  bool
	OpaqueKeys    map[string]bool
}

var (
	stateJSONPolicy     = strictJSONPolicy{}
	envelopeJSONPolicy  = strictJSONPolicy{TopLevelOnly: true}
	migrationJSONPolicy = strictJSONPolicy{
		MaxDepth:      48,
		DisallowNull:  true,
		LowercaseKeys: true,
		OpaqueKeys:    map[string]bool{"server_config": true},
	}
)

// encoding/json compares struct field names using Unicode SimpleFold, which
// includes aliases such as long s and Kelvin sign. Lowercasing alone misses
// those duplicate spellings. A canonical member of each fold cycle gives the
// same equivalence relation in linear key length; no normalization or scan of
// previously seen keys is needed.
func stateFieldEqual(a, b string) bool {
	return stateFieldKey(a) == stateFieldKey(b)
}

func stateFieldKey(name string) string {
	return strings.Map(func(r rune) rune {
		canonical := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		return canonical
	}, name)
}

func validateStrictJSON(data []byte, p strictJSONPolicy) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if p.TopLevelOnly {
		first, err := d.Token()
		if err != nil {
			return err
		}
		if first != json.Delim('{') {
			return errors.New("JSON顶层须为对象")
		}
		seen := map[string]bool{}
		for d.More() {
			tok, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := tok.(string)
			if !ok {
				return errors.New("JSON对象字段无效")
			}
			key := stateFieldKey(name)
			if seen[key] {
				return errors.New("JSON对象含重复字段")
			}
			seen[key] = true
			if p.LowercaseKeys && name != strings.ToLower(name) {
				return errors.New("JSON对象字段拼写无效")
			}
			var raw json.RawMessage
			if err = d.Decode(&raw); err != nil {
				return err
			}
		}
		if _, err := d.Token(); err != nil {
			return err
		}
		if _, err := d.Token(); err != io.EOF {
			return errors.New("JSON包含多余数据")
		}
		return nil
	}

	var walk func(depth int) error
	walk = func(depth int) error {
		if p.MaxDepth > 0 && depth > p.MaxDepth {
			return errors.New("JSON嵌套过深")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			if p.DisallowNull {
				return errors.New("JSON不接受null")
			}
			return nil
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				tok, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := tok.(string)
				if !ok {
					return errors.New("JSON对象字段无效")
				}
				fold := stateFieldKey(name)
				if seen[fold] {
					return errors.New("JSON对象含重复字段")
				}
				seen[fold] = true
				if p.LowercaseKeys && name != strings.ToLower(name) {
					return errors.New("JSON对象字段拼写无效")
				}
				if p.OpaqueKeys[name] {
					var raw json.RawMessage
					if err = d.Decode(&raw); err != nil {
						return err
					}
					continue
				}
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("JSON结构无效")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("JSON包含多余数据")
	}
	return nil
}

func unmarshalStrictStruct(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("JSON包含多余数据")
	}
	return nil
}

func decodeStrictJSON(data []byte, out any, p strictJSONPolicy) error {
	if err := validateStrictJSON(data, p); err != nil {
		return err
	}
	return unmarshalStrictStruct(data, out)
}
