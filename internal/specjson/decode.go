// Package specjson decodes Docker specs with the daemon's standard JSON semantics.
package specjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode requires one object and rejects unknown fields throughout typed specs.
// Parser errors are intentionally redacted: they can contain request values.
func Decode(data []byte, target any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return errors.New("missing or invalid JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid JSON or unsupported Docker field")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("multiple or invalid JSON values")
	}
	return nil
}
