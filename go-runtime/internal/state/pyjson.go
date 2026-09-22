package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON renders a value exactly like the Python reference runtime's
// json.dumps(value, sort_keys=True): object keys sorted by code point, ", " as
// the item separator, ": " after each key, ASCII-only output, and no trailing
// newline.
//
// The Python runner stores every durable detail document with that call
// (“json.dumps(detail, sort_keys=True)“), so byte-identical rows are only
// reachable with the same separators and escaping.
func CanonicalJSON(value any) (string, error) {
	return renderPythonJSON(value, "", ", ", ": ")
}

// CanonicalJSONIndent renders a value like json.dumps(value, indent=n,
// sort_keys=True): keys sorted, one member per line, and a trailing newline is
// added by the caller. Python switches to the compact item separator "," once an
// indent is requested.
func CanonicalJSONIndent(value any, indent int) (string, error) {
	if indent < 0 {
		return "", fmt.Errorf("xir state: negative JSON indent %d", indent)
	}
	return renderPythonJSON(value, strings.Repeat(" ", indent), ",", ": ")
}

func renderPythonJSON(value any, indent, itemSeparator, keySeparator string) (string, error) {
	normalized, err := normalizeJSON(value)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	if err := writePythonJSON(&builder, normalized, indent, "", itemSeparator, keySeparator); err != nil {
		return "", err
	}
	return builder.String(), nil
}

// normalizeJSON round-trips a value through encoding/json so structs, typed maps
// and named integer types all arrive as the plain JSON value tree, and so
// numbers keep the literal spelling encoding/json produced for them.
func normalizeJSON(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("xir state: JSON value is not encodable: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("xir state: JSON value is not decodable: %w", err)
	}
	return decoded, nil
}

// DecodeJSON parses a JSON document with numbers kept as json.Number, so a
// receipt's integer fields and a frozen nonce are never rounded through float64.
func DecodeJSON(document []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("trailing JSON content after the first value")
	}
	return decoded, nil
}

// decodeJSONValue is the string form of DecodeJSON, used by the detail
// documents this package writes and merges.
func decodeJSONValue(document string) (any, error) { return DecodeJSON([]byte(document)) }

func writePythonJSON(
	builder *strings.Builder,
	value any,
	indent string,
	level string,
	itemSeparator string,
	keySeparator string,
) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		if typed {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case json.Number:
		// normalizeJSON leaves every number as its literal spelling, so an
		// integer never passes through a float and a float keeps the shortest
		// representation encoding/json chose for it.
		builder.WriteString(typed.String())
	case string:
		writePythonString(builder, typed)
	case []any:
		if len(typed) == 0 {
			builder.WriteString("[]")
			return nil
		}
		child := level + indent
		builder.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				builder.WriteString(itemSeparator)
			}
			if indent != "" {
				builder.WriteByte('\n')
				builder.WriteString(child)
			}
			if err := writePythonJSON(builder, item, indent, child, itemSeparator, keySeparator); err != nil {
				return err
			}
		}
		if indent != "" {
			builder.WriteByte('\n')
			builder.WriteString(level)
		}
		builder.WriteByte(']')
	case map[string]any:
		if len(typed) == 0 {
			builder.WriteString("{}")
			return nil
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		child := level + indent
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteString(itemSeparator)
			}
			if indent != "" {
				builder.WriteByte('\n')
				builder.WriteString(child)
			}
			writePythonString(builder, key)
			builder.WriteString(keySeparator)
			if err := writePythonJSON(builder, typed[key], indent, child, itemSeparator, keySeparator); err != nil {
				return err
			}
		}
		if indent != "" {
			builder.WriteByte('\n')
			builder.WriteString(level)
		}
		builder.WriteByte('}')
	default:
		return fmt.Errorf("xir state: unsupported JSON value of type %T", value)
	}
	return nil
}

// writePythonString escapes one string the way json.dumps does by default:
// ensure_ascii=True, with the short escapes for the five named control
// characters and lowercase \uXXXX for everything outside printable ASCII.
func writePythonString(builder *strings.Builder, value string) {
	builder.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if character >= 0x20 && character <= 0x7e {
				builder.WriteRune(character)
				continue
			}
			if character == utf8.RuneError {
				// json.dumps on a lone surrogate or invalid byte is not
				// reachable from Go's UTF-8 strings; encode the replacement
				// character instead of dropping the position.
				builder.WriteString(`\ufffd`)
				continue
			}
			if character <= 0xffff {
				fmt.Fprintf(builder, `\u%04x`, character)
				continue
			}
			high, low := utf16.EncodeRune(character)
			fmt.Fprintf(builder, `\u%04x\u%04x`, high, low)
		}
	}
	builder.WriteByte('"')
}
