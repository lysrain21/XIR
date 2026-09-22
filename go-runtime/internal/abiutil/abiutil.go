// Package abiutil wraps the go-ethereum ABI codec for the XIR runtime.
//
// Every XIR call is packed from a JSON ABI document: either a Forge artifact
// (loaded by internal/artifacts) or a fragment committed next to the code that
// uses it. Tuple arguments are passed as Go structs whose fields follow the ABI
// component order; the codec in go-ethereum accepts struct values for tuples
// only when the type was built from JSON components, which is why every type in
// this runtime originates from an ABI document rather than from a type string.
package abiutil

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Contract is one parsed ABI document.
type Contract struct {
	name string
	abi  abi.ABI
}

// New parses an ABI JSON document.
func New(document string) (*Contract, error) {
	parsed, err := abi.JSON(strings.NewReader(document))
	if err != nil {
		return nil, fmt.Errorf("abiutil: parse ABI: %w", err)
	}
	return &Contract{abi: parsed}, nil
}

// Name returns the contract name recorded for evidence rows.
func (c *Contract) Name() string { return c.name }

// SetName records the contract name for diagnostics and evidence rows.
func (c *Contract) SetName(name string) { c.name = name }

// ABI exposes the parsed codec for callers that need it directly.
func (c *Contract) ABI() abi.ABI { return c.abi }

// PackCall returns selector || encoded arguments for one function.
//
// go-ethereum's ABI.Pack already prefixes the four-byte selector, so the result
// is used verbatim; prefixing again would emit calldata that calls nothing.
func (c *Contract) PackCall(name string, args ...any) ([]byte, error) {
	if _, ok := c.abi.Methods[name]; !ok {
		return nil, fmt.Errorf("abiutil: %s has no method %q", c.describe(), name)
	}
	encoded, err := c.abi.Pack(name, args...)
	if err != nil {
		return nil, fmt.Errorf("abiutil: pack %s.%s: %w", c.describe(), name, err)
	}
	return encoded, nil
}

// UnpackOutputs decodes the return data of one function into the given
// destinations, which must be pointers and must match the output count.
//
// The codec accepts one pointer to the single return value, or a pointer to a
// slice for a multi-value return, so the destinations are forwarded in the
// shape it expects rather than as a variadic slice.
func (c *Contract) UnpackOutputs(name string, data []byte, into ...any) error {
	method, ok := c.abi.Methods[name]
	if !ok {
		return fmt.Errorf("abiutil: %s has no method %q", c.describe(), name)
	}
	if len(method.Outputs) == 0 {
		return nil
	}
	if len(into) != len(method.Outputs) {
		return fmt.Errorf(
			"abiutil: %s.%s returns %d values but %d destinations were given",
			c.describe(), name, len(method.Outputs), len(into),
		)
	}
	for index, item := range into {
		value := reflect.ValueOf(item)
		if value.Kind() != reflect.Pointer || value.IsNil() {
			return fmt.Errorf(
				"abiutil: %s.%s destination %d is not a non-nil pointer",
				c.describe(), name, index,
			)
		}
	}
	destination := into
	if len(into) == 1 {
		if err := c.abi.UnpackIntoInterface(into[0], name, data); err != nil {
			return fmt.Errorf("abiutil: unpack %s.%s: %w", c.describe(), name, err)
		}
		return nil
	}
	if err := c.abi.UnpackIntoInterface(&destination, name, data); err != nil {
		return fmt.Errorf("abiutil: unpack %s.%s: %w", c.describe(), name, err)
	}
	return nil
}

// EventTopic returns the topic0 of one event.
func (c *Contract) EventTopic(name string) (common.Hash, error) {
	event, ok := c.abi.Events[name]
	if !ok {
		return common.Hash{}, fmt.Errorf("abiutil: %s has no event %q", c.describe(), name)
	}
	return event.ID, nil
}

// UnpackLog decodes one log into the named inputs of the event.
func (c *Contract) UnpackLog(name string, log *types.Log) (map[string]any, error) {
	event, ok := c.abi.Events[name]
	if !ok {
		return nil, fmt.Errorf("abiutil: %s has no event %q", c.describe(), name)
	}
	values := map[string]any{}
	if err := c.abi.UnpackIntoMap(values, name, log.Data); err != nil {
		return nil, fmt.Errorf("abiutil: unpack %s.%s data: %w", c.describe(), name, err)
	}
	// Indexed arguments live in the topics. ParseTopicsIntoMap decodes value
	// types and returns the topic hash itself for dynamic types, which is what
	// the topic actually carries.
	indexed := make(abi.Arguments, 0, len(event.Inputs))
	for _, input := range event.Inputs {
		if input.Indexed {
			indexed = append(indexed, input)
		}
	}
	if len(indexed) > 0 {
		if len(log.Topics) != len(indexed)+1 {
			return nil, fmt.Errorf(
				"abiutil: %s.%s log has %d topics for %d indexed arguments",
				c.describe(), name, len(log.Topics), len(indexed),
			)
		}
		if err := abi.ParseTopicsIntoMap(values, indexed, log.Topics[1:]); err != nil {
			return nil, fmt.Errorf("abiutil: unpack %s.%s topics: %w", c.describe(), name, err)
		}
	}
	return values, nil
}

// ArgumentFragment renders one input of a method back to ABI JSON components.
// The result can be passed to PackArgument.
func (c *Contract) ArgumentFragment(methodName string, index int) (string, error) {
	method, ok := c.abi.Methods[methodName]
	if !ok {
		return "", fmt.Errorf("abiutil: %s has no method %q", c.describe(), methodName)
	}
	if index < 0 || index >= len(method.Inputs) {
		return "", fmt.Errorf("abiutil: method %q has no argument %d", methodName, index)
	}
	encoded, err := json.Marshal(renderArgument(method.Inputs[index]))
	if err != nil {
		return "", fmt.Errorf("abiutil: render argument: %w", err)
	}
	return string(encoded), nil
}

// PackArgument ABI-encodes one bare argument described by a JSON fragment.
func PackArgument(fragment string, value any) ([]byte, error) {
	var argument abi.Argument
	if err := json.Unmarshal([]byte(fragment), &argument); err != nil {
		return nil, fmt.Errorf("abiutil: parse argument fragment: %w", err)
	}
	encoded, err := abi.Arguments{argument}.Pack(value)
	if err != nil {
		return nil, fmt.Errorf("abiutil: pack argument: %w", err)
	}
	return encoded, nil
}

// PackEncode ABI-encodes several arguments the way Solidity's abi.encode does.
// fragments is a JSON array of ABI argument objects; values follow in order.
//
// The arguments are packed as a synthetic method's inputs because the codec
// accepts tuple-typed values only as method or event inputs; the synthetic
// selector is dropped so the result is exactly abi.encode(...).
func PackEncode(fragments string, values ...any) ([]byte, error) {
	document := fmt.Sprintf(
		`[{"type":"function","name":"encode","stateMutability":"pure","inputs":%s,"outputs":[]}]`,
		fragments,
	)
	contract, err := New(document)
	if err != nil {
		return nil, err
	}
	method, ok := contract.abi.Methods["encode"]
	if !ok {
		return nil, fmt.Errorf("abiutil: synthetic encode method is missing")
	}
	encoded, err := method.Inputs.Pack(values...)
	if err != nil {
		return nil, fmt.Errorf("abiutil: pack encode: %w", err)
	}
	return encoded, nil
}

// DecodeHex decodes a 0x-prefixed hexadecimal string.
func DecodeHex(value string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		return nil, fmt.Errorf("abiutil: decode %q: %w", value, err)
	}
	return raw, nil
}

func (c *Contract) describe() string {
	if c.name == "" {
		return "contract"
	}
	return c.name
}

func renderArgument(input abi.Argument) map[string]any {
	rendered := map[string]any{
		"name": input.Name,
		"type": input.Type.String(),
	}
	if components := renderComponents(input.Type); len(components) > 0 {
		rendered["components"] = components
	}
	if input.Indexed {
		rendered["indexed"] = true
	}
	return rendered
}

func renderComponents(t abi.Type) []map[string]any {
	if len(t.TupleElems) == 0 {
		return nil
	}
	components := make([]map[string]any, 0, len(t.TupleElems))
	for index, element := range t.TupleElems {
		name := ""
		if index < len(t.TupleRawNames) {
			name = t.TupleRawNames[index]
		}
		rendered := map[string]any{"name": name, "type": element.String()}
		if nested := renderComponents(*element); len(nested) > 0 {
			rendered["components"] = nested
		}
		components = append(components, rendered)
	}
	return components
}
