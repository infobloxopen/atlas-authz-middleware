package json_utils

import (
	"encoding/json"
	"fmt"
	"io"
)

// JsonDecoder wraps a json.Decoder to provide some helper methods
type JsonDecoder struct {
	JCfg   *JsonConfig
	Decodr *json.Decoder
}

// NewJsonDecoder returns new instance of JsonDecoder
func NewJsonDecoder(rdr io.Reader, joptList ...JsonOption) *JsonDecoder {
	return &JsonDecoder{
		JCfg:   (&JsonConfig{}).ApplyJsonOptions(joptList...),
		Decodr: json.NewDecoder(rdr),
	}
}

// Decoder returns the wrapped json.Decoder instance
func (dcdr *JsonDecoder) Decoder() *json.Decoder {
	return dcdr.Decodr
}

// ExpectDelim decodes the next token and expects it to be the specified delimiter.
// The decoded delimiter is returned.
func (dcdr *JsonDecoder) ExpectDelim(delimStr string, joptList ...JsonOption) (*string, error) {
	myJCfg := (&JsonConfig{}).ApplyJsonOptions(joptList...)

	tokIfc, err := dcdr.Decodr.Token()
	if err != nil {
		return nil, err
	}

	if myJCfg.AllowNull && tokIfc == nil {
		return nil, nil
	}

	tokDelim, ok := tokIfc.(json.Delim)
	if !ok || (tokDelim.String() != delimStr) {
		return nil, fmt.Errorf("ExpectDelim(%s) fail, got unexpected '%s' (%#v)", delimStr, tokIfc, tokIfc)
	}

	loggr := myJCfg.Loggr
	if loggr == nil {
		loggr = dcdr.JCfg.Loggr
	}
	if loggr != nil {
		loggr.Tracef("ExpectDelim(%s) okay, got '%s'", delimStr, tokDelim)
	}

	tokStr := tokDelim.String()
	return &tokStr, nil
}

// ExpectString decodes the next token and expects it to be a string.
// If exactStr is specified, the decoded string must match.
// The decoded string is returned.
func (dcdr *JsonDecoder) ExpectString(exactStr *string, joptList ...JsonOption) (*string, error) {
	myJCfg := (&JsonConfig{}).ApplyJsonOptions(joptList...)
	loggedExactStr := ""

	if exactStr != nil {
		loggedExactStr = *exactStr
	}

	tokIfc, err := dcdr.Decodr.Token()
	if err != nil {
		return nil, err
	}
	myErr := fmt.Errorf("ExpectString(%s) fail, got unexpected '%s' (%#v)", loggedExactStr, tokIfc, tokIfc)

	if myJCfg.AllowNull && tokIfc == nil {
		return nil, nil
	}

	tokStr, ok := tokIfc.(string)
	if !ok {
		return nil, myErr
	}

	if exactStr != nil && tokStr != *exactStr {
		return nil, myErr
	}

	loggr := myJCfg.Loggr
	if loggr == nil {
		loggr = dcdr.JCfg.Loggr
	}
	if loggr != nil {
		loggr.Tracef("ExpectString(%s) okay, got '%s'", loggedExactStr, tokStr)
	}

	return &tokStr, nil
}
