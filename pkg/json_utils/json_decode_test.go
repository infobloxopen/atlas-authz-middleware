package json_utils

import (
	"strings"
	"testing"
)

func TestExpectDelim(t *testing.T) {
	openBrace := `{` // }
	testMap := []struct {
		name      string
		delimStr  string
		joptList  []JsonOption
		jsonStr   string
		expectErr bool
		expectStr *string
	}{
		{
			name:      `null not allowed`,
			delimStr:  `[`, // ]
			joptList:  nil,
			jsonStr:   `null`,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `null allowed`,
			delimStr:  `[`, // ]
			joptList:  []JsonOption{WithAllowNull(true)},
			jsonStr:   `null`,
			expectErr: false,
			expectStr: nil,
		},
		{
			name:      `delim { ok`, // }
			delimStr:  openBrace,
			joptList:  nil,
			jsonStr:   openBrace,
			expectErr: false,
			expectStr: &openBrace,
		},
		{
			name:      `unexpected delim {`, // }
			delimStr:  `[`,                  // ]
			joptList:  nil,
			jsonStr:   `{`, // }
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `unexpected quoted string`,
			delimStr:  `{`, // }
			joptList:  nil,
			jsonStr:   `"a b c d e"`,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `invalid string`,
			delimStr:  `{`, // }
			joptList:  nil,
			jsonStr:   `a b c d e`,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `unexpected number`,
			delimStr:  `{`, // }
			joptList:  nil,
			jsonStr:   `123`,
			expectErr: true,
			expectStr: nil,
		},
	}

	for nth, tm := range testMap {
		jdec := NewJsonDecoder(strings.NewReader(string(tm.jsonStr)))
		actualStr, actualErr := jdec.ExpectDelim(tm.delimStr, tm.joptList...)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualStr != nil {
			t.Errorf("%d: %q: returned val should be nil if err returned", nth, tm.name)
		}

		if actualStr == nil && tm.expectStr != nil ||
			actualStr != nil && tm.expectStr == nil ||
			actualStr != nil && tm.expectStr != nil && *actualStr != *tm.expectStr {
			t.Errorf("%d: %q: expectStr=%s actualStr=%s",
				nth, tm.name, *tm.expectStr, *actualStr)
		}
	}
}

func TestExpectString(t *testing.T) {
	someStr := `some random str`
	testMap := []struct {
		name      string
		exactStr  string
		joptList  []JsonOption
		jsonStr   string
		expectErr bool
		expectStr *string
	}{
		{
			name:      `null not allowed`,
			exactStr:  ``,
			joptList:  nil,
			jsonStr:   `null`,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `null allowed`,
			exactStr:  ``,
			joptList:  []JsonOption{WithAllowNull(true)},
			jsonStr:   `null`,
			expectErr: false,
			expectStr: nil,
		},
		{
			name:      `invalid string`,
			exactStr:  ``,
			joptList:  nil,
			jsonStr:   someStr,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `unexpected number`,
			exactStr:  ``,
			joptList:  nil,
			jsonStr:   `123`,
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `unexpected delim {`, // }
			exactStr:  ``,
			joptList:  nil,
			jsonStr:   `{`, // }
			expectErr: true,
			expectStr: nil,
		},
		{
			name:      `any string ok`,
			exactStr:  ``,
			joptList:  nil,
			jsonStr:   `"` + someStr + `"`,
			expectErr: false,
			expectStr: &someStr,
		},
		{
			name:      `exact string ok`,
			exactStr:  someStr,
			joptList:  nil,
			jsonStr:   `"` + someStr + `"`,
			expectErr: false,
			expectStr: &someStr,
		},
	}

	for nth, tm := range testMap {
		jdec := NewJsonDecoder(strings.NewReader(string(tm.jsonStr)))
		var exactStr *string
		if len(tm.exactStr) > 0 {
			exactStr = &tm.exactStr
		}
		actualStr, actualErr := jdec.ExpectString(exactStr, tm.joptList...)

		if tm.expectErr && actualErr == nil {
			t.Errorf("%d: %q: expected err, but got no err", nth, tm.name)
		} else if !tm.expectErr && actualErr != nil {
			t.Errorf("%d: %q: got unexpected err=%s", nth, tm.name, actualErr)
		}

		if actualErr != nil && actualStr != nil {
			t.Errorf("%d: %q: returned val should be nil if err returned", nth, tm.name)
		}

		if actualStr == nil && tm.expectStr != nil ||
			actualStr != nil && tm.expectStr == nil ||
			actualStr != nil && tm.expectStr != nil && *actualStr != *tm.expectStr {
			t.Errorf("%d: %q: expectStr=%s actualStr=%s",
				nth, tm.name, *tm.expectStr, *actualStr)
		}
	}
}
