package badoption

import (
	"encoding/json"
	"testing"
)

func TestRangeRejectsExtraBounds(t *testing.T) {
	for _, input := range []string{`"1-2-3"`, `"1-2-"`, `""`} {
		var value Range
		if json.Unmarshal([]byte(input), &value) == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for input, expected := range map[string]Range{`"3"`: {3, 3}, `"1-5"`: {1, 5}, `4`: {4, 4}} {
		var value Range
		if err := json.Unmarshal([]byte(input), &value); err != nil || value != expected {
			t.Fatal(value, err)
		}
	}
}
