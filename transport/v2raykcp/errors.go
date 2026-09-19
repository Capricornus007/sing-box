package v2raykcp

import (
	"errors"
	"strings"
)

var (
	// ErrIOTimeout is returned when I/O operation times out
	ErrIOTimeout = errors.New("i/o timeout")
	// ErrClosedListener is returned when listener is closed
	ErrClosedListener = errors.New("listener closed")
	// ErrClosedConnection is returned when connection is closed
	ErrClosedConnection = errors.New("connection closed")
)

func newError(values ...any) error {
	return errors.New(toString(values...))
}

func toString(values ...any) string {
	var result strings.Builder
	for _, value := range values {
		switch v := value.(type) {
		case string:
			result.WriteString(v)
		case error:
			result.WriteString(v.Error())
		}
	}
	return result.String()
}
