package identity

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEntropyFailureAndExactRead(t *testing.T) {
	t.Parallel()
	for _, sentinel := range []error{ErrSubjectIDEntropy, ErrPreAuthTransactionIDEntropy} {
		for _, source := range []io.Reader{
			bytes.NewReader(nil), bytes.NewReader([]byte{1}), bytes.NewReader(make([]byte, 16)),
			failingEntropyReader{},
		} {
			if got, err := newID(source, sentinel); got != "" || err != sentinel || strings.Contains(err.Error(), "provider-details") {
				t.Fatalf("entropy failure = %q, %v", got, err)
			}
		}
		input := bytes.NewReader(append([]byte{1}, make([]byte, 31)...))
		got, err := newID(input, sentinel)
		if err != nil || got != "AQAAAAAAAAAAAAAAAAAAAA" || input.Len() != 16 {
			t.Fatal("generation did not consume exactly sixteen bytes")
		}
	}
}

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) { return 0, errors.New("provider-details") }
