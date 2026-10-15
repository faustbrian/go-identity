package hibp

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	password "github.com/faustbrian/go-password/v2"
)

func TestCandidateUsesExactBorrowedBytes(t *testing.T) {
	for _, input := range [][]byte{[]byte(" synthetic "), []byte("synthetic"), {'a', 0, 'b'}, {0xff, 0xfe}, []byte("\u00e9"), []byte("e\u0301")} {
		secret, e := password.NewSecret(input)
		if e != nil {
			t.Fatal("synthetic owner construction failed")
		}
		defer secret.Destroy()
		derived, e := deriveCandidate(context.Background(), secret, 1024)
		if e != nil {
			t.Fatal("valid candidate rejected")
		}
		digest := sha1.Sum(input)
		want := strings.ToUpper(hex.EncodeToString(digest[:]))
		if string(derived.prefix[:]) != want[:5] || string(derived.suffix[:]) != want[5:] {
			t.Fatal("candidate byte representation changed")
		}
		if e := secret.Use(func(b []byte) error {
			if !bytes.Equal(b, input) {
				t.Fatal("borrow changed owner")
			}
			return nil
		}); e != nil {
			t.Fatal("borrow destroyed owner")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", derived, derived, derived), want) || strings.Contains(fmt.Sprintf("%v", derived), want[5:]) {
			t.Fatal("candidate diagnostics disclosed derived material")
		}
	}
}

func TestCandidateInvalidBorrowAndCancellation(t *testing.T) {
	if _, e := deriveCandidate(context.Background(), password.Secret{}, 1024); !errors.Is(e, errInvalidCandidate) {
		t.Fatal("zero owner accepted")
	}
	secret, _ := password.NewSecret(bytes.Repeat([]byte{'x'}, 1024))
	defer secret.Destroy()
	if _, e := deriveCandidate(context.Background(), secret, 1023); !errors.Is(e, errInvalidCandidate) {
		t.Fatal("candidate bound exceeded")
	}
	for _, limit := range []int{0, -1, 1<<20 + 1} {
		if _, e := deriveCandidate(context.Background(), secret, limit); !errors.Is(e, errInvalidCandidate) {
			t.Fatal("invalid candidate bound accepted")
		}
	}
	if _, e := deriveCandidate(nil, secret, 1024); e == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := deriveCandidate(ctx, secret, 1024); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if e := secret.Use(func([]byte) error {
		if _, e := deriveCandidate(context.Background(), secret, 1024); !errors.Is(e, errInvalidCandidate) {
			t.Fatal("reentrant borrow accepted")
		}
		return nil
	}); e != nil {
		t.Fatal("outer borrow failed")
	}
	secret.Destroy()
	if _, e := deriveCandidate(context.Background(), secret, 1024); !errors.Is(e, errInvalidCandidate) {
		t.Fatal("destroyed owner accepted")
	}
}
