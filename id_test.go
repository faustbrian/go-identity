package identity_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity"
)

func TestCanonicalIDs(t *testing.T) {
	t.Parallel()
	low := "AAAAAAAAAAAAAAAAAAAAAQ"
	high := "-gAAAAAAAAAAAAAAAAAAAA"
	for _, raw := range []string{low, high, "_____________________w"} {
		subject, err := identity.ParseSubjectID(raw)
		if err != nil || identity.FormatSubjectID(subject) != raw {
			t.Fatalf("subject round trip failed: %v", err)
		}
		attempt, err := identity.ParsePreAuthTransactionID(raw)
		if err != nil || identity.FormatPreAuthTransactionID(attempt) != raw {
			t.Fatalf("attempt round trip failed: %v", err)
		}
	}
	if low < high {
		t.Fatal("ordering fixture must distinguish encoded and decoded ordering")
	}
	for _, pair := range []struct {
		left, right string
		want        int
	}{
		{low, high, -1}, {high, low, 1}, {low, low, 0},
	} {
		a, _ := identity.ParseSubjectID(pair.left)
		b, _ := identity.ParseSubjectID(pair.right)
		if got, err := identity.CompareSubjectID(a, b); err != nil || got != pair.want {
			t.Fatalf("subject comparison = %d, %v", got, err)
		}
		x, _ := identity.ParsePreAuthTransactionID(pair.left)
		y, _ := identity.ParsePreAuthTransactionID(pair.right)
		if got, err := identity.ComparePreAuthTransactionID(x, y); err != nil || got != pair.want {
			t.Fatalf("attempt comparison = %d, %v", got, err)
		}
	}
}

func TestIDsRejectNoncanonicalAndZeroValues(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAQ==",
		"AAAAAAAAAAAAAAAAAAAAAR", " AAAAAAAAAAAAAAAAAAAAAQ",
		"AAAAAAAAAAAAAAAAAAAAA\n", "AAAAAAAAAAAAAAAAAAAAA+",
		"AAAAAAAAAAAAAAAAAAAAA/", "AAAAAAAAAAAAAAAAAAAAA!",
		strings.Repeat("a", 21), strings.Repeat("a", 23), strings.Repeat("a", 1<<20),
	} {
		if got, err := identity.ParseSubjectID(raw); got != "" || !errors.Is(err, identity.ErrInvalidSubjectID) {
			t.Fatal("invalid subject input was accepted")
		}
		if got, err := identity.ParsePreAuthTransactionID(raw); got != "" || !errors.Is(err, identity.ErrInvalidPreAuthTransactionID) {
			t.Fatal("invalid attempt input was accepted")
		}
		if identity.FormatSubjectID(identity.SubjectID(raw)) != "" || identity.FormatPreAuthTransactionID(identity.PreAuthTransactionID(raw)) != "" {
			t.Fatal("format disclosed an invalid representation")
		}
		validSubject, _ := identity.ParseSubjectID("AAAAAAAAAAAAAAAAAAAAAQ")
		for _, pair := range [][2]identity.SubjectID{{identity.SubjectID(raw), validSubject}, {validSubject, identity.SubjectID(raw)}} {
			if got, err := identity.CompareSubjectID(pair[0], pair[1]); got != 0 || !errors.Is(err, identity.ErrInvalidSubjectID) {
				t.Fatal("comparison accepted invalid subject")
			}
		}
		validAttempt, _ := identity.ParsePreAuthTransactionID("AAAAAAAAAAAAAAAAAAAAAQ")
		for _, pair := range [][2]identity.PreAuthTransactionID{{identity.PreAuthTransactionID(raw), validAttempt}, {validAttempt, identity.PreAuthTransactionID(raw)}} {
			if got, err := identity.ComparePreAuthTransactionID(pair[0], pair[1]); got != 0 || !errors.Is(err, identity.ErrInvalidPreAuthTransactionID) {
				t.Fatal("comparison accepted invalid attempt")
			}
		}
	}
}

func TestGeneratedIDsRoundTrip(t *testing.T) {
	for range 16 {
		t.Run("parallel", func(t *testing.T) {
			t.Parallel()
			for range 16 {
				subject, err := identity.NewSubjectID()
				if err != nil {
					t.Fatal(err)
				}
				if got, err := identity.ParseSubjectID(identity.FormatSubjectID(subject)); err != nil || got != subject {
					t.Fatal("generated subject failed round trip")
				}
				attempt, err := identity.NewPreAuthTransactionID()
				if err != nil {
					t.Fatal(err)
				}
				if got, err := identity.ParsePreAuthTransactionID(identity.FormatPreAuthTransactionID(attempt)); err != nil || got != attempt {
					t.Fatal("generated attempt failed round trip")
				}
			}
		})
	}
}

func FuzzIDParsing(f *testing.F) {
	for _, seed := range []string{"", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAR", "_____________________w", "-gAAAAAAAAAAAAAAAAAAAA", "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		valid := false
		if len(raw) == 22 {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
			valid = err == nil && len(decoded) == 16 && !bytes.Equal(decoded, make([]byte, 16))
		}
		got, subjectErr := identity.ParseSubjectID(raw)
		attempt, attemptErr := identity.ParsePreAuthTransactionID(raw)
		if valid {
			if subjectErr != nil || attemptErr != nil || identity.FormatSubjectID(got) != raw || identity.FormatPreAuthTransactionID(attempt) != raw {
				t.Fatal("valid input failed round trip")
			}
		} else if got != "" || attempt != "" || !errors.Is(subjectErr, identity.ErrInvalidSubjectID) || !errors.Is(attemptErr, identity.ErrInvalidPreAuthTransactionID) {
			t.Fatal("invalid input was accepted")
		}
	})
}
