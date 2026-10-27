package apikey_test

import (
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func FuzzSecretCanonicalBound(f *testing.F) {
	f.Add("idk_" + strings.Repeat("A", 43))
	f.Add("idk_" + strings.Repeat("_", 43))
	f.Add("")
	f.Fuzz(func(t *testing.T, wire string) {
		s, err := apikey.ParseSecret(wire)
		if err != nil {
			return
		}
		raw, err := s.Reveal()
		if err != nil || raw != wire || len(raw) != 47 {
			t.Fatal("noncanonical parser acceptance")
		}
		if _, err := s.Reveal(); err == nil {
			t.Fatal("second reveal")
		}
	})
}
