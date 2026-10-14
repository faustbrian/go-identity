package mfapostgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func FuzzContinuationStorage(f *testing.F) {
	original := continuationFixture(f)
	wire, err := encodeContinuationScope(original)
	if err != nil {
		f.Fatal(err)
	}
	digest, err := original.ScopeDigest()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{"Profile":"identity-mfa-postgres-continuation-v1","Scope":null}`))
	f.Add([]byte(`{"Profile":1}`))
	f.Add(append(append([]byte(nil), wire...), 0))
	f.Fuzz(func(t *testing.T, input []byte) {
		restored, err := decodeContinuationScope(input, digest, mfa.Pending, 1, 3)
		if err != nil {
			return
		}
		actual, e := restored.ScopeDigest()
		if e != nil || actual != digest {
			t.Fatal("hostile storage changed original scope")
		}
		encoded, e := encodeContinuationScope(restored)
		defer clear(encoded)
		if e != nil || !bytes.Equal(encoded, input) {
			t.Fatal("ambiguous or noncanonical storage accepted")
		}
	})
}
