package mfapostgres

import (
	"bytes"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
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
	passkeySpec, err := original.Bindings()
	if err != nil {
		f.Fatal(err)
	}
	passkeySpec.PasskeyCommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
	passkeySpec.PrimaryProofID = auth.ProofID(passkeySpec.PasskeyCommandID)
	passkeySpec.AllowedMethods = []string{"totp"}
	passkey, err := mfa.NewPartialAuthContinuation(passkeySpec)
	if err != nil {
		f.Fatal(err)
	}
	passkeyWire, err := encodeContinuationScope(passkey)
	if err != nil {
		f.Fatal(err)
	}
	passkeyDigest, err := passkey.ScopeDigest()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(passkeyWire)
	f.Add([]byte(`{"Profile":"identity-mfa-postgres-continuation-v1","Scope":null}`))
	f.Add([]byte(`{"Profile":1}`))
	f.Add(append(append([]byte(nil), wire...), 0))
	f.Fuzz(func(t *testing.T, input []byte) {
		for _, originalDigest := range [][32]byte{digest, passkeyDigest} {
			restored, err := decodeContinuationScope(input, originalDigest, mfa.Pending, 1, 3)
			if err != nil {
				continue
			}
			actual, e := restored.ScopeDigest()
			if e != nil || actual != originalDigest {
				t.Fatal("hostile storage changed original scope")
			}
			encoded, e := encodeContinuationScope(restored)
			defer clear(encoded)
			if e != nil || !bytes.Equal(encoded, input) {
				t.Fatal("ambiguous or noncanonical storage accepted")
			}
		}
	})
}
