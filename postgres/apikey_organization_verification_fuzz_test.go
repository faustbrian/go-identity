package postgres

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func FuzzOrganizationAPIKeyVerificationPlan(f *testing.F) {
	b, p := apiKeyVerificationCodecSeed(false)
	b.UserID, b.AnonymousFlowID, b.SchemaID = "", string(b.CommandID), "apikey-verify-organization-v1"
	p.Feature.Operation = organizationAPIKeyVerificationOperation()
	fingerprint := [32]byte{9}
	wire, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		f.Fatal("valid nonhuman verification corpus rejected", err)
	}
	for _, seed := range [][]byte{wire, append(bytes.Clone(wire), 0), wire[:len(wire)-1], {}, {0xbf, 0xff}, make([]byte, 65537)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, err := decodeFeaturePlan(b, fingerprint, wire)
		if err != nil {
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || !reflect.DeepEqual(p, CommandPlan{}) {
				t.Fatal("hostile organization-key bytes returned partial authority")
			}
			return
		}
		canonical, err := encodeFeaturePlan(b, fingerprint, p)
		if err != nil || len(wire) > 65536 || p.APIKeyVerification != nil && !validAPIKeyVerificationPlan(b, p) || !bytes.Equal(canonical, wire) || p.Digest != sha256.Sum256(wire) {
			t.Fatal("organization-key bytes escaped their bounded canonical profile")
		}
	})
}
