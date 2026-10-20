package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPhoneResetCanonicalIntentIncludesOriginalBrowserCookie(t *testing.T) {
	proof, _ := passwordResetCodecProof(t, 1)
	secret, _ := primitive.NewSecret([]byte("synthetic phone reset password"))
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("123456")
	input, _ := identity.NewFeaturePhonePasswordResetInputCommand(phoneResetCodecSpec(), secret, proof, code, code)
	generated, _ := identity.NewFeaturePhonePasswordResetCommand(phoneResetCodecSpec(), "synthetic-hash", proof, code, code)
	for _, original := range []identity.Command{input, generated} {
		unbound, err := prepareClaim(original, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		var previous []byte
		for _, value := range []byte{1, 2} {
			wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
			bound, err := identity.BindPhonePasswordResetPreAuth(original, auth.NewBearerCredential(wire))
			if err != nil {
				t.Fatal(err)
			}
			claim, err := prepareClaim(bound, [32]byte{1})
			if err != nil || bytes.Equal(claim.canonical, unbound.canonical) || bytes.Equal(claim.canonical, previous) || !bytes.Equal(claim.safeFields, unbound.safeFields) {
				t.Fatal("original cookie omitted or exposed through safe intent", err)
			}
			if bytes.Contains(claim.canonical, []byte(wire)) || bytes.Contains(claim.safeFields, []byte(wire)) {
				t.Fatal("cookie entered persisted command data")
			}
			rotated, err := prepareClaim(bound, [32]byte{2})
			if err != nil || bytes.Equal(rotated.canonical, claim.canonical) {
				t.Fatal("cookie fingerprint was not keyed", err)
			}
			previous = claim.canonical
		}
	}
}
