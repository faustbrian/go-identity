package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestSessionTokenBindsDisjointPrivateCommandIntent(t *testing.T) {
	spec := featureCodecSpec()
	code, _ := auth.NewOneTimeCode("123456")
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	command, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	key := [32]byte{1}
	bound, err := prepareClaim(command, key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := prepareClaim(codeCodecCommand(t, spec, "123456"), key)
	preauth, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(wire))
	otherContext, _ := prepareClaim(preauth, key)
	if bytes.Equal(bound.canonical, legacy.canonical) || bytes.Equal(bound.canonical, otherContext.canonical) || !bytes.Equal(bound.safeFields, legacy.safeFields) || bytes.Contains(bound.canonical, []byte(wire)) || bytes.Contains(bound.safeFields, []byte(wire)) {
		t.Fatal("session token missing, disclosed or mixed with pre-auth intent")
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-command-secret-v1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, 13))
	mac.Write([]byte("session-token"))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(wire))))
	mac.Write([]byte(wire))
	if !bytes.Contains(bound.canonical, mac.Sum(nil)) {
		t.Fatal("session token digest framing changed")
	}
	otherWire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x12}, 32))
	other, _ := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(otherWire))
	changed, err := prepareClaim(other, key)
	if err != nil || bytes.Equal(bound.canonical, changed.canonical) {
		t.Fatal("token substitution shared intent")
	}
	rotated, err := prepareClaim(command, [32]byte{2})
	if err != nil || rotated.source == nil {
		t.Fatal("original custody lost")
	}
	retained, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(bound.canonical, retained.canonical) {
		t.Fatal("retained-key replay changed")
	}
	coordinator, plain, plan := featurePlanFixture(t)
	declared, _ := plain.Feature()
	secret, _ := identity.NewFeatureOneTimeCodeSessionCommand(declared, code, auth.NewBearerCredential(wire))
	if _, err := coordinator.PrepareCommandPlan(declared.Binding, secret, plan); err == nil {
		t.Fatal("session-token OTP entered generic execution")
	}
}
