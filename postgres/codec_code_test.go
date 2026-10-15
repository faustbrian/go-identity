package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func codeCodecCommand(t *testing.T, spec identity.FeatureCommandSpec, value string) identity.Command {
	t.Helper()
	code, err := auth.NewOneTimeCode(value)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeatureOneTimeCodeCommand(spec, code)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestFeatureCodeCanonicalIntentAndRetainedKey(t *testing.T) {
	spec := featureCodecSpec()
	key := [32]byte{1}
	plain, err := prepareClaim(featureCodecCommand(t, spec), key)
	if err != nil {
		t.Fatal(err)
	}
	command := codeCodecCommand(t, spec, "123456")
	withCode, err := prepareClaim(command, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain.canonical, withCode.canonical) || !bytes.Equal(plain.safeFields, withCode.safeFields) {
		t.Fatal("code missing from private intent or leaked into safe scope")
	}
	// Literal independent framing: raw code, not its storage digest or CBOR text.
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-command-secret-v1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, 13))
	mac.Write([]byte("one-time-code"))
	mac.Write(binary.BigEndian.AppendUint64(nil, 6))
	mac.Write([]byte("123456"))
	if !bytes.Contains(withCode.canonical, mac.Sum(nil)) || bytes.Contains(withCode.canonical, []byte("123456")) {
		t.Fatal("canonical code digest framing or secrecy changed")
	}
	changed, err := prepareClaim(codeCodecCommand(t, spec, "654321"), key)
	if err != nil || bytes.Equal(withCode.canonical, changed.canonical) {
		t.Fatal("changed code shares intent")
	}
	rotated, err := prepareClaim(command, [32]byte{2})
	if err != nil || rotated.source == nil || bytes.Equal(withCode.canonical, rotated.canonical) {
		t.Fatal("key rotation did not rekey secret")
	}
	retained, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(withCode.canonical, retained.canonical) {
		t.Fatal("retained-key code replay changed")
	}
	// An absent code adds no payload field and preserves the existing encoding.
	payload, err := encodeFeature(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := commandScope(spec.Binding)
	scope["feature_owner"] = cborText(spec.Operation.Owner)
	scope["record_requirement"] = cborUint(uint64(spec.Operation.RecordRequirement))
	scope["payload"] = cborMap(payload)
	if !bytes.Equal(plain.canonical, cborMap(scope)) {
		t.Fatal("absent code changed historical bytes")
	}
}

func TestFeatureCodeCannotEnterGenericAdmission(t *testing.T) {
	c, plain, plan := featurePlanFixture(t)
	spec, _ := plain.Feature()
	if _, err := c.PrepareCommandPlan(spec.Binding, plain, plan); err != nil {
		t.Fatal("ordinary fixture not admissible", err)
	}
	command := codeCodecCommand(t, spec, "123456")
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err == nil || prepared.Digest != ([32]byte{}) || prepared.Feature != nil {
		t.Fatal("opaque code entered generic admission without typed OTP phases")
	}
}
