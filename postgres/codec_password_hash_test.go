package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func passwordHashCodecSpec(t *testing.T) identity.FeatureCommandSpec {
	t.Helper()
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestPasswordHashCanonicalIntentAndRetainedKey(t *testing.T) {
	s := passwordHashCodecSpec(t)
	makeCommand := func(hash string) identity.Command {
		command, err := identity.NewFeaturePasswordHashCommand(s, hash)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	key := [32]byte{1}
	plain, err := prepareClaim(featureCodecCommand(t, s), key)
	if err != nil {
		t.Fatal(err)
	}
	hash := "$argon2id$synthetic-command-custody"
	command := makeCommand(hash)
	bound, err := prepareClaim(command, key)
	if err != nil {
		t.Fatal("password hash command denied", err)
	}
	if bytes.Equal(plain.canonical, bound.canonical) || !bytes.Equal(plain.safeFields, bound.safeFields) {
		t.Fatal("hash missing from intent or leaked into safe fields")
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-command-secret-v1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, 13))
	mac.Write([]byte("password-hash"))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(hash))))
	mac.Write([]byte(hash))
	if !bytes.Contains(bound.canonical, mac.Sum(nil)) || bytes.Contains(bound.canonical, []byte(hash)) {
		t.Fatal("hash framing or redaction changed")
	}
	changed, err := prepareClaim(makeCommand(hash+"x"), key)
	if err != nil || bytes.Equal(bound.canonical, changed.canonical) {
		t.Fatal("changed verifier shares command intent")
	}
	rotated, err := prepareClaim(command, [32]byte{2})
	if err != nil || rotated.source == nil || bytes.Equal(bound.canonical, rotated.canonical) {
		t.Fatal("hash not rekeyed")
	}
	retained, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(bound.canonical, retained.canonical) {
		t.Fatal("original retained-key replay changed")
	}
}
