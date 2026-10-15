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

func passwordSignupCodecSpec(anonymous bool) identity.FeatureCommandSpec {
	s := passwordSigninCodecSpec(anonymous)
	s.Operation.OperationID, s.Operation.SchemaID = "identity.password.signup", "password-signup"
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestPasswordSignupCodecBindsBothOriginalInputs(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		s := passwordSignupCodecSpec(anonymous)
		hash := "$synthetic$original-signup-verifier"
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		command := func(hash, wire string) identity.Command {
			c, err := identity.NewFeaturePasswordSignupCommand(s, hash, auth.NewBearerCredential(wire))
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		c := command(hash, wire)
		key := [32]byte{1}
		original, err := prepareClaim(c, key)
		if err != nil {
			t.Fatal("native paired signup intent rejected", err)
		}
		if original.feature == nil || *original.feature != s.Operation || original.source == nil || !bytes.Equal(original.safeFields, commandSafeFields(s.Binding, &s.Operation)) {
			t.Fatal("original signup scope lost")
		}
		// Literal framing is an independent oracle for each secret domain.
		for _, input := range []struct{ path, raw string }{{"password-signup-hash", hash}, {"password-signup-cookie", wire}} {
			mac := hmac.New(sha256.New, key[:])
			mac.Write([]byte("identity-command-secret-v1"))
			mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(input.path))))
			mac.Write([]byte(input.path))
			mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(input.raw))))
			mac.Write([]byte(input.raw))
			if !bytes.Contains(original.canonical, mac.Sum(nil)) || bytes.Contains(original.safeFields, mac.Sum(nil)) {
				t.Fatal("signup fingerprint missing or in safe scope")
			}
		}
		for _, raw := range []string{hash, wire} {
			if bytes.Contains(original.canonical, []byte(raw)) || bytes.Contains(original.safeFields, []byte(raw)) {
				t.Fatal("signup material entered kernel evidence")
			}
		}
		for _, changed := range []identity.Command{command(hash+"x", wire), command(hash, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))} {
			next, err := prepareClaim(changed, key)
			if err != nil || bytes.Equal(next.canonical, original.canonical) || !bytes.Equal(next.safeFields, original.safeFields) {
				t.Fatal("signup input omitted from keyed intent")
			}
		}
		retained, err := prepareClaim(c, key)
		if err != nil || !bytes.Equal(retained.canonical, original.canonical) {
			t.Fatal("original signup intent unstable")
		}
		rotated, err := prepareClaim(c, [32]byte{2})
		if err != nil || bytes.Equal(rotated.canonical, original.canonical) {
			t.Fatal("signup custody not rekeyed")
		}
		for _, partial := range []func() (identity.Command, error){
			func() (identity.Command, error) { return identity.NewFeatureCommand(s) },
			func() (identity.Command, error) {
				return identity.NewFeaturePreAuthCommand(s, auth.NewBearerCredential(wire))
			},
		} {
			p, e := partial()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = prepareClaim(p, key); e == nil {
				t.Fatal("partial signup bypassed paired custody")
			}
		}
	}
}

func TestPasswordSignupCodecPreservesOtherSchemas(t *testing.T) {
	s := passwordSignupCodecSpec(true)
	s.Operation.SchemaID, s.Binding.SchemaID = "native-captcha-protected-v1", "native-captcha-protected-v1"
	s.Operation.RecordRequirement, s.Binding.RecordID = identity.FeatureRecordRequired, "legacy-protected-record"
	command := featureCodecCommand(t, s)
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil || q.feature == nil || *q.feature != s.Operation {
		t.Fatal("alternative signup schema incorrectly closed", err)
	}
}
