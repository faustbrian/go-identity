package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func passwordSigninCodecSpec(anonymous bool) identity.FeatureCommandSpec {
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	s.Binding.OperationID, s.Binding.SchemaID, s.Binding.RecordID = s.Operation.OperationID, s.Operation.SchemaID, ""
	if anonymous {
		s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		s.Binding.UserID, s.Binding.AnonymousFlowID = "", "original-flow"
	}
	return s
}

func passwordSigninCodecCommand(t testing.TB, s identity.FeatureCommandSpec, raw []byte, wire string) (identity.Command, primitive.Secret) {
	t.Helper()
	p, err := primitive.NewSecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Destroy)
	c, err := identity.NewFeaturePasswordSigninCommand(s, p, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func TestPasswordSigninCodecBindsOriginalPairedCustody(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		s := passwordSigninCodecSpec(anonymous)
		raw := []byte(" unnormalized\x00\xffsynthetic-password ")
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		c, owner := passwordSigninCodecCommand(t, s, raw, wire)
		key := [32]byte{1}
		bound, err := prepareClaim(c, key)
		if err != nil {
			t.Fatal("paired password signin rejected", err)
		}
		if bound.feature == nil || *bound.feature != s.Operation || bound.source == nil || bound.purpose != s.Binding.OperationID || !bytes.Equal(bound.safeFields, commandSafeFields(s.Binding, &s.Operation)) {
			t.Fatal("closed original scope lost")
		}
		for _, secret := range [][]byte{raw, []byte(wire)} {
			if bytes.Contains(bound.canonical, secret) || bytes.Contains(bound.safeFields, secret) {
				t.Fatal("raw custody disclosed")
			}
		}
		// Independent literal domain framing: neither scalar feature fields nor
		// the generic pre-auth bearer path can substitute for either input.
		for _, input := range []struct {
			path string
			raw  []byte
		}{{"password-signin-password", raw}, {"password-signin-cookie", []byte(wire)}} {
			mac := hmac.New(sha256.New, key[:])
			mac.Write([]byte("identity-command-secret-v1"))
			mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(input.path))))
			mac.Write([]byte(input.path))
			mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(input.raw))))
			mac.Write(input.raw)
			if !bytes.Contains(bound.canonical, mac.Sum(nil)) || bytes.Contains(bound.safeFields, mac.Sum(nil)) {
				t.Fatal("paired secret fingerprint missing or in safe scope")
			}
		}
		if err := owner.Use(func(got []byte) error {
			if !bytes.Equal(got, raw) {
				t.Error("fingerprinting mutated password owner")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, input := range []struct {
			raw  []byte
			wire string
		}{{append(bytes.Clone(raw), 'x'), wire}, {raw, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))}} {
			changed, _ := passwordSigninCodecCommand(t, s, input.raw, input.wire)
			q, err := prepareClaim(changed, key)
			if err != nil || bytes.Equal(bound.canonical, q.canonical) || !bytes.Equal(bound.safeFields, q.safeFields) {
				t.Fatal("changed secret shares intent or changes collision scope")
			}
		}
		rotated, err := prepareClaim(c, [32]byte{2})
		if err != nil || bytes.Equal(bound.canonical, rotated.canonical) {
			t.Fatal("rotation did not rekey original custody")
		}
		retained, err := prepareClaim(*rotated.source, key)
		if err != nil || !bytes.Equal(bound.canonical, retained.canonical) {
			t.Fatal("retained key cannot replay original custody")
		}
	}
}

func TestPasswordSigninCodecDeniesAbsentBusyAndDestroyedCustody(t *testing.T) {
	s := passwordSigninCodecSpec(false)
	if _, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1}); err == nil {
		t.Fatal("plain signin metadata impersonated paired custody")
	}
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 64))
	c, p := passwordSigninCodecCommand(t, s, []byte("synthetic-live-password"), wire)
	if err := p.Use(func([]byte) error {
		_, err := prepareClaim(c, [32]byte{1})
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Error("busy custody not denied with redacted codec error")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareClaim(c, [32]byte{1}); err != nil {
		t.Fatal("failed borrow poisoned later fingerprinting", err)
	}
	p.Destroy()
	_, err := prepareClaim(c, [32]byte{1})
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) {
		t.Fatal("destroyed custody admitted")
	}
}

func TestPasswordSigninCodecBoundsOriginalPassword(t *testing.T) {
	s := passwordSigninCodecSpec(false)
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	for _, size := range []int{1, 1 << 20} {
		command, _ := passwordSigninCodecCommand(t, s, bytes.Repeat([]byte{0xff}, size), wire)
		q, err := prepareClaim(command, [32]byte{1})
		if err != nil || len(q.canonical) > 1<<20 || len(q.safeFields) > 65536 {
			t.Fatal("valid primitive password bounds rejected or raw size retained", err)
		}
	}
}

func TestPasswordSigninCodecPreservesLegacyCaptchaSchema(t *testing.T) {
	// risk/postgres MapCaptchaUse already uses this record-required schema;
	// its operation name is not the new paired password-signin v1 profile.
	s := passwordSigninCodecSpec(true)
	s.Operation.SchemaID, s.Binding.SchemaID = "native-captcha-protected-v1", "native-captcha-protected-v1"
	s.Operation.RecordRequirement, s.Binding.RecordID = identity.FeatureRecordRequired, "legacy-protected-record"
	command := featureCodecCommand(t, s)
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil || q.feature == nil || *q.feature != s.Operation || !bytes.Equal(q.safeFields, commandSafeFields(s.Binding, &s.Operation)) {
		t.Fatal("existing CAPTCHA-protected signin schema denied", err)
	}
	if _, ok := command.Feature(); !ok {
		t.Fatal("legacy scalar custody changed")
	}
	if _, _, paired := command.PasswordSigninCustody(); paired {
		t.Fatal("legacy CAPTCHA schema became password custody")
	}
}

func FuzzPasswordSigninCodec(f *testing.F) {
	f.Add([]byte("synthetic-password"), false)
	f.Add([]byte{0, 0xff, ' '}, true)
	f.Fuzz(func(t *testing.T, raw []byte, anonymous bool) {
		if len(raw) == 0 || len(raw) > 2048 {
			return
		}
		s := passwordSigninCodecSpec(anonymous)
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{20}, 32))
		command, _ := passwordSigninCodecCommand(t, s, raw, wire)
		q, err := prepareClaim(command, [32]byte{1})
		if err != nil || q.source == nil {
			t.Fatal("bounded arbitrary password rejected", err)
		}
		again, err := prepareClaim(*q.source, [32]byte{1})
		if err != nil || !bytes.Equal(q.canonical, again.canonical) {
			t.Fatal("unchanged raw password changed intent", err)
		}
		changed, _ := passwordSigninCodecCommand(t, s, append(bytes.Clone(raw), 0), wire)
		other, err := prepareClaim(changed, [32]byte{1})
		if err != nil || bytes.Equal(q.canonical, other.canonical) || !bytes.Equal(q.safeFields, other.safeFields) {
			t.Fatal("different arbitrary password lost intent", err)
		}
	})
}
