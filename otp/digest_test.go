package otp_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/otp"
)

func digestScopeSpec(t *testing.T) otp.DigestScopeSpec {
	t.Helper()
	d, e := otp.NewDestinationInput("user@example.test")
	if e != nil {
		t.Fatal(e)
	}
	return otp.DigestScopeSpec{TenantID: "tenant", Purpose: otp.PurposeSignin, SubjectID: "subject", Channel: otp.ChannelEmail, Destination: d, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 3, Generation: 4, AuthorizationBinding: [32]byte{5}}
}

func TestDigestBoundsZeroAndCustody(t *testing.T) {
	s := digestScopeSpec(t)
	for _, value := range []string{"", strings.Repeat("x", 321), "invalid\x00", "\xff"} {
		if _, e := otp.NewDestinationInput(value); !errors.Is(e, otp.ErrInvalidDigest) {
			t.Fatal("invalid destination accepted")
		}
	}
	for _, value := range []string{"x", strings.Repeat("x", 320), "δοκιμή@example.test"} {
		d, e := otp.NewDestinationInput(value)
		if e != nil || d.Value() != value {
			t.Fatal("valid destination changed")
		}
	}
	for _, change := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.TenantID = "" }, func(s *otp.DigestScopeSpec) { s.TenantID = strings.Repeat("x", 257) },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "invalid\n" }, func(s *otp.DigestScopeSpec) { s.Purpose = "unknown" },
		func(s *otp.DigestScopeSpec) { s.Channel = "unknown" }, func(s *otp.DigestScopeSpec) { s.Destination = otp.DestinationInput{} },
		func(s *otp.DigestScopeSpec) { s.ChallengeID = "" }, func(s *otp.DigestScopeSpec) { s.TargetID = "" },
		func(s *otp.DigestScopeSpec) { s.PolicyVersion = 0 }, func(s *otp.DigestScopeSpec) { s.Generation = 0 },
		func(s *otp.DigestScopeSpec) { s.AuthorizationBinding = [32]byte{} },
	} {
		copy := s
		change(&copy)
		if _, e := otp.NewDigestScope(copy); !errors.Is(e, otp.ErrInvalidDigest) {
			t.Fatal("invalid scope accepted")
		}
	}
	for _, keys := range []map[uint32][32]byte{nil, {}, {0: {1}, 1: {1}}, {1: {}}, {2: {2}}} {
		if _, e := otp.NewVerifier(1, keys); !errors.Is(e, otp.ErrInvalidDigest) {
			t.Fatal("invalid keys accepted")
		}
	}
	tooMany := map[uint32][32]byte{}
	for i := uint32(1); i <= 9; i++ {
		tooMany[i] = [32]byte{byte(i)}
	}
	if _, e := otp.NewVerifier(1, tooMany); !errors.Is(e, otp.ErrInvalidDigest) {
		t.Fatal("unbounded ring accepted")
	}
	if _, e := otp.NewVerifier(0, map[uint32][32]byte{1: {1}}); !errors.Is(e, otp.ErrInvalidDigest) {
		t.Fatal("zero current accepted")
	}
	keys := map[uint32][32]byte{1: {1}}
	v, _ := otp.NewVerifier(1, keys)
	keys[1] = [32]byte{2}
	delete(keys, 1)
	scope, _ := otp.NewDigestScope(s)
	code, _ := auth.NewOneTimeCode("123456")
	d, e := v.Digest(scope, code)
	if e != nil {
		t.Fatal("caller key mutation retained")
	}
	for _, derive := range []func() (otp.CodeDigest, error){
		func() (otp.CodeDigest, error) { return (otp.Verifier{}).Digest(scope, code) },
		func() (otp.CodeDigest, error) { return v.Digest(otp.DigestScope{}, code) },
		func() (otp.CodeDigest, error) { return v.Digest(scope, auth.OneTimeCode{}) },
	} {
		if _, e := derive(); !errors.Is(e, otp.ErrInvalidDigest) {
			t.Fatal("invalid digest accepted")
		}
	}
	for _, stored := range []otp.StoredCodeDigest{{}, {KeyVersion: 1}} {
		if ok, e := v.Compare(scope, stored, code); ok || !errors.Is(e, otp.ErrInvalidDigest) {
			t.Fatal("invalid stored digest accepted")
		}
	}
	if ok, e := v.Compare(otp.DigestScope{}, d.Storage(), code); ok || !errors.Is(e, otp.ErrInvalidDigest) {
		t.Fatal("zero scope comparison accepted")
	}
	// Maximum scope remains bounded; absent pre-account subject is explicit.
	s.TenantID = strings.Repeat("x", 256)
	s.SubjectID = ""
	s.ChallengeID = strings.Repeat("x", 256)
	s.TargetID = strings.Repeat("x", 256)
	s.Destination, _ = otp.NewDestinationInput(strings.Repeat("x", 320))
	max, e := otp.NewDigestScope(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := v.Digest(max, code); e != nil {
		t.Fatal("maximum scope rejected")
	}
	for _, value := range []any{s, s.Destination, scope, d, d.Storage(), v} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			out := fmt.Sprintf(format, value)
			if !strings.Contains(out, "redacted") || strings.Contains(out, "user@example.test") {
				t.Fatal("sensitive formatting disclosed")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("sensitive JSON allowed")
		}
		if _, e := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(e, otp.ErrSensitiveSerialization) {
			t.Fatal("sensitive text allowed")
		}
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if ok, e := v.Compare(scope, d.Storage(), code); e != nil || !ok {
				t.Error("concurrent comparison changed")
			}
		})
	}
	wg.Wait()
}

func FuzzDigestScopeIsolation(f *testing.F) {
	f.Add("a", "bc")
	f.Add("ab", "c")
	f.Fuzz(func(t *testing.T, tenant, challenge string) {
		s := digestScopeSpec(t)
		s.TenantID = tenant
		s.ChallengeID = challenge
		scope, e := otp.NewDigestScope(s)
		if e != nil {
			return
		}
		v, _ := otp.NewVerifier(1, map[uint32][32]byte{1: {1}})
		code, _ := auth.NewOneTimeCode("123456")
		d, e := v.Digest(scope, code)
		if e != nil {
			t.Fatal("accepted scope cannot digest")
		}
		if ok, e := v.Compare(scope, d.Storage(), code); e != nil || !ok {
			t.Fatal("exact scope did not match")
		}
		// Swap adjacent fields to catch ambiguous concatenation.
		s.TenantID = challenge
		s.ChallengeID = tenant
		other, e := otp.NewDigestScope(s)
		if e != nil {
			t.Fatal("swapped valid scope rejected")
		}
		if ok, e := v.Compare(other, d.Storage(), code); e != nil || ok != (tenant == challenge) {
			t.Fatal("distinct fields collapsed")
		}
	})
}

func TestDigestExactScopeAndRotation(t *testing.T) {
	s := digestScopeSpec(t)
	scope, e := otp.NewDigestScope(s)
	if e != nil {
		t.Fatal(e)
	}
	v, e := otp.NewVerifier(2, map[uint32][32]byte{1: {1}, 2: {2}})
	if e != nil {
		t.Fatal(e)
	}
	code, _ := auth.NewOneTimeCode("123456")
	got, e := v.Digest(scope, code)
	if e != nil {
		t.Fatal(e)
	}
	stored := got.Storage()
	if stored.KeyVersion != 2 {
		t.Fatal("current key not selected")
	}
	// Independent scope framing oracle, not a production encoder.
	b := []byte("identity-otp-code-scope-v1\x00")
	for _, value := range []string{"tenant", "signin", "subject", "email", "user@example.test", "challenge", "target"} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	b = binary.BigEndian.AppendUint64(b, 3)
	b = binary.BigEndian.AppendUint64(b, 4)
	b = append(b, s.AuthorizationBinding[:]...)
	b = binary.BigEndian.AppendUint32(b, 2)
	msg := []byte("authentication-one-time-code-digest-v1\x00")
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(b)))
	msg = append(msg, b...)
	msg = append(msg, 0, 6)
	msg = append(msg, []byte("123456")...)
	key := [32]byte{2}
	h := hmac.New(sha256.New, key[:])
	h.Write(msg)
	if !hmac.Equal(stored.Value[:], h.Sum(nil)) {
		t.Fatal("framing differs")
	}
	newer, _ := otp.NewVerifier(3, map[uint32][32]byte{2: {2}, 3: {3}})
	if ok, e := newer.Compare(scope, stored, code); e != nil || !ok {
		t.Fatal("retained key changed verification")
	}
	retired, _ := otp.NewVerifier(3, map[uint32][32]byte{3: {3}})
	if ok, e := retired.Compare(scope, stored, code); ok || !errors.Is(e, otp.ErrDigestUnavailable) {
		t.Fatal("retired key fallback")
	}
	wrong, _ := auth.NewOneTimeCode("123457")
	if ok, e := v.Compare(scope, stored, wrong); e != nil || ok {
		t.Fatal("wrong code matched")
	}
	for _, change := range []func(*otp.DigestScopeSpec){
		func(s *otp.DigestScopeSpec) { s.TenantID = "other" }, func(s *otp.DigestScopeSpec) { s.Purpose = otp.PurposeMFA },
		func(s *otp.DigestScopeSpec) { s.SubjectID = "other" }, func(s *otp.DigestScopeSpec) { s.Channel = otp.ChannelSMS },
		func(s *otp.DigestScopeSpec) { s.Destination, _ = otp.NewDestinationInput("other@example.test") },
		func(s *otp.DigestScopeSpec) { s.ChallengeID = "other" }, func(s *otp.DigestScopeSpec) { s.TargetID = "other" },
		func(s *otp.DigestScopeSpec) { s.PolicyVersion++ }, func(s *otp.DigestScopeSpec) { s.Generation++ },
		func(s *otp.DigestScopeSpec) { s.AuthorizationBinding[0]++ },
	} {
		copy := s
		change(&copy)
		other, e := otp.NewDigestScope(copy)
		if e != nil {
			t.Fatal(e)
		}
		if ok, e := v.Compare(other, stored, code); e != nil || ok {
			t.Fatal("cross-scope acceptance")
		}
	}
}
