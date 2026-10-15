package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func passwordChangeCodecProof(s identity.FeatureCommandSpec) auth.ReauthenticationProof {
	now := time.Date(2026, 10, 9, 20, 0, 0, 123456789, time.UTC)
	return auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(strings.Repeat("p", 22)), Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "identity-platform", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, SessionID: "original-private-session", SessionVersion: math.MaxUint64, Action: s.Operation.OperationID}
}

func passwordChangeCodecCommand(t *testing.T, s identity.FeatureCommandSpec, hash, bearer string, proof auth.ReauthenticationProof) identity.Command {
	t.Helper()
	c, err := identity.NewFeaturePasswordChangeCommand(s, hash, auth.NewBearerCredential(bearer), proof)
	if err != nil {
		t.Fatal("command fixture", err)
	}
	return c
}

func TestPasswordChangeCanonicalIntentBindsCompleteCustody(t *testing.T) {
	s := passwordHashCodecSpec(t)
	proof := passwordChangeCodecProof(s)
	hash := "$synthetic$private-verifier"
	bearer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	key := [32]byte{1}
	c := passwordChangeCodecCommand(t, s, hash, bearer, proof)
	baseline, err := prepareClaim(c, key)
	if err != nil {
		t.Fatal("authenticated change intent rejected", err)
	}
	plain, err := prepareClaim(featureCodecCommand(t, s), key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline.safeFields, plain.safeFields) || bytes.Equal(baseline.canonical, plain.canonical) {
		t.Fatal("custody missing from intent or present in safe scope")
	}
	for _, private := range []string{hash, bearer, string(proof.Proof.ID), proof.SessionID, proof.Proof.Audience} {
		if bytes.Contains(baseline.canonical, []byte(private)) || bytes.Contains(baseline.safeFields, []byte(private)) {
			t.Fatal("raw custody escaped into journal")
		}
	}
	// Independent framing oracle for each secret, not the production helper.
	for path, value := range map[string]string{"password-change-hash": hash, "password-change-session": bearer} {
		mac := hmac.New(sha256.New, key[:])
		mac.Write([]byte("identity-command-secret-v1"))
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(path))))
		mac.Write([]byte(path))
		mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(value))))
		mac.Write([]byte(value))
		if !bytes.Contains(baseline.canonical, mac.Sum(nil)) {
			t.Fatal("secret framing changed")
		}
	}
	for name, mutate := range map[string]func(*auth.ReauthenticationProof, *string, *string){
		"hash": func(_ *auth.ReauthenticationProof, h, _ *string) { *h += "x" },
		"bearer": func(_ *auth.ReauthenticationProof, _, b *string) {
			*b = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		},
		"proof-id":  func(p *auth.ReauthenticationProof, _, _ *string) { p.Proof.ID = auth.ProofID(strings.Repeat("q", 22)) },
		"method":    func(p *auth.ReauthenticationProof, _, _ *string) { p.Proof.Method = "passkey" },
		"assurance": func(p *auth.ReauthenticationProof, _, _ *string) { p.Proof.Assurance = auth.AssuranceMultiFactor },
		"audience":  func(p *auth.ReauthenticationProof, _, _ *string) { p.Proof.Audience = "other-audience" },
		"issued-nanosecond": func(p *auth.ReauthenticationProof, _, _ *string) {
			p.Proof.IssuedAt = p.Proof.IssuedAt.Add(time.Nanosecond)
		},
		"expiry-nanosecond": func(p *auth.ReauthenticationProof, _, _ *string) {
			p.Proof.ExpiresAt = p.Proof.ExpiresAt.Add(time.Nanosecond)
		},
		"session":         func(p *auth.ReauthenticationProof, _, _ *string) { p.SessionID += "x" },
		"session-version": func(p *auth.ReauthenticationProof, _, _ *string) { p.SessionVersion-- },
	} {
		t.Run(name, func(t *testing.T) {
			p, h, b := proof, hash, bearer
			mutate(&p, &h, &b)
			changed, err := prepareClaim(passwordChangeCodecCommand(t, s, h, b, p), key)
			if err != nil || bytes.Equal(changed.canonical, baseline.canonical) {
				t.Fatal("changed custody reused original intent")
			}
			if !bytes.Equal(changed.safeFields, baseline.safeFields) {
				t.Fatal("custody changed safe scope")
			}
		})
	}
	proof.Proof.IssuedAt = proof.Proof.IssuedAt.In(time.FixedZone("same-instant", 3600))
	proof.Proof.ExpiresAt = proof.Proof.ExpiresAt.In(time.FixedZone("same-instant", 3600))
	same, err := prepareClaim(passwordChangeCodecCommand(t, s, hash, bearer, proof), key)
	if err != nil || !bytes.Equal(same.canonical, baseline.canonical) {
		t.Fatal("time zone changed original instant intent")
	}
	rotated, err := prepareClaim(c, [32]byte{2})
	if err != nil || rotated.source == nil || bytes.Equal(rotated.canonical, baseline.canonical) {
		t.Fatal("rotation did not rekey custody")
	}
	retained, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(retained.canonical, baseline.canonical) {
		t.Fatal("retained-key replay lost custody")
	}
	hashOnly, err := identity.NewFeaturePasswordHashCommand(s, hash)
	if err != nil {
		t.Fatal(err)
	}
	old, err := prepareClaim(hashOnly, key)
	if err != nil || bytes.Equal(old.canonical, baseline.canonical) {
		t.Fatal("authenticated change collapsed into hash-only intent")
	}
}

func TestPasswordChangeIntentRejectsUnsupportedTimesAndEmptyCommands(t *testing.T) {
	s := passwordHashCodecSpec(t)
	bearer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, year := range []int{0, 10000} {
		proof := passwordChangeCodecProof(s)
		proof.Proof.IssuedAt = time.Date(year, 6, 1, 0, 0, 0, 0, time.UTC)
		proof.Proof.ExpiresAt = proof.Proof.IssuedAt.Add(time.Minute)
		c := passwordChangeCodecCommand(t, s, "synthetic", bearer, proof)
		if _, err := prepareClaim(c, [32]byte{1}); err == nil {
			t.Fatal("out-of-native-profile instant encoded")
		}
	}
	if _, err := prepareClaim(identity.Command{}, [32]byte{1}); err == nil {
		t.Fatal("empty command encoded")
	}
	if _, err := prepareClaim(passwordChangeCodecCommand(t, s, "synthetic", bearer, passwordChangeCodecProof(s)), [32]byte{}); err == nil {
		t.Fatal("zero fingerprint key encoded")
	}
}
