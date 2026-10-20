package passwordpostgres

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneMFAPrimaryCannotRetagExistingSigninEvidence(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, ed25519.SeedSize))
	key, err := NewSigninSigningKey("phone-primary", private)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"phone-primary": private.Public().(ed25519.PublicKey)}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	p := mfaSigninPrimary{Profile: "identity-phone-password-mfa-primary-v1", State: auth.SignInStateChallengeRequired, Issuer: "issuer", Environment: "test", Proof: auth.Proof{ID: "AwMDAwMDAwMDAwMDAwMDAw", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 3, IdentifierID: "phone", IdentifierVersion: 2, VerificationVersion: 2, Authority: session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), SessionFamily: binding("family"), Session: binding("session"), Authorization: binding("authorization")}}
	for _, profile := range []string{p.Profile, mfaSigninPrimaryProfile, usernameMFASigninPrimaryProfile} {
		p.Profile = profile
		signed, err := key.signMFAPrimary(p)
		if err != nil {
			t.Fatal("selected non-final primary cannot be signed", profile, err)
		}
		wire, _, err := encodeMFASigninPrimary(signed)
		if err != nil {
			t.Fatal(err)
		}
		if original, _, err := decodeMFASigninPrimary(wire, keys, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err != nil || original.Profile != profile {
			t.Fatal("original primary did not survive retention", err)
		}
		for _, other := range []string{"identity-phone-password-mfa-primary-v1", mfaSigninPrimaryProfile, usernameMFASigninPrimaryProfile} {
			if other == profile {
				continue
			}
			changed := bytes.Replace(wire, []byte(profile), []byte(other), 1)
			if _, _, err := decodeMFASigninPrimary(changed, keys, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err == nil {
				t.Fatal("primary signature admitted another operation profile")
			}
		}
		changed := signed
		changed.IdentifierID = "other-phone"
		changedWire, _, err := encodeMFASigninPrimary(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := decodeMFASigninPrimary(changedWire, keys, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err == nil {
			t.Fatal("primary signature admitted a substituted phone identifier")
		}
		if _, err := decodeSigninRecord(p.Proof.ID, p.Proof.Tenant, p.Proof.Subject, wire); err == nil {
			t.Fatal("non-final phone comparison became completed authentication")
		}
	}
}
