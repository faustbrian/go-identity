package passwordpostgres

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/session"
)

type nativeMFAPrimarySigner interface {
	signMFAPrimary(mfaSigninPrimary) (mfaSigninPrimary, error)
}

func TestPasswordMFAPrimaryEvidenceCannotBecomeFinalSigninProof(t *testing.T) {
	key, err := NewSigninSigningKey("primary", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := any(key).(nativeMFAPrimarySigner)
	if !ok {
		t.Fatal("native non-final password evidence signing unavailable")
	}
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	p := mfaSigninPrimary{Profile: mfaSigninPrimaryProfile, State: auth.SignInStateChallengeRequired, Issuer: "issuer", Environment: "test", Proof: auth.Proof{ID: "AwMDAwMDAwMDAwMDAwMDAw", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 3}
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	p.Authority = session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), SessionFamily: binding("family"), Session: binding("session"), Authorization: binding("authorization")}
	p.IdentifierID, p.IdentifierVersion, p.VerificationVersion = "email", 1, 1
	signed, err := signer.signMFAPrimary(p)
	if err != nil || signed.State != auth.SignInStateChallengeRequired || signed.Proof != p.Proof || len(signed.Signature) != ed25519.SignatureSize {
		t.Fatal("non-final primary custody lost", err)
	}
	changedRecipient := signed
	changedRecipient.IdentifierID = "different-email"
	changedWire, _, err := encodeMFASigninPrimary(changedRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeMFASigninPrimary(changedWire, map[string]ed25519.PublicKey{"primary": ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)}, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err == nil {
		t.Fatal("signed primary identifier was replaced")
	}
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSigninRecord(signed.Proof.ID, signed.Proof.Tenant, signed.Proof.Subject, wire); err == nil {
		t.Fatal("challenge evidence entered final signin source")
	}
	final := auth.SignedSignInRecord{Issuer: signed.Issuer, Environment: signed.Environment, State: auth.SignInStateAuthenticated, Proof: signed.Proof, ProofVersion: signed.ProofVersion, CredentialID: signed.CredentialID, CredentialVersion: signed.CredentialVersion, KeyID: signed.KeyID, Signature: signed.Signature}
	final.Proof.Purpose = "session-issue"
	frame, err := final.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, public := key.public()
	if id != signed.KeyID || ed25519.Verify(public, frame, signed.Signature) {
		t.Fatal("non-final signature was transferable to final authentication")
	}
	encoded, digest, err := encodeMFASigninPrimary(signed)
	if err != nil || digest == ([32]byte{}) {
		t.Fatal("original non-final evidence could not be retained", err)
	}
	keys := map[string]ed25519.PublicKey{id: public}
	restored, actualDigest, err := decodeMFASigninPrimary(encoded, keys, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject)
	if err != nil || actualDigest != digest || restored.Proof != signed.Proof || !bytes.Equal(restored.Signature, signed.Signature) {
		t.Fatal("restart changed original primary or digest", err)
	}
	for _, corrupt := range [][]byte{
		bytes.Replace(encoded, []byte(`"Profile":`), []byte(`"Profile":"other","Profile":`), 1),
		bytes.Replace(encoded, []byte(`"CredentialVersion":3`), []byte(`"CredentialVersion":4`), 1),
		bytes.Replace(encoded, []byte(`"ScopeKey":"authorization","Version":1`), []byte(`"ScopeKey":"authorization","Version":2`), 1),
		append(bytes.Clone(encoded), ' '),
	} {
		if bytes.Equal(corrupt, encoded) {
			t.Fatal("corruption did not change fixture")
		}
		if _, _, err := decodeMFASigninPrimary(corrupt, keys, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err == nil {
			t.Fatal("ambiguous or substituted original evidence accepted")
		}
	}
	if _, _, err := decodeMFASigninPrimary(encoded, keys, p.Issuer, p.Environment, p.Proof.ID, "other", p.Proof.Subject); err == nil {
		t.Fatal("cross-tenant primary accepted")
	}
	if _, _, err := decodeMFASigninPrimary(encoded, nil, p.Issuer, p.Environment, p.Proof.ID, p.Proof.Tenant, p.Proof.Subject); err == nil {
		t.Fatal("retired signing key accepted")
	}
	for name, change := range map[string]func(*mfaSigninPrimary){
		"final state":    func(p *mfaSigninPrimary) { p.State = auth.SignInStateAuthenticated },
		"final purpose":  func(p *mfaSigninPrimary) { p.Proof.Purpose = "session-issue" },
		"wrong method":   func(p *mfaSigninPrimary) { p.Proof.Method = "oauth" },
		"fabricated MFA": func(p *mfaSigninPrimary) { p.Proof.Assurance = auth.AssuranceMultiFactor },
		"no credential":  func(p *mfaSigninPrimary) { p.CredentialID = "" },
		"no version":     func(p *mfaSigninPrimary) { p.CredentialVersion = 0 },
		"no authority":   func(p *mfaSigninPrimary) { p.Authority = session.AuthoritySnapshotSpec{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			change(&changed)
			if _, err := signer.signMFAPrimary(changed); err == nil {
				t.Fatal("invalid non-final input signed")
			}
		})
	}
}
