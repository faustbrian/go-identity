package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestRPStateLookupIsVersionAndScopeBound(t *testing.T) {
	key := [32]byte{1}
	state := bytes.Repeat([]byte{2}, 32)
	want := rpStateDigest(key, 1, identity.TenantID("tenant-a"), "provider", state)
	if want == ([32]byte{}) || want == rpStateDigest(key, 2, "tenant-a", "provider", state) || want == rpStateDigest(key, 1, "tenant-b", "provider", state) || want == rpStateDigest(key, 1, "tenant-a", "other", state) || want == rpStateDigest([32]byte{3}, 1, "tenant-a", "provider", state) {
		t.Fatal("state lookup failed domain separation")
	}
}

func TestRPStartPreservesNonsecretStateMetadataAfterExchangeSecretErasure(t *testing.T) {
	p, _, _ := rpOutputFixture(t)
	wire, err := p.generateOutput(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _, plan, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	clear(out.PKCECiphertext)
	clear(out.StateProofCiphertext)
	clear(out.Checkpoint)
	b := p.input.binding()
	retained, state, err := p.service.openRPStoredTransaction(context.Background(), b.TenantID, out.BindingCiphertext, out.Binding.Provider, b.RecordID, out.Binding.StateDigest)
	if err != nil || !reflect.DeepEqual(retained, out.Binding) || state != plan.Grants[0] {
		t.Fatal("terminal replay lost original state metadata after exchange custody erasure", err)
	}
	if state.ProofFingerprint == ([32]byte{}) || state.ReplayDigest == ([32]byte{}) || state.MaxUses != 1 || !state.ExpiresAt.Equal(retained.ExpiresAt) {
		t.Fatal("terminal replay received incomplete or renewed state metadata")
	}
}

func rpOutputFixture(t *testing.T) (*rpStartPhase, *time.Time, *capability.KeySet) {
	t.Helper()
	now := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	signing := bytes.Repeat([]byte{9}, 32)
	signer, err := capability.NewHMACSHA256Signer("signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	c := LinkServiceConfig{StateLifetime: 10 * time.Minute, CurrentEnvelopeKey: "rp", EnvelopeKeys: map[string][]byte{"rp": bytes.Repeat([]byte{4}, 32)}, CurrentStateKeyVersion: 1, StateKeys: map[uint32][32]byte{1: {5}}}
	c.Capability = capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {6}}, PreparationTimeout: time.Second}
	issuer, err := capabilitypg.NewIssuer(c.Capability)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := capabilitypg.NewIssuancePreparationCodec(issuer, capabilitypg.IssuancePreparationConfig{Deployment: "test", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{7}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "signing", HMAC: signing}}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keyring)
	if err != nil {
		t.Fatal(err)
	}
	pkce, err := newRPVerifierCustody(verifierKeys())
	if err != nil {
		t.Fatal(err)
	}
	profile := verifierProfile()
	s := &LinkService{issuer: issuer, checkpoint: checkpoint, envelopes: crypto, verifiers: pkce, profiles: map[string]oauth.ProviderProfile{profile.ID: profile}, profile: [32]byte{8}, config: func() LinkServiceConfig { return c }}
	policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), SessionFamily: binding("family"), Session: binding("session"), Authorization: binding("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	original, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity", Version: 1, FamilyVersion: 1, Remember: policy, Authority: authority, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := rpLinkStartOperation()
	input := rpStartInput{Schema: 1, Binding: rpStoredBinding(identity.CommandBinding{CommandID: command, TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(command), RecordID: string(command)}), Provider: profile.ID, Callback: "https://app.example/success", ErrorCallback: "https://app.example/failure", Session: fields, Profile: s.profile, Started: now, ValidUntil: now.Add(20 * time.Second), FactorVersion: 1}
	return &rpStartPhase{service: s, input: &input}, &now, keys
}

func TestRPStartOutputRestoresActualOriginalCapabilityAndIsolatesExchangeSecrets(t *testing.T) {
	p, now, keys := rpOutputFixture(t)
	wire, err := p.generateOutput(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	out, issued, plan, err := p.restoreOutput(context.Background(), 3, wire)
	if err != nil {
		t.Fatal(err)
	}
	if out.Binding.ExpiresAt.Sub(out.Binding.IssuedAt) != 10*time.Minute || !out.Binding.ExpiresAt.After(p.input.ValidUntil) {
		t.Fatal("initiation admission shortened RP lifetime")
	}
	if got, err := issued.Plan(); err != nil || !reflect.DeepEqual(got, plan) {
		t.Fatal("actual issuer custody was not restored")
	}
	b := p.input.binding()
	stored, err := p.service.openRPStartBinding(context.Background(), b.TenantID, out.BindingCiphertext, out.Binding.Provider, b.RecordID, out.Binding.StateDigest)
	if err != nil || !reflect.DeepEqual(stored, out.Binding) {
		t.Fatal("persisted original binding changed", err)
	}
	aad, err := rpStartBindingAAD(string(b.TenantID), out.Binding.Provider, b.RecordID, out.Binding.StateDigest, "state-proof")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.service.openRP(context.Background(), aad, out.StateProofCiphertext, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(proof)
	grant, err := capability.Verify(context.Background(), string(proof), keys, capability.VerifyOptions{Issuer: p.service.config().Capability.Crypto.Issuer, Now: *now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload := grant.Payload()
	plain, err := json.Marshal(out.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	if payload.Subject != string(b.UserID) || payload.Resource != b.RecordID || payload.Operation != "identity.oauth.callback" || payload.Bearer || payload.MaxUses != 1 || payload.Caveats["identity.oauth.rp.binding"] != base64.RawURLEncoding.EncodeToString(digest[:]) || sha256.Sum256(proof) != plan.Grants[0].ProofFingerprint {
		t.Fatal("canonical grant failed complete original binding")
	}
	if bytes.Contains(plain, proof) || bytes.Contains(plain, out.PKCECiphertext) || bytes.Contains(plain, out.Checkpoint) || bytes.Contains(plain, out.StateProofCiphertext) {
		t.Fatal("binding duplicates terminally erased exchange custody")
	}
	vb, err := newRPVerifierBinding(string(b.TenantID), out.Binding.Provider, b.RecordID, out.Binding.StateDigest, b.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	pkce, err := p.service.verifiers.open(context.Background(), vb, rpSealedVerifier{ciphertext: out.PKCECiphertext, commitment: out.Binding.PKCECommitment, keyVersion: out.Binding.PKCEKeyVersion}, out.Binding.IssuedAt, out.Binding.ExpiresAt, *now)
	if err != nil {
		t.Fatal(err)
	}
	defer pkce.Destroy()
	if pkce.Challenge() != out.Binding.Challenge {
		t.Fatal("authorization challenge does not match original encrypted PKCE")
	}
	*now = now.Add(time.Minute)
	again, _, againPlan, err := p.restoreOutput(context.Background(), 3, wire)
	if err != nil || !reflect.DeepEqual(again, out) || !reflect.DeepEqual(againPlan, plan) {
		t.Fatal("restoration renewed or regenerated original output", err)
	}
	*now = out.Binding.ExpiresAt
	if _, _, _, err := p.restoreOutput(context.Background(), 3, wire); err == nil {
		t.Fatal("expired canonical state restored")
	}
}

func TestRPStartOutputRejectsChangedGenerationInputCiphertextAndPlans(t *testing.T) {
	p, _, _ := rpOutputFixture(t)
	wire, err := p.generateOutput(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.restoreOutput(context.Background(), 2, wire); err == nil {
		t.Fatal("generation rebound")
	}
	wrong := *p.input
	wrong.ErrorCallback = "https://app.example/changed"
	other := *p
	other.input = &wrong
	if _, _, _, err := other.restoreOutput(context.Background(), 1, wire); err == nil {
		t.Fatal("full original input rebound")
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, _, err := p.restoreOutput(context.Background(), 1, corrupt); err == nil {
		t.Fatal("corrupt retained ciphertext accepted")
	}
	aad, err := p.outputAAD(1)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*rpStartOutput){
		"grant expiry":      func(v *rpStartOutput) { v.Plan.Grants[0].ExpiresAt = v.Plan.Grants[0].ExpiresAt.Add(time.Second) },
		"grant fingerprint": func(v *rpStartOutput) { v.Plan.Grants[0].ProofFingerprint[0] ^= 1 },
		"issuer checkpoint": func(v *rpStartOutput) { v.Checkpoint[len(v.Checkpoint)-1] ^= 1 },
		"callback command":  func(v *rpStartOutput) { v.Binding.CallbackCommandID = "invalid" },
		"state digest":      func(v *rpStartOutput) { v.Binding.StateDigest[0] ^= 1 },
		"replay key":        func(v *rpStartOutput) { v.Binding.StateReplayKeyVersion++ },
		"nonce":             func(v *rpStartOutput) { v.Binding.Nonce = "invalid" },
		"persisted binding": func(v *rpStartOutput) { v.BindingCiphertext[len(v.BindingCiphertext)-1] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&out)
			plain, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			changed, err := p.service.sealRP(context.Background(), aad, plain)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := p.restoreOutput(context.Background(), 1, changed); err == nil {
				t.Fatal("changed authenticated output restored")
			}
		})
	}
}

func TestRPStartLifetimeHonorsOriginalFreshnessWithoutRenewal(t *testing.T) {
	p, _, _ := rpOutputFixture(t)
	original, err := p.originalSession()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.IssuedAt = p.input.Started.Add(-14 * time.Minute)
	spec.IssuedAt = spec.Authentication.Proof.IssuedAt
	spec.LastActivityAt = spec.IssuedAt
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	p.input.Session, err = sessionpg.OriginalSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	issued, expires, err := p.stateLifetime()
	if err != nil || !issued.Equal(p.input.Started) || !expires.Equal(p.input.Started.Add(time.Minute)) {
		t.Fatal("original freshness was renewed or ignored", err)
	}
	p.input.Started = expires
	if _, _, err := p.stateLifetime(); err == nil {
		t.Fatal("expired original freshness admitted")
	}
}
