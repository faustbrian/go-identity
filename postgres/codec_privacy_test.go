package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

func recordPrivacy(t *testing.T, change func(*identity.PrivacyExportRequestCommand), proofChange func(*capability.Payload), keyID string) identity.Command {
	t.Helper()
	const scope = "AQEBAQEBAQEBAQEBAQEBAQ"
	c := identity.PrivacyExportRequestCommand{
		Binding:                 identity.CommandBinding{CommandID: "CgoKCgoKCgoKCgoKCgoKCg", TenantID: scope, UserID: scope, ActorID: scope, ActorKind: authorization.SubjectUser, OperationID: "identity.privacy-export.request", PolicyID: "privacy-policy", PolicyVersion: 1, SchemaID: "identity-privacy-export", SchemaVersion: 1, CorrelationID: scope},
		ExpectedIdentityVersion: 3, ExpectedAuthorityVersion: 4, ExpectedPrivacyEpoch: 5,
		SessionID: "fresh-session", SessionVersion: 2, MaximumBytes: 256 << 20, ArtifactTTL: 24 * time.Hour,
	}
	for _, id := range identity.PrivacyExportContributorsV1() {
		c.Projections = append(c.Projections, identity.PrivacyExportProjectionSpecV1{ContributorID: id, ProjectionID: identity.PrivacyExportSubjectJournalV1})
	}
	if change != nil {
		change(&c)
	}
	p, err := identity.BuildPrivacyExportProofPayload(identity.PrivacyExportProofSpec{Command: c, Issuer: "https://identity.example.test", Audience: "backend", ID: "privacy-proof-a", IssuedAt: time.Unix(900, 0), ExpiresAt: time.Unix(1100, 0)})
	if err != nil {
		t.Fatal("privacy fixture", err)
	}
	if proofChange != nil {
		proofChange(&p)
	}
	c.Proof = recordGrant(t, p, keyID)
	command, err := identity.NewPrivacyExportRequestCommand(c)
	if err != nil {
		t.Fatal("privacy command", err)
	}
	return command
}

func TestPrivacyClaimBindsOriginalIntentAndProof(t *testing.T) {
	command := recordPrivacy(t, nil, nil, "privacy-key")
	original, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal("native privacy claim missing", err)
	}
	spec, _ := command.RequestPrivacyExport()
	if original.commandID != spec.Binding.CommandID || original.tenant != spec.Binding.TenantID || original.purpose != spec.Binding.OperationID || original.source == nil || !validClaim(original, claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}) {
		t.Fatal("wrong native claim scope")
	}
	for name, change := range map[string]func(*identity.PrivacyExportRequestCommand){
		"identity":        func(c *identity.PrivacyExportRequestCommand) { c.ExpectedIdentityVersion++ },
		"authority":       func(c *identity.PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion++ },
		"privacy":         func(c *identity.PrivacyExportRequestCommand) { c.ExpectedPrivacyEpoch++ },
		"session":         func(c *identity.PrivacyExportRequestCommand) { c.SessionID = "other-session" },
		"session-version": func(c *identity.PrivacyExportRequestCommand) { c.SessionVersion++ },
		"maximum":         func(c *identity.PrivacyExportRequestCommand) { c.MaximumBytes++ },
		"ttl":             func(c *identity.PrivacyExportRequestCommand) { c.ArtifactTTL += time.Second },
		"projection": func(c *identity.PrivacyExportRequestCommand) {
			c.Projections[0].ProjectionID = identity.PrivacyExportStagedSubjectV1
		},
		"full-width": func(c *identity.PrivacyExportRequestCommand) {
			c.ExpectedIdentityVersion = ^uint64(0)
			c.ExpectedAuthorityVersion = ^uint64(0)
			c.ExpectedPrivacyEpoch = ^uint64(0) - 1
			c.SessionVersion = ^uint64(0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := prepareClaim(recordPrivacy(t, change, nil, "privacy-key"), [32]byte{1})
			if err != nil || bytes.Equal(original.canonical, changed.canonical) || !bytes.Equal(original.safeFields, changed.safeFields) {
				t.Fatal("distinct intent not bound", err)
			}
		})
	}
	for name, change := range map[string]func(*capability.Payload){
		"id":       func(p *capability.Payload) { p.ID = "other-proof" },
		"issuer":   func(p *capability.Payload) { p.Issuer = "https://other.example.test" },
		"audience": func(p *capability.Payload) { p.Audiences = []string{"other-backend"} },
		"expiry":   func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"issued":   func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Second) },
	} {
		t.Run("proof-"+name, func(t *testing.T) {
			changed, err := prepareClaim(recordPrivacy(t, nil, change, "privacy-key"), [32]byte{1})
			if err != nil || bytes.Equal(original.canonical, changed.canonical) {
				t.Fatal("original proof envelope lost", err)
			}
		})
	}
	changed, err := prepareClaim(recordPrivacy(t, nil, nil, "other-privacy-key"), [32]byte{1})
	if err != nil || bytes.Equal(original.canonical, changed.canonical) {
		t.Fatal("proof header lost", err)
	}
	// Same authenticated header and payload, different original signature.
	// Header/payload-only encoding would conflate these submitted proofs.
	secret := bytes.Repeat([]byte{2}, 32)
	signer, err := capability.NewHMACSHA256Signer("privacy-key", secret)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{ID: "privacy-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	token, err := capability.Issue(ctx, spec.Proof.Payload(), signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	otherProof, err := capability.Verify(ctx, token, resolver, capability.VerifyOptions{Now: time.Unix(1000, 0), Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	otherSpec := spec
	otherSpec.Proof = otherProof
	otherCommand, err := identity.NewPrivacyExportRequestCommand(otherSpec)
	if err != nil {
		t.Fatal(err)
	}
	otherClaim, err := prepareClaim(otherCommand, [32]byte{1})
	if err != nil || bytes.Equal(original.canonical, otherClaim.canonical) {
		t.Fatal("different original signature conflated", err)
	}
	rotated, err := prepareClaim(command, [32]byte{2})
	if err != nil || bytes.Equal(original.canonical, rotated.canonical) || !bytes.Equal(original.safeFields, rotated.safeFields) {
		t.Fatal("fingerprint key not bound", err)
	}
	again, err := prepareClaim(command, [32]byte{1})
	if err != nil || !bytes.Equal(original.canonical, again.canonical) {
		t.Fatal("original encoding renewed", err)
	}
	for _, sensitive := range []string{spec.SessionID, spec.Proof.Payload().ID, spec.Proof.Header().KeyID, spec.Projections[0].ContributorID, spec.Proof.Payload().Caveats["intent_digest"]} {
		if sensitive != "" && (bytes.Contains(original.canonical, []byte(sensitive)) || bytes.Contains(original.safeFields, []byte(sensitive))) {
			t.Fatal("private intent/proof metadata stored")
		}
	}
	coordinator, _, plan := coordinatorFixture(t)
	if _, err := coordinator.PrepareCommandPlan(spec.Binding, command, plan); err == nil {
		t.Fatal("incomplete privacy workflow activated")
	}
}

func TestPrivacyClaimRejectsInvalidEncodingInputs(t *testing.T) {
	command := recordPrivacy(t, nil, nil, "privacy-key")
	if _, err := prepareClaim(command, [32]byte{}); err == nil {
		t.Fatal("zero fingerprint key")
	}
	spec, _ := command.RequestPrivacyExport()
	bad := spec
	bad.Proof = capability.Grant{}
	if _, err := encodePrivacy(bad, [32]byte{1}); err == nil {
		t.Fatal("zero opaque proof")
	}
	bad = spec
	bad.Projections = bad.Projections[:22]
	if _, err := encodePrivacy(bad, [32]byte{1}); err == nil {
		t.Fatal("incomplete manifest")
	}
	bad = spec
	p := spec.Proof.Payload()
	p.Issuer = string(bytes.Repeat([]byte{'a'}, 257))
	limits := capability.DefaultLimits()
	limits.MaxFieldBytes = 512
	bad.Proof = recordGrantWithLimits(t, p, "privacy-key", limits)
	if _, err := encodePrivacy(bad, [32]byte{1}); err == nil {
		t.Fatal("broader proof profile adopted")
	}
}
