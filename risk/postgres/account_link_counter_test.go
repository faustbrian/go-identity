package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func accountLinkCounterFixture(t *testing.T, at time.Time) identity.Command {
	t.Helper()
	s, _ := protectedCommand(t, "counter-tenant").Feature()
	b := s.Binding
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID, b.LinkMode = "identity.account.link-token", "identity-account", 1, "account", identity.AccountLinkExplicit
	spec := identity.AccountLinkCommand{Binding: b, SessionID: "original-session", SessionVersion: 17,
		Change: identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: identity.Account{ID: "account", TenantID: b.TenantID, UserID: b.UserID, Provider: "configured-oidc", Issuer: "https://provider.example", Subject: "synthetic-subject", Version: 1}, ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}}
	key := bytes.Repeat([]byte{0x41}, 32)
	signer, err := capability.NewHMACSHA256Signer("synthetic-link", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "synthetic-link", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: spec, Issuer: "https://identity.example", Audience: "identity-backend", ID: "synthetic-grant", IssuedAt: at.Add(-time.Second).Truncate(time.Second), ExpiresAt: at.Add(time.Minute).Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	spec.Proof, err = capability.Verify(ctx, token, keys, capability.VerifyOptions{Issuer: payload.Issuer, Now: at, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountLinkCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestAccountLinkProtectedCounterCanonicalPreparationAndRestoration(t *testing.T) {
	at := time.Date(2026, 11, 1, 11, 0, 0, 123000, time.UTC)
	original := accountLinkCounterFixture(t, at)
	repo, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: "subject", Session: "original-session", Network: "2001:db8::12"}
	command, plan, err := repo.PrepareAccountLinkCommandCounters(original, subject, at)
	if err != nil {
		t.Fatal("canonical link cannot prepare protected counters", err)
	}
	spec, metadata, ok := command.AccountLinkCounterCommand()
	before, _ := original.LinkAccount()
	if !ok || spec.Binding != before.Binding || spec.Proof.EnvelopeDigest() != before.Proof.EnvelopeDigest() || metadata.PreparedAt != at || metadata.Network != subject.Network || len(metadata.KeyVersions) != 1 || metadata.KeyVersions[0] != 7 {
		t.Fatal("counter mapping lost canonical intent, proof or original time")
	}
	if _, ok := command.Feature(); ok {
		t.Fatal("link counter preparation became generic feature execution")
	}
	if _, ok := command.LinkAccount(); ok {
		t.Fatal("legacy executor can drop counter context")
	}
	if err := repo.ValidateCommandCounters(command, plan); err != nil {
		t.Fatal("canonical counters cannot restore", err)
	}
	restored, err := repo.restoreCounter(command, plan)
	if err != nil || restored.scope.Operation != "identity.account.link-token" || restored.subject != subject || restored.command.Bindings().PreparedAt != at || len(restored.command.Bindings().Targets) != 4 {
		t.Fatal("restored original counter scope differs", err)
	}
	if err := restored.validateAt(at.Add(15 * time.Minute)); err == nil {
		t.Fatal("counter restoration renewed exclusive original expiry")
	}
	if err := repo.ValidateCommandCounters(original, plan); err == nil {
		t.Fatal("bare command accepted without prepared context")
	}
	if _, _, err := repo.PrepareAccountLinkCommandCounters(command, subject, at); err == nil {
		t.Fatal("counter context replaced on retry")
	}
	for _, mutate := range []func(*risk.Subject){
		func(s *risk.Subject) { s.User = "other" },
		func(s *risk.Subject) { s.Session = "other" },
		func(s *risk.Subject) { s.Actor = "other" },
		func(s *risk.Subject) { s.Device = "device" },
		func(s *risk.Subject) { s.IdentifierDigest = "identifier" },
		func(s *risk.Subject) { s.Resource = "other" },
		func(s *risk.Subject) { s.Network = "not-a-network" },
	} {
		selected := subject
		mutate(&selected)
		if _, _, err := repo.PrepareAccountLinkCommandCounters(original, selected, at); err == nil {
			t.Fatal("foreign or undeclared counter dimension admitted")
		}
	}
	changed := plan
	changed.Fingerprint[0] ^= 1
	if err := repo.ValidateCommandCounters(command, changed); err == nil {
		t.Fatal("foreign prepared fingerprint admitted")
	}
	metadata.Network = "192.0.2.15"
	altered, err := identity.NewAccountLinkCounterCommand(original, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ValidateCommandCounters(altered, plan); err == nil {
		t.Fatal("network attribution substituted after preparation")
	}
	for _, mutate := range []func(*identity.AccountLinkCounterContext){
		func(c *identity.AccountLinkCounterContext) { c.KeyVersions = []uint32{8, 7} },
	} {
		_, context, _ := command.AccountLinkCounterCommand()
		mutate(&context)
		changed, err := identity.NewAccountLinkCounterCommand(original, context)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ValidateCommandCounters(changed, plan); err == nil {
			t.Fatal("unavailable key alias substituted")
		}
	}
	// CounterBinding deliberately excludes PreparedAt from logical replay
	// identity (risk.CounterBinding). The native command codec binds it to the
	// original keyed command, and CheckCommandCounters compares the locked
	// charge's exact prepared_at. Stateless restoration is not that allowance.
	_, originalContext, _ := command.AccountLinkCounterCommand()
	if originalContext.PreparedAt != at || restored.command.Bindings().PreparedAt != at {
		t.Fatal("restoration replaced the supplied original preparation instant")
	}
	for _, disabled := range []*Repository{nil, {}, {counters: &risk.CommandCounterPolicyConfig{}}} {
		if _, _, err := disabled.PrepareAccountLinkCommandCounters(original, subject, at); err == nil {
			t.Fatal("disabled counter owner admitted canonical link")
		}
		if err := disabled.ValidateCommandCounters(command, plan); err == nil {
			t.Fatal("disabled counter owner restored allowance")
		}
	}
}

func TestAccountLinkProtectedCounterRetainedKeyRotationAndExclusiveExpiry(t *testing.T) {
	at := time.Date(2026, 11, 1, 11, 0, 0, 123000, time.UTC)
	original := accountLinkCounterFixture(t, at)
	key7, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	key9, _ := risk.NewCounterDigestKey(9, bytes.Repeat([]byte{0x32}, 32))
	old, err := NewRepository(protectedConfig(t, key7))
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: "subject", Session: "original-session", Network: "192.0.2.15"}
	command, plan, err := old.PrepareAccountLinkCommandCounters(original, subject, at)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewRepository(protectedConfig(t, key9, key7))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := rotated.restoreCounter(command, plan)
	if err != nil || retained.command.Bindings().PreparedAt != at || len(retained.command.Bindings().Targets[0].Keys) != 1 || len(retained.current.Targets[0].Keys) != 2 {
		t.Fatal("retained counter history reset across key rotation", err)
	}
	if err := retained.validateAt(at.Add(15*time.Minute - time.Microsecond)); err != nil {
		t.Fatal("valid original interval lost", err)
	}
	if err := retained.validateAt(at.Add(15 * time.Minute)); err == nil {
		t.Fatal("rotation extended original preparation lifetime")
	}
	wrong7, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x33}, 32))
	foreign, err := NewRepository(protectedConfig(t, key9, wrong7))
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.ValidateCommandCounters(command, plan); err == nil {
		t.Fatal("same version with different retained key accepted")
	}
	dropped, err := NewRepository(protectedConfig(t, key9))
	if err != nil {
		t.Fatal(err)
	}
	if err := dropped.ValidateCommandCounters(command, plan); err == nil {
		t.Fatal("missing original key alias accepted")
	}
}
