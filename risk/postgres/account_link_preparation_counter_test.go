package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestOriginalAccountLinkPreparationUsesRealProtectedCounterPolicy(t *testing.T) {
	at := time.Date(2026, 11, 1, 11, 0, 0, 123000, time.UTC)
	feature, _ := protectedCommand(t, "counter-tenant").Feature()
	b := feature.Binding
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID, b.LinkMode = "identity.account.link-token", "identity-account", 1, "account", identity.AccountLinkExplicit
	spec := identity.AccountLinkPreparationCommand{Binding: b, ProviderID: "configured-oidc", ProviderConfigVersion: 3, FlowID: "original-flow", FlowFingerprint: [32]byte{1}, SessionID: "original-session", SessionVersion: 17}
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	callback, err := identity.NewOAuthCallbackInput([]byte("synthetic-original-code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	bearer := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	repo, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: string(b.UserID), Session: spec.SessionID, Network: "2001:db8::12"}
	command, plan, err := repo.PrepareAccountLinkPreparationCounters(spec, callback, bearer, subject, at)
	if err != nil {
		t.Fatal("original callback cannot prepare actual protected counters", err)
	}
	original, retained, session, ok := command.AccountLinkPreparationInput()
	if !ok || original.Binding != spec.Binding || original.ProviderConfigVersion != spec.ProviderConfigVersion || original.FlowFingerprint != spec.FlowFingerprint || original.SessionVersion != spec.SessionVersion || original.Counters.Network != subject.Network || original.Counters.PreparedAt != at || len(original.Counters.KeyVersions) != 1 || original.Counters.KeyVersions[0] != 7 || session.Token() != bearer.Token() {
		t.Fatal("protected preparation changed original callback/session intent")
	}
	if err := retained.Use(t.Context(), func(_ context.Context, code, gotState []byte) error {
		if !bytes.Equal(code, []byte("synthetic-original-code")) || string(gotState) != state {
			t.Fatal("counter preparation substituted original provider input")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := command.Feature(); ok {
		t.Fatal("original callback was wrapped as a generic feature")
	}
	if _, _, ok := command.AccountLinkCounterCommand(); ok {
		t.Fatal("original callback invented a signed provider subject or grant")
	}
	native, err := repo.restoreCounter(command, plan)
	if err != nil || native.subject != subject || native.scope.Operation != "identity.account.link-token" || native.command.Bindings().PreparedAt != at || len(native.command.Bindings().Targets) != 4 {
		t.Fatal("native policy cannot restore original callback counters", err)
	}
	if err := native.validateAt(at.Add(15*time.Minute - time.Microsecond)); err != nil {
		t.Fatal("original live evidence rejected", err)
	}
	if err := native.validateAt(at.Add(15 * time.Minute)); err == nil {
		t.Fatal("restoring original callback renewed exclusive expiry")
	}
	original.Counters.KeyVersions[0]++
	if err := repo.ValidateCommandCounters(command, plan); err != nil {
		t.Fatal("returned metadata aliases frozen original context", err)
	}
	if _, _, err := repo.PrepareAccountLinkPreparationCounters(original, callback, bearer, subject, at); err == nil {
		t.Fatal("repeat preparation overwrote original counters")
	}
	for _, mutate := range []func(*risk.Subject){
		func(s *risk.Subject) { s.User = "other" },
		func(s *risk.Subject) { s.Session = "other" },
		func(s *risk.Subject) { s.Actor = "other" },
		func(s *risk.Subject) { s.Resource = "other" },
		func(s *risk.Subject) { s.Device = "other" },
		func(s *risk.Subject) { s.IdentifierDigest = "other" },
	} {
		wrong := subject
		mutate(&wrong)
		if _, _, err := repo.PrepareAccountLinkPreparationCounters(spec, callback, bearer, wrong, at); err == nil {
			t.Fatal("foreign or extra dimensions accepted")
		}
	}
	for _, mutate := range []func(*identity.AccountLinkPreparationCommand){
		func(s *identity.AccountLinkPreparationCommand) {
			s.Binding.LinkMode = identity.AccountLinkAdministrative
		},
		func(s *identity.AccountLinkPreparationCommand) { s.ProviderConfigVersion = 0 },
		func(s *identity.AccountLinkPreparationCommand) { s.FlowFingerprint = [32]byte{} },
		func(s *identity.AccountLinkPreparationCommand) { s.Counters.Network = subject.Network },
		func(s *identity.AccountLinkPreparationCommand) { s.Counters.PreparedAt = at },
	} {
		wrong := spec
		mutate(&wrong)
		mapped, denied, err := repo.PrepareAccountLinkPreparationCounters(wrong, callback, bearer, subject, at)
		_, _, _, live := mapped.AccountLinkPreparationInput()
		if err == nil || live || denied.PolicyVersion != 0 || denied.Fingerprint != ([32]byte{}) {
			t.Fatal("invalid or already prepared intent returned usable counter custody")
		}
	}
	for _, disabled := range []*Repository{nil, {}} {
		if _, _, err := disabled.PrepareAccountLinkPreparationCounters(spec, callback, bearer, subject, at); err == nil {
			t.Fatal("missing configured counter owner accepted")
		}
	}
	key7, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	key9, _ := risk.NewCounterDigestKey(9, bytes.Repeat([]byte{0x32}, 32))
	rotated, err := NewRepository(protectedConfig(t, key9, key7))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.restoreCounter(command, plan); err != nil {
		t.Fatal("original callback lost retained-key compatibility", err)
	}
	dropped, err := NewRepository(protectedConfig(t, key9))
	if err != nil {
		t.Fatal(err)
	}
	if err := dropped.ValidateCommandCounters(command, plan); err == nil {
		t.Fatal("original callback accepted without its retained key")
	}
	callback.Destroy()
	if _, _, err := repo.PrepareAccountLinkPreparationCounters(spec, callback, bearer, subject, at); err == nil {
		t.Fatal("destroyed original callback accepted")
	}
}
