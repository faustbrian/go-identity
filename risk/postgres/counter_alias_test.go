package postgres

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestRetainedCounterPreparationSurvivesAddedKeysWithoutRenewal(t *testing.T) {
	at := time.Date(2026, 11, 2, 3, 0, 0, 123000, time.UTC)
	cfg := protectedConfig(t)
	old, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	feature, _ := protectedCommand(t, "counter-tenant").Feature()
	b := feature.Binding
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID, b.LinkMode = "identity.account.link-token", "identity-account", 1, "account", identity.AccountLinkExplicit
	spec := identity.AccountLinkPreparationCommand{Binding: b, ProviderID: "configured", ProviderConfigVersion: 1, FlowID: "original-flow", FlowFingerprint: [32]byte{1}, SessionID: "original-session", SessionVersion: 1}
	input, err := identity.NewOAuthCallbackInput([]byte("synthetic-code"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Destroy()
	bearer := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	subject := risk.Subject{User: string(b.UserID), Session: spec.SessionID, Network: "192.0.2.7"}
	original, plan, err := old.PrepareAccountLinkPreparationCounters(spec, input, bearer, subject, at)
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(8, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rotated := *cfg.CommandCounters
	rotated.Keys = append([]risk.CounterDigestKey{key}, rotated.Keys...)
	cfg.CommandCounters = &rotated
	current, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, changed, err := current.PrepareAccountLinkPreparationCounters(spec, input, bearer, subject, at)
	if err != nil || changed == plan {
		t.Fatal("fixture did not expose active-key claim drift", err)
	}
	replayed, same, err := current.PrepareAccountLinkPreparationCountersWithRetainedKeys(spec, input, bearer, subject, at, []uint32{7})
	if err != nil || same != plan {
		t.Fatal("rotation rewrote original counter plan", err)
	}
	want, _, _, _ := original.AccountLinkPreparationInput()
	got, _, _, _ := replayed.AccountLinkPreparationInput()
	if !reflect.DeepEqual(want, got) || current.ValidateCommandCounters(replayed, same) != nil {
		t.Fatal("retained reconstruction changed original callback intent")
	}
	owned, err := current.restoreCounter(replayed, same)
	if err != nil || owned.validateAt(at.Add(15*time.Minute)) == nil {
		t.Fatal("retained reconstruction renewed original exclusive expiry")
	}
	featureCommand := protectedCommand(t, "counter-tenant")
	featureSubject := risk.Subject{User: "subject", Session: "session", Network: subject.Network}
	_, featurePlan, err := old.PrepareCommandCounters(featureCommand, featureSubject, at)
	if err != nil {
		t.Fatal(err)
	}
	_, restoredPlan, err := current.PrepareCommandCountersWithRetainedKeys(featureCommand, featureSubject, at, []uint32{7})
	if err != nil || featurePlan != restoredPlan {
		t.Fatal("feature retry rewrote original risk plan", err)
	}
	for _, versions := range [][]uint32{nil, {0}, {9}, {7, 7}, {7, 8}} {
		if _, _, err := current.PrepareAccountLinkPreparationCountersWithRetainedKeys(spec, input, bearer, subject, at, versions); err == nil {
			t.Fatal("invalid retained aliases accepted")
		}
	}
	rotated.Keys = rotated.Keys[:1]
	removed, err := NewRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := removed.PrepareAccountLinkPreparationCountersWithRetainedKeys(spec, input, bearer, subject, at, []uint32{7}); err == nil {
		t.Fatal("removed key reconstructed historical custody")
	}
}
