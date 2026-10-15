package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func mfaActionSessionFixture(t *testing.T) (*PasswordMFAActionSessionGuard, PasswordMFAActionSessionInput) {
	t.Helper()
	original, command, profile := identifierSessionFixture(t)
	s, _ := original.Bindings()
	token, _ := session.NewToken(32)
	lookup, _ := session.NewDigestKey(1, make([]byte, 32))
	s.Lookup, _ = token.Digest(lookup, string(s.TenantID))
	original, _ = session.NewSession(s)
	original, csrf, csrfKey := csrfAdmissionFixture(t, original)
	b := command.Binding
	b.CommandID, _ = identity.NewCommandID()
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "mfa-test-policy", 1, string(b.CommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = "identity.mfa.totp-verify", "mfa-totp-step-up", 1, "AAAAAAAAAAAAAAAAAAAAAQ"
	fields, err := OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	until := s.LastActivityAt.Add(20 * time.Second)
	fields = append(fields, identity.FeatureField{Name: "mfa.session-valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: until.UTC().Format(storedTimeLayout)}})
	wire, _ := token.Reveal()
	c, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, Fields: fields}, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewPasswordMFAActionSessionGuard(Config{Schema: "session_store", MaximumDuration: time.Second}, profile)
	if err != nil {
		t.Fatal(err)
	}
	return g, PasswordMFAActionSessionInput{Command: c, Original: original, ValidUntil: until, LookupKey: lookup, CSRFToken: csrf, CSRFKey: csrfKey}
}

func TestMFAActionSessionBindsBearerCSRFOriginalRecordAndDeadline(t *testing.T) {
	g, input := mfaActionSessionFixture(t)
	for range 2 {
		if err := g.originalInput(input); err != nil {
			t.Fatal("exact original input rejected", err)
		}
	}
	for _, mutation := range []string{"bearer", "lookup-key", "csrf", "csrf-key", "original", "deadline", "missing-fields", "no-bearer"} {
		bad := input
		p, _ := input.Command.Feature()
		bearer, _ := input.Command.SessionToken()
		switch mutation {
		case "bearer":
			token, _ := session.NewToken(32)
			wire, _ := token.Reveal()
			bad.Command, _ = identity.NewFeatureSessionCommand(p, auth.NewBearerCredential(wire))
		case "lookup-key":
			bad.LookupKey, _ = session.NewDigestKey(2, make([]byte, 32))
		case "csrf":
			bad.CSRFToken, _ = session.NewCSRFToken()
		case "csrf-key":
			bad.CSRFKey, _ = session.NewCSRFKey(8, make([]byte, 32))
		case "original":
			s, _ := input.Original.Bindings()
			s.Version++
			bad.Original, _ = session.NewSession(s)
		case "deadline":
			bad.ValidUntil = input.ValidUntil.Add(time.Second)
		case "missing-fields":
			p.Fields = p.Fields[1:]
			bad.Command, _ = identity.NewFeatureSessionCommand(p, bearer)
		case "no-bearer":
			bad.Command, _ = identity.NewFeatureCommand(p)
		}
		if err := g.originalInput(bad); err == nil {
			t.Fatal("substitution admitted", mutation)
		}
	}
	if err := g.Check(context.Background(), kernel.Work{}, nil, input); err == nil {
		t.Fatal("valid metadata became authority without native Work")
	}
	if err := g.Check(nil, kernel.Work{}, nil, input); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Check(ctx, kernel.Work{}, nil, input); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
	if _, err := input.CSRFToken.Reveal(); err != nil {
		t.Fatal("admission consumed synchronizer delivery", err)
	}
	for _, value := range []any{g, input} {
		if wire, err := json.Marshal(value); err == nil || len(wire) != 0 {
			t.Fatal("implicit custody export")
		}
		if text := fmt.Sprintf("%#v", value); text != "postgres.PasswordMFAActionSessionGuard(redacted)" && text != "postgres.PasswordMFAActionSessionInput(redacted)" {
			t.Fatal("diagnostic custody export")
		}
	}
}

func TestFactorUpdateSessionCustodyRequiresItsExactNativeSchema(t *testing.T) {
	g, input := mfaActionSessionFixture(t)
	p, _ := input.Command.Feature()
	bearer, _ := input.Command.SessionToken()
	p.Binding.OperationID, p.Binding.SchemaID = "identity.mfa.factor-update", "mfa-factor-update"
	p.Binding.RecordID = string(p.Binding.UserID)
	p.Operation.OperationID, p.Operation.SchemaID = p.Binding.OperationID, p.Binding.SchemaID
	var err error
	input.Command, err = identity.NewFeatureSessionCommand(p, bearer)
	if err != nil || g.originalInput(input) != nil {
		t.Fatal("exact factor-update custody rejected", err)
	}
	p.Binding.SchemaID, p.Operation.SchemaID = "mfa-recovery-regenerate", "mfa-recovery-regenerate"
	input.Command, err = identity.NewFeatureSessionCommand(p, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if g.originalInput(input) == nil {
		t.Fatal("factor update borrowed regeneration schema authority")
	}
}

func TestMFAActionSessionGuardRequiresExplicitPasswordProfile(t *testing.T) {
	_, _, profile := identifierSessionFixture(t)
	for _, config := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 6 * time.Second}} {
		if g, err := NewPasswordMFAActionSessionGuard(config, profile); err == nil || g != nil {
			t.Fatal("invalid native guard configuration admitted")
		}
	}
	profile.CredentialOwner = "unselected-owner"
	if g, err := NewPasswordMFAActionSessionGuard(Config{Schema: "session_store", MaximumDuration: time.Second}, profile); err == nil || g != nil {
		t.Fatal("unselected password owner admitted")
	}
}

func TestDisableSessionCustodyRequiresItsExactNativeSchema(t *testing.T) {
	g, input := mfaActionSessionFixture(t)
	p, _ := input.Command.Feature()
	bearer, _ := input.Command.SessionToken()
	p.Binding.OperationID, p.Binding.SchemaID = "identity.mfa.disable", "mfa-disable"
	p.Binding.RecordID = string(p.Binding.UserID)
	p.Operation.OperationID, p.Operation.SchemaID = p.Binding.OperationID, p.Binding.SchemaID
	input.Command, _ = identity.NewFeatureSessionCommand(p, bearer)
	if err := g.originalInput(input); err != nil {
		t.Fatal("exact disable custody rejected", err)
	}
	p.Binding.SchemaID, p.Operation.SchemaID = "mfa-factor-update", "mfa-factor-update"
	input.Command, _ = identity.NewFeatureSessionCommand(p, bearer)
	if g.originalInput(input) == nil {
		t.Fatal("disable borrowed factor-update schema authority")
	}
}
