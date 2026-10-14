package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
)

func securityInput(t *testing.T) SecurityEventInput {
	t.Helper()
	id, e := NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return SecurityEventInput{Action: SecurityHIBPQueryRange, OccurredAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), Outcome: audit.OutcomeSucceeded, Reason: SecurityCompleted, TenantID: TenantID(id), CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: SecurityAuthenticationAttempt, SubjectID: string(id), PolicyID: string(id), PolicyVersion: 3, Provider: SecurityProvider{Kind: SecurityProviderHIBP, Profile: SecurityHIBPRange, Version: 1, Result: SecurityProviderAccepted}}
}

func TestSecurityProfileCanonicalConstructionAndOwnership(t *testing.T) {
	b, e := NewIdentitySecurityEventV1(testWall(time.Date(2026, 10, 4, 0, 1, 0, 0, time.UTC)))
	if e != nil {
		t.Fatal(e)
	}
	input := securityInput(t)
	record, e := b.Build(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := audit.CanonicalJSON(record)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	attrs := parsed.Attributes()
	if attrs["identity.profile"] != "identity.security.v1" || attrs["retention.class"] != "protected" || attrs["provider.kind"] != "hibp" || attrs["provider.version"] != "1" || record.Policy().Version != "3" || record.Description() != "" || !record.RedactionApplied() || !record.Changes().NoChange() || record.Actor().Kind() != audit.ActorAnonymous || record.Subject().Type() != "authentication_attempt" {
		t.Fatal("profile mapping violated")
	}
	if !record.OccurredAt().Equal(input.OccurredAt) || record.RecordedAt().Equal(input.OccurredAt) {
		t.Fatal("record/occurrence times conflated")
	}
	attrs["provider.kind"] = "unsafe"
	if record.Attributes()["provider.kind"] != "hibp" {
		t.Fatal("record exposed mutable map")
	}
}

func TestSecurityProfilePreservesRegisteredPaddingVariants(t *testing.T) {
	b, err := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []SecurityProviderProfile{SecurityHIBPRange, "hibp.range.unpadded.v1"} {
		for _, action := range []SecurityAction{SecurityHIBPQueryRange, SecurityHIBPDetectMatch, SecurityHIBPRejectRange} {
			input := securityInput(t)
			input.Provider.Profile, input.Action = profile, action
			record, err := b.Build(context.Background(), input)
			if err != nil {
				t.Fatal("registered profile rejected", err)
			}
			raw, err := audit.CanonicalJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
			if err != nil || parsed.Attributes()["provider.profile"] != string(profile) || parsed.Attributes()["retention.class"] != "protected" || parsed.Action() != string(action) {
				t.Fatal("canonical profile rewritten", err)
			}
		}
	}
	for _, profile := range []SecurityProviderProfile{"hibp.range.arbitrary.v1", "hibp.range.unpadded.v2"} {
		input := securityInput(t)
		input.Provider.Profile = profile
		if _, err := b.Build(context.Background(), input); !errors.Is(err, ErrInvalidSecurityEvent) {
			t.Fatal("unregistered privacy profile accepted", err)
		}
	}
	input := securityInput(t)
	input.Provider.Profile, input.Provider.Version = SecurityHIBPRangeUnpadded, 0
	if _, err := b.Build(context.Background(), input); !errors.Is(err, ErrInvalidSecurityEvent) {
		t.Fatal("zero unpadded provider version accepted", err)
	}
}

type testWall time.Time

func TestSecurityProfileAttemptCannotBeIdentifierDigest(t *testing.T) {
	b, e := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if e != nil {
		t.Fatal(e)
	}
	i := securityInput(t)
	i.SubjectID = "0123456789abcdef0123456789abcdef"
	if _, e := b.Build(context.Background(), i); !errors.Is(e, ErrInvalidSecurityEvent) {
		t.Fatal("digest accepted as pre-auth attempt", e)
	}
}

func TestSecurityProfileAcceptsAnExistingEventAsCausation(t *testing.T) {
	b, e := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if e != nil {
		t.Fatal(e)
	}
	input := securityInput(t)
	query, e := b.Build(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	input.Action = SecurityHIBPDetectMatch
	input.CausationID = CommandID(query.ID())
	detected, e := b.Build(context.Background(), input)
	if e != nil || detected.Context().CausationID() != query.ID() {
		t.Fatal("actual query event cannot cause match detection", e)
	}
}

func TestSecurityProfilePreservesImportedIDsAndCopiesDelegation(t *testing.T) {
	b, e := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "01234567-89ab-cdef-0123-456789abcdef", "0123456789abcdef0123456789abcdef"} {
		i := securityInput(t)
		i.TenantID = TenantID(id)
		i.PolicyID = id
		i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: id, AuthenticationMethod: audit.AuthenticationMethodPasskey, DelegatedBy: &audit.ActorInput{Kind: audit.ActorSystem, ID: id}}
		r, e := b.Build(context.Background(), i)
		if e != nil || r.Context().TenantID() != id || r.Actor().ID() != id || r.Policy().PolicyID != id {
			t.Fatal("canonical imported ID changed", e)
		}
		i.Actor.DelegatedBy.ID = "changed"
		if r.Actor().DelegatedBy().ID() != id {
			t.Fatal("delegation custody escaped")
		}
	}
	i := securityInput(t)
	i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: string(i.CommandID)}
	i.Actor.DelegatedBy = &i.Actor
	if _, e := b.Build(context.Background(), i); !errors.Is(e, ErrInvalidSecurityEvent) {
		t.Fatal("delegation cycle accepted", e)
	}
}

func (w testWall) Now() time.Time { return time.Time(w) }

func TestSecurityProfileRejectsPrivacyAndOutcomeViolations(t *testing.T) {
	b, e := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*SecurityEventInput){
		func(i *SecurityEventInput) { i.Action = SecurityAction("identity.hibp.query_range_succeeded") }, func(i *SecurityEventInput) { i.SubjectID = "email@example.test" }, func(i *SecurityEventInput) { i.TenantID = "tenant@example.test" }, func(i *SecurityEventInput) { i.PolicyID = "arbitrary policy name" }, func(i *SecurityEventInput) { i.PolicyVersion = 0 }, func(i *SecurityEventInput) { i.CommandID = "" }, func(i *SecurityEventInput) { i.CorrelationID = "" }, func(i *SecurityEventInput) { i.Provider.Result = SecurityProviderResult("suffix-data") }, func(i *SecurityEventInput) { i.Provider.Profile = "raw-provider-profile" }, func(i *SecurityEventInput) { i.Provider.Version = 0 }, func(i *SecurityEventInput) { i.Reason = SecurityProviderUnavailable }, func(i *SecurityEventInput) { i.Outcome = audit.OutcomeUnknown }, func(i *SecurityEventInput) {
			i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: "raw@example.test"}
		},
	} {
		input := securityInput(t)
		change(&input)
		if _, e := b.Build(context.Background(), input); !errors.Is(e, ErrInvalidSecurityEvent) {
			t.Fatal("unsafe profile accepted", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := b.Build(ctx, securityInput(t)); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled builder proceeded", e)
	}
}
