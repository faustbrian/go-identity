package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func riskSecurityInput(t *testing.T) RiskSecurityEventInput {
	t.Helper()
	i := securityInput(t)
	return RiskSecurityEventInput{Decision: RiskSecurityAllow, OccurredAt: i.OccurredAt,
		TenantID: i.TenantID, CommandID: i.CommandID, CorrelationID: i.CorrelationID,
		Actor: i.Actor, Subject: i.Subject, SubjectID: i.SubjectID,
		PolicyID: i.PolicyID, PolicyVersion: i.PolicyVersion}
}

func TestRiskSecurityEventCanonicalDecisionWithoutProviderFacts(t *testing.T) {
	b, err := NewIdentitySecurityEventV1(testWall(time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		decision RiskSecurityDecision
		outcome  audit.Outcome
		reason   string
	}{
		{RiskSecurityAllow, audit.OutcomeSucceeded, "completed"},
		{RiskSecurityDeny, audit.OutcomeDenied, "risk_denied"},
		{RiskSecurityThrottle, audit.OutcomeDenied, "rate_limited"},
		{RiskSecurityStepUp, audit.OutcomeDenied, "step_up_required"},
	} {
		i := riskSecurityInput(t)
		i.Decision = item.decision
		r, err := b.BuildRiskDecision(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := audit.CanonicalJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		attrs := parsed.Attributes()
		if parsed.Action() != "identity.risk.decide" || parsed.Outcome() != item.outcome || parsed.ReasonCode() != item.reason ||
			attrs["identity.profile"] != "identity.security.v1" || attrs["retention.class"] != "protected" || attrs["command.id"] != string(i.CommandID) || len(attrs) != 3 ||
			parsed.Context().TenantID() != string(i.TenantID) || parsed.Context().CorrelationID() != string(i.CorrelationID) || parsed.Context().CausationID() != "" ||
			parsed.Subject().Type() != "authentication_attempt" || parsed.Subject().ID() != i.SubjectID || parsed.Policy().PolicyID != i.PolicyID || parsed.Policy().Version != "3" ||
			!parsed.OccurredAt().Equal(i.OccurredAt) || parsed.RecordedAt().Equal(i.OccurredAt) || parsed.Description() != "" || !r.RedactionApplied() || !parsed.Changes().NoChange() {
			t.Fatal("risk decision attribution changed")
		}
		attrs["retention.class"] = "standard"
		if r.Attributes()["retention.class"] != "protected" {
			t.Fatal("mutable attributes escaped")
		}
	}
}

func TestRiskSecurityEventKnownSubjectAndDelegation(t *testing.T) {
	b, err := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "01234567-89ab-cdef-0123-456789abcdef", "0123456789abcdef0123456789abcdef"} {
		i := riskSecurityInput(t)
		i.Subject, i.SubjectID = SecurityUser, id
		i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: id, AuthenticationMethod: audit.AuthenticationMethodPasskey,
			DelegatedBy: &audit.ActorInput{Kind: audit.ActorHuman, ID: string(i.CommandID)}}
		i.ImpersonationGrantID = string(i.CommandID)
		prior, err := b.Build(context.Background(), securityInput(t))
		if err != nil {
			t.Fatal(err)
		}
		i.CausationID = CommandID(prior.ID())
		r, err := b.BuildRiskDecision(context.Background(), i)
		if err != nil || r.Subject().Type() != "user" || r.Subject().ID() != id || r.Actor().ID() != id || r.Actor().AuthenticationMethod() != audit.AuthenticationMethodPasskey ||
			r.Actor().DelegatedBy().ID() != string(i.CommandID) || r.Context().CausationID() != prior.ID() || r.Attributes()["scope.impersonation_grant_id"] != i.ImpersonationGrantID {
			t.Fatal("known/delegated attribution changed", err)
		}
		i.Actor.DelegatedBy.ID = "changed"
		if r.Actor().DelegatedBy().ID() != string(i.CommandID) {
			t.Fatal("delegation was not copied")
		}
	}
	i := riskSecurityInput(t)
	i.Subject = SecurityUser
	i.Actor = audit.ActorInput{Kind: audit.ActorSystem, ID: string(i.CommandID)}
	if _, err := b.BuildRiskDecision(context.Background(), i); err != nil {
		t.Fatal("system attribution rejected", err)
	}
}

func TestRiskSecurityEventRejectsUntrustedAndUnknownAttribution(t *testing.T) {
	b, err := NewIdentitySecurityEventV1(testWall(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RiskSecurityEventInput){
		func(i *RiskSecurityEventInput) { i.Decision = "" },
		func(i *RiskSecurityEventInput) { i.Decision = "challenge" },
		func(i *RiskSecurityEventInput) { i.Decision = "revoke" },
		func(i *RiskSecurityEventInput) { i.Decision = "commit_unknown" },
		func(i *RiskSecurityEventInput) { i.Subject = "provider_subject" },
		func(i *RiskSecurityEventInput) { i.SubjectID = "0123456789abcdef0123456789abcdef" },
		func(i *RiskSecurityEventInput) { i.Subject = SecurityUser; i.SubjectID = "private@example.test" },
		func(i *RiskSecurityEventInput) { i.TenantID = "" },
		func(i *RiskSecurityEventInput) { i.CommandID = "" },
		func(i *RiskSecurityEventInput) { i.CorrelationID = "" },
		func(i *RiskSecurityEventInput) { i.CausationID = "private@example.test" },
		func(i *RiskSecurityEventInput) { i.PolicyID = "192.0.2.1" },
		func(i *RiskSecurityEventInput) { i.PolicyVersion = 0 },
		func(i *RiskSecurityEventInput) { i.OccurredAt = time.Time{} },
		func(i *RiskSecurityEventInput) { i.OccurredAt = i.OccurredAt.In(time.FixedZone("not-UTC", 0)) },
		func(i *RiskSecurityEventInput) { i.Actor.ID = string(i.CommandID) },
		func(i *RiskSecurityEventInput) { i.Actor.AuthenticationMethod = audit.AuthenticationMethodPasskey },
		func(i *RiskSecurityEventInput) {
			i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: "private@example.test"}
		},
		func(i *RiskSecurityEventInput) { i.ImpersonationGrantID = string(i.CommandID) },
		func(i *RiskSecurityEventInput) {
			i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: string(i.CommandID), DelegatedBy: &audit.ActorInput{Kind: audit.ActorHuman, ID: string(i.CommandID)}}
		},
		func(i *RiskSecurityEventInput) {
			i.Actor = audit.ActorInput{Kind: audit.ActorHuman, ID: string(i.CommandID)}
			i.Actor.DelegatedBy = &i.Actor
			i.ImpersonationGrantID = string(i.CommandID)
		},
	} {
		i := riskSecurityInput(t)
		change(&i)
		r, err := b.BuildRiskDecision(context.Background(), i)
		if !errors.Is(err, ErrInvalidSecurityEvent) || r.ID() != "" {
			t.Fatal("unsafe input accepted", err)
		}
	}
	for _, ctx := range []context.Context{nil, func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(), func() context.Context {
		c, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		cancel()
		return c
	}()} {
		r, err := b.BuildRiskDecision(ctx, riskSecurityInput(t))
		if r.ID() != "" || ctx == nil && !errors.Is(err, ErrInvalidSecurityEvent) || ctx != nil && !errors.Is(err, ctx.Err()) {
			t.Fatal("context identity lost", err)
		}
	}
	for _, invalid := range []*IdentitySecurityEventV1{nil, {}} {
		r, err := invalid.BuildRiskDecision(context.Background(), riskSecurityInput(t))
		if r.ID() != "" || !errors.Is(err, ErrInvalidSecurityEvent) {
			t.Fatal("zero owner accepted", err)
		}
	}
}
