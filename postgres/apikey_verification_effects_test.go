package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
)

func TestAPIKeyVerificationEffectsSeparateAuthenticationFromMutation(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		anonymous, authenticated, narrowed bool
	}{
		{"known-allowed", false, true, false},
		{"known-denied", false, false, false},
		{"unknown-denied", true, false, false},
		{"narrowed-allowed", false, true, true},
		{"narrowed-denied", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, declaration := apiKeyVerificationPlanFixture(t, tc.anonymous)
			p := &admittedKernelPlan{binding: b, feature: declaration.Feature, subjectType: declaration.SubjectType, lifecycle: declaration.Lifecycle, audits: declaration.Audits, apiKeyVerification: declaration.APIKeyVerification}
			outcome := APIKeyVerificationOutcome{Authenticated: tc.authenticated, PermissionsChanged: tc.narrowed}
			got, err := buildAPIKeyVerificationEffects(t.Context(), p, outcome, time.Now().UTC().Truncate(time.Microsecond))
			if err != nil {
				t.Fatal(err)
			}
			expected := audit.OutcomeDenied
			if tc.authenticated {
				expected = audit.OutcomeSucceeded
			}
			target := string(b.ActorID)
			if tc.anonymous {
				target = b.AnonymousFlowID
			}
			if len(got.audits) < 1 || got.audits[0].Action() != "identity.api_key.authenticate" || got.audits[0].Outcome() != expected || got.audits[0].Subject().ID() != target || got.audits[0].Subject().Type() != declaration.SubjectType || got.audits[0].Attributes()["aggregate.before_version"] != "0" || got.audits[0].Attributes()["aggregate.after_version"] != "0" {
				t.Fatal("attempt audit impersonated owner or reported a key mutation")
			}
			if !tc.narrowed {
				if len(got.audits) != 1 || got.lifecycle != nil {
					t.Fatal("ordinary verification invented key mutation/lifecycle")
				}
				return
			}
			if len(got.audits) != 2 || got.audits[1].Action() != "identity.api_key.update" || got.audits[1].Outcome() != audit.OutcomeSucceeded || got.audits[1].Subject().ID() != target || got.audits[1].Attributes()["aggregate.before_version"] != "7" || got.audits[1].Attributes()["aggregate.after_version"] != "8" || got.lifecycle == nil || *got.lifecycle != (LifecyclePlan{EventType: "api_key.permissions_changed.v1", BeforeVersion: 7, AfterVersion: 8}) {
				t.Fatal("Narrow lost actual key mutation or relabeled authentication denial as success")
			}
			first, second := got.audits[0].Context(), got.audits[1].Context()
			if first.CausationID() == "" || second.CausationID() == "" || first.CausationID() == second.CausationID() || first.CorrelationID() != b.CorrelationID || second.CorrelationID() != b.CorrelationID || got.audits[0].Attributes()["command.id"] != string(b.CommandID) || got.audits[1].Attributes()["command.id"] != string(b.CommandID) {
				t.Fatal("composed authentication/update audits lost distinct causation or shared original correlation")
			}
		})
	}
}

func TestAPIKeyVerificationEffectsRejectUnknownKeyAuthority(t *testing.T) {
	b, declaration := apiKeyVerificationPlanFixture(t, true)
	p := &admittedKernelPlan{binding: b, feature: declaration.Feature, subjectType: declaration.SubjectType, lifecycle: declaration.Lifecycle, audits: declaration.Audits, apiKeyVerification: declaration.APIKeyVerification}
	for _, outcome := range []APIKeyVerificationOutcome{{Authenticated: true}, {PermissionsChanged: true}, {Authenticated: true, PermissionsChanged: true}} {
		if got, err := buildAPIKeyVerificationEffects(t.Context(), p, outcome, time.Now().UTC().Truncate(time.Microsecond)); err == nil || len(got.audits) != 0 || got.lifecycle != nil {
			t.Fatal("unknown key fabricated authentication or mutable authority")
		}
	}
}
