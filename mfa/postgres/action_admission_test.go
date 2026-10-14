package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type actionAdmissionClock struct{}

func (actionAdmissionClock) Now() time.Time { return time.Now().UTC() }

type actionAdmissionPolicy struct {
	outcome  authorization.Outcome
	revision authorization.Revision
}

func (p actionAdmissionPolicy) Decide(ctx context.Context, _ authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: p.outcome, Revision: p.revision}, ctx.Err()
}

func TestNativeMFAActionAdmissionRequiresCurrentAllowAtConfiguredRevision(t *testing.T) {
	r := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.mfa.recovery-regenerate", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}
	for _, p := range []actionAdmissionPolicy{{authorization.Deny, 9}, {authorization.Allow, 8}, {authorization.Allow, 9}} {
		state := &totpEnrollmentState{config: TOTPEnrollmentConfig{Coordinator: kernel.CoordinatorConfig{AdmissionPolicy: &kernel.CommandQueryPolicy{Authorization: p, Clock: actionAdmissionClock{}, PolicyVersion: 9}}}}
		err := authorizeNativeMFAAction(t.Context(), state, r, "identity.mfa.recovery-regenerate")
		if p.outcome == authorization.Allow && p.revision == 9 {
			if err != nil {
				t.Fatal("current Allow rejected", err)
			}
		} else {
			if _, ok := err.(identity.ForbiddenError); !ok {
				t.Fatal("denied/stale policy granted native mutation", err)
			}
		}
	}
}
