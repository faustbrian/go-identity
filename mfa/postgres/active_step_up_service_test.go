package mfapostgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestActiveStepUpRequiresNativeCompositionAndExplicitVariant(t *testing.T) {
	if service, err := NewTOTPActiveStepUpService(nil, TOTPActiveStepUpConfig{}); err == nil || service != nil {
		t.Fatal("unconfigured active-factor verification admitted")
	}
	for _, service := range []*TOTPActiveStepUpService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := service.TotpVerify(ctx, mfa.TotpVerifyRequest{})
			if err == nil || out.StepUpProof.Bindings().Proof.ID != "" || out.Outcome != 0 {
				t.Fatal("unselected active-factor verification supplied proof")
			}
			lifetime, until, err := service.ActiveStepUpRateSource(ctx, mfa.TotpVerifyRequest{})
			if err == nil || lifetime != 0 || !until.IsZero() {
				t.Fatal("unselected step-up supplied quota metadata")
			}
		}
	}
}

func TestActiveStepUpUnselectedEmailChangeDeniesBeforeOwnerWork(t *testing.T) {
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	r := mfa.TotpVerifyRequest{
		TenantID: "tenant-a", CommandID: "AAAAAAAAAAAAAAAAAAAAAw", FactorID: "AAAAAAAAAAAAAAAAAAAABA",
		Code: code, Origin: "https://app.example", Network: "192.0.2.1",
		Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-a", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}},
		StepUp: &mfa.TOTPAuthenticatedStepUp{Session: auth.NewBearerCredential(strings.Repeat("A", 43)), CSRFToken: csrf, Purpose: "identity.email.change-request"},
	}
	if err := r.Validate(); err != nil {
		t.Fatal("fixture must reach native selection", err)
	}
	// No shared owner is installed: an unselected action must be denied before
	// consulting session/factor/risk or constructing a coordinator.
	state := &activeStepUpState{config: TOTPActiveStepUpConfig{AllowedOrigins: []string{r.Origin}}}
	s := &TOTPActiveStepUpService{state: func() *activeStepUpState { return state }}
	var denied identity.ForbiddenError
	out, err := s.TotpVerify(t.Context(), r)
	if !errors.As(err, &denied) || out.StepUpProof.Bindings().Proof.ID != "" || out.Outcome != 0 {
		t.Fatal("unselected email action reached native owner work")
	}
	lifetime, until, err := s.ActiveStepUpRateSource(t.Context(), r)
	if !errors.As(err, &denied) || lifetime != 0 || !until.IsZero() {
		t.Fatal("unselected email action acquired quota custody")
	}
}
