package anonymous_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	"github.com/faustbrian/go-identity/session"
)

// Structural custody only. The native workflow must authenticate the actual
// stored target proof and both sessions; these caller-constructed values cannot.
func upgradeRequest(t testing.TB) anonymous.UpgradeRequest {
	t.Helper()
	r := signinRequest(t)
	deletion := deletionRequest(t)
	plan := upgradePlanFixture(t)
	plan.Conflicts = nil
	source, _ := plan.Source.Record()
	proof, err := auth.NewProof(auth.ProofSpec{ID: "abcdefghijklmnopqrstuv", Tenant: string(source.TenantID), Subject: string(plan.Target), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "identity", IssuedAt: source.CreatedAt, ExpiresAt: source.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return anonymous.UpgradeRequest{TenantID: source.TenantID, TargetSession: r.Cookie, TargetProof: auth.ReauthenticationProof{Proof: proof, SessionID: "permanent-session", SessionVersion: 1, Action: "identity.anonymous.upgrade"}, TargetCSRF: deletion.CSRFToken, Guest: deletion.Credential, GuestCSRF: deletion.CSRFToken, Plan: plan, Remember: r.Remember, Origin: r.Origin, Network: r.Network, Device: r.Device, IdempotencyKey: r.IdempotencyKey, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(source.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(plan.Target)}, Action: "identity.anonymous.upgrade", Resource: authorization.Resource{Type: "anonymous", ID: authorization.ResourceID(source.UserID)}}}}
}

func TestUpgradeRequestKeepsTargetProofAndGuestPossessionDistinct(t *testing.T) {
	r := upgradeRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("original upgrade structure", err)
	}
	for _, change := range []func(*anonymous.UpgradeRequest){
		func(r *anonymous.UpgradeRequest) { r.TenantID = "other-tenant" },
		func(r *anonymous.UpgradeRequest) { r.TargetSession = auth.BearerCredential{} },
		func(r *anonymous.UpgradeRequest) { r.TargetSession = auth.NewBearerCredential("invalid") },
		func(r *anonymous.UpgradeRequest) { r.TargetProof = auth.ReauthenticationProof{} },
		func(r *anonymous.UpgradeRequest) {
			s, _ := r.Plan.Source.Record()
			r.TargetProof.Proof.Subject = string(s.ID)
		},
		func(r *anonymous.UpgradeRequest) { r.TargetProof.Action = "identity.anonymous.delete" },
		func(r *anonymous.UpgradeRequest) { r.TargetProof.Proof.Purpose = "identity.password.change" },
		func(r *anonymous.UpgradeRequest) { r.TargetProof.SessionVersion = 0 },
		func(r *anonymous.UpgradeRequest) { r.TargetCSRF = session.CSRFToken{} },
		func(r *anonymous.UpgradeRequest) { r.Guest = session.Credential{} },
		func(r *anonymous.UpgradeRequest) { r.GuestCSRF = session.CSRFToken{} },
		func(r *anonymous.UpgradeRequest) { r.Remember = session.RememberPolicy{} },
		func(r *anonymous.UpgradeRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *anonymous.UpgradeRequest) { r.Caller.Request.Subject.ID = "other-target" },
		func(r *anonymous.UpgradeRequest) { r.Caller.Request.Action = "identity.anonymous.delete" },
		func(r *anonymous.UpgradeRequest) { r.Network = "fe80::1%en0" },
		func(r *anonymous.UpgradeRequest) { r.Origin = "https://example.test\n" },
	} {
		changed := r
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("substituted or incomplete upgrade custody admitted")
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatal("validation consumed original custody", err)
	}
}

func TestUpgradeRequestAndResultForbidImplicitDisclosure(t *testing.T) {
	r := upgradeRequest(t)
	for _, value := range []any{r, anonymous.UpgradeResult{}, anonymous.UpgradeRecoveryRequest{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit upgrade serialization")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, r.TargetSession.Token()) || strings.Contains(text, r.Origin) || strings.Contains(text, string(r.Plan.Target)) {
				t.Fatal("upgrade diagnostics exposed original custody")
			}
		}
	}
}

func TestUpgradeRecoveryCorrelatesBothOriginalCommandsWithoutRenewal(t *testing.T) {
	r := upgradeRequest(t)
	a, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	source, _ := r.Plan.Source.Record()
	preparation := identity.RecoveryQuery{CommandID: a, TenantID: r.TenantID, UserID: identity.UserID(r.Plan.Target), ActorID: identity.ActorID(r.Plan.Target), ActorKind: authorization.SubjectUser, OperationID: "identity.anonymous.upgrade"}
	protected := preparation
	protected.CommandID, protected.OperationID, protected.RecordID = b, "identity.anonymous.upgrade", string(source.UserID)
	recovery := anonymous.UpgradeRecoveryRequest{Preparation: preparation, Recovery: protected, TargetSession: r.TargetSession, TargetCSRF: r.TargetCSRF, Guest: r.Guest, GuestCSRF: r.GuestCSRF, Origin: r.Origin, Network: r.Network, Device: r.Device}
	if err := recovery.Validate(); err != nil {
		t.Fatal("original pair rejected", err)
	}
	for _, change := range []func(*anonymous.UpgradeRecoveryRequest){
		func(r *anonymous.UpgradeRecoveryRequest) { r.Preparation.CommandID = r.Recovery.CommandID },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Preparation.RecordID = r.Recovery.RecordID },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Preparation.TenantID = "foreign" },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Preparation.UserID = "other-target" },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Recovery.ActorID = "guest" },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Recovery.RecordID = string(r.Recovery.UserID) },
		func(r *anonymous.UpgradeRecoveryRequest) { r.Recovery.OperationID = "identity.anonymous.delete" },
		func(r *anonymous.UpgradeRecoveryRequest) { r.GuestCSRF = session.CSRFToken{} },
		func(r *anonymous.UpgradeRecoveryRequest) { r.TargetSession = auth.BearerCredential{} },
	} {
		changed := recovery
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("foreign or incomplete original pair admitted")
		}
	}
}
