package postgres

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestSSOOIDCSigninRequiresOriginalBrowserAndValidity(t *testing.T) {
	fixture, original, _ := oauthSigninMappingFixture(t, false)
	record, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	binding := fixture.Binding
	binding.AnonymousFlowID = string(flowID)
	binding.OperationID = ssoOIDCSessionOperation().OperationID
	proofExpiry := record.Authentication.Proof.ExpiresAt
	flow := session.PreAuthTransactionSpec{
		Binding: session.PreAuthBinding{
			ID: flowID, IssuedAt: proofExpiry.Add(-time.Minute), ExpiresAt: proofExpiry,
			Intent: session.PreAuthIntent{TenantID: binding.TenantID, Action: binding.OperationID, PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion, Origin: "https://identity.example", Nonce: [32]byte{1}, Remember: record.Remember},
		},
		Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{2}}, Version: 1,
	}
	consumed := kernel.CapabilityReservationBinding{Command: binding, Plan: kernel.CapabilityPlan{Purpose: "identity.sso.oidc-callback", ExpiresAt: proofExpiry, MaxUses: 1}, Generation: 3, Fingerprint: [32]byte{4}}
	for _, tc := range []struct {
		name   string
		change func(*session.SessionSpec, *session.PreAuthTransactionSpec, *kernel.CapabilityReservationBinding)
	}{
		{name: "exact"},
		{name: "other-flow", change: func(_ *session.SessionSpec, _ *session.PreAuthTransactionSpec, r *kernel.CapabilityReservationBinding) {
			r.Command.AnonymousFlowID = "different"
		}},
		{name: "other-policy", change: func(_ *session.SessionSpec, f *session.PreAuthTransactionSpec, _ *kernel.CapabilityReservationBinding) {
			f.Binding.Intent.PolicyVersion++
		}},
		{name: "other-tenant", change: func(_ *session.SessionSpec, f *session.PreAuthTransactionSpec, _ *kernel.CapabilityReservationBinding) {
			f.Binding.Intent.TenantID = "tenant-b"
		}},
		{name: "renewed-browser-validity", change: func(_ *session.SessionSpec, f *session.PreAuthTransactionSpec, _ *kernel.CapabilityReservationBinding) {
			f.Binding.IssuedAt = f.Binding.IssuedAt.Add(-time.Second)
			f.Binding.ExpiresAt = f.Binding.ExpiresAt.Add(-time.Second)
		}},
		{name: "renewed-capability-validity", change: func(_ *session.SessionSpec, _ *session.PreAuthTransactionSpec, r *kernel.CapabilityReservationBinding) {
			r.Plan.ExpiresAt = r.Plan.ExpiresAt.Add(-time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, c := record, flow, consumed
			if tc.change != nil {
				tc.change(&s, &f, &c)
			}
			preauth, err := session.NewPreAuthTransaction(f)
			if err != nil {
				t.Fatal("expected structurally valid preauth fixture", err)
			}
			use, err := ssoOIDCSigninPreAuth(s, preauth, c)
			if tc.change == nil {
				if err != nil || use != (PreAuthUse{Command: binding, Generation: consumed.Generation, Fingerprint: consumed.Fingerprint}) {
					t.Fatal("exact browser and valid original reservation were not retained", err)
				}
			} else if !errors.Is(err, session.ErrInvalidSessionCommand) || use != (PreAuthUse{}) {
				t.Fatal("changed browser or validity was accepted", err)
			}
		})
	}
}
