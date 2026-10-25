package mfapostgres

import (
	"context"
	"errors"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Trusted record projection only; no factor verification or session issuance.
func completedPasskeyFactorSession(t testing.TB, factorID string) session.Session {
	t.Helper()
	record := passkeyFactorSession(t)
	s, _ := record.Bindings()
	s.Authentication.Proof.Purpose = session.PasskeyMFAPrimaryPurpose
	s.Authentication.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAQ"
	remember, _ := s.Remember.Bindings()
	m, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{
		CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: "AAAAAAAAAAAAAAAAAAAAAQ",
		ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1},
		Method: "totp", FactorID: factorID, EnrollmentVersion: 1,
		FactorAuthorityVersion: 1, ContinuationVersion: 1, Remember: remember,
		VerifiedAt: s.IssuedAt, ValidUntil: s.Authentication.Proof.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err = session.NewSessionWithPasskeyMFA(s, m)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestMFAPasskeySessionFactorAuthorityRequiresOriginalInvocation(t *testing.T) {
	record := completedPasskeyFactorSession(t, "BgYGBgYGBgYGBgYGBgYGBg")
	if err := RequireMFAPasskeySessionFactors(nil, kernel.Work{}, nil, record); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequireMFAPasskeySessionFactors(ctx, kernel.Work{}, nil, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	for _, candidate := range []session.Session{{}, passkeyFactorSession(t), record} {
		if err := RequireMFAPasskeySessionFactors(t.Context(), kernel.Work{}, nil, candidate); err == nil {
			t.Fatal("unregistered Work or wrong completed profile admitted")
		}
	}
	if err := RequirePasskeySessionFactors(t.Context(), kernel.Work{}, nil, record); err == nil {
		t.Fatal("completed MFA entered known-empty fence")
	}
}
