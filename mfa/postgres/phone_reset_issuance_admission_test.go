package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// This is the closed structural selection only, not authentication or live Work.
func TestPhoneResetIssuanceRequiresExactOriginalFactorAndFlow(t *testing.T) {
	_, snapshot := phoneRecoveryFixture(t)
	m, _ := snapshot.Metadata()
	f := phoneResetIssuanceSpecFixture(m)
	original := phoneResetIssuanceFlowFixture(t)
	if err := phoneResetIssuanceSpec(f, snapshot, original); err != nil {
		t.Fatal("exact original request rejected", err)
	}
	for name, mutate := range map[string]func(*identity.FeatureCommandSpec){
		"tenant":     func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		"user":       func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "other" },
		"request-id": func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other" },
		"operation": func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.phone.password-reset-complete"
		},
		"factor":         func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Text = "AAAAAAAAAAAAAAAAAAAAAg" },
		"enrollment":     func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Uint64++ },
		"aggregate":      func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Uint64++ },
		"policy":         func(s *identity.FeatureCommandSpec) { s.Binding.PolicyVersion++ },
		"missing-factor": func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := phoneResetIssuanceSpecFixture(m)
			mutate(&changed)
			if phoneResetIssuanceSpec(changed, snapshot, original) == nil {
				t.Fatal("foreign structural request accepted")
			}
		})
	}
	if phoneResetIssuanceSpec(f, TOTPFactorSnapshot{}, original) == nil || phoneResetIssuanceSpec(f, snapshot, session.PreAuthTransaction{}) == nil {
		t.Fatal("zero custody accepted")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if RequirePhoneResetIssuancePreparation(ctx, kernel.Work{}, nil, identity.Command{}, snapshot, original) == nil || RequirePhoneResetIssuance(ctx, kernel.Work{}, nil, identity.Command{}, snapshot, original) == nil {
			t.Fatal("structural snapshot fabricated live admission")
		}
	}
}

func phoneResetIssuanceSpecFixture(m TOTPFactorMetadata) identity.FeatureCommandSpec {
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return identity.FeatureCommandSpec{Operation: op, Binding: identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: m.TenantID, UserID: m.UserID, ActorID: "actor-a", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "request-policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: "AgICAgICAgICAgICAgICAg", CorrelationID: "request-fixture"}, Fields: []identity.FeatureField{
		{Name: "phone.reset.factor-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: m.FactorID}},
		{Name: "phone.reset.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.EnrollmentVersion}},
		{Name: "phone.reset.factor-authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.FactorAuthorityVersion}},
	}}
}

func phoneResetIssuanceFlowFixture(t *testing.T) session.PreAuthTransaction {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	original, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: "AwMDAwMDAwMDAwMDAwMDAw", Intent: session.PreAuthIntent{TenantID: "tenant-a", Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", PolicyID: "request-policy", PolicyVersion: 1, Nonce: [32]byte{1}, IdentifierBinding: [32]byte{2}, Origin: "https://identity.test"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return original
}
