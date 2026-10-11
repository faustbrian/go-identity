package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

type resetIssuancePhase struct{ operation identity.FeatureOperation }

func (*resetIssuancePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *resetIssuancePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation}
}
func (*resetIssuancePhase) ValidateFeatureCommand(identity.Command, CommandPlan) error {
	return invalidPlan()
}
func (*resetIssuancePhase) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, invalidWork()
}
func (*resetIssuancePhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func resetIssuanceFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, _ := signupPreparationPlanFixture(t)
	feature := *original.Feature
	feature.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	original.Feature = &feature
	original.Lifecycle = &LifecyclePlan{EventType: "password.reset-requested.v1"}
	original.Audits[0].RetentionClass = "protected"
	b.OperationID, b.SchemaID = feature.Operation.OperationID, feature.Operation.SchemaID
	final := original
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete"
	final.CapabilityIssuance.ResetRecipientUserID = "existing-user"
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor)
	return b, original, final
}

func TestResetRecipientIssuanceRequiresNativeFence(t *testing.T) {
	b, _, p := resetIssuanceFixture(t)
	phase := &resetIssuancePhase{operation: p.Feature.Operation}
	r := RecipientRecord{Query: RecipientQuery{TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: "reset@example.test", Eligibility: RecipientVerified}, User: identity.User{TenantID: b.TenantID, ID: "existing-user", Status: identity.StatusActive, Version: 1}, Identifier: identity.Identifier{ID: "email", UserID: "existing-user", Kind: identity.IdentifierEmail, CanonicalValue: "reset@example.test", Version: 7}, UserAuthorityVersion: 2, IdentifierAuthorityVersion: 3, CredentialAuthorityVersion: 4, ObservedAt: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	a := CredentialAdmission{Credential: identity.CredentialRef{TenantID: b.TenantID, UserID: r.User.ID, ID: "password", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 5}, UserAuthorityVersion: 2, IdentifierAuthorityVersion: 3, CredentialAuthorityVersion: 4}
	w := capability.Payload{Subject: string(r.User.ID), Tenant: string(b.TenantID), Resource: "identity.password/password", CorrelationID: string(b.CommandID), Caveats: map[string]string{"password.identifier": "email", "password.identifier-version": "7", "password.credential-version": "5", "password.credential-authority-version": "4", "password.user-authority-version": "2"}}
	s := &workState{binding: b, featureInvocation: phase}
	if _, err := resetIssuanceSubject(s, p, w); err == nil {
		t.Fatal("declaration alone selected recipient")
	}
	s.resetRecipient = &resetRecipientAdmission{owner: phase, recipient: r, credential: a}
	if subject, err := resetIssuanceSubject(s, p, w); err != nil || subject != r.User.ID || s.binding.UserID != "" {
		t.Fatal("native frozen recipient not selected", err)
	}
	for name, change := range map[string]func(*capability.Payload){
		"subject":            func(w *capability.Payload) { w.Subject = "foreign" },
		"resource":           func(w *capability.Payload) { w.Resource = "identity.password/foreign" },
		"origin":             func(w *capability.Payload) { w.CorrelationID = "foreign" },
		"identifier":         func(w *capability.Payload) { w.Caveats["password.identifier"] = "foreign" },
		"identifier-version": func(w *capability.Payload) { w.Caveats["password.identifier-version"] = "8" },
		"credential-version": func(w *capability.Payload) {
			w.Caveats["password.credential-version"] = strconv.FormatUint(a.Credential.Version+1, 10)
		},
		"credential-epoch": func(w *capability.Payload) { w.Caveats["password.credential-authority-version"] = "5" },
		"user-epoch":       func(w *capability.Payload) { w.Caveats["password.user-authority-version"] = "3" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := w
			changed.Caveats = make(map[string]string, len(w.Caveats))
			for key, value := range w.Caveats {
				changed.Caveats[key] = value
			}
			change(&changed)
			if _, err := resetIssuanceSubject(s, p, changed); err == nil {
				t.Fatal("foreign scope selected native recipient")
			}
		})
	}
	s.featureInvocation = &resetIssuancePhase{operation: p.Feature.Operation}
	if _, err := resetIssuanceSubject(s, p, w); err == nil {
		t.Fatal("foreign invocation borrowed native fence")
	}
}

func TestResetRecipientIssuanceOriginalAnonymousScopeAndRoundTrip(t *testing.T) {
	b, original, final := resetIssuanceFixture(t)
	before, err := encodeFeaturePlan(b, [32]byte{1}, original)
	if err != nil {
		t.Fatal(err)
	}
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("reset cannot enlist its generated token")
	}
	wire, err := encodeFeaturePlan(b, [32]byte{1}, final)
	if err != nil {
		t.Fatal(err)
	}
	final.Digest = sha256.Sum256(wire)
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, final) {
		t.Fatal("original reset target lost", err)
	}
	other := final
	other.CapabilityIssuance = cloneCapabilityIssuancePlan(final.CapabilityIssuance)
	other.CapabilityIssuance.ResetRecipientUserID = "another-user"
	changed, err := encodeFeaturePlan(b, [32]byte{1}, other)
	if err != nil || bytes.Equal(wire, changed) {
		t.Fatal("selected recipient not bound into history", err)
	}
	after, err := encodeFeaturePlan(b, [32]byte{1}, original)
	if err != nil || !bytes.Equal(before, after) || b.UserID != "" {
		t.Fatal("original anonymous scope or bytes changed", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated reset history admitted")
		}
	}
}

func TestResetRecipientIssuanceCannotBroadenSignupOrOtherFlows(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"signup-target":         func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "new-user" },
		"invalid-target":        func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.ResetRecipientUserID = "\x00" },
		"authenticated-command": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "existing-user"; b.AnonymousFlowID = "" },
		"foreign-owner":         func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "foreign" },
		"wrong-operation": func(b *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.signup"
			b.OperationID = p.Feature.Operation.OperationID
		},
		"foreign-purpose": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.verify"
		},
		"multiple-grants": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := resetIssuanceFixture(t)
			mutate(&b, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("foreign reset preparation admitted")
			}
			if _, err := encodeFeaturePlan(b, [32]byte{1}, final); err == nil {
				t.Fatal("foreign reset issuance admitted")
			}
		})
	}
}
