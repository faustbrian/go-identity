package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

type magicLinkIssuancePhase struct{ resetIssuancePhase }

func (*magicLinkIssuancePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}

func TestMagicLinkRecipientFenceIsExplicitAndRejectsUnownedWork(t *testing.T) {
	reader, ok := any(Work{}).(interface {
		RequireMagicLinkRecipient(context.Context, FeatureExecutionContributor, RecipientRecord) error
	})
	if !ok {
		t.Fatal("missing native magic-link recipient fence")
	}
	if err := reader.RequireMagicLinkRecipient(context.Background(), &magicLinkIssuancePhase{}, RecipientRecord{}); err == nil {
		t.Fatal("unowned Work granted recipient selection")
	}
}

func TestMagicLinkIssuanceRequiresInvocationFenceAndExactSignedRecipient(t *testing.T) {
	b, _, plan := magicLinkIssuanceFixture(t)
	r, err := decodeRecipient(RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}, recipientRowFixture(), "19", "23")
	if err != nil {
		t.Fatal(err)
	}
	b.TenantID = r.Query.TenantID
	plan.CapabilityIssuance.MagicLinkRecipientUserID = r.User.ID
	phase := &magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}
	payload := capability.Payload{Subject: string(r.User.ID), Tenant: string(b.TenantID), Resource: "identity.magiclink/identifier", CorrelationID: string(b.CommandID), Caveats: map[string]string{"magiclink.identifier": "identifier", "magiclink.identifier-version": "11", "magiclink.verification-version": "17", "magiclink.identifier-authority-version": "13", "magiclink.user-authority-version": "19", "magiclink.credential-authority-version": "23", "magiclink.canonical-email": r.Query.CanonicalValue}}
	s := &workState{binding: b, featureInvocation: phase}
	if _, err := magicLinkIssuanceSubject(s, plan, payload); err == nil {
		t.Fatal("declaration alone selected recipient")
	}
	s.magicLinkRecipient = &magicLinkRecipientAdmission{owner: phase, recipient: r}
	if subject, err := magicLinkIssuanceSubject(s, plan, payload); err != nil || subject != r.User.ID || s.binding.UserID != "" {
		t.Fatal("native recipient selection lost original anonymous scope", err)
	}
	for name, change := range map[string]func(*capability.Payload){
		"subject":              func(v *capability.Payload) { v.Subject = "foreign" },
		"tenant":               func(v *capability.Payload) { v.Tenant = "foreign" },
		"resource":             func(v *capability.Payload) { v.Resource = "identity.password/identifier" },
		"origin":               func(v *capability.Payload) { v.CorrelationID = "foreign" },
		"identifier":           func(v *capability.Payload) { v.Caveats["magiclink.identifier"] = "foreign" },
		"identifier-version":   func(v *capability.Payload) { v.Caveats["magiclink.identifier-version"] = "12" },
		"verification-version": func(v *capability.Payload) { v.Caveats["magiclink.verification-version"] = "18" },
		"identifier-epoch":     func(v *capability.Payload) { v.Caveats["magiclink.identifier-authority-version"] = "14" },
		"user-epoch":           func(v *capability.Payload) { v.Caveats["magiclink.user-authority-version"] = "20" },
		"credential-epoch":     func(v *capability.Payload) { v.Caveats["magiclink.credential-authority-version"] = "24" },
		"canonical-email":      func(v *capability.Payload) { v.Caveats["magiclink.canonical-email"] = "foreign@example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := payload
			changed.Caveats = make(map[string]string, len(payload.Caveats))
			for k, v := range payload.Caveats {
				changed.Caveats[k] = v
			}
			change(&changed)
			if _, err := magicLinkIssuanceSubject(s, plan, changed); err == nil {
				t.Fatal("foreign signed scope borrowed recipient selection")
			}
		})
	}
	s.featureInvocation = &magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}
	if _, err := magicLinkIssuanceSubject(s, plan, payload); err == nil {
		t.Fatal("foreign invocation borrowed native fence")
	}
}

func magicLinkIssuanceFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	b, original, final := resetIssuanceFixture(t)
	original.Feature.Operation = identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.request", SchemaID: "magic-link-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	original.Feature.Contributor = ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
	original.Contributors = append([]ContributorDescriptor(nil), original.Contributors...)
	original.Contributors[len(original.Contributors)-1] = original.Feature.Contributor
	original.Lifecycle = &LifecyclePlan{EventType: "magic-link.requested.v1"}
	b.OperationID, b.SchemaID = original.Feature.Operation.OperationID, original.Feature.Operation.SchemaID
	final.Feature, final.Lifecycle = original.Feature, original.Lifecycle
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor)
	final.CapabilityIssuance.ResetRecipientUserID = ""
	final.CapabilityIssuance.MagicLinkRecipientUserID = "existing-user"
	final.CapabilityIssuance.Grants[0].Purpose = "identity.magic-link.consume"
	return b, original, final
}

func TestMagicLinkRecipientIssuancePreservesAnonymousScopeAndHistory(t *testing.T) {
	b, original, final := magicLinkIssuanceFixture(t)
	before, err := encodeFeaturePlan(b, [32]byte{1}, original)
	if err != nil {
		t.Fatal(err)
	}
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("magic-link request cannot declare original issuance")
	}
	wire, err := encodeFeaturePlan(b, [32]byte{1}, final)
	if err != nil {
		t.Fatal(err)
	}
	final.Digest = sha256.Sum256(wire)
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, final) {
		t.Fatal("magic-link recipient lost in retained history", err)
	}
	changed := final
	changed.CapabilityIssuance = cloneCapabilityIssuancePlan(final.CapabilityIssuance)
	changed.CapabilityIssuance.MagicLinkRecipientUserID = "foreign-user"
	other, err := encodeFeaturePlan(b, [32]byte{1}, changed)
	if err != nil || bytes.Equal(wire, other) {
		t.Fatal("recipient omitted from original intent", err)
	}
	after, err := encodeFeaturePlan(b, [32]byte{1}, original)
	if err != nil || !bytes.Equal(before, after) || b.UserID != "" {
		t.Fatal("anonymous original scope changed", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated history admitted")
		}
	}
}

func TestMagicLinkRecipientIssuanceDoesNotBroadenOtherProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"registration-target": func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "new-user" },
		"reset-target": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.ResetRecipientUserID = "existing-user"
		},
		"invalid-target": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.MagicLinkRecipientUserID = "\x00"
		},
		"authenticated": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID, b.AnonymousFlowID = "existing-user", "" },
		"foreign-owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.password"
		},
		"foreign-operation": func(b *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.reset-request"
			b.OperationID = p.Feature.Operation.OperationID
		},
		"foreign-purpose": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete"
		},
		"multiple-grants": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := magicLinkIssuanceFixture(t)
			mutate(&b, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("foreign profile admitted to preparation")
			}
			if _, err := encodeFeaturePlan(b, [32]byte{1}, final); err == nil {
				t.Fatal("foreign profile admitted to retained history")
			}
		})
	}
}
