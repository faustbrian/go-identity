package postgres

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func passkeyRegistrationPlanFixture(t testing.TB) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	p := CommandPlan{
		Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, {Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}},
		Audits:       []AuditPlan{{Required: true, SchemaVersion: 1, BindingDigest: [32]byte{2}, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 8192, MaxAggregateBytes: 16384}},
	}
	op := passkeyRegistrationOperation()
	b := codecBinding()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.UserID, b.AnonymousFlowID, b.RecordID = "", "prospective-signup-flow", "prospective-passkey"
	b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "signup-service"
	d := ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	p.Contributors[len(p.Contributors)-1] = d
	p.Feature = &FeatureRegistration{Contributor: d, Operation: op}
	p.SubjectType = "credential"
	p.Lifecycle = &LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}
	p.Audits[0].EventType, p.Audits[0].RetentionClass = "identity.passkey.create_credential", "protected"
	p.PasskeyRegistration = &PasskeyRegistrationPlan{UserID: "prospective-user", CredentialID: identity.CredentialID(b.RecordID), CreationDigest: [32]byte{9}, CreationEventIndex: 1}
	return b, p
}

func TestPasskeyRegistrationPlanRoundTripAndScope(t *testing.T) {
	b, p := passkeyRegistrationPlanFixture(t)
	fp := [32]byte{7}
	encoded, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(b, fp, encoded)
	if err != nil || decoded.PasskeyRegistration == nil || *decoded.PasskeyRegistration != *p.PasskeyRegistration || decoded.Digest != sha256.Sum256(encoded) {
		t.Fatal("original prospective plan not recoverable", err)
	}
	for name, change := range map[string]func(*PasskeyRegistrationPlan){
		"user":       func(r *PasskeyRegistrationPlan) { r.UserID = "other-user" },
		"credential": func(r *PasskeyRegistrationPlan) { r.CredentialID = "other-passkey" },
		"creation":   func(r *PasskeyRegistrationPlan) { r.CreationDigest[0]++ },
		"event":      func(r *PasskeyRegistrationPlan) { r.CreationEventIndex++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := p
			candidate.PasskeyRegistration = clonePasskeyRegistrationPlan(p.PasskeyRegistration)
			change(candidate.PasskeyRegistration)
			changed, err := encodeFeaturePlan(b, fp, candidate)
			if err == nil && bytes.Equal(changed, encoded) {
				t.Fatal("changed creation omitted from plan")
			}
		})
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.PasskeyRegistration.UserID = "" },
		func(p *CommandPlan) { p.PasskeyRegistration.CredentialID = "" },
		func(p *CommandPlan) { p.PasskeyRegistration.CreationDigest = [32]byte{} },
		func(p *CommandPlan) { p.PasskeyRegistration.CreationEventIndex = p.Lifecycle.EventIndex },
		func(p *CommandPlan) { p.MagicLinkRegistration = &MagicLinkRegistrationPlan{} },
		func(p *CommandPlan) { p.MFAContinuation = &MFAContinuationPlan{} },
		func(p *CommandPlan) { p.Feature.Operation.SchemaID = "identity.passkey.register-verify.native-v1" },
		func(p *CommandPlan) { p.Feature.Operation.SubjectRequirement = identity.FeatureSubjectUser },
		func(p *CommandPlan) { p.SubjectType = "user" },
		func(p *CommandPlan) { p.Lifecycle.EventType = "passkey.registered.v1" },
	} {
		bad := p
		bad.PasskeyRegistration = clonePasskeyRegistrationPlan(p.PasskeyRegistration)
		l := *p.Lifecycle
		bad.Lifecycle = &l
		f := *p.Feature
		bad.Feature = &f
		change(&bad)
		if _, err := FeaturePlanDigest(b, fp, bad); err == nil {
			t.Fatal("incomplete or foreign signup plan admitted")
		}
	}
	for i := range encoded {
		if _, err := decodeFeaturePlan(b, fp, encoded[:i]); err == nil {
			t.Fatal("truncated plan decoded", i)
		}
	}
	if _, err := decodeFeaturePlan(b, fp, append(bytes.Clone(encoded), 0)); err == nil {
		t.Fatal("trailing plan bytes accepted")
	}
	foreign := b
	foreign.AnonymousFlowID = "different-flow"
	if _, err := decodeFeaturePlan(foreign, fp, encoded); err == nil {
		t.Fatal("original plan rebound to different browser")
	}
	if _, err := KernelPlanDigest(b, fp, p); err == nil {
		t.Fatal("signup entered legacy kernel-only profile")
	}
	if !preparationFinalDeclaration(b, p, p) {
		t.Fatal("unchanged signup declaration cannot retain generated session custody")
	}
	final := p
	final.PasskeyRegistration = clonePasskeyRegistrationPlan(p.PasskeyRegistration)
	final.PasskeyRegistration.UserID = "other-generated-user"
	if preparationFinalDeclaration(b, p, final) {
		t.Fatal("restoration retargeted prospective account")
	}
	final = p
	final.PasskeyRegistration = nil
	if preparationFinalDeclaration(b, p, final) {
		t.Fatal("restoration removed prospective creation")
	}
}

func FuzzPasskeyRegistrationPlan(f *testing.F) {
	b, p := passkeyRegistrationPlanFixture(f)
	seed, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xa3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65537 {
			t.Skip()
		}
		b, _ := passkeyRegistrationPlanFixture(t)
		p, err := decodeFeaturePlan(b, [32]byte{1}, data)
		if err == nil {
			encoded, err := encodeFeaturePlan(b, [32]byte{1}, p)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("accepted noncanonical signup plan")
			}
		}
	})
}
