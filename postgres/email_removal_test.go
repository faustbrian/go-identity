package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestAdministrativeEmailRemovalBindsActorDirectoryWithoutChangingSelfCustody(t *testing.T) {
	i := EmailRemovalIntent{Change: identity.IdentifierChange{TenantID: "tenant", UserID: "target", ID: "address", Action: identity.IdentifierRemove, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3}, ComparisonProfile: "email-v1", Reason: "admin-requested"}
	type wire EmailRemovalIntent
	plain, err := json.Marshal(wire(i))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	fields["Administration"] = json.RawMessage(`{"GlobalAuthorityID":"deployment","GlobalVersion":5,"TenantVersion":7}`)
	plain, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var selected wire
	if err := json.Unmarshal(plain, &selected); err != nil {
		t.Fatal(err)
	}
	frozen, err := EmailRemovalFields(EmailRemovalIntent(selected))
	if err != nil || len(frozen) != 13 {
		t.Fatal("administrative removal omitted original actor directory scope/epochs", err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, f := range frozen {
		seen[f.Name] = f.Value
	}
	if seen["email-removal.actor-global"].Text != "deployment" || seen["email-removal.actor-global-version"].Uint64 != 5 || seen["email-removal.actor-tenant-version"].Uint64 != 7 {
		t.Fatal("actor directory evidence was not fingerprinted")
	}
}

func TestEmailRemovalReplacementFingerprintAndLegacyCustody(t *testing.T) {
	i := EmailRemovalIntent{Change: identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "address", Action: identity.IdentifierRemove, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3}, ComparisonProfile: "email-v1", Reason: "user-requested"}
	type wire EmailRemovalIntent
	old := struct {
		Change                    identity.IdentifierChange
		ComparisonProfile, Reason string
		LeavePrimaryUnassigned    bool
	}{i.Change, i.ComparisonProfile, i.Reason, i.LeavePrimaryUnassigned}
	current, _ := json.Marshal(wire(i))
	legacy, _ := json.Marshal(old)
	if !bytes.Equal(current, legacy) {
		t.Fatal("unselected replacement rewrote original legacy custody")
	}
	i.ReplacementPrimary = identity.IdentifierPrimarySelection{ID: "remaining", ExpectedIdentifierVersion: 5, ExpectedVerificationVersion: 7}
	fields, err := EmailRemovalFields(i)
	if err != nil || len(fields) != 13 {
		t.Fatal("replacement omitted exact fingerprint", err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, f := range fields {
		seen[f.Name] = f.Value
	}
	if seen["email-removal.replacement-identifier"].Text != "remaining" || seen["email-removal.replacement-identifier-version"].Uint64 != 5 || seen["email-removal.replacement-verification-version"].Uint64 != 7 {
		t.Fatal("replacement predecessors not bound")
	}
	for _, mode := range []string{"self", "zero", "conflicting"} {
		bad := i
		switch mode {
		case "self":
			bad.ReplacementPrimary.ID = i.Change.ID
		case "zero":
			bad.ReplacementPrimary.ExpectedVerificationVersion = 0
		case "conflicting":
			bad.LeavePrimaryUnassigned = true
		}
		if _, err := EmailRemovalFields(bad); err == nil {
			t.Fatal("invalid replacement intent admitted", mode)
		}
	}
}

func TestEmailRemovalFieldsBindExactOriginalPredecessors(t *testing.T) {
	i := EmailRemovalIntent{Change: identity.IdentifierChange{
		TenantID: "tenant", UserID: "user", ID: "address", Action: identity.IdentifierRemove,
		ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4,
		ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3,
	}, ComparisonProfile: "email-v1", Reason: "user-requested", LeavePrimaryUnassigned: true}
	fields, err := EmailRemovalFields(i)
	if err != nil || len(fields) != 10 {
		t.Fatal("missing complete removal fingerprint", err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, f := range fields {
		if _, duplicate := seen[f.Name]; duplicate {
			t.Fatal("ambiguous original removal field")
		}
		seen[f.Name] = f.Value
	}
	if seen["email-removal.identifier-version"].Uint64 != 2 || seen["email-removal.verification-version"].Uint64 != 3 || seen["email-removal.reason"].Text != "user-requested" || !seen["email-removal.leave-primary-unassigned"].Bool {
		t.Fatal("original target or disposition lost")
	}
	for name, alter := range map[string]func(*EmailRemovalIntent){
		"attach":       func(i *EmailRemovalIntent) { i.Change.Action = identity.IdentifierAttach },
		"tenant":       func(i *EmailRemovalIntent) { i.Change.TenantID = "" },
		"target":       func(i *EmailRemovalIntent) { i.Change.ID = "" },
		"user-version": func(i *EmailRemovalIntent) { i.Change.ExpectedUserVersion = 0 },
		"authority":    func(i *EmailRemovalIntent) { i.Change.ExpectedAuthorityVersion = ^uint64(0) },
		"identifier":   func(i *EmailRemovalIntent) { i.Change.ExpectedIdentifierVersion = 0 },
		"verification": func(i *EmailRemovalIntent) { i.Change.ExpectedVerificationVersion = 0 },
		"reason":       func(i *EmailRemovalIntent) { i.Reason = "" },
		"profile":      func(i *EmailRemovalIntent) { i.ComparisonProfile = "" },
		"candidate":    func(i *EmailRemovalIntent) { i.Change.CanonicalValue = "untrusted@example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := i
			alter(&bad)
			if _, err := EmailRemovalFields(bad); err == nil {
				t.Fatal("unbounded or substituted removal admitted")
			}
		})
	}
}

func TestEmailRemovalScopeRequiresLockedOriginalApplyInvocation(t *testing.T) {
	for _, mode := range []string{"original", "unprepared", "already-applied", "returned", "foreign-owner", "reconstructed", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			_, command, plan := featurePlanFixture(t)
			spec, _ := command.Feature()
			owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{emailRemovalOperation()}}
			spec.Operation = emailRemovalOperation()
			spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: spec.Operation}
			frozen := &admittedKernelPlan{binding: spec.Binding, feature: feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
			progress := &emailRemovalProgress{intent: EmailRemovalIntent{Change: identity.IdentifierChange{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, ID: identity.IdentifierID(spec.Binding.RecordID), Action: identity.IdentifierRemove}}}
			w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, generation: 3, feature: feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, emailRemoval: progress, execution: &domainExecution{reservation: reservation}}}
			candidate, participant := command, FeatureExecutionContributor(owner)
			switch mode {
			case "unprepared":
				w.state.emailRemoval = nil
			case "already-applied":
				progress.applied = true
			case "returned":
				w.state.featureInvocation = nil
			case "foreign-owner":
				participant = &scopeFeatureParticipant{operations: owner.operations}
			case "reconstructed":
				candidate, err = identity.NewFeatureCommand(spec)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-target":
				progress.intent.Change.ID = "another"
			}
			reader, ok := any(w).(interface {
				EmailRemovalScope(context.Context, FeatureExecutionContributor, identity.Command) (identity.CommandBinding, error)
			})
			if !ok {
				t.Fatal("capability owner cannot fence exact kernel-locked removal")
			}
			b, err := reader.EmailRemovalScope(context.Background(), participant, candidate)
			if mode == "original" {
				if err != nil || b != spec.Binding {
					t.Fatal("original prepared invocation denied", err)
				}
			} else if err == nil || b != (identity.CommandBinding{}) {
				t.Fatal("unprepared/foreign/returned scope escaped")
			}
		})
	}
}

type emailRemovalMapperFixture struct {
	FeatureCommitContributor
	intent EmailRemovalIntent
	domain *EmailRemovalDomain
}

func (p emailRemovalMapperFixture) EmailRemoval(identity.Command) (EmailRemovalIntent, *EmailRemovalDomain, error) {
	return p.intent, p.domain, nil
}

func TestEmailRemovalCommandDeniesSubstitutedCustody(t *testing.T) {
	b := codecBinding()
	op := emailRemovalOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.RecordID, b.ActorID = "address", identity.ActorID(b.UserID)
	i := EmailRemovalIntent{Change: identity.IdentifierChange{
		TenantID: b.TenantID, UserID: b.UserID, ID: "address", Action: identity.IdentifierRemove,
		ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4,
		ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3,
	}, ComparisonProfile: "email-v1", Reason: "user-requested", LeavePrimaryUnassigned: true}
	fields, err := EmailRemovalFields(i)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := freezeIdentifierRemovalCascade(removalCascadeConfig())
	if err != nil {
		t.Fatal(err)
	}
	phase := emailRemovalMapperFixture{intent: i, domain: &EmailRemovalDomain{directory: &EmailAttachmentDomain{
		repository: &Repository{}, comparison: "email-v1",
		reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}},
	}, cascade: policy}}
	plan := CommandPlan{
		Feature:     &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: op},
		SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.removed.v1", BeforeVersion: 2, AfterVersion: 3},
		Audits: []AuditPlan{{Required: true, RetentionClass: "protected"}},
	}
	build := func(binding identity.CommandBinding, fields []identity.FeatureField, session bool) identity.Command {
		t.Helper()
		spec := identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}
		var c identity.Command
		var err error
		if session {
			c, err = identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		} else {
			c, err = identity.NewFeatureCommand(spec)
		}
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	command := build(b, fields, true)
	if _, _, err := emailRemovalCommand(phase, command, plan); err != nil {
		t.Fatal("bound native removal denied", err)
	}
	for index := range fields {
		changed := append([]identity.FeatureField(nil), fields...)
		switch changed[index].Value.Kind {
		case identity.FeatureText:
			changed[index].Value.Text += "other"
		case identity.FeatureUint64:
			changed[index].Value.Uint64++
		case identity.FeatureBool:
			changed[index].Value.Bool = !changed[index].Value.Bool
		}
		if _, _, err := emailRemovalCommand(phase, build(b, changed, true), plan); err == nil {
			t.Fatal("substituted target/predecessor/disposition admitted")
		}
	}
	if _, _, err := emailRemovalCommand(phase, build(b, fields[1:], true), plan); err == nil {
		t.Fatal("missing owned field admitted")
	}
	if _, _, err := emailRemovalCommand(phase, build(b, fields, false), plan); err == nil {
		t.Fatal("sessionless removal admitted")
	}
	for _, binding := range []identity.CommandBinding{
		func() identity.CommandBinding { v := b; v.ActorID = "another"; return v }(),
		func() identity.CommandBinding { v := b; v.ActorKind = authorization.SubjectServiceAccount; return v }(),
	} {
		if _, _, err := emailRemovalCommand(phase, build(binding, fields, true), plan); err == nil {
			t.Fatal("nonself actor admitted")
		}
	}
	changedPlan := plan
	changedPlan.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 2, AfterVersion: 3}
	if _, _, err := emailRemovalCommand(phase, command, changedPlan); err == nil {
		t.Fatal("removal reinterpreted as verification")
	}
	changedPlan = plan
	changedPlan.Audits = []AuditPlan{{Required: false, RetentionClass: "protected"}}
	if _, _, err := emailRemovalCommand(phase, command, changedPlan); err == nil {
		t.Fatal("optional audit substituted for protected mutation")
	}
}
