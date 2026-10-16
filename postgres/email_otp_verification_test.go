package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestOTPEmailVerificationAuditRetainsSelectorWithoutFalseTransition(t *testing.T) {
	_, spec, _ := otpEmailFixture(t)
	for _, class := range []string{"committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		t.Run(class, func(t *testing.T) {
			r, err := securityMutationAudit(context.Background(), spec.Binding, 2, 3, time.Now().UTC(), class, spec.Binding.OperationID, "identifier", spec.Binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			a := r.Attributes()
			if a["authentication.recovery_path"] != "email_verification_otp" {
				t.Fatal("audit lost canonical original recovery selector")
			}
			want := "2"
			if class == "committed" {
				want = "3"
			}
			if a["aggregate.before_version"] != "2" || a["aggregate.after_version"] != want || !validSecurityAuditRecord(r, "identifier") {
				t.Fatal("audit describes fictitious transition or invalid selector")
			}
			if _, err := securityAuditBindingDigest(spec.Binding, &spec.Operation, "identifier", spec.Binding.RecordID, r); err != nil {
				t.Fatal("selected audit not bound to native command", err)
			}
		})
	}
}

func TestOTPEmailVerificationOnlyAdmitsItsPersistedIdentifierSuccessor(t *testing.T) {
	owner, spec, plan := otpEmailFixture(t)
	b := spec.Binding
	original := CredentialAdmission{Credential: identity.CredentialRef{ID: "password", Kind: identity.CredentialPassword, Version: 3, Owner: "identity/password"}, UserAuthorityVersion: 6, IdentifierAuthorityVersion: 4, CredentialAuthorityVersion: 8}
	progress := managedEmailVerificationProgress{intent: owner.intent, applied: true,
		before:   identity.IdentifierState{User: identity.User{Version: 9}, AuthorityVersion: 4},
		mutation: identity.IdentifierMutation{State: identity.IdentifierState{User: identity.User{Version: 10}, AuthorityVersion: 5}}}
	w := Work{state: &workState{binding: b, feature: plan.Feature, managedEmailVerification: &progress}}
	mapped, err := otpEmailVerificationCredential(w, b, original)
	want := original
	want.IdentifierAuthorityVersion++
	if err != nil || mapped != want {
		t.Fatal("exact successor did not preserve original credential dimensions", err)
	}
	u, err := otpEmailVerificationUser(w, b, UserAuthorityAdmission{UserAuthorityVersion: 6, IdentifierAuthorityVersion: 4, CredentialAuthorityVersion: 8})
	if err != nil || u != (UserAuthorityAdmission{UserAuthorityVersion: 6, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 8}) {
		t.Fatal("exact successor lost original user dimensions", err)
	}
	for name, mutate := range map[string]func(*managedEmailVerificationProgress, *identity.CommandBinding, *CredentialAdmission){
		"wrong-predecessor": func(_ *managedEmailVerificationProgress, _ *identity.CommandBinding, c *CredentialAdmission) {
			c.IdentifierAuthorityVersion++
		},
		"future-epoch": func(p *managedEmailVerificationProgress, _ *identity.CommandBinding, _ *CredentialAdmission) {
			p.mutation.State.AuthorityVersion++
		},
		"future-aggregate": func(p *managedEmailVerificationProgress, _ *identity.CommandBinding, _ *CredentialAdmission) {
			p.mutation.State.User.Version++
		},
		"foreign-record": func(p *managedEmailVerificationProgress, _ *identity.CommandBinding, _ *CredentialAdmission) {
			p.intent.Change.ID = "other"
		},
		"foreign-command": func(_ *managedEmailVerificationProgress, b *identity.CommandBinding, _ *CredentialAdmission) {
			b.CommandID = "AgICAgICAgICAgICAgICAg"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, binding, c := progress, b, original
			mutate(&p, &binding, &c)
			work := Work{state: &workState{binding: b, feature: plan.Feature, managedEmailVerification: &p}}
			if _, err := otpEmailVerificationCredential(work, binding, c); err == nil {
				t.Fatal("arbitrary successor or foreign authority admitted")
			}
		})
	}
	progress.applied = false
	unchanged, err := otpEmailVerificationCredential(w, b, original)
	if err != nil || unchanged != original {
		t.Fatal("unapplied transition renewed authority")
	}
}

// A checked code is not sufficient authority to write an arbitrary feature.
// The native email domain must bind the pending identifier and its versions.
func TestOTPEmailVerificationRejectsUntypedDomain(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-verify", SchemaID: "identity.otp.email-verify.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Operation = op
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	spec.Binding.RecordID = "pending-email"
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal("bounded feature fixture", err)
	}
	plan.Feature = &FeatureRegistration{Operation: op, Contributor: otpDescriptor()}
	plan.SubjectType = "identifier"
	plan.OTP = &OTPAttemptPlan{Mode: OTPConsume}
	owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}
	if err := validateFeatureCommand(owner, command, plan); err == nil {
		t.Fatal("OTP email verification admitted without native pending-address owner")
	}
}

type emailOTPMapper struct {
	scopeFeatureParticipant
	intent ManagedEmailVerificationIntent
	domain *EmailAttachmentDomain
}

func (*emailOTPMapper) Descriptor() ContributorDescriptor {
	return otpDescriptor()
}

func (p *emailOTPMapper) ManagedEmailVerification(identity.Command) (ManagedEmailVerificationIntent, *EmailAttachmentDomain, error) {
	return p.intent, p.domain, nil
}

func (*emailOTPMapper) CheckFeatureCommit(context.Context, Work, identity.Command) error { return nil }

func otpEmailFixture(t *testing.T) (*emailOTPMapper, identity.FeatureCommandSpec, CommandPlan) {
	t.Helper()
	b := codecBinding()
	op := otpEmailVerificationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, 1, "pending-email"
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	i := ManagedEmailVerificationIntent{Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: identity.IdentifierID(b.RecordID), Action: identity.IdentifierVerify, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2}, CanonicalAddress: "pending@example.test", ComparisonProfile: "email-v1", RequestCommandID: "AQEBAQEBAQEBAQEBAQEBAQ"}
	send := identity.CommandID("AgICAgICAgICAgICAgICAg")
	i.RequestCommandID = send
	fields, err := OTPEmailVerificationFields(i, send)
	if err != nil {
		t.Fatal("native pending verification fields", err)
	}
	repository := &Repository{pool: &database.Pool{}, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row { panic("pure mapping performed IO") }}
	domain, err := NewEmailAttachmentDomain(repository, EmailAttachmentDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {7}}})
	if err != nil {
		t.Fatal("native identifier owner", err)
	}
	owner := &emailOTPMapper{intent: i, domain: domain}
	owner.operations = []identity.FeatureOperation{op}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}
	plan := CommandPlan{Feature: &FeatureRegistration{Operation: op, Contributor: owner.Descriptor()}, SubjectType: "identifier", OTP: &OTPAttemptPlan{Mode: OTPConsume, ChallengeID: string(send)}, Lifecycle: &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 2, AfterVersion: 3}}
	return owner, spec, plan
}

func TestOTPEmailVerificationBindsExactPendingTransition(t *testing.T) {
	owner, spec, plan := otpEmailFixture(t)
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFeatureCommand(owner, command, plan); err != nil {
		t.Fatal("exact native OTP pending-address transition rejected", err)
	}
	for _, mutate := range []func(*ManagedEmailVerificationIntent){
		func(i *ManagedEmailVerificationIntent) { i.Change.Action = identity.IdentifierVerifyPrimary },
		func(i *ManagedEmailVerificationIntent) { i.Change.ExpectedIdentifierVersion++ },
		func(i *ManagedEmailVerificationIntent) { i.RequestCommandID = "AQEBAQEBAQEBAQEBAQEBAQ" },
	} {
		changed := owner.intent
		mutate(&changed)
		if _, err := OTPEmailVerificationFields(changed, identity.CommandID(plan.OTP.ChallengeID)); err == nil {
			t.Fatal("unsupported transition or aliased origin admitted")
		}
	}
}

func TestOTPEmailVerificationRejectsSubstitutedScope(t *testing.T) {
	cases := map[string]func(*identity.FeatureCommandSpec, *CommandPlan){
		"check-only":    func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.OTP.Mode = OTPCheck },
		"link-as-code":  func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"missing-code":  func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.OTP = nil },
		"foreign-send":  func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.OTP.ChallengeID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"foreign-actor": func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Binding.ActorID = "other-user" },
		"service-actor": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		"wrong-event": func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.Lifecycle.EventType = "identifier.primary-changed.v1"
		},
		"wrong-version":        func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Lifecycle.BeforeVersion++ },
		"wrong-owner":          func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Feature.Contributor.ContractID = "other" },
		"missing-native-field": func(s *identity.FeatureCommandSpec, _ *CommandPlan) { s.Fields = s.Fields[1:] },
		"unknown-native-field": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "managed-email-verification.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
		},
		"unknown-otp-field": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "email-otp.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
		},
		"wrong-selector": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			for n := range s.Fields {
				if s.Fields[n].Name == "email-otp.recovery-path" {
					s.Fields[n].Value.Text = "emailed_password_reset"
				}
			}
		},
		"missing-selector": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			s.Fields = s.Fields[:len(s.Fields)-2]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			owner, spec, plan := otpEmailFixture(t)
			mutate(&spec, &plan)
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal("test changed command structure, not native authority", err)
			}
			if err := validateFeatureCommand(owner, command, plan); err == nil {
				t.Fatal("substituted OTP email-verification scope admitted")
			}
		})
	}
}
