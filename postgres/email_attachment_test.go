package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestEmailAttachmentFieldsAndCustody(t *testing.T) {
	intent := EmailAttachmentIntent{Change: identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "pending-email", Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", DisplayValue: "Synthetic@example.test", ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4}, ComparisonProfile: "email-v1"}
	fields, err := EmailAttachmentFields(intent)
	if err != nil || len(fields) != 8 {
		t.Fatal("valid pending attachment", err)
	}
	seen := make(map[string]bool)
	for _, field := range fields {
		if seen[field.Name] || !strings.HasPrefix(field.Name, "email-attachment.") {
			t.Fatal("duplicate or foreign field")
		}
		seen[field.Name] = true
	}
	for _, mutate := range []func(*EmailAttachmentIntent){
		func(i *EmailAttachmentIntent) { i.Change.TenantID = "" },
		func(i *EmailAttachmentIntent) { i.Change.UserID = "" },
		func(i *EmailAttachmentIntent) { i.Change.ID = "" },
		func(i *EmailAttachmentIntent) { i.Change.Action = identity.IdentifierVerify },
		func(i *EmailAttachmentIntent) { i.Change.Kind = identity.IdentifierPhone },
		func(i *EmailAttachmentIntent) { i.Change.CanonicalValue = "" },
		func(i *EmailAttachmentIntent) { i.Change.CanonicalValue = strings.Repeat("a", 255) },
		func(i *EmailAttachmentIntent) { i.Change.DisplayValue = strings.Repeat("a", 255) },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedUserVersion = 0 },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedUserVersion = ^uint64(0) },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedAuthorityVersion = 0 },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedAuthorityVersion = ^uint64(0) },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedIdentifierVersion = 1 },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedVerificationVersion = 1 },
		func(i *EmailAttachmentIntent) { i.ComparisonProfile = "" },
	} {
		changed := intent
		mutate(&changed)
		if _, err := EmailAttachmentFields(changed); err == nil {
			t.Fatal("invalid pending attachment admitted")
		}
	}
	repo := &Repository{pool: &database.Pool{}, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row { panic("constructor performed IO") }}
	c := EmailAttachmentDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {7}}}
	domain, err := NewEmailAttachmentDomain(repo, c)
	if err != nil {
		t.Fatal(err)
	}
	c.RetainedIdentifierKeys[1] = [32]byte{8}
	if domain.reuse.keys[1] != ([32]byte{7}) {
		t.Fatal("caller mutated retained key custody")
	}
	for _, bad := range []EmailAttachmentDomainConfig{{}, {ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 2, RetainedIdentifierKeys: c.RetainedIdentifierKeys}, {ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {}}}} {
		if _, err := NewEmailAttachmentDomain(repo, bad); err == nil {
			t.Fatal("invalid native policy admitted")
		}
	}
	if _, err := NewEmailAttachmentDomain(nil, c); err == nil {
		t.Fatal("missing kernel owner admitted")
	}
	for _, v := range []interface{ MarshalJSON() ([]byte, error) }{intent, c, *domain} {
		if _, err := v.MarshalJSON(); err == nil {
			t.Fatal("private intent or keys serialized")
		}
		if diagnostic := fmt.Sprintf("%#v", v); !strings.Contains(diagnostic, "redacted") {
			t.Fatal("private intent or keys disclosed")
		}
	}
}

func TestEmailResendFieldsRetainExactPendingPredecessors(t *testing.T) {
	intent := EmailAttachmentIntent{Change: identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "pending-email", Action: identity.IdentifierRestartVerification, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}, ExistingCanonicalAddress: "synthetic@example.test", ComparisonProfile: "email-v1"}
	fields, err := EmailAttachmentFields(intent)
	if err != nil || len(fields) != 10 {
		t.Fatal("pending resend has no complete directory binding", err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, field := range fields {
		seen[field.Name] = field.Value
	}
	if seen["email-attachment.canonical-address"].Text != intent.ExistingCanonicalAddress || seen["email-attachment.identifier-version"].Uint64 != 3 || seen["email-attachment.verification-version"].Uint64 != 2 {
		t.Fatal("resend omitted original pending identity or generation")
	}
	for _, mutate := range []func(*EmailAttachmentIntent){
		func(i *EmailAttachmentIntent) { i.ExistingCanonicalAddress = "" },
		func(i *EmailAttachmentIntent) { i.Change.Kind = identity.IdentifierEmail },
		func(i *EmailAttachmentIntent) { i.Change.CanonicalValue = "other@example.test" },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedIdentifierVersion = 0 },
		func(i *EmailAttachmentIntent) { i.Change.ExpectedVerificationVersion = ^uint64(0) },
	} {
		changed := intent
		mutate(&changed)
		if _, err := EmailAttachmentFields(changed); err == nil {
			t.Fatal("resend substituted identity or omitted predecessor")
		}
	}
}

func TestManagedConfirmationBindsSuccessorWithoutWideningSignup(t *testing.T) {
	id, _ := identity.NewCommandID()
	change := identity.IdentifierChange{TenantID: "tenant", UserID: "user", ID: "pending-email", Action: identity.IdentifierVerify, ExpectedUserVersion: 12, ExpectedAuthorityVersion: 7, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 3}
	managed := ManagedEmailVerificationIntent{Change: change, CanonicalAddress: "synthetic@example.test", ComparisonProfile: "email-v1", RequestCommandID: id}
	fields, err := ManagedEmailVerificationFields(managed)
	if err != nil || len(fields) != 10 {
		t.Fatal("managed successor cannot confirm", err)
	}
	versions := map[string]uint64{}
	for _, f := range fields {
		versions[f.Name] = f.Value.Uint64
	}
	if versions["managed-email-verification.identifier-version"] != 3 || versions["managed-email-verification.verification-version"] != 3 {
		t.Fatal("managed fields discarded original successors")
	}
	if _, err := EmailVerificationFields(EmailVerificationIntent{Change: change, CanonicalAddress: managed.CanonicalAddress, ComparisonProfile: managed.ComparisonProfile, RegistrationCommandID: id}); err == nil {
		t.Fatal("registration borrowed management successor profile")
	}
	for _, version := range []uint64{0, ^uint64(0)} {
		bad := managed
		bad.Change.ExpectedIdentifierVersion = version
		if _, err := ManagedEmailVerificationFields(bad); err == nil {
			t.Fatal("unbounded successor admitted")
		}
	}
}

type emailAttachmentMapperFixture struct {
	FeatureCommitContributor
	intent EmailAttachmentIntent
	domain *EmailAttachmentDomain
}

func (p emailAttachmentMapperFixture) EmailAttachment(identity.Command) (EmailAttachmentIntent, *EmailAttachmentDomain, error) {
	return p.intent, p.domain, nil
}

func TestEmailAttachmentCommandDeniesSubstitutedNativeInput(t *testing.T) {
	b := codecBinding()
	b.OperationID = "identity.email.verification-send"
	b.SchemaID = b.OperationID + ".native-v1"
	b.RecordID = "pending-email"
	b.ActorID = identity.ActorID(b.UserID)
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	intent := EmailAttachmentIntent{Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: identity.IdentifierID(b.RecordID), Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4}, ComparisonProfile: "email-v1"}
	fields, err := EmailAttachmentFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	mapper := emailAttachmentMapperFixture{intent: intent, domain: &EmailAttachmentDomain{repository: &Repository{}, comparison: "email-v1", reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}}}}
	plan := CommandPlan{Feature: &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: op}, SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.attached.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []AuditPlan{{RetentionClass: "protected"}}}
	build := func(b identity.CommandBinding, fields []identity.FeatureField) identity.Command {
		t.Helper()
		command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := build(b, fields)
	if _, _, err := emailAttachmentCommand(mapper, command, plan); err != nil {
		t.Fatal("valid native fields including absent display denied", err)
	}
	for index := range fields {
		changed := append([]identity.FeatureField(nil), fields...)
		if changed[index].Value.Kind == identity.FeatureText {
			changed[index].Value.Text += "other"
		} else {
			changed[index].Value.Uint64++
		}
		if _, _, err := emailAttachmentCommand(mapper, build(b, changed), plan); err == nil {
			t.Fatal("substituted kernel field accepted")
		}
	}
	if _, _, err := emailAttachmentCommand(mapper, build(b, fields[1:]), plan); err == nil {
		t.Fatal("missing owned field accepted")
	}
	changed := append(append([]identity.FeatureField(nil), fields...), identity.FeatureField{Name: "email-attachment.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unsupported"}})
	if _, _, err := emailAttachmentCommand(mapper, build(b, changed), plan); err == nil {
		t.Fatal("unrecognized owned field accepted")
	}
	foreign := b
	foreign.ActorID = "other-human"
	if _, _, err := emailAttachmentCommand(mapper, build(foreign, fields), plan); err == nil {
		t.Fatal("another actor became self authority")
	}
	foreign = b
	foreign.ActorKind = authorization.SubjectServiceAccount
	if _, _, err := emailAttachmentCommand(mapper, build(foreign, fields), plan); err == nil {
		t.Fatal("service actor became self authority")
	}
	plain, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emailAttachmentCommand(mapper, plain, plan); err == nil {
		t.Fatal("projection fabricated original session custody")
	}
	foreignPlan := plan
	foreignPlan.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 0, AfterVersion: 1}
	if _, _, err := emailAttachmentCommand(mapper, command, foreignPlan); err == nil {
		t.Fatal("attachment became verification")
	}
}
