package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type phoneEnrollmentMapperFixture struct {
	FeatureCommitContributor
	intent PhoneEnrollmentIntent
	domain *PhoneEnrollmentDomain
}

func (p phoneEnrollmentMapperFixture) PhoneEnrollment(identity.Command) (PhoneEnrollmentIntent, *PhoneEnrollmentDomain, error) {
	return p.intent, p.domain, nil
}

func TestPhoneEnrollmentResultRequiresAppliedKernelMutation(t *testing.T) {
	op := phoneEnrollmentOperation()
	feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
	receipt := &identity.FeatureReceipt{Operation: op, AfterVersion: 1}
	plan := &admittedKernelPlan{feature: feature, lifecycle: &LifecyclePlan{EventType: "identifier.attached.v1", AfterVersion: 1}}
	w := Work{state: &workState{feature: feature, featureReceipt: receipt, execution: &domainExecution{reservation: &reservationState{plan: plan}}}}
	result := identity.CommandResult{Feature: receipt}
	if matchesDomainResult(w, result) {
		t.Fatal("native receipt fabricated a pending phone without kernel apply")
	}
	w.state.phoneEnrollment = &phoneEnrollmentProgress{}
	if matchesDomainResult(w, result) {
		t.Fatal("unapplied candidate passed the commit boundary")
	}
	w.state.phoneEnrollment.applied = true
	if !matchesDomainResult(w, result) {
		t.Fatal("actual pending phone could not commit its original receipt")
	}
	wrong := *receipt
	wrong.AfterVersion++
	result.Feature = &wrong
	if matchesDomainResult(w, result) {
		t.Fatal("phone receipt changed its applied transition")
	}
}

func TestPhoneEnrollmentCandidateRejectsZeroWork(t *testing.T) {
	if err := (Work{}).RequirePhoneEnrollmentCandidate(context.Background(), nil, identity.Command{}, phoneEnrollmentIntent()); err == nil {
		t.Fatal("number intent fabricated a protected candidate")
	}
}

func TestPhoneEnrollmentCommandConservesOriginalCandidateAndSelfSession(t *testing.T) {
	b := codecBinding()
	b.OperationID, b.SchemaID = "identity.phone.send-verification", "identity.phone.send-verification.native-v1"
	b.RecordID, b.ActorID = "pending-phone", identity.ActorID(b.UserID)
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: b.OperationID, SchemaID: b.SchemaID,
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	intent := phoneEnrollmentIntent()
	intent.Change.TenantID, intent.Change.UserID, intent.Change.ID = b.TenantID, b.UserID, identity.IdentifierID(b.RecordID)
	fields, err := PhoneEnrollmentFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	mapper := phoneEnrollmentMapperFixture{intent: intent, domain: &PhoneEnrollmentDomain{
		repository: &Repository{}, profile: intent.Change.NormalizationProfile, version: 1,
		reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}, reuseCooldown: 30 * 24 * time.Hour},
	}}
	plan := CommandPlan{Feature: &FeatureRegistration{Contributor: ContributorDescriptor{
		Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op},
		SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.attached.v1", AfterVersion: 1},
		Audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}}
	build := func(binding identity.CommandBinding, f []identity.FeatureField, session bool) identity.Command {
		t.Helper()
		spec := identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: f}
		var c identity.Command
		var e error
		if session {
			c, e = identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		} else {
			c, e = identity.NewFeatureCommand(spec)
		}
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	c := build(b, fields, true)
	if got, domain, err := phoneEnrollmentCommand(mapper, c, plan); err != nil || got != intent || domain != mapper.domain {
		t.Fatal("valid pending phone lost original custody", err)
	}
	for index := range fields {
		changed := append([]identity.FeatureField(nil), fields...)
		if changed[index].Value.Kind == identity.FeatureText {
			changed[index].Value.Text += "other"
		} else {
			changed[index].Value.Uint64++
		}
		if _, _, err := phoneEnrollmentCommand(mapper, build(b, changed, true), plan); err == nil {
			t.Fatal("substituted candidate accepted")
		}
	}
	if _, _, err := phoneEnrollmentCommand(mapper, build(b, fields[1:], true), plan); err == nil {
		t.Fatal("missing phone binding accepted")
	}
	unknown := append(append([]identity.FeatureField(nil), fields...), identity.FeatureField{Name: "phone-enrollment.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "other"}})
	if _, _, err := phoneEnrollmentCommand(mapper, build(b, unknown, true), plan); err == nil {
		t.Fatal("unknown phone field accepted")
	}
	if _, _, err := phoneEnrollmentCommand(mapper, build(b, fields, false), plan); err == nil {
		t.Fatal("caller fields fabricated original session")
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.ActorID = "other-human" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		func(b *identity.CommandBinding) { b.UserID = "other-user" },
		func(b *identity.CommandBinding) { b.TenantID = "other-tenant" },
		func(b *identity.CommandBinding) { b.RecordID = "other-phone" },
	} {
		foreign := b
		mutate(&foreign)
		if _, _, err := phoneEnrollmentCommand(mapper, build(foreign, fields, true), plan); err == nil {
			t.Fatal("foreign self-session binding accepted")
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Feature = nil },
		func(p *CommandPlan) {
			p.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: op}
		},
		func(p *CommandPlan) { p.SubjectType = "user" },
		func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", AfterVersion: 1}
		},
		func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "identifier.attached.v1", BeforeVersion: 1, AfterVersion: 2}
		},
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		func(p *CommandPlan) { p.Audits = []AuditPlan{{Required: false, RetentionClass: "protected"}} },
		func(p *CommandPlan) { p.Audits = []AuditPlan{{Required: true, RetentionClass: "standard"}} },
		func(p *CommandPlan) { p.Audits = nil },
	} {
		foreign := plan
		mutate(&foreign)
		if _, _, err := phoneEnrollmentCommand(mapper, c, foreign); err == nil {
			t.Fatal("foreign attachment effects accepted")
		}
	}
	foreign := mapper
	copyDomain := *mapper.domain
	copyDomain.version++
	foreign.domain = &copyDomain
	if _, _, err := phoneEnrollmentCommand(foreign, c, plan); err == nil {
		t.Fatal("metadata profile was renewed")
	}
}

func phoneEnrollmentIntent() PhoneEnrollmentIntent {
	return PhoneEnrollmentIntent{Change: identity.IdentifierChange{
		TenantID: "tenant", UserID: "user", ID: "pending-phone",
		Action: identity.IdentifierAttach, Kind: identity.IdentifierPhone,
		CanonicalValue: "+358401234567", DisplayValue: "0401234567",
		NormalizationProfile: "identity.phone.e164-ascii-v1.metadata-v9.0.40",
		NormalizationVersion: 1, ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4,
	}}
}

func TestPhoneEnrollmentFieldsFreezeOnlyPhoneCandidate(t *testing.T) {
	i := phoneEnrollmentIntent()
	fields, err := PhoneEnrollmentFields(i)
	if err != nil || len(fields) != 9 {
		t.Fatal("phone candidate lacks complete kernel input", err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, f := range fields {
		if _, duplicate := seen[f.Name]; duplicate || !strings.HasPrefix(f.Name, "phone-enrollment.") {
			t.Fatal("duplicate or foreign enrollment field")
		}
		seen[f.Name] = f.Value
	}
	if seen["phone-enrollment.canonical-number"].Text != i.Change.CanonicalValue ||
		seen["phone-enrollment.normalization-profile"].Text != i.Change.NormalizationProfile ||
		seen["phone-enrollment.normalization-version"].Uint64 != 1 ||
		seen["phone-enrollment.user-version"].Uint64 != 9 ||
		seen["phone-enrollment.authority-version"].Uint64 != 4 {
		t.Fatal("phone candidate changed frozen identity or predecessor")
	}
	for name, mutate := range map[string]func(*PhoneEnrollmentIntent){
		"foreign-kind":     func(i *PhoneEnrollmentIntent) { i.Change.Kind = identity.IdentifierEmail },
		"foreign-action":   func(i *PhoneEnrollmentIntent) { i.Change.Action = identity.IdentifierVerify },
		"missing-tenant":   func(i *PhoneEnrollmentIntent) { i.Change.TenantID = "" },
		"missing-user":     func(i *PhoneEnrollmentIntent) { i.Change.UserID = "" },
		"missing-record":   func(i *PhoneEnrollmentIntent) { i.Change.ID = "" },
		"missing-profile":  func(i *PhoneEnrollmentIntent) { i.Change.NormalizationProfile = "" },
		"missing-version":  func(i *PhoneEnrollmentIntent) { i.Change.NormalizationVersion = 0 },
		"national-number":  func(i *PhoneEnrollmentIntent) { i.Change.CanonicalValue = "0401234567" },
		"zero-country":     func(i *PhoneEnrollmentIntent) { i.Change.CanonicalValue = "+0401234567" },
		"punctuation":      func(i *PhoneEnrollmentIntent) { i.Change.CanonicalValue = "+358 401234567" },
		"unicode":          func(i *PhoneEnrollmentIntent) { i.Change.CanonicalValue = "+３５８４０１２３４５６７" },
		"oversized-number": func(i *PhoneEnrollmentIntent) { i.Change.CanonicalValue = "+1234567890123456" },
		"oversized-display": func(i *PhoneEnrollmentIntent) {
			i.Change.DisplayValue = strings.Repeat("1", 129)
		},
		"existing-record": func(i *PhoneEnrollmentIntent) { i.Change.ExpectedIdentifierVersion = 1 },
		"existing-proof":  func(i *PhoneEnrollmentIntent) { i.Change.ExpectedVerificationVersion = 1 },
		"user-overflow":   func(i *PhoneEnrollmentIntent) { i.Change.ExpectedUserVersion = ^uint64(0) },
		"epoch-overflow":  func(i *PhoneEnrollmentIntent) { i.Change.ExpectedAuthorityVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := i
			mutate(&changed)
			if _, err := PhoneEnrollmentFields(changed); err == nil {
				t.Fatal("invalid phone enrollment candidate accepted")
			}
		})
	}
}

func TestPhoneEnrollmentDomainCopiesExplicitPolicyWithoutIO(t *testing.T) {
	repo := &Repository{pool: &database.Pool{}, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row {
		panic("constructor performed IO")
	}}
	c := PhoneEnrollmentDomainConfig{NormalizationProfile: phoneEnrollmentIntent().Change.NormalizationProfile,
		NormalizationVersion: 1, CurrentIdentifierKeyVersion: 1,
		RetainedIdentifierKeys: map[uint32][32]byte{1: {7}}, ReuseCooldown: 30 * 24 * time.Hour}
	d, err := NewPhoneEnrollmentDomain(repo, c)
	if err != nil {
		t.Fatal("valid phone storage policy denied", err)
	}
	c.RetainedIdentifierKeys[1] = [32]byte{8}
	if d.reuse.keys[1] != ([32]byte{7}) || d.reuse.reuseCooldown != 30*24*time.Hour {
		t.Fatal("phone policy borrowed caller keys or lost recycling policy")
	}
	for _, mutate := range []func(*PhoneEnrollmentDomainConfig){
		func(c *PhoneEnrollmentDomainConfig) { c.NormalizationProfile = "" },
		func(c *PhoneEnrollmentDomainConfig) { c.NormalizationVersion = 0 },
		func(c *PhoneEnrollmentDomainConfig) { c.NormalizationProfile = "unsupported profile" },
		func(c *PhoneEnrollmentDomainConfig) { c.CurrentIdentifierKeyVersion = 2 },
		func(c *PhoneEnrollmentDomainConfig) { c.RetainedIdentifierKeys = nil },
		func(c *PhoneEnrollmentDomainConfig) { c.ReuseCooldown = 0 },
		func(c *PhoneEnrollmentDomainConfig) { c.ReuseCooldown = 366 * 24 * time.Hour },
	} {
		bad := c
		mutate(&bad)
		if _, err := NewPhoneEnrollmentDomain(repo, bad); err == nil {
			t.Fatal("invalid phone storage policy accepted")
		}
	}
	if _, err := NewPhoneEnrollmentDomain(nil, c); err == nil {
		t.Fatal("missing directory owner accepted")
	}
	for _, value := range []any{phoneEnrollmentIntent(), c, *d} {
		if out := fmt.Sprintf("%#v", value); !strings.Contains(out, "redacted") || strings.Contains(out, "+358") {
			t.Fatal("phone storage custody leaked through diagnostics")
		}
		if _, err := value.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON(); err == nil {
			t.Fatal("phone storage custody implicitly serialized")
		}
	}
}
