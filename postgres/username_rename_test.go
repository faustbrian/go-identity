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

func usernameRenameIntentFixture() UsernameRenameIntent {
	return UsernameRenameIntent{Change: identity.IdentifierChange{
		TenantID: "tenant", UserID: "user", ID: "username", Action: identity.IdentifierRename,
		Kind: identity.IdentifierUsername, CanonicalValue: "successor", DisplayValue: "Successor",
		NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1,
		ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4,
		ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2,
	}}
}

type usernameRenameMapperFixture struct {
	FeatureCommitContributor
	intent UsernameRenameIntent
	domain *UsernameRenameDomain
}

func (p usernameRenameMapperFixture) UsernameRename(identity.Command) (UsernameRenameIntent, *UsernameRenameDomain, error) {
	return p.intent, p.domain, nil
}

func TestUsernameRenameCommandRequiresExactSelfAndIntent(t *testing.T) {
	b := codecBinding()
	op := usernameRenameOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.RecordID, b.ActorID = "username", identity.ActorID(b.UserID)
	i := usernameRenameIntentFixture()
	i.Change.TenantID, i.Change.UserID = b.TenantID, b.UserID
	fields, err := UsernameRenameFields(i)
	if err != nil {
		t.Fatal(err)
	}
	mapper := usernameRenameMapperFixture{intent: i, domain: &UsernameRenameDomain{repository: &Repository{}, profile: i.Change.NormalizationProfile, version: 1, reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}}}}
	plan := CommandPlan{Feature: &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}, Operation: op}, SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.updated.v1", BeforeVersion: 3, AfterVersion: 4}, Audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}}
	build := func(b identity.CommandBinding, fields []identity.FeatureField) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	command := build(b, fields)
	if _, _, err := usernameRenameCommand(mapper, command, plan); err != nil {
		t.Fatal("valid native mapping denied", err)
	}
	for index := range fields {
		changed := append([]identity.FeatureField(nil), fields...)
		if changed[index].Value.Kind == identity.FeatureText {
			changed[index].Value.Text += "other"
		} else {
			changed[index].Value.Uint64++
		}
		if _, _, err := usernameRenameCommand(mapper, build(b, changed), plan); err == nil {
			t.Fatal("substituted owned input admitted")
		}
	}
	for _, changed := range [][]identity.FeatureField{fields[1:], append(append([]identity.FeatureField(nil), fields...), identity.FeatureField{Name: "username-rename.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unsupported"}})} {
		if _, _, err := usernameRenameCommand(mapper, build(b, changed), plan); err == nil {
			t.Fatal("missing or unknown owned input admitted")
		}
	}
	foreign := b
	foreign.ActorID = "other-human"
	if _, _, err := usernameRenameCommand(mapper, build(foreign, fields), plan); err == nil {
		t.Fatal("foreign actor admitted")
	}
	foreign = b
	foreign.ActorKind = authorization.SubjectServiceAccount
	if _, _, err := usernameRenameCommand(mapper, build(foreign, fields), plan); err == nil {
		t.Fatal("service became self authority")
	}
	plain, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := usernameRenameCommand(mapper, plain, plan); err == nil {
		t.Fatal("projection replaced session custody")
	}
	bad := plan
	bad.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 3, AfterVersion: 4}
	if _, _, err := usernameRenameCommand(mapper, command, bad); err == nil {
		t.Fatal("rename became verification")
	}
}

func TestUsernameRenameFieldsBindExactPredecessorsAndProfile(t *testing.T) {
	intent := usernameRenameIntentFixture()
	fields, err := UsernameRenameFields(intent)
	if err != nil || len(fields) != 11 {
		t.Fatal("rename lacks complete canonical intent", err)
	}
	seen := make(map[string]identity.FeatureValue)
	for _, field := range fields {
		if _, duplicate := seen[field.Name]; duplicate || !strings.HasPrefix(field.Name, "username-rename.") {
			t.Fatal("duplicate or foreign intent")
		}
		seen[field.Name] = field.Value
	}
	if seen["username-rename.normalization-profile"].Text != intent.Change.NormalizationProfile || seen["username-rename.normalization-version"].Uint64 != 1 || seen["username-rename.verification-version"].Uint64 != 2 {
		t.Fatal("comparison or verification predecessor missing")
	}
	for _, mutate := range []func(*identity.IdentifierChange){
		func(c *identity.IdentifierChange) { c.Action = identity.IdentifierReplace },
		func(c *identity.IdentifierChange) { c.Kind = identity.IdentifierEmail },
		func(c *identity.IdentifierChange) { c.NormalizationProfile = "" },
		func(c *identity.IdentifierChange) { c.NormalizationVersion = 0 },
		func(c *identity.IdentifierChange) { c.ExpectedUserVersion = 0 },
		func(c *identity.IdentifierChange) { c.ExpectedUserVersion = ^uint64(0) },
		func(c *identity.IdentifierChange) { c.ExpectedAuthorityVersion = ^uint64(0) },
		func(c *identity.IdentifierChange) { c.ExpectedIdentifierVersion = 0 },
		func(c *identity.IdentifierChange) { c.ExpectedVerificationVersion = ^uint64(0) },
	} {
		changed := intent
		mutate(&changed.Change)
		if _, err := UsernameRenameFields(changed); err == nil {
			t.Fatal("invalid native rename admitted")
		}
	}
}

func TestUsernameRenameDomainFreezesPolicyWithoutIO(t *testing.T) {
	r := &Repository{pool: &database.Pool{}, read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row { panic("constructor performed IO") }}
	c := UsernameRenameDomainConfig{NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {7}}, ReuseCooldown: 30 * 24 * time.Hour}
	domain, err := NewUsernameRenameDomain(r, c)
	if err != nil {
		t.Fatal(err)
	}
	c.RetainedIdentifierKeys[1] = [32]byte{9}
	if domain.reuse.keys[1] != ([32]byte{7}) || domain.reuse.reuseCooldown != c.ReuseCooldown {
		t.Fatal("native rename policy aliases caller input")
	}
	for _, mutate := range []func(*UsernameRenameDomainConfig){
		func(c *UsernameRenameDomainConfig) { c.NormalizationProfile = "" },
		func(c *UsernameRenameDomainConfig) { c.NormalizationVersion = 0 },
		func(c *UsernameRenameDomainConfig) { c.ReuseCooldown = -time.Second },
		func(c *UsernameRenameDomainConfig) { c.ReuseCooldown = time.Nanosecond },
		func(c *UsernameRenameDomainConfig) { c.CurrentIdentifierKeyVersion = 2 },
	} {
		changed := c
		mutate(&changed)
		if _, err := NewUsernameRenameDomain(r, changed); err == nil {
			t.Fatal("invalid rename domain admitted")
		}
	}
	if _, err := NewUsernameRenameDomain(nil, c); err == nil {
		t.Fatal("missing directory owner admitted")
	}
	for _, v := range []interface{ MarshalJSON() ([]byte, error) }{usernameRenameIntentFixture(), c, *domain} {
		if _, err := v.MarshalJSON(); err == nil || !strings.Contains(fmt.Sprintf("%#v", v), "redacted") {
			t.Fatal("correlated intent or keys implicitly disclosed")
		}
	}
}

func TestUsernameAvailabilityRejectsUnownedPrimaryAndScope(t *testing.T) {
	q := UsernameQuery{TenantID: "tenant", CanonicalValue: "candidate", NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
	for _, domain := range []*UsernameRenameDomain{nil, {}, {repository: &Repository{}, profile: q.NormalizationProfile, version: 1}} {
		if available, err := domain.UsernameAvailable(context.Background(), q); err == nil || available {
			t.Fatal("missing native primary or reuse custody promised availability")
		}
	}
}
