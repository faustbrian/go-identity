package identity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
)

func privacyRequestFixture() PrivacyExportRequestCommand {
	id := "AQEBAQEBAQEBAQEBAQEBAQ"
	c := PrivacyExportRequestCommand{
		Binding:                 CommandBinding{CommandID: CommandID(id), TenantID: TenantID(id), UserID: UserID(id), ActorID: ActorID(id), ActorKind: authorization.SubjectUser, OperationID: "identity.privacy-export.request", PolicyID: "privacy-policy", PolicyVersion: 1, SchemaID: "identity-privacy-export", SchemaVersion: 1, CorrelationID: id},
		ExpectedIdentityVersion: 3, ExpectedAuthorityVersion: 4, ExpectedPrivacyEpoch: 5,
		SessionID: "fresh-session", SessionVersion: 2, MaximumBytes: 256 << 20, ArtifactTTL: 24 * time.Hour,
	}
	for _, id := range PrivacyExportContributorsV1() {
		c.Projections = append(c.Projections, PrivacyExportProjectionSpecV1{ContributorID: id, ProjectionID: PrivacyExportSubjectJournalV1})
	}
	return c
}

func signPrivacyCommand(t *testing.T, c *PrivacyExportRequestCommand) {
	t.Helper()
	signer, _ := capability.NewHMACSHA256Signer("privacy-key", []byte("0123456789abcdef0123456789abcdef"))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "privacy-key", Verifier: verifier}})
	now := queryClock{}.Now()
	caps, err := capability.NewService(capability.ServiceConfig{Issuer: "https://identity.example", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPrivacyExportProofPayload(PrivacyExportProofSpec{Command: *c, Issuer: "https://identity.example", Audience: "identity-backend", ID: "privacy-proof", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := caps.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	c.Proof, err = caps.Verify(context.Background(), proof, capability.Purpose(c.Binding.OperationID), "identity-backend")
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrivacyCommandFreezesSignedIntent(t *testing.T) {
	c := privacyRequestFixture()
	signPrivacyCommand(t, &c)
	command, err := NewPrivacyExportRequestCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Projections[0].ProjectionID = PrivacyExportStagedSubjectV1
	got, ok := command.RequestPrivacyExport()
	if !ok || got.Projections[0].ProjectionID != PrivacyExportSubjectJournalV1 {
		t.Fatal("input projection alias")
	}
	got.Projections[0].ProjectionID = PrivacyExportStagedSubjectV1
	again, _ := command.RequestPrivacyExport()
	if again.Projections[0].ProjectionID != PrivacyExportSubjectJournalV1 {
		t.Fatal("output projection alias")
	}
	if _, ok := command.CreateUser(); ok {
		t.Fatal("wrong union branch")
	}
	if _, err := command.MarshalJSON(); err == nil {
		t.Fatal("command serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", again), "fresh-session") {
		t.Fatal("command disclosed session")
	}
}

func TestPrivacyCommandRejectsUnsignedSubstitution(t *testing.T) {
	changes := []func(*PrivacyExportRequestCommand){
		func(c *PrivacyExportRequestCommand) { c.MaximumBytes++ },
		func(c *PrivacyExportRequestCommand) { c.ArtifactTTL += time.Second },
		func(c *PrivacyExportRequestCommand) { c.ExpectedIdentityVersion++ },
		func(c *PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion++ },
		func(c *PrivacyExportRequestCommand) { c.ExpectedPrivacyEpoch++ },
		func(c *PrivacyExportRequestCommand) { c.SessionVersion++ },
		func(c *PrivacyExportRequestCommand) { c.SessionID = "other-session" },
		func(c *PrivacyExportRequestCommand) { c.Binding.CorrelationID = "other-correlation" },
		func(c *PrivacyExportRequestCommand) { c.Binding.PolicyID = "other-policy" },
		func(c *PrivacyExportRequestCommand) { c.Binding.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(c *PrivacyExportRequestCommand) { c.Projections[0].ProjectionID = PrivacyExportStagedSubjectV1 },
		func(c *PrivacyExportRequestCommand) { c.Proof = capability.Grant{} },
	}
	for i, change := range changes {
		c := privacyRequestFixture()
		signPrivacyCommand(t, &c)
		change(&c)
		if _, err := NewPrivacyExportRequestCommand(c); err == nil {
			t.Fatalf("unsigned substitution %d", i)
		}
	}
}

func TestPrivacyCommandRejectsInvalidProfilesBeforeSigning(t *testing.T) {
	for i, change := range []func(*PrivacyExportRequestCommand){
		func(c *PrivacyExportRequestCommand) { c.Projections = c.Projections[:22] },
		func(c *PrivacyExportRequestCommand) { c.Projections = append(c.Projections, c.Projections[0]) },
		func(c *PrivacyExportRequestCommand) { c.Projections[1] = c.Projections[0] },
		func(c *PrivacyExportRequestCommand) { c.Projections[0].ProjectionID = "current-table" },
		func(c *PrivacyExportRequestCommand) { c.MaximumBytes = 0 },
		func(c *PrivacyExportRequestCommand) { c.MaximumBytes = 1<<30 + 1 },
		func(c *PrivacyExportRequestCommand) { c.ArtifactTTL = 15*time.Minute - time.Nanosecond },
		func(c *PrivacyExportRequestCommand) { c.ArtifactTTL = 7*24*time.Hour + time.Second },
		func(c *PrivacyExportRequestCommand) { c.ExpectedIdentityVersion = 0 },
		func(c *PrivacyExportRequestCommand) { c.ExpectedPrivacyEpoch = ^uint64(0) },
		func(c *PrivacyExportRequestCommand) { c.Binding.ActorKind = authorization.SubjectAPIKey },
		func(c *PrivacyExportRequestCommand) { c.Binding.ActorID = "other-user" },
	} {
		c := privacyRequestFixture()
		change(&c)
		if _, err := PrivacyExportIntentDigest(c); err == nil {
			t.Fatalf("invalid profile %d", i)
		}
	}
}

func TestPrivacyCommandClosedUnionAndReceiptDenial(t *testing.T) {
	c := privacyRequestFixture()
	signPrivacyCommand(t, &c)
	command, err := NewPrivacyExportRequestCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, mix := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
		func(c *Command) { c.feature = &featureCommandState{} },
	} {
		mixed := command
		mix(&mixed)
		if _, ok := mixed.RequestPrivacyExport(); ok {
			t.Fatal("mixed privacy accepted")
		}
		if _, ok := mixed.CreateUser(); ok {
			t.Fatal("mixed creation accepted")
		}
		if _, ok := mixed.UpdateUser(); ok {
			t.Fatal("mixed update accepted")
		}
		if _, ok := mixed.UpdateProfile(); ok {
			t.Fatal("mixed profile accepted")
		}
		if _, ok := mixed.UserStatus(); ok {
			t.Fatal("mixed status accepted")
		}
		if _, ok := mixed.UnlinkAccount(); ok {
			t.Fatal("mixed unlink accepted")
		}
		if _, ok := mixed.LinkAccount(); ok {
			t.Fatal("mixed link accepted")
		}
		if _, ok := mixed.ChangeIdentifier(); ok {
			t.Fatal("mixed identifier accepted")
		}
		if _, ok := mixed.Feature(); ok {
			t.Fatal("mixed feature accepted")
		}
	}
	if _, ok := (Command{}).RequestPrivacyExport(); ok {
		t.Fatal("zero command accepted")
	}
	if err := (CommandResult{Binding: c.Binding, Outcome: CommitOutcomeCommitted}).Validate(); err == nil {
		t.Fatal("premature export receipt accepted")
	}
}

func TestPrivacyProofIssuanceBoundsAndPolicy(t *testing.T) {
	now := queryClock{}.Now()
	spec := PrivacyExportProofSpec{Command: privacyRequestFixture(), Issuer: "https://identity.example", Audience: "identity-backend", ID: "privacy-proof", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	p, err := BuildPrivacyExportProofPayload(spec)
	if err != nil || p.MaxUses != 1 || p.Bearer || p.Resource != string(spec.Command.Binding.UserID) || p.Operation != "identity.privacy-export.request" || p.NotBefore != now.UTC() || len(p.Caveats) != 1 {
		t.Fatal("wrong exact issuance profile", err)
	}
	for i, change := range []func(*PrivacyExportProofSpec){
		func(s *PrivacyExportProofSpec) { s.ExpiresAt = s.IssuedAt },
		func(s *PrivacyExportProofSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		func(s *PrivacyExportProofSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		func(s *PrivacyExportProofSpec) { s.IssuedAt = time.Time{} },
		func(s *PrivacyExportProofSpec) { s.Audience = "" },
		func(s *PrivacyExportProofSpec) { s.ID = "" },
		func(s *PrivacyExportProofSpec) { s.Issuer = "" },
		func(s *PrivacyExportProofSpec) { signPrivacyCommand(t, &s.Command) },
	} {
		bad := spec
		change(&bad)
		if _, err := BuildPrivacyExportProofPayload(bad); err == nil {
			t.Fatalf("unsafe issuance %d", i)
		}
	}
	for _, bounds := range []struct {
		bytes uint64
		ttl   time.Duration
	}{{1 << 20, 15 * time.Minute}, {1 << 30, 7 * 24 * time.Hour}} {
		c := privacyRequestFixture()
		c.MaximumBytes = bounds.bytes
		c.ArtifactTTL = bounds.ttl
		if _, err := PrivacyExportIntentDigest(c); err != nil {
			t.Fatal("valid policy boundary rejected", err)
		}
	}
}
