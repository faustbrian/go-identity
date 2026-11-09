package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type neutralLinker struct{}

func (*neutralLinker) ApplyLink(context.Context, LinkCommand) (LinkResult, error) {
	return LinkResult{}, ForbiddenError{}
}

func TestLinkTransactionIntentRetainsProofPolicyAndContributorOwnership(t *testing.T) {
	original := linkCounterCommand(t)
	before, _ := original.LinkAccount()
	contributors := []LinkContributor{{Owner: "identity/postgres", ContractID: "identity.directory", Version: 1}, {Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}}
	command, err := NewLinkCommand(original, LinkPreserveExistingAccess, contributors)
	if err != nil {
		t.Fatal(err)
	}
	retained, ok := command.Command()
	after, valid := retained.LinkAccount()
	if !ok || !valid || !reflect.DeepEqual(before, after) || command.FinalAccessPolicy() != LinkPreserveExistingAccess {
		t.Fatal("neutral intent changed signed link or final-access policy")
	}
	contributors[0].Owner = "foreign"
	projected := command.Contributors()
	projected[0].Owner = "another"
	if command.Contributors()[0].Owner != "identity/postgres" {
		t.Fatal("caller rewrote the selected contributor set")
	}
	linker := &neutralLinker{}
	participants, err := NewLinkParticipants(linker, command.Contributors())
	if err != nil || participants.Linker() != linker || !reflect.DeepEqual(participants.Contributors(), command.Contributors()) {
		t.Fatal("participant selection lost its actual authoritative linker", err)
	}
	for _, value := range []any{command, participants} {
		if wire, err := json.Marshal(value); err == nil || len(wire) != 0 {
			t.Fatal("link authority serialized")
		}
		if text := fmt.Sprintf("%#v", value); strings.Contains(text, string(before.Binding.UserID)) || strings.Contains(text, "subject-b") {
			t.Fatal("private link intent leaked")
		}
	}
}

func TestLinkTransactionRejectsMissingPolicyOwnersAndTypedNil(t *testing.T) {
	original := linkCounterCommand(t)
	owners := []LinkContributor{{Owner: "identity/postgres", ContractID: "identity.directory", Version: 1}}
	if _, err := NewLinkCommand(Command{}, LinkPreserveExistingAccess, owners); err == nil {
		t.Fatal("empty link intent accepted")
	}
	if _, err := NewLinkCommand(original, 0, owners); err == nil {
		t.Fatal("unspecified final-access policy accepted")
	}
	if _, err := NewLinkCommand(original, LinkPreserveExistingAccess, nil); err == nil {
		t.Fatal("missing contributor set accepted")
	}
	if _, err := NewLinkCommand(original, LinkPreserveExistingAccess, append(owners, owners...)); err == nil {
		t.Fatal("duplicate contributor accepted")
	}
	var absent *neutralLinker
	if _, err := NewLinkParticipants(absent, owners); err == nil {
		t.Fatal("typed-nil linker accepted")
	}
	if _, ok := (LinkCommand{}).Command(); ok {
		t.Fatal("zero command exposed usable intent")
	}
}

func TestLinkTransactionPreservesProtectedCounterIntent(t *testing.T) {
	bare := linkCounterCommand(t)
	before, _ := bare.LinkAccount()
	counters := AccountLinkCounterContext{Network: "192.0.2.17", PreparedAt: queryClock{}.Now(), KeyVersions: []uint32{9, 7}}
	counted, err := NewAccountLinkCounterCommand(bare, counters)
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewLinkCommand(counted, LinkPreserveExistingAccess, []LinkContributor{{Owner: "identity/postgres", ContractID: "identity.directory", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	retained, valid := command.Command()
	after, got, countedOK := retained.AccountLinkCounterCommand()
	if !valid || !countedOK || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(counters, got) || after.Proof.EnvelopeDigest() != before.Proof.EnvelopeDigest() || after.SessionID != before.SessionID || after.SessionVersion != before.SessionVersion {
		t.Fatal("neutral link intent dropped protected counters, original proof or browser binding")
	}
	counters.KeyVersions[0], got.KeyVersions[1] = 100, 200
	_, preserved, _ := retained.AccountLinkCounterCommand()
	if !reflect.DeepEqual(preserved.KeyVersions, []uint32{9, 7}) {
		t.Fatal("protected neutral intent aliases caller or projected counter keys")
	}
	if _, ok := retained.LinkAccount(); ok {
		t.Fatal("neutral intent re-enabled a legacy executor that omits protected counters")
	}
}

func TestLinkTransactionApplicationNeverClaimsCommitment(t *testing.T) {
	original := linkCounterCommand(t)
	spec, _ := original.LinkAccount()
	b, change := spec.Binding, spec.Change
	application := LinkApplication{Binding: b, User: User{TenantID: b.TenantID, ID: b.UserID, Status: StatusActive, Version: change.ExpectedUserVersion + 1}, ExpectedVersion: change.ExpectedUserVersion, AuditEventID: "link-audit", Link: AccountLinkReceipt{AccountID: change.Account.ID, Mode: change.Mode, ExpectedAccountVersion: change.ExpectedAccountVersion, ExpectedSocialLinkVersion: change.ExpectedSocialLinkVersion, ExpectedCredentialVersion: change.ExpectedCredentialVersion, AccountVersion: change.Account.Version, SocialLinkVersion: change.ExpectedSocialLinkVersion + 1, CredentialVersion: change.ExpectedCredentialVersion}}
	applied, err := NewAppliedLinkResult(application)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := applied.Receipt(); ok {
		t.Fatal("provisional application claimed durable commitment")
	}
	got, ok := applied.Application()
	if !ok || got != application {
		t.Fatal("provisional mutation lost exact application")
	}
	observed, err := NewObservedLinkResult(CommandResult{Binding: b, Outcome: CommitOutcomeUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := observed.Application(); ok {
		t.Fatal("unknown receipt fabricated a provisional mutation")
	}
	r, ok := observed.Receipt()
	if !ok || r.Outcome != CommitOutcomeUnknown || r.Link != nil {
		t.Fatal("unknown observation became success")
	}
	application.Link.AccountID = "other"
	if _, err := NewAppliedLinkResult(application); err == nil {
		t.Fatal("mismatched provisional account accepted")
	}
}
