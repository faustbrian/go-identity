package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func TestAccountUnlinkDomainResultRequiresActualAppliedReceipt(t *testing.T) {
	_, w, command, _ := unlinkInvocationFixture(t)
	spec, _, _ := command.AccountUnlinkCounterCommand()
	u := identity.User{TenantID: spec.Binding.TenantID, ID: spec.Binding.UserID, Status: identity.StatusActive, Version: 2}
	receipt := identity.AccountUnlinkReceipt{AccountID: spec.Change.AccountID, ExpectedAccountVersion: 1,
		ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1, TombstoneVersion: 2, SocialLinkVersion: 2,
		CredentialVersion: 2, InvalidatesCredential: true, ProviderOutcome: identity.ProviderRevocationNotRequested}
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, User: u, ExpectedVersion: 1, Unlink: &receipt, AuditEventID: "audit-a"}
	if result.Validate() != nil {
		t.Fatal("invalid controlled unlink result fixture")
	}
	progress := &accountUnlinkProgress{command: command, user: u, receipt: receipt, stage: accountUnlinkApplied}
	w.state.accountUnlink = progress
	if !matchesDomainResult(w, result) {
		t.Fatal("actual provisional unlink result cannot reach native commit")
	}
	for _, stage := range []accountUnlinkStage{accountUnlinkUnchecked, accountUnlinkChecked, accountUnlinkEligible, accountUnlinkPersisted, accountUnlinkFinalized} {
		progress.stage = stage
		if matchesDomainResult(w, result) {
			t.Fatal("incomplete or already-finalized unlink fabricated commit result", stage)
		}
	}
	progress.stage = accountUnlinkApplied
	changed := receipt
	changed.CredentialVersion++
	result.Unlink = &changed
	if matchesDomainResult(w, result) {
		t.Fatal("caller-authored credential epoch replaced actual unlink receipt")
	}
	result.Unlink = &receipt
	w.state.creation = &u
	if matchesDomainResult(w, result) {
		t.Fatal("unlink and another native mutation shared one command result")
	}
}

func TestAccountUnlinkApplyRejectsUnownedWorkBeforeSQL(t *testing.T) {
	type unlinkApplier interface {
		ApplyAccountUnlink(context.Context, Work, identity.Command) (identity.CommandResult, error)
	}
	repository := &Repository{read: func(context.Context, identity.TenantID, identity.UserID) pgx.Row {
		t.Fatal("unowned unlink called repository read")
		return nil
	}}
	r, ok := any(repository).(unlinkApplier)
	if !ok {
		t.Fatal("native repository has no typed account-unlink apply operation")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if result, err := r.ApplyAccountUnlink(ctx, Work{}, identity.Command{}); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("unowned apply disclosed a result or reached SQL")
		}
	}
	_, foreign, command, _ := unlinkInvocationFixture(t)
	if result, err := r.ApplyAccountUnlink(foreign.state.ctx, foreign, command); err == nil || result.Outcome != identity.CommitOutcomeInvalid || foreign.usable() == nil {
		t.Fatal("foreign repository borrowed unlink SQL authority or ignored denial")
	}
}
