package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

type unlinkOwner struct {
	state   AccountUnlinkState
	spec    *AccountUnlinkCommand
	receipt CommandResult
	lose    bool
	writes  int
}

func (o *unlinkOwner) GetAccountUnlinkState(context.Context, AccountUnlinkQuery) (AccountUnlinkState, error) {
	return o.state, nil
}
func (o *unlinkOwner) Execute(_ context.Context, c Command) (CommandResult, error) {
	s, ok := c.UnlinkAccount()
	if !ok {
		panic("wrong command")
	}
	if o.spec != nil {
		if !reflect.DeepEqual(s, *o.spec) {
			return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return o.receipt, nil
	}
	m, e := ApplyAccountUnlink(o.state, s.Change, queryClock{}.Now())
	if e != nil {
		return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	o.spec = &s
	o.state.Access = m.Access
	o.state.SocialLinkVersion = m.SocialLinkVersion
	o.state.CredentialVersion = m.CredentialVersion
	o.writes++
	p := ProviderRevocationNotRequested
	if s.RevokeProvider {
		p = ProviderRevocationPending
	}
	o.receipt = CommandResult{Binding: s.Binding, Outcome: CommitOutcomeCommitted, User: m.Access.User, ExpectedVersion: s.Change.ExpectedUserVersion, AuditEventID: "audit-unlink", Unlink: &AccountUnlinkReceipt{AccountID: s.Change.AccountID, ExpectedAccountVersion: s.Change.ExpectedAccountVersion, ExpectedSocialLinkVersion: s.Change.ExpectedSocialLinkVersion, ExpectedCredentialVersion: s.Change.ExpectedCredentialVersion, TombstoneVersion: m.TombstoneVersion, SocialLinkVersion: m.SocialLinkVersion, CredentialVersion: m.CredentialVersion, InvalidatesCredential: m.InvalidatesCredential, ProviderOutcome: p}}
	if o.lose {
		return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeUnknown}, errors.New("sensitive lost reply")
	}
	return o.receipt, nil
}
func (o *unlinkOwner) Recover(_ context.Context, q RecoveryQuery) (CommandResult, error) {
	return o.receipt, nil
}

func unlinkCommandFixture(t *testing.T) (*AccountUnlinkService, *unlinkOwner, AccountUnlinkRequest, capability.Service, capability.Payload) {
	t.Helper()
	f := newQueryFixture(t)
	state, change := unlinkState(t)
	owner := &unlinkOwner{state: state}
	now := queryClock{}.Now()
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, _ := capability.NewHMACSHA256Signer("unlink-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "unlink-key", Verifier: verifier}})
	caps, e := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewAccountUnlinkService(owner, owner, f.service.authorize, queryRedact, caps, AccountUnlinkConfig{Query: f.service.config, ProofIssuer: "https://identity.example", ProofAudience: "identity-backend", MaximumProofAge: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	r := AccountUnlinkRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Change: change, SessionID: "session-a", SessionVersion: 1, RevokeProvider: true, ActorScope: f.request.Context}
	r.ActorScope.Request.Subject.ID = authorization.SubjectID(r.Change.UserID)
	r.ActorScope.Request.Action = "identity.account.unlink"
	p := capability.Payload{Version: 1, Issuer: "https://identity.example", Audiences: []string{"identity-backend"}, Subject: string(change.UserID), Resource: string(change.AccountID), Operation: "identity.account.unlink", Tenant: string(change.TenantID), ID: "proof-aaaaaaaaaaaaaaaaaa", MaxUses: 1, IssuedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Caveats: map[string]string{"command_id": string(r.CommandID), "session_id": "session-a", "session_version": "1", "user_version": "2", "account_version": "1", "social_link_version": "3", "credential_version": "5", "policy_version": "1"}}
	p.Caveats["revoke_provider"] = "true"
	r.Proof, _, e = caps.Issue(context.Background(), p)
	// The provider choice is part of the exact signed operation, not a hint.
	if e != nil {
		t.Fatal(e)
	}
	return s, owner, r, caps, p
}

func TestAccountUnlinkCommandWorkflowReplaysAndRecoversWithoutAnotherRemoval(t *testing.T) {
	s, o, r, _, _ := unlinkCommandFixture(t)
	first, e := s.AccountUnlink(context.Background(), r)
	if e != nil || first.CommitOutcome != CommitOutcomeCommitted || first.ProviderOutcome != ProviderRevocationPending || first.Version != 3 || o.writes != 1 {
		t.Fatalf("unlink = %+v %v", first, e)
	}
	again, e := s.AccountUnlink(context.Background(), r)
	if e != nil || again != first || o.writes != 1 {
		t.Fatal("replay mutated twice")
	}
	recovered, e := s.RecoverAccountUnlink(context.Background(), AccountUnlinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, AccountID: r.Change.AccountID, ActorScope: r.ActorScope})
	if e != nil || recovered != first || o.writes != 1 {
		t.Fatal("recovery mutated or changed outcome")
	}
}

func TestAccountUnlinkCommandLostReplyIsUnknownUntilScopedRecovery(t *testing.T) {
	s, o, r, _, _ := unlinkCommandFixture(t)
	o.lose = true
	got, e := s.AccountUnlink(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.Version != 0 || o.writes != 1 {
		t.Fatal("lost reply inferred rollback")
	}
	got, e = s.RecoverAccountUnlink(context.Background(), AccountUnlinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, AccountID: r.Change.AccountID, ActorScope: r.ActorScope})
	if e != nil || got.CommitOutcome != CommitOutcomeCommitted || o.writes != 1 {
		t.Fatal("committed recovery failed")
	}
}

func TestAccountUnlinkCommandRejectsSignedButWrongProofBindings(t *testing.T) {
	for _, change := range []func(*capability.Payload){func(p *capability.Payload) { p.Subject = "foreign" }, func(p *capability.Payload) { p.Tenant = "foreign" }, func(p *capability.Payload) { p.Resource = "foreign" }, func(p *capability.Payload) { p.MaxUses = 0 }, func(p *capability.Payload) { p.Caveats["command_id"] = "other" }, func(p *capability.Payload) { p.Caveats["credential_version"] = "6" }, func(p *capability.Payload) { delete(p.Caveats, "session_id") }, func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Hour); p.NotBefore = p.IssuedAt }} {
		s, o, r, caps, p := unlinkCommandFixture(t)
		change(&p)
		var e error
		r.Proof, _, e = caps.Issue(context.Background(), p)
		if e != nil {
			t.Fatal(e)
		}
		got, e := s.AccountUnlink(context.Background(), r)
		if e == nil || got.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
			t.Fatal("mismatched/reusable/stale proof reached mutation")
		}
	}
}

func TestAccountUnlinkCommandBindsProviderRevocationChoice(t *testing.T) {
	s, o, r, _, _ := unlinkCommandFixture(t)
	r.RevokeProvider = false
	got, e := s.AccountUnlink(context.Background(), r)
	if e == nil || got.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
		t.Fatal("proof authorized a changed provider action")
	}
}

func TestAccountUnlinkCommandKnownCommitSurvivesProjectionFailure(t *testing.T) {
	s, o, r, _, _ := unlinkCommandFixture(t)
	s.policy.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{}, errors.New("sensitive projection")
	}
	got, e := s.AccountUnlink(context.Background(), r)
	if e == nil || got.CommitOutcome != CommitOutcomeCommitted || got.Version != 0 || got.ProviderOutcome != 0 || o.writes != 1 {
		t.Fatal("output failure erased committed observation")
	}
}

func TestAccountUnlinkCommandExecutionPanicRemainsUnknown(t *testing.T) {
	s, _, r, _, _ := unlinkCommandFixture(t)
	s.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) { panic("sensitive execution") }}
	got, e := s.AccountUnlink(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.Version != 0 {
		t.Fatal("panic inferred rollback")
	}
}

func TestAccountUnlinkCommandCurrentPolicyAndContextDeny(t *testing.T) {
	for _, which := range []string{"deny-admission", "deny-current", "wrong-actor", "wrong-operation", "cancel"} {
		s, o, r, _, _ := unlinkCommandFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			calls++
			out := authorization.Allow
			if which == "deny-admission" || which == "deny-current" && calls == 2 {
				out = authorization.Deny
			}
			return authorization.Decision{Outcome: out, Revision: 1}, nil
		})
		if which == "wrong-actor" {
			r.ActorScope.Request.Subject.ID = "foreign"
		}
		if which == "wrong-operation" {
			r.ActorScope.Request.Action = "identity.account.list"
		}
		if which == "cancel" {
			cancel()
		}
		got, e := s.AccountUnlink(ctx, r)
		cancel()
		if e == nil || got.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
			t.Fatal("denied request mutated identity")
		}
	}
}

func TestAccountUnlinkCommandRejectsRecoveryPurposeAndTargetSubstitution(t *testing.T) {
	for _, which := range []string{"purpose", "actor", "account", "tenant"} {
		s, o, r, _, _ := unlinkCommandFixture(t)
		if _, e := s.AccountUnlink(context.Background(), r); e != nil {
			t.Fatal(e)
		}
		q := AccountUnlinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, AccountID: r.Change.AccountID, ActorScope: r.ActorScope}
		switch which {
		case "purpose":
			q.ActorScope.Request.Action = "identity.user.create"
		case "actor":
			q.ActorScope.Request.Subject.ID = "foreign"
		case "account":
			q.AccountID = "foreign"
		case "tenant":
			q.TenantID = "foreign"
		}
		got, e := s.RecoverAccountUnlink(context.Background(), q)
		if e == nil || got.Version != 0 || o.writes != 1 {
			t.Fatal("recovery exposed another scope")
		}
	}
}

func TestAccountUnlinkCommandClosedUnionAndReceiptRejectCrossPurpose(t *testing.T) {
	s, o, r, _, _ := unlinkCommandFixture(t)
	if _, e := s.AccountUnlink(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	c, e := NewAccountUnlinkCommand(*o.spec)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.CreateUser(); ok {
		t.Fatal("unlink became creation")
	}
	if _, ok := c.UpdateUser(); ok {
		t.Fatal("unlink became update")
	}
	if _, ok := c.UpdateProfile(); ok {
		t.Fatal("unlink became profile")
	}
	if _, ok := c.UserStatus(); ok {
		t.Fatal("unlink became status")
	}
	c.create = &CreateUserCommand{}
	if _, ok := c.UnlinkAccount(); ok {
		t.Fatal("mixed union accepted")
	}
	receipt := o.receipt
	receipt.Binding.OperationID = "identity.user.update-admin"
	if receipt.valid() {
		t.Fatal("unlink payload accepted under other operation")
	}
}

func TestAccountUnlinkRecoveryUsesExactAccountPolicyBeforeReceiptRead(t *testing.T) {
	for _, allow := range []bool{false, true} {
		s, o, r, _, _ := unlinkCommandFixture(t)
		if _, e := s.AccountUnlink(context.Background(), r); e != nil {
			t.Fatal(e)
		}
		reads := 0
		s.uow = creationOwnerFunc{recover: func(ctx context.Context, q RecoveryQuery) (CommandResult, error) { reads++; return o.Recover(ctx, q) }}
		s.policy.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			account, _ := dc.Request.Resource.Attributes["identity.account.id"].String()
			outcome := authorization.Allow
			if allow && account != string(r.Change.AccountID) || !allow && account == string(r.Change.AccountID) {
				outcome = authorization.Deny
			}
			return authorization.Decision{Outcome: outcome, Revision: 1}, nil
		})
		q := AccountUnlinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, AccountID: r.Change.AccountID, ActorScope: r.ActorScope}
		q.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.account.id": authorization.StringValue("spoofed")}
		out, e := s.RecoverAccountUnlink(context.Background(), q)
		if allow {
			if e != nil || out.Version == 0 || reads != 1 {
				t.Fatal("allowed exact account could not recover")
			}
		} else if e == nil || out.Version != 0 || reads != 0 {
			t.Fatal("denied account recovered or read receipt")
		}
	}
}
