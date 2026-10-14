package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

func linkState(t *testing.T) (AccountLinkState, AccountLinkChange) {
	t.Helper()
	a := accessFixture(t)
	b := a.Accounts[0]
	b.ID, b.Subject = "account-b", "subject-b"
	c := AccountLinkChange{Mode: AccountLinkExplicit, Account: b, ExpectedUserVersion: a.User.Version, ExpectedSocialLinkVersion: 3, ExpectedCredentialVersion: 5}
	return AccountLinkState{Access: a, Candidate: b, SocialLinkVersion: 3, CredentialVersion: 5}, c
}

func TestAccountLinkTransitionCopiesAndFences(t *testing.T) {
	s, c := linkState(t)
	method := LoginMethod{Credential: CredentialRef{ID: "provider-b", TenantID: c.Account.TenantID, UserID: c.Account.UserID, Kind: CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: c.Account.ID, Usable: true}
	c.Method = &method
	m, err := ApplyAccountLink(s, c, queryClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Access.Accounts) != 2 || len(m.Access.Methods) != 3 || m.Access.Accounts[1] != c.Account || m.Access.User.Version != s.Access.User.Version+1 || m.SocialLinkVersion != 4 || m.CredentialVersion != 6 || !m.AddsCredential {
		t.Fatal("link lost copied authority/state")
	}
	m.Access.Accounts[0].Subject = "changed"
	m.Access.Methods[0].Credential.ID = "changed"
	if s.Access.Accounts[0].Subject == "changed" || s.Access.Methods[0].Credential.ID == "changed" {
		t.Fatal("output aliases primary state")
	}
	for _, alter := range []func(*AccountLinkState, *AccountLinkChange){
		func(_ *AccountLinkState, c *AccountLinkChange) { c.ExpectedUserVersion++ },
		func(_ *AccountLinkState, c *AccountLinkChange) { c.ExpectedAccountVersion = 1; c.Account.Version = 2 },
		func(_ *AccountLinkState, c *AccountLinkChange) { c.ExpectedSocialLinkVersion++ },
		func(_ *AccountLinkState, c *AccountLinkChange) { c.ExpectedCredentialVersion++ },
		func(s *AccountLinkState, _ *AccountLinkChange) { s.Access.User.Status = StatusBanned },
		func(s *AccountLinkState, _ *AccountLinkChange) { s.Candidate.Subject = "other" },
		func(s *AccountLinkState, _ *AccountLinkChange) { s.SocialLinkVersion = ^uint64(0) },
	} {
		s, c := linkState(t)
		alter(&s, &c)
		if out, err := ApplyAccountLink(s, c, queryClock{}.Now()); err == nil || !reflect.DeepEqual(out, AccountLinkMutation{}) {
			t.Fatal("stale/invalid state linked")
		}
	}
}

func TestAccountLinkSubjectCollisionNeverTransfersOwnership(t *testing.T) {
	for _, owner := range []UserID{"foreign", "user-a"} {
		s, c := linkState(t)
		old := c.Account
		old.ID = "existing"
		old.UserID = owner
		s.SubjectOwner = &old
		if out, err := ApplyAccountLink(s, c, queryClock{}.Now()); err == nil || !reflect.DeepEqual(out, AccountLinkMutation{}) {
			t.Fatal("provider identity was merged or stolen")
		}
	}
	s, c := linkState(t)
	s.RecordVersion = 4
	c.ExpectedAccountVersion = 4
	c.Account.Version = 5
	s.Candidate = c.Account
	m, err := ApplyAccountLink(s, c, queryClock{}.Now())
	if err != nil || m.Account.Version != 5 || m.CredentialVersion != 5 || m.AddsCredential {
		t.Fatal("fresh data-only relink failed")
	}
	c.ExpectedAccountVersion = 0
	c.Account.Version = 1
	if _, err := ApplyAccountLink(s, c, queryClock{}.Now()); err == nil {
		t.Fatal("stale callback resurrected link")
	}
}

func TestAccountLinkRejectsContradictoryAbsentSubjectObservation(t *testing.T) {
	s, c := linkState(t)
	c.Account.Provider, c.Account.Issuer, c.Account.Subject = s.Access.Accounts[0].Provider, s.Access.Accounts[0].Issuer, s.Access.Accounts[0].Subject
	s.Candidate = c.Account
	if out, e := ApplyAccountLink(s, c, queryClock{}.Now()); e == nil || !reflect.DeepEqual(out, AccountLinkMutation{}) {
		t.Fatal("duplicate provider subject admitted from contradictory absence")
	}
}

type linkOwner struct {
	state   AccountLinkState
	spec    *AccountLinkCommand
	receipt CommandResult
	writes  int
	lose    bool
}

func (o *linkOwner) GetAccountLinkState(_ context.Context, q AccountLinkQuery) (AccountLinkState, error) {
	return o.state, nil
}
func (o *linkOwner) Execute(_ context.Context, c Command) (CommandResult, error) {
	s, ok := c.LinkAccount()
	if !ok {
		panic("wrong command")
	}
	if o.spec != nil {
		if !reflect.DeepEqual(*o.spec, s) {
			return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return o.receipt, nil
	}
	m, e := ApplyAccountLink(o.state, s.Change, queryClock{}.Now())
	if e != nil {
		return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	o.spec = &s
	o.writes++
	o.state.Access = m.Access
	o.state.RecordVersion = m.Account.Version
	o.state.SocialLinkVersion = m.SocialLinkVersion
	o.state.CredentialVersion = m.CredentialVersion
	account := m.Account
	o.state.SubjectOwner = &account
	if o.state.Identifiers != nil {
		next := *o.state.Identifiers
		next.User = m.Access.User
		o.state.Identifiers = &next
	}
	o.receipt = CommandResult{Binding: s.Binding, Outcome: CommitOutcomeCommitted, User: m.Access.User, ExpectedVersion: s.Change.ExpectedUserVersion, AuditEventID: "audit-link", Link: &AccountLinkReceipt{AccountID: m.Account.ID, Mode: s.Change.Mode, ExpectedAccountVersion: s.Change.ExpectedAccountVersion, ExpectedSocialLinkVersion: s.Change.ExpectedSocialLinkVersion, ExpectedCredentialVersion: s.Change.ExpectedCredentialVersion, AccountVersion: m.Account.Version, SocialLinkVersion: m.SocialLinkVersion, CredentialVersion: m.CredentialVersion, AddsCredential: m.AddsCredential}}
	if o.lose {
		return CommandResult{Binding: s.Binding, Outcome: CommitOutcomeUnknown}, errors.New("sensitive lost reply")
	}
	return o.receipt, nil
}

func TestAccountLinkProofPayloadHasExactOwnedBindings(t *testing.T) {
	_, o, r, _, _ := linkCommandFixture(t)
	now := queryClock{}.Now()
	command := AccountLinkCommand{Binding: CommandBinding{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: "identity.account.link-token", PolicyID: "identity-read", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: string(r.CommandID)}, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion}
	command.Binding.RecordID, command.Binding.LinkMode = string(r.Change.Account.ID), r.Change.Mode
	p, e := BuildAccountLinkProofPayload(AccountLinkProofSpec{Command: command, Issuer: "https://identity.example", Audience: "identity-backend", ID: "proof-link-aaaaaaaaaa", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)})
	if e != nil || p.Subject != string(o.state.Access.User.ID) || p.Resource != string(r.Change.Account.ID) || p.Tenant != string(r.Change.Account.TenantID) || p.MaxUses != 1 || p.Bearer || p.Operation != "identity.account.link-token" || len(p.Caveats) != 8 || p.Caveats["session_id"] != "present:session-a" || p.Caveats["pre_auth_id"] != "absent" || p.Caveats["command_id"] != string(r.CommandID) {
		t.Fatal("owned proof builder omitted exact binding")
	}
}

func TestAccountLinkRejectsWrongSignedAuthorityAndLifetimes(t *testing.T) {
	for name, alter := range map[string]func(*capability.Payload){
		"wrong issuer":       func(p *capability.Payload) { p.Issuer = "https://foreign.example" },
		"wrong tenant":       func(p *capability.Payload) { p.Tenant = "foreign" },
		"wrong subject":      func(p *capability.Payload) { p.Subject = "foreign" },
		"wrong resource":     func(p *capability.Payload) { p.Resource = "foreign" },
		"wrong actor":        func(p *capability.Payload) { p.Caveats["actor_id"] = "foreign" },
		"wrong revision":     func(p *capability.Payload) { p.Caveats["policy_version"] = "2" },
		"wrong attempt":      func(p *capability.Payload) { p.Caveats["pre_auth_id"] = "present:AgICAgICAgICAgICAgICAg" },
		"extra caveat":       func(p *capability.Payload) { p.Caveats["ignored"] = "true" },
		"missing caveat":     func(p *capability.Payload) { delete(p.Caveats, "session_version") },
		"reusable":           func(p *capability.Payload) { p.MaxUses = 0 },
		"expired age":        func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(-time.Hour); p.NotBefore = p.IssuedAt },
		"multiple audiences": func(p *capability.Payload) { p.Audiences = append(p.Audiences, "other") },
	} {
		t.Run(name, func(t *testing.T) {
			s, o, r, caps, p := linkCommandFixture(t)
			alter(&p)
			var e error
			r.Proof, _, e = caps.Issue(context.Background(), p)
			if e != nil {
				t.Fatal(e)
			}
			if out, e := s.AccountLink(context.Background(), r); e == nil || out.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
				t.Fatal("signed but inapplicable authority reached mutation")
			}
		})
	}
}

func TestAccountLinkDeniedAndCancelledAdmissionCannotWrite(t *testing.T) {
	for _, stage := range []string{"admission", "current", "cancelled", "foreign-user", "unsupported-actor"} {
		s, o, r, _, _ := linkCommandFixture(t)
		ctx := context.Background()
		switch stage {
		case "admission":
			s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		case "current":
			s.policy.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				admission, _ := dc.Request.Resource.Attributes["identity.command.read-admission"].Bool()
				if admission {
					return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
				}
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		case "cancelled":
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		case "foreign-user":
			r.ActorScope.Request.Subject.ID = "foreign"
		case "unsupported-actor":
			r.ActorScope.Request.Subject.Kind = authorization.SubjectAPIKey
		}
		if out, e := s.AccountLink(ctx, r); e == nil || out.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
			t.Fatal("denied/cancelled admission wrote link")
		}
	}
}

func TestAccountLinkMalformedReceiptRemainsUnknown(t *testing.T) {
	s, o, r, _, _ := linkCommandFixture(t)
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		receipt, e := o.Execute(ctx, c)
		receipt.Link.AccountID = "foreign"
		return receipt, e
	}}
	out, e := s.AccountLink(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.AccountID != "" || o.writes != 1 {
		t.Fatal("mismatched receipt fabricated success")
	}
}

func FuzzAccountLinkIntentDigest(f *testing.F) {
	f.Add("subject-b", "https://issuer.example", uint64(0))
	f.Add("\xff", "invalid", ^uint64(0))
	f.Add("", "https://issuer.example", uint64(1))
	f.Fuzz(func(t *testing.T, subject, issuer string, previous uint64) {
		c := AccountLinkChange{Mode: AccountLinkExplicit, Account: Account{ID: "account-b", TenantID: "tenant", UserID: "user", Provider: "example", Issuer: issuer, Subject: subject, Version: previous + 1}, ExpectedUserVersion: 1, ExpectedAccountVersion: previous, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}
		first, e := AccountLinkIntentDigest(c)
		if e != nil {
			if first != ([32]byte{}) || e.Error() != "identity: invalid input" {
				t.Fatal("partial digest or input disclosure")
			}
			return
		}
		second, e := AccountLinkIntentDigest(c)
		if e != nil || first != second || first == ([32]byte{}) || len(subject) > 512 || len(issuer) > 2048 {
			t.Fatal("unstable/unbounded digest")
		}
		c.Account.Subject += "x"
		if changed, e := AccountLinkIntentDigest(c); e == nil && changed == first {
			t.Fatal("provider subject not bound")
		}
	})
}

func TestAccountLinkImplicitRequiresCurrentVerifiedIdentifier(t *testing.T) {
	for _, invalid := range []string{"", "unverified", "wrong-value", "stale-identifier", "stale-verification", "stale-authority", "foreign-owner", "wrong-workload", "disabled"} {
		t.Run(invalid, func(t *testing.T) {
			s, o, r, caps, p := linkCommandFixture(t)
			now := queryClock{}.Now()
			r.Change.Mode = AccountLinkImplicit
			r.Change.MatchedIdentifier = "verified-email"
			r.Change.VerifiedCanonicalIdentifier = "person@example.test"
			r.Change.ExpectedIdentifierAuthorityVersion = 2
			r.Change.ExpectedIdentifierVersion = 3
			r.Change.ExpectedVerificationVersion = 4
			o.state.Identifiers = &IdentifierState{User: o.state.Access.User, AuthorityVersion: 2, Identifiers: []Identifier{{ID: "verified-email", UserID: o.state.Access.User.ID, Kind: IdentifierEmail, CanonicalValue: "person@example.test", Verified: true, Version: 3}}, Verifications: []Verification{{IdentifierID: "verified-email", State: VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 4}}}
			r.SessionID = ""
			r.SessionVersion = 0
			r.PreAuthTransactionID = "AgICAgICAgICAgICAgICAg"
			r.ActorScope.Request.Subject.Kind = authorization.SubjectServiceAccount
			r.ActorScope.Request.Subject.ID = "provider-workload"
			switch invalid {
			case "unverified":
				o.state.Identifiers.Identifiers[0].Verified = false
				o.state.Identifiers.Verifications[0].State = VerificationPending
				o.state.Identifiers.Verifications[0].VerifiedAt = time.Time{}
			case "wrong-value":
				o.state.Identifiers.Identifiers[0].CanonicalValue = "other@example.test"
			case "stale-identifier":
				o.state.Identifiers.Identifiers[0].Version++
			case "stale-verification":
				o.state.Identifiers.Verifications[0].Version++
			case "stale-authority":
				o.state.Identifiers.AuthorityVersion++
			case "foreign-owner":
				o.state.Identifiers.Identifiers[0].UserID = "other"
			case "wrong-workload":
				r.ActorScope.Request.Subject.ID = "foreign-workload"
			case "disabled":
				s.config.AllowImplicit = false
			}
			p.Caveats = linkCaveats(AccountLinkCommand{Binding: CommandBinding{CommandID: r.CommandID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, PolicyVersion: 1}, Change: r.Change, PreAuthTransactionID: r.PreAuthTransactionID})
			var e error
			r.Proof, _, e = caps.Issue(context.Background(), p)
			if e != nil {
				t.Fatal(e)
			}
			out, e := s.AccountLink(context.Background(), r)
			if invalid == "" {
				if e != nil || out.CommitOutcome != CommitOutcomeCommitted || o.writes != 1 {
					t.Fatalf("verified implicit link denied: %v", e)
				}
			} else if e == nil || o.writes != 0 {
				t.Fatal("ambiguous/unverified implicit link reached mutation")
			}
		})
	}
}

func TestAccountLinkAdministrativeActorIsNotTargetAuthority(t *testing.T) {
	for _, invalid := range []string{"", "disabled", "unregistered-reason", "actor-substitution"} {
		s, o, r, caps, p := linkCommandFixture(t)
		r.Change.Mode = AccountLinkAdministrative
		r.Change.Reason = "approved-recovery"
		r.ActorScope.Request.Subject.ID = "administrator"
		p.Caveats = linkCaveats(AccountLinkCommand{Binding: CommandBinding{CommandID: r.CommandID, ActorID: "administrator", ActorKind: authorization.SubjectUser, PolicyVersion: 1}, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion})
		var e error
		r.Proof, _, e = caps.Issue(context.Background(), p)
		if e != nil {
			t.Fatal(e)
		}
		switch invalid {
		case "disabled":
			s.config.AllowAdministrative = false
		case "unregistered-reason":
			s.config.AdministrativeReasons = []PolicyReason{"other"}
		case "actor-substitution":
			r.ActorScope.Request.Subject.ID = "another-administrator"
		}
		out, e := s.AccountLink(context.Background(), r)
		if invalid == "" {
			if e != nil || out.CommitOutcome != CommitOutcomeCommitted || o.spec.Binding.ActorID == ActorID(o.spec.Binding.UserID) || o.writes != 1 {
				t.Fatal("actor and target were conflated")
			}
		} else if e == nil || o.writes != 0 {
			t.Fatal("administrator role label granted linking")
		}
	}
}

func TestAccountLinkReceiptUnionAndCopies(t *testing.T) {
	s, o, r, caps, p := linkCommandFixture(t)
	r.Change.Method = &LoginMethod{Credential: CredentialRef{ID: "provider-b", TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, Kind: CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: r.Change.Account.ID}
	p.Caveats = linkCaveats(AccountLinkCommand{Binding: CommandBinding{CommandID: r.CommandID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, PolicyVersion: 1}, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion})
	var e error
	r.Proof, _, e = caps.Issue(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AccountLink(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	cmd, e := NewAccountLinkCommand(*o.spec)
	if e != nil {
		t.Fatal(e)
	}
	first, ok := cmd.LinkAccount()
	if !ok {
		t.Fatal("typed accessor rejected")
	}
	first.Change.Method.Credential.ID = "mutated"
	second, _ := cmd.LinkAccount()
	if second.Change.Method.Credential.ID == "mutated" {
		t.Fatal("command aliases accessor")
	}
	if _, ok := cmd.CreateUser(); ok {
		t.Fatal("link became creation")
	}
	if _, ok := cmd.UpdateUser(); ok {
		t.Fatal("link became update")
	}
	if _, ok := cmd.UpdateProfile(); ok {
		t.Fatal("link became profile")
	}
	if _, ok := cmd.UserStatus(); ok {
		t.Fatal("link became status")
	}
	if _, ok := cmd.UnlinkAccount(); ok {
		t.Fatal("link became unlink")
	}
	cmd.create = &CreateUserCommand{}
	if _, ok := cmd.LinkAccount(); ok {
		t.Fatal("mixed union accepted")
	}
	for _, operation := range []string{"identity.user.create", "identity.profile.update", "identity.account.unlink"} {
		receipt := o.receipt
		receipt.Binding.OperationID = operation
		if receipt.valid() {
			t.Fatal("link receipt accepted for another purpose")
		}
	}
	if !slices.Equal(o.state.Access.Accounts, []Account{accessFixture(t).Accounts[0], r.Change.Account}) {
		t.Fatal("existing account changed")
	}
}

func TestAccountLinkRetainsKnownCommitAfterDisclosureFailure(t *testing.T) {
	s, o, r, _, _ := linkCommandFixture(t)
	s.policy.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{}, errors.New("private")
	}
	out, e := s.AccountLink(context.Background(), r)
	if e == nil || out.CommitOutcome != CommitOutcomeCommitted || out.AccountID != "" || out.Version != 0 || o.writes != 1 {
		t.Fatal("known commit relabeled or disclosed")
	}
}

func TestAccountLinkPanickingOwnerIsUnknown(t *testing.T) {
	s, _, r, _, _ := linkCommandFixture(t)
	s.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) { panic("private") }}
	out, e := s.AccountLink(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.Version != 0 {
		t.Fatal("owner panic fabricated rollback")
	}
}

func TestAccountLinkRecoveryRejectsDifferentScope(t *testing.T) {
	for _, wrong := range []string{"mode", "account", "tenant", "actor", "operation"} {
		s, o, r, _, _ := linkCommandFixture(t)
		if _, e := s.AccountLink(context.Background(), r); e != nil {
			t.Fatal(e)
		}
		q := AccountLinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, AccountID: r.Change.Account.ID, Mode: r.Change.Mode, ActorScope: r.ActorScope}
		switch wrong {
		case "mode":
			q.Mode = AccountLinkAdministrative
		case "account":
			q.AccountID = "foreign"
		case "tenant":
			q.TenantID = "foreign"
		case "actor":
			q.ActorScope.Request.Subject.ID = "foreign"
		case "operation":
			q.ActorScope.Request.Action = "identity.account.unlink"
		}
		out, e := s.RecoverAccountLink(context.Background(), q)
		if e == nil || out.AccountID != "" || out.Version != 0 || o.writes != 1 {
			t.Fatal("recovery disclosed another purpose/scope")
		}
	}
}

func TestAccountLinkRecoveryUsesExactAccountPolicyBeforeReceiptRead(t *testing.T) {
	for _, allow := range []bool{false, true} {
		s, o, r, _, _ := linkCommandFixture(t)
		if _, e := s.AccountLink(context.Background(), r); e != nil {
			t.Fatal(e)
		}
		reads := 0
		s.uow = creationOwnerFunc{recover: func(ctx context.Context, q RecoveryQuery) (CommandResult, error) { reads++; return o.Recover(ctx, q) }}
		s.policy.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			account, _ := dc.Request.Resource.Attributes["identity.account.id"].String()
			outcome := authorization.Allow
			if allow && account != string(r.Change.Account.ID) || !allow && account == string(r.Change.Account.ID) {
				outcome = authorization.Deny
			}
			return authorization.Decision{Outcome: outcome, Revision: 1}, nil
		})
		q := AccountLinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, AccountID: r.Change.Account.ID, Mode: r.Change.Mode, ActorScope: r.ActorScope}
		q.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.account.id": authorization.StringValue("spoofed")}
		out, e := s.RecoverAccountLink(context.Background(), q)
		if allow {
			if e != nil || out.AccountID != r.Change.Account.ID || reads != 1 {
				t.Fatal("allowed exact account could not recover")
			}
		} else if e == nil || out.AccountID != "" || reads != 0 {
			t.Fatal("denied account recovered or read receipt")
		}
	}
}

func TestAccountLinkRecoveryRejectsWrongRecordAndModeForEveryOutcome(t *testing.T) {
	for _, outcome := range []CommitOutcome{CommitOutcomeNotCommitted, CommitOutcomeConflict, CommitOutcomeInProgress, CommitOutcomeUnknown} {
		s, _, r, _, _ := linkCommandFixture(t)
		var receipt CommandResult
		s.uow = creationOwnerFunc{execute: func(_ context.Context, c Command) (CommandResult, error) {
			spec, _ := c.LinkAccount()
			receipt = CommandResult{Binding: spec.Binding, Outcome: outcome}
			if outcome == CommitOutcomeInProgress {
				receipt.RetryAfter = time.Second
			}
			return receipt, nil
		}, recover: func(context.Context, RecoveryQuery) (CommandResult, error) { return receipt, nil }}
		_, _ = s.AccountLink(context.Background(), r)
		q := AccountLinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, AccountID: r.Change.Account.ID, Mode: r.Change.Mode, ActorScope: r.ActorScope}
		for _, wrongMode := range []bool{false, true} {
			q.AccountID, q.Mode = r.Change.Account.ID, r.Change.Mode
			if wrongMode {
				q.Mode = AccountLinkAdministrative
			} else {
				q.AccountID = "permitted-other-record"
			}
			out, e := s.RecoverAccountLink(context.Background(), q)
			var unknown UnknownCommitError
			if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.AccountID != "" {
				t.Fatal("other account/mode disclosed noncommitted receipt", outcome, wrongMode)
			}
		}
		q.AccountID, q.Mode = r.Change.Account.ID, r.Change.Mode
		out, e := s.RecoverAccountLink(context.Background(), q)
		if e == nil || out.CommitOutcome != outcome {
			t.Fatal("exact scope lost outcome", outcome)
		}
	}
}
func (o *linkOwner) Recover(_ context.Context, q RecoveryQuery) (CommandResult, error) {
	return o.receipt, nil
}

func linkCommandFixture(t *testing.T) (*AccountLinkService, *linkOwner, AccountLinkRequest, capability.Service, capability.Payload) {
	t.Helper()
	f := newQueryFixture(t)
	s, c := linkState(t)
	o := &linkOwner{state: s}
	now := queryClock{}.Now()
	signer, _ := capability.NewHMACSHA256Signer("link-key", []byte("0123456789abcdef0123456789abcdef"))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "link-key", Verifier: verifier}})
	caps, e := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	service, e := NewAccountLinkService(o, o, f.service.authorize, queryRedact, caps, AccountLinkConfig{Query: f.service.config, ProofIssuer: "https://identity.example", ProofAudience: "identity-backend", MaximumProofAge: 5 * time.Minute, AllowAdministrative: true, AdministrativeReasons: []PolicyReason{"approved-recovery"}, AllowImplicit: true, ImplicitActorID: "provider-workload"})
	if e != nil {
		t.Fatal(e)
	}
	r := AccountLinkRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Change: c, SessionID: "session-a", SessionVersion: 1, ActorScope: f.request.Context}
	r.ActorScope.Request.Action = "identity.account.link-token"
	r.ActorScope.Request.Subject.ID = authorization.SubjectID(c.Account.UserID)
	p := capability.Payload{Version: 1, Issuer: "https://identity.example", Audiences: []string{"identity-backend"}, Subject: string(c.Account.UserID), Resource: string(c.Account.ID), Operation: "identity.account.link-token", Tenant: string(c.Account.TenantID), ID: "proof-link-aaaaaaaaaa", MaxUses: 1, IssuedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	p.Caveats = linkCaveats(AccountLinkCommand{Binding: CommandBinding{CommandID: r.CommandID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, PolicyVersion: 1}, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion})
	r.Proof, _, e = caps.Issue(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	return service, o, r, caps, p
}

func TestAccountLinkCommandReplayAndRecovery(t *testing.T) {
	s, o, r, _, _ := linkCommandFixture(t)
	first, e := s.AccountLink(context.Background(), r)
	if e != nil || first.CommitOutcome != CommitOutcomeCommitted || first.Version != 3 || first.AccountID != r.Change.Account.ID || o.writes != 1 {
		t.Fatalf("link = %+v %v", first, e)
	}
	again, e := s.AccountLink(context.Background(), r)
	if e != nil || again != first || o.writes != 1 {
		t.Fatal("replay linked twice")
	}
	recovered, e := s.RecoverAccountLink(context.Background(), AccountLinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, AccountID: r.Change.Account.ID, Mode: r.Change.Mode, ActorScope: r.ActorScope})
	if e != nil || recovered != first || o.writes != 1 {
		t.Fatal("recovery executed mutation")
	}
}

func TestAccountLinkCommandLostReplyRetainsUnknownUntilRecovery(t *testing.T) {
	s, o, r, _, _ := linkCommandFixture(t)
	o.lose = true
	out, e := s.AccountLink(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.AccountID != "" || o.writes != 1 {
		t.Fatal("lost commit treated as rollback")
	}
	out, e = s.RecoverAccountLink(context.Background(), AccountLinkRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, AccountID: r.Change.Account.ID, Mode: r.Change.Mode, ActorScope: r.ActorScope})
	if e != nil || out.CommitOutcome != CommitOutcomeCommitted {
		t.Fatal("recovery lost commitment")
	}
}

func TestAccountLinkCommandSignedIntentCannotBeSubstituted(t *testing.T) {
	for _, alter := range []func(*AccountLinkRequest){
		func(r *AccountLinkRequest) { r.Change.Account.Subject = "other" }, func(r *AccountLinkRequest) { r.Change.Account.Issuer = "https://other.example" }, func(r *AccountLinkRequest) { r.Change.Account.Provider = "other" }, func(r *AccountLinkRequest) {
			r.Change.Mode = AccountLinkAdministrative
			r.Change.Reason = "approved-recovery"
		}, func(r *AccountLinkRequest) { r.SessionVersion++ }, func(r *AccountLinkRequest) { r.Change.ExpectedCredentialVersion++ }, func(r *AccountLinkRequest) { r.CommandID = "AgICAgICAgICAgICAgICAg" },
	} {
		s, o, r, _, _ := linkCommandFixture(t)
		alter(&r)
		if out, e := s.AccountLink(context.Background(), r); e == nil || out.CommitOutcome == CommitOutcomeCommitted || o.writes != 0 {
			t.Fatal("changed signed intent reached mutation")
		}
	}
}

func TestAccountLinkDiagnosticsRedactIntent(t *testing.T) {
	s, c := linkState(t)
	for _, v := range []any{s, c} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			out := fmt.Sprintf(verb, v)
			if !strings.Contains(out, "redacted") || strings.Contains(out, "subject-b") || strings.Contains(out, "https://issuer") {
				t.Fatal("link intent leaked")
			}
		}
	}
}
