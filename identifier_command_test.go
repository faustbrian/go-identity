package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
)

func TestIdentifierCommandCommitsAndRecoversExactChange(t *testing.T) {
	s, owner, r, _ := identifierCommandFixture(t)
	out, err := s.IdentifierChange(context.Background(), r)
	if err != nil || out.CommitOutcome != CommitOutcomeCommitted || out.Version != 5 || out.AuthorityVersion != 3 || out.IdentifierID != "b" || owner.writes != 1 || len(owner.state.Identifiers) != 2 {
		t.Fatal("identifier attach was not committed with exact fences", err)
	}
	replay, err := s.IdentifierChange(context.Background(), r)
	if err != nil || replay != out || owner.writes != 1 {
		t.Fatal("same command replay changed its receipt", err)
	}
	recovered, err := s.RecoverIdentifierChange(context.Background(), IdentifierRecoveryRequest{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, IdentifierID: r.Change.ID, Action: r.Change.Action, ActorScope: r.ActorScope})
	if err != nil || recovered != out || owner.writes != 1 {
		t.Fatal("exact recovery did not retain result", err)
	}
}

func TestIdentifierCommandRejectsReceiptForDifferentSignedIntent(t *testing.T) {
	s, o, r, caps := identifierCommandFixture(t)
	if _, e := s.IdentifierChange(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	// The owner deliberately returns the old receipt for a re-signed different
	// candidate under the same command ID. A real owner must reject its journal
	// fingerprint; admission must also refuse to disclose it as this intent.
	r.Change.CanonicalValue = "different@example.test"
	signIdentifierRequest(t, s, caps, &r)
	out, e := s.IdentifierChange(context.Background(), r)
	var unknown UnknownCommitError
	if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.IdentifierID != "" || o.writes != 1 {
		t.Fatal("different signed intent accepted the original receipt")
	}
}

func TestIdentifierRecoveryRejectsWrongRecordForEveryOutcome(t *testing.T) {
	for _, outcome := range []CommitOutcome{CommitOutcomeNotCommitted, CommitOutcomeConflict, CommitOutcomeInProgress, CommitOutcomeUnknown} {
		s, _, r, _ := identifierCommandFixture(t)
		var receipt CommandResult
		s.uow = creationOwnerFunc{execute: func(_ context.Context, c Command) (CommandResult, error) {
			spec, _ := c.ChangeIdentifier()
			receipt = CommandResult{Binding: spec.Binding, Outcome: outcome}
			if outcome == CommitOutcomeInProgress {
				receipt.RetryAfter = time.Second
			}
			return receipt, nil
		}, recover: func(context.Context, RecoveryQuery) (CommandResult, error) { return receipt, nil }}
		_, _ = s.IdentifierChange(context.Background(), r)
		q := IdentifierRecoveryRequest{r.CommandID, r.Change.TenantID, r.Change.UserID, "permitted-other-record", r.Change.Action, r.ActorScope}
		out, e := s.RecoverIdentifierChange(context.Background(), q)
		var unknown UnknownCommitError
		if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.IdentifierID != "" {
			t.Fatal("other record disclosed original noncommitted receipt", outcome)
		}
		q.IdentifierID = r.Change.ID
		out, e = s.RecoverIdentifierChange(context.Background(), q)
		if e == nil || out.CommitOutcome != outcome {
			t.Fatal("exact record lost authoritative outcome", outcome)
		}
	}
}

func TestIdentifierCommandOwnsFiveDistinctTransitions(t *testing.T) {
	s, o, r, caps := identifierCommandFixture(t)
	for _, action := range []IdentifierAction{IdentifierAttach, IdentifierVerify, IdentifierMakePrimary, IdentifierReplace, IdentifierRemove} {
		r.Change.Action = action
		r.CommandID, _ = NewCommandID()
		r.Change.ExpectedUserVersion = o.state.User.Version
		r.Change.ExpectedAuthorityVersion = o.state.AuthorityVersion
		if action != IdentifierAttach {
			i, v := o.state.Identifiers[1], o.state.Verifications[1]
			r.Change.ExpectedIdentifierVersion, r.Change.ExpectedVerificationVersion = i.Version, v.Version
		}
		r.Change.Kind, r.Change.CanonicalValue, r.Change.DisplayValue = "", "", ""
		if action == IdentifierAttach || action == IdentifierReplace {
			r.Change.Kind, r.Change.CanonicalValue = IdentifierEmail, "two@example.test"
		}
		if action == IdentifierReplace {
			r.Change.CanonicalValue = "replacement@example.test"
		}
		r.ActorScope.Request.Action = authorization.Action(identifierOperation(action))
		signIdentifierRequest(t, s, caps, &r)
		out, e := s.IdentifierChange(context.Background(), r)
		if e != nil || out.CommitOutcome != CommitOutcomeCommitted || out.AuthorityVersion != r.Change.ExpectedAuthorityVersion+1 || out.Version != r.Change.ExpectedUserVersion+1 {
			t.Fatal("distinct transition failed", action, e)
		}
		switch action {
		case IdentifierAttach:
			if o.state.Identifiers[1].Verified {
				t.Fatal("attach grants verification")
			}
		case IdentifierVerify:
			if !o.state.Identifiers[1].Verified || o.state.Identifiers[1].Primary {
				t.Fatal("verify granted primary or lost verification")
			}
		case IdentifierMakePrimary:
			if !o.state.Identifiers[1].Primary || o.state.Identifiers[0].Primary {
				t.Fatal("primary switch lost atomicity")
			}
		case IdentifierReplace:
			if o.state.Identifiers[1].Verified || o.state.Identifiers[1].Primary || o.state.Verifications[1].State != VerificationPending {
				t.Fatal("replacement retained old authority")
			}
		case IdentifierRemove:
			if len(o.state.Identifiers) != 1 {
				t.Fatal("removal retained record")
			}
		}
	}
	if o.writes != 5 {
		t.Fatal("not all transitions owned")
	}
}

func TestIdentifierCommandRejectsUnsignedIntentSubstitution(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierChangeRequest){
		"value":           func(r *IdentifierChangeRequest) { r.Change.CanonicalValue = "other@example.test" },
		"display":         func(r *IdentifierChangeRequest) { r.Change.DisplayValue = "other" },
		"record":          func(r *IdentifierChangeRequest) { r.Change.ID = "c" },
		"kind":            func(r *IdentifierChangeRequest) { r.Change.Kind = IdentifierUsername },
		"authority":       func(r *IdentifierChangeRequest) { r.Change.ExpectedAuthorityVersion++ },
		"aggregate":       func(r *IdentifierChangeRequest) { r.Change.ExpectedUserVersion++ },
		"session":         func(r *IdentifierChangeRequest) { r.SessionID = "other" },
		"session version": func(r *IdentifierChangeRequest) { r.SessionVersion++ },
		"command":         func(r *IdentifierChangeRequest) { r.CommandID = "AgICAgICAgICAgICAgICAg" },
		"action": func(r *IdentifierChangeRequest) {
			r.Change = IdentifierChange{TenantID: r.Change.TenantID, UserID: r.Change.UserID, ID: "a", Action: IdentifierRemove, ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
			r.ActorScope.Request.Action = "identity.identifier.remove"
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, o, r, _ := identifierCommandFixture(t)
			alter(&r)
			out, e := s.IdentifierChange(context.Background(), r)
			if e == nil || out.IdentifierID != "" || o.writes != 0 || o.reads != 0 {
				t.Fatal("unsigned substitution reached primary state")
			}
		})
	}
}

func TestIdentifierCommandRejectsSignedWrongAuthority(t *testing.T) {
	for name, alter := range map[string]func(*capability.Payload){
		"issuer":            func(p *capability.Payload) { p.Issuer = "https://foreign.example" },
		"audience":          func(p *capability.Payload) { p.Audiences = []string{"other"} },
		"multiple audience": func(p *capability.Payload) { p.Audiences = append(p.Audiences, "other") },
		"tenant":            func(p *capability.Payload) { p.Tenant = "foreign" },
		"owner":             func(p *capability.Payload) { p.Subject = "foreign" },
		"record":            func(p *capability.Payload) { p.Resource = "foreign" },
		"action":            func(p *capability.Payload) { p.Operation = "identity.identifier.remove" },
		"actor":             func(p *capability.Payload) { p.Caveats["actor_id"] = "foreign" },
		"digest":            func(p *capability.Payload) { p.Caveats["intent_digest"] = strings.Repeat("0", 64) },
		"extra caveat":      func(p *capability.Payload) { p.Caveats["unexpected"] = "yes" },
		"missing caveat":    func(p *capability.Payload) { delete(p.Caveats, "session_version") },
		"reusable":          func(p *capability.Payload) { p.MaxUses = 2 },
		"expired":           func(p *capability.Payload) { p.ExpiresAt = queryClock{}.Now() },
		"future": func(p *capability.Payload) {
			p.IssuedAt = queryClock{}.Now().Add(time.Minute)
			p.NotBefore = p.IssuedAt
			p.ExpiresAt = p.IssuedAt.Add(time.Minute)
		},
		"long lifetime": func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(6 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			s, o, r, caps := identifierCommandFixture(t)
			g, e := caps.Verify(context.Background(), r.Proof, "identity.identifier.attach", s.config.ProofAudience)
			if e != nil {
				t.Fatal(e)
			}
			p := g.Payload()
			alter(&p)
			if name == "issuer" {
				// A foreign issuer can sign a structurally valid token. The
				// application's configured verifier must still refuse it.
				signer, _ := capability.NewHMACSHA256Signer("identifier-key", []byte("0123456789abcdef0123456789abcdef"))
				wire, err := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				r.Proof, e = capability.ParseProof(wire, capability.DefaultLimits())
			} else {
				r.Proof, _, e = caps.Issue(context.Background(), p)
			}
			if e != nil {
				t.Fatal("bad fixture", e)
			}
			out, e := s.IdentifierChange(context.Background(), r)
			if e == nil || out.IdentifierID != "" || o.reads != 0 || o.writes != 0 {
				t.Fatal("signed wrong authority reached primary state")
			}
		})
	}
}

func TestIdentifierCommandDeniesBeforePrimaryAndRejectsInvalidState(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierService, *identifierOwner, *IdentifierChangeRequest){
		"denied": func(s *IdentifierService, _ *identifierOwner, _ *IdentifierChangeRequest) {
			s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		},
		"unsupported decision": func(s *IdentifierService, _ *identifierOwner, _ *IdentifierChangeRequest) {
			s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.NotApplicable, Revision: 1}, nil
			})
		},
		"stale decision": func(s *IdentifierService, _ *identifierOwner, _ *IdentifierChangeRequest) {
			s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
			})
		},
		"foreign actor": func(_ *IdentifierService, _ *identifierOwner, r *IdentifierChangeRequest) {
			r.ActorScope.Request.Subject.ID = "other"
		},
		"workload": func(_ *IdentifierService, _ *identifierOwner, r *IdentifierChangeRequest) {
			r.ActorScope.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
		"foreign context tenant": func(_ *IdentifierService, _ *identifierOwner, r *IdentifierChangeRequest) {
			r.ActorScope.Request.Tenant = "other"
		},
		"foreign state": func(_ *IdentifierService, o *identifierOwner, _ *IdentifierChangeRequest) {
			o.state.Identifiers[0].UserID = "other"
		},
		"blocked": func(_ *IdentifierService, o *identifierOwner, _ *IdentifierChangeRequest) {
			o.state.User.Status = StatusBanned
		},
		"future aggregate": func(_ *IdentifierService, o *identifierOwner, _ *IdentifierChangeRequest) { o.state.User.Version-- },
		"future authority": func(_ *IdentifierService, o *identifierOwner, _ *IdentifierChangeRequest) { o.state.AuthorityVersion-- },
		"duplicate": func(_ *IdentifierService, o *identifierOwner, r *IdentifierChangeRequest) {
			o.state.Identifiers[0].CanonicalValue = r.Change.CanonicalValue
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, o, r, _ := identifierCommandFixture(t)
			alter(s, o, &r)
			out, e := s.IdentifierChange(context.Background(), r)
			if e == nil || out.IdentifierID != "" || o.writes != 0 {
				t.Fatal("invalid state or denied policy wrote change")
			}
			if name == "denied" || name == "unsupported decision" || name == "stale decision" || name == "foreign actor" || name == "workload" || name == "foreign context tenant" {
				if o.reads != 0 {
					t.Fatal("denial reached primary")
				}
			}
		})
	}
}

func TestIdentifierRecoveryRequiresExactRecordActionAndCurrentPolicy(t *testing.T) {
	for name, alter := range map[string]func(*IdentifierRecoveryRequest){
		"record": func(r *IdentifierRecoveryRequest) { r.IdentifierID = "other" },
		"action": func(r *IdentifierRecoveryRequest) {
			r.Action = IdentifierRemove
			r.ActorScope.Request.Action = "identity.identifier.remove"
		},
		"actor":  func(r *IdentifierRecoveryRequest) { r.ActorScope.Request.Subject.ID = "other" },
		"tenant": func(r *IdentifierRecoveryRequest) { r.TenantID = "other"; r.ActorScope.Request.Tenant = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			s, o, r, _ := identifierCommandFixture(t)
			if _, e := s.IdentifierChange(context.Background(), r); e != nil {
				t.Fatal(e)
			}
			q := IdentifierRecoveryRequest{r.CommandID, r.Change.TenantID, r.Change.UserID, r.Change.ID, r.Change.Action, r.ActorScope}
			alter(&q)
			out, e := s.RecoverIdentifierChange(context.Background(), q)
			if e == nil || out.IdentifierID != "" || o.writes != 1 {
				t.Fatal("recovery scope substitution allowed")
			}
		})
	}
	for _, allow := range []bool{false, true} {
		s, o, r, _ := identifierCommandFixture(t)
		if _, e := s.IdentifierChange(context.Background(), r); e != nil {
			t.Fatal(e)
		}
		reads := 0
		s.uow = creationOwnerFunc{recover: func(ctx context.Context, q RecoveryQuery) (CommandResult, error) { reads++; return o.Recover(ctx, q) }}
		s.policy.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			id, _ := dc.Request.Resource.Attributes["identity.identifier.id"].String()
			outcome := authorization.Allow
			if allow && id != string(r.Change.ID) || !allow && id == string(r.Change.ID) {
				outcome = authorization.Deny
			}
			return authorization.Decision{Outcome: outcome, Revision: 1}, nil
		})
		q := IdentifierRecoveryRequest{r.CommandID, r.Change.TenantID, r.Change.UserID, r.Change.ID, r.Change.Action, r.ActorScope}
		q.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.identifier.id": authorization.StringValue("spoofed")}
		out, e := s.RecoverIdentifierChange(context.Background(), q)
		if allow {
			if e != nil || out.IdentifierID != r.Change.ID || reads != 1 {
				t.Fatal("exact permitted record cannot recover")
			}
		} else if e == nil || out.IdentifierID != "" || reads != 0 {
			t.Fatal("denied record read/disclosed receipt")
		}
	}
}

func TestIdentifierCommandPreservesKnownCommitAndRecoversLostReply(t *testing.T) {
	t.Run("output failure", func(t *testing.T) {
		s, o, r, _ := identifierCommandFixture(t)
		s.policy.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
			return RedactionPolicyDecision{}, errors.New("sensitive dependency")
		}
		out, e := s.IdentifierChange(context.Background(), r)
		if e == nil || strings.Contains(e.Error(), "sensitive") || out.CommitOutcome != CommitOutcomeCommitted || out.IdentifierID != "" || o.writes != 1 {
			t.Fatal("output failure lost known commitment or disclosed data")
		}
	})
	t.Run("cancel after commit", func(t *testing.T) {
		s, o, r, _ := identifierCommandFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
			receipt, e := o.Execute(ctx, c)
			cancel()
			return receipt, e
		}}
		out, e := s.IdentifierChange(ctx, r)
		if !errors.Is(e, context.Canceled) || out.CommitOutcome != CommitOutcomeCommitted || out.IdentifierID != "" || o.writes != 1 {
			t.Fatal("cancellation invented rollback")
		}
	})
	t.Run("lost reply", func(t *testing.T) {
		s, o, r, _ := identifierCommandFixture(t)
		s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
			_, _ = o.Execute(ctx, c)
			return CommandResult{}, errors.New("lost reply")
		}, recover: o.Recover}
		out, e := s.IdentifierChange(context.Background(), r)
		var unknown UnknownCommitError
		if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || out.IdentifierID != "" || o.writes != 1 {
			t.Fatal("lost reply did not remain unknown")
		}
		out, e = s.RecoverIdentifierChange(context.Background(), IdentifierRecoveryRequest{r.CommandID, r.Change.TenantID, r.Change.UserID, r.Change.ID, r.Change.Action, r.ActorScope})
		if e != nil || out.CommitOutcome != CommitOutcomeCommitted || o.writes != 1 {
			t.Fatal("lost reply not recovered")
		}
	})
	t.Run("execution panic", func(t *testing.T) {
		s, _, r, _ := identifierCommandFixture(t)
		s.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) { panic("secret") }}
		out, e := s.IdentifierChange(context.Background(), r)
		var unknown UnknownCommitError
		if !errors.As(e, &unknown) || out.CommitOutcome != CommitOutcomeUnknown || strings.Contains(e.Error(), "secret") {
			t.Fatal("panic invented rollback/disclosed panic")
		}
	})
	t.Run("cancel before read", func(t *testing.T) {
		s, o, r, _ := identifierCommandFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, e := s.IdentifierChange(ctx, r)
		if !errors.Is(e, context.Canceled) || out.IdentifierID != "" || o.reads != 0 || o.writes != 0 {
			t.Fatal("cancelled request reached storage")
		}
	})
}

func TestIdentifierCommandClosedUnionAndRedaction(t *testing.T) {
	s, o, r, _ := identifierCommandFixture(t)
	if _, e := s.IdentifierChange(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	g, e := s.caps.Verify(context.Background(), r.Proof, "identity.identifier.attach", s.config.ProofAudience)
	if e != nil {
		t.Fatal(e)
	}
	c, e := NewIdentifierCommand(IdentifierCommand{Binding: o.receipt.Binding, Change: r.Change, Proof: g, SessionID: r.SessionID, SessionVersion: r.SessionVersion})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.CreateUser(); ok {
		t.Fatal("identifier became creation")
	}
	if _, ok := c.LinkAccount(); ok {
		t.Fatal("identifier became link")
	}
	copy, _ := c.ChangeIdentifier()
	copy.Change.CanonicalValue = "mutated"
	original, _ := c.ChangeIdentifier()
	if original.Change.CanonicalValue != r.Change.CanonicalValue {
		t.Fatal("accessor aliases intent")
	}
	c.create = &CreateUserCommand{}
	if _, ok := c.ChangeIdentifier(); ok {
		t.Fatal("mixed union admitted")
	}
	if _, ok := c.CreateUser(); ok {
		t.Fatal("mixed creation admitted")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, original), r.Change.CanonicalValue) {
			t.Fatal("command leaked identifier")
		}
	}
	receipt := o.receipt
	receipt.Binding.OperationID = "identity.user.update-admin"
	if receipt.valid() {
		t.Fatal("identifier receipt accepted under another operation")
	}
	receipt = o.receipt
	receipt.Outcome = CommitOutcomeUnknown
	if receipt.valid() {
		t.Fatal("unknown carried success metadata")
	}
	if _, e = (Command{}).MarshalJSON(); e == nil {
		t.Fatal("command serialization permitted")
	}
}

func FuzzIdentifierIntentDigest(f *testing.F) {
	f.Add("person@example.test", "Display")
	f.Add("\x00", "")
	f.Fuzz(func(t *testing.T, value, display string) {
		_, c, _ := identifierFixture()
		c.CanonicalValue, c.DisplayValue = value, display
		one, e := IdentifierIntentDigest(c)
		two, e2 := IdentifierIntentDigest(c)
		if (e == nil) != (e2 == nil) || one != two {
			t.Fatal("nondeterministic intent")
		}
		if e != nil && one != ([32]byte{}) {
			t.Fatal("invalid intent returned digest")
		}
	})
}

func TestIdentifierIntentEncodingAndStructuralBounds(t *testing.T) {
	_, c, _ := identifierFixture()
	d, e := IdentifierIntentDigest(c)
	if e != nil || hex.EncodeToString(d[:]) != "b34fe865c65f31b1a88236fdabd98337da387f991a2371c34d067bdb072e73b9" {
		t.Fatal("intent encoding changed")
	}
	for name, alter := range map[string]func(*IdentifierChange){
		"unknown action":          func(c *IdentifierChange) { c.Action = 0 },
		"empty record":            func(c *IdentifierChange) { c.ID = "" },
		"value bound":             func(c *IdentifierChange) { c.CanonicalValue = strings.Repeat("a", 513) },
		"display bound":           func(c *IdentifierChange) { c.DisplayValue = strings.Repeat("a", 513) },
		"invalid utf8":            func(c *IdentifierChange) { c.CanonicalValue = "\xff" },
		"zero authority":          func(c *IdentifierChange) { c.ExpectedAuthorityVersion = 0 },
		"overflow":                func(c *IdentifierChange) { c.ExpectedAuthorityVersion = ^uint64(0) },
		"attach existing version": func(c *IdentifierChange) { c.ExpectedIdentifierVersion = 1 },
		"attach verification":     func(c *IdentifierChange) { c.ExpectedVerificationVersion = 1 },
		"remove values": func(c *IdentifierChange) {
			c.Action = IdentifierRemove
			c.ExpectedIdentifierVersion = 1
			c.ExpectedVerificationVersion = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := c
			alter(&copy)
			d, e := IdentifierIntentDigest(copy)
			if e == nil || d != ([32]byte{}) {
				t.Fatal("invalid intent retained digest")
			}
		})
	}
	a, b := c, c
	a.CanonicalValue, a.DisplayValue = "ab", "c"
	b.CanonicalValue, b.DisplayValue = "a", "bc"
	da, _ := IdentifierIntentDigest(a)
	db, _ := IdentifierIntentDigest(b)
	if da == db {
		t.Fatal("length prefixes lost field boundaries")
	}
}

func TestIdentifierConstructionRejectsInvalidConfigurationAndProofSpec(t *testing.T) {
	s, o, r, caps := identifierCommandFixture(t)
	for name, alter := range map[string]func(*IdentifierConfig){
		"zero age": func(c *IdentifierConfig) { c.MaximumProofAge = 0 },
		"long age": func(c *IdentifierConfig) { c.MaximumProofAge = 6 * time.Minute },
		"issuer":   func(c *IdentifierConfig) { c.ProofIssuer = "http://insecure.example" },
		"audience": func(c *IdentifierConfig) { c.ProofAudience = "" },
		"clock":    func(c *IdentifierConfig) { c.Query.Clock = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := s.config
			alter(&c)
			got, e := NewIdentifierService(o, o, s.policy.policy.authorize, queryRedact, caps, c)
			if e == nil || got != nil {
				t.Fatal("invalid configuration constructed service")
			}
		})
	}
	if got, e := NewIdentifierService((*identifierOwner)(nil), o, s.policy.policy.authorize, queryRedact, caps, s.config); e == nil || got != nil {
		t.Fatal("typed nil dependency accepted")
	}
	_, _ = s.IdentifierChange(context.Background(), r)
	c := IdentifierCommand{Binding: o.receipt.Binding, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion}
	valid := IdentifierProofSpec{Command: c, Issuer: s.config.ProofIssuer, Audience: s.config.ProofAudience, ID: "proof-a", IssuedAt: queryClock{}.Now(), ExpiresAt: queryClock{}.Now().Add(time.Minute)}
	for name, alter := range map[string]func(*IdentifierProofSpec){
		"zero issued":      func(s *IdentifierProofSpec) { s.IssuedAt = time.Time{} },
		"subsecond":        func(s *IdentifierProofSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		"exclusive expiry": func(s *IdentifierProofSpec) { s.ExpiresAt = s.IssuedAt },
		"long lifetime":    func(s *IdentifierProofSpec) { s.ExpiresAt = s.IssuedAt.Add(5*time.Minute + time.Second) },
		"missing session":  func(s *IdentifierProofSpec) { s.Command.SessionID = "" },
		"foreign actor":    func(s *IdentifierProofSpec) { s.Command.Binding.ActorID = "other" },
		"wrong purpose":    func(s *IdentifierProofSpec) { s.Command.Binding.OperationID = "identity.identifier.verify" },
		"wrong schema":     func(s *IdentifierProofSpec) { s.Command.Binding.SchemaVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := valid
			alter(&copy)
			p, e := BuildIdentifierProofPayload(copy)
			if e == nil || p.ID != "" {
				t.Fatal("bad spec created unsigned proof")
			}
		})
	}
	if p, e := BuildIdentifierProofPayload(valid); e != nil || p.MaxUses != 1 || p.Resource != "b" || len(p.Caveats) != 6 {
		t.Fatal("valid spec does not own exact shape")
	}
}

type identifierOwner struct {
	state         IdentifierState
	receipt       CommandResult
	writes, reads int
}

func (o *identifierOwner) GetIdentifierState(ctx context.Context, q IdentifierQuery) (IdentifierState, error) {
	if _, ok := ctx.Deadline(); !ok || q.TenantID != o.state.User.TenantID || q.UserID != o.state.User.ID || q.MaximumIdentifiers != 128 {
		panic("unbounded or changed identifier scope")
	}
	o.reads++
	return o.state, nil
}

func (o *identifierOwner) Execute(_ context.Context, command Command) (CommandResult, error) {
	c, ok := command.ChangeIdentifier()
	if !ok {
		return CommandResult{}, errors.New("wrong command variant")
	}
	if o.receipt.Binding.CommandID == c.Binding.CommandID {
		return o.receipt, nil
	}
	next, e := ApplyIdentifierChange(o.state, c.Change, queryClock{}.Now())
	if e != nil {
		return CommandResult{Binding: c.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	o.state = next.State
	o.writes++
	digest, _ := IdentifierIntentDigest(c.Change)
	o.receipt = CommandResult{Binding: c.Binding, Outcome: CommitOutcomeCommitted, User: o.state.User, ExpectedVersion: c.Change.ExpectedUserVersion, AuditEventID: "audit-id", Identifier: &IdentifierReceipt{IdentifierID: c.Change.ID, Action: c.Change.Action, ExpectedAuthorityVersion: c.Change.ExpectedAuthorityVersion, AuthorityVersion: o.state.AuthorityVersion, IntentDigest: digest}}
	return o.receipt, nil
}

func (o *identifierOwner) Recover(_ context.Context, _ RecoveryQuery) (CommandResult, error) {
	return o.receipt, nil
}

func identifierCommandFixture(t *testing.T) (*IdentifierService, *identifierOwner, IdentifierChangeRequest, capability.Service) {
	t.Helper()
	f := newQueryFixture(t)
	state, change, _ := identifierFixture()
	state.Verifications[0].VerifiedAt = queryClock{}.Now().Add(-time.Hour)
	o := &identifierOwner{state: state}
	signer, _ := capability.NewHMACSHA256Signer("identifier-key", []byte("0123456789abcdef0123456789abcdef"))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "identifier-key", Verifier: verifier}})
	caps, e := capability.NewService(capability.ServiceConfig{Issuer: "https://identity.example", Signer: signer, Resolver: keys, Clock: func() time.Time { return queryClock{}.Now() }, Limits: capability.DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewIdentifierService(o, o, f.service.authorize, queryRedact, caps, IdentifierConfig{Query: f.service.config, ProofIssuer: "https://identity.example", ProofAudience: "identity-backend", MaximumProofAge: 5 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	r := IdentifierChangeRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Change: change, SessionID: "session-a", SessionVersion: 1, ActorScope: f.request.Context}
	r.ActorScope.Request.Subject.ID = authorization.SubjectID(change.UserID)
	r.ActorScope.Request.Tenant = authorization.TenantID(change.TenantID)
	r.ActorScope.Request.Resource.ID = authorization.ResourceID(change.UserID)
	r.ActorScope.Request.Action = authorization.Action("identity.identifier.attach")
	signIdentifierRequest(t, s, caps, &r)
	return s, o, r, caps
}

func signIdentifierRequest(t *testing.T, s *IdentifierService, caps capability.Service, r *IdentifierChangeRequest) {
	t.Helper()
	b := CommandBinding{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: identifierOperation(r.Change.Action), PolicyID: s.config.Query.PolicyID, PolicyVersion: s.config.Query.PolicyVersion, SchemaID: "identity-identifier", SchemaVersion: 1, CorrelationID: string(r.CommandID)}
	b.RecordID = string(r.Change.ID)
	p, e := BuildIdentifierProofPayload(IdentifierProofSpec{Command: IdentifierCommand{Binding: b, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion}, Issuer: s.config.ProofIssuer, Audience: s.config.ProofAudience, ID: "identifier-proof-a", IssuedAt: queryClock{}.Now().Add(-time.Minute), ExpiresAt: queryClock{}.Now().Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	r.Proof, _, e = caps.Issue(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
}
