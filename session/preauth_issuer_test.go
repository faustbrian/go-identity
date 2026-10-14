package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

type preAuthIssueStub struct {
	execute func(context.Context, PreAuthIssueCommand) (PreAuthIssueExecution, error)
	recover func(context.Context, identity.RecoveryQuery) (identity.CommandResult, error)
}

func (s *preAuthIssueStub) ExecutePreAuthIssuance(ctx context.Context, c PreAuthIssueCommand) (PreAuthIssueExecution, error) {
	return s.execute(ctx, c)
}
func (s *preAuthIssueStub) RecoverPreAuthIssue(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	return s.recover(ctx, q)
}

type preAuthIssuerClock struct{ now time.Time }

func (c *preAuthIssuerClock) Now() time.Time { return c.now }

func preAuthIssuerFixture(t *testing.T) (*PreAuthIssuer, PreparedPreAuthIssuance, *preAuthIssueStub, *preAuthIssuerClock) {
	t.Helper()
	_, key, spec := preAuthFixture(t)
	clock := &preAuthIssuerClock{now: spec.Binding.IssuedAt}
	cookie, err := NewCookiePolicy(CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	executor := &preAuthIssueStub{execute: func(_ context.Context, command PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		return preAuthCommitted(command), nil
	}}
	issuer, err := NewPreAuthIssuer(executor, PreAuthIssuerConfig{ActorID: "preauth-service", Action: spec.Binding.Intent.Action, Origin: spec.Binding.Intent.Origin, CallbackURL: spec.Binding.Intent.CallbackURL, PolicyID: spec.Binding.Intent.PolicyID, PolicyVersion: spec.Binding.Intent.PolicyVersion, Clock: clock, MaximumDuration: time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	p, err := issuer.Prepare(PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: spec.Binding.Intent.TenantID, CorrelationID: "preauth-original", Remember: spec.Binding.Intent.Remember})
	if err != nil {
		t.Fatal(err)
	}
	return issuer, p, executor, clock
}

func preAuthCommitted(c PreAuthIssueCommand) PreAuthIssueExecution {
	s, _ := c.Record.Bindings()
	b := identity.CommandBinding{CommandID: c.CommandID, TenantID: s.Binding.Intent.TenantID, AnonymousFlowID: string(s.Binding.ID), ActorID: "preauth-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.session.preauth-issue", RecordID: string(s.Binding.ID), PolicyID: s.Binding.Intent.PolicyID, PolicyVersion: s.Binding.Intent.PolicyVersion, SchemaID: "session-preauth-issue-v1", SchemaVersion: 1, CorrelationID: c.CorrelationID}
	op := identity.FeatureOperation{Owner: "identity/session", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	return PreAuthIssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: op, AfterVersion: 1}}}
}

func noPreAuthDelivery(t *testing.T, out PreAuthIssueResult) {
	t.Helper()
	if _, err := out.Token.Reveal(); !errors.Is(err, ErrInvalidToken) || !reflect.DeepEqual(out.Cookie, http.Cookie{}) {
		t.Fatal("undeliverable outcome exposed flow credential")
	}
}

func TestPreAuthIssuerOwnsOriginalPreparationAndDelivery(t *testing.T) {
	issuer, p, executor, clock := preAuthIssuerFixture(t)
	c, ok := p.Command()
	if !ok {
		t.Fatal("missing retained command")
	}
	s, _ := c.Record.Bindings()
	if s.Binding.Intent.Nonce == ([32]byte{}) || s.Cookie.Sum == ([32]byte{}) || s.Version != 1 || s.Binding.ID == "" || !s.Binding.IssuedAt.Equal(clock.now) || s.Binding.ExpiresAt.Sub(clock.now) != 5*time.Minute {
		t.Fatal("issuer did not own complete original state")
	}
	executor.execute = func(ctx context.Context, actual PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		if actual != c {
			t.Fatal("original command changed before execution")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("executor call unbounded")
		}
		clock.now = clock.now.Add(1500 * time.Millisecond)
		return preAuthCommitted(actual), nil
	}
	out, err := issuer.Issue(context.Background(), p)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		t.Fatal("new committed flow was not deliverable", err)
	}
	if out.Cookie.Name != "__Host-identity_flow" || out.Cookie.Value != "" || out.Cookie.Domain != "" || out.Cookie.Path != "/" || !out.Cookie.Secure || !out.Cookie.HttpOnly || out.Cookie.SameSite != http.SameSiteLaxMode || out.Cookie.MaxAge != 298 || out.Cookie.Expires.After(s.Binding.ExpiresAt) {
		t.Fatal("flow cookie scope or original expiry changed")
	}
	wire, err := out.Token.Reveal()
	if err != nil {
		t.Fatal("fresh committed credential missing")
	}
	parsed, err := ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := preAuthFixture(t)
	digest, err := parsed.PreAuthDigest(key, s.Binding)
	if err != nil || digest != s.Cookie {
		t.Fatal("delivered cookie did not match exact original commitment")
	}
	if _, err = out.Token.Reveal(); !errors.Is(err, ErrTokenAlreadyRevealed) {
		t.Fatal("flow bearer revealed twice")
	}
	if got, err := issuer.Issue(context.Background(), p); !errors.Is(err, ErrIssuanceAlreadyAttempted) {
		t.Fatal("same preparation reexecuted", err)
	} else {
		noPreAuthDelivery(t, got)
	}
}

func TestPreAuthIssuerNeverDeliversHistoricalOrFailedExecution(t *testing.T) {
	for _, mode := range []string{"replay", "error", "cancel", "expired", "subsecond", "substitution", "panic", "not-committed", "unknown", "conflict", "pending"} {
		t.Run(mode, func(t *testing.T) {
			issuer, p, executor, clock := preAuthIssuerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor.execute = func(_ context.Context, c PreAuthIssueCommand) (PreAuthIssueExecution, error) {
				e := preAuthCommitted(c)
				switch mode {
				case "replay":
					e.Replayed = true
				case "error":
					return e, errors.New("private dependency detail")
				case "cancel":
					cancel()
				case "expired":
					clock.now = clock.now.Add(5 * time.Minute)
				case "subsecond":
					clock.now = clock.now.Add(5*time.Minute - time.Nanosecond)
				case "substitution":
					e.Receipt.Binding.CorrelationID = "another"
				case "panic":
					panic("private dependency detail")
				default:
					e.Receipt.Feature.AfterVersion = 0
					e.Receipt.AuditEventID = ""
					e.Receipt.Outcome = map[string]identity.CommitOutcome{"not-committed": identity.CommitOutcomeNotCommitted, "unknown": identity.CommitOutcomeUnknown, "conflict": identity.CommitOutcomeConflict, "pending": identity.CommitOutcomeInProgress}[mode]
					if mode == "pending" {
						e.Receipt.RetryAfter = time.Second
					}
				}
				return e, nil
			}
			out, err := issuer.Issue(ctx, p)
			noPreAuthDelivery(t, out)
			if mode == "replay" {
				if err != nil || !out.Replayed || out.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("historical commitment lost", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("failed execution classification or redaction", err)
			}
			if (mode == "error" || mode == "cancel" || mode == "expired" || mode == "subsecond") && out.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("known commitment erased")
			}
		})
	}
}

func TestPreAuthIssuerCopiesShareOneExecutionClaim(t *testing.T) {
	issuer, p, executor, _ := preAuthIssuerFixture(t)
	var calls, delivered atomic.Int32
	executor.execute = func(_ context.Context, c PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		calls.Add(1)
		return preAuthCommitted(c), nil
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func(copy PreparedPreAuthIssuance) {
			defer group.Done()
			out, err := issuer.Issue(context.Background(), copy)
			if err == nil {
				delivered.Add(1)
			} else if !errors.Is(err, ErrIssuanceAlreadyAttempted) {
				t.Error("unexpected concurrency error", err)
			}
			if err != nil {
				noPreAuthDelivery(t, out)
			}
		}(p)
	}
	group.Wait()
	if calls.Load() != 1 || delivered.Load() != 1 {
		t.Fatal("copied preparation executed or delivered more than once")
	}
}

func TestPreAuthIssuerRecoveryIsOutcomeOnlyAndExact(t *testing.T) {
	issuer, p, executor, _ := preAuthIssuerFixture(t)
	c, _ := p.Command()
	expected := preAuthCommitted(c).Receipt
	executor.recover = func(_ context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
		b := expected.Binding
		if q.CommandID != b.CommandID || q.TenantID != b.TenantID || q.AnonymousFlowID != b.AnonymousFlowID || q.ActorID != b.ActorID || q.ActorKind != b.ActorKind || q.OperationID != b.OperationID || q.RecordID != b.RecordID || q.UserID != "" || q.LinkMode != 0 {
			t.Fatal("recovery scope changed")
		}
		return expected, nil
	}
	out, err := issuer.Recover(context.Background(), c)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || !out.Replayed {
		t.Fatal("exact historical commitment lost", err)
	}
	noPreAuthDelivery(t, out)
	if out.Flow != (PreAuthTransaction{}) {
		t.Fatal("outcome-only recovery asserted caller-provided historical payload")
	}
	for _, value := range []any{p, out} {
		if strings.Contains(fmt.Sprintf("%+v", value), string(c.CommandID)) {
			t.Fatal("private custody formatting disclosed")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private custody serialized")
		}
	}
}

func TestPreAuthIssuerRejectsInvalidCompositionAndOriginalInput(t *testing.T) {
	issuer, p, executor, clock := preAuthIssuerFixture(t)
	for _, alter := range []func(*PreAuthIssuerConfig){
		func(c *PreAuthIssuerConfig) { c.Clock = nil },
		func(c *PreAuthIssuerConfig) { c.Clock = (*preAuthIssuerClock)(nil) },
		func(c *PreAuthIssuerConfig) { c.FlowTTL = time.Minute - time.Nanosecond },
		func(c *PreAuthIssuerConfig) { c.FlowTTL = 10*time.Minute + time.Nanosecond },
		func(c *PreAuthIssuerConfig) { c.ActorID = "" },
		func(c *PreAuthIssuerConfig) { c.PolicyVersion = 0 },
		func(c *PreAuthIssuerConfig) { c.Origin = "https://identity.test/path" },
		func(c *PreAuthIssuerConfig) { c.CallbackURL = "http://unsafe.test" },
		func(c *PreAuthIssuerConfig) { c.MaximumDuration = 0 },
		func(c *PreAuthIssuerConfig) { c.Cookie = CookiePolicy{} },
		func(c *PreAuthIssuerConfig) { c.Cookie.name = "__Host-session" },
		func(c *PreAuthIssuerConfig) { c.LookupKey = DigestKey{} },
		func(c *PreAuthIssuerConfig) { c.TokenSize = 31 },
	} {
		config := issuer.config
		alter(&config)
		if got, err := NewPreAuthIssuer(executor, config); err == nil || got != nil {
			t.Fatal("invalid trusted composition admitted")
		}
	}
	c, _ := p.Command()
	spec, _ := c.Record.Bindings()
	original := PreAuthPrepareInput{CommandID: c.CommandID, TenantID: spec.Binding.Intent.TenantID, CorrelationID: c.CorrelationID, Remember: spec.Binding.Intent.Remember}
	for _, alter := range []func(*PreAuthPrepareInput){
		func(i *PreAuthPrepareInput) { i.CommandID = "invalid" },
		func(i *PreAuthPrepareInput) { i.TenantID = "" },
		func(i *PreAuthPrepareInput) { i.CorrelationID = "" },
		func(i *PreAuthPrepareInput) { i.Remember = RememberPolicy{} },
	} {
		input := original
		alter(&input)
		if got, err := issuer.Prepare(input); err == nil || got.state != nil {
			t.Fatal("invalid original input admitted")
		}
	}
	foreign, _, _, _ := preAuthIssuerFixture(t)
	if got, err := foreign.Issue(context.Background(), p); err == nil {
		t.Fatal("foreign preparation admitted")
	} else {
		noPreAuthDelivery(t, got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := issuer.Issue(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation misclassified", err)
	} else {
		noPreAuthDelivery(t, got)
	}
	clock.now = clock.now.Add(5 * time.Minute)
	if got, err := issuer.Issue(context.Background(), p); !errors.Is(err, ErrPreAuthDenied) {
		t.Fatal("expired original executed", err)
	} else {
		noPreAuthDelivery(t, got)
	}
	if p.state.attempted.Load() {
		t.Fatal("pre-execution denial consumed local attempt")
	}
}

func TestPreAuthIssuerRememberChoicesDoNotExtendFlow(t *testing.T) {
	issuer, p, _, clock := preAuthIssuerFixture(t)
	c, _ := p.Command()
	spec, _ := c.Record.Bindings()
	for _, choice := range []RememberChoice{BrowserSession, PersistentSession} {
		remember, err := ResolveRememberPolicy(choice, LifetimeConfig{Default: BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := issuer.Prepare(PreAuthPrepareInput{CommandID: c.CommandID, TenantID: spec.Binding.Intent.TenantID, CorrelationID: c.CorrelationID, Remember: remember})
		if err != nil {
			t.Fatal(err)
		}
		command, _ := prepared.Command()
		s, _ := command.Record.Bindings()
		if s.Binding.Intent.Remember != remember || s.Binding.ExpiresAt.Sub(clock.now) != 5*time.Minute || s.Binding.ID == spec.Binding.ID || s.Binding.Intent.Nonce == spec.Binding.Intent.Nonce || s.Cookie == spec.Cookie {
			t.Fatal("flow choice/timeline/entropy was reused or altered")
		}
		out, err := issuer.Issue(context.Background(), prepared)
		if err != nil || out.Cookie.MaxAge != 300 || !out.Cookie.Expires.Equal(s.Binding.ExpiresAt) {
			t.Fatal("remember choice extended flow", err)
		}
	}
}
